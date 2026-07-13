# Multi-region / HA architecture

For enterprise + federal deployments where a single-AZ outage cannot take the platform down. This document describes the topology, what is stateless versus stateful, and the failover characteristics of each tier.

## Topology

```
                             ┌──────────────────────────┐
   Region A (primary) ──────►│  Cloudflare global edge  │◄────── Region B (DR)
                             │  (Workers + KV global)   │
                             └────────────┬─────────────┘
                                          │
                  ┌───────────────────────┼───────────────────────┐
                  │                       │                       │
                  ▼                       ▼                       ▼
           Region A AZ-1         Region A AZ-2           Region B AZ-1
   ┌──────────────────────────────────────────────────────────────────────┐
   │  API replicas (stateless, n × per AZ)                                │
   └────────────┬─────────────────────────┬───────────────────────────────┘
                ▼                         ▼
   ┌─────────────────────┐    ┌─────────────────────┐
   │ Postgres primary +  │    │ Redis Sentinel/Cluster │
   │  read replicas      │    │  (active in primary,   │
   │  (sync replication  │    │   replicated to DR)    │
   │   to a DR replica   │    │                        │
   │   in Region B)      │    │                        │
   └─────────────────────┘    └─────────────────────┘
   ┌──────────────────────────────────────────────────────────────────────┐
   │  ClickHouse: replicated MergeTree + distributed tables               │
   │  (2 shards × 2 replicas per region; cross-region async replication)  │
   └──────────────────────────────────────────────────────────────────────┘
```

## What's stateless

Every component above the data tier:

- **API process** (`api.py` / `uvicorn`) — fully stateless. Any number of replicas; the L7 LB distributes round-robin or least-conn.
- **Cloudflare Worker** — stateless by design (Cloudflare runs your code in every PoP).
- **scripts/** — all CLI helpers are stateless and re-runnable.

Implication: scaling the API is `n × replicas`. There is no leader-election, no stuck-pod recovery, no warm-up period beyond container start.

## What's stateful (and the failover semantics)

### Redis (Sentinel mode, recommended)

Three Sentinel nodes (`cache.r7g.large`-class) with quorum-based failover. Failover takes 5–10 s.

- **Replication**: synchronous WAIT for `min-replicas-to-write 1`.
- **What lives here**: revocation list (`revoked:<jti>`), DPoP nonce store (`dpop_nonce:<jti>`), per-agent risk-score cache, behavioral profile baselines.
- **Acceptable loss**: nonce store (5-min TTL means brief replay window after primary-replica skew). Everything else is rebuilt from Postgres / ClickHouse on warm-up.
- **Cluster mode**: switch to it when the dataset crosses ~16 GB or when sustained ops/sec crosses ~50k. Below those thresholds Sentinel is simpler and cheaper.

### Postgres

Primary + 1 sync replica per region + 1 async replica in DR region.

- **Sync replication** to the same-region replica: write latency stays inside the AZ (~1 ms RTT). Primary-fail loses zero committed writes.
- **Async replication** to the DR region: ≤30 s lag under normal load. Primary-region-fail loses up to 30 s of writes.
- **Promotion**: `pg_ctl promote` on the warm standby. ~1 minute end-to-end (DNS / connection-string flip dominates).
- **Tables that matter**: tenant store, attestation cert store, drift events, posture statements, signed compliance snapshots.

### ClickHouse

Replicated MergeTree per shard, 2 replicas per shard, 2 shards per region.

- **Per-shard durability**: write goes to one replica, replicates to the other within the second. Replica-loss is opaque to clients.
- **Cross-region**: configure as a separate ClickHouse cluster receiving INSERT-streaming via `clickhouse-keeper`-replicated DDL + a Materialized View. Lag depends on inter-region bandwidth (typically <60 s).
- **What lives here**: UIS event store (90-day TTL), audit log, threat-intel observation log.
- **Recovery**: a lost replica re-syncs automatically from its peer on restart.

## Failover playbook

| Failure                                    | Detection                                              | Action                                                                                            |
|--------------------------------------------|--------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| Single API pod crash                       | k8s liveness probe                                     | Pod restarts; LB drops it from rotation in <10 s. No human action.                                |
| Whole API replica set unhealthy            | Grafana `p99 /secure > 100 ms` alert pages             | Roll back the last deploy (`docs/operations/RUNBOOK.md` § Rollback).                              |
| Single Redis node loss                     | Sentinel reports                                       | Failover automatic in <10 s. Replace the lost node from the IaC pipeline within 24 h.             |
| Whole Redis cluster down                   | Health check `redis.ok=false`                          | API enters **degraded mode** (no nonce check, no edge cache hits). Client-facing 200s continue; revocation enforcement is best-effort until Redis recovers. |
| Postgres primary loss in primary region    | Health check `postgres.ok=false` for >30 s             | Promote sync replica (`pg_ctl promote`); update the connection string secret; bounce API. ~1 min. |
| Whole primary region loss                  | All region-A health checks failing for >2 min          | Promote DR Postgres replica; flip Cloudflare LB to Region B; up to 30 s of writes lost.           |
| ClickHouse single replica loss             | Internal replica lag alert                             | No client impact. Replace the node from IaC.                                                      |
| ClickHouse whole shard loss                | Audit-write timeout from API                           | API returns 200 to clients but logs `audit_dropped` (hash chain re-syncs on shard recovery).      |
| Cloudflare Worker outage                   | Cloudflare status page                                 | Out of our control. Document for the customer's risk register.                                    |

## Stateless vs stateful summary

| Component        | State            | Scaling axis                        | Failover RTO/RPO                         |
|------------------|------------------|-------------------------------------|------------------------------------------|
| API              | None             | Horizontal                          | RTO ≤10s (pod restart) / RPO 0           |
| Cloudflare Worker| None (KV global) | None (Cloudflare-managed)           | Cloudflare-managed                       |
| Edge KV cache    | Read-through      | None                                | RTO 60s (next cron) / RPO 60s            |
| Redis Sentinel   | Yes               | Vertical until 16 GB, then Cluster  | RTO ~10s / RPO 0 (sync writes)           |
| Postgres         | Yes               | Read replicas + sharding (future)   | RTO ~1 min / RPO 0 (sync) or ~30 s (DR)  |
| ClickHouse       | Yes               | Add shards / replicas               | RTO 0 (replica takeover) / RPO ~1 s      |

## Not-yet-supported (documented honestly)

- **Active-active multi-region writes**. Today the primary region is the only writer; DR is read-replica + warm standby. Active-active is on the roadmap once we add CRDT / OT for the writes that are actually contended (audit log, posture statements).
- **Cross-region failover for Redis Sentinel**. Today, a region loss means rebuilding the Redis cluster from Postgres — acceptable degradation for the trial / pilot phase, but enterprise customers should plan for ~5 min of degraded enforcement during regional cutover.
- **Compute-instance hot standby**. We rely on container restart latency (~10s) rather than a hot-standby pool. For sub-second failover, run 2× the steady-state replica count.

## Capacity planning per scale tier

| Scale tier         | Sustained rps | Agents  | Recommended footprint                                                              |
|--------------------|---------------|---------|------------------------------------------------------------------------------------|
| Pilot              |  ~50 rps      | 1k      | 1 region · 2 API replicas · 1 Redis · 1 Postgres · 2 ClickHouse                    |
| Production / Pro   | ~500 rps      | 10k     | 1 region · 4 API replicas · 3 Redis Sentinel · 1 Postgres + 1 read · 4 ClickHouse  |
| Enterprise         | 1k–5k rps     | 100k+   | 2 regions · 8 API replicas / region · 3 Redis Sentinel / region · Postgres primary + sync + DR replica · 4-shard × 2-replica ClickHouse / region |
| Federal IL5        | Per-customer  | Per-customer | Customer-managed Kubernetes; same shape; KMS → CloudHSM swap                  |
