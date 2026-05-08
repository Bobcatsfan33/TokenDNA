# TokenDNA Collector

Open-source edge collector for the TokenDNA AI runtime security platform. Apache 2.0.

The collector lives **inside the customer's network**. It pulls events from systems they already run — Okta, Splunk, AWS CloudTrail, Azure Sentinel, MCP traffic, etc. — normalises them into a single shape, and ships them over mTLS to the TokenDNA Cloud platform for correlation and intelligence.

The customer's existing stack is never replaced. The collector is the *only* TokenDNA component they install on their side.

## Why open source

- **Auditable**: it runs in the customer's network. They should be able to read every line of code.
- **Adoption**: zero-friction deployment beats every paid demo.
- **Ecosystem**: anyone can write a new adapter for a system we haven't covered yet — and contribute it back.
- **Trust**: a security product whose code you can read is a security product worth running.

## What lives here vs. in `../platform/`

| Concern                                              | Lives where           |
|------------------------------------------------------|-----------------------|
| Adapters that talk to customer systems               | `collector/` (here)   |
| `NormalizedEvent` schema                             | `collector/` (here)   |
| Transport layer to the cloud (mTLS, buffer, compress)| `collector/` (here)   |
| Local-mode findings (basic rule checks, no cloud)    | `collector/` (here)   |
| `/health` + Prometheus metrics                       | `collector/` (here)   |
| Intelligence engines (trust graph, behavioural DNA, blast radius, MCP inspector, policy guard) | `../platform/` |
| Dashboard, finding management UI                     | `../platform/`        |
| Compliance framework mapping + evidence export       | `../platform/`        |
| Alert routing, SIEM forwarding, ticketing            | `../platform/`        |
| Response actions (webhook enforcement)               | `../platform/`        |
| Multi-tenant SaaS infrastructure                     | `../platform/`        |
| The runtime-enforcement SDK                          | `../platform/` (gated to top-tier customers) |

The split is the entire point of the redesign described in `~/Desktop/tokendna/TOKENDNA-DEPLOYMENT-REDESIGN.md`. The collector is the customer's free, auditable observation layer. The platform is the proprietary intelligence that turns observed events into prioritised, correlated, compliance-mapped findings.

## Layout

```
collector/
├── LICENSE                     Apache License 2.0 (full text)
├── NOTICE                      Required attribution file
├── README.md                   You are here
├── pyproject.toml              Package metadata; PyPI: tokendna-collector
├── Dockerfile                  Distroless multi-arch image (placeholder until Sprint 1-2 follow-up)
└── tokendna_collector/         Importable Python package
    ├── __init__.py             version + public re-exports
    ├── schema.py               NormalizedEvent + EventCategory + EventOutcome
    ├── config.py               AdapterConfig + CollectorConfig
    ├── health.py               HealthStatus + HealthState
    ├── adapters/
    │   ├── __init__.py         re-exports BaseAdapter
    │   ├── base.py             BaseAdapter ABC — the adapter contract
    │   ├── idp/                identity-provider adapters
    │   ├── siem/                SIEM adapters
    │   ├── cloud/               cloud-platform adapters
    │   └── ai_workload/         AI runtime / MCP adapters
    └── transport/
        ├── __init__.py         re-exports CloudStream / LocalBuffer / Compressor
        ├── stream.py           streaming client to cloud (mTLS)
        ├── buffer.py           local disk overflow during outages
        └── compress.py         frame-level codec for the wire
```

## Adding a new adapter

A concrete adapter is one Python file inside the appropriate category package. Subclass `BaseAdapter`, fill in `source_type`, `connect`, `poll`, `health_check`. The transport layer takes care of the rest.

```python
from tokendna_collector.adapters.base import BaseAdapter
from tokendna_collector.schema import NormalizedEvent, EventCategory, EventOutcome

class MyAdapter(BaseAdapter):
    @property
    def source_type(self) -> str:
        return "my_source"

    async def connect(self, config):
        # establish API session
        ...

    async def poll(self):
        # yield NormalizedEvent instances since the last cursor
        ...

    async def health_check(self):
        # return HealthStatus
        ...
```

Adapters MUST:

1. Be safe to instantiate without doing I/O.
2. Track their own cursor so a restart doesn't drop or duplicate events.
3. Convert source-system errors into adapter-level exceptions; never log raw secrets.
4. Tag every emitted `NormalizedEvent` with the same `tenant_id` + `collector_id` the rest of the collector is using (the framework injects these — adapter just receives `AdapterConfig` and uses fields from it).

## Status

This directory landed as **scaffolding only** in PR `#sprint/1-2-collector-platform-split`. The transport-layer placeholders, the Dockerfile placeholder, and the empty adapter-category packages will be filled in by subsequent commits in the same sprint per the plan in `~/Desktop/tokendna/TOKENDNA-DEPLOYMENT-REDESIGN.md`.

## License

Apache License, Version 2.0. See `LICENSE`.
