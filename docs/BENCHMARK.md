# TokenDNA Detection-Efficacy Benchmark

`scripts/efficacy_benchmark.py` is a **reproducible, self-contained** harness
that measures how well TokenDNA's runtime-risk engine detects the three
RSA-2026 scenarios the README claims to close, and what it costs to decide.

It exists so that "we detect X" is a **number you can regenerate**, not a
marketing claim. It runs in CI as an advisory (non-blocking) job that publishes
its report as an artifact.

## What it measures

Against an **in-process instance** of the API (FastAPI `TestClient`, booted with
`DEV_MODE=true` + `TOKENDNA_ENV=ci`, a throwaway SQLite DB, and a sandboxed
audit sink), the benchmark replays each scenario `--iterations` times and
reports:

| Metric | Definition |
|---|---|
| **Detection rate** | fraction of injected attacks that produce the expected detection signal |
| **False-positive rate** | fraction of a **benign-traffic baseline** that (wrongly) trips a detection |
| **Decision latency** | p50 / p95 / p99 of the decisive decision HTTP call, per scenario and overall |

### The three scenarios

| Scenario | Attack driver | Detection signal | Benign control |
|---|---|---|---|
| **Permission drift** | `POST /api/drift/record` — scope grows >2× across observations with `has_attestation=false` | an open alert appears at `GET /api/drift/alerts` | the same agent growing scope **with attestation**, small |
| **Policy self-modification** | `POST /api/policy/guard/evaluate` — an **agent** attempts `update` with a self-scope-expanding `scope_delta` (CONST-01) | disposition `block`/`flag` or a violation is recorded | a **human** operator making a routine non-governance policy update |
| **MCP tool-chain attack** | `POST /api/mcp/inspect` — `read_file` (sensitive) → `send_email` (exfil) within one session window | a `chain_patterns` match / `flag`/`block` recommendation | two benign `read_file` calls, no exfil |

Detection endpoints are reused from `scripts/demo_runtime_risk_engine.py`, so the
benchmark exercises the same code path the live demo does.

## Running it

```bash
TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py                 # run + write report
TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py --strict        # CI gate (exit≠0 on regression)
TOKENDNA_ENV=ci python scripts/efficacy_benchmark.py --iterations 50 --out-dir reports/
```

Outputs `efficacy_report.json` and `efficacy_report.md` in `--out-dir`.
`--strict` exits non-zero if **detection rate < 100 %** or **any false positive**
occurs. Latency is **never** part of the strict gate (see below).

## How to read the latency number honestly

`EDGE_DECISION_SLO_MS` (default **5 ms**) is the SLO for the **edge enforcement
fast path** (`modules/identity/edge_enforcement.evaluate_runtime_enforcement`) —
a single, lean allow/step-up/block decision.

The three benchmark scenarios do **not** hit that fast path. They exercise the
richer detection endpoints (drift bookkeeping, constitutional-rule evaluation,
MCP chain reconstruction), measured **end-to-end through the in-process HTTP
layer** (ASGI routing + JSON (de)serialization included). Those numbers are
therefore a **conservative upper bound** and are expected to sit above the 5 ms
edge SLO. The report prints `p95_within_slo` as an informational flag, **not** a
pass/fail. Treat the latency section as "decision cost, order-of-magnitude,"
not as an edge-SLO conformance test.

## What this benchmark does **NOT** cover

Stated plainly so the number is not over-read:

- **Not an independent red-team.** Scenarios are hand-authored by the same team
  that built the detectors. A determined adversary designs around known signals;
  this measures the *claimed* detections, not unknown evasions.
- **Not a garak / LLM-jailbreak study.** It does not probe model-level prompt
  injection or jailbreak robustness — only the identity/behavioral runtime
  controls.
- **Not live traffic.** Inputs are deterministic and synthetic. There is no real
  benign-traffic corpus, so the false-positive rate is measured against a small,
  curated benign baseline — a floor, not a production FP estimate.
- **No evasion / gap-tuning sweep.** It uses the default chain-gap and
  time-window thresholds; it does not search for the largest gap or slowest
  drift that still evades detection.
- **Single-tenant, single-process.** No concurrency, no multi-tenant
  interference, no Postgres backend, no network. Latency excludes real I/O.
- **Detection = signal fired**, not "attack fully mitigated end-to-end." It
  confirms the engine *flags* the scenario; downstream enforcement/response is
  covered by other tests (`tests/test_rsa_narrative_e2e.py`, the adversarial
  harness).

For adversarial *robustness* checks see `scripts/adversarial_harness.py`; for the
end-to-end detection→block→advise→approve loop see
`tests/test_rsa_narrative_e2e.py`.
