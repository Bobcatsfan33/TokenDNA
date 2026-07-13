# Changelog

All notable changes to the `tokendna-sdk` Python package are recorded here.

The TokenDNA backend service (`api.py`, `modules/`) is **not** distributed via
PyPI. Backend changes are tracked in git history and the production rollout
checklist; this file covers only the public SDK surface.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-16

### Added — Local mode + new client surface
- `TokenDNALocalClient` — zero-config local mode. Writes signed JSONL audit
  events to `~/.tokendna/events.jsonl` using a host-local HMAC key (mode
  0600). `pip install tokendna-sdk` now works end-to-end without a server
  account.
- `TokenDNAClient` — high-level remote client with `health`, `normalize`,
  `attest`, `verify`, and `flush` methods. Wraps the existing low-level
  `Client` for transport. Raises typed exceptions on explicit failures;
  fire-and-forget streams stay silent.
- `make_client()` — auto-picks remote (`TokenDNAClient`) vs local
  (`TokenDNALocalClient`) based on `TOKENDNA_URL`.
- `EventEmitter` — buffered, daemon-threaded event batcher (1 s tick or
  50-event threshold) with `atexit` flush. Failures re-queue without loss.
- Typed data models: `AgentIdentity`, `ToolCallEvent`, `ModelCallEvent`,
  `PolicyVerdict`, `Attestation`, `BehavioralBaseline`.
- Typed exception hierarchy: `TokenDNAError` → `TokenDNAConfigError`,
  `TokenDNAUnavailableError`, `TokenDNAVerificationError`,
  `TokenDNAAttestationError`. The decorator wedge still never raises.

### Added — Native framework middleware
- `tokendna_sdk.integrations.langchain.TokenDNAMiddleware` — implements
  LangChain v0.3 `wrap_model_call` / `wrap_tool_call` / `after_agent`
  hooks. Lazy-imports LangChain; duck-typed base class fallback.
- `tokendna_sdk.integrations.crewai.TokenDNACrewCallback` — supports both
  classic `step_callback` and the newer `on_tool_start` / `on_tool_end` /
  `on_finish` hook surfaces.
- `tokendna_sdk.integrations.autogen.TokenDNAAutoGenMiddleware` —
  `attach()` patches the agent's `_function_map` in place; `detach()`
  restores originals exactly.

### Added — MCP tool-call interceptor
- `tokendna_sdk.integrations.mcp.TokenDNAMCPProxy` — drop-in proxy that
  records every MCP tool call, scores it against the agent's baseline,
  and (optionally) enforces deny chains via bounded-gap subsequence
  matching.
- `secure_mcp_server` decorator for one-liner MCP-server wrapping.

### Added — Behavioral baselines
- File-backed `BaselineStore` at `~/.tokendna/baselines.json`. Three-signal
  anomaly score (frequency z-score, vocab anomaly, sequence anomaly)
  combined via max into `[0.0, 1.0]`. Cold baselines (<5 sessions)
  suppress to 0.0 to keep the FPR under 10% during warmup.
- `detect_chain()` — bounded-gap chain detector exposed for advanced
  users.

### Added — CLI
- `tokendna status` — show client mode, recent event count, and known
  baselines.
- `tokendna verify <agent_id> <action>` — one-shot policy verify.
- `tokendna demo` — synthetic agent run end-to-end (works in local mode).
- `tokendna baseline show <agent_id>` — print the rolling baseline.

### Changed
- `TOKENDNA_URL` env var is now the preferred name. Legacy
  `TOKENDNA_API_BASE` still works; `TOKENDNA_URL` wins on conflict.
- `pyproject.toml` extras: `[langchain]`, `[crewai]`, `[autogen]`,
  `[mcp]`, `[all]`, `[dev]`. `[test]` now includes `pytest-asyncio` and
  `pytest-cov`.
- The `@tool` decorator's fallback client now goes through `make_client()`
  so local-mode callers get the JSONL-backed local client instead of
  buffering events forever in memory.

### Compatibility
- `@identified` + `@tool` decorator surface is unchanged. Code written
  against v0.1.x runs unmodified.
- `Client` and `OfflineBufferClient` classes are kept verbatim for
  direct callers.
- Python 3.9+ supported (uses `typing.Union` rather than PEP 604 `|` for
  runtime annotations).

## [0.1.0] - 2026-04-24

### Added
- Initial public release of the developer SDK.
- `@tokendna.identified` decorator for class-level agent attestation.
- `@tokendna.tool` decorator for per-tool UIS event emission.
- `tokendna.configure()` for API base + key + tenant scoping.
- `tokendna.client` low-level HTTP client (stdlib `urllib` only — zero
  runtime dependencies).
- `tokendna` CLI: `init`, `verify`, `inspect` commands.
- Examples for LangChain, CrewAI, AutoGen, and plain Python agents.
