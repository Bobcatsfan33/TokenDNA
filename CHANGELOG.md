# Changelog

All notable changes to the `tokendna-sdk` Python package are recorded here.

The TokenDNA backend service (`api.py`, `modules/`) is **not** distributed via
PyPI. Backend changes are tracked in git history and the production rollout
checklist; this file covers only the public SDK surface.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production secret gate (`modules/security/secret_gate.py`) — backend-only,
  no SDK impact.

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
