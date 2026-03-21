# Contributing to TokenDNA

Thank you for your interest in contributing to TokenDNA. This project exists to replace legacy security tooling with open, cloud-native, AI-driven alternatives — and community contributions are how we get there.

## Ground Rules

All contributions require review and explicit approval by the project maintainer ([@Bobcatsfan33](https://github.com/Bobcatsfan33)) before merging. No exceptions. Security software demands this level of scrutiny.

## Before You Start

1. **Open an issue first.** Describe what you want to build or fix. This prevents duplicate work and ensures alignment before you write a line of code.
2. **For security vulnerabilities** — do NOT open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Development Setup

```bash
git clone https://github.com/Bobcatsfan33/TokenDNA.git
cd TokenDNA
cp .env.example .env          # fill in your values
pip install -r requirements.txt
DEV_MODE=true uvicorn api:app --reload
```

**Note:** `DEV_MODE=true` is strictly for local development. It disables JWT validation. Never deploy with this flag.

## Pull Request Requirements

Every PR must include:

- [ ] A clear description of the change and why it's needed
- [ ] Tests or a manual test plan
- [ ] No new secrets, credentials, or API keys in source
- [ ] No weakening of existing security controls
- [ ] Updated documentation if behavior changes
- [ ] Passing CI checks (CodeQL, Dependabot, linting)

**Security-sensitive PRs** (auth, crypto, network scanning, remediation agents, SIEM transport) receive extended review and may require additional justification.

## What We're Looking For

- Cloud scanner plugins (Azure, GCP, Kubernetes, Terraform drift)
- SIEM integrations (Wazuh, QRadar, Sentinel, Chronicle)
- AI agent improvements (better remediation strategies, safer defaults)
- OpenSearch dashboard templates
- Documentation and runbooks
- Bug fixes with clear reproduction steps

## What We Will Not Accept

- Proprietary SDK dependencies (Splunk, Elastic paid, Datadog)
- Code that disables or weakens security controls
- Features that remove the DRY_RUN / AUTO_REMEDIATE safety gates
- Breaking changes to the public API without a deprecation path

## Code Style

- Python: PEP 8, type hints on all public functions
- Docstrings on all modules, classes, and public functions
- No `print()` — use `logging` with the module logger
- Secrets always from environment variables or secrets manager, never hardcoded

## Commit Message Format

```
type(scope): short description

Longer explanation if needed. Reference issues with #123.
```

Types: `feat`, `fix`, `chore`, `docs`, `security`, `perf`, `refactor`

## License

By contributing, you agree your contributions are licensed under the same [Business Source License 1.1](LICENSE) that covers this project.
