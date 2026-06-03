# Continuous Monitoring Plan

## Cadence

| Frequency | Activity | Evidence |
|-----------|----------|----------|
| Every PR | lint, tests, dependency audit, CodeQL, secret scan, container scan, Helm validation | GitHub Actions logs and SARIF/artifacts |
| Every release | release manifest, ATO evidence bundle, OSCAL component mapping, STIG evidence, production preflight | `dist/release-bundle/`, `dist/ato/` |
| Monthly | dependency review, image rebuild, POA&M review, audit-log integrity sample | vulnerability report, POA&M updates, audit verification report |
| Quarterly | backup/restore drill, key rotation drill, incident-response tabletop | DR report, key rotation audit, tabletop after-action report |
| Annually | penetration test, architecture review, external assessment refresh | assessor report, updated SSP, updated control matrix |

## Automated Evidence

Run:

```bash
python scripts/collect_ato_evidence.py
python scripts/generate_oscal.py
python scripts/stig_evidence.py
```

The generated files are release artifacts and should be attached to the
customer authorization package.

## POA&M Flow

1. Record every unmet control or deployment-specific gap in
   `docs/ato/poam-template.csv`.
2. Assign owner, severity, target completion date, and compensating control.
3. Review open items monthly and before every production release.
4. Close only when evidence is linked and reviewed by the customer security
   owner or assessor.
