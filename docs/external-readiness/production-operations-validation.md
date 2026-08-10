# Production Operations and Resilience Validation

Owner: production SRE or platform engineering

Run the release candidate in the target topology with production-equivalent
Postgres, Redis, ClickHouse, ingress, TLS, secrets, telemetry, and retention.

Required evidence:

- 72-hour soak and representative peak-load results with stated SLOs;
- node, process, datastore, and network-failure injection results;
- backup restore plus regional/site disaster-recovery exercise;
- measured RTO/RPO, alert delivery, escalation, and incident timeline;
- upgrade, rollback, schema migration, capacity, and log-retention validation;
- signed runbook review and on-call ownership.

Acceptance: agreed SLO, RTO, and RPO targets are met with no unexplained data
loss or control bypass, and SRE signs the release-candidate report.
