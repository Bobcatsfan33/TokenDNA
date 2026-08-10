# Independent Security Assessment

Owner: independent application-security assessor

Scope must include the control-plane API, SDK trust boundary, authentication
and authorization, tenant isolation, DPoP/OIDC validation, cryptographic key
handling, image and deployment configuration, SSRF/injection classes, storage
access, and abuse of enforcement or kill-switch paths.

Required evidence:

- assessor identity, independence statement, dates, commit and image digest;
- documented methodology and authenticated/unauthenticated attack coverage;
- findings with severity, exploit narrative, affected assets, and remediation;
- retest evidence for every Critical or High finding;
- signed final report and risk-acceptance record for residual findings.

Acceptance: no open Critical or High finding, Medium findings have approved
owners and dates, the assessed commit is an ancestor of the release, and the
security authority signs the final report.
