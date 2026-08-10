# Identity Interoperability Validation

Owner: enterprise identity engineering

Validate OIDC, SAML, SCIM, role/group mapping, deprovisioning, session expiry,
key rotation, replay handling, clock skew, and failure modes against supported
real identity providers. Mocks and unit tests do not satisfy this gate.

Required evidence:

- a declared supported-provider/version matrix;
- successful positive and negative test runs for every supported provider;
- tenant-isolation and least-privilege validation;
- disable/delete propagation and emergency revocation timing;
- signed exceptions for unsupported provider-specific behavior.

Acceptance: the published compatibility matrix matches the tested matrix, all
security-negative cases fail closed, and identity engineering signs the report.
