# Customer Responsibility Matrix

| Domain | TokenDNA responsibility | Customer / inherited responsibility |
|--------|-------------------------|-------------------------------------|
| Identity provider | Verify JWTs, require explicit tenant claims, map roles/groups, consume SCIM group mappings | Operate CAC/PIV, IdP, MFA, account lifecycle, federation policy |
| RBAC | Enforce TokenDNA roles and least-privilege API-key defaults | Assign users/groups to appropriate TokenDNA roles |
| Secrets | Support env, AWS Secrets Manager, and Vault retrieval; profile-gate managed backends | Provision KMS/HSM/Vault, rotate keys, protect root/admin credentials |
| Cryptography | Provide FIPS/TLS helpers, KMS/HSM trust authority backends, signed attestations | Deploy on validated crypto modules and approved cloud/enclave services |
| Storage | Use Postgres backend in production and migration gates | Provide encrypted database, backups, PITR, object lock, DB STIG evidence |
| Audit | Emit HMAC/hash-chained audit events and SIEM forwarding | Retain audit logs, operate SIEM, configure WORM storage, review alerts |
| Network | Support internal mTLS, Redis TLS, ClickHouse TLS, and Kubernetes network policy | Operate ingress, WAF, firewalls, DNS, certificates, enclave routing |
| Vulnerability management | CI gates, dependency audit, CodeQL, Trivy, release manifest | Scan deployed hosts/clusters, remediate enclave findings, maintain POA&M |
| Incident response | Product runbooks for breach, revocation, key rotation, audit verification | Agency/customer IR process, reporting timelines, evidence preservation |
| Assessment package | Control matrix, generated evidence manifests, docs, tests | eMASS entry, inherited controls, assessor coordination, AO risk acceptance |
