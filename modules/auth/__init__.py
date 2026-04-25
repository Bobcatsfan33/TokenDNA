"""TokenDNA enterprise authentication scaffolds.

* :mod:`saml` — SAML 2.0 SSO. SP-initiated AuthnRequest emission, ACS
  assertion handling, IdP metadata XML.
* :mod:`scim` — SCIM 2.0 user / group provisioning endpoints.

Both modules are alpha. They define the route shape, request / response
schemas, and integration points so customers can evaluate the API.
The actual cryptographic verification of SAML assertions and the
production-grade audit-log wiring are tracked for follow-up sprints.
"""
