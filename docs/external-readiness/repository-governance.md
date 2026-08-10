# Repository Governance and Separation of Duties

Owner: repository administrator and independent second maintainer

The live repository currently lacks the full target protection described by
the SDLC policy. Do not enable code-owner enforcement until an independent
maintainer is accepted and listed on every CODEOWNERS rule.

Required evidence:

- accepted second maintainer with write or greater access;
- updated CODEOWNERS containing that maintainer on every rule;
- successful `scripts/org/protect.sh TokenDNA <login>` execution;
- exported main-branch protection showing admin enforcement, signed commits,
  code-owner review, last-push approval, conversation resolution, and all CI
  job contexts required;
- a test pull request proving self-approval and red-check merges are blocked.

Acceptance: the exported settings and negative test PR prove independent review
cannot be bypassed by the author or repository administrator.
