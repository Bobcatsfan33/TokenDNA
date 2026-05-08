"""Cloud-platform adapters — read audit + AI-service activity from CSPs.

Planned concrete adapters:

  * ``aws`` — CloudTrail + Bedrock + SageMaker enumeration  (P0)
  * ``azure`` — Activity Log + Azure OpenAI + ML workspace  (P1)
  * ``gcp`` — Audit Log + Vertex AI                          (P2)

These adapters power TokenDNA Cloud's *AI asset discovery* pipeline:
the customer's read-only IAM role is enough to enumerate every AI
workload in their account, including ones nobody on the security team
knew about (shadow AI).
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.
