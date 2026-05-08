"""AI-workload adapters — observe AI runtime traffic.

Planned concrete adapters:

  * ``mcp_mirror`` — MCP protocol traffic mirror              (P3)
  * ``bedrock`` — AWS Bedrock invocation log                  (P0, partial overlap with cloud.aws)
  * ``openai`` — Azure OpenAI usage log                       (P1, partial overlap with cloud.azure)

These adapters target the runtime layer specifically — the bytes
flowing in and out of the model — rather than the control plane that
the IDP and cloud adapters watch.  Provides the data that the
behavioural-DNA + MCP-inspector engines on the cloud side use to score
intent and detect chain attacks.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.
