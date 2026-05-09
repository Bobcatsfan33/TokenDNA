"""Cloud-platform adapters — read audit + AI-service activity from CSPs.

Concrete adapters:

  * ``aws.AWSCloudTrailAdapter`` — CloudTrail audit + AI service enum (P0)
  * ``azure.AzureActivityLogAdapter`` — Activity Log + Azure OpenAI/ML (P1)

GCP is planned for a follow-up sprint; the same adapter contract
applies (subclass ``BaseAdapter``, emit ``NormalizedEvent``).

These adapters power the platform's *AI asset discovery* pipeline:
the customer's read-only IAM role / service principal is enough to
enumerate every AI workload in their account, including ones the
security team didn't know about (shadow AI).
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from .aws import AWSAdapterError, AWSCloudTrailAdapter
from .azure import AzureActivityLogAdapter, AzureAdapterError

__all__ = [
    "AWSAdapterError",
    "AWSCloudTrailAdapter",
    "AzureActivityLogAdapter",
    "AzureAdapterError",
]
