"""Cloud transport — TLS event stream (placeholder).

Sprint 1-2 follow-up commit will port the production mTLS logic from
the platform's ``modules.security.mtls`` into this module, adapted to be
a streaming *client* (push events to the cloud ingestion endpoint)
rather than the embedded TLS server-side configuration the platform
already has.

This file is intentionally a placeholder so the directory structure
can land first; the implementation follows in the same sprint without
further structural churn.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

# TODO(sprint-1-2): port mTLS client + add backpressure-aware send loop.


class StreamNotImplementedError(NotImplementedError):
    """Raised by callers if they invoke the placeholder stream."""


class CloudStream:
    """Placeholder for the streaming client to TokenDNA Cloud."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise StreamNotImplementedError(
            "CloudStream is a Sprint 1-2 placeholder; implementation pending."
        )
