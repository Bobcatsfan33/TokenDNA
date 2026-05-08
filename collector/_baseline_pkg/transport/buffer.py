"""Local disk buffer for network outages (placeholder).

When the connection to TokenDNA Cloud is unavailable, collected
``NormalizedEvent`` records spill to disk under
``CollectorConfig.buffer_path``.  When the connection returns, the
buffer drains in arrival order with at-least-once delivery semantics.

Implementation lands in a Sprint 1-2 follow-up commit.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

# TODO(sprint-1-2): on-disk ring buffer with size + age caps.


class LocalBuffer:
    """Placeholder for the on-disk overflow buffer."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise NotImplementedError(
            "LocalBuffer is a Sprint 1-2 placeholder; implementation pending."
        )
