"""Event-stream compression (placeholder).

Wraps the outbound stream with a frame-level codec (zstd by default)
so the collector ships fewer bytes over the customer's egress.

Implementation lands in a Sprint 1-2 follow-up commit.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

# TODO(sprint-1-2): zstd-frame codec + content-length negotiation.


class Compressor:
    """Placeholder for the streaming compressor."""

    def __init__(self, *_args, **_kwargs) -> None:
        raise NotImplementedError(
            "Compressor is a Sprint 1-2 placeholder; implementation pending."
        )
