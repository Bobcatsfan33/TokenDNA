"""Transport layer — moves NormalizedEvents from collector to cloud.

Public surface (placeholder until Sprint 1-2 implementation lands):
  * ``CloudStream``  — streaming client over mTLS
  * ``LocalBuffer``  — disk overflow during outages
  * ``Compressor``   — frame-level codec for the wire

Each module is intentionally thin while the directory structure stabilises;
the actual implementations port from ``modules.security.mtls`` and the
existing buffering primitives in the platform repo.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from .buffer import LocalBuffer
from .compress import Compressor
from .stream import CloudStream, StreamNotImplementedError

__all__ = [
    "CloudStream",
    "Compressor",
    "LocalBuffer",
    "StreamNotImplementedError",
]
