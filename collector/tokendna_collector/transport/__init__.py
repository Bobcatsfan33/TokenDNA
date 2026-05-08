"""Transport layer — moves NormalizedEvents from collector to cloud."""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from .buffer import LocalBuffer
from .compress import Codec, Compressor, GzipCodec, IdentityCodec
from .stream import (
    CloudStream,
    CloudTransportError,
    PermanentTransportError,
    TransientTransportError,
)

__all__ = [
    "Codec",
    "CloudStream",
    "CloudTransportError",
    "Compressor",
    "GzipCodec",
    "IdentityCodec",
    "LocalBuffer",
    "PermanentTransportError",
    "TransientTransportError",
]
