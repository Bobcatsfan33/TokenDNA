"""Frame-level event-stream compression.

Wraps the outbound stream with gzip so the collector ships fewer bytes
over the customer's egress.  zstd is the better choice on a per-frame
basis but it requires an external dependency; gzip is in the stdlib and
is good enough for the sizes we ship per frame (a few KB each).

If a customer's deployment is bandwidth-constrained (federal
deployments commonly are), they can switch to ``Compressor.zstd()``
which expects ``zstandard`` to be installed in the collector image.
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 TokenDNA contributors.

from __future__ import annotations

import gzip
import io
from typing import Protocol


class Codec(Protocol):
    name: str

    def encode(self, data: bytes) -> bytes: ...

    def decode(self, data: bytes) -> bytes: ...


class GzipCodec:
    name = "gzip"

    def __init__(self, level: int = 6):
        if not 1 <= level <= 9:
            raise ValueError(f"gzip level must be 1-9, got {level}")
        self._level = level

    def encode(self, data: bytes) -> bytes:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=self._level, mtime=0) as gz:
            gz.write(data)
        return buf.getvalue()

    def decode(self, data: bytes) -> bytes:
        return gzip.decompress(data)


class IdentityCodec:
    """No-op codec — useful for tests + low-CPU environments."""
    name = "identity"

    def encode(self, data: bytes) -> bytes:
        return data

    def decode(self, data: bytes) -> bytes:
        return data


class Compressor:
    """Façade so callers can switch codecs without rewriting call-sites."""

    def __init__(self, codec: Codec | None = None):
        self._codec: Codec = codec or GzipCodec()

    @property
    def name(self) -> str:
        return self._codec.name

    def encode(self, data: bytes) -> bytes:
        return self._codec.encode(data)

    def decode(self, data: bytes) -> bytes:
        return self._codec.decode(data)

    @classmethod
    def gzip(cls, level: int = 6) -> "Compressor":
        return cls(GzipCodec(level=level))

    @classmethod
    def identity(cls) -> "Compressor":
        return cls(IdentityCodec())

    @classmethod
    def zstd(cls, level: int = 6) -> "Compressor":
        try:
            import zstandard as _zstd  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "zstd compression requested but the 'zstandard' package "
                "is not installed; pip install zstandard or fall back to "
                "Compressor.gzip()."
            ) from exc

        class _ZstdCodec:
            name = "zstd"

            def __init__(self, lvl: int) -> None:
                self._cctx = _zstd.ZstdCompressor(level=lvl)
                self._dctx = _zstd.ZstdDecompressor()

            def encode(self, data: bytes) -> bytes:
                return self._cctx.compress(data)

            def decode(self, data: bytes) -> bytes:
                return self._dctx.decompress(data)

        return cls(_ZstdCodec(level))
