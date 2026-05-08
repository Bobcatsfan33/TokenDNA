"""Tests for the transport-layer compression codec."""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest

from tokendna_collector.transport.compress import (
    Compressor,
    GzipCodec,
)


def test_gzip_round_trip() -> None:
    c = Compressor.gzip()
    payload = b'{"event_id":"e-1","subject":"alice"}\n' * 64
    encoded = c.encode(payload)
    assert encoded != payload
    assert c.decode(encoded) == payload


def test_identity_codec_passes_bytes_through() -> None:
    c = Compressor.identity()
    payload = b"abcd"
    assert c.encode(payload) == payload
    assert c.decode(payload) == payload


def test_gzip_actually_compresses() -> None:
    c = Compressor.gzip()
    payload = b"a" * 10_000
    encoded = c.encode(payload)
    assert len(encoded) < len(payload) // 5  # at least 5x ratio on this input


def test_gzip_level_validation() -> None:
    with pytest.raises(ValueError):
        GzipCodec(level=0)
    with pytest.raises(ValueError):
        GzipCodec(level=10)


def test_compressor_name_reflects_codec() -> None:
    assert Compressor.gzip().name == "gzip"
    assert Compressor.identity().name == "identity"


def test_default_compressor_is_gzip() -> None:
    assert Compressor().name == "gzip"
