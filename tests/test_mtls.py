from __future__ import annotations

import os
from pathlib import Path

import pytest

from modules.security.mtls import (
    MTLSConfigError,
    MTLSPair,
    load,
    load_or_raise,
)


@pytest.fixture
def cert_dir(tmp_path):
    """Materialise dummy CA + service cert/key files on disk."""
    for name in ("ca.crt", "api.crt", "api.key", "redis.crt", "redis.key",
                 "clickhouse.crt", "clickhouse.key", "postgres.crt", "postgres.key"):
        (tmp_path / name).write_bytes(b"-----BEGIN CERT-----\nstub\n-----END CERT-----\n")
    return tmp_path


def _set_env(d: dict[str, str], monkeypatch):
    for k, v in d.items():
        monkeypatch.setenv(k, v)


def test_load_returns_inactive_when_nothing_configured(monkeypatch):
    for v in ("TLS_CA_CERT_PATH", "TLS_API_CERT_PATH", "TLS_API_KEY_PATH"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("TOKENDNA_ENV", "dev")
    cfg = load()
    assert cfg.is_active is False
    assert cfg.uvicorn_kwargs() == {}
    assert cfg.redis_kwargs() == {}
    assert cfg.clickhouse_kwargs() == {}
    assert cfg.postgres_dsn_params() == {}


def test_load_resolves_full_pair_when_files_present(cert_dir, monkeypatch):
    _set_env({
        "TOKENDNA_ENV": "production",
        "TLS_CA_CERT_PATH": str(cert_dir / "ca.crt"),
        "TLS_API_CERT_PATH": str(cert_dir / "api.crt"),
        "TLS_API_KEY_PATH": str(cert_dir / "api.key"),
        "TLS_REDIS_CERT_PATH": str(cert_dir / "redis.crt"),
        "TLS_REDIS_KEY_PATH": str(cert_dir / "redis.key"),
        "TLS_CLICKHOUSE_CERT_PATH": str(cert_dir / "clickhouse.crt"),
        "TLS_CLICKHOUSE_KEY_PATH": str(cert_dir / "clickhouse.key"),
        "TLS_POSTGRES_CERT_PATH": str(cert_dir / "postgres.crt"),
        "TLS_POSTGRES_KEY_PATH": str(cert_dir / "postgres.key"),
    }, monkeypatch)
    cfg = load_or_raise()
    assert cfg.is_active is True
    uv = cfg.uvicorn_kwargs()
    assert "ssl_certfile" in uv and "ssl_keyfile" in uv and "ssl_ca_certs" in uv
    redis = cfg.redis_kwargs()
    assert redis["ssl"] is True
    assert "ssl_ca_certs" in redis and "ssl_certfile" in redis
    ch = cfg.clickhouse_kwargs()
    assert ch["secure"] is True and "ca_cert" in ch
    pg = cfg.postgres_dsn_params()
    assert pg["sslmode"] == "verify-full" and pg["sslrootcert"].endswith("ca.crt")


def test_load_or_raise_raises_in_production_when_ca_missing(cert_dir, monkeypatch):
    _set_env({
        "TOKENDNA_ENV": "production",
        # No CA, no API cert
    }, monkeypatch)
    for v in ("TLS_CA_CERT_PATH", "TLS_API_CERT_PATH", "TLS_API_KEY_PATH"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(MTLSConfigError) as exc:
        load_or_raise()
    msg = str(exc.value)
    assert "TLS_CA_CERT_PATH" in msg
    assert "TLS_API_CERT_PATH/TLS_API_KEY_PATH" in msg


def test_load_or_raise_dev_returns_inactive_without_raising(monkeypatch):
    monkeypatch.setenv("TOKENDNA_ENV", "dev")
    for v in ("TLS_CA_CERT_PATH", "TLS_API_CERT_PATH", "TLS_API_KEY_PATH"):
        monkeypatch.delenv(v, raising=False)
    cfg = load_or_raise()
    assert cfg.is_active is False


def test_uvicorn_kwargs_requires_client_cert_when_ca_present(cert_dir, monkeypatch):
    _set_env({
        "TOKENDNA_ENV": "production",
        "TLS_CA_CERT_PATH": str(cert_dir / "ca.crt"),
        "TLS_API_CERT_PATH": str(cert_dir / "api.crt"),
        "TLS_API_KEY_PATH": str(cert_dir / "api.key"),
    }, monkeypatch)
    cfg = load_or_raise()
    import ssl as _ssl
    assert cfg.uvicorn_kwargs()["ssl_cert_reqs"] == _ssl.CERT_REQUIRED


def test_partial_service_pair_does_not_break_load(cert_dir, monkeypatch):
    """A service pair with only the cert (missing key) should resolve to None."""
    _set_env({
        "TOKENDNA_ENV": "dev",
        "TLS_CA_CERT_PATH": str(cert_dir / "ca.crt"),
        "TLS_API_CERT_PATH": str(cert_dir / "api.crt"),
        "TLS_API_KEY_PATH": str(cert_dir / "api.key"),
        "TLS_REDIS_CERT_PATH": str(cert_dir / "redis.crt"),
    }, monkeypatch)
    monkeypatch.delenv("TLS_REDIS_KEY_PATH", raising=False)
    cfg = load()
    assert cfg.redis is None  # no key path → no pair
    # Other services unaffected
    assert cfg.api is not None and cfg.api.exists


def test_mtls_pair_exists_returns_false_when_files_missing(tmp_path):
    pair = MTLSPair(
        cert_path=tmp_path / "missing.crt",
        key_path=tmp_path / "missing.key",
    )
    assert pair.exists is False
