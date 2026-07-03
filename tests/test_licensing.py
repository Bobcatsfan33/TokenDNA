"""Unit tests for the signed-license entitlement boundary."""
from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from modules.product import licensing


@pytest.fixture()
def signing_key(monkeypatch, tmp_path):
    """Ephemeral keypair; public half patched into the licensing module.
    Also isolates env/file state so tests never see a real license."""
    key = Ed25519PrivateKey.generate()
    pub_hex = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    monkeypatch.setattr(licensing, "LICENSE_PUBLIC_KEY_HEX", pub_hex)
    monkeypatch.delenv("TOKENDNA_LICENSE_KEY", raising=False)
    monkeypatch.delenv("TOKENDNA_LICENSE_ENFORCEMENT", raising=False)
    monkeypatch.setenv("TOKENDNA_LICENSE_FILE", str(tmp_path / "license.key"))
    licensing.reload()
    yield key
    licensing.reload()


def make_key(
    key: Ed25519PrivateKey,
    *,
    tier: str = "enterprise",
    exp_delta: int = 3600,
    features: tuple[str, ...] = (),
) -> str:
    now = int(time.time())
    payload = {
        "lid": "L-TEST-1",
        "sub": "cus_test123",
        "org": "TestCo",
        "tier": tier,
        "features": list(features),
        "iat": now,
        "exp": now + exp_delta,
    }
    payload_b64 = licensing._b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    sig = key.sign(f"{licensing.LICENSE_PREFIX}.{payload_b64}".encode("ascii"))
    return f"{licensing.LICENSE_PREFIX}.{payload_b64}.{licensing._b64url_encode(sig)}"


def test_valid_license_parses(signing_key):
    lic = licensing.parse_and_verify(make_key(signing_key, tier="pro"))
    assert lic.tier == "pro"
    assert lic.customer == "cus_test123"
    assert not lic.is_expired()


def test_tampered_payload_rejected(signing_key):
    raw = make_key(signing_key)
    prefix, payload_b64, sig_b64 = raw.split(".")
    forged = json.loads(licensing._b64url_decode(payload_b64))
    forged["tier"] = "enterprise"
    forged["exp"] = int(time.time()) + 10**9
    forged_b64 = licensing._b64url_encode(
        json.dumps(forged, separators=(",", ":")).encode()
    )
    with pytest.raises(licensing.LicenseError):
        licensing.parse_and_verify(f"{prefix}.{forged_b64}.{sig_b64}")


def test_expired_license_rejected(signing_key):
    with pytest.raises(licensing.LicenseError, match="expired"):
        licensing.parse_and_verify(make_key(signing_key, exp_delta=-10))


def test_wrong_key_rejected(signing_key):
    other = Ed25519PrivateKey.generate()
    with pytest.raises(licensing.LicenseError):
        licensing.parse_and_verify(make_key(other))


def test_malformed_key_rejected(signing_key):
    for bad in ("", "TDNA1", "TDNA1.abc", "NOPE.abc.def", "TDNA1.!!!.???"):
        with pytest.raises(licensing.LicenseError):
            licensing.parse_and_verify(bad)


def test_enforcement_defaults_off(signing_key):
    assert licensing.enforcement_mode() == "off"


def test_enforce_without_license_grants_community(signing_key, monkeypatch):
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    licensing.reload()
    assert licensing.enforcement_mode() == "enforce"
    assert licensing.licensed_tier() == "community"
    assert licensing.get_license() is None
    assert licensing.status()["state"] == "missing"


def test_enforce_with_license_grants_tier(signing_key, monkeypatch):
    raw = make_key(signing_key, tier="enterprise", features=("ent.blast_radius",))
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    monkeypatch.setenv("TOKENDNA_LICENSE_KEY", raw)
    licensing.reload()
    assert licensing.licensed_tier() == "enterprise"
    assert licensing.feature_granted("ent.blast_radius")
    assert not licensing.feature_granted("ent.mcp_gateway")
    assert licensing.status()["state"] == "valid"


def test_activate_persists_to_file(signing_key, monkeypatch, tmp_path):
    target = tmp_path / "license.key"
    monkeypatch.setenv("TOKENDNA_LICENSE_FILE", str(target))
    raw = make_key(signing_key, tier="pro")
    lic = licensing.activate(raw)
    assert lic.tier == "pro"
    assert target.read_text().strip() == raw
    licensing.reload()
    assert licensing.licensed_tier() == "pro"


def test_license_cap_applies_in_require_feature(signing_key, monkeypatch):
    """enforce + no license => enterprise-plan tenant loses ent.* access."""
    from modules.product import commercial_tiers as ct

    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "enforce")
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.COMMUNITY]
    assert state == "missing"

    # With a valid enterprise license the cap lifts.
    monkeypatch.setenv(
        "TOKENDNA_LICENSE_KEY", make_key(signing_key, tier="enterprise")
    )
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.ENTERPRISE]
    assert state is None

    # Mode off => never caps (back-compat default).
    monkeypatch.setenv("TOKENDNA_LICENSE_ENFORCEMENT", "off")
    monkeypatch.delenv("TOKENDNA_LICENSE_KEY", raising=False)
    licensing.reload()
    rank, state = ct._license_capped_rank(
        ct._TIER_RANK[ct.CommercialTier.ENTERPRISE], "ent.blast_radius"
    )
    assert rank == ct._TIER_RANK[ct.CommercialTier.ENTERPRISE]
    assert state is None
