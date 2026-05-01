from __future__ import annotations

import pytest

from modules.security.field_crypto import (
    FieldCrypto,
    FieldCryptoError,
    generate_key,
    reset_engine_for_tests,
)


@pytest.fixture(autouse=True)
def _clear_singleton():
    reset_engine_for_tests()
    yield
    reset_engine_for_tests()


# ── Basic round-trips ────────────────────────────────────────────────────────


def test_round_trip_string(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    engine = FieldCrypto.from_env()
    enc = engine.encrypt("agent-secret-baseline")
    assert enc.startswith("v1:")
    assert engine.decrypt(enc) == "agent-secret-baseline"


def test_round_trip_bytes_utf8(monkeypatch):
    """Bytes input is supported as long as it decodes back as UTF-8 — the
    fields this module encrypts (JSON blobs, fingerprints, signal payloads)
    are all UTF-8 by construction."""
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    engine = FieldCrypto.from_env()
    enc = engine.encrypt("agent-fingerprint-α-Ω".encode("utf-8"))
    assert engine.decrypt(enc) == "agent-fingerprint-α-Ω"


def test_empty_string_passes_through(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    engine = FieldCrypto.from_env()
    assert engine.encrypt("") == ""
    assert engine.encrypt(None) == ""
    assert engine.decrypt("") == ""
    assert engine.decrypt(None) == ""


def test_is_encrypted(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    engine = FieldCrypto.from_env()
    enc = engine.encrypt("hello")
    assert engine.is_encrypted(enc) is True
    assert engine.is_encrypted("plaintext") is False
    assert engine.is_encrypted("") is False


# ── Key rotation ─────────────────────────────────────────────────────────────


def test_versioned_keyring_decrypts_old_ciphertext(monkeypatch):
    k1, k2 = generate_key(), generate_key()
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1},v2:{k2}")
    monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "1")

    # Issued under v1
    eng_old = FieldCrypto.from_env()
    old_ct = eng_old.encrypt("session-baseline-2025")
    assert old_ct.startswith("v1:")

    # Now rotate active to v2 — old cipher must still decrypt
    monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "2")
    eng_new = FieldCrypto.from_env()
    new_ct = eng_new.encrypt("session-baseline-2026")
    assert new_ct.startswith("v2:")

    # Both readable from the v2-active engine
    assert eng_new.decrypt(old_ct) == "session-baseline-2025"
    assert eng_new.decrypt(new_ct) == "session-baseline-2026"


def test_reencrypt_promotes_to_active_version(monkeypatch):
    k1, k2 = generate_key(), generate_key()
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1},v2:{k2}")
    monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "2")
    eng = FieldCrypto.from_env()

    # Hand-craft a v1 ciphertext by transiently switching active
    monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "1")
    eng_v1 = FieldCrypto.from_env()
    old = eng_v1.encrypt("rotate-me")
    assert old.startswith("v1:")

    # Re-encrypt via the v2-active engine
    promoted = eng.reencrypt(old)
    assert promoted.startswith("v2:")
    assert eng.decrypt(promoted) == "rotate-me"


def test_decrypt_unknown_version_raises(monkeypatch):
    k1 = generate_key()
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1}")
    eng = FieldCrypto.from_env()
    forged = "v9:Z3M9PQ=="
    with pytest.raises(FieldCryptoError) as exc:
        eng.decrypt(forged)
    assert "v9" in str(exc.value)


def test_decrypt_missing_prefix_raises(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    eng = FieldCrypto.from_env()
    with pytest.raises(FieldCryptoError) as exc:
        eng.decrypt("nope-not-versioned")
    assert "version prefix" in str(exc.value)


def test_decrypt_tampered_ciphertext_raises(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEY", generate_key())
    eng = FieldCrypto.from_env()
    enc = eng.encrypt("genuine")
    # Flip a character inside the token (leave the prefix intact)
    head, body = enc.split(":", 1)
    flipped_char = "A" if body[5] != "A" else "B"
    tampered = f"{head}:{body[:5]}{flipped_char}{body[6:]}"
    with pytest.raises(FieldCryptoError):
        eng.decrypt(tampered)


# ── Construction failure modes ───────────────────────────────────────────────


def test_no_keys_raises(monkeypatch):
    for v in ("FIELD_CRYPTO_KEY", "FIELD_CRYPTO_KEYRING", "FIELD_CRYPTO_ACTIVE_VERSION"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(FieldCryptoError):
        FieldCrypto.from_env()


def test_active_version_missing_raises(monkeypatch):
    k1 = generate_key()
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1}")
    monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "5")
    with pytest.raises(FieldCryptoError) as exc:
        FieldCrypto.from_env()
    assert "v5" in str(exc.value) or "ACTIVE_VERSION=5" in str(exc.value)


def test_malformed_keyring_entry_raises(monkeypatch):
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", "v1NOCOLON")
    with pytest.raises(FieldCryptoError):
        FieldCrypto.from_env()


def test_keyring_versions_returns_sorted(monkeypatch):
    k1, k2, k3 = generate_key(), generate_key(), generate_key()
    monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v3:{k3},v1:{k1},v2:{k2}")
    eng = FieldCrypto.from_env()
    assert eng.keyring_versions() == [1, 2, 3]
    # active defaults to highest
    assert eng.active_version == 3
