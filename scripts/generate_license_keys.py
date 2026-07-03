#!/usr/bin/env python3
"""Generate the Ed25519 keypair that signs TokenDNA licenses.

The PRIVATE key stays on the vendor's machine (default ~/.tokendna/) and must
never be committed to any repository. The PUBLIC key is embedded in
modules/product/licensing.py via --inject.

Usage:
    python scripts/generate_license_keys.py                       # generate
    python scripts/generate_license_keys.py --inject modules/product/licensing.py
    python scripts/generate_license_keys.py --show                # print pubkey
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_KEY_PATH = pathlib.Path.home() / ".tokendna" / "license_signing_private.pem"


def load_or_create(path: pathlib.Path, force: bool) -> Ed25519PrivateKey:
    if path.exists() and not force:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{path} is not an Ed25519 private key")
        print(f"using existing private key: {path}")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 600
    print(f"NEW private key written: {path}  (chmod 600 — BACK THIS UP, never commit)")
    return key


def pubkey_hex(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def inject(target: pathlib.Path, hexkey: str) -> None:
    text = target.read_text(encoding="utf-8")
    new_text, n = re.subn(
        r'LICENSE_PUBLIC_KEY_HEX = "[^"]*"',
        f'LICENSE_PUBLIC_KEY_HEX = "{hexkey}"',
        text,
        count=1,
    )
    if n != 1:
        raise SystemExit(f"LICENSE_PUBLIC_KEY_HEX assignment not found in {target}")
    target.write_text(new_text, encoding="utf-8")
    print(f"public key injected into {target}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--key", type=pathlib.Path, default=DEFAULT_KEY_PATH)
    ap.add_argument("--inject", type=pathlib.Path, default=None,
                    help="path to licensing.py to receive the public key")
    ap.add_argument("--show", action="store_true", help="print public key hex only")
    ap.add_argument("--force", action="store_true", help="overwrite an existing key")
    args = ap.parse_args()

    key = load_or_create(args.key, args.force)
    hexkey = pubkey_hex(key)
    print(f"public key (hex): {hexkey}")
    if args.inject:
        inject(args.inject, hexkey)
    return 0


if __name__ == "__main__":
    sys.exit(main())
