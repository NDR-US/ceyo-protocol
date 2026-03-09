#!/usr/bin/env python3
"""
CEYO Protocol — Sealing tool

Reads:  example_artifact/sample_record.json
Writes: example_artifact/sealed_artifact.json
        example_artifact/public_key.pem
        example_artifact/private_key.pem  (should be ignored by .gitignore)

Output envelope follows docs/artifact-schema.json:
  body → canonicalization → integrity → key_reference

Signature: ECDSA P-256 over SHA-256(canonical(body))
Canonicalization: RFC 8785 (JCS) if available; otherwise a deterministic fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

from ceyo.crypto import b64u, b64u_decode, canonicalize, sha256
from ceyo.keys import LocalKeyProvider
from ceyo.seal import seal_body

ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "example_artifact"

RECORD_PATH = EXAMPLE_DIR / "sample_record.json"
SEALED_PATH = EXAMPLE_DIR / "sealed_artifact.json"
PRIVKEY_PATH = EXAMPLE_DIR / "private_key.pem"
PUBKEY_PATH = EXAMPLE_DIR / "public_key.pem"


def main() -> None:
    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    if not RECORD_PATH.exists():
        raise FileNotFoundError(f"Missing {RECORD_PATH}. Create it first.")

    body = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    key_provider = LocalKeyProvider(PRIVKEY_PATH, PUBKEY_PATH)
    sealed = seal_body(body, key_provider, validate=False)

    SEALED_PATH.write_text(
        json.dumps(sealed, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Wrote: {SEALED_PATH}")
    print(f"Wrote: {PUBKEY_PATH}")
    print(f"Private key (should be ignored): {PRIVKEY_PATH}")


if __name__ == "__main__":
    main()
