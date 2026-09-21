#!/usr/bin/env python3
"""Generate a protocol-v2 CEYO example artifact.

Reads ``example_artifact/sample_record.json`` and writes a sealed artifact plus
local public/private key files for development use. The private key path is
expected to remain ignored by version control.

Protocol v2 signs SHA-256(RFC8785-or-declared-canonicalization(protected)) via
the normal ``ceyo.seal.seal_body`` implementation. The generated artifact has
the top-level shape ``{protected, integrity, receipts}``.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    artifact = seal_body(body, key_provider, validate=False)

    SEALED_PATH.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Wrote: {SEALED_PATH}")
    print(f"Wrote: {PUBKEY_PATH}")
    print(f"Private key (should remain uncommitted): {PRIVKEY_PATH}")


if __name__ == "__main__":
    main()
