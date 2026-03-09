#!/usr/bin/env python3
"""
CEYO Protocol — Artifact verifier

Reads a sealed artifact envelope and verifies:
  1. Schema validation
  2. Canonicalize the body using the declared scheme
  3. Recompute SHA-256 hash and compare to integrity.hash.value_b64u
  4. Validate ECDSA-P256 signature against the public key

Usage:
    python3 tools/ceyo_verify.py example_artifact/sealed_artifact.json example_artifact/public_key.pem
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from repo root
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ceyo.verify import verify_artifact


def verify(artifact_path: str, pubkey_path: str) -> bool:
    """Verify a sealed CEYO artifact. Returns True on success, False on failure."""
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    pub_pem = Path(pubkey_path).read_bytes()

    result = verify_artifact(artifact, pub_pem)

    for msg in result.passed:
        print(f"PASS: {msg}")
    for msg in result.failed:
        print(f"FAIL: {msg}")

    if result.ok:
        print("\nVerification PASSED")
    else:
        print("\nVerification FAILED")

    return result.ok


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sealed_artifact.json> <public_key.pem>")
        sys.exit(1)

    success = verify(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
