#!/usr/bin/env python3
"""
CEYO Protocol — standalone artifact verifier (tools wrapper)

Verifies a sealed artifact envelope using the ceyo_verify package,
which has no dependency on the ceyo SDK. Only requires:
    pip install cryptography rfc8785

Usage:
    python3 tools/ceyo_verify.py <sealed_artifact.json> <public_key.pem>

Or use the package directly (equivalent):
    python -m ceyo_verify <sealed_artifact.json> <public_key.pem>
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root without installing
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ceyo_verify import verify_artifact  # noqa: E402
from ceyo_verify.verifier import load_artifact, load_pubkey  # noqa: E402


def verify(artifact_path: str, pubkey_path: str) -> bool:
    """Verify a sealed CEYO artifact. Returns True on success, False on failure."""
    artifact = load_artifact(artifact_path)
    pub_pem = load_pubkey(pubkey_path)

    result = verify_artifact(artifact, pub_pem)

    for msg in result.passed:
        print(f"PASS: {msg}")
    for msg in result.failed:
        print(f"FAIL: {msg}")

    status = "PASSED" if result.ok else "FAILED"
    print(f"\nVerification {status}")
    return result.ok


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sealed_artifact.json> <public_key.pem>")
        sys.exit(1)

    success = verify(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
