#!/usr/bin/env python3
"""
CEYO Protocol — Artifact verifier

Reads a sealed artifact envelope and verifies:
  1. Canonicalize the body using the declared scheme
  2. Recompute SHA-256 hash and compare to integrity.hash.value_b64u
  3. Validate ECDSA-P256 signature against the public key

Usage:
    python3 tools/ceyo_verify.py example_artifact/sealed_artifact.json example_artifact/public_key.pem
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    import rfc8785
    HAS_RFC8785 = True
except ImportError:
    HAS_RFC8785 = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature


def b64u_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding as needed."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def canonicalize(obj: Any, scheme: str) -> bytes:
    if scheme == "RFC8785":
        if not HAS_RFC8785:
            print("WARNING: Artifact declares RFC8785 but rfc8785 is not installed; using fallback")
        else:
            return rfc8785.dumps(obj)

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify(artifact_path: str, pubkey_path: str) -> bool:
    """Verify a sealed CEYO artifact. Returns True on success, False on failure."""
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    pub_pem = Path(pubkey_path).read_bytes()

    pub_key = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        print(f"FAIL: Expected ECDSA public key, got {type(pub_key).__name__}")
        return False

    body = artifact["body"]
    canon_section = artifact["canonicalization"]
    integrity = artifact["integrity"]

    # Step 1: Canonicalize
    scheme = canon_section["scheme"]
    canonical_bytes = canonicalize(body, scheme)

    # Step 2: Recompute hash and compare
    expected_hash = b64u_decode(integrity["hash"]["value_b64u"])
    actual_hash = hashlib.sha256(canonical_bytes).digest()

    if actual_hash != expected_hash:
        print("FAIL: Hash mismatch")
        print(f"  Expected: {integrity['hash']['value_b64u']}")
        print(f"  Got:      {base64.urlsafe_b64encode(actual_hash).decode().rstrip('=')}")
        return False

    print("PASS: Hash matches")

    # Step 3: Verify signature
    sig_bytes = b64u_decode(integrity["sig"]["value_b64u"])

    try:
        pub_key.verify(sig_bytes, actual_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        print("FAIL: Signature invalid")
        return False

    print("PASS: Signature valid")

    # Optional: Verify public key fingerprint
    key_ref = artifact.get("key_reference")
    if key_ref and "public_key_fingerprint" in key_ref:
        pub_der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_fp = b64u_decode(key_ref["public_key_fingerprint"]["value_b64u"])
        actual_fp = hashlib.sha256(pub_der).digest()
        if actual_fp != expected_fp:
            print("FAIL: Public key fingerprint mismatch")
            return False
        print("PASS: Key fingerprint matches")

    print("\nVerification PASSED")
    return True


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sealed_artifact.json> <public_key.pem>")
        sys.exit(1)

    success = verify(sys.argv[1], sys.argv[2])
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
