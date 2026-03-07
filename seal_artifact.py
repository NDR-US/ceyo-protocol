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

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

# Optional RFC 8785 canonicalization (recommended)
try:
    import rfc8785  # pip install rfc8785
    HAS_RFC8785 = True
except ImportError:
    HAS_RFC8785 = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "example_artifact"

RECORD_PATH = EXAMPLE_DIR / "sample_record.json"
SEALED_PATH = EXAMPLE_DIR / "sealed_artifact.json"

PRIVKEY_PATH = EXAMPLE_DIR / "private_key.pem"
PUBKEY_PATH = EXAMPLE_DIR / "public_key.pem"


def b64u(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding as needed."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def canonicalize(obj: Any) -> bytes:
    if HAS_RFC8785:
        return rfc8785.dumps(obj)

    # Deterministic fallback (NOT full RFC 8785): stable key order + compact separators.
    # Good enough for demo; for production, install rfc8785.
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_or_create_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    if PRIVKEY_PATH.exists():
        priv = serialization.load_pem_private_key(PRIVKEY_PATH.read_bytes(), password=None)
        if not isinstance(priv, ec.EllipticCurvePrivateKey):
            raise TypeError(f"Expected ECDSA private key, got {type(priv).__name__}")
    else:
        priv = ec.generate_private_key(ec.SECP256R1())
        PRIVKEY_PATH.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PUBKEY_PATH.write_bytes(pub_pem)
    return priv, pub_pem, pub_der


def main() -> None:
    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    if not RECORD_PATH.exists():
        raise FileNotFoundError(f"Missing {RECORD_PATH}. Create it first.")

    body: Dict[str, Any] = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    canonical_bytes = canonicalize(body)
    digest = sha256(canonical_bytes)

    priv, pub_pem, pub_der = load_or_create_keypair()

    signature = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    canon_scheme = "RFC8785" if HAS_RFC8785 else "deterministic-json-fallback"

    sealed = {
        "product": "CEYO",
        "envelope_version": "1.0",
        "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
        "artifact_id": f"ceyo_art_{uuid.uuid4().hex[:26]}",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "body": body,
        "canonicalization": {
            "scheme": canon_scheme,
            "version": "1.0",
            "scope": "body",
        },
        "integrity": {
            "hash": {
                "alg": "SHA-256",
                "value_b64u": b64u(digest),
                "covers": "canonical(body)",
            },
            "sig": {
                "alg": "ECDSA-P256-SHA256",
                "format": "DER",
                "value_b64u": b64u(signature),
                "covers": "canonical(body)",
            },
        },
        "key_reference": {
            "registry": "local",
            "key_id": "local:public_key.pem",
            "public_key_fingerprint": {
                "alg": "SHA-256",
                "value_b64u": b64u(sha256(pub_der)),
                "covers": "public_key_spki_der",
            },
        },
    }

    SEALED_PATH.write_text(json.dumps(sealed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Wrote: {SEALED_PATH}")
    print(f"Wrote: {PUBKEY_PATH}")
    print(f"Private key (should be ignored): {PRIVKEY_PATH}")
    if not HAS_RFC8785:
        print("Note: Install rfc8785 for strict RFC 8785 canonicalization: pip install rfc8785")


if __name__ == "__main__":
    main()
