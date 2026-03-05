#!/usr/bin/env python3
"""
CEYO Protocol — Sealing demo

Reads:  example_artifact/sample_record.json
Writes: example_artifact/sealed_artifact.json
       example_artifact/sample_signature.json
       example_artifact/public_key.pem
       example_artifact/private_key.pem  (should be ignored by .gitignore)

Signature: ECDSA P-256 over SHA-256(canonical_bytes)
Canonicalization: RFC 8785 (JCS) if available; otherwise a deterministic fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict

# Optional RFC 8785 canonicalization (recommended)
try:
    import rfc8785  # pip install rfc8785
    HAS_RFC8785 = True
except Exception:
    HAS_RFC8785 = False

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "example_artifact"

RECORD_PATH = EXAMPLE_DIR / "sample_record.json"
SEALED_PATH = EXAMPLE_DIR / "sealed_artifact.json"
SIG_PATH = EXAMPLE_DIR / "sample_signature.json"

PRIVKEY_PATH = EXAMPLE_DIR / "private_key.pem"
PUBKEY_PATH = EXAMPLE_DIR / "public_key.pem"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


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


def load_or_create_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    if PRIVKEY_PATH.exists():
        priv = serialization.load_pem_private_key(PRIVKEY_PATH.read_bytes(), password=None)
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
    PUBKEY_PATH.write_bytes(pub_pem)
    return priv, PRIVKEY_PATH.read_bytes(), pub_pem


def main() -> None:
    EXAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    if not RECORD_PATH.exists():
        raise FileNotFoundError(f"Missing {RECORD_PATH}. Create it first.")

    record: Dict[str, Any] = json.loads(RECORD_PATH.read_text(encoding="utf-8"))

    canonical_bytes = canonicalize(record)
    digest = sha256(canonical_bytes)

    priv, _priv_pem, pub_pem = load_or_create_keypair()

    signature = priv.sign(digest, ec.ECDSA(hashes.SHA256()))

    sealed = {
        "schema_version": "1.0",
        "canonicalization": "RFC8785" if HAS_RFC8785 else "deterministic-json-fallback",
        "hash": {"alg": "sha256", "value_b64u": b64u(digest)},
        "signature": {"alg": "ecdsa-p256-sha256", "value_b64u": b64u(signature)},
        "public_key": {"format": "spki-pem", "value_pem": pub_pem.decode("utf-8")},
        "record": record,
    }

    SEALED_PATH.write_text(json.dumps(sealed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    SIG_PATH.write_text(
        json.dumps(
            {
                "hash_alg": "sha256",
                "hash_b64u": b64u(digest),
                "sig_alg": "ecdsa-p256-sha256",
                "sig_b64u": b64u(signature),
                "canonicalization": sealed["canonicalization"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Wrote: {SEALED_PATH}")
    print(f"Wrote: {SIG_PATH}")
    print(f"Wrote: {PUBKEY_PATH}")
    print(f"Private key (should be ignored): {PRIVKEY_PATH}")
    if not HAS_RFC8785:
        print("Note: Install rfc8785 for strict RFC 8785 canonicalization: pip install rfc8785")


if __name__ == "__main__":
    main()
