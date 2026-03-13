"""Artifact verification for CEYO Protocol."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ceyo.crypto import b64u_decode
from ceyo.schema import validate_envelope


class VerificationResult:
    """Result of an artifact verification."""

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[str] = []

    @property
    def ok(self) -> bool:
        return len(self.failed) == 0

    def _pass(self, msg: str) -> None:
        self.passed.append(msg)

    def _fail(self, msg: str) -> None:
        self.failed.append(msg)

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        status = "PASSED" if self.ok else "FAILED"
        return f"VerificationResult({status}, passed={len(self.passed)}, failed={len(self.failed)})"


def _canonicalize_for_verify(body: Any, scheme: str) -> bytes:
    """Canonicalize body using the scheme declared in the envelope.

    Raises RuntimeError if the declared scheme is unavailable.
    """
    if scheme == "RFC8785":
        try:
            import rfc8785
        except ImportError:
            raise RuntimeError(
                "Artifact declares canonicalization scheme 'RFC8785' but the "
                "'rfc8785' package is not installed. Install it to verify this artifact."
            )
        return rfc8785.dumps(body)

    import json
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_artifact(
    artifact: dict[str, Any],
    public_key_pem: bytes,
    *,
    check_schema: bool = True,
    check_fingerprint: bool = True,
) -> VerificationResult:
    """Verify a sealed CEYO artifact envelope.

    Args:
        artifact: The sealed artifact dict.
        public_key_pem: Public key PEM bytes.
        check_schema: Whether to validate envelope schema.
        check_fingerprint: Whether to verify key fingerprint.

    Returns:
        VerificationResult with pass/fail details.
    """
    result = VerificationResult()

    # Step 0: Schema validation
    if check_schema:
        errors = validate_envelope(artifact)
        if errors:
            for e in errors:
                result._fail(f"Schema: {e}")
            return result
        result._pass("Schema valid")

    # Step 1: Load public key
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        result._fail(f"Key load: {exc}")
        return result

    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        result._fail(f"Key type: expected ECDSA, got {type(pub_key).__name__}")
        return result

    if not isinstance(pub_key.curve, ec.SECP256R1):
        result._fail(
            f"Key curve: expected secp256r1 (P-256), got {pub_key.curve.name!r}"
        )
        return result

    # Step 2: Canonicalize and hash
    body = artifact["body"]
    scheme = artifact["canonicalization"]["scheme"]

    try:
        canonical_bytes = _canonicalize_for_verify(body, scheme)
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result

    actual_hash = hashlib.sha256(canonical_bytes).digest()
    expected_hash = b64u_decode(artifact["integrity"]["hash"]["value_b64u"])

    if not hmac.compare_digest(actual_hash, expected_hash):
        result._fail("Hash mismatch")
        return result
    result._pass("Hash matches")

    # Step 3: Verify signature
    sig_bytes = b64u_decode(artifact["integrity"]["sig"]["value_b64u"])
    try:
        pub_key.verify(sig_bytes, actual_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        result._fail("Signature invalid")
        return result
    result._pass("Signature valid")

    # Step 4: Verify key fingerprint
    if check_fingerprint:
        key_ref = artifact.get("key_reference")
        if key_ref and "public_key_fingerprint" in key_ref:
            pub_der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            expected_fp = b64u_decode(key_ref["public_key_fingerprint"]["value_b64u"])
            actual_fp = hashlib.sha256(pub_der).digest()
            if not hmac.compare_digest(actual_fp, expected_fp):
                result._fail("Key fingerprint mismatch")
                return result
            result._pass("Key fingerprint matches")

    return result
