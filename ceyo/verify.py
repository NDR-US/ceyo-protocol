"""Artifact verification for CEYO Protocol."""

from __future__ import annotations

import hashlib
import hmac
import json
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
        return (
            f"VerificationResult({status}, "
            f"passed={len(self.passed)}, failed={len(self.failed)})"
        )


def _canonicalize_for_verify(value: Any, scheme: str) -> bytes:
    """Canonicalize using exactly the suite declared by the artifact."""
    if scheme == "RFC8785":
        try:
            import rfc8785
        except ImportError as exc:
            raise RuntimeError(
                "Artifact declares RFC8785 but the rfc8785 package is unavailable"
            ) from exc
        return rfc8785.dumps(value)

    if scheme == "deterministic-json-fallback":
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    raise RuntimeError(f"Unsupported canonicalization scheme: {scheme!r}")


def _load_p256_key(
    public_key_pem: bytes,
    result: VerificationResult,
) -> ec.EllipticCurvePublicKey | None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        result._fail(f"Key load: {exc}")
        return None

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        result._fail(
            f"Key type: expected ECDSA, got {type(public_key).__name__}"
        )
        return None

    if not isinstance(public_key.curve, ec.SECP256R1):
        result._fail(
            f"Key curve: expected secp256r1 (P-256), got {public_key.curve.name!r}"
        )
        return None

    return public_key


def _verify_fingerprint(
    key_ref: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
) -> bool:
    fingerprint = key_ref.get("public_key_fingerprint")
    if not isinstance(fingerprint, dict) or "value_b64u" not in fingerprint:
        result._fail("Key fingerprint missing")
        return False

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual = hashlib.sha256(public_der).digest()

    try:
        expected = b64u_decode(fingerprint["value_b64u"])
    except (TypeError, ValueError) as exc:
        result._fail(f"Fingerprint decode: {exc}")
        return False

    if not hmac.compare_digest(actual, expected):
        result._fail("Key fingerprint mismatch")
        return False

    result._pass("Key fingerprint matches")
    return True


def _is_v2_shape(artifact: dict[str, Any]) -> bool:
    """Treat any envelope containing ``protected`` as a v2 candidate."""
    return "protected" in artifact


def _verify_v2(
    artifact: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
    *,
    check_fingerprint: bool,
) -> VerificationResult:
    protected = artifact.get("protected")
    integrity = artifact.get("integrity")
    if not isinstance(protected, dict) or not isinstance(integrity, dict):
        result._fail("Malformed v2 envelope")
        return result

    if protected.get("product") != "CEYO":
        result._fail("Unsupported product")
        return result
    if protected.get("protocol_version") != "2.0":
        result._fail(
            f"Unsupported protocol version: {protected.get('protocol_version')!r}"
        )
        return result
    if protected.get("artifact_schema") != {
        "name": "ceyo.artifact",
        "version": "1.0",
    }:
        result._fail("Unsupported artifact schema")
        return result

    canonicalization_suite = protected.get("canonicalization_suite")
    signing_suite = protected.get("signing_suite")
    key_reference = protected.get("key_reference")

    if canonicalization_suite != {
        "scheme": "RFC8785",
        "version": "1.0",
    }:
        result._fail("Unsupported protocol-v2 canonicalization suite")
        return result

    if signing_suite != {
        "alg": "ECDSA-P256-SHA256",
        "format": "DER",
        "hash": "SHA-256",
    }:
        result._fail("Unsupported signing suite")
        return result

    if not isinstance(key_reference, dict):
        result._fail("Key reference missing")
        return result

    digest_block = integrity.get("digest")
    signature_block = integrity.get("signature")
    if not isinstance(digest_block, dict) or not isinstance(signature_block, dict):
        result._fail("Malformed integrity block")
        return result
    if digest_block.get("alg") != "SHA-256":
        result._fail("Unsupported digest algorithm")
        return result
    if digest_block.get("covers") != "canonical(protected)":
        result._fail("Unsupported digest scope")
        return result
    if signature_block.get("alg") != "ECDSA-P256-SHA256":
        result._fail("Unsupported signature algorithm")
        return result
    if signature_block.get("format") != "DER":
        result._fail("Unsupported signature format")
        return result
    if signature_block.get("covers") != "sha256(canonical(protected))":
        result._fail("Unsupported signature scope")
        return result

    try:
        canonical_bytes = _canonicalize_for_verify(protected, "RFC8785")
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result

    actual_digest = hashlib.sha256(canonical_bytes).digest()
    try:
        expected_digest = b64u_decode(digest_block["value_b64u"])
    except (KeyError, TypeError, ValueError) as exc:
        result._fail(f"Digest decode: {exc}")
        return result

    if not hmac.compare_digest(actual_digest, expected_digest):
        result._fail("Hash mismatch")
        return result
    result._pass("Hash matches")

    try:
        signature = b64u_decode(signature_block["value_b64u"])
        public_key.verify(
            signature,
            actual_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        result._fail(f"Signature invalid: {exc}")
        return result
    result._pass("Signature valid")

    if check_fingerprint and not _verify_fingerprint(
        key_reference,
        public_key,
        result,
    ):
        return result

    return result


def _verify_v1(
    artifact: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
    *,
    check_fingerprint: bool,
) -> VerificationResult:
    if artifact.get("product") != "CEYO" or artifact.get("envelope_version") != "1.0":
        result._fail("Unsupported legacy envelope")
        return result

    body = artifact.get("body")
    canonicalization = artifact.get("canonicalization")
    integrity = artifact.get("integrity")
    key_reference = artifact.get("key_reference")
    if (
        not isinstance(body, dict)
        or not isinstance(canonicalization, dict)
        or not isinstance(integrity, dict)
        or not isinstance(key_reference, dict)
    ):
        result._fail("Malformed legacy v1 envelope")
        return result

    if canonicalization.get("scope") != "body":
        result._fail("Unsupported legacy canonicalization scope")
        return result

    hash_block = integrity.get("hash")
    signature_block = integrity.get("sig")
    if not isinstance(hash_block, dict) or not isinstance(signature_block, dict):
        result._fail("Malformed legacy integrity block")
        return result
    if hash_block.get("alg") != "SHA-256":
        result._fail("Unsupported legacy digest algorithm")
        return result
    if signature_block.get("alg") != "ECDSA-P256-SHA256":
        result._fail("Unsupported legacy signature algorithm")
        return result
    if signature_block.get("format") != "DER":
        result._fail("Unsupported legacy signature format")
        return result

    try:
        canonical_bytes = _canonicalize_for_verify(
            body,
            str(canonicalization.get("scheme")),
        )
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result

    actual_digest = hashlib.sha256(canonical_bytes).digest()
    try:
        expected_digest = b64u_decode(hash_block["value_b64u"])
    except (KeyError, TypeError, ValueError) as exc:
        result._fail(f"Hash decode: {exc}")
        return result

    if not hmac.compare_digest(actual_digest, expected_digest):
        result._fail("Hash mismatch")
        return result
    result._pass("Hash matches")

    try:
        signature = b64u_decode(signature_block["value_b64u"])
        public_key.verify(
            signature,
            actual_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        result._fail(f"Signature invalid: {exc}")
        return result
    result._pass("Signature valid")

    if check_fingerprint and not _verify_fingerprint(
        key_reference,
        public_key,
        result,
    ):
        return result

    result._pass(
        "Legacy v1 scope: metadata outside body was not signature-bound"
    )
    return result


def verify_artifact(
    artifact: dict[str, Any],
    public_key_pem: bytes,
    *,
    check_schema: bool = True,
    check_fingerprint: bool = True,
) -> VerificationResult:
    """Verify a CEYO v2 artifact or a legacy-v1 artifact.

    Basic artifact validity is derived from authenticated artifact content.
    Receipts, revocation state, trust anchors, and external time evidence are
    evaluated separately by higher-level trust profiles.
    """
    result = VerificationResult()

    if not isinstance(artifact, dict):
        result._fail("Artifact must be an object")
        return result

    if check_schema:
        errors = validate_envelope(artifact)
        if errors:
            for error in errors:
                result._fail(f"Schema: {error}")
            return result
        result._pass("Schema valid")

    public_key = _load_p256_key(public_key_pem, result)
    if public_key is None:
        return result

    if _is_v2_shape(artifact):
        return _verify_v2(
            artifact,
            public_key,
            result,
            check_fingerprint=check_fingerprint,
        )

    return _verify_v1(
        artifact,
        public_key,
        result,
        check_fingerprint=check_fingerprint,
    )
