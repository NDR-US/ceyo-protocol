"""Standalone CEYO artifact verifier.

This module intentionally imports no code from the ``ceyo`` SDK. It supports
current protocol-v2 protected envelopes and legacy protocol-v1 artifacts.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

_ARTIFACT_ID_V2 = re.compile(r"^ceyo_art_[0-9a-f]{26}$")
_B64U = re.compile(r"^[A-Za-z0-9_-]+$")
_DATETIME = re.compile(
    r"^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"T([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(\.\d{1,6})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$"
)
_EXPECTED_ARTIFACT_SCHEMA = {"name": "ceyo.artifact", "version": "1.0"}
_EXPECTED_CANONICALIZATION = {"scheme": "RFC8785", "version": "1.0"}
_EXPECTED_SIGNING_SUITE = {
    "alg": "ECDSA-P256-SHA256",
    "format": "DER",
    "hash": "SHA-256",
}


class VerificationResult:
    """Outcome of an artifact verification."""

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[str] = []

    @property
    def ok(self) -> bool:
        return not self.failed

    def _pass(self, message: str) -> None:
        self.passed.append(message)

    def _fail(self, message: str) -> None:
        self.failed.append(message)

    def __bool__(self) -> bool:
        return self.ok

    def __repr__(self) -> str:
        status = "PASSED" if self.ok else "FAILED"
        return (
            f"VerificationResult({status}, "
            f"passed={len(self.passed)}, failed={len(self.failed)})"
        )


def _b64u_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not _B64U.fullmatch(value):
        raise ValueError("invalid base64url value")
    raw = value.encode("ascii")
    padded = raw + b"=" * (-len(raw) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc


def _canonicalize(value: Any, scheme: str) -> bytes:
    """Reproduce the exact canonicalization suite required by the artifact."""
    if scheme == "RFC8785":
        try:
            import rfc8785
        except ImportError as exc:
            raise RuntimeError(
                "Artifact declares RFC8785 but the rfc8785 package is unavailable"
            ) from exc
        return rfc8785.dumps(value)

    # Legacy-v1 compatibility only. Protocol v2 rejects this scheme before
    # reaching canonicalization.
    if scheme == "deterministic-json-fallback":
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    raise RuntimeError(f"Unsupported canonicalization scheme: {scheme!r}")


def _check_exact_keys(
    value: dict[str, Any],
    *,
    required: set[str],
    prefix: str,
    allowed: set[str] | None = None,
) -> list[str]:
    errors: list[str] = []
    permitted = allowed if allowed is not None else required
    for field in sorted(required - value.keys()):
        errors.append(f"{prefix}{field}: missing required field")
    for field in sorted(value.keys() - permitted):
        errors.append(f"{prefix}{field}: unexpected field")
    return errors


def _check_fingerprint_block(value: Any, prefix: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{prefix}: expected object"]
    errors = _check_exact_keys(
        value,
        required={"alg", "value_b64u", "covers"},
        prefix=f"{prefix}.",
    )
    if value.get("alg") != "SHA-256":
        errors.append(f"{prefix}.alg: expected SHA-256")
    if value.get("covers") != "public_key_spki_der":
        errors.append(f"{prefix}.covers: expected public_key_spki_der")
    encoded = value.get("value_b64u")
    if not isinstance(encoded, str) or not _B64U.fullmatch(encoded):
        errors.append(f"{prefix}.value_b64u: invalid base64url")
    return errors


def _check_body(body: Any, prefix: str) -> list[str]:
    errors: list[str] = []
    if not isinstance(body, dict):
        return [f"{prefix}: expected object"]

    event = body.get("event")
    if not isinstance(event, dict):
        return [f"{prefix}.event: missing or expected object"]
    for field in ("event_id", "type", "occurred_at"):
        if field not in event:
            errors.append(f"{prefix}.event.{field}: missing required field")
        elif not isinstance(event[field], str):
            errors.append(f"{prefix}.event.{field}: expected string")

    occurred_at = event.get("occurred_at")
    if isinstance(occurred_at, str) and not _DATETIME.fullmatch(occurred_at):
        errors.append(f"{prefix}.event.occurred_at: invalid date-time")
    if "request_id" in event and not isinstance(event["request_id"], str):
        errors.append(f"{prefix}.event.request_id: expected string")

    policy = body.get("policy")
    if policy is not None:
        if not isinstance(policy, dict):
            errors.append(f"{prefix}.policy: expected object")
        else:
            for field in ("id", "version"):
                if field in policy and not isinstance(policy[field], str):
                    errors.append(f"{prefix}.policy.{field}: expected string")
            digest = policy.get("digest")
            if digest is not None:
                if not isinstance(digest, dict):
                    errors.append(f"{prefix}.policy.digest: expected object")
                else:
                    errors.extend(
                        _check_exact_keys(
                            digest,
                            required={"alg", "value_b64u", "covers"},
                            prefix=f"{prefix}.policy.digest.",
                        )
                    )
                    if digest.get("alg") != "SHA-256":
                        errors.append(f"{prefix}.policy.digest.alg: expected SHA-256")
                    encoded = digest.get("value_b64u")
                    if not isinstance(encoded, str) or not _B64U.fullmatch(encoded):
                        errors.append(
                            f"{prefix}.policy.digest.value_b64u: invalid base64url"
                        )
                    if not isinstance(digest.get("covers"), str):
                        errors.append(f"{prefix}.policy.digest.covers: expected string")

    if "disclosure_tier" in body and not isinstance(body["disclosure_tier"], str):
        errors.append(f"{prefix}.disclosure_tier: expected string")

    disclosure_policy = body.get("disclosure_policy")
    if disclosure_policy is not None:
        if not isinstance(disclosure_policy, dict):
            errors.append(f"{prefix}.disclosure_policy: expected object")
        else:
            for field in ("tier", "policy_id", "policy_version"):
                if field in disclosure_policy and not isinstance(
                    disclosure_policy[field], str
                ):
                    errors.append(
                        f"{prefix}.disclosure_policy.{field}: expected string"
                    )

    for field in ("capture", "environment"):
        if field in body and not isinstance(body[field], dict):
            errors.append(f"{prefix}.{field}: expected object")

    return errors


def _check_v2(artifact: dict[str, Any]) -> list[str]:
    errors = _check_exact_keys(
        artifact,
        required={"protected", "integrity", "receipts"},
        prefix="",
    )
    if errors:
        return errors

    protected = artifact["protected"]
    if not isinstance(protected, dict):
        return ["protected: expected object"]

    required_protected = {
        "product",
        "protocol_version",
        "artifact_schema",
        "artifact_id",
        "sealed_at",
        "canonicalization_suite",
        "signing_suite",
        "key_reference",
        "body",
    }
    errors.extend(
        _check_exact_keys(
            protected,
            required=required_protected,
            prefix="protected.",
        )
    )
    if protected.get("product") != "CEYO":
        errors.append("protected.product: expected 'CEYO'")
    if protected.get("protocol_version") != "2.0":
        errors.append("protected.protocol_version: expected '2.0'")
    if protected.get("artifact_schema") != _EXPECTED_ARTIFACT_SCHEMA:
        errors.append("protected.artifact_schema: unsupported schema")

    artifact_id = protected.get("artifact_id")
    if not isinstance(artifact_id, str) or not _ARTIFACT_ID_V2.fullmatch(artifact_id):
        errors.append("protected.artifact_id: invalid v2 artifact id")
    sealed_at = protected.get("sealed_at")
    if not isinstance(sealed_at, str) or not _DATETIME.fullmatch(sealed_at):
        errors.append("protected.sealed_at: invalid date-time")
    if protected.get("canonicalization_suite") != _EXPECTED_CANONICALIZATION:
        errors.append("protected.canonicalization_suite: unsupported suite")
    if protected.get("signing_suite") != _EXPECTED_SIGNING_SUITE:
        errors.append("protected.signing_suite: unsupported suite")

    key_reference = protected.get("key_reference")
    if not isinstance(key_reference, dict):
        errors.append("protected.key_reference: expected object")
    else:
        errors.extend(
            _check_exact_keys(
                key_reference,
                required={"registry", "key_id", "public_key_fingerprint"},
                allowed={
                    "registry",
                    "key_id",
                    "public_key_fingerprint",
                    "authority",
                },
                prefix="protected.key_reference.",
            )
        )
        if not isinstance(key_reference.get("registry"), str):
            errors.append("protected.key_reference.registry: expected string")
        if not isinstance(key_reference.get("key_id"), str):
            errors.append("protected.key_reference.key_id: expected string")
        errors.extend(
            _check_fingerprint_block(
                key_reference.get("public_key_fingerprint"),
                "protected.key_reference.public_key_fingerprint",
            )
        )
        if "authority" in key_reference and not isinstance(
            key_reference["authority"], dict
        ):
            errors.append("protected.key_reference.authority: expected object")

    errors.extend(_check_body(protected.get("body"), "protected.body"))

    integrity = artifact["integrity"]
    if not isinstance(integrity, dict):
        errors.append("integrity: expected object")
    else:
        errors.extend(
            _check_exact_keys(
                integrity,
                required={"digest", "signature"},
                prefix="integrity.",
            )
        )
        digest = integrity.get("digest")
        if not isinstance(digest, dict):
            errors.append("integrity.digest: expected object")
        else:
            errors.extend(
                _check_exact_keys(
                    digest,
                    required={"alg", "value_b64u", "covers"},
                    prefix="integrity.digest.",
                )
            )
            if digest.get("alg") != "SHA-256":
                errors.append("integrity.digest.alg: expected SHA-256")
            if digest.get("covers") != "canonical(protected)":
                errors.append("integrity.digest.covers: wrong scope")
            encoded = digest.get("value_b64u")
            if not isinstance(encoded, str) or not _B64U.fullmatch(encoded):
                errors.append("integrity.digest.value_b64u: invalid base64url")

        signature = integrity.get("signature")
        if not isinstance(signature, dict):
            errors.append("integrity.signature: expected object")
        else:
            errors.extend(
                _check_exact_keys(
                    signature,
                    required={"alg", "format", "value_b64u", "covers"},
                    prefix="integrity.signature.",
                )
            )
            if signature.get("alg") != "ECDSA-P256-SHA256":
                errors.append("integrity.signature.alg: unsupported")
            if signature.get("format") != "DER":
                errors.append("integrity.signature.format: expected DER")
            if signature.get("covers") != "sha256(canonical(protected))":
                errors.append("integrity.signature.covers: wrong scope")
            encoded = signature.get("value_b64u")
            if not isinstance(encoded, str) or not _B64U.fullmatch(encoded):
                errors.append("integrity.signature.value_b64u: invalid base64url")

    receipts = artifact["receipts"]
    if not isinstance(receipts, list):
        errors.append("receipts: expected array")
    elif any(not isinstance(receipt, dict) for receipt in receipts):
        errors.append("receipts: every entry must be an object")
    return errors


def _check_v1(artifact: dict[str, Any]) -> list[str]:
    required = {
        "product",
        "envelope_version",
        "artifact_schema",
        "artifact_id",
        "created_at",
        "body",
        "canonicalization",
        "integrity",
        "key_reference",
    }
    errors = _check_exact_keys(artifact, required=required, prefix="")
    if errors:
        return errors
    if artifact.get("product") != "CEYO":
        errors.append("product: expected 'CEYO'")
    if artifact.get("envelope_version") != "1.0":
        errors.append("envelope_version: expected '1.0'")
    if artifact.get("artifact_schema") != _EXPECTED_ARTIFACT_SCHEMA:
        errors.append("artifact_schema: unsupported schema")
    errors.extend(_check_body(artifact.get("body"), "body"))
    return errors


def _load_key(
    public_key_pem: bytes,
    result: VerificationResult,
) -> ec.EllipticCurvePublicKey | None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        result._fail(f"Key load: {exc}")
        return None
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        result._fail(f"Key type: expected ECDSA, got {type(public_key).__name__}")
        return None
    if not isinstance(public_key.curve, ec.SECP256R1):
        result._fail(
            f"Key curve: expected secp256r1 (P-256), got {public_key.curve.name!r}"
        )
        return None
    return public_key


def _check_fingerprint(
    key_reference: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
) -> bool:
    fingerprint = key_reference.get("public_key_fingerprint")
    if not isinstance(fingerprint, dict):
        result._fail("Key fingerprint missing")
        return False
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual = hashlib.sha256(public_der).digest()
    try:
        expected = _b64u_decode(fingerprint["value_b64u"])
    except (KeyError, TypeError, ValueError) as exc:
        result._fail(f"Fingerprint decode: {exc}")
        return False
    if not hmac.compare_digest(actual, expected):
        result._fail("Key fingerprint mismatch")
        return False
    result._pass("Key fingerprint matches")
    return True


def _verify_v2(
    artifact: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
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
    if protected.get("artifact_schema") != _EXPECTED_ARTIFACT_SCHEMA:
        result._fail("Unsupported artifact schema")
        return result
    if protected.get("canonicalization_suite") != _EXPECTED_CANONICALIZATION:
        result._fail("Unsupported protocol-v2 canonicalization suite")
        return result
    if protected.get("signing_suite") != _EXPECTED_SIGNING_SUITE:
        result._fail("Unsupported signing suite")
        return result

    key_reference = protected.get("key_reference")
    digest_block = integrity.get("digest")
    signature_block = integrity.get("signature")
    if not isinstance(key_reference, dict):
        result._fail("Key reference missing")
        return result
    if not isinstance(digest_block, dict) or not isinstance(signature_block, dict):
        result._fail("Malformed integrity block")
        return result
    if (
        digest_block.get("alg") != "SHA-256"
        or digest_block.get("covers") != "canonical(protected)"
    ):
        result._fail("Unsupported digest semantics")
        return result
    if (
        signature_block.get("alg") != "ECDSA-P256-SHA256"
        or signature_block.get("format") != "DER"
        or signature_block.get("covers") != "sha256(canonical(protected))"
    ):
        result._fail("Unsupported signature semantics")
        return result

    try:
        canonical = _canonicalize(protected, "RFC8785")
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result
    digest = hashlib.sha256(canonical).digest()
    try:
        expected_digest = _b64u_decode(digest_block["value_b64u"])
    except (KeyError, TypeError, ValueError) as exc:
        result._fail(f"Digest decode: {exc}")
        return result
    if not hmac.compare_digest(digest, expected_digest):
        result._fail("Hash mismatch")
        return result
    result._pass("Hash matches")

    try:
        signature = _b64u_decode(signature_block["value_b64u"])
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        result._fail(f"Signature invalid: {exc}")
        return result
    result._pass("Signature valid")

    if check_fingerprint and not _check_fingerprint(
        key_reference, public_key, result
    ):
        return result
    return result


def _verify_v1(
    artifact: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
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
        canonical = _canonicalize(body, str(canonicalization.get("scheme")))
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result
    digest = hashlib.sha256(canonical).digest()
    try:
        expected_digest = _b64u_decode(hash_block["value_b64u"])
    except (KeyError, TypeError, ValueError) as exc:
        result._fail(f"Hash decode: {exc}")
        return result
    if not hmac.compare_digest(digest, expected_digest):
        result._fail("Hash mismatch")
        return result
    result._pass("Hash matches")

    try:
        signature = _b64u_decode(signature_block["value_b64u"])
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        result._fail(f"Signature invalid: {exc}")
        return result
    result._pass("Signature valid")

    if check_fingerprint and not _check_fingerprint(
        key_reference, public_key, result
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
    """Verify a current v2 or legacy-v1 CEYO artifact."""
    result = VerificationResult()
    if not isinstance(artifact, dict):
        result._fail("Artifact must be an object")
        return result

    is_v2 = "protected" in artifact
    if check_schema:
        errors = _check_v2(artifact) if is_v2 else _check_v1(artifact)
        if errors:
            for error in errors:
                result._fail(f"Schema: {error}")
            return result
        result._pass("Schema valid")

    public_key = _load_key(public_key_pem, result)
    if public_key is None:
        return result

    if is_v2:
        return _verify_v2(
            artifact, public_key, result, check_fingerprint
        )
    return _verify_v1(
        artifact, public_key, result, check_fingerprint
    )


def load_artifact(path: str) -> dict[str, Any]:
    """Load one artifact JSON file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_pubkey(path: str) -> bytes:
    """Load one PEM-encoded public key file."""
    return Path(path).read_bytes()
