"""Standalone inclusion-proof verifier for the CEYO transparency prototype.

The module has no dependency on the ``ceyo`` SDK. It verifies Merkle membership
relative to a supplied proof and, optionally, a signed checkpoint. A successful
check does not by itself establish checkpoint freshness, global log consistency,
or independently trusted time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

_MAX_PROOF_DEPTH = 63
_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


class VerificationResult:
    """Outcome of an inclusion-proof verification."""

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[str] = []

    @property
    def ok(self) -> bool:
        return len(self.failed) == 0

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
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base64url value")
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


def _canonicalize(value: Any) -> bytes:
    """Canonicalize transparency objects using the fixed RFC 8785 profile."""
    try:
        import rfc8785
    except ImportError as exc:
        raise RuntimeError(
            "CEYO transparency verification requires the rfc8785 package"
        ) from exc
    return rfc8785.dumps(value)


def _artifact_log_subject(artifact: dict[str, Any]) -> dict[str, Any]:
    """Return the stable subject used by the reference Merkle log."""
    if "protected" not in artifact:
        return artifact

    protected = artifact.get("protected")
    integrity = artifact.get("integrity")
    if not isinstance(protected, dict) or not isinstance(integrity, dict):
        raise ValueError("v2 artifact missing protected or integrity object")
    if protected.get("protocol_version") != "2.0":
        raise ValueError("unsupported protected-envelope protocol version")

    return {
        "protected": protected,
        "integrity": integrity,
    }


def _leaf_hash(artifact_hash_bytes: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + artifact_hash_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _load_checkpoint_key(
    checkpoint_pubkey_pem: bytes,
    result: VerificationResult,
) -> ec.EllipticCurvePublicKey | None:
    try:
        public_key = serialization.load_pem_public_key(checkpoint_pubkey_pem)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        result._fail(f"Checkpoint key load error: {exc}")
        return None

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        result._fail(
            "Checkpoint key type: expected ECDSA EllipticCurvePublicKey"
        )
        return None
    if not isinstance(public_key.curve, ec.SECP256R1):
        result._fail(
            f"Checkpoint key curve: expected secp256r1 (P-256), "
            f"got {public_key.curve.name!r}"
        )
        return None

    return public_key


def _verify_checkpoint_key_reference(
    checkpoint: dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    result: VerificationResult,
) -> bool:
    """Check descriptive checkpoint fingerprint consistency.

    Checkpoint format 1.0 keeps key_reference outside the signed checkpoint body,
    so the trusted key must come from the caller/profile rather than this field.
    """
    key_reference = checkpoint.get("key_reference")
    if not isinstance(key_reference, dict):
        result._fail("Checkpoint key_reference missing")
        return False
    fingerprint = key_reference.get("public_key_fingerprint")
    if not isinstance(fingerprint, dict) or "value_b64u" not in fingerprint:
        result._fail("Checkpoint key fingerprint missing")
        return False

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual = hashlib.sha256(public_der).digest()
    try:
        expected = _b64u_decode(fingerprint["value_b64u"])
    except (TypeError, ValueError) as exc:
        result._fail(f"Checkpoint fingerprint decode error: {exc}")
        return False

    if not hmac.compare_digest(actual, expected):
        result._fail("Checkpoint key fingerprint mismatch")
        return False

    result._pass("Checkpoint key fingerprint matches supplied key")
    return True


def verify_inclusion_proof(
    proof: dict[str, Any],
    checkpoint: dict[str, Any] | None = None,
    checkpoint_pubkey_pem: bytes | None = None,
    *,
    artifact: dict[str, Any] | None = None,
) -> VerificationResult:
    """Verify Merkle membership, optionally against a signed checkpoint."""
    result = VerificationResult()

    if not isinstance(proof, dict):
        result._fail("Proof must be an object")
        return result

    required_fields = {
        "artifact_id",
        "artifact_hash",
        "leaf_index",
        "tree_size",
        "root_hash",
        "hashes",
    }
    missing = required_fields - proof.keys()
    if missing:
        for field in sorted(missing):
            result._fail(f"Proof missing field: {field}")
        return result

    leaf_index = proof["leaf_index"]
    tree_size = proof["tree_size"]
    hashes_list = proof["hashes"]

    if not isinstance(leaf_index, int) or leaf_index < 0:
        result._fail("leaf_index must be a non-negative integer")
        return result
    if not isinstance(tree_size, int) or tree_size <= 0:
        result._fail("tree_size must be a positive integer")
        return result
    if leaf_index >= tree_size:
        result._fail(f"leaf_index {leaf_index} >= tree_size {tree_size}")
        return result
    if not isinstance(hashes_list, list):
        result._fail("Proof hashes must be a list")
        return result

    max_depth = math.ceil(math.log2(tree_size)) if tree_size > 1 else 0
    if len(hashes_list) > max_depth:
        result._fail(
            f"Proof has {len(hashes_list)} hash steps but tree_size {tree_size} "
            f"allows at most {max_depth}"
        )
        return result
    if len(hashes_list) > _MAX_PROOF_DEPTH:
        result._fail(
            f"Proof depth {len(hashes_list)} exceeds maximum {_MAX_PROOF_DEPTH}"
        )
        return result

    try:
        artifact_hash_bytes = _b64u_decode(proof["artifact_hash"])
        expected_root_bytes = _b64u_decode(proof["root_hash"])
    except (TypeError, ValueError) as exc:
        result._fail(f"Proof digest decode error: {exc}")
        return result

    result._pass("Proof structure valid")

    if artifact is not None:
        try:
            subject = _artifact_log_subject(artifact)
            computed = hashlib.sha256(_canonicalize(subject)).digest()
        except (ValueError, RuntimeError) as exc:
            result._fail(f"Artifact subject: {exc}")
            return result
        if not hmac.compare_digest(computed, artifact_hash_bytes):
            result._fail(
                "Artifact hash mismatch: artifact subject does not match proof"
            )
            return result
        result._pass("Artifact subject hash matches proof")

    current = _leaf_hash(artifact_hash_bytes)
    for index, step in enumerate(hashes_list):
        if not isinstance(step, dict):
            result._fail(f"hashes[{index}] must be an object")
            return result
        direction = step.get("direction")
        if direction not in {"left", "right"}:
            result._fail(f"hashes[{index}].direction invalid")
            return result
        try:
            sibling = _b64u_decode(step["value_b64u"])
        except (KeyError, TypeError, ValueError) as exc:
            result._fail(f"hashes[{index}] decode error: {exc}")
            return result
        current = (
            _node_hash(current, sibling)
            if direction == "right"
            else _node_hash(sibling, current)
        )

    if not hmac.compare_digest(current, expected_root_bytes):
        result._fail(
            "Inclusion proof invalid: computed root does not match proof root_hash"
        )
        return result
    result._pass("Merkle root matches")

    if checkpoint is None:
        return result
    if checkpoint_pubkey_pem is None:
        result._fail(
            "checkpoint_pubkey_pem is required when checkpoint is provided"
        )
        return result
    if not isinstance(checkpoint, dict):
        result._fail("Checkpoint must be an object")
        return result

    required_checkpoint = {
        "product",
        "type",
        "tree_size",
        "root_hash",
        "created_at",
        "sig",
        "key_reference",
    }
    missing_checkpoint = required_checkpoint - checkpoint.keys()
    if missing_checkpoint:
        for field in sorted(missing_checkpoint):
            result._fail(f"Checkpoint missing field: {field}")
        return result

    if checkpoint.get("product") != "CEYO":
        result._fail("Checkpoint product invalid")
        return result
    if checkpoint.get("type") != "transparency-checkpoint":
        result._fail("Checkpoint type invalid")
        return result

    signature_block = checkpoint.get("sig")
    if not isinstance(signature_block, dict):
        result._fail("Checkpoint sig block malformed")
        return result
    if signature_block.get("alg") != "ECDSA-P256-SHA256":
        result._fail("Checkpoint signature algorithm unsupported")
        return result
    if signature_block.get("format") != "DER":
        result._fail("Checkpoint signature format unsupported")
        return result
    if signature_block.get("covers") not in {
        "canonical(checkpoint_body)",
        "RFC8785(checkpoint_body)",
    }:
        result._fail("Checkpoint signature scope unsupported")
        return result

    public_key = _load_checkpoint_key(checkpoint_pubkey_pem, result)
    if public_key is None:
        return result

    checkpoint_body = {
        "product": checkpoint["product"],
        "type": checkpoint["type"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
        "created_at": checkpoint["created_at"],
    }
    try:
        body_digest = hashlib.sha256(_canonicalize(checkpoint_body)).digest()
    except RuntimeError as exc:
        result._fail(f"Checkpoint canonicalization: {exc}")
        return result

    try:
        signature = _b64u_decode(signature_block["value_b64u"])
        public_key.verify(
            signature,
            body_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        result._fail(f"Checkpoint signature invalid: {exc}")
        return result
    result._pass("Checkpoint signature valid")

    if not _verify_checkpoint_key_reference(checkpoint, public_key, result):
        return result

    try:
        checkpoint_root = _b64u_decode(checkpoint["root_hash"])
    except (TypeError, ValueError) as exc:
        result._fail(f"Checkpoint root decode error: {exc}")
        return result

    if not hmac.compare_digest(expected_root_bytes, checkpoint_root):
        result._fail("Proof root does not match checkpoint root")
        return result
    result._pass("Proof root matches checkpoint root")

    if proof["tree_size"] != checkpoint["tree_size"]:
        result._fail("Proof tree_size does not match checkpoint tree_size")
        return result
    result._pass("Proof tree_size matches checkpoint")

    return result
