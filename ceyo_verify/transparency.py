"""Standalone inclusion-proof verifier for the CEYO transparency log.

This module is **self-contained**: it only imports from the standard library,
``cryptography``, and (optionally) ``rfc8785``.  It does **not** import
from the ``ceyo`` SDK, so any third party can verify a CEYO transparency
log inclusion proof with nothing more than those packages.

Verification steps
------------------
1. Validate the proof structure (required fields, sensible values).
2. Recompute the Merkle leaf hash from ``proof["artifact_hash"]``.
3. Walk the sibling-hash path, hashing at each level.
4. Compare the computed root to ``proof["root_hash"]``.
5. *(Optional)* If a signed checkpoint is supplied:
   a. Load the checkpoint signing key and verify the ECDSA signature.
   b. Confirm ``proof["root_hash"]`` == ``checkpoint["root_hash"]``.
   c. Confirm ``proof["tree_size"]`` == ``checkpoint["tree_size"]``.
6. *(Optional)* If the original *artifact* envelope is supplied, verify
   that its canonical hash matches ``proof["artifact_hash"]``.

Usage
-----
::

    from ceyo_verify.transparency import verify_inclusion_proof

    result = verify_inclusion_proof(proof, checkpoint, checkpoint_pubkey_pem)
    print(result)   # VerificationResult(PASSED, ...)
    assert result.ok
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# ---------------------------------------------------------------------------
# Base64url helpers (no ceyo dependency)
# ---------------------------------------------------------------------------


def _b64u_decode(s: str) -> bytes:
    """Base64url decode with automatic padding reconstruction."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# Canonicalization (must match ceyo.crypto.canonicalize)
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> bytes:
    """Deterministic JSON serialization.

    Mirrors ``ceyo.crypto.canonicalize``: tries RFC 8785 (JCS) first,
    falls back to sorted-key compact JSON so the verifier works whether
    or not ``rfc8785`` is installed — as long as it matches the signer.
    """
    try:
        import rfc8785  # noqa: PLC0415
        return rfc8785.dumps(obj)
    except ImportError:
        pass
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Merkle tree primitives (must match ceyo/transparency_log.py)
# ---------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(artifact_hash_bytes: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + artifact_hash_bytes).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class VerificationResult:
    """Outcome of an inclusion-proof verification.

    Attributes:
        passed: List of check descriptions that passed.
        failed: List of check descriptions that failed.
        ok:     True when *failed* is empty.
    """

    def __init__(self) -> None:
        self.passed: list[str] = []
        self.failed: list[str] = []

    @property
    def ok(self) -> bool:
        """True if no checks failed."""
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


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def verify_inclusion_proof(
    proof: dict[str, Any],
    checkpoint: dict[str, Any] | None = None,
    checkpoint_pubkey_pem: bytes | None = None,
    *,
    artifact: dict[str, Any] | None = None,
) -> VerificationResult:
    """Verify a CEYO transparency log inclusion proof.

    Args:
        proof:
            Inclusion-proof dict produced by
            ``TransparencyLog.prove_inclusion()``.
        checkpoint:
            Optional signed checkpoint dict from
            ``TransparencyLog.checkpoint()``.  When provided the proof's
            root hash and tree size are checked against it, and the
            checkpoint's ECDSA signature is verified.
        checkpoint_pubkey_pem:
            PEM bytes of the ECDSA P-256 public key that signed
            *checkpoint*.  **Required** when *checkpoint* is provided.
        artifact:
            Optional original sealed artifact envelope dict.  When
            provided, its canonical SHA-256 hash is recomputed and
            compared to ``proof["artifact_hash"]``, binding the proof to
            the specific envelope.

    Returns:
        :class:`VerificationResult` — inspect ``.ok`` for a boolean
        outcome and ``.passed``/``.failed`` for step details.
    """
    result = VerificationResult()

    # ----------------------------------------------------------------
    # Step 1 — validate proof structure
    # ----------------------------------------------------------------
    required_fields = {
        "artifact_id", "artifact_hash", "leaf_index",
        "tree_size", "root_hash", "hashes",
    }
    missing = required_fields - proof.keys()
    if missing:
        for f in sorted(missing):
            result._fail(f"Proof missing field: {f}")
        return result

    leaf_index: int = proof["leaf_index"]
    tree_size: int = proof["tree_size"]
    expected_root_b64u: str = proof["root_hash"]

    if not isinstance(leaf_index, int) or leaf_index < 0:
        result._fail(
            f"leaf_index must be a non-negative integer, got {leaf_index!r}"
        )
        return result
    if not isinstance(tree_size, int) or tree_size <= 0:
        result._fail(
            f"tree_size must be a positive integer, got {tree_size!r}"
        )
        return result
    if leaf_index >= tree_size:
        result._fail(f"leaf_index {leaf_index} >= tree_size {tree_size}")
        return result

    try:
        artifact_hash_bytes = _b64u_decode(proof["artifact_hash"])
    except Exception as exc:
        result._fail(f"artifact_hash decode error: {exc}")
        return result

    result._pass("Proof structure valid")

    # ----------------------------------------------------------------
    # Step 2 — optional: verify artifact_hash against original envelope
    # ----------------------------------------------------------------
    if artifact is not None:
        computed_ah = hashlib.sha256(_canonicalize(artifact)).digest()
        expected_ah = artifact_hash_bytes
        if not hmac.compare_digest(computed_ah, expected_ah):
            result._fail(
                "Artifact hash mismatch: envelope does not match proof artifact_hash"
            )
            return result
        result._pass("Artifact hash matches envelope")

    # ----------------------------------------------------------------
    # Step 3 — recompute Merkle root from leaf + sibling path
    # ----------------------------------------------------------------
    current = _leaf_hash(artifact_hash_bytes)

    for i, step in enumerate(proof["hashes"]):
        direction = step.get("direction")
        if direction not in ("left", "right"):
            result._fail(
                f"hashes[{i}].direction must be 'left' or 'right', "
                f"got {direction!r}"
            )
            return result
        try:
            sibling = _b64u_decode(step["value_b64u"])
        except Exception as exc:
            result._fail(f"hashes[{i}].value_b64u decode error: {exc}")
            return result

        if direction == "right":
            current = _node_hash(current, sibling)
        else:
            current = _node_hash(sibling, current)

    try:
        expected_root_bytes = _b64u_decode(expected_root_b64u)
    except Exception as exc:
        result._fail(f"root_hash decode error: {exc}")
        return result

    if not hmac.compare_digest(current, expected_root_bytes):
        result._fail(
            "Inclusion proof invalid: computed root does not match proof root_hash"
        )
        return result
    result._pass("Merkle root matches")

    # ----------------------------------------------------------------
    # Step 4 — verify checkpoint (optional)
    # ----------------------------------------------------------------
    if checkpoint is None:
        return result

    if checkpoint_pubkey_pem is None:
        result._fail(
            "checkpoint_pubkey_pem is required when checkpoint is provided"
        )
        return result

    # 4a — load checkpoint signing key
    try:
        cp_pubkey = serialization.load_pem_public_key(checkpoint_pubkey_pem)
    except Exception as exc:
        result._fail(f"Checkpoint key load error: {exc}")
        return result

    if not isinstance(cp_pubkey, ec.EllipticCurvePublicKey):
        result._fail(
            f"Checkpoint key type: expected ECDSA EllipticCurvePublicKey, "
            f"got {type(cp_pubkey).__name__}"
        )
        return result

    # 4b — verify checkpoint structure
    required_cp = {
        "product", "type", "tree_size", "root_hash",
        "created_at", "sig", "key_reference",
    }
    missing_cp = required_cp - checkpoint.keys()
    if missing_cp:
        for f in sorted(missing_cp):
            result._fail(f"Checkpoint missing field: {f}")
        return result

    # 4c — reconstruct signed body and verify signature
    checkpoint_body = {
        "product": checkpoint["product"],
        "type": checkpoint["type"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
        "created_at": checkpoint["created_at"],
    }
    body_digest = hashlib.sha256(_canonicalize(checkpoint_body)).digest()

    sig_block = checkpoint.get("sig", {})
    try:
        sig_bytes = _b64u_decode(sig_block["value_b64u"])
    except Exception as exc:
        result._fail(f"Checkpoint signature decode error: {exc}")
        return result

    try:
        cp_pubkey.verify(
            sig_bytes,
            body_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        result._fail("Checkpoint signature invalid")
        return result
    result._pass("Checkpoint signature valid")

    # 4d — proof root_hash must match checkpoint root_hash
    if not hmac.compare_digest(
        proof["root_hash"].encode(), checkpoint["root_hash"].encode()
    ):
        result._fail(
            f"Proof root_hash {proof['root_hash']!r} does not match "
            f"checkpoint root_hash {checkpoint['root_hash']!r}"
        )
        return result
    result._pass("Proof root matches checkpoint root")

    # 4e — proof tree_size must match checkpoint tree_size
    if proof["tree_size"] != checkpoint["tree_size"]:
        result._fail(
            f"Proof tree_size {proof['tree_size']} does not match "
            f"checkpoint tree_size {checkpoint['tree_size']}"
        )
        return result
    result._pass("Proof tree_size matches checkpoint")

    return result
