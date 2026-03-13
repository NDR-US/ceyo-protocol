"""Standalone CEYO artifact verifier.

This module is self-contained: it imports only from the standard library,
``cryptography``, and ``rfc8785``. It reproduces the exact verification
steps that the CEYO SDK performs so that any third party can independently
confirm artifact integrity.

Verification steps
------------------
1. Validate the envelope schema (structure, required fields, const values).
2. Load the PEM public key and confirm it is ECDSA (EllipticCurvePublicKey).
3. Canonicalize ``artifact["body"]`` using the scheme declared in
   ``artifact["canonicalization"]["scheme"]``.
4. Recompute SHA-256 of the canonical bytes and compare (timing-safe) to
   ``artifact["integrity"]["hash"]["value_b64u"]``.
5. Verify the ECDSA-P256 DER signature in
   ``artifact["integrity"]["sig"]["value_b64u"]`` against the digest.
6. Optionally verify the public-key fingerprint stored in
   ``artifact["key_reference"]["public_key_fingerprint"]["value_b64u"]``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# ---------------------------------------------------------------------------
# Base64url helpers (no ceyo dependency)
# ---------------------------------------------------------------------------

def _b64u_decode(s: str) -> bytes:
    """Base64url decode with padding reconstruction."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# Canonicalization (no ceyo dependency)
# ---------------------------------------------------------------------------

def _canonicalize(body: Any, scheme: str) -> bytes:
    """Reproduce the canonicalization declared in the envelope.

    Args:
        body:   The artifact body object.
        scheme: Canonicalization scheme name from the envelope
                (e.g. ``"RFC8785"`` or ``"deterministic-json-fallback"``).

    Raises:
        RuntimeError: If the declared scheme is ``"RFC8785"`` but the
            ``rfc8785`` package is not installed.
    """
    if scheme == "RFC8785":
        try:
            import rfc8785  # noqa: PLC0415
        except ImportError:
            raise RuntimeError(
                "Artifact declares canonicalization scheme 'RFC8785' but the "
                "'rfc8785' package is not installed. "
                "Install it with: pip install rfc8785"
            )
        return rfc8785.dumps(body)

    # Deterministic JSON fallback (matches ceyo.crypto.canonicalize fallback)
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Lightweight envelope schema check (no ceyo dependency)
# ---------------------------------------------------------------------------

_REQUIRED_TOP = {"product", "envelope_version", "artifact_schema", "artifact_id",
                 "created_at", "body", "canonicalization", "integrity", "key_reference"}
_REQUIRED_INTEGRITY = {"hash", "sig"}
_REQUIRED_HASH = {"alg", "value_b64u", "covers"}
_REQUIRED_SIG  = {"alg", "format", "value_b64u", "covers"}
_REQUIRED_KEY_REF = {"registry", "key_id", "public_key_fingerprint"}
_REQUIRED_FP = {"alg", "value_b64u", "covers"}
_ARTIFACT_ID_RE = re.compile(r"^ceyo_art_[0-9a-f]{26}$")


def _check_envelope(artifact: dict[str, Any]) -> list[str]:
    """Return a list of schema errors, or an empty list if valid."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["root: expected object"]

    missing = _REQUIRED_TOP - artifact.keys()
    for f in sorted(missing):
        errors.append(f"missing required field: {f}")
    if missing:
        return errors  # can't continue without structure

    if artifact.get("product") != "CEYO":
        errors.append(f"product: expected 'CEYO', got {artifact.get('product')!r}")

    aid = artifact.get("artifact_id", "")
    if not isinstance(aid, str) or not _ARTIFACT_ID_RE.match(aid):
        errors.append(
            f"artifact_id: must match ^ceyo_art_[0-9a-f]{{26}}$, got {aid!r}"
        )

    integrity = artifact.get("integrity", {})
    if not isinstance(integrity, dict):
        errors.append("integrity: expected object")
    else:
        for f in _REQUIRED_INTEGRITY - integrity.keys():
            errors.append(f"integrity.{f}: missing required field")

        h = integrity.get("hash", {})
        if isinstance(h, dict):
            for f in _REQUIRED_HASH - h.keys():
                errors.append(f"integrity.hash.{f}: missing required field")
            if h.get("alg") != "SHA-256":
                errors.append(f"integrity.hash.alg: expected 'SHA-256', got {h.get('alg')!r}")
        else:
            errors.append("integrity.hash: expected object")

        s = integrity.get("sig", {})
        if isinstance(s, dict):
            for f in _REQUIRED_SIG - s.keys():
                errors.append(f"integrity.sig.{f}: missing required field")
            if s.get("alg") != "ECDSA-P256-SHA256":
                errors.append(f"integrity.sig.alg: expected 'ECDSA-P256-SHA256', got {s.get('alg')!r}")
            if s.get("format") != "DER":
                errors.append(f"integrity.sig.format: expected 'DER', got {s.get('format')!r}")
        else:
            errors.append("integrity.sig: expected object")

    key_ref = artifact.get("key_reference", {})
    if not isinstance(key_ref, dict):
        errors.append("key_reference: expected object")
    else:
        for f in _REQUIRED_KEY_REF - key_ref.keys():
            errors.append(f"key_reference.{f}: missing required field")
        fp = key_ref.get("public_key_fingerprint", {})
        if isinstance(fp, dict):
            for f in _REQUIRED_FP - fp.keys():
                errors.append(f"key_reference.public_key_fingerprint.{f}: missing required field")
        else:
            errors.append("key_reference.public_key_fingerprint: expected object")

    canon = artifact.get("canonicalization", {})
    if not isinstance(canon, dict):
        errors.append("canonicalization: expected object")
    else:
        if canon.get("scope") != "body":
            errors.append(f"canonicalization.scope: expected 'body', got {canon.get('scope')!r}")
        scheme = canon.get("scheme")
        if scheme not in {"RFC8785", "deterministic-json-fallback"}:
            errors.append(f"canonicalization.scheme: unknown scheme {scheme!r}; expected 'RFC8785' or 'deterministic-json-fallback'")

    return errors


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------

class VerificationResult:
    """Outcome of an artifact verification."""

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
        return f"VerificationResult({status}, passed={len(self.passed)}, failed={len(self.failed)})"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_artifact(
    artifact: dict[str, Any],
    public_key_pem: bytes,
    *,
    check_schema: bool = True,
    check_fingerprint: bool = True,
) -> VerificationResult:
    """Verify a sealed CEYO artifact envelope.

    This function is the independent-verifier equivalent of
    ``ceyo.verify.verify_artifact``. It shares no code with the SDK.

    Args:
        artifact:        Parsed artifact envelope dict.
        public_key_pem:  PEM bytes of the ECDSA P-256 public key.
        check_schema:    Validate envelope structure before crypto checks.
        check_fingerprint: Verify the key fingerprint in ``key_reference``.

    Returns:
        :class:`VerificationResult` — inspect ``.ok``, ``.passed``,
        and ``.failed`` for details.
    """
    result = VerificationResult()

    # Step 0 — schema
    if check_schema:
        errors = _check_envelope(artifact)
        if errors:
            for e in errors:
                result._fail(f"Schema: {e}")
            return result
        result._pass("Schema valid")

    # Step 1 — load key
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        result._fail(f"Key load: {exc}")
        return result

    if not isinstance(pub_key, ec.EllipticCurvePublicKey):
        result._fail(f"Key type: expected ECDSA EllipticCurvePublicKey, got {type(pub_key).__name__}")
        return result

    if not isinstance(pub_key.curve, ec.SECP256R1):
        result._fail(f"Key curve: expected secp256r1 (P-256), got {pub_key.curve.name!r}")
        return result

    # Step 2 — canonicalize body and verify hash
    body = artifact["body"]
    scheme = artifact["canonicalization"]["scheme"]

    try:
        canonical_bytes = _canonicalize(body, scheme)
    except RuntimeError as exc:
        result._fail(f"Canonicalization: {exc}")
        return result

    actual_hash = hashlib.sha256(canonical_bytes).digest()

    try:
        expected_hash = _b64u_decode(artifact["integrity"]["hash"]["value_b64u"])
    except (ValueError, UnicodeDecodeError) as exc:
        result._fail(f"Hash decode: {exc}")
        return result

    if not hmac.compare_digest(actual_hash, expected_hash):
        result._fail("Hash mismatch: body has been modified or canonicalization differs")
        return result
    result._pass("Hash matches")

    # Step 3 — verify signature
    try:
        sig_bytes = _b64u_decode(artifact["integrity"]["sig"]["value_b64u"])
    except (ValueError, UnicodeDecodeError) as exc:
        result._fail(f"Signature decode: {exc}")
        return result

    try:
        pub_key.verify(sig_bytes, actual_hash, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        result._fail("Signature invalid: does not match body hash or wrong key")
        return result
    result._pass("Signature valid")

    # Step 4 — verify key fingerprint
    if check_fingerprint:
        key_ref = artifact.get("key_reference", {})
        fp_block = key_ref.get("public_key_fingerprint", {})
        if fp_block and "value_b64u" in fp_block:
            pub_der = pub_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            actual_fp = hashlib.sha256(pub_der).digest()
            try:
                expected_fp = _b64u_decode(fp_block["value_b64u"])
            except (ValueError, UnicodeDecodeError) as exc:
                result._fail(f"Fingerprint decode: {exc}")
                return result
            if not hmac.compare_digest(actual_fp, expected_fp):
                result._fail("Key fingerprint mismatch: artifact was sealed with a different key")
                return result
            result._pass("Key fingerprint matches")

    return result


def load_artifact(path: str) -> dict[str, Any]:
    """Load a sealed artifact JSON file."""
    import pathlib  # noqa: PLC0415
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def load_pubkey(path: str) -> bytes:
    """Load a PEM public key file."""
    import pathlib  # noqa: PLC0415
    return pathlib.Path(path).read_bytes()
