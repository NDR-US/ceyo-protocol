"""Core cryptographic primitives for CEYO Protocol."""

from __future__ import annotations

import base64
import hashlib
from typing import Any

try:
    import rfc8785
except ImportError as exc:  # pragma: no cover - dependency is required by the package
    rfc8785 = None  # type: ignore[assignment]
    _RFC8785_IMPORT_ERROR: ImportError | None = exc
else:
    _RFC8785_IMPORT_ERROR = None


def b64u(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(value: str) -> bytes:
    """Strictly decode an unpadded base64url string."""
    if not isinstance(value, str) or not value:
        raise ValueError("base64url value must be a non-empty string")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url value must contain ASCII characters only") from exc
    padded = raw + b"=" * (-len(raw) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc


def canonicalize(obj: Any) -> bytes:
    """Canonicalize a JSON value using RFC 8785 (JCS).

    Protocol v2 intentionally has one normative canonicalization suite. A
    verifier must never substitute another serializer when an artifact declares
    RFC8785. Historical v1 artifacts may still declare a legacy deterministic
    JSON fallback; v1 verification handles that compatibility case separately.
    """
    if rfc8785 is None:
        raise RuntimeError(
            "RFC8785 canonicalization is required for CEYO protocol v2"
        ) from _RFC8785_IMPORT_ERROR
    return rfc8785.dumps(obj)


def canon_scheme() -> str:
    """Return the canonicalization suite emitted by the current protocol."""
    return "RFC8785"


def sha256(data: bytes) -> bytes:
    """Compute a SHA-256 digest."""
    return hashlib.sha256(data).digest()
