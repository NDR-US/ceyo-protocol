"""Core cryptographic primitives for CEYO Protocol."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

try:
    import rfc8785
    HAS_RFC8785 = True
except ImportError:
    HAS_RFC8785 = False


def b64u(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    """Base64url decode, re-adding padding as needed."""
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def canonicalize(obj: Any) -> bytes:
    """Canonicalize a JSON-serializable object.

    Uses RFC 8785 (JCS) if available, otherwise a deterministic fallback
    with sorted keys and compact separators.
    """
    if HAS_RFC8785:
        return rfc8785.dumps(obj)
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canon_scheme() -> str:
    """Return the name of the active canonicalization scheme."""
    return "RFC8785" if HAS_RFC8785 else "deterministic-json-fallback"


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 digest."""
    return hashlib.sha256(data).digest()
