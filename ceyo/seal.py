"""Artifact sealing for CEYO Protocol."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ceyo.crypto import b64u, canonicalize, canon_scheme, sha256
from ceyo.keys import KeyProvider, InMemoryKeyProvider
from ceyo.schema import validate_body_or_raise


def seal_body(
    body: dict[str, Any],
    key_provider: KeyProvider | None = None,
    *,
    validate: bool = True,
    artifact_id: str | None = None,
) -> dict[str, Any]:
    """Seal an artifact body dict and return the full envelope.

    Args:
        body: The artifact body to seal.
        key_provider: Key provider for signing. Defaults to in-memory.
        validate: Whether to validate body against the schema.
        artifact_id: Optional artifact ID. Auto-generated if omitted.

    Returns:
        The sealed artifact envelope dict.
    """
    if validate:
        validate_body_or_raise(body)

    if key_provider is None:
        key_provider = InMemoryKeyProvider()

    canonical_bytes = canonicalize(body)
    digest = sha256(canonical_bytes)

    priv = key_provider.get_private_key()
    signature = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    if artifact_id is None:
        artifact_id = f"ceyo_art_{uuid.uuid4().hex[:26]}"

    return {
        "product": "CEYO",
        "envelope_version": "1.0",
        "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
        "artifact_id": artifact_id,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "body": body,
        "canonicalization": {
            "scheme": canon_scheme(),
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
        "key_reference": key_provider.key_reference(),
    }


def seal(
    event_id: str,
    event_type: str,
    occurred_at: str,
    *,
    request_id: str | None = None,
    policy_id: str | None = None,
    policy_version: str = "1.0",
    disclosure_tier: str = "internal",
    capture: dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
    key_provider: KeyProvider | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """Convenience function to seal an event from individual fields.

    Returns the sealed artifact envelope dict.
    """
    body: dict[str, Any] = {
        "event": {
            "event_id": event_id,
            "type": event_type,
            "occurred_at": occurred_at,
        },
    }
    if request_id:
        body["event"]["request_id"] = request_id
    if policy_id:
        body["policy"] = {"id": policy_id, "version": policy_version}
    if disclosure_tier:
        body["disclosure_tier"] = disclosure_tier
    if capture:
        body["capture"] = capture
    if environment:
        body["environment"] = environment

    return seal_body(body, key_provider, validate=validate)
