"""Artifact sealing for CEYO Protocol.

Protocol v2 signs ``canonical(protected)`` so artifact-level trust inputs are
integrity-bound. Protocol v1 sealing is retained only for compatibility testing
and historical tooling.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ceyo.crypto import b64u, canon_scheme, canonicalize, sha256
from ceyo.keys import InMemoryKeyProvider, KeyProvider
from ceyo.schema import validate_body_or_raise

_ARTIFACT_ID_RE = re.compile(r"^ceyo_art_[0-9a-f]{26}$")


def _new_artifact_id() -> str:
    return f"ceyo_art_{uuid.uuid4().hex[:26]}"


def _validated_artifact_id(value: str | None) -> str:
    artifact_id = value or _new_artifact_id()
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError(
            "artifact_id must match ^ceyo_art_[0-9a-f]{26}$"
        )
    return artifact_id


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign_digest(digest: bytes, key_provider: KeyProvider) -> bytes:
    private_key = key_provider.get_private_key()
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError(
            "CEYO protocol v2 requires an ECDSA P-256 (secp256r1) signing key"
        )
    return private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )


def seal_body_v1(
    body: dict[str, Any],
    key_provider: KeyProvider | None = None,
    *,
    validate: bool = True,
    artifact_id: str | None = None,
) -> dict[str, Any]:
    """Seal a legacy protocol-v1 artifact.

    V1 signs only ``canonical(body)``. It is preserved so historical artifacts
    can be reproduced and tested, but new callers should use :func:`seal_body`.
    """
    if validate:
        validate_body_or_raise(body)

    key_provider = key_provider or InMemoryKeyProvider()
    canonical_bytes = canonicalize(body)
    digest = sha256(canonical_bytes)
    signature = _sign_digest(digest, key_provider)

    return {
        "product": "CEYO",
        "envelope_version": "1.0",
        "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
        "artifact_id": artifact_id or _new_artifact_id(),
        "created_at": _utc_now(),
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


def seal_body(
    body: dict[str, Any],
    key_provider: KeyProvider | None = None,
    *,
    validate: bool = True,
    artifact_id: str | None = None,
    receipts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Seal an artifact body as a CEYO protocol-v2 envelope.

    The v2 signature scope is ``canonical(protected)``. ``protected`` contains
    artifact identity, signer/key binding, declared cryptographic suites,
    signer-asserted sealing time, schema reference, and body. Receipts remain
    outside the artifact signature so separately authenticated evidence can be
    attached later.

    ``sealed_at`` is signer-asserted time. The signature prevents post-seal
    editing; it does not prove clock accuracy or prevent deliberate backdating.
    Stronger time assurance requires an accepted external time mechanism.
    """
    if validate:
        validate_body_or_raise(body)

    key_provider = key_provider or InMemoryKeyProvider()
    resolved_artifact_id = _validated_artifact_id(artifact_id)

    protected: dict[str, Any] = {
        "product": "CEYO",
        "protocol_version": "2.0",
        "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
        "artifact_id": resolved_artifact_id,
        "sealed_at": _utc_now(),
        "canonicalization_suite": {
            "scheme": canon_scheme(),
            "version": "1.0",
        },
        "signing_suite": {
            "alg": "ECDSA-P256-SHA256",
            "format": "DER",
            "hash": "SHA-256",
        },
        "key_reference": key_provider.key_reference(),
        "body": body,
    }

    canonical_protected = canonicalize(protected)
    digest = sha256(canonical_protected)
    signature = _sign_digest(digest, key_provider)

    return {
        "protected": protected,
        "integrity": {
            "digest": {
                "alg": "SHA-256",
                "value_b64u": b64u(digest),
                "covers": "canonical(protected)",
            },
            "signature": {
                "alg": "ECDSA-P256-SHA256",
                "format": "DER",
                "value_b64u": b64u(signature),
                "covers": "sha256(canonical(protected))",
            },
        },
        "receipts": list(receipts or []),
    }


def seal(
    event_id: str,
    event_type: str,
    occurred_at: str,
    *,
    request_id: str | None = None,
    policy_id: str | None = None,
    policy_version: str = "1.0",
    policy_digest: dict[str, Any] | None = None,
    disclosure_tier: str = "internal",
    disclosure_policy: dict[str, Any] | None = None,
    capture: dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
    key_provider: KeyProvider | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """Build and seal a protocol-v2 event artifact."""
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
        policy: dict[str, Any] = {"id": policy_id, "version": policy_version}
        if policy_digest is not None:
            policy["digest"] = policy_digest
        body["policy"] = policy
    if disclosure_policy is not None:
        body["disclosure_policy"] = disclosure_policy
    elif disclosure_tier:
        body["disclosure_tier"] = disclosure_tier
    if capture:
        body["capture"] = capture
    if environment:
        body["environment"] = environment

    return seal_body(body, key_provider, validate=validate)
