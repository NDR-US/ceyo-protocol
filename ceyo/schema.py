"""JSON Schema validation for CEYO artifact envelopes."""

from __future__ import annotations

from typing import Any

# Canonical JSON Schema for a CEYO sealed artifact envelope.
ENVELOPE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CEYO Sealed Artifact Envelope",
    "type": "object",
    "required": [
        "product",
        "envelope_version",
        "artifact_schema",
        "artifact_id",
        "created_at",
        "body",
        "canonicalization",
        "integrity",
        "key_reference",
    ],
    "properties": {
        "product": {"type": "string", "const": "CEYO"},
        "envelope_version": {"type": "string"},
        "artifact_schema": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
            },
        },
        "artifact_id": {"type": "string", "pattern": "^ceyo_art_"},
        "created_at": {"type": "string", "format": "date-time"},
        "body": {"type": "object"},
        "canonicalization": {
            "type": "object",
            "required": ["scheme", "version", "scope"],
            "properties": {
                "scheme": {"type": "string"},
                "version": {"type": "string"},
                "scope": {"type": "string", "const": "body"},
            },
        },
        "integrity": {
            "type": "object",
            "required": ["hash", "sig"],
            "properties": {
                "hash": {
                    "type": "object",
                    "required": ["alg", "value_b64u", "covers"],
                    "properties": {
                        "alg": {"type": "string", "const": "SHA-256"},
                        "value_b64u": {"type": "string"},
                        "covers": {"type": "string"},
                    },
                },
                "sig": {
                    "type": "object",
                    "required": ["alg", "format", "value_b64u", "covers"],
                    "properties": {
                        "alg": {"type": "string", "const": "ECDSA-P256-SHA256"},
                        "format": {"type": "string", "const": "DER"},
                        "value_b64u": {"type": "string"},
                        "covers": {"type": "string"},
                    },
                },
            },
        },
        "key_reference": {
            "type": "object",
            "required": ["registry", "key_id", "public_key_fingerprint"],
            "properties": {
                "registry": {"type": "string"},
                "key_id": {"type": "string"},
                "public_key_fingerprint": {
                    "type": "object",
                    "required": ["alg", "value_b64u", "covers"],
                    "properties": {
                        "alg": {"type": "string", "const": "SHA-256"},
                        "value_b64u": {"type": "string"},
                        "covers": {"type": "string"},
                    },
                },
            },
        },
    },
    "additionalProperties": False,
}

# Body schema for event artifacts.
BODY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CEYO Artifact Body",
    "type": "object",
    "required": ["event"],
    "properties": {
        "event": {
            "type": "object",
            "required": ["event_id", "type", "occurred_at"],
            "properties": {
                "event_id": {"type": "string"},
                "type": {"type": "string"},
                "occurred_at": {"type": "string", "format": "date-time"},
                "request_id": {"type": "string"},
            },
        },
        "policy": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "version": {"type": "string"},
            },
        },
        "disclosure_tier": {"type": "string"},
        "capture": {"type": "object"},
        "environment": {"type": "object"},
    },
}


class ValidationError(Exception):
    """Raised when an artifact fails schema validation."""


def _validate(obj: dict[str, Any], schema: dict[str, Any], path: str = "") -> list[str]:
    """Validate an object against a schema. Returns list of error messages.

    This is a lightweight validator that checks required fields, types, const
    values, and patterns without pulling in a full JSON Schema library.
    """
    errors: list[str] = []

    schema_type = schema.get("type")
    if schema_type == "object" and not isinstance(obj, dict):
        errors.append(f"{path or 'root'}: expected object, got {type(obj).__name__}")
        return errors
    if schema_type == "string" and not isinstance(obj, str):
        errors.append(f"{path or 'root'}: expected string, got {type(obj).__name__}")
        return errors

    if "const" in schema and obj != schema["const"]:
        errors.append(f"{path or 'root'}: expected {schema['const']!r}, got {obj!r}")

    if "pattern" in schema and isinstance(obj, str):
        import re
        if not re.match(schema["pattern"], obj):
            errors.append(f"{path or 'root'}: does not match pattern {schema['pattern']}")

    if schema_type == "object" and isinstance(obj, dict):
        for field in schema.get("required", []):
            if field not in obj:
                errors.append(f"{path}.{field}: missing required field" if path else f"{field}: missing required field")

        props = schema.get("properties", {})
        for key, sub_schema in props.items():
            if key in obj:
                sub_path = f"{path}.{key}" if path else key
                errors.extend(_validate(obj[key], sub_schema, sub_path))

        if schema.get("additionalProperties") is False:
            extra = set(obj.keys()) - set(props.keys())
            for key in sorted(extra):
                errors.append(f"{path}.{key}: unexpected field" if path else f"{key}: unexpected field")

    return errors


def validate_envelope(artifact: dict[str, Any]) -> list[str]:
    """Validate a sealed artifact envelope against the CEYO schema.

    Returns a list of error strings. Empty list means valid.
    """
    return _validate(artifact, ENVELOPE_SCHEMA)


def validate_body(body: dict[str, Any]) -> list[str]:
    """Validate an artifact body against the CEYO body schema.

    Returns a list of error strings. Empty list means valid.
    """
    return _validate(body, BODY_SCHEMA)


def validate_envelope_or_raise(artifact: dict[str, Any]) -> None:
    """Validate a sealed artifact envelope; raise ValidationError on failure."""
    errors = validate_envelope(artifact)
    if errors:
        raise ValidationError("; ".join(errors))


def validate_body_or_raise(body: dict[str, Any]) -> None:
    """Validate an artifact body; raise ValidationError on failure."""
    errors = validate_body(body)
    if errors:
        raise ValidationError("; ".join(errors))
