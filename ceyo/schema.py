"""JSON Schema validation for CEYO artifact envelopes."""

from __future__ import annotations

import re
from typing import Any

# ISO 8601 UTC datetime with strict range validation.
# Year: 1000–2999, month: 01–12, day: 01–31, hour: 00–23, min/sec: 00–59.
_DATETIME_RE = re.compile(
    r"^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"T([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(\.\d{1,6})?"
    r"(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$"
)

# Base64url without padding (URL-safe chars only)
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]+$")

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
        "created_at": {
            "type": "string",
            "format": "date-time",
            "pattern": r"^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,6})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$",
        },
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
                        "value_b64u": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
                        "covers": {"type": "string"},
                    },
                },
                "sig": {
                    "type": "object",
                    "required": ["alg", "format", "value_b64u", "covers"],
                    "properties": {
                        "alg": {"type": "string", "const": "ECDSA-P256-SHA256"},
                        "format": {"type": "string", "const": "DER"},
                        "value_b64u": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
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
                        "value_b64u": {"type": "string", "pattern": "^[A-Za-z0-9_-]+$"},
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
                "occurred_at": {
                    "type": "string",
                    "format": "date-time",
                    "pattern": r"^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,6})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$",
                },
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
    if schema_type == "integer" and not isinstance(obj, int):
        errors.append(f"{path or 'root'}: expected integer, got {type(obj).__name__}")
        return errors
    if schema_type == "array" and not isinstance(obj, list):
        errors.append(f"{path or 'root'}: expected array, got {type(obj).__name__}")
        return errors

    if "const" in schema and obj != schema["const"]:
        errors.append(f"{path or 'root'}: expected {schema['const']!r}, got {obj!r}")

    if "enum" in schema and obj not in schema["enum"]:
        errors.append(f"{path or 'root'}: expected one of {schema['enum']!r}, got {obj!r}")

    if "pattern" in schema and isinstance(obj, str):
        # Guard against ReDoS on pathologically long input before regex matching.
        if len(obj) > 2048:
            errors.append(f"{path or 'root'}: string exceeds 2048 characters")
        elif not re.match(schema["pattern"], obj):
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

    if schema_type == "array" and isinstance(obj, list):
        if "minItems" in schema and len(obj) < schema["minItems"]:
            errors.append(f"{path or 'root'}: expected at least {schema['minItems']} items, got {len(obj)}")
        if "maxItems" in schema and len(obj) > schema["maxItems"]:
            errors.append(f"{path or 'root'}: expected at most {schema['maxItems']} items, got {len(obj)}")
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(obj):
                errors.extend(_validate(item, item_schema, f"{path or 'root'}[{i}]"))

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
