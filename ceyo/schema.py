"""Schema validation for CEYO artifact envelopes.

Protocol v2 places artifact-level trust inputs inside a signed ``protected``
object. Protocol v1 remains readable as a legacy format so historical artifacts
retain their original, narrower guarantee.
"""

from __future__ import annotations

import re
from typing import Any

_DATETIME_RE = re.compile(
    r"^[12]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])"
    r"T([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    r"(\.\d{1,6})?"
    r"(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$"
)
_B64U_PATTERN = r"^[A-Za-z0-9_-]+$"
_ARTIFACT_ID_PATTERN = r"^ceyo_art_[0-9a-f]{26}$"

_FINGERPRINT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["alg", "value_b64u", "covers"],
    "additionalProperties": False,
    "properties": {
        "alg": {"type": "string", "const": "SHA-256"},
        "value_b64u": {"type": "string", "pattern": _B64U_PATTERN},
        "covers": {"type": "string", "const": "public_key_spki_der"},
    },
}

_KEY_REFERENCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["registry", "key_id", "public_key_fingerprint"],
    "additionalProperties": False,
    "properties": {
        "registry": {"type": "string"},
        "key_id": {"type": "string"},
        "public_key_fingerprint": _FINGERPRINT_SCHEMA,
        "authority": {"type": "object"},
    },
}

_ARTIFACT_SCHEMA_REF: dict[str, Any] = {
    "type": "object",
    "required": ["name", "version"],
    "additionalProperties": False,
    "properties": {
        "name": {"type": "string", "const": "ceyo.artifact"},
        "version": {"type": "string", "const": "1.0"},
    },
}

_CANON_SUITE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["scheme", "version"],
    "additionalProperties": False,
    "properties": {
        "scheme": {"type": "string", "const": "RFC8785"},
        "version": {"type": "string", "const": "1.0"},
    },
}

_SIGNING_SUITE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["alg", "format", "hash"],
    "additionalProperties": False,
    "properties": {
        "alg": {"type": "string", "const": "ECDSA-P256-SHA256"},
        "format": {"type": "string", "const": "DER"},
        "hash": {"type": "string", "const": "SHA-256"},
    },
}


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
                    "pattern": _DATETIME_RE.pattern,
                },
                "request_id": {"type": "string"},
            },
        },
        "policy": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "version": {"type": "string"},
                "digest": {
                    "type": "object",
                    "required": ["alg", "value_b64u", "covers"],
                    "additionalProperties": False,
                    "properties": {
                        "alg": {"type": "string", "const": "SHA-256"},
                        "value_b64u": {
                            "type": "string",
                            "pattern": _B64U_PATTERN,
                        },
                        "covers": {"type": "string"},
                    },
                },
            },
        },
        "disclosure_tier": {"type": "string"},
        "disclosure_policy": {
            "type": "object",
            "properties": {
                "tier": {"type": "string"},
                "policy_id": {"type": "string"},
                "policy_version": {"type": "string"},
            },
        },
        "capture": {"type": "object"},
        "environment": {"type": "object"},
    },
}


ENVELOPE_SCHEMA_V1: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CEYO Sealed Artifact Envelope v1 (legacy)",
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
        "envelope_version": {"type": "string", "const": "1.0"},
        "artifact_schema": _ARTIFACT_SCHEMA_REF,
        "artifact_id": {"type": "string", "pattern": r"^ceyo_art_"},
        "created_at": {
            "type": "string",
            "format": "date-time",
            "pattern": _DATETIME_RE.pattern,
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
                        "value_b64u": {
                            "type": "string",
                            "pattern": _B64U_PATTERN,
                        },
                        "covers": {"type": "string"},
                    },
                },
                "sig": {
                    "type": "object",
                    "required": ["alg", "format", "value_b64u", "covers"],
                    "properties": {
                        "alg": {
                            "type": "string",
                            "const": "ECDSA-P256-SHA256",
                        },
                        "format": {"type": "string", "const": "DER"},
                        "value_b64u": {
                            "type": "string",
                            "pattern": _B64U_PATTERN,
                        },
                        "covers": {"type": "string"},
                    },
                },
            },
        },
        "key_reference": _KEY_REFERENCE_SCHEMA,
    },
    "additionalProperties": False,
}


_PROTECTED_V2_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "product",
        "protocol_version",
        "artifact_schema",
        "artifact_id",
        "sealed_at",
        "canonicalization_suite",
        "signing_suite",
        "key_reference",
        "body",
    ],
    "additionalProperties": False,
    "properties": {
        "product": {"type": "string", "const": "CEYO"},
        "protocol_version": {"type": "string", "const": "2.0"},
        "artifact_schema": _ARTIFACT_SCHEMA_REF,
        "artifact_id": {"type": "string", "pattern": _ARTIFACT_ID_PATTERN},
        "sealed_at": {
            "type": "string",
            "format": "date-time",
            "pattern": _DATETIME_RE.pattern,
        },
        "canonicalization_suite": _CANON_SUITE_SCHEMA,
        "signing_suite": _SIGNING_SUITE_SCHEMA,
        "key_reference": _KEY_REFERENCE_SCHEMA,
        "body": {"type": "object"},
    },
}

ENVELOPE_SCHEMA_V2: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CEYO Sealed Artifact Envelope v2",
    "type": "object",
    "required": ["protected", "integrity", "receipts"],
    "additionalProperties": False,
    "properties": {
        "protected": _PROTECTED_V2_SCHEMA,
        "integrity": {
            "type": "object",
            "required": ["digest", "signature"],
            "additionalProperties": False,
            "properties": {
                "digest": {
                    "type": "object",
                    "required": ["alg", "value_b64u", "covers"],
                    "additionalProperties": False,
                    "properties": {
                        "alg": {"type": "string", "const": "SHA-256"},
                        "value_b64u": {
                            "type": "string",
                            "pattern": _B64U_PATTERN,
                        },
                        "covers": {
                            "type": "string",
                            "const": "canonical(protected)",
                        },
                    },
                },
                "signature": {
                    "type": "object",
                    "required": ["alg", "format", "value_b64u", "covers"],
                    "additionalProperties": False,
                    "properties": {
                        "alg": {
                            "type": "string",
                            "const": "ECDSA-P256-SHA256",
                        },
                        "format": {"type": "string", "const": "DER"},
                        "value_b64u": {
                            "type": "string",
                            "pattern": _B64U_PATTERN,
                        },
                        "covers": {
                            "type": "string",
                            "const": "sha256(canonical(protected))",
                        },
                    },
                },
            },
        },
        "receipts": {"type": "array", "items": {"type": "object"}},
    },
}

ENVELOPE_SCHEMA = ENVELOPE_SCHEMA_V2


class ValidationError(Exception):
    """Raised when an artifact fails schema validation."""


def _validate(obj: Any, schema: dict[str, Any], path: str = "") -> list[str]:
    """Validate a value against the lightweight CEYO schema subset."""
    errors: list[str] = []

    schema_type = schema.get("type")
    if schema_type == "object" and not isinstance(obj, dict):
        errors.append(
            f"{path or 'root'}: expected object, got {type(obj).__name__}"
        )
        return errors
    if schema_type == "string" and not isinstance(obj, str):
        errors.append(
            f"{path or 'root'}: expected string, got {type(obj).__name__}"
        )
        return errors
    if schema_type == "integer" and not isinstance(obj, int):
        errors.append(
            f"{path or 'root'}: expected integer, got {type(obj).__name__}"
        )
        return errors
    if schema_type == "array" and not isinstance(obj, list):
        errors.append(
            f"{path or 'root'}: expected array, got {type(obj).__name__}"
        )
        return errors

    if "const" in schema and obj != schema["const"]:
        errors.append(
            f"{path or 'root'}: expected {schema['const']!r}, got {obj!r}"
        )

    if "enum" in schema and obj not in schema["enum"]:
        errors.append(
            f"{path or 'root'}: expected one of {schema['enum']!r}, got {obj!r}"
        )

    if "pattern" in schema and isinstance(obj, str):
        if len(obj) > 2048:
            errors.append(f"{path or 'root'}: string exceeds 2048 characters")
        elif not re.match(schema["pattern"], obj):
            errors.append(
                f"{path or 'root'}: does not match pattern {schema['pattern']}"
            )

    if schema_type == "object" and isinstance(obj, dict):
        for field in schema.get("required", []):
            if field not in obj:
                errors.append(
                    f"{path}.{field}: missing required field"
                    if path
                    else f"{field}: missing required field"
                )

        properties = schema.get("properties", {})
        for key, sub_schema in properties.items():
            if key in obj:
                sub_path = f"{path}.{key}" if path else key
                errors.extend(_validate(obj[key], sub_schema, sub_path))

        if schema.get("additionalProperties") is False:
            extra = set(obj.keys()) - set(properties.keys())
            for key in sorted(extra):
                errors.append(
                    f"{path}.{key}: unexpected field"
                    if path
                    else f"{key}: unexpected field"
                )

    if schema_type == "array" and isinstance(obj, list):
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(obj):
                errors.extend(
                    _validate(item, item_schema, f"{path or 'root'}[{index}]")
                )

    return errors


def is_v2_envelope(artifact: dict[str, Any]) -> bool:
    """Return True when *artifact* declares the supported v2 protocol."""
    protected = artifact.get("protected")
    return (
        isinstance(protected, dict)
        and protected.get("protocol_version") == "2.0"
    )


def validate_envelope(artifact: dict[str, Any]) -> list[str]:
    """Validate a current v2 artifact or a legacy-v1 artifact."""
    if "protected" in artifact:
        errors = _validate(artifact, ENVELOPE_SCHEMA_V2)
        protected = artifact.get("protected")
        if isinstance(protected, dict) and isinstance(
            protected.get("body"), dict
        ):
            body_errors = validate_body(protected["body"])
            errors.extend(f"protected.body.{error}" for error in body_errors)
        return errors

    errors = _validate(artifact, ENVELOPE_SCHEMA_V1)
    if isinstance(artifact.get("body"), dict):
        body_errors = validate_body(artifact["body"])
        errors.extend(f"body.{error}" for error in body_errors)
    return errors


def validate_body(body: dict[str, Any]) -> list[str]:
    """Validate an artifact body against the current body schema."""
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
