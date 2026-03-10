"""Schema versioning and migration for CEYO Protocol.

Tracks envelope schema versions and provides a migration framework
for upgrading artifacts from older schema versions to newer ones.
"""

from __future__ import annotations

from typing import Any, Callable

# Current schema version
CURRENT_VERSION = "1.0"

# Registry of known schema versions and their changes
SCHEMA_VERSIONS: dict[str, dict[str, Any]] = {
    "1.0": {
        "released": "2026-01-01",
        "description": "Initial schema — ECDSA P-256, SHA-256, RFC 8785 canonicalization",
        "required_fields": [
            "product", "envelope_version", "artifact_schema", "artifact_id",
            "created_at", "body", "canonicalization", "integrity", "key_reference",
        ],
    },
}

# Migration functions: (from_version, to_version) → callable
_migrations: dict[tuple[str, str], Callable[[dict[str, Any]], dict[str, Any]]] = {}


def register_migration(
    from_version: str,
    to_version: str,
    fn: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    """Register a migration function between schema versions."""
    _migrations[(from_version, to_version)] = fn


def get_version(artifact: dict[str, Any]) -> str:
    """Extract the schema version from an artifact envelope."""
    schema = artifact.get("artifact_schema", {})
    return schema.get("version", "1.0")


def needs_migration(artifact: dict[str, Any]) -> bool:
    """Check whether an artifact needs migration to the current version."""
    return get_version(artifact) != CURRENT_VERSION


def migrate(artifact: dict[str, Any], target_version: str | None = None) -> dict[str, Any]:
    """Migrate an artifact to a target schema version.

    Args:
        artifact: The sealed artifact envelope.
        target_version: Target version (defaults to CURRENT_VERSION).

    Returns:
        The migrated artifact (new dict, original not modified).

    Raises:
        ValueError: If no migration path exists.
    """
    if target_version is None:
        target_version = CURRENT_VERSION

    current = get_version(artifact)
    if current == target_version:
        return artifact

    key = (current, target_version)
    if key not in _migrations:
        raise ValueError(
            f"No migration path from {current!r} to {target_version!r}. "
            f"Available: {list(_migrations.keys())}"
        )

    result = _migrations[key](dict(artifact))  # shallow copy
    result["artifact_schema"] = dict(result.get("artifact_schema", {}))
    result["artifact_schema"]["version"] = target_version
    return result


def list_versions() -> list[str]:
    """Return all known schema versions in order."""
    return sorted(SCHEMA_VERSIONS.keys())
