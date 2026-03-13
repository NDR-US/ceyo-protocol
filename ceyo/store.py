"""Append-only artifact store with hash chaining.

Stores sealed artifacts in SQLite with each row chained to the previous
via SHA-256, forming a tamper-evident log.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from ceyo.crypto import b64u, sha256


class ArtifactStore:
    """Append-only SQLite store for CEYO artifacts.

    Each artifact is stored with a chain_hash linking it to the previous
    entry, creating a tamper-evident append-only log.
    """

    GENESIS_HASH = b64u(sha256(b"ceyo:genesis"))

    def __init__(self, db_path: str | Path = "ceyo_artifacts.db"):
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL,
                envelope    TEXT    NOT NULL,
                entry_hash  TEXT    NOT NULL,
                chain_hash  TEXT    NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_artifact_id ON artifacts(artifact_id)
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_created_at ON artifacts(created_at)
        """)
        self._conn.commit()

    def _last_row(self) -> tuple[int, str]:
        """Return (last_seq, last_chain_hash), or (0, GENESIS_HASH) for an empty store."""
        row = self._conn.execute(
            "SELECT seq, chain_hash FROM artifacts ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, self.GENESIS_HASH)

    def append(self, artifact: dict[str, Any]) -> int:
        """Append a sealed artifact to the store.

        Args:
            artifact: A sealed artifact envelope dict.

        Returns:
            The sequence number of the stored artifact.

        Raises:
            ValueError: If required envelope fields are missing.
        """
        missing = [f for f in ("artifact_id", "created_at") if f not in artifact]
        if missing:
            raise ValueError(f"Artifact missing required fields: {missing}")

        envelope_json = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
        entry_hash = b64u(sha256(envelope_json.encode("utf-8")))
        last_seq, prev_chain = self._last_row()
        next_seq = last_seq + 1
        # Include next_seq in the chain so deletions are detectable: removing an
        # entry breaks seq continuity and invalidates every subsequent chain_hash.
        chain_hash = b64u(sha256(f"{prev_chain}:{next_seq}:{entry_hash}".encode("utf-8")))

        cursor = self._conn.execute(
            "INSERT INTO artifacts (artifact_id, created_at, envelope, entry_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                artifact["artifact_id"],
                artifact["created_at"],
                envelope_json,
                entry_hash,
                chain_hash,
            ),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get(self, artifact_id: str) -> Optional[dict[str, Any]]:
        """Retrieve an artifact by ID."""
        row = self._conn.execute(
            "SELECT envelope FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def get_by_seq(self, seq: int) -> Optional[dict[str, Any]]:
        """Retrieve an artifact by sequence number."""
        row = self._conn.execute(
            "SELECT envelope FROM artifacts WHERE seq = ?", (seq,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def count(self) -> int:
        """Return the number of stored artifacts."""
        row = self._conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()
        return row[0]  # type: ignore[index]

    def verify_chain(self) -> tuple[bool, int]:
        """Verify the integrity of the entire chain.

        Returns:
            (ok, count) — True if chain is intact, and how many entries checked.
        """
        rows = self._conn.execute(
            "SELECT seq, envelope, entry_hash, chain_hash FROM artifacts ORDER BY seq"
        ).fetchall()

        prev_chain = self.GENESIS_HASH
        checked = 0

        for seq, envelope_json, stored_entry_hash, stored_chain_hash in rows:
            # Recompute entry hash
            actual_entry = b64u(sha256(envelope_json.encode("utf-8")))
            if actual_entry != stored_entry_hash:
                return False, checked

            # Recompute chain hash — seq must be contiguous; any deleted row
            # will cause a mismatch on all subsequent entries.
            actual_chain = b64u(sha256(f"{prev_chain}:{seq}:{actual_entry}".encode("utf-8")))
            if actual_chain != stored_chain_hash:
                return False, checked

            prev_chain = stored_chain_hash
            checked += 1

        return True, checked

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most recent artifacts."""
        rows = self._conn.execute(
            "SELECT envelope FROM artifacts ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def export_rows(self) -> list[tuple[int, str, str, str, str, str]]:
        """Return all rows for export: (seq, artifact_id, created_at, envelope, entry_hash, chain_hash)."""
        return self._conn.execute(
            "SELECT seq, artifact_id, created_at, envelope, entry_hash, chain_hash "
            "FROM artifacts ORDER BY seq"
        ).fetchall()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> ArtifactStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
