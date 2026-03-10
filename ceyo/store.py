"""Append-only artifact store with hash chaining.

Stores sealed artifacts in SQLite with each row chained to the previous
via SHA-256, forming a tamper-evident log. Supports export to JSON Lines
and CSV for external auditors.
"""

from __future__ import annotations

import csv
import io
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

    def _last_chain_hash(self) -> str:
        row = self._conn.execute(
            "SELECT chain_hash FROM artifacts ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else self.GENESIS_HASH

    def append(self, artifact: dict[str, Any]) -> int:
        """Append a sealed artifact to the store.

        Args:
            artifact: A sealed artifact envelope dict.

        Returns:
            The sequence number of the stored artifact.
        """
        envelope_json = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
        entry_hash = b64u(sha256(envelope_json.encode("utf-8")))
        prev_chain = self._last_chain_hash()
        chain_hash = b64u(sha256(f"{prev_chain}:{entry_hash}".encode("utf-8")))

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

            # Recompute chain hash
            actual_chain = b64u(sha256(f"{prev_chain}:{actual_entry}".encode("utf-8")))
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

    def export_jsonl(self, output: str | Path | None = None) -> str:
        """Export all artifacts as JSON Lines (one JSON object per line).

        Each line contains: seq, artifact_id, created_at, envelope, entry_hash, chain_hash.
        If output is None, returns the JSONL string. Otherwise writes to file.
        """
        rows = self._conn.execute(
            "SELECT seq, artifact_id, created_at, envelope, entry_hash, chain_hash "
            "FROM artifacts ORDER BY seq"
        ).fetchall()

        lines: list[str] = []
        for seq, artifact_id, created_at, envelope, entry_hash, chain_hash in rows:
            record = {
                "seq": seq,
                "artifact_id": artifact_id,
                "created_at": created_at,
                "envelope": json.loads(envelope),
                "entry_hash": entry_hash,
                "chain_hash": chain_hash,
            }
            lines.append(json.dumps(record, separators=(",", ":"), ensure_ascii=False))

        content = "\n".join(lines) + "\n" if lines else ""
        if output is not None:
            Path(output).write_text(content, encoding="utf-8")
        return content

    def export_csv(self, output: str | Path | None = None) -> str:
        """Export artifact metadata as CSV for auditors.

        Columns: seq, artifact_id, created_at, event_type, hash_alg, sig_alg, entry_hash, chain_hash.
        If output is None, returns the CSV string. Otherwise writes to file.
        """
        rows = self._conn.execute(
            "SELECT seq, artifact_id, created_at, envelope, entry_hash, chain_hash "
            "FROM artifacts ORDER BY seq"
        ).fetchall()

        buf = io.StringIO()
        writer = csv.writer(buf)
        header = ["seq", "artifact_id", "created_at", "event_type", "hash_alg", "sig_alg", "entry_hash", "chain_hash"]
        writer.writerow(header)

        for seq, artifact_id, created_at, envelope_json, entry_hash, chain_hash in rows:
            envelope = json.loads(envelope_json)
            event_type = envelope.get("body", {}).get("event", {}).get("type", "")
            hash_alg = envelope.get("integrity", {}).get("hash", {}).get("alg", "")
            sig_alg = envelope.get("integrity", {}).get("sig", {}).get("alg", "")
            writer.writerow([seq, artifact_id, created_at, event_type, hash_alg, sig_alg, entry_hash, chain_hash])

        content = buf.getvalue()
        if output is not None:
            Path(output).write_text(content, encoding="utf-8")
        return content

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> ArtifactStore:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
