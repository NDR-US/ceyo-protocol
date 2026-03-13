"""Tamper-evident transparency log for CEYO Protocol.

Implements an append-only Merkle tree log with signed checkpoints and
inclusion proof generation, following RFC 6962 hash-prefix conventions.

Data flow
---------
1. An artifact is sealed (``seal.py`` / ``CeyoClient``).
2. ``TransparencyLog.append(envelope)`` records its hash as a Merkle leaf.
3. ``TransparencyLog.checkpoint()`` signs the current root → stored checkpoint.
4. ``TransparencyLog.prove_inclusion(artifact_id)`` emits a sibling-path proof.
5. ``ceyo_verify.transparency.verify_inclusion_proof()`` verifies the proof
   independently of the CEYO SDK.

Merkle tree algorithm
---------------------
- Leaf hash:  SHA-256(0x00 ‖ artifact_hash_bytes)
- Node hash:  SHA-256(0x01 ‖ left ‖ right)
- Odd nodes are promoted unchanged (no duplication).
- Empty tree root: SHA-256(b"ceyo:empty-tree")
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ceyo.crypto import b64u, b64u_decode, canonicalize, sha256
from ceyo.keys import InMemoryKeyProvider, KeyProvider

# ---------------------------------------------------------------------------
# Merkle tree primitives (RFC 6962 hash-prefix domain separation)
# ---------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(artifact_hash_bytes: bytes) -> bytes:
    """SHA-256(0x00 ‖ artifact_hash_bytes)."""
    return sha256(_LEAF_PREFIX + artifact_hash_bytes)


def _node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 ‖ left ‖ right)."""
    return sha256(_NODE_PREFIX + left + right)


def compute_root(leaf_hashes: list[bytes]) -> bytes:
    """Compute the Merkle root of *leaf_hashes*.

    Odd nodes at any level are promoted unchanged rather than duplicated,
    matching the RFC 6962 / Certificate Transparency convention.

    Args:
        leaf_hashes: Ordered list of leaf hash bytes.

    Returns:
        The root hash bytes.  The empty-tree root is
        ``SHA-256(b"ceyo:empty-tree")``.
    """
    if not leaf_hashes:
        return sha256(b"ceyo:empty-tree")
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])  # promote lone node unchanged
        level = next_level
    return level[0]


def compute_inclusion_proof(
    leaf_index: int,
    leaf_hashes: list[bytes],
) -> list[tuple[str, bytes]]:
    """Generate a Merkle inclusion proof for the leaf at *leaf_index*.

    Args:
        leaf_index:  0-based index of the target leaf.
        leaf_hashes: Complete ordered list of leaf hash bytes.

    Returns:
        List of ``(direction, sibling_hash)`` pairs, walking from the leaf
        up to (but not including) the root.  *direction* is ``"left"`` when
        the sibling is to the left of the current node, ``"right"`` otherwise.

    Raises:
        ValueError: If *leaf_hashes* is empty.
        IndexError: If *leaf_index* is out of range.
    """
    n = len(leaf_hashes)
    if n == 0:
        raise ValueError("Cannot prove inclusion in an empty tree")
    if leaf_index >= n:
        raise IndexError(f"leaf_index {leaf_index} >= tree_size {n}")

    proof: list[tuple[str, bytes]] = []
    level = list(leaf_hashes)
    idx = leaf_index

    while len(level) > 1:
        # Build the next level so we can record the current sibling
        next_level: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])

        if idx % 2 == 0:
            # Even index → sibling is to the right (if it exists)
            if idx + 1 < len(level):
                proof.append(("right", level[idx + 1]))
            # else: lone node promoted, no sibling at this level
        else:
            # Odd index → sibling is to the left
            proof.append(("left", level[idx - 1]))

        idx //= 2
        level = next_level

    return proof


# ---------------------------------------------------------------------------
# TransparencyLog
# ---------------------------------------------------------------------------


class TransparencyLog:
    """Append-only Merkle tree log with signed checkpoints.

    Each :meth:`append` records an artifact's hash as a Merkle leaf.
    :meth:`checkpoint` produces a signed snapshot of the current tree root.
    :meth:`prove_inclusion` emits a proof that can be verified independently
    with :func:`ceyo_verify.transparency.verify_inclusion_proof`.

    Args:
        db_path:      Path to the SQLite log database
                      (default: ``ceyo_log.db``).
        key_provider: Key provider used to sign checkpoints.  Defaults to a
                      per-process in-memory key — use a
                      :class:`~ceyo.keys.LocalKeyProvider` for persistent,
                      cross-session checkpoints.
    """

    def __init__(
        self,
        db_path: str | Path = "ceyo_log.db",
        key_provider: KeyProvider | None = None,
    ) -> None:
        self._db_path = str(db_path)
        self._key_provider = key_provider or InMemoryKeyProvider()
        self._conn = sqlite3.connect(self._db_path, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS log_entries (
                seq           INTEGER PRIMARY KEY AUTOINCREMENT,
                artifact_id   TEXT    NOT NULL UNIQUE,
                artifact_hash TEXT    NOT NULL,
                leaf_hash     TEXT    NOT NULL,
                logged_at     TEXT    NOT NULL
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                tree_size       INTEGER NOT NULL,
                root_hash       TEXT    NOT NULL,
                created_at      TEXT    NOT NULL,
                checkpoint_json TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_log_artifact_id
                ON log_entries(artifact_id);
        """)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _all_leaf_hashes(self) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT leaf_hash FROM log_entries ORDER BY seq"
        ).fetchall()
        return [b64u_decode(row[0]) for row in rows]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Record *artifact* in the transparency log.

        Computes:

        - ``artifact_hash = SHA-256(canonical(envelope))`` — the
          authoritative hash of the sealed artifact.
        - ``leaf_hash = SHA-256(0x00 ‖ artifact_hash)`` — the Merkle leaf.

        Both are stored in base64url encoding.

        Args:
            artifact: A sealed CEYO artifact envelope dict.

        Returns:
            A log-entry dict with ``seq``, ``artifact_id``,
            ``artifact_hash``, ``leaf_hash``, and ``logged_at``.

        Raises:
            ValueError: If *artifact* is missing ``artifact_id``.
        """
        artifact_id = artifact.get("artifact_id")
        if not artifact_id:
            raise ValueError("artifact missing 'artifact_id'")

        artifact_hash_bytes = sha256(canonicalize(artifact))
        artifact_hash_b64u = b64u(artifact_hash_bytes)
        leaf_hash_b64u = b64u(_leaf_hash(artifact_hash_bytes))
        logged_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        cursor = self._conn.execute(
            "INSERT INTO log_entries "
            "(artifact_id, artifact_hash, leaf_hash, logged_at) "
            "VALUES (?, ?, ?, ?)",
            (artifact_id, artifact_hash_b64u, leaf_hash_b64u, logged_at),
        )
        return {
            "seq": cursor.lastrowid,
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash_b64u,
            "leaf_hash": leaf_hash_b64u,
            "logged_at": logged_at,
        }

    def tree_size(self) -> int:
        """Return the number of entries currently in the log."""
        row = self._conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()
        return row[0]

    def root_hash(self) -> str:
        """Return the current Merkle root hash as a base64url string."""
        return b64u(compute_root(self._all_leaf_hashes()))

    def checkpoint(self) -> dict[str, Any]:
        """Sign the current log state and return a signed checkpoint dict.

        The **checkpoint body** (the object that is canonicalized and
        signed) contains: ``product``, ``type``, ``tree_size``,
        ``root_hash``, and ``created_at``.  The full checkpoint appends
        ``sig`` and ``key_reference`` and is also persisted in the DB.

        The signature algorithm matches artifact sealing:
        ``ECDSA-P256-SHA256`` over the DER-encoded signature with a
        pre-hashed SHA-256 digest of the canonical body.

        Returns:
            The full signed checkpoint dict.
        """
        size = self.tree_size()
        root = self.root_hash()
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        checkpoint_body: dict[str, Any] = {
            "product": "CEYO",
            "type": "transparency-checkpoint",
            "tree_size": size,
            "root_hash": root,
            "created_at": created_at,
        }

        digest = sha256(canonicalize(checkpoint_body))
        priv = self._key_provider.get_private_key()
        sig_bytes = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        full_checkpoint: dict[str, Any] = {
            **checkpoint_body,
            "sig": {
                "alg": "ECDSA-P256-SHA256",
                "format": "DER",
                "value_b64u": b64u(sig_bytes),
                "covers": "canonical(checkpoint_body)",
            },
            "key_reference": self._key_provider.key_reference(),
        }

        self._conn.execute(
            "INSERT INTO checkpoints "
            "(tree_size, root_hash, created_at, checkpoint_json) "
            "VALUES (?, ?, ?, ?)",
            (size, root, created_at, json.dumps(full_checkpoint)),
        )
        return full_checkpoint

    def prove_inclusion(self, artifact_id: str) -> dict[str, Any]:
        """Generate a Merkle inclusion proof for *artifact_id*.

        The proof can be verified independently using
        :func:`ceyo_verify.transparency.verify_inclusion_proof`.

        Args:
            artifact_id: The artifact ID to prove membership for.

        Returns:
            An inclusion-proof dict with: ``artifact_id``,
            ``artifact_hash``, ``leaf_index``, ``tree_size``,
            ``root_hash``, and ``hashes`` (the sibling path as a list of
            ``{"direction": "left"|"right", "value_b64u": ...}`` dicts).

        Raises:
            KeyError: If *artifact_id* is not present in the log.
        """
        row = self._conn.execute(
            "SELECT seq, artifact_hash FROM log_entries WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"artifact not found in log: {artifact_id!r}")

        db_seq, artifact_hash_b64u = row
        leaf_index = db_seq - 1  # seq is 1-based; leaf_index is 0-based

        leaf_hashes = self._all_leaf_hashes()
        proof_steps = compute_inclusion_proof(leaf_index, leaf_hashes)
        root = b64u(compute_root(leaf_hashes))

        return {
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash_b64u,
            "leaf_index": leaf_index,
            "tree_size": len(leaf_hashes),
            "root_hash": root,
            "hashes": [
                {"direction": direction, "value_b64u": b64u(h)}
                for direction, h in proof_steps
            ],
        }

    def get_entry(self, artifact_id: str) -> Optional[dict[str, Any]]:
        """Return the log entry for *artifact_id*, or ``None`` if absent."""
        row = self._conn.execute(
            "SELECT seq, artifact_id, artifact_hash, leaf_hash, logged_at "
            "FROM log_entries WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "seq": row[0],
            "artifact_id": row[1],
            "artifact_hash": row[2],
            "leaf_hash": row[3],
            "logged_at": row[4],
        }

    def latest_checkpoint(self) -> Optional[dict[str, Any]]:
        """Return the most recently stored checkpoint, or ``None``."""
        row = self._conn.execute(
            "SELECT checkpoint_json FROM checkpoints ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_entries(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return up to *limit* most recent log entries (newest first)."""
        rows = self._conn.execute(
            "SELECT seq, artifact_id, artifact_hash, leaf_hash, logged_at "
            "FROM log_entries ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "seq": r[0],
                "artifact_id": r[1],
                "artifact_hash": r[2],
                "leaf_hash": r[3],
                "logged_at": r[4],
            }
            for r in rows
        ]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    def __enter__(self) -> TransparencyLog:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
