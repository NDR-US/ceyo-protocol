"""Local Merkle inclusion log for CEYO artifacts.

The reference log records a stable digest for each artifact and can produce
Merkle inclusion proofs plus signed checkpoints. It is a transparency-log
prototype, not by itself a globally witnessed append-only service.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from ceyo.crypto import b64u, b64u_decode, sha256
from ceyo.keys import InMemoryKeyProvider, KeyProvider

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _transparency_canonicalize(value: Any) -> bytes:
    """Canonicalize transparency subjects/checkpoints using RFC 8785 only.

    Unlike artifact sealing, the current transparency proof/checkpoint formats
    do not carry a canonicalization-suite field. Their canonicalization is
    therefore fixed by this specification rather than selected at runtime.
    """
    try:
        import rfc8785
    except ImportError as exc:
        raise RuntimeError(
            "CEYO transparency operations require the rfc8785 package"
        ) from exc
    return rfc8785.dumps(value)


def _leaf_hash(artifact_hash_bytes: bytes) -> bytes:
    """SHA-256(0x00 || artifact_hash_bytes)."""
    return sha256(_LEAF_PREFIX + artifact_hash_bytes)


def _node_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 || left || right)."""
    return sha256(_NODE_PREFIX + left + right)


def compute_root(leaf_hashes: list[bytes]) -> bytes:
    """Compute the Merkle root of *leaf_hashes*."""
    if not leaf_hashes:
        return sha256(b"ceyo:empty-tree")

    level = list(leaf_hashes)
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])
        level = next_level
    return level[0]


def compute_inclusion_proof(
    leaf_index: int,
    leaf_hashes: list[bytes],
) -> list[tuple[str, bytes]]:
    """Generate a sibling-path inclusion proof for one leaf."""
    count = len(leaf_hashes)
    if count == 0:
        raise ValueError("Cannot prove inclusion in an empty tree")
    if leaf_index < 0 or leaf_index >= count:
        raise IndexError(f"leaf_index {leaf_index} outside tree_size {count}")

    proof: list[tuple[str, bytes]] = []
    level = list(leaf_hashes)
    index = leaf_index

    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level) - 1, 2):
            next_level.append(_node_hash(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            next_level.append(level[-1])

        if index % 2 == 0:
            if index + 1 < len(level):
                proof.append(("right", level[index + 1]))
        else:
            proof.append(("left", level[index - 1]))

        index //= 2
        level = next_level

    return proof


def _artifact_id(artifact: dict[str, Any]) -> str:
    """Resolve the artifact identifier without trusting unsigned v2 metadata."""
    if "protected" in artifact:
        protected = artifact.get("protected")
        if not isinstance(protected, dict):
            raise ValueError("v2 artifact has malformed protected object")
        if protected.get("protocol_version") != "2.0":
            raise ValueError("unsupported protected-envelope protocol version")
        value = protected.get("artifact_id")
    else:
        value = artifact.get("artifact_id")

    if not value:
        raise ValueError("artifact missing authoritative artifact_id")
    return str(value)


def artifact_log_subject(artifact: dict[str, Any]) -> dict[str, Any]:
    """Return the stable object committed to by the transparency log.

    For protocol v2, receipts are intentionally excluded. They are appendable
    external evidence and must not change the subject that a transparency proof
    refers to. The v2 subject is therefore exactly ``protected + integrity``.

    Legacy v1 artifacts retain the historical full-envelope subject so existing
    v1 proof semantics are not silently rewritten.
    """
    if "protected" not in artifact:
        return artifact

    protected = artifact.get("protected")
    integrity = artifact.get("integrity")
    if not isinstance(protected, dict) or not isinstance(integrity, dict):
        raise ValueError("v2 artifact missing protected or integrity object")
    if protected.get("protocol_version") != "2.0":
        raise ValueError("unsupported protected-envelope protocol version")

    return {
        "protected": protected,
        "integrity": integrity,
    }


def artifact_log_digest(artifact: dict[str, Any]) -> bytes:
    """Compute the RFC-8785-based digest used as the Merkle-log subject."""
    return sha256(_transparency_canonicalize(artifact_log_subject(artifact)))


class TransparencyLog:
    """Local Merkle inclusion log with signed checkpoints."""

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

    def _all_leaf_hashes(self) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT leaf_hash FROM log_entries ORDER BY seq"
        ).fetchall()
        return [b64u_decode(row[0]) for row in rows]

    def append(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Record a current v2 or legacy-v1 artifact in the local Merkle log.

        V2 commits to ``SHA-256(RFC8785({protected, integrity}))`` so later
        receipt attachment does not invalidate or circularly redefine an
        existing inclusion proof. V1 retains its historical full-envelope
        subject, canonicalized with RFC 8785 for new reference-log entries.

        ``logged_at`` is local log metadata. It is not independently trusted time.
        """
        artifact_id = _artifact_id(artifact)
        artifact_hash_bytes = artifact_log_digest(artifact)
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
        row = self._conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()
        return row[0]

    def root_hash(self) -> str:
        return b64u(compute_root(self._all_leaf_hashes()))

    def checkpoint(self) -> dict[str, Any]:
        """Sign the current tree size/root as a checkpoint assertion.

        ``created_at`` is signed and therefore cannot be edited without breaking
        the checkpoint signature, but it remains an assertion of the checkpoint
        signer rather than an independently trusted timestamp.

        The current checkpoint ``key_reference`` is descriptive metadata outside
        the signed checkpoint body. Verification relies on the separately
        supplied checkpoint public key, not on that unsigned reference.
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
        digest = sha256(_transparency_canonicalize(checkpoint_body))
        private_key = self._key_provider.get_private_key()
        signature = private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )

        checkpoint: dict[str, Any] = {
            **checkpoint_body,
            "sig": {
                "alg": "ECDSA-P256-SHA256",
                "format": "DER",
                "value_b64u": b64u(signature),
                "covers": "RFC8785(checkpoint_body)",
            },
            "key_reference": self._key_provider.key_reference(),
        }
        self._conn.execute(
            "INSERT INTO checkpoints "
            "(tree_size, root_hash, created_at, checkpoint_json) "
            "VALUES (?, ?, ?, ?)",
            (size, root, created_at, json.dumps(checkpoint)),
        )
        return checkpoint

    def prove_inclusion(self, artifact_id: str) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT seq, artifact_hash FROM log_entries WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"artifact not found in log: {artifact_id!r}")

        db_seq, artifact_hash_b64u = row
        leaf_index = db_seq - 1
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
                {"direction": direction, "value_b64u": b64u(value)}
                for direction, value in proof_steps
            ],
        }

    def get_entry(self, artifact_id: str) -> Optional[dict[str, Any]]:
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
        row = self._conn.execute(
            "SELECT checkpoint_json FROM checkpoints ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_entries(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT seq, artifact_id, artifact_hash, leaf_hash, logged_at "
            "FROM log_entries ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "seq": row[0],
                "artifact_id": row[1],
                "artifact_hash": row[2],
                "leaf_hash": row[3],
                "logged_at": row[4],
            }
            for row in rows
        ]

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> TransparencyLog:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
