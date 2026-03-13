"""CEYO Protocol command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ceyo.keys import LocalKeyProvider
from ceyo.seal import seal_body
from ceyo.store import ArtifactStore
from ceyo.transparency_log import TransparencyLog
from ceyo.verify import verify_artifact


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate a new ECDSA P-256 key pair and write to PEM files."""
    priv_path = Path(args.out_private)
    pub_path = Path(args.out_public) if args.out_public else priv_path.with_suffix(".pub.pem")

    if priv_path.exists() and not args.force:
        print(f"Error: private key already exists: {priv_path}  (use --force to overwrite)", file=sys.stderr)
        sys.exit(1)

    # LocalKeyProvider auto-generates and persists; re-use that logic.
    kp = LocalKeyProvider(priv_path, pub_path)
    # Force generation by calling the method that loads/creates
    kp.get_private_key()

    print(f"Private key: {priv_path}")
    print(f"Public key:  {pub_path}")
    print(f"Fingerprint: {kp.fingerprint()}")


def cmd_seal(args: argparse.Namespace) -> None:
    """Seal a JSON record file."""
    try:
        body: dict[str, Any] = json.loads(Path(args.record).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: record file not found: {args.record}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in record file: {exc}", file=sys.stderr)
        sys.exit(1)

    key_provider = LocalKeyProvider(args.key)
    try:
        envelope = seal_body(body, key_provider, validate=not args.no_validate)
    except Exception as exc:
        print(f"Error sealing artifact: {exc}", file=sys.stderr)
        sys.exit(1)

    output = args.output or str(Path(args.record).with_suffix(".sealed.json"))
    Path(output).write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Sealed:     {output}")
    print(f"Artifact:   {envelope['artifact_id']}")
    print(f"Public key: {key_provider.public_key_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a sealed artifact against a public key."""
    try:
        artifact: dict[str, Any] = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: artifact file not found: {args.artifact}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in artifact file: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        pub_pem = Path(args.pubkey).read_bytes()
    except FileNotFoundError:
        print(f"Error: public key file not found: {args.pubkey}", file=sys.stderr)
        sys.exit(1)

    result = verify_artifact(artifact, pub_pem)
    for msg in result.passed:
        print(f"PASS: {msg}")
    for msg in result.failed:
        print(f"FAIL: {msg}")

    status = "PASSED" if result.ok else "FAILED"
    print(f"\nVerification {status}")
    sys.exit(0 if result.ok else 1)


def cmd_store_list(args: argparse.Namespace) -> None:
    """List recent artifacts from a store database."""
    with ArtifactStore(args.db) as store:
        artifacts = store.recent(args.limit)
        if not artifacts:
            print("No artifacts in store.")
            return
        for art in artifacts:
            print(f"  {art['artifact_id']}  {art['created_at']}")


def cmd_store_inspect(args: argparse.Namespace) -> None:
    """Inspect a single artifact from a store database."""
    with ArtifactStore(args.db) as store:
        artifact = store.get(args.artifact_id)
        if artifact is None:
            print(f"Error: artifact not found: {args.artifact_id}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(artifact, indent=2, ensure_ascii=False))


def cmd_store_verify_chain(args: argparse.Namespace) -> None:
    """Verify the hash chain integrity of a store database."""
    with ArtifactStore(args.db) as store:
        ok, count = store.verify_chain()
        status = "INTACT" if ok else "BROKEN"
        print(f"Checked {count} entries: {status}")
        sys.exit(0 if ok else 1)


def cmd_log_list(args: argparse.Namespace) -> None:
    """List recent entries from a transparency log database."""
    with TransparencyLog(args.db) as log:
        entries = log.list_entries(args.limit)
        if not entries:
            print("No entries in transparency log.")
            return
        for e in entries:
            print(f"  [{e['seq']:>6}]  {e['artifact_id']}  {e['logged_at']}")


def cmd_log_checkpoint(args: argparse.Namespace) -> None:
    """Sign and store a checkpoint of the current transparency log state."""
    key_provider = LocalKeyProvider(args.key)
    with TransparencyLog(args.db, key_provider) as log:
        cp = log.checkpoint()
        output = args.output
        if output:
            Path(output).write_text(
                json.dumps(cp, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"Checkpoint written: {output}")
        else:
            print(json.dumps(cp, indent=2, ensure_ascii=False))
        print(f"Tree size: {cp['tree_size']}  Root: {cp['root_hash']}", file=sys.stderr)


def cmd_log_prove(args: argparse.Namespace) -> None:
    """Generate an inclusion proof for an artifact in the transparency log."""
    with TransparencyLog(args.db) as log:
        try:
            proof = log.prove_inclusion(args.artifact_id)
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        output = args.output
        if output:
            Path(output).write_text(
                json.dumps(proof, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"Proof written: {output}")
        else:
            print(json.dumps(proof, indent=2, ensure_ascii=False))


def cmd_log_verify_proof(args: argparse.Namespace) -> None:
    """Verify an inclusion proof, optionally against a signed checkpoint."""
    from ceyo_verify.transparency import verify_inclusion_proof

    try:
        proof: dict[str, Any] = json.loads(
            Path(args.proof).read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        print(f"Error: proof file not found: {args.proof}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in proof file: {exc}", file=sys.stderr)
        sys.exit(1)

    checkpoint: dict[str, Any] | None = None
    if args.checkpoint:
        try:
            checkpoint = json.loads(
                Path(args.checkpoint).read_text(encoding="utf-8")
            )
        except FileNotFoundError:
            print(
                f"Error: checkpoint file not found: {args.checkpoint}",
                file=sys.stderr,
            )
            sys.exit(1)
        except json.JSONDecodeError as exc:
            print(f"Error: invalid JSON in checkpoint file: {exc}", file=sys.stderr)
            sys.exit(1)

    pubkey_pem: bytes | None = None
    if args.pubkey:
        try:
            pubkey_pem = Path(args.pubkey).read_bytes()
        except FileNotFoundError:
            print(
                f"Error: public key file not found: {args.pubkey}",
                file=sys.stderr,
            )
            sys.exit(1)

    result = verify_inclusion_proof(proof, checkpoint, pubkey_pem)
    for msg in result.passed:
        print(f"PASS: {msg}")
    for msg in result.failed:
        print(f"FAIL: {msg}")

    status = "PASSED" if result.ok else "FAILED"
    print(f"\nInclusion proof verification {status}")
    sys.exit(0 if result.ok else 1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="ceyo", description="CEYO Protocol CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # ceyo keygen
    p_keygen = sub.add_parser("keygen", help="Generate a new ECDSA P-256 key pair")
    p_keygen.add_argument(
        "--out-private", default="ceyo_private.pem",
        help="Private key output path (default: ceyo_private.pem)",
    )
    p_keygen.add_argument("--out-public", help="Public key output path (default: <out-private>.pub.pem)")
    p_keygen.add_argument("--force", action="store_true", help="Overwrite existing key files")
    p_keygen.set_defaults(func=cmd_keygen)

    # ceyo seal
    p_seal = sub.add_parser("seal", help="Seal a JSON record")
    p_seal.add_argument("record", help="Path to JSON record file")
    p_seal.add_argument("--key", default="ceyo_private.pem", help="Private key PEM path (default: ceyo_private.pem)")
    p_seal.add_argument("--output", "-o", help="Output path (default: <record>.sealed.json)")
    p_seal.add_argument("--no-validate", action="store_true", help="Skip body schema validation")
    p_seal.set_defaults(func=cmd_seal)

    # ceyo verify
    p_verify = sub.add_parser("verify", help="Verify a sealed artifact")
    p_verify.add_argument("artifact", help="Path to sealed artifact JSON")
    p_verify.add_argument("pubkey", help="Path to public key PEM")
    p_verify.set_defaults(func=cmd_verify)

    # ceyo store
    p_store = sub.add_parser("store", help="Artifact store operations")
    store_sub = p_store.add_subparsers(dest="store_command", required=True)

    p_list = store_sub.add_parser("list", help="List recent artifacts")
    p_list.add_argument("db", help="Path to SQLite database")
    p_list.add_argument("--limit", "-n", type=int, default=10, help="Number of entries (default: 10)")
    p_list.set_defaults(func=cmd_store_list)

    p_inspect = store_sub.add_parser("inspect", help="Print a single artifact from the store")
    p_inspect.add_argument("db", help="Path to SQLite database")
    p_inspect.add_argument("artifact_id", help="Artifact ID to inspect")
    p_inspect.set_defaults(func=cmd_store_inspect)

    p_chain = store_sub.add_parser("verify-chain", help="Verify store chain integrity")
    p_chain.add_argument("db", help="Path to SQLite database")
    p_chain.set_defaults(func=cmd_store_verify_chain)

    # ceyo log
    p_log = sub.add_parser("log", help="Transparency log operations")
    log_sub = p_log.add_subparsers(dest="log_command", required=True)

    p_log_list = log_sub.add_parser("list", help="List recent log entries")
    p_log_list.add_argument("db", help="Path to transparency log SQLite database")
    p_log_list.add_argument(
        "--limit", "-n", type=int, default=10,
        help="Number of entries to show (default: 10)",
    )
    p_log_list.set_defaults(func=cmd_log_list)

    p_log_cp = log_sub.add_parser("checkpoint", help="Sign and store a log checkpoint")
    p_log_cp.add_argument("db", help="Path to transparency log SQLite database")
    p_log_cp.add_argument(
        "--key", default="ceyo_private.pem",
        help="Private key PEM for signing (default: ceyo_private.pem)",
    )
    p_log_cp.add_argument("--output", "-o", help="Write checkpoint JSON to this file")
    p_log_cp.set_defaults(func=cmd_log_checkpoint)

    p_log_prove = log_sub.add_parser("prove", help="Generate an inclusion proof")
    p_log_prove.add_argument("db", help="Path to transparency log SQLite database")
    p_log_prove.add_argument("artifact_id", help="Artifact ID to prove")
    p_log_prove.add_argument("--output", "-o", help="Write proof JSON to this file")
    p_log_prove.set_defaults(func=cmd_log_prove)

    p_log_vp = log_sub.add_parser("verify-proof", help="Verify an inclusion proof")
    p_log_vp.add_argument("proof", help="Path to inclusion-proof JSON file")
    p_log_vp.add_argument(
        "--checkpoint", help="Path to signed checkpoint JSON (optional)"
    )
    p_log_vp.add_argument(
        "--pubkey", help="Path to checkpoint public key PEM (required with --checkpoint)"
    )
    p_log_vp.set_defaults(func=cmd_log_verify_proof)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
