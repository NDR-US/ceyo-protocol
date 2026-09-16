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


def _artifact_meta(artifact: dict[str, Any]) -> tuple[str, str]:
    protected = artifact.get("protected")
    if isinstance(protected, dict) and protected.get("protocol_version") == "2.0":
        return str(protected["artifact_id"]), str(protected["sealed_at"])
    return str(artifact["artifact_id"]), str(artifact["created_at"])


def cmd_keygen(args: argparse.Namespace) -> None:
    """Generate a new ECDSA P-256 key pair and write to PEM files."""
    priv_path = Path(args.out_private)
    pub_path = Path(args.out_public) if args.out_public else priv_path.with_suffix(".pub.pem")
    if priv_path.exists() and not args.force:
        print(
            f"Error: private key already exists: {priv_path}  (use --force to overwrite)",
            file=sys.stderr,
        )
        sys.exit(1)
    kp = LocalKeyProvider(priv_path, pub_path)
    kp.get_private_key()
    print(f"Private key: {priv_path}")
    print(f"Public key:  {pub_path}")
    print(f"Fingerprint: {kp.fingerprint()}")


def cmd_seal(args: argparse.Namespace) -> None:
    """Seal a JSON record file as a protocol-v2 artifact."""
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
    artifact_id, _ = _artifact_meta(envelope)
    print(f"Sealed:     {output}")
    print(f"Artifact:   {artifact_id}")
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
        for artifact in artifacts:
            artifact_id, sealing_time = _artifact_meta(artifact)
            print(f"  {artifact_id}  {sealing_time}")


def cmd_store_inspect(args: argparse.Namespace) -> None:
    """Inspect a single artifact from a store database."""
    with ArtifactStore(args.db) as store:
        artifact = store.get(args.artifact_id)
        if artifact is None:
            print(f"Error: artifact not found: {args.artifact_id}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(artifact, indent=2, ensure_ascii=False))


def cmd_store_verify_chain(args: argparse.Namespace) -> None:
    """Verify the hash-chain integrity of a store database."""
    with ArtifactStore(args.db) as store:
        ok, count = store.verify_chain()
        status = "INTACT" if ok else "BROKEN"
        print(f"Checked {count} entries: {status}")
        sys.exit(0 if ok else 1)


def cmd_log_list(args: argparse.Namespace) -> None:
    """List recent entries from a transparency-log database."""
    with TransparencyLog(args.db) as log:
        entries = log.list_entries(args.limit)
        if not entries:
            print("No entries in transparency log.")
            return
        for entry in entries:
            print(f"  [{entry['seq']:>6}]  {entry['artifact_id']}  {entry['logged_at']}")


def cmd_log_checkpoint(args: argparse.Namespace) -> None:
    """Sign and store a checkpoint of the current transparency-log state."""
    key_provider = LocalKeyProvider(args.key)
    with TransparencyLog(args.db, key_provider) as log:
        checkpoint = log.checkpoint()
        if args.output:
            Path(args.output).write_text(
                json.dumps(checkpoint, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"Checkpoint written: {args.output}")
        else:
            print(json.dumps(checkpoint, indent=2, ensure_ascii=False))
        print(
            f"Tree size: {checkpoint['tree_size']}  Root: {checkpoint['root_hash']}",
            file=sys.stderr,
        )


def cmd_log_prove(args: argparse.Namespace) -> None:
    """Generate an inclusion proof for an artifact in the transparency log."""
    with TransparencyLog(args.db) as log:
        try:
            proof = log.prove_inclusion(args.artifact_id)
        except KeyError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        if args.output:
            Path(args.output).write_text(
                json.dumps(proof, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            print(f"Proof written: {args.output}")
        else:
            print(json.dumps(proof, indent=2, ensure_ascii=False))


def cmd_log_verify_proof(args: argparse.Namespace) -> None:
    """Verify an inclusion proof, optionally against a signed checkpoint."""
    from ceyo_verify.transparency import verify_inclusion_proof

    try:
        proof: dict[str, Any] = json.loads(Path(args.proof).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Error: proof file not found: {args.proof}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON in proof file: {exc}", file=sys.stderr)
        sys.exit(1)

    checkpoint: dict[str, Any] | None = None
    if args.checkpoint:
        try:
            checkpoint = json.loads(Path(args.checkpoint).read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"Error: checkpoint file not found: {args.checkpoint}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError as exc:
            print(f"Error: invalid JSON in checkpoint file: {exc}", file=sys.stderr)
            sys.exit(1)

    pubkey_pem: bytes | None = None
    if args.pubkey:
        try:
            pubkey_pem = Path(args.pubkey).read_bytes()
        except FileNotFoundError:
            print(f"Error: public key file not found: {args.pubkey}", file=sys.stderr)
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

    p_keygen = sub.add_parser("keygen", help="Generate a new ECDSA P-256 key pair")
    p_keygen.add_argument("--out-private", default="ceyo_private.pem")
    p_keygen.add_argument("--out-public")
    p_keygen.add_argument("--force", action="store_true")
    p_keygen.set_defaults(func=cmd_keygen)

    p_seal = sub.add_parser("seal", help="Seal a JSON record")
    p_seal.add_argument("record")
    p_seal.add_argument("--key", default="ceyo_private.pem")
    p_seal.add_argument("--output", "-o")
    p_seal.add_argument("--no-validate", action="store_true")
    p_seal.set_defaults(func=cmd_seal)

    p_verify = sub.add_parser("verify", help="Verify a sealed artifact")
    p_verify.add_argument("artifact")
    p_verify.add_argument("pubkey")
    p_verify.set_defaults(func=cmd_verify)

    p_store = sub.add_parser("store", help="Artifact store operations")
    store_sub = p_store.add_subparsers(dest="store_command", required=True)
    p_list = store_sub.add_parser("list", help="List recent artifacts")
    p_list.add_argument("db")
    p_list.add_argument("--limit", "-n", type=int, default=10)
    p_list.set_defaults(func=cmd_store_list)
    p_inspect = store_sub.add_parser("inspect", help="Print one artifact")
    p_inspect.add_argument("db")
    p_inspect.add_argument("artifact_id")
    p_inspect.set_defaults(func=cmd_store_inspect)
    p_chain = store_sub.add_parser("verify-chain", help="Verify store chain")
    p_chain.add_argument("db")
    p_chain.set_defaults(func=cmd_store_verify_chain)

    p_log = sub.add_parser("log", help="Transparency log operations")
    log_sub = p_log.add_subparsers(dest="log_command", required=True)
    p_log_list = log_sub.add_parser("list", help="List recent entries")
    p_log_list.add_argument("db")
    p_log_list.add_argument("--limit", "-n", type=int, default=10)
    p_log_list.set_defaults(func=cmd_log_list)
    p_log_cp = log_sub.add_parser("checkpoint", help="Sign/store a checkpoint")
    p_log_cp.add_argument("db")
    p_log_cp.add_argument("--key", default="ceyo_private.pem")
    p_log_cp.add_argument("--output", "-o")
    p_log_cp.set_defaults(func=cmd_log_checkpoint)
    p_log_prove = log_sub.add_parser("prove", help="Generate inclusion proof")
    p_log_prove.add_argument("db")
    p_log_prove.add_argument("artifact_id")
    p_log_prove.add_argument("--output", "-o")
    p_log_prove.set_defaults(func=cmd_log_prove)
    p_log_vp = log_sub.add_parser("verify-proof", help="Verify inclusion proof")
    p_log_vp.add_argument("proof")
    p_log_vp.add_argument("--checkpoint")
    p_log_vp.add_argument("--pubkey")
    p_log_vp.set_defaults(func=cmd_log_verify_proof)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
