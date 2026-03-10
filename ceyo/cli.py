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
from ceyo.verify import verify_artifact


def cmd_seal(args: argparse.Namespace) -> None:
    """Seal a JSON record file."""
    body: dict[str, Any] = json.loads(Path(args.record).read_text(encoding="utf-8"))
    key_provider = LocalKeyProvider(args.key)
    envelope = seal_body(body, key_provider, validate=not args.no_validate)

    output = args.output or str(Path(args.record).with_suffix(".sealed.json"))
    Path(output).write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Sealed: {output}")
    print(f"Public key: {key_provider._pub_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a sealed artifact against a public key."""
    artifact: dict[str, Any] = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    pub_pem = Path(args.pubkey).read_bytes()

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


def cmd_store_verify_chain(args: argparse.Namespace) -> None:
    """Verify the hash chain integrity of a store database."""
    with ArtifactStore(args.db) as store:
        ok, count = store.verify_chain()
        status = "INTACT" if ok else "BROKEN"
        print(f"Checked {count} entries: {status}")
        sys.exit(0 if ok else 1)


def cmd_store_export(args: argparse.Namespace) -> None:
    """Export artifacts from a store database."""
    with ArtifactStore(args.db) as store:
        if args.format == "jsonl":
            content = store.export_jsonl(args.output)
        else:
            content = store.export_csv(args.output)

        if args.output:
            print(f"Exported to {args.output}")
        else:
            print(content, end="")


def cmd_version(_args: argparse.Namespace) -> None:
    """Show CEYO version and schema info."""
    from ceyo.schema_version import CURRENT_VERSION, list_versions

    print("ceyo 0.1.0")
    print(f"Schema version: {CURRENT_VERSION}")
    print(f"Known versions: {', '.join(list_versions())}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="ceyo", description="CEYO Protocol CLI")
    sub = parser.add_subparsers(dest="command", required=True)

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

    p_chain = store_sub.add_parser("verify-chain", help="Verify store chain integrity")
    p_chain.add_argument("db", help="Path to SQLite database")
    p_chain.set_defaults(func=cmd_store_verify_chain)

    p_export = store_sub.add_parser("export", help="Export artifacts for auditors")
    p_export.add_argument("db", help="Path to SQLite database")
    p_export.add_argument(
        "--format", "-f", choices=["jsonl", "csv"], default="jsonl", help="Export format (default: jsonl)",
    )
    p_export.add_argument("--output", "-o", help="Output file path (default: stdout)")
    p_export.set_defaults(func=cmd_store_export)

    # ceyo version
    p_version = sub.add_parser("version", help="Show version and schema info")
    p_version.set_defaults(func=cmd_version)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
