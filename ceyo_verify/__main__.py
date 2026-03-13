"""CLI entry point for ``python -m ceyo_verify``.

Usage::

    python -m ceyo_verify <sealed_artifact.json> <public_key.pem>

Exit codes: 0 = verification passed, 1 = verification failed, 2 = usage error.
"""

from __future__ import annotations

import sys

from ceyo_verify.verifier import load_artifact, load_pubkey, verify_artifact


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python -m ceyo_verify <artifact.json> <public_key.pem>", file=sys.stderr)
        sys.exit(2)

    artifact_path, pubkey_path = sys.argv[1], sys.argv[2]

    try:
        artifact = load_artifact(artifact_path)
    except FileNotFoundError:
        print(f"Error: artifact file not found: {artifact_path}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"Error reading artifact: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        pub_pem = load_pubkey(pubkey_path)
    except FileNotFoundError:
        print(f"Error: public key file not found: {pubkey_path}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"Error reading public key: {exc}", file=sys.stderr)
        sys.exit(2)

    result = verify_artifact(artifact, pub_pem)

    for msg in result.passed:
        print(f"PASS: {msg}")
    for msg in result.failed:
        print(f"FAIL: {msg}")

    status = "PASSED" if result.ok else "FAILED"
    print(f"\nVerification {status}")
    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
