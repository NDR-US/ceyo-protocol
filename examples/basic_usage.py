#!/usr/bin/env python3
"""CEYO SDK — runnable usage examples.

Run from the repo root after ``pip install -e .``::

    python examples/basic_usage.py
"""

import os
import tempfile

from ceyo import ArtifactStore, CeyoClient
from ceyo.keys import InMemoryKeyProvider
from ceyo_verify import verify_artifact as standalone_verify


def example_seal_and_verify():
    """Seal an artifact and verify it."""
    print("=== Seal and Verify ===")
    client = CeyoClient()

    body = {
        "event": {
            "event_id": "evt_example_001",
            "type": "classification",
            "occurred_at": "2026-03-09T12:00:00Z",
            "request_id": "req_example_001",
        },
        "policy": {"id": "DEMO-001", "version": "1.0"},
        "disclosure_tier": "public",
    }

    envelope = client.seal(body, persist=False)
    print(f"Artifact ID: {envelope['artifact_id']}")

    result = client.verify(envelope)
    print(f"SDK verify:  {result}")
    for msg in result.passed:
        print(f"  PASS: {msg}")


def example_standalone_verify():
    """Verify using the standalone ceyo_verify verifier (no SDK dependency)."""
    print("\n=== Standalone Verify (ceyo_verify) ===")
    kp = InMemoryKeyProvider()
    body = {
        "event": {
            "event_id": "evt_standalone_001",
            "type": "inference",
            "occurred_at": "2026-03-09T12:00:00Z",
        },
    }
    from ceyo.seal import seal_body
    envelope = seal_body(body, kp)

    result = standalone_verify(envelope, kp.get_public_key_pem())
    print(f"Standalone verify: {result}")
    assert result.ok, "Standalone verification should pass"
    print("Independent verification confirmed.")


def example_decorator():
    """Use the @trace decorator to automatically seal function calls."""
    print("\n=== Decorator (@client.trace) ===")
    client = CeyoClient()

    @client.trace(event_type="classification", policy_id="DEMO-001")
    def classify(text: str) -> str:
        if "urgent" in text.lower():
            return "high_priority"
        return "normal"

    label = classify("This is an urgent request")
    print(f"Classification: {label}")
    print("Artifact sealed automatically via @trace.")


def example_store():
    """Append-only store with hash-chain integrity verification."""
    print("\n=== Artifact Store ===")
    db_path = os.path.join(tempfile.mkdtemp(), "example.db")

    with ArtifactStore(db_path) as store:
        client = CeyoClient(store=store)

        for i in range(5):
            body = {
                "event": {
                    "event_id": f"evt_batch_{i:04d}",
                    "type": "inference",
                    "occurred_at": "2026-03-09T12:00:00Z",
                },
                "disclosure_tier": "internal",
            }
            client.seal(body)

        print(f"Stored {store.count()} artifacts")
        ok, checked = store.verify_chain()
        print(f"Chain integrity: {'PASSED' if ok else 'FAILED'} ({checked} entries)")


if __name__ == "__main__":
    example_seal_and_verify()
    example_standalone_verify()
    example_decorator()
    example_store()
    print("\nAll examples completed successfully.")
