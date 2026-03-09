#!/usr/bin/env python3
"""Basic CEYO SDK usage examples."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ceyo import CeyoClient, ArtifactStore
from ceyo.keys import InMemoryKeyProvider


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
    print(f"Sealed artifact: {envelope['artifact_id']}")

    result = client.verify(envelope)
    print(f"Verification: {result}")
    for msg in result.passed:
        print(f"  PASS: {msg}")


def example_decorator():
    """Use the @trace decorator to automatically seal function calls."""
    print("\n=== Decorator ===")
    client = CeyoClient()

    @client.trace(event_type="classification", policy_id="DEMO-001")
    def classify(text: str) -> str:
        # Simulated AI classification
        if "urgent" in text.lower():
            return "high_priority"
        return "normal"

    result = classify("This is an urgent request")
    print(f"Classification result: {result}")
    print("Artifact sealed automatically")


def example_store():
    """Use the artifact store for append-only logging with chain integrity."""
    print("\n=== Artifact Store ===")
    import tempfile
    import os

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

    os.unlink(db_path)


if __name__ == "__main__":
    example_seal_and_verify()
    example_decorator()
    example_store()
