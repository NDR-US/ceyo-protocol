#!/usr/bin/env python3
"""CEYO protocol-v2 runnable usage examples.

Run from the repository root after ``pip install -e .``::

    python examples/basic_usage.py
"""

import os
import tempfile

from ceyo import ArtifactStore, CeyoClient
from ceyo.keys import InMemoryKeyProvider
from ceyo.seal import seal_body
from ceyo_verify import verify_artifact as standalone_verify


def example_seal_and_verify():
    """Seal a protocol-v2 artifact and verify its cryptographic validity."""
    print("=== Seal and Verify ===")
    kp = InMemoryKeyProvider()
    client = CeyoClient(key_provider=kp)

    body = {
        "event": {
            "event_id": "evt_example_001",
            "type": "classification",
            "occurred_at": "2026-09-15T12:00:00Z",
            "request_id": "req_example_001",
        },
        "policy": {"id": "DEMO-001", "version": "1.0"},
        "disclosure_policy": {"tier": "public"},
    }

    artifact = client.seal(body, persist=False)
    print(f"Artifact ID: {artifact['protected']['artifact_id']}")

    result = client.verify(artifact)
    print(f"SDK verify:  {result}")
    for message in result.passed:
        print(f"  PASS: {message}")


def example_standalone_verify():
    """Verify using ceyo_verify, which does not import the CEYO SDK package."""
    print("\n=== Standalone Verify (ceyo_verify) ===")
    kp = InMemoryKeyProvider()
    body = {
        "event": {
            "event_id": "evt_standalone_001",
            "type": "inference",
            "occurred_at": "2026-09-15T12:00:00Z",
        },
    }
    artifact = seal_body(body, kp)

    result = standalone_verify(artifact, kp.get_public_key_pem())
    print(f"Standalone verify: {result}")
    assert result.ok, "Standalone artifact verification should pass"
    print("Artifact cryptographic validity confirmed by the standalone verifier.")


def example_decorator():
    """Use the @trace convenience decorator to seal function-call evidence."""
    print("\n=== Decorator (@client.trace) ===")
    client = CeyoClient(key_provider=InMemoryKeyProvider())

    @client.trace(event_type="classification", policy_id="DEMO-001")
    def classify(text: str) -> str:
        if "urgent" in text.lower():
            return "high_priority"
        return "normal"

    label = classify("This is an urgent request")
    print(f"Classification: {label}")
    print("A protocol-v2 artifact was sealed by the trace helper.")


def example_store():
    """Use the local hash-chained reference artifact store."""
    print("\n=== Artifact Store ===")
    db_path = os.path.join(tempfile.mkdtemp(), "example.db")
    kp = InMemoryKeyProvider()

    with ArtifactStore(db_path) as store:
        client = CeyoClient(key_provider=kp, store=store)

        for i in range(5):
            body = {
                "event": {
                    "event_id": f"evt_batch_{i:04d}",
                    "type": "inference",
                    "occurred_at": "2026-09-15T12:00:00Z",
                },
                "disclosure_policy": {"tier": "internal"},
            }
            client.seal(body)

        print(f"Stored {store.count()} artifacts")
        ok, checked = store.verify_chain()
        print(f"Local chain integrity: {'PASSED' if ok else 'FAILED'} ({checked} entries)")
        print("Note: the local chain is not an externally witnessed append-only guarantee.")


if __name__ == "__main__":
    example_seal_and_verify()
    example_standalone_verify()
    example_decorator()
    example_store()
    print("\nAll examples completed successfully.")
