# CEYO Developer Integration Guide

**Version:** 1.0
**Last Updated:** 2026-03-11

---

## 1. Overview

This guide explains how to integrate CEYO artifact generation into an AI system's inference pipeline. CEYO operates as a sidecar layer — it observes decision events, constructs evidentiary artifacts, and seals them cryptographically. It does not modify inference behavior.

After integration, your system produces cryptographically verifiable records of AI decision events that can be independently validated without access to your infrastructure.

---

## 2. Architecture: Where CEYO Attaches

CEYO attaches at the output boundary of the inference pipeline, after the AI system has produced a decision but before the response is returned to the caller.

```
┌─────────────────────────────────────────────────────┐
│                   AI System                         │
│                                                     │
│   Request ──► Preprocessing ──► Model Inference     │
│                                       │             │
│                                       ▼             │
│                                 Decision Output     │
│                                       │             │
│           ┌───────────────────────────┤             │
│           │                           │             │
│           ▼                           ▼             │
│   ┌──────────────┐            Response Returned     │
│   │ CEYO Capture │                                  │
│   │    Layer     │                                  │
│   └──────┬───────┘                                  │
│          │                                          │
│          ▼                                          │
│   Artifact Body ──► Canonicalize ──► Hash ──► Sign  │
│                                                │    │
│                                                ▼    │
│                                        Sealed       │
│                                        Artifact     │
└─────────────────────────────────────────────────────┘
```

**Key principle:** CEYO operates on a non-blocking path. If artifact generation fails, the inference response is unaffected. CEYO is fail-open by design.

---

## 3. Integration Steps

### 3.1 Install the CEYO SDK

```bash
pip install ceyo
```

Requires Python 3.10+. The SDK has two dependencies: `cryptography` and `rfc8785`.

### 3.2 Initialize a Client

```python
from ceyo.client import CeyoClient

client = CeyoClient()
```

The default client generates an ephemeral ECDSA P-256 key pair and stores artifacts in a local SQLite database. For production use, configure a key provider and persistent storage.

### 3.3 Instrument Decision Events

At the point in your pipeline where a decision is produced, call the CEYO client to seal the event:

```python
from datetime import datetime, timezone

artifact = client.seal(
    event_id="evt_20260311_001",
    event_type="classification",
    occurred_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    request_id="req_abc123",
    policy_id="content-moderation-v2",
    policy_version="2.1",
    disclosure_tier="internal",
    capture={
        "input_ref_hash": {
            "alg": "SHA-256",
            "value_b64u": "<sha256_of_policy_scoped_input>",
            "covers": "policy_scoped_input_representation"
        },
        "output_ref_hash": {
            "alg": "SHA-256",
            "value_b64u": "<sha256_of_policy_scoped_output>",
            "covers": "policy_scoped_output_representation"
        }
    },
    environment={
        "deployment_id": "prod-us-east-1",
        "model_ref": "content-classifier-v3.2",
        "runtime_ref": "inference-cluster-07"
    }
)
```

The `seal()` method:
1. Constructs the artifact body from the provided fields
2. Validates the body against the artifact schema
3. Canonicalizes the body using RFC 8785
4. Computes the SHA-256 digest
5. Signs the digest with ECDSA P-256
6. Assembles the complete artifact envelope
7. Persists the artifact to the configured store

### 3.4 Using the Trace Decorator

For simpler integration, use the `@trace` decorator to automatically capture function calls:

```python
from ceyo.client import CeyoClient

client = CeyoClient()

@client.trace(event_type="inference", policy_id="default-policy")
def classify(text: str) -> str:
    # Your inference logic here
    return model.predict(text)
```

Each call to the decorated function generates a sealed artifact automatically.

---

## 4. Policy-Scoped Capture

### 4.1 Principle

CEYO does not capture raw model inputs or outputs. Instead, it records policy-scoped references — typically cryptographic hashes of the data, scoped to what the capture policy permits.

This design ensures:
- No sensitive user data is stored in artifacts
- Capture scope is explicitly defined and auditable
- Artifacts remain useful for verification without containing proprietary data

### 4.2 Example Capture Policy Scope

```
Record:
  ✓ Event identifier and timestamp
  ✓ Request identifier
  ✓ SHA-256 hash of policy-scoped input representation
  ✓ SHA-256 hash of policy-scoped output representation
  ✓ Model reference and deployment identifier

Do not record:
  ✗ Raw user input text
  ✗ Raw model output
  ✗ Model weights or parameters
  ✗ User identity information
```

### 4.3 Capture Fields

The `capture` object in the artifact body contains references to the data observed during the decision event. Typical fields:

| Field | Description |
|---|---|
| `input_ref_hash` | SHA-256 hash of the policy-scoped input representation |
| `output_ref_hash` | SHA-256 hash of the policy-scoped output representation |

Each hash reference includes `alg`, `value_b64u`, and `covers` fields to make the reference self-describing.

### 4.4 Disclosure Tiers

The `disclosure_tier` field controls the sensitivity classification of the artifact:

- `"public"` — Artifact may be shared with external parties
- `"internal"` — Artifact restricted to organizational access
- `"restricted"` — Artifact subject to additional access controls

Tiers are advisory. Enforcement is the responsibility of the storage and access layer.

---

## 5. Artifact Construction

### 5.1 Body Construction

The artifact body is assembled from event metadata, policy references, capture data, and environment information. The body is a plain JSON object.

```python
body = {
    "event": {
        "event_id": "evt_20260311_001",
        "type": "classification",
        "occurred_at": "2026-03-11T14:30:00Z"
    },
    "policy": {
        "id": "content-moderation-v2",
        "version": "2.1"
    },
    "disclosure_tier": "internal",
    "capture": { ... },
    "environment": { ... }
}
```

### 5.2 Direct Body Sealing

If you construct the body manually, use `seal_body()`:

```python
from ceyo.seal import seal_body

envelope = seal_body(body, key_provider=my_key_provider)
```

---

## 6. Sealing Process

The sealing process transforms an artifact body into a complete, cryptographically sealed envelope.

```
Body (JSON object)
  │
  ▼
Canonicalize (RFC 8785)
  │
  ▼
Canonical Bytes (UTF-8)
  │
  ▼
SHA-256 Digest (32 bytes)
  │
  ▼
ECDSA-P256 Sign (DER-encoded signature)
  │
  ▼
Assemble Envelope (body + integrity + key_reference + metadata)
```

The sealing process is deterministic: the same body, signed with the same key, produces the same hash (though ECDSA signatures include randomness by design).

---

## 7. Verification

### 7.1 Verifying Artifacts

```python
from ceyo.verify import verify_artifact

# Load the public key
with open("public_key.pem", "rb") as f:
    pub_key_pem = f.read()

result = verify_artifact(artifact, pub_key_pem)

if result.ok:
    print("Verification PASSED")
else:
    print("Verification FAILED")
    for msg in result.failed:
        print(f"  FAIL: {msg}")
```

### 7.2 CLI Verification

```bash
ceyo verify sealed_artifact.json --key public_key.pem
```

### 7.3 Third-Party Verification

Verification requires only:
- The sealed artifact JSON
- The public verification key
- An RFC 8785 implementation
- Standard SHA-256 and ECDSA P-256 libraries

No access to the CEYO SDK, the AI system, or any proprietary infrastructure is needed.

---

## 8. Key Management

### 8.1 Default (Development)

The default `InMemoryKeyProvider` generates an ephemeral ECDSA P-256 key pair. Suitable for development and testing only.

### 8.2 Environment-Based Keys

For CI/CD and containerized deployments, load keys from environment variables using `EnvKeyProvider` (available in ceyo-core):

```python
from ceyo_core import EnvKeyProvider

provider = EnvKeyProvider()  # Reads CEYO_PRIVATE_KEY, CEYO_KEY_ID
client = CeyoClient(key_provider=provider)
```

### 8.3 HSM / KMS Integration

For production environments, use hardware-backed key management:

```python
from ceyo_core import KmsKeyProvider

provider = KmsKeyProvider(key_id="arn:aws:kms:us-east-1:...:key/...")
client = CeyoClient(key_provider=provider)
```

The private key never leaves the KMS boundary. Signing operations are delegated to the KMS API.

---

## 9. Storage

### 9.1 Default Store

The CEYO SDK includes a local SQLite-backed artifact store with append-only semantics and hash chaining:

```python
client = CeyoClient(store_path="artifacts.db")
```

### 9.2 Retrieving Artifacts

```python
# By artifact ID
artifact = client.store.get("ceyo_art_a5e2f966f10d49e1be3c47a5ca")

# All artifacts
for artifact in client.store.list():
    print(artifact["artifact_id"])
```

### 9.3 Exporting for Audit

```python
from ceyo_core import StoreExporter

exporter = StoreExporter(client.store)
exporter.to_jsonl("artifacts.jsonl")
exporter.to_csv("artifacts.csv")
```

---

## 10. Deployment Patterns

### 10.1 Sidecar

CEYO runs as a sidecar process alongside the inference service. The inference service emits decision events over a local interface (function call, Unix socket, or local HTTP). The sidecar seals artifacts independently.

### 10.2 In-Process

CEYO runs within the inference process using the SDK. Suitable for simpler deployments where operational isolation is not required.

### 10.3 Gateway

A CEYO capture layer sits at the API gateway, observing requests and responses. Artifacts are generated from the gateway's perspective without modifying the inference service.

---

## 11. Failure Handling

CEYO is designed to be fail-open. If artifact generation fails for any reason:

- The inference response is NOT blocked or delayed
- The failure is logged for operational monitoring
- The system continues normal operation

Artifact generation failures should be treated as operational alerts, not system-critical failures.
