# CEYO

Cryptographic evidentiary infrastructure for AI systems.

CEYO seals AI decision records as tamper-evident artifacts. Each artifact is
canonicalized, SHA-256 hashed, and ECDSA-P256 signed. Any third party can
verify integrity and trace membership in the transparency log without access
to the originating system.

---

## Repository Layout

```
spec/               ← Protocol specification, schemas, pipeline
ceyo/               ← Python reference implementation
ceyo_verify/        ← Independent verifier (no SDK dependency)
docs/               ← Developer integration guides
examples/           ← Runnable SDK examples
tests/              ← Unit, integration, negative, and CLI smoke tests
```

### Three Layers

| Layer | Directory | Role |
|-------|-----------|------|
| **Protocol** | `spec/` | Defines the standard — schemas, algorithms, pipeline, security model |
| **Reference impl** | `ceyo/` | Python SDK — seal, verify, store, transparency log, CLI |
| **Independent verifier** | `ceyo_verify/` | Standalone — only `cryptography` + `rfc8785`, no SDK dependency |

---

## Pipeline

```
Input / Output
      ↓
Canonicalization          (RFC 8785 / deterministic JSON)
      ↓
Hash + Signature          (SHA-256 + ECDSA-P256)
      ↓
Artifact Envelope         (spec/artifact-schema.json)
      ↓
Transparency Log          (append-only Merkle tree)
      ↓
Signed Checkpoint         (spec/checkpoint.schema.json)
      ↓
Standalone Verification   (ceyo_verify/verifier.py)
      ↓
Inclusion Proof Validation (ceyo_verify/transparency.py)
```

See [`spec/pipeline.md`](spec/pipeline.md) for the full specification of each stage.

---

## Install

```bash
pip install .
```

For development (ruff, mypy, coverage, pytest):

```bash
pip install -e ".[dev]"
```

This installs the `ceyo` package, the `ceyo` CLI, and the `ceyo_verify`
standalone verifier.

---

## Quickstart

### Generate a key pair

```bash
ceyo keygen --out-private keys/private.pem --out-public keys/public.pem
```

### Seal a record

```bash
ceyo seal example_artifact/sample_record.json \
    --key keys/private.pem \
    -o sealed_artifact.json
```

### Verify an artifact

```bash
ceyo verify sealed_artifact.json keys/public.pem
```

Expected output:

```
PASS: Schema valid
PASS: Hash matches
PASS: Signature valid
PASS: Key fingerprint matches

Verification PASSED
```

### Verify independently (no SDK required)

```bash
python -m ceyo_verify sealed_artifact.json keys/public.pem
```

### Transparency log

```bash
# Append artifacts to the log via the SDK, then:
ceyo log checkpoint ceyo_log.db --key keys/private.pem --output checkpoint.json
ceyo log prove      ceyo_log.db <artifact_id>          --output proof.json
ceyo log verify-proof proof.json \
    --checkpoint checkpoint.json \
    --pubkey keys/public.pem
```

---

## SDK Usage

```python
from ceyo import CeyoClient, TransparencyLog
from ceyo.keys import LocalKeyProvider
from ceyo.store import ArtifactStore

client = CeyoClient(
    key_provider=LocalKeyProvider("keys/private.pem"),
    store=ArtifactStore("artifacts.db"),
    log=TransparencyLog("ceyo_log.db"),
)

# Seal a body dict — automatically stored and logged
envelope = client.seal({
    "event": {
        "event_id":   "evt_001",
        "type":       "classification",
        "occurred_at":"2026-03-13T12:00:00Z",
    },
    "policy":          {"id": "POL-001", "version": "1.0"},
    "disclosure_tier": "internal",
})

result = client.verify(envelope)
assert result.ok

# @trace decorator — seals an artifact automatically per call
@client.trace(event_type="inference", policy_id="POL-001")
def predict(text):
    return model(text)
```

```python
# Standalone inclusion proof verification (no SDK)
from ceyo_verify import verify_inclusion_proof
import json

proof      = json.load(open("proof.json"))
checkpoint = json.load(open("checkpoint.json"))
pubkey_pem = open("keys/public.pem", "rb").read()

result = verify_inclusion_proof(proof, checkpoint, pubkey_pem)
assert result.ok
```

See [`examples/basic_usage.py`](examples/basic_usage.py) for a complete runnable demo.

---

## Verification Steps

Both `ceyo verify` and `python -m ceyo_verify` perform:

1. **Schema validation** — required fields, const values, `artifact_id` prefix, ISO 8601 timestamps
2. **Key load** — verify the PEM is a valid ECDSA `EllipticCurvePublicKey`
3. **Canonicalization** — reproduce `canonical(body)` using the declared scheme (RFC 8785 or fallback)
4. **Hash verification** — recompute SHA-256, compare timing-safe to `integrity.hash.value_b64u`
5. **Signature verification** — ECDSA-P256 DER signature over the SHA-256 digest
6. **Key fingerprint** — SHA-256 of public key SPKI DER vs `key_reference.public_key_fingerprint`

---

## CLI Reference

```
ceyo keygen  [--out-private PATH] [--out-public PATH] [--force]
ceyo seal    <record.json> [--key PATH] [-o OUTPUT] [--no-validate]
ceyo verify  <artifact.json> <public_key.pem>

ceyo store list          <store.db> [-n LIMIT]
ceyo store inspect       <store.db> <artifact_id>
ceyo store verify-chain  <store.db>

ceyo log list            <log.db> [-n LIMIT]
ceyo log checkpoint      <log.db> [--key PATH] [-o OUTPUT]
ceyo log prove           <log.db> <artifact_id> [-o OUTPUT]
ceyo log verify-proof    <proof.json> [--checkpoint FILE] [--pubkey FILE]

python -m ceyo_verify <artifact.json> <public_key.pem>
```

---

## Artifact Envelope

Every sealed artifact is a JSON object:

```json
{
  "product":          "CEYO",
  "envelope_version": "1.0",
  "artifact_schema":  {"name": "ceyo.artifact", "version": "1.0"},
  "artifact_id":      "ceyo_art_<hex>",
  "created_at":       "2026-03-13T12:00:00Z",
  "body":             { ... },
  "canonicalization": {"scheme": "RFC8785", "version": "1.0", "scope": "body"},
  "integrity": {
    "hash": {"alg": "SHA-256",         "value_b64u": "...", "covers": "canonical(body)"},
    "sig":  {"alg": "ECDSA-P256-SHA256","format": "DER", "value_b64u": "...", "covers": "canonical(body)"}
  },
  "key_reference": {
    "registry": "local",
    "key_id":   "local:public_key.pem",
    "public_key_fingerprint": {"alg": "SHA-256", "value_b64u": "...", "covers": "public_key_spki_der"}
  }
}
```

Full schema: [`spec/artifact-schema.json`](spec/artifact-schema.json)

---

## Specification

The `spec/` directory is the authoritative source for the protocol:

| Document | Description |
|----------|-------------|
| [`spec/pipeline.md`](spec/pipeline.md) | End-to-end pipeline specification |
| [`spec/protocol-specification.md`](spec/protocol-specification.md) | Formal protocol specification |
| [`spec/transparency-log.md`](spec/transparency-log.md) | Transparency log, Merkle tree, checkpoints, inclusion proofs |
| [`spec/security-model.md`](spec/security-model.md) | Security guarantees and assumptions |
| [`spec/threat-model.md`](spec/threat-model.md) | Threat categories and mitigations |
| [`spec/artifact-schema.json`](spec/artifact-schema.json) | JSON Schema for sealed envelopes |
| [`spec/checkpoint.schema.json`](spec/checkpoint.schema.json) | JSON Schema for signed checkpoints |
| [`spec/inclusion-proof.schema.json`](spec/inclusion-proof.schema.json) | JSON Schema for inclusion proofs |

---

## Runtime-Generated Files

Gitignored at runtime:

| Pattern | Description |
|---------|-------------|
| `*.pem` | Key pairs from `ceyo keygen` or `LocalKeyProvider` |
| `*.db`, `*.db-shm`, `*.db-wal` | SQLite artifact store and transparency log files |

---

## Non-Goals

CEYO does not:

- determine whether an AI decision is correct
- prove fairness or absence of bias
- certify regulatory compliance
- enforce governance policies
- modify or instrument model behavior

CEYO provides tamper-evident records that allow independent cryptographic
verification of captured AI decision data, anchored in a Merkle transparency
log with signed checkpoints and verifiable inclusion proofs.

---

## License

Copyright (c) 2026 Brian Covarrubias. All rights reserved.

This repository is provided for informational and evaluation purposes. No
license to use, copy, modify, or distribute is granted without explicit
written permission from the author.
