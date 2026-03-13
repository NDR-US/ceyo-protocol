# CEYO

Cryptographic evidentiary infrastructure for AI systems.

CEYO seals AI decision records as tamper-evident artifacts. Each artifact is canonicalized, SHA-256 hashed, and ECDSA-P256 signed. Any third party can verify integrity without access to the originating system.

---

## Install

```bash
pip install .
```

For development (ruff, mypy, coverage, pytest):

```bash
pip install -e ".[dev]"
```

This installs the `ceyo` package, the `ceyo` CLI, and the `ceyo_verify` standalone verifier.

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

Output: `sealed_artifact.json` — a fully structured envelope containing the artifact body, canonicalization metadata, SHA-256 hash, and ECDSA-P256 signature.

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

The `ceyo_verify` package depends only on `cryptography` and `rfc8785`:

```bash
python -m ceyo_verify sealed_artifact.json keys/public.pem
```

---

## SDK usage

```python
from ceyo import CeyoClient
from ceyo.keys import LocalKeyProvider
from ceyo.store import ArtifactStore

client = CeyoClient(
    key_provider=LocalKeyProvider("keys/private.pem"),
    store=ArtifactStore("artifacts.db"),
)

# Seal a body dict
envelope = client.seal({
    "event": {
        "event_id": "evt_001",
        "type": "classification",
        "occurred_at": "2026-03-09T12:00:00Z",
    },
    "policy": {"id": "POL-001", "version": "1.0"},
    "disclosure_tier": "internal",
})

# Verify
result = client.verify(envelope)
assert result.ok

# @trace decorator — seals an artifact automatically per call
@client.trace(event_type="inference", policy_id="POL-001")
def predict(text):
    return model(text)
```

See [`examples/basic_usage.py`](examples/basic_usage.py) for a complete runnable demo.

---

## Verification steps

Both `ceyo verify` and `python -m ceyo_verify` perform:

1. **Schema validation** — envelope structure, required fields, const values, `artifact_id` prefix pattern, ISO 8601 timestamp format
2. **Key load** — verify the PEM is a valid ECDSA `EllipticCurvePublicKey`
3. **Canonicalization** — reproduce `canonical(body)` using the scheme declared in `artifact["canonicalization"]["scheme"]` (RFC 8785 or deterministic-JSON fallback)
4. **Hash verification** — recompute SHA-256 and compare (timing-safe) to `integrity.hash.value_b64u`
5. **Signature verification** — ECDSA-P256 DER signature over the SHA-256 digest
6. **Key fingerprint** — SHA-256 of the public key SPKI DER compared to `key_reference.public_key_fingerprint.value_b64u`

The standalone `ceyo_verify` package shares no code with the `ceyo` SDK. It reimplements only the primitives needed for verification (base64url, canonicalization, schema check) so that independent verifiers have no SDK dependency.

---

## Package structure

```
ceyo/               # SDK — seal, verify, store, client, keys, schema, crypto, CLI
ceyo_verify/        # Standalone verifier — no ceyo dependency
docs/               # Protocol specification and schema files
examples/           # Runnable usage examples
tests/              # Unit, integration, negative, and CLI smoke tests
spec/               # Artifact JSON Schema (artifact-schema.json)
```

### Package boundary

`ceyo_verify` intentionally does not import from `ceyo`. It reproduces the canonical verification logic (canonicalization, hash replay, ECDSA signature check) using only `cryptography` and `rfc8785`. This preserves the independent-verifier property of the protocol.

---

## CLI reference

```
ceyo keygen  [--out-private PATH] [--out-public PATH] [--force]
ceyo seal    <record.json> [--key PATH] [-o OUTPUT] [--no-validate]
ceyo verify  <artifact.json> <public_key.pem>
ceyo store list          <store.db> [-n LIMIT]
ceyo store inspect       <store.db> <artifact_id>
ceyo store verify-chain  <store.db>

python -m ceyo_verify <artifact.json> <public_key.pem>
```

---

## Artifact envelope

Every sealed artifact is a JSON object with this structure:

```json
{
  "product": "CEYO",
  "envelope_version": "1.0",
  "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
  "artifact_id": "ceyo_art_<hex>",
  "created_at": "2026-03-09T12:00:00Z",
  "body": { ... },
  "canonicalization": {
    "scheme": "RFC8785",
    "version": "1.0",
    "scope": "body"
  },
  "integrity": {
    "hash": {"alg": "SHA-256", "value_b64u": "...", "covers": "canonical(body)"},
    "sig":  {"alg": "ECDSA-P256-SHA256", "format": "DER", "value_b64u": "...", "covers": "canonical(body)"}
  },
  "key_reference": {
    "registry": "local",
    "key_id": "local:public_key.pem",
    "public_key_fingerprint": {"alg": "SHA-256", "value_b64u": "...", "covers": "public_key_spki_der"}
  }
}
```

Full schema: [`spec/artifact-schema.json`](spec/artifact-schema.json)

---

## Artifact store

`ArtifactStore` is an append-only SQLite log with hash chaining. Each row records:

- the sealed envelope (JSON)
- `entry_hash` — SHA-256 of the canonical envelope bytes
- `chain_hash` — SHA-256 of `prev_chain_hash:entry_hash`

Tampering with any stored envelope breaks the chain and is detected by `ceyo store verify-chain`.

---

## Runtime-generated files

The following files are generated at runtime and gitignored:

| Pattern | Description |
|---------|-------------|
| `*.pem` | Key pair files generated by `ceyo keygen` or `LocalKeyProvider` |
| `*.db`, `*.db-shm`, `*.db-wal` | SQLite artifact store and WAL files |
| `example_artifact/sealed_artifact.json` | Sealed output from demo/CI |

---

## Non-goals

CEYO does not:

- determine whether an AI decision is correct
- prove fairness or absence of bias
- certify regulatory compliance
- enforce governance policies
- modify or instrument model behavior

CEYO provides tamper-evident records that allow independent cryptographic verification of captured AI decision data.

---

## License

Copyright (c) 2026 Brian Covarrubias. All rights reserved.

This repository is provided for informational and evaluation purposes. No license to use, copy, modify, or distribute is granted without explicit written permission from the author.
