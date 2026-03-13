# CEYO Protocol — End-to-End Pipeline

Version: 1.0-draft
Status: Draft

---

## Overview

The CEYO pipeline transforms a raw AI decision event into a tamper-evident,
independently verifiable record anchored in a signed Merkle transparency log.
Each stage is deterministic: identical inputs always produce identical
cryptographic outputs.

```
Input / Output
      ↓
Canonicalization
      ↓
Hash + Signature
      ↓
Artifact Envelope
      ↓
Transparency Log
      ↓
Signed Checkpoint
      ↓
Standalone Verification
      ↓
Inclusion Proof Validation
```

---

## Stage 1 — Input / Output

**Purpose:** Define what gets recorded.

An AI decision event is captured according to an operator-defined capture
policy. The policy determines which fields are included, excluded, or masked.
Raw inputs and outputs are **not** stored; only policy-scoped references
(SHA-256 hashes of a canonicalized representation) are embedded in the
artifact body.

**Body fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `event.event_id` | Yes | Unique identifier for this event |
| `event.type` | Yes | Event type (e.g. `inference`, `classification`) |
| `event.occurred_at` | Yes | ISO 8601 UTC timestamp |
| `event.request_id` | No | Correlation ID for the originating request |
| `policy.id` | No | Capture policy identifier |
| `policy.version` | No | Capture policy version |
| `disclosure_tier` | No | `public`, `internal`, or `restricted` |
| `capture.input_ref_hash` | No | SHA-256 hash of policy-scoped input |
| `capture.output_ref_hash` | No | SHA-256 hash of policy-scoped output |
| `environment` | No | Deployment and model metadata |

**Schema:** `spec/artifact-schema.json` (body sub-object)

**Reference implementation:** `ceyo/seal.py:seal()`, `ceyo/client.py:CeyoClient.trace()`

---

## Stage 2 — Canonicalization

**Purpose:** Produce a deterministic byte sequence from the artifact body so
that any party can reproduce the exact same bytes from the same data.

**Algorithm:**

1. Serialize the body object using RFC 8785 (JSON Canonicalization Scheme).
   RFC 8785 enforces: lexicographic key ordering, no insignificant whitespace,
   deterministic number encoding, UTF-8 output.
2. If RFC 8785 is unavailable, fall back to sorted-key compact JSON
   (`sort_keys=True`, `separators=(",", ":")`, UTF-8).
3. Record the scheme name in `canonicalization.scheme` so verifiers can
   reproduce it exactly.

**Output:** `canonical_bytes: bytes`

**Declared in envelope:** `canonicalization.scheme` — either `"RFC8785"` or
`"deterministic-json-fallback"`.

**Reference implementation:** `ceyo/crypto.py:canonicalize()`

**Standalone implementation:** `ceyo_verify/verifier.py:_canonicalize()`

---

## Stage 3 — Hash + Signature

**Purpose:** Cryptographically bind the artifact body to the issuing key so
that any modification is detectable.

### 3a — Hash

```
digest = SHA-256(canonical_bytes)
```

- Algorithm: SHA-256 (FIPS 180-4)
- Output: 32-byte digest, encoded as base64url (no padding)
- Stored in: `integrity.hash.value_b64u`

### 3b — Signature

```
signature = ECDSA-P256(private_key, digest, Prehashed-SHA256)
```

- Curve: NIST P-256 (secp256r1)
- Hash: SHA-256 (prehashed mode — the 32-byte digest is signed directly)
- Encoding: DER (Distinguished Encoding Rules)
- Stored in: `integrity.sig.value_b64u`

**Key reference** is embedded alongside the signature in `key_reference`,
including the SHA-256 fingerprint of the public key's SPKI DER encoding.
This fingerprint is checked during verification to detect key-substitution
attacks.

**Reference implementation:** `ceyo/seal.py:seal_body()`

**Standalone implementation:** `ceyo_verify/verifier.py:verify_artifact()`

---

## Stage 4 — Artifact Envelope

**Purpose:** Package the body, canonicalization metadata, integrity proofs,
and key reference into a single self-describing JSON document.

**Top-level envelope fields:**

| Field | Value / Description |
|-------|---------------------|
| `product` | `"CEYO"` (constant) |
| `envelope_version` | `"1.0"` |
| `artifact_schema` | `{"name": "ceyo.artifact", "version": "1.0"}` |
| `artifact_id` | Unique ID matching `^ceyo_art_` |
| `created_at` | ISO 8601 UTC timestamp |
| `body` | Policy-scoped event data (Stage 1) |
| `canonicalization` | Scheme, version, scope |
| `integrity` | Hash and signature blocks (Stage 3) |
| `key_reference` | Registry, key ID, public key fingerprint |

**Schema:** `spec/artifact-schema.json`

**Reference implementation:** `ceyo/seal.py:seal_body()` (envelope assembly),
`ceyo/schema.py` (validation)

---

## Stage 5 — Transparency Log

**Purpose:** Record each sealed artifact in an append-only Merkle tree so
that the complete log can be audited and individual membership can be proven.

### Log Entry

Each entry records:

```
artifact_hash = SHA-256(canonical(envelope))
leaf_hash     = SHA-256(0x00 ‖ artifact_hash)
```

The `0x00` prefix is the RFC 6962 leaf domain separator, preventing
second-preimage attacks between leaf hashes and internal node hashes.

### Merkle Tree

Nodes are computed as:

```
node_hash(left, right) = SHA-256(0x01 ‖ left ‖ right)
```

The `0x01` prefix is the RFC 6962 internal-node domain separator.

Tree construction: leaves are hashed in append order. At each level, pairs
of nodes are combined. Lone nodes at odd positions are **promoted unchanged**
(not duplicated). This matches the RFC 6962 / Certificate Transparency
convention.

**Storage:** SQLite database with append-only semantics enforced by a
`UNIQUE` constraint on `artifact_id`.

**Schema:** `spec/inclusion-proof.schema.json`

**Reference implementation:** `ceyo/transparency_log.py:TransparencyLog`

---

## Stage 6 — Signed Checkpoint

**Purpose:** Produce a signed, timestamped snapshot of the Merkle tree root
so that inclusion proofs can be anchored to a specific verifiable state.

### Checkpoint Body

```json
{
  "product": "CEYO",
  "type":    "transparency-checkpoint",
  "tree_size": <integer>,
  "root_hash": "<base64url SHA-256>",
  "created_at": "<ISO 8601 UTC>"
}
```

### Signing

```
checkpoint_digest = SHA-256(canonical(checkpoint_body))
checkpoint_sig    = ECDSA-P256(private_key, checkpoint_digest, Prehashed-SHA256)
```

The same signing algorithm as artifact sealing is used. The full checkpoint
embeds `sig` and `key_reference` fields alongside the body fields.

**Schema:** `spec/checkpoint.schema.json`

**Reference implementation:** `ceyo/transparency_log.py:TransparencyLog.checkpoint()`

**Standalone verifier:** `ceyo_verify/transparency.py:verify_inclusion_proof()`
(checkpoint signature verification)

---

## Stage 7 — Standalone Verification

**Purpose:** Allow any third party to verify an artifact's integrity and
authenticity without access to the CEYO SDK or the originating AI system.

**Steps:**

1. Validate envelope schema (required fields, const values, patterns).
2. Load the ECDSA P-256 public key from PEM.
3. Canonicalize `artifact["body"]` using the declared scheme.
4. Recompute SHA-256 and compare to `integrity.hash.value_b64u` (timing-safe).
5. Verify ECDSA DER signature in `integrity.sig.value_b64u` against the digest.
6. Optionally verify key fingerprint in `key_reference.public_key_fingerprint`.

**Dependencies:** standard library + `cryptography` + optional `rfc8785`.
No CEYO SDK required.

**Reference implementation:** `ceyo_verify/verifier.py:verify_artifact()`

**CLI:** `python -m ceyo_verify <artifact.json> <pubkey.pem>`

---

## Stage 8 — Inclusion Proof Validation

**Purpose:** Prove that a specific artifact was included in the Merkle tree
at the time a checkpoint was signed, without replaying the entire log.

### Proof Structure

```json
{
  "artifact_id":   "ceyo_art_...",
  "artifact_hash": "<base64url SHA-256>",
  "leaf_index":    <integer>,
  "tree_size":     <integer>,
  "root_hash":     "<base64url SHA-256>",
  "hashes": [
    { "direction": "left"|"right", "value_b64u": "<base64url SHA-256>" },
    ...
  ]
}
```

### Validation Algorithm

```
current = SHA-256(0x00 ‖ b64u_decode(proof.artifact_hash))   # leaf hash

for each step in proof.hashes:
    sibling = b64u_decode(step.value_b64u)
    if step.direction == "right":
        current = SHA-256(0x01 ‖ current ‖ sibling)
    else:
        current = SHA-256(0x01 ‖ sibling ‖ current)

assert current == b64u_decode(proof.root_hash)
```

If a checkpoint is provided, additionally verify:

1. Checkpoint ECDSA signature is valid (Stage 6 algorithm).
2. `proof.root_hash == checkpoint.root_hash`
3. `proof.tree_size == checkpoint.tree_size`

**Schema:** `spec/inclusion-proof.schema.json`

**Reference implementation:** `ceyo/transparency_log.py:TransparencyLog.prove_inclusion()`

**Standalone verifier:** `ceyo_verify/transparency.py:verify_inclusion_proof()`

---

## Pipeline Properties

| Property | Guarantee |
|----------|-----------|
| **Determinism** | Identical body → identical canonical bytes → identical hash |
| **Integrity** | Any modification to body bytes causes hash mismatch |
| **Authenticity** | Signature can only be produced by the holder of the private key |
| **Non-repudiation** | Key fingerprint in envelope binds signature to a specific public key |
| **Append-only log** | UNIQUE constraint + sequential seq prevent insertion or reordering |
| **Merkle membership** | Inclusion proof size is O(log n); verification is O(log n) |
| **Checkpoint anchoring** | Checkpoint signature binds root hash to a specific key and timestamp |
| **Independent verification** | All stages 7 and 8 require only stdlib + `cryptography` |

---

## Algorithm Reference

| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Canonicalization | RFC 8785 JCS | RFC 8785 |
| Body hash | SHA-256 | FIPS 180-4 |
| Artifact signature | ECDSA P-256 (prehashed) | FIPS 186-5 |
| Key fingerprint | SHA-256 of SPKI DER | RFC 5480 |
| Log leaf hash | SHA-256(0x00 ‖ data) | RFC 6962 §2.1 |
| Log node hash | SHA-256(0x01 ‖ left ‖ right) | RFC 6962 §2.1 |
| Checkpoint hash | SHA-256 of canonical body | FIPS 180-4 |
| Checkpoint signature | ECDSA P-256 (prehashed) | FIPS 186-5 |
| All base64url encoding | Base64url, no padding | RFC 4648 §5 |
