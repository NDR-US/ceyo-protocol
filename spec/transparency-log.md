# CEYO Transparency Log Specification

Version: 1.0-draft
Status: Draft

---

## 1. Purpose

The CEYO Transparency Log is an append-only Merkle tree that records the
hash of every sealed artifact. It provides two properties that the
artifact store alone cannot:

- **Global consistency:** any party with the log's public key can verify
  that a signed checkpoint covers a specific set of artifacts.
- **Efficient membership:** a logarithmic-size inclusion proof demonstrates
  that one artifact hash is in the tree without revealing any others.

The log is complementary to, and independent of, the `ArtifactStore` hash
chain. The store chains artifact envelopes; the log anchors artifact hashes
in a Merkle tree that can be publicly audited.

---

## 2. Definitions

| Term | Definition |
|------|------------|
| **Artifact hash** | `SHA-256(canonical(envelope))` — the authoritative digest of a sealed artifact |
| **Leaf hash** | `SHA-256(0x00 ‖ artifact_hash)` — the Merkle leaf value |
| **Node hash** | `SHA-256(0x01 ‖ left ‖ right)` — an internal Merkle node |
| **Root hash** | The single hash at the top of the Merkle tree |
| **Checkpoint** | A signed record of `(tree_size, root_hash, created_at)` |
| **Inclusion proof** | A sibling-hash path from a leaf to the root |
| **Log entry** | A record of `(seq, artifact_id, artifact_hash, leaf_hash, logged_at)` |

---

## 3. Log Entry

### 3.1 Appending

When a sealed artifact is logged, the implementation:

1. Computes `artifact_hash = SHA-256(canonical(envelope))`.
2. Computes `leaf_hash = SHA-256(0x00 ‖ artifact_hash)`.
3. Inserts `(artifact_id, artifact_hash, leaf_hash, logged_at)` into the
   log database. The row's `seq` (auto-increment integer primary key)
   determines the leaf's position: `leaf_index = seq - 1`.

### 3.2 Uniqueness

Each `artifact_id` may appear at most once. A second attempt to log the
same `artifact_id` is an error. This mirrors the UNIQUE constraint used by
the ArtifactStore.

### 3.3 Log Entry Fields

```json
{
  "seq":           1,
  "artifact_id":   "ceyo_art_...",
  "artifact_hash": "<base64url SHA-256>",
  "leaf_hash":     "<base64url SHA-256>",
  "logged_at":     "2026-03-13T12:00:00Z"
}
```

---

## 4. Merkle Tree

### 4.1 Hash Functions

| Operation | Expression |
|-----------|-----------|
| Leaf hash | `SHA-256(0x00 ‖ artifact_hash_bytes)` |
| Internal node | `SHA-256(0x01 ‖ left_bytes ‖ right_bytes)` |

The byte-prefix domain separators (`0x00` for leaves, `0x01` for internal
nodes) follow RFC 6962 §2.1. They prevent second-preimage attacks where an
internal node could be confused with a leaf.

### 4.2 Tree Construction

Given an ordered list of leaf hashes `[L_0, L_1, ..., L_{n-1}]`:

```
level = [L_0, L_1, ..., L_{n-1}]

while len(level) > 1:
    next = []
    for i in range(0, len(level) - 1, 2):
        next.append(node_hash(level[i], level[i+1]))
    if len(level) is odd:
        next.append(level[-1])   # promote lone node unchanged
    level = next

root = level[0]
```

**Odd-node promotion:** When a level has an odd number of nodes, the last
node is carried to the next level unchanged (not duplicated, not hashed with
itself). This matches RFC 6962 and Certificate Transparency.

### 4.3 Empty Tree

The empty-tree root is defined as `SHA-256(b"ceyo:empty-tree")`. This
constant allows a checkpoint to be issued before any artifacts are logged.

### 4.4 Tree Size

`tree_size` is the count of log entries (leaves) in the tree at the time
a root hash or checkpoint is computed.

---

## 5. Signed Checkpoint

### 5.1 Checkpoint Body

The object that is canonicalized and signed:

```json
{
  "product":    "CEYO",
  "type":       "transparency-checkpoint",
  "tree_size":  <integer>,
  "root_hash":  "<base64url SHA-256>",
  "created_at": "<ISO 8601 UTC>"
}
```

All five fields are required. The `created_at` field is included in the
signed body to prevent checkpoint replay.

### 5.2 Signing Algorithm

```
canonical_body = canonicalize(checkpoint_body)
digest         = SHA-256(canonical_body)
signature      = ECDSA-P256(private_key, digest, Prehashed-SHA256)
```

Canonicalization follows the same RFC 8785 / deterministic JSON fallback
procedure as artifact body sealing (see `spec/pipeline.md §2`).

### 5.3 Full Checkpoint Structure

```json
{
  "product":    "CEYO",
  "type":       "transparency-checkpoint",
  "tree_size":  42,
  "root_hash":  "<base64url SHA-256>",
  "created_at": "2026-03-13T12:00:00Z",
  "sig": {
    "alg":       "ECDSA-P256-SHA256",
    "format":    "DER",
    "value_b64u":"<base64url DER signature>",
    "covers":    "canonical(checkpoint_body)"
  },
  "key_reference": {
    "registry":  "<registry name>",
    "key_id":    "<key identifier>",
    "public_key_fingerprint": {
      "alg":       "SHA-256",
      "value_b64u":"<base64url SHA-256 of SPKI DER>",
      "covers":    "public_key_spki_der"
    }
  }
}
```

**Schema:** `spec/checkpoint.schema.json`

### 5.4 Checkpoint Verification

1. Extract `checkpoint_body` by taking the fields: `product`, `type`,
   `tree_size`, `root_hash`, `created_at` in that order.
2. Compute `digest = SHA-256(canonicalize(checkpoint_body))`.
3. Load the ECDSA P-256 public key from PEM.
4. Verify `sig.value_b64u` against `digest` using ECDSA P-256 (prehashed).

**Reference:** `ceyo_verify/transparency.py`

---

## 6. Inclusion Proofs

### 6.1 Proof Structure

```json
{
  "artifact_id":   "ceyo_art_...",
  "artifact_hash": "<base64url SHA-256>",
  "leaf_index":    0,
  "tree_size":     10,
  "root_hash":     "<base64url SHA-256>",
  "hashes": [
    { "direction": "right", "value_b64u": "<base64url SHA-256>" },
    { "direction": "left",  "value_b64u": "<base64url SHA-256>" }
  ]
}
```

**Schema:** `spec/inclusion-proof.schema.json`

### 6.2 Proof Generation

Given `leaf_index` and the full ordered list of leaf hashes:

```
current_index = leaf_index
level         = [all leaf hashes]
proof         = []

while len(level) > 1:
    build next level (same algorithm as §4.2)

    if current_index is even:
        if current_index + 1 < len(level):
            proof.append(("right", level[current_index + 1]))
        # else: lone node, no sibling at this level
    else:
        proof.append(("left", level[current_index - 1]))

    current_index = current_index // 2
    level = next level
```

### 6.3 Proof Verification Algorithm

```
# Step 1: recompute leaf hash from artifact hash
current = SHA-256(0x00 ‖ b64u_decode(proof.artifact_hash))

# Step 2: walk the sibling path
for each step in proof.hashes:
    sibling = b64u_decode(step.value_b64u)
    if step.direction == "right":
        current = SHA-256(0x01 ‖ current ‖ sibling)
    else:
        current = SHA-256(0x01 ‖ sibling ‖ current)

# Step 3: compare computed root to declared root (timing-safe)
assert timing_safe_equal(current, b64u_decode(proof.root_hash))
```

### 6.4 Anchoring to a Checkpoint

When a checkpoint is available, the proof verification additionally requires:

```
assert proof.root_hash  == checkpoint.root_hash
assert proof.tree_size  == checkpoint.tree_size
# and checkpoint signature must be valid (§5.4)
```

This anchors the proof to a specific signed state of the log, preventing
an operator from presenting a proof against a manufactured root.

### 6.5 Binding to the Original Artifact

Optionally, the verifier may recompute `artifact_hash` from the original
envelope to confirm the proof refers to that specific envelope:

```
expected_artifact_hash = SHA-256(canonicalize(artifact_envelope))
assert timing_safe_equal(expected_artifact_hash,
                         b64u_decode(proof.artifact_hash))
```

**Reference implementation:** `ceyo_verify/transparency.py:verify_inclusion_proof()`

---

## 7. Security Properties

| Property | Mechanism |
|----------|-----------|
| **Append-only** | UNIQUE constraint on `artifact_id`; seq is auto-increment |
| **Leaf domain separation** | `0x00` prefix prevents leaf/node hash confusion |
| **Node domain separation** | `0x01` prefix prevents node/leaf hash confusion |
| **Checkpoint non-replayability** | `created_at` in signed body |
| **Key binding** | `key_reference.public_key_fingerprint` in checkpoint |
| **Timing-safe comparison** | HMAC digest comparison for root hash check |
| **Independence** | `ceyo_verify/transparency.py` has no SDK dependency |

### 7.1 What the Log Proves

- An artifact with a given `artifact_hash` was appended to the log before
  the checkpoint was signed.
- The Merkle root at that time was `checkpoint.root_hash`.
- The checkpoint was signed by the key identified by `checkpoint.key_reference`.

### 7.2 What the Log Does Not Prove

- That the artifact body is correct or fair.
- That the artifact was not suppressed (absence of an artifact in the log
  cannot be proven by an inclusion proof).
- That the signing key has not been compromised since the checkpoint.

---

## 8. Integration with Artifact Sealing

The transparency log is **separate** from the artifact store. They serve
different purposes:

| Component | Purpose | Link |
|-----------|---------|------|
| `ArtifactStore` | Store full envelopes; detect tampering via hash chaining | `ceyo/store.py` |
| `TransparencyLog` | Record artifact hashes in a Merkle tree; enable inclusion proofs | `ceyo/transparency_log.py` |

Both can be used together. `CeyoClient` accepts both `store` and `log`
parameters and populates both on each `seal()` call when `persist=True`.

The `artifact_hash` stored in the log is `SHA-256(canonical(envelope))`.
This is the hash of the **complete** sealed envelope (including `artifact_id`,
`created_at`, `integrity`, and `key_reference`), not just the body.
