# CEYO Transparency Log Specification

Version: 2.0-draft  
Status: Prototype

## 1. Purpose

The CEYO reference transparency component is a local Merkle inclusion log. It records a stable digest for each artifact, can produce Merkle inclusion proofs, and can sign checkpoints describing a particular tree size/root.

It is useful for demonstrating independently verifiable membership in a signed tree state.

It is **not**, by itself, a complete globally consistent or globally append-only transparency service. Inclusion proofs and signed checkpoints do not prevent a log operator from maintaining multiple views, replaying an older valid checkpoint, or rolling back local state. Stronger deployment profiles need additional mechanisms such as consistency proofs, witnesses, monitors, gossip, or independently anchored checkpoints.

## 2. Transparency canonicalization profile

The current reference transparency format fixes canonicalization to **RFC 8785**.

Unlike protocol-v2 artifact sealing, the current transparency proof/checkpoint formats do not carry their own canonicalization-suite field. Producer and independent verifier therefore MUST use RFC 8785 for transparency artifact subjects and checkpoint bodies.

A missing RFC 8785 implementation is an error. The transparency implementation does not silently switch to the artifact-layer deterministic fallback.

## 3. Artifact subject

### Protocol v2

V2 receipts are appendable external evidence and are intentionally outside the artifact signature. A transparency proof must therefore bind to a stable artifact subject that does not change when receipts are later attached.

The v2 log subject is:

```json
{
  "protected": { "...": "..." },
  "integrity": { "...": "..." }
}
```

The log records:

```text
artifact_hash = SHA-256(RFC8785({protected, integrity}))
```

`receipts` is excluded from this digest.

This avoids two problems:

1. attaching a later receipt does not invalidate an existing inclusion proof;
2. a transparency receipt can refer to the artifact core without creating a circular hash dependency on itself.

### Legacy v1

For a legacy-v1 artifact newly entered into this reference transparency log, the log subject is the complete legacy envelope and the current transparency profile canonicalizes that subject with RFC 8785.

This does not change the original v1 artifact signature scope; v1 signature verification still follows its historical `canonical(body)` semantics.

## 4. Merkle hashing

The reference implementation uses domain-separated SHA-256 hashing:

```text
leaf_hash = SHA-256(0x00 || artifact_hash)
node_hash = SHA-256(0x01 || left || right)
```

Leaves are ordered by local sequence number. When a level has an unpaired final node, that node is promoted unchanged to the next level.

The empty local tree root is:

```text
SHA-256("ceyo:empty-tree")
```

## 5. Log entry

A local entry contains:

```json
{
  "seq": 1,
  "artifact_id": "ceyo_art_...",
  "artifact_hash": "<base64url SHA-256>",
  "leaf_hash": "<base64url SHA-256>",
  "logged_at": "2026-09-15T12:00:00Z"
}
```

For v2, `artifact_id` is read from signed `protected.artifact_id`.

`logged_at` is local log metadata. It is not, by itself, independently trusted time and is not part of the inclusion proof.

A local uniqueness constraint prevents a second row with the same artifact ID in that database. It does not prove global uniqueness or append-only history to an outside verifier.

## 6. Checkpoints

The current checkpoint body is:

```json
{
  "product": "CEYO",
  "type": "transparency-checkpoint",
  "tree_size": 42,
  "root_hash": "<base64url SHA-256>",
  "created_at": "2026-09-15T12:00:00Z"
}
```

New reference checkpoints compute:

```text
checkpoint_digest = SHA-256(RFC8785(checkpoint_body))
checkpoint_sig = ECDSA-P256(private_key, checkpoint_digest, Prehashed-SHA256)
```

New checkpoints declare:

```text
sig.covers = "RFC8785(checkpoint_body)"
```

The independent verifier also accepts the earlier descriptor string `canonical(checkpoint_body)` for checkpoint-format compatibility. That legacy descriptor is interpreted using the same RFC 8785 checkpoint canonicalization rule; it is not permission to choose an arbitrary serialization.

The full checkpoint adds:

```text
sig
key_reference
```

### Time semantics

Because `created_at` is inside the signed checkpoint body, changing that field later invalidates the signature.

That does **not** prevent replay of the entire old signed checkpoint, and it does not independently prove that the checkpoint signer's clock was accurate. Freshness and trusted-time claims require additional external mechanisms.

### Key-reference semantics

In the current checkpoint format, `key_reference` is outside the signed checkpoint body.

The standalone verifier therefore treats the caller-supplied checkpoint public key as the authenticated verification input and only checks the checkpoint fingerprint for consistency. The checkpoint key reference must not be treated as independently authenticated identity metadata merely because it appears in the checkpoint.

A future checkpoint-format revision may bind additional checkpoint metadata into its signed scope.

## 7. Inclusion proof

A proof contains:

```json
{
  "artifact_id": "ceyo_art_...",
  "artifact_hash": "<base64url SHA-256>",
  "leaf_index": 0,
  "tree_size": 10,
  "root_hash": "<base64url SHA-256>",
  "hashes": [
    {"direction": "right", "value_b64u": "..."},
    {"direction": "left", "value_b64u": "..."}
  ]
}
```

Verification starts from:

```text
current = SHA-256(0x00 || artifact_hash)
```

and walks the sibling path until it reconstructs the declared root.

When the original artifact is supplied, the verifier recomputes the RFC-8785-based stable log subject described in Section 3 and confirms it matches `artifact_hash`.

## 8. Checkpoint-bound proof verification

If a checkpoint and externally selected checkpoint public key are supplied, the verifier also checks:

1. checkpoint product/type and signature structure;
2. ECDSA P-256 checkpoint signature;
3. descriptive checkpoint fingerprint consistency with the supplied key;
4. proof root equals checkpoint root;
5. proof tree size equals checkpoint tree size.

A successful result means the artifact subject is a member of the tree represented by that signed checkpoint.

It does not establish that the checkpoint is the newest checkpoint or the only checkpoint of that tree size.

## 9. Security properties

The prototype provides:

- deterministic RFC-8785-based transparency-subject verification;
- Merkle membership verification relative to a supplied root;
- domain separation between leaves and internal nodes;
- signed checkpoint assertions of tree size/root/declared checkpoint time;
- independent proof verification without the CEYO SDK;
- stable protocol-v2 artifact subjects that survive receipt attachment.

It does not, by itself, provide:

- global append-only consistency;
- consistency proofs between checkpoints;
- checkpoint freshness;
- protection against split-view/equivocation;
- independently trusted checkpoint time;
- proof of absence from the log;
- guaranteed detection of local database rollback/tail truncation.

## 10. High-assurance extensions

A stronger transparency profile can add some combination of:

- Merkle consistency proofs;
- witnessed/cosigned checkpoints;
- independent monitors;
- gossip between verifiers;
- monotonic checkpoint publication;
- external timestamp authorities;
- independently anchored checkpoint hashes/tree sizes.

Those properties should be claimed only when the corresponding mechanism is implemented and verified.

## 11. Reference implementation

Producer/log:

- `ceyo/transparency_log.py`

Independent proof verifier:

- `ceyo_verify/transparency.py`

Schemas:

- `spec/checkpoint.schema.json`
- `spec/inclusion-proof.schema.json`
