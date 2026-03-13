# CEYO Artifact Lifecycle

**Version:** 1.0
**Last Updated:** 2026-03-11

---

## Overview

This document describes the complete lifecycle of a CEYO artifact, from the initial AI decision event through independent verification and audit usage. Each stage is described with its inputs, outputs, and invariants.

---

## Lifecycle Stages

```
 ┌──────────────────┐
 │  AI Decision      │    Stage 1: An AI system produces a decision
 │  Event            │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Policy-Scoped    │    Stage 2: Capture policy determines what is recorded
 │  Capture          │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Artifact Body    │    Stage 3: Structured body assembled from captured data
 │  Construction     │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Canonicalization  │    Stage 4: Body serialized to deterministic byte form
 │  (RFC 8785)       │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Hash Generation   │    Stage 5: SHA-256 digest computed over canonical bytes
 │  (SHA-256)        │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Signature         │    Stage 6: Digest signed with ECDSA P-256
 │  Generation       │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Artifact          │    Stage 7: Envelope persisted to append-only store
 │  Storage          │
 └────────┬─────────┘
          │
          ▼
 ┌──────────────────┐
 │  Independent       │    Stage 8: Third party recomputes hash and validates
 │  Verification     │              signature using only the artifact and
 └────────┬─────────┘              public key
          │
          ▼
 ┌──────────────────┐
 │  Audit Usage       │    Stage 9: Verified artifacts used in oversight,
 │                    │              compliance, or legal contexts
 └──────────────────┘
```

---

## Stage 1: AI Decision Event

An AI system processes a request and produces a decision output. This is the triggering event for artifact generation.

**Examples of decision events:**
- A content moderation system classifies a post
- A recommendation engine selects items for a user
- A risk scoring system assigns a risk level
- An automated review system approves or denies an application

**Input:** User request or system trigger
**Output:** Decision output from the AI system
**CEYO's role:** None. CEYO does not participate in the decision process.

---

## Stage 2: Policy-Scoped Capture

The CEYO capture layer observes the decision event and extracts data according to the active capture policy. The capture policy defines exactly which fields are recorded and in what form.

**Key properties:**
- Only policy-permitted data is captured
- Raw inputs and outputs are typically not recorded — instead, cryptographic hashes of policy-scoped representations are captured
- The capture policy identifier and version are recorded in the artifact body

**Input:** Decision event data, active capture policy
**Output:** Policy-scoped event data (hashes, metadata, identifiers)

**Example capture policy scope:**
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

---

## Stage 3: Artifact Body Construction

The captured data is assembled into a structured artifact body — a JSON object conforming to the declared artifact schema.

**Required fields:**
- `event.event_id` — Unique identifier for this decision event
- `event.type` — Classification of the event type
- `event.occurred_at` — UTC timestamp of the event

**Optional fields:**
- `event.request_id` — Correlation identifier
- `policy` — Capture policy reference (id and version)
- `disclosure_tier` — Sensitivity classification
- `capture` — Captured data references
- `environment` — Deployment and runtime metadata

**Input:** Policy-scoped event data
**Output:** Artifact body (JSON object)

---

## Stage 4: Canonicalization

The artifact body is serialized to a deterministic canonical byte form using RFC 8785 (JSON Canonicalization Scheme).

**What RFC 8785 guarantees:**
- Object keys sorted lexicographically by Unicode code point
- No whitespace between tokens
- Deterministic number representation
- UTF-8 encoded output

**Why canonicalization matters:** Two semantically identical JSON objects may have different byte representations due to key ordering, whitespace, or encoding differences. Canonicalization ensures that the hash is computed over a single, deterministic representation.

**Input:** Artifact body (JSON object)
**Output:** Canonical byte sequence (UTF-8)

---

## Stage 5: Hash Generation

A SHA-256 cryptographic digest is computed over the canonical byte sequence.

**Properties:**
- The hash is a fixed 32-byte (256-bit) value
- Any change to the body — even a single byte — produces a completely different hash
- The hash is stored as a base64url-encoded string (without padding)

**Input:** Canonical byte sequence
**Output:** SHA-256 digest (32 bytes), encoded as base64url

---

## Stage 6: Signature Generation

The SHA-256 digest is digitally signed using the operator's private ECDSA P-256 key.

**Properties:**
- The signature uses prehashed mode — the raw 32-byte digest is signed directly
- The signature is DER-encoded per SEC 1
- The signature proves that the artifact was sealed by the holder of the corresponding private key
- The private key never appears in the artifact; only a fingerprint of the public key is included

**Input:** SHA-256 digest, private signing key
**Output:** DER-encoded ECDSA signature, encoded as base64url

---

## Stage 7: Artifact Storage

The complete artifact envelope (body + canonicalization metadata + integrity fields + key reference) is persisted to the artifact store.

**Storage properties:**
- The store is append-only — artifacts are never modified after storage
- Each stored artifact receives a sequence number
- Artifacts are hash-chained: each entry's chain hash covers the previous entry's hash, creating a tamper-evident sequence
- The store supports retrieval by artifact ID and listing by sequence

**Input:** Sealed artifact envelope
**Output:** Stored artifact with sequence number and chain hash

---

## Stage 8: Independent Verification

A third party retrieves the artifact and the public verification key, then independently verifies the artifact's integrity and authenticity.

**Verification steps:**
1. Validate envelope schema structure
2. Load the public verification key
3. Canonicalize the body using RFC 8785
4. Recompute SHA-256 hash and compare to stored hash
5. Verify ECDSA signature using the public key
6. Verify public key fingerprint matches declared fingerprint

**Requirements for verification:**
- The sealed artifact (JSON)
- The public verification key (PEM)
- Standard cryptographic libraries (SHA-256, ECDSA P-256, RFC 8785)

**Not required for verification:**
- Access to the AI system
- Access to the CEYO SDK
- Access to the artifact store
- Any proprietary infrastructure

**Input:** Sealed artifact, public verification key
**Output:** Verification result (PASS or FAIL with details)

---

## Stage 9: Audit Usage

Verified artifacts serve as evidentiary records in oversight and compliance contexts.

**Audit scenarios:**

| Scenario | How Artifacts Are Used |
|---|---|
| **Internal audit** | Review artifact sequences to confirm decision events were captured per policy |
| **Regulatory review** | Provide verified artifacts as evidence of AI system behavior |
| **Legal discovery** | Produce tamper-evident records of specific decision events |
| **Third-party assessment** | Independent auditors verify artifact integrity without accessing internal systems |
| **Incident investigation** | Reconstruct the sequence of AI decisions during a specific time window |

**Properties that support audit usage:**
- Artifacts are tamper-evident (any modification breaks verification)
- Artifacts are independently verifiable (no dependency on the generating system)
- Artifacts are time-stamped and sequenced
- Artifact chains provide evidence of completeness within the stored sequence

---

## Invariants Across the Lifecycle

The following properties hold throughout the artifact lifecycle:

1. **Integrity** — Any modification to the artifact body after sealing causes hash mismatch and verification failure
2. **Authenticity** — The signature binds the artifact to a specific signing key
3. **Determinism** — Canonicalization ensures reproducible hash computation
4. **Independence** — Verification requires no access to the generating system
5. **Non-interference** — Artifact generation does not affect AI system behavior
6. **Policy scope** — Only policy-permitted data appears in the artifact body
