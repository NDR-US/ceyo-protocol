# CEYO Protocol — End-to-End Pipeline

Version: 2.0-draft  
Status: Draft

## Overview

CEYO transforms a policy-scoped record of an AI-supported operation into a cryptographically verifiable artifact. Protocol v2 signs the complete `protected` object rather than only the body so artifact-level trust inputs are integrity-bound.

```text
Policy-scoped event/body
        ↓
Build protected object
        ↓
RFC 8785 canonicalization
        ↓
SHA-256 digest
        ↓
ECDSA-P256 signature
        ↓
Artifact envelope
        ↓
Independent verification
        ↓
Optional external receipts / transparency evidence
```

The basic artifact-validity path does not require a transparency log. External receipts may strengthen a later trust decision without changing the original artifact signature.

---

## Stage 1 — Policy-scoped body

The body records fields authorized by the applicable capture policy.

Typical fields include:

| Field | Description |
|---|---|
| `event.event_id` | Event identifier |
| `event.type` | Event type |
| `event.occurred_at` | Source-asserted event time |
| `event.request_id` | Optional correlation identifier |
| `policy.id` | Capture-policy identifier |
| `policy.version` | Capture-policy version |
| `policy.digest` | Optional digest committing to an exact policy representation |
| `capture` | Policy-scoped capture references |
| `disclosure_policy` | Sealing-time disclosure commitment |
| `environment` | Declared runtime/deployment metadata |

The protocol does not establish that pre-seal capture was complete or truthful. It makes later changes to signature-bound evidence detectable.

---

## Stage 2 — Build `protected`

Protocol v2 constructs:

```text
protected
├── product
├── protocol_version
├── artifact_schema
├── artifact_id
├── sealed_at
├── canonicalization_suite
├── signing_suite
├── key_reference
└── body
```

`protocol_version` controls CEYO processing and trust semantics. `artifact_schema` controls the shape/version of `protected.body`.

`sealed_at` is a signed signer-asserted time. It is not independently trusted time.

`key_reference` is inside `protected`, so registry/key/fingerprint metadata committed to by the signer cannot be altered later without invalidating the artifact.

---

## Stage 3 — Canonicalization

Protocol v2 uses RFC 8785 JSON Canonicalization Scheme (JCS) for the complete `protected` object.

```text
canonical_bytes = RFC8785(protected)
```

Current artifacts MUST declare:

```text
protected.canonicalization_suite.scheme  = "RFC8785"
protected.canonicalization_suite.version = "1.0"
```

A producer MUST NOT silently substitute another serializer when RFC 8785 is unavailable. A verifier MUST reproduce the declared supported scheme exactly.

Legacy-v1 artifacts may retain historical canonicalization declarations and are verified under their original semantics.

---

## Stage 4 — Digest

```text
digest = SHA-256(canonical_bytes)
```

The digest is stored in:

`integrity.digest.value_b64u`

with:

`integrity.digest.covers = "canonical(protected)"`

Changing any canonicalized field in `protected` changes the digest.

---

## Stage 5 — Signature

Current protocol-v2 signing suite:

- ECDSA P-256 / secp256r1
- SHA-256
- prehashed mode
- DER signature encoding

```text
signature = ECDSA-P256(private_key, digest, Prehashed-SHA256)
```

The signature is stored in:

`integrity.signature.value_b64u`

with:

`integrity.signature.covers = "sha256(canonical(protected))"`

The artifact signature authenticates `protected`; it does not cover `receipts`.

---

## Stage 6 — Artifact envelope

A current artifact is:

```text
artifact
├── protected
├── integrity
└── receipts[]
```

`receipts` exists outside the artifact signature so independently authenticated evidence can be appended later.

Appending, removing, or modifying `receipts` does not change artifact signature validity. A receipt affects trust only if its own type-specific proof, issuer, and subject binding are validated by an applicable profile.

Schema: `spec/artifact-schema.json`  
Legacy schema: `spec/artifact-schema-v1.json`

---

## Stage 7 — Independent artifact verification

A v2 verifier performs at least:

1. envelope/schema validation;
2. protocol/canonicalization/signing-suite checks;
3. public-key loading and P-256 enforcement;
4. RFC 8785 canonicalization of `artifact["protected"]`;
5. SHA-256 digest recomputation;
6. digest comparison;
7. ECDSA signature verification;
8. public-key fingerprint comparison against `protected.key_reference`.

Successful completion establishes cryptographic artifact validity under protocol v2. It does not by itself establish signer authorization, historical key status, externally trusted time, compliance, or correctness of the underlying AI event.

Reference implementation: `ceyo/verify.py`  
Independent implementation: `ceyo_verify/verifier.py`

---

## Stage 8 — Trust evaluation

Artifact validity and trust are intentionally separate.

```text
artifact validity
    = schema/protocol processing
    + digest verification
    + signature verification
    + protected key-fingerprint consistency

trust status
    = artifact validity
    + signer/key authorization or trust state
    + status/revocation evidence
    + accepted receipts / anchors
    + profile policy
```

A verifier may therefore report a valid artifact while a higher-assurance profile remains unsatisfied or indeterminate.

---

## Stage 9 — Optional transparency evidence

The repository includes a Merkle-tree transparency prototype. It records a stable artifact subject, issues signed checkpoints, and generates inclusion proofs.

For protocol v2, the stable log subject is:

```text
{ protected, integrity }
```

and excludes `receipts`. This allows later receipt attachment without changing an existing transparency subject or creating a circular receipt hash.

A verified inclusion proof can show that the artifact subject is a member of the tree represented by a particular signed checkpoint.

Important limits:

- `checkpoint.created_at` is a signed assertion by the checkpoint signer; it is not automatically independent trusted time;
- an old valid checkpoint can be replayed unless a freshness mechanism is added;
- inclusion proofs do not by themselves prove global append-only consistency;
- a log operator can potentially equivocate unless consistency/witness/monitor/gossip mechanisms are added;
- absence from the log is not proved by an inclusion proof.

See `spec/transparency-log.md`.

---

## Time model

CEYO distinguishes several time claims:

| Time | Meaning | Assurance |
|---|---|---|
| `protected.body.event.occurred_at` | Originating system's assertion about event time | Source asserted |
| `protected.sealed_at` | Artifact signer's assertion about sealing time | Signature-bound, self asserted |
| `checkpoint.created_at` | Transparency-checkpoint signer's assertion about checkpoint time | Signature-bound, not automatically fresh or independently trusted |
| accepted external time evidence | Time evidence from a separately authenticated mechanism accepted by the verification profile | Depends on mechanism, issuer/witness independence, and profile |

Signing `sealed_at` solves post-seal modification of that field. It does not solve malicious signer backdating.

Historical revocation evaluation should use an accepted external time anchor when required by the verification profile.

---

## Legacy v1

Protocol v1 used:

```text
signature_scope = canonical(body)
```

The v1 top-level artifact ID, creation time, canonicalization declaration, and key reference were outside that signature scope.

V1 remains verifiable under its original semantics and must not be represented as though those fields were historically signature-bound.

---

## Security properties and limits

| Property | Protocol-v2 statement |
|---|---|
| Deterministic verification | RFC 8785 defines the canonical bytes for the signed `protected` object |
| Protected-field integrity | Modification after sealing changes digest/signature verification |
| Key-reference integrity | V2 key reference is inside the signed `protected` object |
| Artifact authenticity | Signature verifies under the supplied corresponding public key; organizational identity/authorization requires separate trust evidence |
| External receipts | Can strengthen trust only after their own authentication and subject binding are validated |
| Independent verification | Artifact cryptographic validity can be checked without access to the originating AI system |
| Objective event truth | Not established |
| Trusted time | Not established by `sealed_at` alone |
| Global transparency consistency | Not established by inclusion proofs/checkpoints alone |

---

## Algorithm summary

| Operation | Current algorithm |
|---|---|
| Protected canonicalization | RFC 8785 JCS |
| Artifact digest | SHA-256 |
| Artifact signature | ECDSA P-256, SHA-256, DER |
| Public-key fingerprint | SHA-256 of SPKI DER |
| Merkle leaf/node hashing | SHA-256 with domain-separation prefixes |
| Base64 representation | base64url without padding |
