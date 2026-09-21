# CEYO Architecture

## Overview

CEYO is a neutral evidentiary layer for AI-supported systems. It creates portable, policy-scoped artifacts whose cryptographic integrity can be checked independently of the originating model or application.

The architecture is designed around a narrow claim: CEYO can make later modification of authenticated evidence detectable and can preserve verifiable provenance about the key, protocol rules, and declared capture context used to seal that evidence. It does not determine whether the underlying AI event was correct, complete, fair, lawful, or true.

## Core flow

```text
AI-supported operation
        ↓
Policy-scoped capture
        ↓
Build protected artifact state
        ↓
Deterministic canonicalization
        ↓
SHA-256 digest
        ↓
ECDSA-P256 signature
        ↓
CEYO artifact
        ↓
Independent verification
        ↓
Optional external receipts / transparency evidence
```

## Trust boundary

Protocol v2 has a deliberate three-part structure:

```text
artifact
├── protected
├── integrity
└── receipts[]
```

### `protected`

Contains every artifact-level input that can affect cryptographic validity or artifact-level trust interpretation:

- protocol identifier/version
- body-schema reference
- artifact identifier
- signer-asserted sealing time
- canonicalization suite
- signing suite
- key reference/fingerprint
- policy-scoped body

The signature covers the canonical representation of this object.

### `integrity`

Contains the SHA-256 digest and ECDSA-P256 signature used to authenticate `protected`.

### `receipts`

Contains optional later evidence. Receipts are not covered by the original artifact signature so they can be added after sealing. A receipt is meaningful to trust evaluation only after its own authentication and subject binding are validated.

## Capture boundary

The capture layer records only fields allowed by the operator-defined capture policy. CEYO can be deployed in-process, as a sidecar, or at an API/gateway boundary.

The protocol does not require custody of raw prompts, outputs, model weights, or private signing keys. Deployments may retain those entirely within the operator's trust boundary.

A capture policy may include hashes/references rather than raw sensitive material. CEYO does not, however, guarantee that the policy was complete or correctly enforced before sealing.

## Canonicalization boundary

Protocol v2 signs the declaration of the canonicalization suite itself. Independent verifiers therefore know which supported deterministic serialization procedure the signer committed to.

The current reference implementation recognizes RFC 8785 and a separately named deterministic fallback. The fallback is not represented as RFC 8785.

## Key boundary

CEYO does not need to own the operator's private signing key. A deployment may use local key storage, HSM/KMS-backed signing, or another provider that satisfies the applicable security profile.

`protected.key_reference` is signature-bound in protocol v2. This prevents later modification of artifact-level key-resolution metadata without invalidating the artifact.

A valid signature proves successful verification under the supplied public key. Trust in the organization, operator, or authority associated with that key requires additional trust-anchor evidence.

## Time boundary

CEYO distinguishes between different kinds of time claims:

- `event.occurred_at` — source-asserted event time;
- `protected.sealed_at` — signer-asserted sealing time, protected against later modification;
- external time evidence — separately authenticated evidence from a transparency service, timestamp authority, witness, or equivalent mechanism.

`sealed_at` is not independently trusted time. A malicious signer can still backdate when creating the signature. High-assurance historical revocation evaluation therefore requires an accepted external time basis.

## Verification boundary

Independent artifact verification checks the v2 signature-bound state:

1. schema/protocol support;
2. canonicalization of `protected`;
3. SHA-256 digest;
4. ECDSA-P256 signature;
5. public-key fingerprint binding.

That establishes **artifact validity**.

A broader **trust decision** may additionally require:

- signer/key authorization;
- historical revocation/status evidence;
- accepted external-time evidence;
- validated receipts;
- capture-policy/profile requirements.

The protocol intentionally keeps those two layers separate.

## Storage

The reference implementation includes a local SQLite artifact store with hash chaining. This provides local tamper evidence for the stored sequence, but it is not equivalent to globally witnessed append-only storage.

In particular, a local database owner can potentially truncate the tail and present an earlier internally consistent state unless the latest state is anchored elsewhere.

## Transparency

The repository also includes a Merkle-tree transparency-log prototype with signed checkpoints and inclusion proofs.

It can provide verifiable membership in a signed tree state. It does not yet provide all properties of a globally consistent transparency service: consistency proofs, witnesses, monitors, gossip, and independently anchored checkpoints are separate hardening mechanisms.

## Protocol-v1 compatibility

Protocol v1 signed only `canonical(body)`. Several top-level metadata fields used by later trust logic were therefore outside the v1 signature scope.

V1 artifacts remain verifiable under that original guarantee. They are not rewritten or re-labeled as though those fields were historically protected.

## Architectural invariants

For protocol v2:

1. **Protected-state integrity** — changing any canonicalized field in `protected` after sealing invalidates the recorded digest/signature.
2. **Key-reference integrity** — signer/key reference data used at artifact level is inside `protected`.
3. **Explicit algorithm commitment** — canonicalization and signing-suite declarations are signature-bound.
4. **Independent verification** — cryptographic artifact validity does not require access to the originating AI model.
5. **Receipt separation** — later external evidence can be appended without rewriting the original artifact signature.
6. **Validity/trust separation** — cryptographic validity does not automatically imply evidentiary trust under every verification profile.
7. **No objective-time overclaim** — signer timestamps remain signer assertions unless corroborated by accepted external evidence.

## Non-goals

CEYO does not attempt to:

- determine the correctness of AI outputs;
- guarantee fairness or absence of bias;
- prove completeness of pre-seal capture;
- certify regulatory compliance;
- establish legal admissibility;
- replace institutional judgment;
- prove objective real-world event truth;
- establish independently trusted time without external evidence.
