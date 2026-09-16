# CEYO Security Model

## Purpose

This document defines what CEYO protocol-v2 artifact verification can establish, the assumptions required for those conclusions, and the properties it deliberately does not claim.

CEYO is evidentiary infrastructure. It authenticates a policy-scoped record and selected artifact metadata; it does not determine whether the underlying AI event was correct, complete, fair, lawful, compliant, or objectively true.

## Security invariant

A conforming v2 verifier MUST derive artifact-level validity and trust inputs only from:

- fields contained in the signed `protected` object; or
- independently authenticated external evidence validated by the applicable profile.

Unauthenticated envelope metadata MUST NOT influence artifact trust status.

## Artifact-validity guarantees

When a protocol-v2 artifact passes schema checks, canonicalization, digest verification, signature verification, and public-key fingerprint matching, the verifier can conclude the following within the stated assumptions.

### Protected-state integrity

The canonical `protected` object presented to the verifier matches the SHA-256 digest recorded in the artifact.

Changing a canonicalized field in `protected` after sealing changes the recomputed digest and causes artifact verification to fail unless a new valid signature is produced.

### Signature validity

The ECDSA P-256 signature verifies over the SHA-256 digest of `canonical(protected)` under the supplied public key.

This demonstrates successful use of the corresponding private key. It does not, by itself, establish the real-world identity, authority, or trustworthiness of whoever controlled that key.

### Key-reference integrity

`protected.key_reference` is inside the v2 signature scope. Registry, key identifier, fingerprint, and any included authority metadata therefore cannot be changed after sealing without invalidating the artifact.

The verifier separately confirms that the supplied public key matches the fingerprint committed to in `protected.key_reference`.

### Algorithm commitment

The canonicalization and signing-suite declarations are also inside `protected`. The artifact therefore commits to the exact supported cryptographic processing rules used for the artifact.

### Signer-asserted sealing time integrity

`protected.sealed_at` is signature-bound. A third party cannot alter it later without invalidating the artifact.

This is not the same as trusted time. A malicious or compromised signer can still use an incorrect clock or deliberately backdate when creating the artifact.

## Validity is not trust

CEYO separates cryptographic validity from higher-level evidentiary trust.

```text
artifact validity
    = protected object + digest/signature/key-fingerprint verification

trust / evidentiary status
    = artifact validity
    + signer/key authorization
    + revocation/status evidence
    + required receipts/anchors
    + verification-profile policy
```

A cryptographically valid artifact can therefore be untrusted, indeterminate, or insufficient under a stricter verification profile.

## Receipts and external evidence

`receipts` is outside the original artifact signature so additional evidence can be attached later.

The presence of a receipt does not automatically strengthen trust. A verifier must validate the receipt's type, subject binding, issuer/key, cryptographic proof, and any profile-specific requirements before relying on it.

Unknown or unauthenticated receipt objects MUST NOT satisfy a trust requirement merely because they appear in the `receipts` array.

## Time model

CEYO distinguishes multiple time claims.

### Event time

`body.event.occurred_at` is the originating system's assertion about when the underlying event occurred.

### Sealing time

`protected.sealed_at` is the signer's assertion about when the artifact was sealed. It is protected against later editing but is not independently trustworthy solely because it is signed.

### External time

An external timestamp, transparency receipt, witnessed checkpoint, or equivalent mechanism may provide a stronger time basis if its own trust assumptions are accepted by the verification profile.

Historical key-status or revocation evaluation SHOULD use accepted external time evidence when the profile requires protection against signer backdating.

If no acceptable external anchor exists, the verifier should describe the time basis as signer-asserted rather than independently established.

## Revocation

Revocation state is external to the immutable artifact.

Protocol v2 commits to the signing-key identity/fingerprint in `protected`. A trust verifier evaluates key status from independently authenticated status/revocation evidence.

A verifier must not silently convert an unavailable or ambiguous revocation check into a positive trust conclusion. Profiles that require revocation evidence should represent unavailable evidence as indeterminate or unsatisfied.

## Capture assumptions

CEYO protects information only after the signed `protected` state is constructed.

CEYO cannot independently prove that:

- every event that should have been captured was captured;
- source data was truthful before capture;
- the operator did not omit relevant information before sealing;
- a declared capture policy was correctly designed or enforced.

Those properties require complementary controls such as independent monitoring, gateway enforcement, trusted execution, attestations, or external audit evidence.

## Signing-key assumptions

Artifact authenticity depends on the security of the private signing key.

If the private key is compromised, an attacker may create new artifacts that pass cryptographic verification until the compromise is detected and the key's trust status is updated.

Deployments should use key-management controls appropriate to their assurance requirements, potentially including HSM/KMS-backed signing, access controls, rotation, audit logging, and independently available revocation/status infrastructure.

CEYO does not require CEYO itself to possess operator private keys.

## Canonicalization assumptions

Producer and verifier must implement the declared canonicalization suite consistently.

A verifier must not silently substitute another serialization scheme. The separately named deterministic fallback is not equivalent to RFC 8785 and must remain distinguishable in the artifact.

Cross-implementation test vectors are required for high-confidence interoperability.

## Storage guarantees

The reference `ArtifactStore` hashes each stored envelope and chains rows together locally.

This can detect modification of stored rows and many middle-of-chain deletions when verifying the available database state. It is not a complete externally witnessed append-only guarantee.

In particular, tail truncation or rollback to an earlier internally consistent state can remain undetectable unless a later chain head/count/checkpoint is anchored outside the local store.

## Transparency-log guarantees

The reference transparency-log prototype can produce Merkle inclusion proofs and signed checkpoints.

A successfully verified inclusion proof can demonstrate membership in the tree represented by the supplied checkpoint.

The current design must not be described as globally append-only or globally consistent solely because inclusion proofs and signed checkpoints exist. Stronger properties require additional mechanisms such as consistency proofs, witnesses, monitors, gossip, or independent checkpoint anchoring.

A checkpoint's own signed timestamp is still an assertion of the checkpoint signer unless independently anchored.

## Protocol-v1 boundary

Protocol v1 signed only `canonical(body)`. Its top-level key reference and creation timestamp were not part of that signature scope.

V1 artifacts remain cryptographically verifiable under their original semantics, but they provide a weaker metadata-integrity guarantee than v2.

A v1 artifact must not be rewritten or described as though those fields were historically signature-bound. A later attestation may add new evidence about the exact v1 artifact digest, but it cannot change the original guarantee.

## What successful v2 artifact verification does not establish

It does not establish:

- objective truth of the underlying event;
- independent accuracy of `event.occurred_at` or `sealed_at`;
- completeness of pre-seal capture;
- correctness of an AI output;
- fairness or absence of bias;
- regulatory compliance;
- legal admissibility;
- authorization of a key merely because the signature verifies;
- uncompromised status of the signing key without status/revocation evidence;
- global transparency-log consistency without additional mechanisms.

## Operational guidance

Deployments should select controls based on the required assurance profile. Common controls include:

- protected private-key storage;
- explicit trust-anchor and key-registration procedures;
- key rotation and signed revocation/status records;
- strict schema validation;
- canonicalization interoperability testing;
- artifact-generation monitoring to detect suppression/gaps;
- external anchoring of storage/log state where rollback resistance is required;
- independently authenticated time evidence where historical-time trust is required.

## Summary

CEYO v2 provides a stronger artifact-integrity boundary by signing the complete `protected` state, including the key reference and signer-asserted sealing time. That closes metadata-tampering gaps present in the legacy v1 envelope.

The protocol deliberately stops short of claiming objective truth, trusted time, regulatory compliance, or institutional trust from cryptographic validity alone. Those conclusions require additional independently authenticated evidence and explicit verification profiles.
