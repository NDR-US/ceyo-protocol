# CEYO Status and Target Architecture

**Created and led by Brian Covarrubias**

This document separates the current public CEYO protocol profile from experimental R&D and planned infrastructure. It is intended to prevent future-state architecture from being mistaken for already deployed guarantees while preserving the full direction of the project.

## Status vocabulary

- **Implemented** — present in the current public reference implementation and represented in the current public specification.
- **Experimental** — implemented or explored in research code, but not normative for the public protocol profile.
- **Planned** — target architecture that remains to be specified, implemented, tested, and independently reviewed.

## Current public profile — implemented

The current public profile includes:

- structured CEYO artifact envelopes;
- RFC 8785 JSON Canonicalization Scheme;
- SHA-256 integrity digests;
- ECDSA P-256 / SHA-256 signatures;
- artifact schema validation;
- independent digest/signature verification;
- public-key fingerprint checks;
- append-only storage primitives;
- Merkle-tree transparency logging;
- signed transparency checkpoints;
- inclusion-proof generation and verification;
- reference SDK, CLI, tests, and standalone verifier components.

The current artifact profile signs the canonicalized artifact body. Security-relevant envelope fields outside that signed scope should not be treated as cryptographically protected merely because they appear in the envelope.

## Experimental R&D

The private `ceyo-core` repository contains non-normative experiments including:

- Ed25519 signing profiles;
- local revocation-ledger semantics;
- alternative transparency structures;
- trust-anchor and authority models;
- custody and disclosure models;
- policy-enforcement models;
- deployment topologies;
- legal and institutional review research.

Experimental work can inform future CEYO versions but does not redefine the current public profile.

## Target architecture — planned

The target CEYO architecture is:

```text
consequential system event
        ↓
governed capture
        ↓
canonical evidentiary object
        ↓
cryptographic digest + signature
        ↓
protected protocol / policy / schema context
        ↓
trusted-time and transparency evidence
        ↓
authenticated trust registry / delegated authority
        ↓
key lifecycle, rotation, and revocation
        ↓
custody and constrained disclosure
        ↓
independent institutional verification
```

Planned capabilities include:

### Protected artifact context

A future protocol profile should cryptographically bind the security-relevant context a verifier relies upon, including protocol version, artifact identifier, policy identity/version/digest, schema identity/version/digest, trust-domain/key reference, and other protected metadata defined by that profile.

### Policy binding

A future profile should make capture-policy identity and version first-class verifiable data rather than relying only on descriptive policy fields.

### Trusted time

Local system timestamps are not independent proof of real-world time. Future profiles may support trusted timestamp authorities, externally witnessed transparency checkpoints, or other verifiable temporal evidence.

### Trust registries

A key fingerprint proves correspondence to a key, not institutional authorization. Future CEYO verification should support authenticated trust policies, delegated trust domains, and independently configured trust anchors.

### Revocation and historical trust

Future revocation semantics should bind key status to independently supportable time and authenticated revocation state, with explicit historical-validation rules.

### Transparency and anti-equivocation

Signed Merkle checkpoints are a foundation. Future infrastructure may add replication, witnesses, consistency proofs, external anchoring, and anti-equivocation mechanisms.

### Hardware-backed custody

Production-oriented profiles should support operator-controlled HSM/KMS/TEE signing without requiring CEYO to custody private signing keys.

### Confidentiality and constrained disclosure

Encryption may be used to protect confidential evidence and disclosure tiers. Encryption is a confidentiality control; artifact integrity and authenticity remain separate cryptographic properties.

### Conformance

A protocol profile intended for institutional adoption should include:

- canonical test vectors;
- valid and invalid artifact fixtures;
- cross-language canonicalization vectors;
- signature and verifier conformance tests;
- transparency-log proof vectors;
- explicit failure-state semantics;
- independent implementation testing.

## Evidentiary boundary

CEYO is designed to make recorded evidence verifiable. It does not make the underlying event true.

Verification may establish, depending on the profile and supplied evidence:

- structural validity;
- integrity of protected content;
- signature validity;
- correspondence to a referenced key;
- transparency inclusion;
- other explicitly defined trust-policy results.

It does not automatically establish:

- pre-capture truth or completeness;
- model correctness or fairness;
- legal compliance;
- institutional authorization unless a trust basis is supplied;
- trusted time unless verifiable time evidence is supplied;
- legal admissibility or sufficiency.

## Promotion rule

A planned or experimental feature becomes part of CEYO only when it is:

1. assigned to an explicit protocol version;
2. normatively specified;
3. represented in schemas or machine-readable rules where appropriate;
4. implemented in the public reference implementation;
5. supported by independent-verifier behavior;
6. covered by conformance tests;
7. documented with security assumptions and residual risks.
