# CEYO Protocol

**Independent evidentiary infrastructure for AI and autonomous systems**

**Created and led by Brian Covarrubias**  
**Copyright © 2026 Brian Covarrubias. All rights reserved.**

CEYO is a protocol and reference architecture for producing deterministic, cryptographically verifiable evidence artifacts from consequential AI and autonomous-system operations.

The project is designed around a narrow institutional question:

> Can a later reviewer independently verify what record was sealed, under what declared context, and whether that record has changed since sealing — without requiring access to model weights or proprietary system internals?

CEYO provides evidence infrastructure. It does not adjudicate the underlying decision.

## Project status

CEYO is under active development. Documentation distinguishes three states:

- **Implemented** — behavior present in the current public reference implementation and testable today.
- **Experimental** — implemented or explored in research branches or private R&D, but not part of the normative public profile.
- **Planned / target architecture** — intended infrastructure that has not yet been promoted into the current protocol profile.

Future-state language describes the direction of CEYO; it must not be read as a claim that every target capability is already production-ready.

## Canonical repository role

This repository is the **canonical public protocol repository** for CEYO.

It contains:

- the normative protocol specification in `spec/`;
- canonical JSON schemas;
- the Python reference implementation in `ceyo/`;
- a standalone verifier in `ceyo_verify/`;
- examples, tests, security documentation, and transparency-log reference components.

Other CEYO repositories must not silently redefine the protocol.

## Current reference profile — implemented

The current public reference profile uses:

```text
policy-scoped structured record
        ↓
RFC 8785 JSON Canonicalization Scheme
        ↓
SHA-256 digest
        ↓
ECDSA P-256 / SHA-256 digital signature
        ↓
CEYO artifact envelope
        ↓
independent verification
```

The reference implementation also includes append-only storage primitives and a Merkle-tree transparency log with signed checkpoints and inclusion proofs.

The current canonical artifact schema is:

- `spec/artifact-schema.json`

The current canonical cryptographic suite is:

- Canonicalization: `RFC8785`
- Digest: `SHA-256`
- Signature: `ECDSA-P256-SHA256`
- Signature encoding: ASN.1 DER

Any future change to canonicalization, hashing, signature suites, protected fields, trust semantics, or verification behavior requires an explicit versioned protocol revision.

## Target architecture — planned direction

CEYO is intended to evolve beyond basic artifact sealing into a broader evidentiary trust layer:

```text
AI / autonomous-system event
        ↓
governed capture policy
        ↓
canonical evidentiary object
        ↓
hash + digital signature
        ↓
protected protocol / policy / schema context
        ↓
trusted-time and transparency evidence
        ↓
authenticated key authority + revocation
        ↓
custody and constrained-disclosure controls
        ↓
independent institutional verification
```

Target research areas include:

- cryptographic binding of capture-policy identity, version, and digest;
- protected signing of security-relevant artifact metadata;
- authenticated trust registries and delegated trust domains;
- hardware-backed KMS/HSM signing;
- trusted-time evidence;
- transparency witnesses, signed checkpoints, and anti-equivocation mechanisms;
- key rotation and revocation with defensible historical semantics;
- independent multi-implementation verification;
- protocol conformance vectors and interoperability suites;
- chain-of-custody and constrained-disclosure workflows.

See `spec/status-and-roadmap.md` for the implementation/target boundary.

## What cryptography establishes

CEYO separates several distinct security functions:

- **Canonicalization** creates a deterministic byte representation.
- **Hashing** creates a stable integrity digest and allows tamper comparison.
- **Digital signatures** bind signed content to the holder of a cryptographic key.
- **Encryption**, when used in future deployments, protects confidentiality; it is not a substitute for integrity validation.
- **Trust policy** determines whether a key or authority is recognized for a verification context.
- **Time / transparency evidence** can strengthen claims about when an artifact or checkpoint existed.
- **Revocation evidence** supports evaluation of key status under defined historical rules.

## What CEYO does not claim

CEYO does not, by cryptography alone:

- determine whether an AI output is correct;
- prove fairness or absence of bias;
- certify regulatory compliance;
- establish the truth or completeness of pre-capture source data;
- prove that a local timestamp is an independently trusted time assertion;
- establish legal admissibility or evidentiary sufficiency in a particular proceeding;
- replace governance, adjudication, human review, or institutional authority.

CEYO produces verifiable evidence records, not judgments.

## Repository structure

```text
ceyo-protocol/
├── spec/              # canonical protocol specification and schemas
├── ceyo/              # public reference implementation
├── ceyo_verify/       # standalone independent verifier
├── docs/              # developer and integration guidance
├── examples/          # reference examples
├── example_artifact/  # sample CEYO artifacts and verification material
├── tests/             # protocol/reference implementation tests
├── scripts/           # development utilities
├── tools/             # standalone tooling
├── SECURITY.md
├── CONTRIBUTING.md
├── VERSION
└── README.md
```

## Minimal SDK example

```python
from ceyo import CeyoClient
from ceyo.keys import LocalKeyProvider
from ceyo.store import ArtifactStore

client = CeyoClient(
    key_provider=LocalKeyProvider("keys/private.pem"),
    store=ArtifactStore("artifacts.db"),
)

envelope = client.seal({
    "event": {
        "event_id": "evt_001",
        "type": "classification",
        "occurred_at": "2026-03-09T12:00:00Z",
    },
    "policy": {
        "id": "example.capture-policy",
        "version": "1.0",
    },
    "disclosure_tier": "internal",
})

result = client.verify(envelope)
assert result.ok
```

## Independent verification

The verifier checks the artifact against the current protocol profile, including schema validity, deterministic canonicalization, digest comparison, signature validity, and key fingerprint consistency.

Where transparency evidence is supplied, inclusion proofs and signed checkpoints can be evaluated independently of the sealing path.

## Protocol authority

Normative protocol behavior is defined by the versioned material in `spec/` and the corresponding schemas. README text, website copy, demos, and private research documents are explanatory and must remain consistent with that source of truth.

## Project ecosystem

- `NDR-US/ceyo-protocol` — canonical public protocol and reference implementation
- `NDR-US/ceyo-core` — private R&D, target architecture, security/governance/legal/product research
- `NDR-US/ceyo-decision-verification-demo` — public demonstration of the canonical workflow
- `NDR-US/ceyo-site` — public presentation and institutional explanation
- `NDR-US/ndr-us` — project/research publishing identity

## Security

This is an early-stage reference architecture, not a production security certification. Production use would require deployment-specific threat modeling, independent cryptographic review, hardened key custody, operational controls, conformance testing, and appropriate institutional/legal review.

See `SECURITY.md`, `spec/security-model.md`, and `spec/threat-model.md`.

## Authorship and intellectual property

CEYO was conceived and is directed by **Brian Covarrubias**.

This repository is published through the NDR-US GitHub identity. Copyright and licensing are governed by `LICENSE`; publication does not transfer ownership or grant rights beyond those expressly stated there.

## License

All Rights Reserved. See `LICENSE`.
