# CEYO Protocol — Specification

This directory contains the implementation-neutral protocol documents and schemas for CEYO.

The current artifact format is protocol v2. Legacy v1 remains documented only for historical verification compatibility.

## Core documents

| Document | Purpose |
|---|---|
| [protocol-specification.md](protocol-specification.md) | Normative v2 artifact structure, signing scope, verification semantics, time model, and v1 compatibility |
| [pipeline.md](pipeline.md) | End-to-end v2 evidence pipeline |
| [architecture.md](architecture.md) | Trust boundaries and component roles |
| [security-model.md](security-model.md) | Security guarantees, assumptions, and explicit non-guarantees |
| [threat-model.md](threat-model.md) | Threats, mitigations, and residual risks |
| [transparency-log.md](transparency-log.md) | Merkle inclusion/checkpoint prototype and its limits |
| [glossary.md](glossary.md) | Protocol terminology |
| [governance.md](governance.md) | Project governance principles |

## Schemas

| Schema | Purpose |
|---|---|
| [artifact-schema.json](artifact-schema.json) | Current protocol-v2 artifact envelope |
| [artifact-schema-v1.json](artifact-schema-v1.json) | Preserved legacy-v1 artifact envelope |
| [checkpoint.schema.json](checkpoint.schema.json) | Transparency checkpoint format |
| [inclusion-proof.schema.json](inclusion-proof.schema.json) | Merkle inclusion-proof format |

## Current artifact pipeline

```text
Policy-scoped body
        ↓
Build protected object
        ↓
Canonicalize protected
        ↓
SHA-256 digest
        ↓
ECDSA-P256 signature
        ↓
{ protected, integrity, receipts[] }
        ↓
Independent artifact verification
        ↓
Optional trust-profile evaluation
        ↓
Optional external receipts / transparency evidence
```

## Protocol-v2 invariant

A conforming v2 verifier must derive artifact-level validity and trust inputs only from authenticated fields in `protected` or independently authenticated external evidence.

`receipts` is outside the original artifact signature by design. Receipt presence alone has no trust meaning until the receipt is validated under a recognized profile.

## Time model

`protected.sealed_at` is signature-bound but self-asserted by the signer. It prevents later timestamp editing; it does not prevent signer backdating.

Externally trusted historical time requires a separately authenticated time mechanism accepted by the verification profile.

## Reference implementations

| Directory | Role |
|---|---|
| `/ceyo` | Python reference implementation: sealing, verification, local store, transparency prototype |
| `/ceyo_verify` | Independent verifier with no dependency on the `ceyo` SDK package |

The specification is authoritative for protocol semantics. Reference code should be treated as an implementation of those rules, not as a substitute for them.
