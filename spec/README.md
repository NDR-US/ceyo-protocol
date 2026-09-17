# CEYO Protocol — Canonical Specification Index

This directory is the authoritative public specification for the current CEYO protocol profile.

**Creator and project lead: Brian Covarrubias**

The specification defines protocol behavior independently of any particular deployment. Public implementations, demos, and website claims should resolve back to this directory.

## Current normative pipeline

```text
policy-scoped structured input
      ↓
RFC 8785 canonicalization
      ↓
SHA-256 digest
      ↓
ECDSA P-256 / SHA-256 signature
      ↓
CEYO artifact envelope
      ↓
optional transparency-log publication
      ↓
signed checkpoint / inclusion proof
      ↓
independent verification
```

## Normative files

| File | Role |
|---|---|
| `protocol-specification.md` | Current protocol profile, fields, algorithms, and constants |
| `pipeline.md` | End-to-end processing and verification sequence |
| `artifact-schema.json` | Canonical artifact-envelope schema |
| `transparency-log.md` | Merkle log, checkpoints, and inclusion-proof behavior |
| `checkpoint.schema.json` | Signed-checkpoint schema |
| `inclusion-proof.schema.json` | Inclusion-proof schema |
| `architecture.md` | Component boundaries and protocol architecture |
| `security-model.md` | Security properties, assumptions, and limitations |
| `threat-model.md` | Threat categories, attack surfaces, and residual risk |
| `governance.md` | Governance boundaries and use principles |
| `glossary.md` | Canonical terminology |
| `status-and-roadmap.md` | Implemented vs experimental vs planned architecture |

## Relationship to implementation

The public reference implementation is in:

- `/ceyo` — sealing, verification, key interfaces, store, transparency log;
- `/ceyo_verify` — standalone verification components designed to remain independent of the sealing SDK.

A conformant implementation must follow the versioned specification and schemas, not merely reproduce README prose.

## Version discipline

Changes that affect deterministic verification or interoperability require explicit protocol-version treatment. Examples include:

- artifact schema changes;
- changes to fields covered by the signature;
- canonicalization changes;
- digest algorithm changes;
- signature-suite changes;
- key-reference or trust-policy semantics;
- transparency-proof behavior;
- verification-result semantics.

The project should not introduce a second public CEYO profile implicitly through demos, website tooling, or private R&D code.

## Target architecture

CEYO is intended to evolve beyond the current reference profile. Planned capabilities are documented in `status-and-roadmap.md` and must remain labeled as target architecture until they are specified, implemented, tested, and promoted into a versioned public profile.
