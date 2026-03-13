# CEYO Protocol — Specification

This directory is the canonical specification for the CEYO Protocol.
It defines the protocol standard independently of any implementation.

## Pipeline

```
Input / Output
      ↓
Canonicalization          spec/pipeline.md §2
      ↓
Hash + Signature          spec/pipeline.md §3
      ↓
Artifact Envelope         spec/artifact-schema.json
      ↓
Transparency Log          spec/transparency-log.md
      ↓
Signed Checkpoint         spec/checkpoint.schema.json
      ↓
Standalone Verification   spec/verification-protocol.md
      ↓
Inclusion Proof Validation spec/transparency-log.md §6
```

## Specification Documents

| Document | Description |
|----------|-------------|
| [pipeline.md](pipeline.md) | End-to-end pipeline from input capture to inclusion-proof validation |
| [protocol-specification.md](protocol-specification.md) | Formal protocol specification (fields, algorithms, constants) |
| [specification.md](specification.md) | Artifact structure and sealing procedure |
| [transparency-log.md](transparency-log.md) | Transparency log, Merkle tree, checkpoints, inclusion proofs |
| [architecture.md](architecture.md) | System architecture and component roles |
| [architecture-diagram.md](architecture-diagram.md) | ASCII architecture diagrams |
| [artifact-lifecycle.md](artifact-lifecycle.md) | Artifact lifecycle from event to audit |
| [design-principles.md](design-principles.md) | Core design principles |
| [security-model.md](security-model.md) | Security guarantees and assumptions |
| [threat-model.md](threat-model.md) | Threat categories and mitigations |
| [threat-model-diagram.md](threat-model-diagram.md) | Threat model diagrams |
| [verification-protocol.md](verification-protocol.md) | Step-by-step verification procedure |
| [glossary.md](glossary.md) | Terminology definitions |
| [governance.md](governance.md) | Governance principles and acceptable use |

## Schemas

| Schema | Description |
|--------|-------------|
| [artifact-schema.json](artifact-schema.json) | JSON Schema (Draft 2020-12) for sealed artifact envelopes |
| [checkpoint.schema.json](checkpoint.schema.json) | JSON Schema for signed transparency log checkpoints |
| [inclusion-proof.schema.json](inclusion-proof.schema.json) | JSON Schema for Merkle inclusion proofs |

## Relationship to Implementation

The specification in this directory defines the protocol standard.
The Python packages implement it:

| Directory | Role |
|-----------|------|
| `/ceyo` | Reference implementation (sealing, verification, store, transparency log) |
| `/ceyo_verify` | Independent verifier (no SDK dependency) |

Any conformant implementation must produce and verify artifacts that
satisfy the schemas and algorithms described here.
