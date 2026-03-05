# CEYO Protocol

Cryptographically sealed evidentiary artifacts for AI decision records.

CEYO defines a protocol for generating deterministic, verifiable records of AI system events. These records allow independent parties to validate AI outputs without requiring access to proprietary models, training data, or internal infrastructure.

The protocol introduces a neutral evidentiary layer that produces tamper-evident artifacts through deterministic canonicalization, cryptographic hashing, and digital signatures.

---

## Purpose

Modern AI systems increasingly influence real-world decisions, yet most systems operate as opaque environments where outputs cannot easily be audited or verified externally.

CEYO addresses this problem by defining a standardized artifact structure that records AI decision events in a deterministic and cryptographically verifiable format.

These artifacts allow independent verification long after the original decision occurred.

---

## Core Principles

Deterministic Canonicalization  
Artifacts must produce identical serialized representations when processed by independent systems.

Cryptographic Sealing  
Artifacts are hashed and digitally signed so any modification becomes immediately detectable.

Policy-Scoped Capture  
Only explicitly defined fields are recorded. Sensitive or proprietary information remains outside the artifact.

Independent Verification  
Third parties can verify artifact integrity without requiring access to the originating AI system.

Model Neutrality  
CEYO does not modify or instrument the underlying AI model.

---

## Artifact Structure

A CEYO artifact contains:

- Schema version
- Event metadata
- Policy identifier
- Environment fingerprint
- Canonicalized payload hash
- Cryptographic signature

The artifact schema is defined here:

docs/artifact-schema.json

---

## Protocol Workflow

High-level artifact lifecycle:

1. AI system generates an output or decision event  
2. Policy defines which fields are captured  
3. Event data is canonicalized deterministically  
4. Canonical record is hashed  
5. Hash is cryptographically signed  
6. Artifact becomes independently verifiable

Detailed workflow documentation:

docs/example-workflow.md

---

## Protocol Documentation

Architecture  
docs/architecture.md

Protocol Specification  
docs/protocol-specification.md

Verification Protocol  
docs/verification-protocol.md

Verification Walkthrough  
docs/verification-walkthrough.md

Artifact Schema  
docs/artifact-schema.json

Security Model  
docs/security-model.md

Threat Model  
docs/threat-model.md

Key Management  
docs/key-management.md

Governance Model  
docs/governance.md

Design Principles  
docs/design-principles.md

Glossary  
docs/glossary.md

Roadmap  
docs/roadmap.md

Versioning Policy  
docs/versioning.md

---

## Related Project

Public website and overview:

https://ndr-us.github.io/ceyo-site/

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
