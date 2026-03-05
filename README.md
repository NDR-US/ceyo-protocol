# CEYO Protocol

Cryptographically sealed evidentiary artifacts for AI decision records.

CEYO defines a protocol for generating deterministic, verifiable records
of AI system events. These records allow independent parties to validate
AI outputs without accessing proprietary models or internal system details.

The protocol introduces a neutral evidentiary layer that produces
tamper-evident artifacts through canonicalization, hashing, and
cryptographic signatures.

---

## Purpose

Modern AI systems increasingly influence real-world decisions, yet most
models operate as opaque systems where outputs cannot easily be audited
or verified externally.

CEYO addresses this by defining a standardized artifact structure that
records AI decision events in a deterministic and cryptographically
verifiable format.

These artifacts allow independent verification long after the original
decision occurred.

---

## Core Concepts

CEYO is built on several principles:

**Deterministic Artifact Generation**  
Records must produce identical canonical representations when serialized.

**Cryptographic Sealing**  
Artifacts are hashed and digitally signed so any modification becomes
detectable.

**Policy-Scoped Data Capture**  
Only explicitly declared fields are recorded. Sensitive or proprietary
information remains outside the artifact.

**Independent Verification**  
Third parties can recompute hashes and validate signatures without
access to the AI system itself.

**Model Neutrality**  
CEYO does not modify or instrument the underlying AI model.

---

## Repository Structure
