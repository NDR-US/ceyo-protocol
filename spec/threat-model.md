# CEYO Threat Model

**Version:** 1.0
**Last Updated:** 2026-03-11

---

## 1. Introduction

This document defines the threat model for the CEYO evidentiary infrastructure protocol. It identifies attack vectors that could compromise artifact integrity, authenticity, availability, or verification reliability, and describes the mitigations provided by the protocol architecture.

CEYO generates deterministic, cryptographically sealed artifacts describing AI system decision events. The threat model focuses on threats to the artifact generation and verification pipeline — not on threats to AI model correctness, fairness, or regulatory compliance.

---

## 2. Security Objectives

### 2.1 Artifact Integrity

Artifacts MUST NOT be modifiable after cryptographic sealing without detection. Any alteration to artifact contents MUST produce a different hash and cause verification failure.

### 2.2 Artifact Authenticity

Artifacts MUST be verifiably associated with the entity that generated the cryptographic signature. Verification MUST confirm that the artifact was sealed by the holder of the declared signing key.

### 2.3 Deterministic Reproducibility

Independent verifiers MUST be able to recompute canonical artifact hashes using the declared canonicalization scheme. Verification results MUST be reproducible across environments and implementations.

### 2.4 Independent Verification

Verification MUST NOT require access to the original AI system. Artifacts MUST contain sufficient information for independent verification without revealing proprietary model details.

### 2.5 Policy-Bounded Data Capture

Artifact contents MUST remain constrained to policy-scoped fields defined by the capture policy. System data outside the policy scope MUST NOT be recorded.

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│              Operator-Controlled                 │
│                                                  │
│  ┌──────────┐    ┌──────────┐    ┌───────────┐  │
│  │ AI System │───►│  CEYO    │───►│ Artifact  │  │
│  │           │    │ Capture  │    │  Store    │  │
│  └──────────┘    │ + Seal   │    └───────────┘  │
│                  └────┬─────┘                    │
│                       │                          │
│                  ┌────▼─────┐                    │
│                  │ Signing  │                    │
│                  │   Key    │                    │
│                  └──────────┘                    │
│                                                  │
├──────────────────────────────────────────────────┤
│              Verifier-Controlled                 │
│                                                  │
│  ┌──────────┐    ┌──────────┐    ┌───────────┐  │
│  │ Artifact │───►│ Verifier │◄───│  Public   │  │
│  │  (JSON)  │    │          │    │   Key     │  │
│  └──────────┘    └──────────┘    └───────────┘  │
│                                                  │
└──────────────────────────────────────────────────┘
```

**Operator domain:** AI system, capture layer, sealing process, signing key, artifact storage.
**Verifier domain:** Artifact copy, verification software, public key.
**Trust boundary:** The artifact envelope is the trust boundary. Verification operates entirely on the artifact and public key without crossing into the operator domain.

---

## 4. Threat Categories

### 4.1 Artifact Tampering

**Threat:** An attacker modifies artifact contents after generation — altering fields, timestamps, identifiers, or removing recorded data.

**Impact:** If undetected, tampering destroys the evidentiary value of the artifact. A modified artifact could misrepresent the AI system's behavior.

**Attack vectors:**
- Direct modification of stored artifact JSON
- Man-in-the-middle alteration during artifact transmission
- Database-level modification of artifact records
- Field injection or removal in transit

**Mitigation:**
- Artifacts are sealed with SHA-256 hash over the canonicalized body. Any modification changes the hash.
- Artifacts are signed with ECDSA P-256. Any modification invalidates the signature.
- Verification recomputes the hash and validates the signature, detecting any tampering.
- Hash chaining in the artifact store provides sequence-level tamper evidence.

**Residual risk:** Tampering is detectable but not preventable. An attacker with storage access can delete artifacts entirely (see Section 4.6).

---

### 4.2 Replay Attacks

**Threat:** An attacker reuses a previously generated, validly signed artifact to misrepresent a new or different event.

**Impact:** A replayed artifact passes cryptographic verification because it was genuinely sealed. The deception is semantic — the artifact is authentic but presented out of context.

**Attack vectors:**
- Submitting an old artifact as evidence of a recent event
- Reusing artifacts across different systems or deployments
- Duplicating artifacts within an artifact store

**Mitigation:**
- Each artifact contains a unique `artifact_id` (prefixed `ceyo_art_`)
- Each artifact contains an `event.event_id` and `event.occurred_at` timestamp
- The artifact store assigns monotonic sequence numbers and chain hashes
- Verification systems SHOULD enforce uniqueness of artifact identifiers
- Verification systems SHOULD validate timestamps against expected time windows

**Residual risk:** Replay detection requires policy enforcement at the verification or storage layer. The protocol provides the identifiers and timestamps needed for detection but does not mandate a specific replay detection mechanism.

---

### 4.3 Signing Key Compromise

**Threat:** An attacker obtains the private signing key and generates artifacts that appear authentic.

**Impact:** Critical. A compromised signing key allows an attacker to forge artifacts that pass all cryptographic verification checks.

**Attack vectors:**
- Key extraction from insecure storage (file system, environment variables)
- Side-channel attacks on signing operations
- Insider access to key material
- Compromise of key management infrastructure

**Mitigation:**
- CEYO does not manage signing keys. Key management is the operator's responsibility.
- Operators SHOULD store signing keys in hardware security modules (HSM) or managed key services (KMS) where the private key never leaves the hardware boundary.
- Key rotation procedures SHOULD be implemented to limit the window of exposure.
- The `key_reference` field in each artifact identifies the signing key, enabling revocation and rotation tracking.
- Verification systems SHOULD maintain a record of valid key identifiers and rotation events.

**Residual risk:** If an attacker compromises the signing key, forged artifacts are cryptographically indistinguishable from genuine ones until the compromise is detected and the key is revoked.

---

### 4.4 Schema Manipulation

**Threat:** An attacker modifies the artifact schema or capture policy to change which fields are recorded, altering the meaning or completeness of artifacts without modifying individual artifact contents.

**Impact:** Artifacts may appear valid but record different information than expected. Field semantics may shift without detection.

**Attack vectors:**
- Modifying the capture policy to exclude critical fields
- Changing schema definitions to redefine field semantics
- Deploying a modified schema version without change control

**Mitigation:**
- Each artifact declares its schema version in `artifact_schema` (name and version)
- Verification systems MUST validate artifacts against the declared schema version
- Schema changes SHOULD follow versioned change control with audit trails
- Schema versions SHOULD be immutable once published
- Verifiers SHOULD reject artifacts referencing unknown schema versions

**Residual risk:** Schema governance is an operational concern. The protocol provides schema versioning, but enforcement requires organizational discipline.

---

### 4.5 Canonicalization Inconsistencies

**Threat:** Different implementations of the canonicalization scheme produce different byte output for the same input, causing verification failures on legitimate artifacts or (worse) allowing two different bodies to produce the same canonical form.

**Impact:** False verification failures on legitimate artifacts. In the worst case, canonicalization collisions could allow body substitution.

**Attack vectors:**
- Use of non-conforming canonicalization implementations
- Edge cases in Unicode normalization or number serialization
- Implementation bugs in RFC 8785 libraries

**Mitigation:**
- CEYO mandates RFC 8785 (JSON Canonicalization Scheme), which is a well-defined standard with deterministic behavior
- The `canonicalization.scheme` field declares the scheme used, enabling verifiers to select the correct implementation
- Reference implementations SHOULD be validated against RFC 8785 test vectors
- Operators SHOULD verify that their canonicalization library produces identical output to the reference implementation

**Residual risk:** Low, given RFC 8785 is a narrowly scoped standard. Risk increases if implementations deviate from the standard or handle edge cases differently.

---

### 4.6 Artifact Suppression

**Threat:** An operator or attacker intentionally prevents artifact generation for certain events, removing evidence of those events entirely.

**Impact:** Selective suppression creates gaps in the evidentiary record. Events that should have produced artifacts leave no trace.

**Attack vectors:**
- Disabling the CEYO capture layer for specific event types
- Filtering events before they reach the capture layer
- Dropping artifacts before they reach storage
- Selectively deleting artifacts from storage

**Mitigation:**
- CEYO cannot fully prevent artifact suppression by a compromised operator
- Mitigation strategies include:
  - Monitoring artifact generation rates for anomalous drops
  - Maintaining independent audit logs of AI system activity
  - Enforcing capture policies at infrastructure boundaries (e.g., API gateway)
  - Using append-only or write-once storage systems
  - Hash chaining in the artifact store makes deletion of individual artifacts detectable within the sequence
- External artifact registries or third-party witnesses can provide independent records of artifact existence

**Residual risk:** Suppression by a privileged operator is fundamentally difficult to prevent. Detection mechanisms reduce but do not eliminate this risk.

---

### 4.7 Verification Abuse

**Threat:** An attacker exploits the verification system to produce false validation results — either false positives (invalid artifacts accepted) or false negatives (valid artifacts rejected).

**Impact:** False positives undermine trust in the verification process. False negatives could be used to discredit legitimate artifacts.

**Attack vectors:**
- Submitting malformed artifacts designed to exploit parser vulnerabilities
- Manipulating verification software or its dependencies
- Bypassing verification steps through software bugs
- Supplying incorrect public keys to cause false failures

**Mitigation:**
- Verification software MUST enforce strict schema validation before cryptographic verification
- Verification MUST treat any validation error as a verification failure
- Verification implementations SHOULD be tested against known-good and known-bad artifacts
- Verification software SHOULD be subject to security review and dependency auditing
- Verification libraries SHOULD reject malformed base64url, invalid DER encodings, and unexpected field types

**Residual risk:** Verification software quality is an implementation concern. The protocol defines the verification procedure; correctness depends on implementation fidelity.

---

### 4.8 Storage Manipulation

**Threat:** An attacker modifies artifact records after they are stored — altering, deleting, or reordering artifacts in the storage system.

**Impact:** If artifacts in storage are modified, the stored record no longer reflects the original sealed artifacts. If modifications go undetected, the evidentiary chain is broken.

**Attack vectors:**
- Direct database modification
- File system alteration of stored artifact JSON
- Backup restoration that overwrites newer artifacts
- Storage system compromise

**Mitigation:**
- Cryptographic verification detects modifications to individual artifacts regardless of storage
- The artifact store implements hash chaining — each entry's chain hash covers the previous entry, creating a tamper-evident sequence
- Operators SHOULD use append-only or write-once storage systems
- Operators SHOULD maintain replicated copies of artifact stores
- Operators SHOULD periodically verify stored artifact integrity

**Residual risk:** Storage manipulation is detectable through verification and chain hash validation, but prevention depends on storage infrastructure security.

---

### 4.9 Availability Attacks

**Threat:** An attacker disrupts artifact generation or verification infrastructure through denial-of-service attacks, storage disruption, or verification service interruption.

**Impact:** Artifacts cannot be generated or verified during the disruption. If the AI system is coupled to artifact generation, availability attacks could affect inference.

**Attack vectors:**
- Denial-of-service attacks against verification endpoints
- Storage system disruption (disk exhaustion, network partition)
- Key management service unavailability
- Compute resource exhaustion during sealing

**Mitigation:**
- CEYO is designed to be fail-open: artifact generation failures MUST NOT block inference operations
- The sealing pipeline operates locally and does not depend on external network services (unless using KMS-backed keys)
- Verification infrastructure MAY be distributed for redundancy
- Artifact stores MAY be replicated across availability zones
- Operators SHOULD monitor artifact generation and verification service health

**Residual risk:** Availability depends on infrastructure resilience. CEYO's fail-open design ensures AI system availability is not affected, but artifact coverage may have gaps during outages.

---

## 5. Out-of-Scope Threats

CEYO does not address the following threat categories:

| Threat | Reason |
|---|---|
| Correctness of AI model outputs | CEYO records decisions, it does not evaluate them |
| Bias or fairness in AI decisions | CEYO is evidence infrastructure, not a fairness tool |
| Regulatory compliance evaluation | CEYO provides evidence; compliance determination is a governance function |
| Adversarial attacks against AI models | Model robustness is outside the artifact pipeline |
| Training data poisoning | Training-time threats are outside CEYO's scope |
| Privacy of model inputs/outputs | CEYO captures policy-scoped references, not raw data; data privacy is governed by capture policy |

---

## 6. Security Assumptions

The CEYO threat model assumes:

1. **Signing keys are securely managed** by the system operator using appropriate key management infrastructure
2. **Canonicalization is correctly implemented** using a conforming RFC 8785 library
3. **Verification software faithfully implements** the verification procedure defined in the protocol specification
4. **Capture policies are correctly enforced** by the system operator
5. **Cryptographic primitives are sound** — SHA-256 and ECDSA P-256 provide their stated security properties

Violations of these assumptions may compromise artifact reliability.

---

## 7. Summary

| Threat | Severity | Mitigated By |
|---|---|---|
| Artifact Tampering | High | SHA-256 hash + ECDSA signature |
| Replay Attacks | Medium | Unique IDs, timestamps, sequence numbers |
| Signing Key Compromise | Critical | HSM/KMS, key rotation, key revocation |
| Schema Manipulation | Medium | Schema versioning, change control |
| Canonicalization Inconsistencies | Low | RFC 8785 standard, test vectors |
| Artifact Suppression | High | Monitoring, append-only storage, hash chaining |
| Verification Abuse | Medium | Strict validation, security review |
| Storage Manipulation | Medium | Hash chaining, append-only storage, replication |
| Availability Attacks | Medium | Fail-open design, redundancy |

CEYO provides cryptographically verifiable artifacts that enable independent validation of AI system event records. The architecture mitigates integrity and authenticity threats through deterministic canonicalization and cryptographic sealing. Operational threats (suppression, availability, key management) require complementary infrastructure and governance controls.
