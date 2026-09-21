# CEYO Threat Model

Version: 2.0-draft  
Status: Draft

## 1. Scope

This document describes threats to CEYO artifact construction, storage, verification, key resolution, and optional transparency evidence.

CEYO is designed to make unauthorized post-seal modification of authenticated evidence detectable and to support independent cryptographic verification. It does not determine whether the underlying AI event was correct, complete, fair, lawful, compliant, or objectively true.

## 2. Assets

Relevant assets include:

- the policy-scoped event/body being sealed;
- the protocol-v2 `protected` object;
- private signing keys;
- public-key trust/status information;
- artifact stores;
- transparency-log state and checkpoints;
- receipts and other external evidence;
- verification software and its dependencies.

## 3. Trust boundaries

```text
Operator trust boundary
┌─────────────────────────────────────────────┐
│ AI/application → policy capture → sealing   │
│                         │                   │
│                         └→ signing key      │
│                                             │
│ artifact store / optional local log         │
└─────────────────────────────────────────────┘
                     │
                     │ portable artifact/evidence
                     ▼
Verifier trust boundary
┌─────────────────────────────────────────────┐
│ artifact + public key + trust/status data   │
│                 ↓                           │
│              verifier                       │
└─────────────────────────────────────────────┘

Optional external evidence boundary
┌─────────────────────────────────────────────┐
│ transparency service / TSA / witness / CA   │
└─────────────────────────────────────────────┘
```

The cryptographic artifact boundary is the v2 `protected` object plus its `integrity` proof. Receipts are external evidence and are trusted only after their own authentication and subject binding are validated.

## 4. Security objectives

### 4.1 Protected-state integrity

Any modification to canonicalized fields inside `protected` after sealing must be detectable by digest/signature verification.

### 4.2 Signature validity

A verifier must be able to determine whether the signature verifies under the supplied ECDSA P-256 public key.

### 4.3 Key-reference integrity

Artifact-level key-resolution metadata used by v2 must be signature-bound so storage modification cannot silently change the artifact's declared key reference.

### 4.4 Explicit algorithm commitment

Canonicalization and signing-suite declarations used for artifact validity must themselves be inside the signed scope.

### 4.5 Independent verification

Basic artifact validity must be checkable without access to the originating AI system or CEYO SDK.

### 4.6 Honest limitation of time claims

The protocol must distinguish signed signer assertions from independently anchored time evidence.

## 5. Threats

### 5.1 Protected-field tampering

**Threat:** An attacker with storage or transport access changes `artifact_id`, `sealed_at`, `key_reference`, policy metadata, event data, capture data, environment metadata, or another field inside `protected`.

**Mitigation:** Protocol v2 hashes and signs `canonical(protected)`. Any canonicalized change produces a digest mismatch or invalid signature unless the attacker can produce a new valid signature under an accepted key.

**Residual risk:** A holder of a trusted private key can intentionally create misleading evidence at signing time. Cryptography authenticates what was signed; it does not guarantee truthfulness of the signer.

### 5.2 Key-reference substitution

**Threat:** An attacker modifies signer/key-resolution metadata after sealing.

**Legacy-v1 exposure:** V1 stored `key_reference` outside `canonical(body)`, so the reference itself was not signature-bound.

**V2 mitigation:** `protected.key_reference` is inside the signed scope. The verifier also checks that the supplied public key matches the committed fingerprint.

**Residual risk:** A fingerprint match does not prove that the key belongs to a trusted organization or person. Authorization requires external trust-anchor evidence.

### 5.3 Timestamp manipulation and backdating

**Threat A — post-seal editing:** A third party changes the artifact's sealing timestamp after generation.

**V2 mitigation:** `protected.sealed_at` is signature-bound.

**Threat B — signer backdating:** A malicious or compromised signer chooses an incorrect time at signing, potentially to make an artifact appear to predate key revocation or another event.

**Mitigation:** Not solved by the artifact signature alone. A higher-assurance profile requires independently authenticated time evidence such as an accepted transparency receipt/checkpoint, timestamp authority, or witness mechanism.

**Residual risk:** The strength of the time claim depends on the external mechanism's own clock, identity, anti-equivocation, and availability assumptions.

### 5.4 Signing-key compromise

**Threat:** An attacker obtains or can use the private signing key.

**Impact:** The attacker may create new artifacts that pass cryptographic artifact-validity checks.

**Mitigations:** Deployment controls may include HSM/KMS-backed signing, access controls, usage audit logs, rotation, signed status/revocation records, and external monitoring.

**Residual risk:** Artifacts produced during an undetected compromise may remain cryptographically valid. Historical trust requires reliable compromise/revocation timing evidence.

### 5.5 Capture suppression or pre-seal manipulation

**Threat:** An operator or attacker omits events, suppresses CEYO artifact generation, or changes source data before the protected object is created.

**Mitigation:** CEYO alone cannot prevent a privileged operator from suppressing evidence. Complementary controls may include gateway enforcement, independent event counters, trusted execution, rate monitoring, external witnesses, or system audit logs.

**Residual risk:** Cryptographic verification of an existing artifact does not prove completeness of the overall event record.

### 5.6 Replay and contextual misuse

**Threat:** A genuine artifact is presented as evidence for a different request, system, time window, or event.

**Mitigations:** Signed artifact/event identifiers, source-asserted timestamps, request/correlation identifiers, policy references, and deployment context can support contextual checks. Verification profiles should enforce expected uniqueness and context where required.

**Residual risk:** Basic signature verification cannot determine whether a valid artifact is being presented in the correct real-world context.

### 5.7 Canonicalization divergence

**Threat:** Producer and verifier serialize the same logical JSON differently.

**Impact:** Legitimate artifacts may fail verification, or an implementation bug may create ambiguous processing behavior.

**Mitigations:** The canonicalization suite and version are signed inside `protected`; verifiers fail closed on unsupported schemes; RFC 8785 and any CEYO-specific profile should have normative cross-implementation test vectors.

**Residual risk:** Implementation defects remain possible. The separately named deterministic fallback must not be misrepresented as RFC 8785.

### 5.8 Schema/version confusion

**Threat:** A verifier interprets an artifact under the wrong processing rules or body schema.

**Mitigation:** V2 signs both `protocol_version` and `artifact_schema`. The verifier selects processing semantics from the protocol version and validates the body against the declared supported schema.

**Residual risk:** Implementations that disable schema checks or silently coerce unknown versions may reintroduce ambiguity. Production profiles should fail closed on unsupported versions.

### 5.9 Receipt spoofing or tampering

**Threat:** An attacker appends an arbitrary object to `receipts`, modifies a legitimate receipt, or presents a receipt for the wrong artifact.

**Mitigation:** Receipts do not affect basic artifact validity. A trust profile must validate a recognized receipt type, subject binding, issuer/key, signature/proof, and profile-specific requirements before relying on it.

**Residual risk:** Until typed receipt schemas and validators are defined, receipt presence alone carries no trust weight.

### 5.10 Artifact-store modification

**Threat:** An attacker changes, deletes, reorders, or rolls back locally stored artifacts.

**Mitigations:** Individual artifacts remain independently verifiable. The reference store also hashes each stored envelope and chains rows by sequence number.

**Residual risk:** Local hash chaining is not an externally witnessed append-only guarantee. Tail truncation or rollback to an earlier internally consistent state can remain undetected unless a later chain head/count/checkpoint is anchored elsewhere.

### 5.11 Transparency-log equivocation

**Threat:** A log operator presents different signed tree states to different verifiers or replays an older valid checkpoint.

**Mitigations currently available:** Signed checkpoints and Merkle inclusion proofs authenticate membership relative to a supplied checkpoint.

**Not yet provided by basic inclusion proofs:** global consistency, freshness, anti-equivocation, or non-replay.

**Further controls:** consistency proofs, witnesses, monitors, gossip, monotonic externally anchored state, or independent checkpoint publication.

### 5.12 Checkpoint timestamp overclaim

**Threat:** A verifier treats a signed checkpoint timestamp as independently trusted time merely because the checkpoint is signed.

**Mitigation:** Documentation and trust profiles must treat checkpoint time as an assertion of the checkpoint signer unless independently anchored.

### 5.13 Verification implementation abuse

**Threat:** Malformed artifacts, malformed DER/base64url, unsupported algorithms, parser edge cases, or disabled validation cause false acceptance or crashes.

**Mitigations:** Strict schema validation, algorithm whitelisting, P-256 enforcement, bounded proof structures, timing-safe comparisons for digests, negative tests, fuzzing, dependency review, and independent implementation comparison.

**Residual risk:** Verification reliability ultimately depends on implementation quality.

### 5.14 Availability failures

**Threat:** Artifact generation, key services, storage, or verification infrastructure becomes unavailable.

**Mitigation:** Availability behavior is deployment policy, not a universal protocol guarantee. Some deployments may choose fail-open inference; others may require fail-closed evidence production for specific workflows.

**Residual risk:** A fail-open deployment preserves application availability at the cost of potential evidence gaps. A fail-closed deployment may affect application availability.

## 6. Legacy-v1 risk boundary

Protocol v1 signed only `canonical(body)`. Artifact-level metadata outside that scope did not receive the same integrity guarantee.

V1 remains verifiable according to its original semantics and must not be upgraded by rewriting history. A later attestation can add new evidence about the exact v1 artifact digest, but it cannot make previously unsigned fields historically signer-bound.

## 7. Assumptions

CEYO's conclusions rely on assumptions including:

1. cryptographic primitives behave according to their expected security properties;
2. private keys are protected according to the deployment's assurance requirements;
3. verifiers correctly implement the declared canonicalization and signature suites;
4. schema/version handling fails closed for unsupported formats;
5. external trust/status/time evidence is authenticated before influencing trust;
6. capture-policy and deployment controls are evaluated separately from basic artifact cryptography.

## 8. Out of scope for basic artifact validity

Basic artifact verification does not establish:

- correctness of AI model outputs;
- fairness or absence of bias;
- regulatory compliance;
- legal admissibility;
- completeness of the event record;
- objective real-world event truth;
- independent accuracy of signer timestamps;
- authorization of an otherwise valid key;
- global transparency-log consistency.

## 9. Review priorities

Before production use, priority review areas include:

- cross-implementation canonicalization vectors;
- complete mutation tests over every protected field;
- unsupported-version/fail-closed behavior;
- typed receipt schemas and receipt validators;
- historical revocation/status semantics;
- external-time profile;
- transparency consistency/witness model;
- storage rollback/tail-truncation anchoring;
- independent cryptography/security review.
