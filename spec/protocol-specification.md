# CEYO Protocol Specification

**Status: public draft profile 0.1.0-draft**  
**Creator and project lead: Brian Covarrubias**

## 1. Purpose

The CEYO protocol defines a deterministic procedure for producing and independently verifying cryptographically sealed evidence artifacts associated with AI and autonomous-system operations.

The current public profile is intentionally narrow. It defines:

- artifact-envelope structure;
- deterministic canonicalization of the artifact body;
- SHA-256 digest generation;
- ECDSA P-256 / SHA-256 signing;
- public-key fingerprint references;
- independent artifact verification;
- companion transparency-log evidence defined elsewhere in `spec/`.

CEYO does not determine whether an underlying AI output is correct, fair, lawful, complete, or institutionally sufficient.

## 2. Artifact envelope

The canonical machine-readable schema is `spec/artifact-schema.json`.

A current-profile envelope contains:

| Field | Meaning | Signed in profile 0.1 |
|---|---|---|
| `product` | Protocol identifier (`CEYO`) | No |
| `envelope_version` | Envelope format version | No |
| `artifact_schema` | Declared body-schema identity/version | No |
| `artifact_id` | Artifact identifier | No |
| `created_at` | Artifact-creation timestamp asserted by the sealing process | No |
| `body` | Structured evidentiary record | **Yes** |
| `canonicalization` | Canonicalization metadata | No |
| `integrity` | Digest and signature material | Derived / signature field |
| `key_reference` | Declared signing-key reference and fingerprint | No |

### 2.1 Signed-scope rule

**Profile 0.1 signs only `canonical(body)`.**

Therefore, successful signature verification establishes integrity/authenticity properties for the canonicalized `body` under the supplied verification key. It does **not** by itself establish cryptographic integrity of unsigned envelope metadata.

Verifiers and downstream systems MUST NOT treat `artifact_id`, `created_at`, `artifact_schema`, `canonicalization`, or `key_reference` as signed merely because those fields appear in a verified envelope.

A future protocol profile is expected to expand the protected scope to security-relevant protocol, policy, schema, key/trust, and temporal context. That future profile is not implied by this one.

## 3. Artifact body

The body is a structured JSON object representing the record selected for evidentiary capture.

The reference implementation supports event fields and may include declared policy, disclosure, capture, and environment context.

A declared `policy` object in profile 0.1 is data inside the signed body and is therefore integrity-protected when present. However, the current profile does not independently establish that:

- the policy was institutionally authorized;
- the policy was the policy actually enforced before capture;
- the policy definition has been retrieved from an authenticated registry;
- the captured record is complete with respect to a real-world event.

Those are target-architecture concerns tracked in `status-and-roadmap.md`.

## 4. Canonicalization

The current profile requires **RFC 8785 JSON Canonicalization Scheme (JCS)** for the artifact body.

```text
canonical_body = RFC8785(body)
```

A conformant implementation MUST use RFC 8785 semantics when the envelope declares `RFC8785`.

A deterministic JSON fallback that is not RFC 8785 conformant MUST NOT be labeled `RFC8785` and is not interoperable with the current canonical profile unless a separately versioned scheme explicitly defines that behavior.

Canonicalization is applied to `body` only in profile 0.1.

## 5. Digest generation

The digest is:

```text
digest = SHA-256(canonical_body)
```

The 32-byte digest is encoded as base64url without padding and stored in:

`integrity.hash.value_b64u`

The current profile identifies the digest algorithm as `SHA-256`.

## 6. Signature generation

The current profile uses:

- Curve: NIST P-256 / `secp256r1`
- Signature: ECDSA
- Digest: SHA-256
- Protocol identifier: `ECDSA-P256-SHA256`
- Signature encoding: ASN.1 DER

The reference implementation signs the already-computed SHA-256 digest using ECDSA with prehashed SHA-256 semantics:

```text
signature = ECDSA-P256-SHA256(private_key, digest)
```

The signature is stored in `integrity.sig.value_b64u` using base64url without padding.

## 7. Key fingerprint

The public-key fingerprint is:

```text
fingerprint = SHA-256(DER(SubjectPublicKeyInfo(public_key)))
```

The digest is base64url-encoded without padding and recorded in `key_reference.public_key_fingerprint.value_b64u`.

A matching fingerprint establishes correspondence between the supplied key and the declared fingerprint. It does **not** by itself establish institutional authorization of that key. Authorization requires an external trust basis or future authenticated trust-registry mechanism.

## 8. Verification procedure

A profile-0.1 verifier performs, at minimum:

1. Validate the envelope structure against `spec/artifact-schema.json`.
2. Confirm the declared canonicalization scheme is supported by the verifier.
3. Canonicalize `body` using RFC 8785.
4. Recompute `SHA-256(canonical(body))`.
5. Compare the recomputed digest with `integrity.hash.value_b64u`.
6. Load the supplied P-256 public key.
7. Confirm the public-key fingerprint against `key_reference.public_key_fingerprint` when fingerprint checking is enabled.
8. Verify the ECDSA P-256 signature over the recomputed digest using prehashed SHA-256 semantics.

A successful result means the signed body matches the body that was signed by the holder of the supplied key, subject to the verifier's key/trust assumptions.

## 9. Time semantics

`created_at` is an envelope timestamp asserted by the sealing process.

Because `created_at` is outside the profile-0.1 signed body and is not backed by an independent trusted timestamp mechanism, profile 0.1 does **not** claim that cryptographic verification alone proves the real-world time at which the artifact existed.

Transparency checkpoints can provide additional evidence about log state. Stronger temporal guarantees are target architecture.

## 10. Transparency evidence

The CEYO transparency-log profile is specified separately in `transparency-log.md`.

Reference components support:

- Merkle-tree append-only logging;
- signed checkpoints;
- artifact inclusion proofs;
- independent proof verification.

A transparency inclusion proof demonstrates inclusion relative to a particular root/checkpoint under the verification assumptions of that checkpoint. It is not, by itself, proof that the underlying event was true.

## 11. Security properties and boundaries

Depending on the evidence supplied and verifier configuration, profile 0.1 can support verification of:

- schema/structural validity;
- deterministic body representation;
- body-digest integrity;
- signature validity;
- correspondence to a supplied P-256 key;
- declared public-key fingerprint consistency;
- transparency inclusion where applicable.

Profile 0.1 does not by itself establish:

- pre-capture truth or completeness;
- AI correctness or fairness;
- regulatory compliance;
- authorization of a key without an external trust basis;
- trusted real-world time from `created_at` alone;
- integrity of unsigned envelope metadata;
- legal admissibility or evidentiary sufficiency.

See `security-model.md`, `threat-model.md`, and `status-and-roadmap.md`.

## 12. Cryptographic confidentiality

Encryption is not part of the mandatory profile-0.1 sealing/verification pipeline.

Future deployment profiles may use encryption for confidential artifacts, selective disclosure, or protected transport/storage. Encryption is a confidentiality mechanism; it does not replace canonicalization, hashing, digital signatures, trust evaluation, or transparency evidence.

## 13. Versioning and protocol evolution

Any change that affects deterministic verification or interoperability requires explicit protocol-version treatment, including changes to:

- signed/protected scope;
- artifact schema;
- canonicalization rules;
- digest algorithms;
- signature suites;
- trust/key-reference semantics;
- temporal evidence;
- transparency-proof semantics;
- verification-result semantics.

No website, demo, private R&D implementation, or explanatory document may silently create an alternative CEYO protocol profile.

## 14. Target architecture

The broader intended architecture — protected policy/schema context, authenticated trust registries, trusted time, revocation, hardware-backed key custody, constrained disclosure, anti-equivocation mechanisms, and multi-implementation conformance — is documented in `status-and-roadmap.md`.

Those features remain planned or experimental until promoted into a versioned public profile.
