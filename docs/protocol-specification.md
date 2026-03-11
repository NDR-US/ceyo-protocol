# CEYO Protocol Specification

## Overview

The CEYO protocol defines a deterministic procedure for producing cryptographically verifiable records of AI decision events.

A CEYO artifact represents a structured envelope containing a policy-scoped record of a decision event along with canonicalization metadata and cryptographic integrity fields.

The protocol enables independent verification of artifact integrity without requiring access to the originating AI system.

The protocol defines procedures for:

- artifact construction
- canonicalization
- digest generation
- signature creation
- verification

The protocol does not attempt to evaluate the correctness or fairness of AI decisions.

Its purpose is limited to producing tamper-evident decision records.

---

## Artifact Structure

A CEYO artifact consists of a structured envelope containing the following components:

- artifact metadata
- captured decision record
- canonicalization metadata
- cryptographic integrity fields
- verification references

The canonical JSON schema defining the artifact structure is located at:

`spec/artifact-schema.json`

Implementations must conform to this schema when generating artifacts.

The envelope contains the following top-level fields:

| Field | Type | Description |
|---|---|---|
| `product` | string | Protocol identifier. Must be `"CEYO"`. |
| `envelope_version` | string | Envelope format version. |
| `artifact_schema` | object | Schema name and version governing the artifact body. |
| `artifact_id` | string | Unique artifact identifier. Must match `^ceyo_art_`. |
| `created_at` | string | ISO 8601 UTC timestamp of artifact creation. |
| `body` | object | Policy-scoped decision record. |
| `canonicalization` | object | Canonicalization scheme, version, and scope. |
| `integrity` | object | Cryptographic hash and digital signature. |
| `key_reference` | object | Signing key identifier and public key fingerprint. |

All fields are required.

The `integrity` object contains:

- `hash` — algorithm identifier (`SHA-256`), base64url-encoded digest, and coverage descriptor
- `sig` — algorithm identifier (`ECDSA-P256-SHA256`), DER format, base64url-encoded signature, and coverage descriptor

The `key_reference` object contains:

- `registry` — key registry identifier
- `key_id` — key identifier within the registry
- `public_key_fingerprint` — SHA-256 digest of the public key in DER-encoded SubjectPublicKeyInfo format, base64url-encoded

---

## Canonicalization

Before hashing, the artifact body must be converted into a deterministic canonical representation.

CEYO uses RFC 8785 JSON Canonicalization Scheme (JCS).

Canonicalization ensures that identical logical records always produce identical byte representations.

This property allows independent verifiers to recompute hashes reliably.

RFC 8785 specifies:

- Lexicographic ordering of object member names by Unicode code point
- No whitespace between tokens
- Deterministic number serialization
- UTF-8 encoding of the output

Canonicalization is applied to the `body` field only. The envelope structure, integrity fields, and key reference are not canonicalized.

If RFC 8785 is unavailable, implementations may temporarily use deterministic JSON serialization with sorted keys and fixed separators, though RFC 8785 is the preferred canonicalization method.

---

## Digest Generation

After canonicalization, the canonical byte sequence is hashed using SHA-256.

```
digest = SHA-256(canonicalized_body)
```

The resulting digest becomes the artifact integrity hash.

This digest uniquely represents the canonicalized record content.

Any modification to the artifact body will produce a different digest.

The digest is a 32-byte (256-bit) value, encoded as a base64url string without padding and stored in `integrity.hash.value_b64u`.

---

## Signature Generation

The artifact digest is signed using a cryptographic signing key.

The protocol uses:

- Algorithm: ECDSA with NIST P-256 curve (secp256r1)
- Algorithm identifier: `ECDSA-P256-SHA256`

The signature is generated over the digest using prehashed SHA-256.

```
signature = Sign(private_key, digest)
```

The signature is DER-encoded and stored as a base64url string without padding in `integrity.sig.value_b64u`.

The public key fingerprint is computed as:

```
fingerprint = SHA-256(DER(SubjectPublicKeyInfo(public_key)))
```

The signature and key reference are embedded in the artifact envelope.

---

## Verification Procedure

Artifact verification consists of the following steps.

1. Validate artifact structure against the JSON schema defined in `spec/artifact-schema.json`.

2. Canonicalize the artifact body using the declared canonicalization scheme (RFC 8785).

3. Recompute the SHA-256 digest over the canonical byte sequence.

4. Compare the recomputed digest against the recorded digest in `integrity.hash.value_b64u`. If the values do not match, verification fails.

5. Validate the digital signature in `integrity.sig.value_b64u` using the referenced public key and ECDSA with prehashed SHA-256. If signature validation fails, verification fails.

6. Confirm the public key fingerprint by computing `SHA-256(DER(SubjectPublicKeyInfo(public_key)))` and comparing against `key_reference.public_key_fingerprint.value_b64u`. If the values do not match, verification fails.

Verification succeeds if all checks pass.

Verification requires only:

- The sealed artifact envelope (JSON)
- The public verification key
- An RFC 8785 canonicalization implementation
- Standard SHA-256 and ECDSA P-256 libraries

No access to the originating AI system or proprietary infrastructure is required.

---

## Security Considerations

CEYO artifacts provide tamper-evident integrity verification of recorded decision events.

Verification confirms that:

- the artifact content has not been modified
- the artifact was signed by the expected key
- the canonicalization and hashing processes are reproducible

Verification does not guarantee:

- correctness of the AI decision
- fairness or absence of bias
- regulatory compliance
- legal admissibility

CEYO artifacts represent verifiable evidence records, not judgments.

Signing key management is the responsibility of the system operator. Keys should be protected using appropriate key management infrastructure such as hardware security modules or managed key services.

A comprehensive threat model is provided in the companion document `docs/threat-model.md`.

---

## Protocol Scope

The CEYO protocol defines artifact construction and verification rules.

It does not define:

- AI model behavior
- governance policy enforcement
- auditing frameworks
- regulatory compliance systems

The protocol focuses exclusively on deterministic artifact generation and verification.
