# CEYO Protocol Specification

**Version:** 1.0
**Status:** Draft
**Last Updated:** 2026-03-11

---

## 1. Introduction

### 1.1 Purpose

This document specifies the CEYO artifact format, sealing process, and verification procedure for generating cryptographically verifiable evidentiary records of AI system decision events.

### 1.2 Scope

This specification defines:

- The structure of CEYO artifact envelopes
- Canonicalization requirements for deterministic serialization
- Cryptographic hashing and digital signature procedures
- The verification process for independent artifact validation
- Schema versioning and interoperability requirements

This specification does not define capture policies, storage requirements, or governance models. Those concerns are addressed in companion documents.

### 1.3 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

An implementation claiming conformance to this specification MUST implement all requirements identified by "MUST" and "SHALL".

---

## 2. Terminology

**Artifact** — A structured record describing a policy-scoped AI system decision event, together with cryptographic integrity fields.

**Artifact Body** — The portion of the artifact containing event data captured according to a defined capture policy. The body is the input to canonicalization and hashing.

**Artifact Envelope** — The complete artifact structure containing the body, canonicalization metadata, cryptographic integrity fields, and key reference information.

**Canonicalization** — The deterministic serialization process applied to the artifact body prior to hashing. Produces identical byte output for semantically identical input across all conforming implementations.

**Sealing** — The process of generating cryptographic integrity fields (hash and digital signature) over the canonicalized artifact body and assembling the complete artifact envelope.

**Verification** — The process of independently confirming artifact integrity and authenticity by recomputing the canonical hash and validating the digital signature.

**Signing Key** — The private key used to generate the digital signature during sealing. Controlled by the system operator.

**Verification Key** — The public key corresponding to the signing key, used during verification to validate the digital signature.

**Key Fingerprint** — A SHA-256 digest of the public key in DER-encoded SubjectPublicKeyInfo format, used to identify the verification key without transmitting the full key.

---

## 3. Artifact Envelope Structure

### 3.1 Overview

A CEYO artifact envelope is a JSON object containing the following top-level fields. All fields are REQUIRED unless otherwise noted.

### 3.2 Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `product` | string | REQUIRED | Protocol identifier. MUST be `"CEYO"`. |
| `envelope_version` | string | REQUIRED | Envelope format version. Current value: `"1.0"`. |
| `artifact_schema` | object | REQUIRED | Schema name and version for the artifact body. |
| `artifact_id` | string | REQUIRED | Unique artifact identifier. MUST match pattern `^ceyo_art_`. |
| `created_at` | string | REQUIRED | ISO 8601 UTC timestamp of artifact creation. Format: `YYYY-MM-DDTHH:MM:SSZ`. |
| `body` | object | REQUIRED | The artifact body containing policy-scoped event data. |
| `canonicalization` | object | REQUIRED | Canonicalization metadata. |
| `integrity` | object | REQUIRED | Cryptographic integrity fields (hash and signature). |
| `key_reference` | object | REQUIRED | Information identifying the signing key. |

### 3.3 Complete Envelope Example

```json
{
  "product": "CEYO",
  "envelope_version": "1.0",
  "artifact_schema": {
    "name": "ceyo.artifact",
    "version": "1.0"
  },
  "artifact_id": "ceyo_art_a5e2f966f10d49e1be3c47a5ca",
  "created_at": "2026-03-09T20:58:26Z",
  "body": {
    "event": {
      "event_id": "evt_demo_0001",
      "type": "classification",
      "occurred_at": "2026-02-19T12:00:00Z",
      "request_id": "req_demo_0001"
    },
    "policy": {
      "id": "demo-policy",
      "version": "1.0"
    },
    "disclosure_tier": "public",
    "capture": {
      "input_ref_hash": {
        "alg": "SHA-256",
        "value_b64u": "placeholder_input_hash",
        "covers": "policy_scoped_input_representation"
      },
      "output_ref_hash": {
        "alg": "SHA-256",
        "value_b64u": "placeholder_output_hash",
        "covers": "policy_scoped_output_representation"
      }
    },
    "environment": {
      "deployment_id": "dep_demo_local",
      "model_ref": "demo-ai-system-v1.0",
      "runtime_ref": "local"
    }
  },
  "canonicalization": {
    "scheme": "RFC8785",
    "version": "1.0",
    "scope": "body"
  },
  "integrity": {
    "hash": {
      "alg": "SHA-256",
      "value_b64u": "0ME3dmu5bgTV-QjewZhLYWtp6N1-6lkwt5MWUNwl1SU",
      "covers": "canonical(body)"
    },
    "sig": {
      "alg": "ECDSA-P256-SHA256",
      "format": "DER",
      "value_b64u": "MEYCIQCbsJVo_pZMISWpE8Yiu7PRcEvCXsxaEYtB3800FtzGnAIhAOUow8eW_PZYt23XQoxpaHs_EqFcY99hGYUm4k6FgeYh",
      "covers": "canonical(body)"
    }
  },
  "key_reference": {
    "registry": "local",
    "key_id": "local:private_key.pub.pem",
    "public_key_fingerprint": {
      "alg": "SHA-256",
      "value_b64u": "DLTVwvuJ8xEMbfliGHw3maWFI6V1fE8QHcfgBI7zWJ8",
      "covers": "public_key_spki_der"
    }
  }
}
```

### 3.4 Field Definitions

#### 3.4.1 `artifact_schema`

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | REQUIRED | Schema identifier. Default: `"ceyo.artifact"`. |
| `version` | string | REQUIRED | Schema version using semantic versioning. |

#### 3.4.2 `body`

The artifact body is a JSON object containing policy-scoped event data. The body structure is defined by the artifact schema version.

For schema version `ceyo.artifact/1.0`, the body MUST contain:

| Field | Type | Required | Description |
|---|---|---|---|
| `event` | object | REQUIRED | Event metadata. |
| `event.event_id` | string | REQUIRED | Unique event identifier. |
| `event.type` | string | REQUIRED | Event classification type. |
| `event.occurred_at` | string | REQUIRED | ISO 8601 UTC timestamp of the event. |
| `event.request_id` | string | OPTIONAL | Request identifier for correlation. |
| `policy` | object | OPTIONAL | Capture policy reference. |
| `policy.id` | string | OPTIONAL | Policy identifier. |
| `policy.version` | string | OPTIONAL | Policy version. |
| `disclosure_tier` | string | OPTIONAL | Data sensitivity tier (e.g., `"public"`, `"internal"`). |
| `capture` | object | OPTIONAL | Policy-scoped captured data or references. |
| `environment` | object | OPTIONAL | Deployment and runtime environment metadata. |

#### 3.4.3 `canonicalization`

| Field | Type | Required | Description |
|---|---|---|---|
| `scheme` | string | REQUIRED | Canonicalization scheme. MUST be `"RFC8785"`. |
| `version` | string | REQUIRED | Scheme version. |
| `scope` | string | REQUIRED | Scope of canonicalization. MUST be `"body"`. |

#### 3.4.4 `integrity`

Contains two sub-objects: `hash` and `sig`.

**`integrity.hash`**

| Field | Type | Required | Description |
|---|---|---|---|
| `alg` | string | REQUIRED | Hash algorithm. MUST be `"SHA-256"`. |
| `value_b64u` | string | REQUIRED | Base64url-encoded (unpadded) hash digest. |
| `covers` | string | REQUIRED | Description of the hashed content. Value: `"canonical(body)"`. |

**`integrity.sig`**

| Field | Type | Required | Description |
|---|---|---|---|
| `alg` | string | REQUIRED | Signature algorithm. MUST be `"ECDSA-P256-SHA256"`. |
| `format` | string | REQUIRED | Signature encoding format. MUST be `"DER"`. |
| `value_b64u` | string | REQUIRED | Base64url-encoded (unpadded) DER-encoded signature. |
| `covers` | string | REQUIRED | Description of the signed content. Value: `"canonical(body)"`. |

#### 3.4.5 `key_reference`

| Field | Type | Required | Description |
|---|---|---|---|
| `registry` | string | REQUIRED | Key registry identifier (e.g., `"local"`, `"kms"`, `"env"`). |
| `key_id` | string | REQUIRED | Key identifier within the registry. |
| `public_key_fingerprint` | object | REQUIRED | Fingerprint of the verification key. |
| `public_key_fingerprint.alg` | string | REQUIRED | Fingerprint algorithm. MUST be `"SHA-256"`. |
| `public_key_fingerprint.value_b64u` | string | REQUIRED | Base64url-encoded fingerprint. |
| `public_key_fingerprint.covers` | string | REQUIRED | Description of fingerprinted content. Value: `"public_key_spki_der"`. |

---

## 4. Canonicalization

### 4.1 Requirements

Implementations MUST canonicalize the artifact body before hashing. Canonicalization MUST produce identical byte output for semantically identical JSON input across all conforming implementations.

### 4.2 Canonical Form

The REQUIRED canonicalization scheme is RFC 8785 (JSON Canonicalization Scheme / JCS).

RFC 8785 specifies:

- Lexicographic ordering of object member names based on Unicode code points
- No whitespace between tokens
- Specific number serialization rules
- UTF-8 encoding of the output

### 4.3 Scope

Canonicalization is applied to the `body` field only. The envelope structure, integrity fields, and key reference are NOT canonicalized.

### 4.4 Output

The canonicalization output is a byte sequence (UTF-8 encoded canonical JSON). This byte sequence is the input to the hash function.

---

## 5. Hashing

### 5.1 Algorithm

Implementations MUST use SHA-256 as the hash algorithm.

### 5.2 Input

The hash input is the byte output of the canonicalization step (Section 4.4).

### 5.3 Output

The hash output is a 32-byte (256-bit) digest.

### 5.4 Encoding

The hash digest MUST be encoded as a base64url string without padding (RFC 4648, Section 5, with trailing `=` characters removed) and stored in `integrity.hash.value_b64u`.

---

## 6. Digital Signature

### 6.1 Algorithm

Implementations MUST use ECDSA with the NIST P-256 curve (secp256r1) and SHA-256 as the hash function.

The algorithm identifier is `"ECDSA-P256-SHA256"`.

### 6.2 Input

The signature is computed over the SHA-256 digest produced in Section 5.3. The signing operation uses prehashed mode — the raw 32-byte digest is signed directly, not hashed again.

### 6.3 Output Format

The signature MUST be DER-encoded per SEC 1, Section C.8.

### 6.4 Encoding

The DER-encoded signature MUST be encoded as a base64url string without padding and stored in `integrity.sig.value_b64u`.

### 6.5 Key Fingerprint

The public key fingerprint is computed as:

```
fingerprint = SHA-256(DER(SubjectPublicKeyInfo(public_key)))
```

The DER-encoded SubjectPublicKeyInfo representation of the public key is hashed with SHA-256. The resulting digest is base64url-encoded without padding.

---

## 7. Verification Procedure

### 7.1 Overview

Verification confirms that an artifact has not been modified since sealing and that the artifact was sealed by the holder of the declared signing key.

Verification MUST NOT require access to the original AI system or any proprietary infrastructure.

### 7.2 Procedure

A conforming verifier MUST execute the following steps in order. If any step fails, the artifact MUST be rejected.

**Step 1 — Schema Validation**

Validate the artifact envelope structure against the declared schema version. Confirm all required fields are present and correctly typed.

**Step 2 — Load Verification Key**

Load the public key identified by `key_reference`. The key MUST be an ECDSA P-256 public key in PEM or DER format.

**Step 3 — Canonicalize Body**

Extract the `body` field and canonicalize it using the scheme declared in `canonicalization.scheme` (MUST be RFC 8785).

**Step 4 — Recompute Hash**

Compute `SHA-256(canonical_bytes)` and compare the result to the value stored in `integrity.hash.value_b64u` (after base64url decoding). If the values do not match, verification MUST fail with a hash mismatch error.

**Step 5 — Validate Signature**

Decode `integrity.sig.value_b64u` to obtain the DER-encoded signature. Verify the signature against the recomputed hash digest using the loaded public key and ECDSA with prehashed SHA-256. If signature validation fails, verification MUST fail.

**Step 6 — Verify Key Fingerprint**

Compute `SHA-256(DER(SubjectPublicKeyInfo(public_key)))` and compare the result to `key_reference.public_key_fingerprint.value_b64u`. If the values do not match, verification MUST fail with a key fingerprint mismatch error.

### 7.3 Verification Result

Verification produces a binary outcome: PASS or FAIL.

A passing result confirms:

1. The artifact body has not been modified since sealing
2. The digital signature was produced by the holder of the corresponding private key
3. The public key matches the declared fingerprint
4. The artifact structure conforms to the declared schema

A passing result does NOT confirm:

- The correctness or fairness of the underlying AI decision
- Compliance with any regulatory framework
- The accuracy of the event data recorded in the body

---

## 8. Schema Versioning

### 8.1 Envelope Version

The `envelope_version` field identifies the version of the envelope structure itself. Changes to the envelope format (adding or removing top-level fields, modifying integrity field structures) require a new envelope version.

### 8.2 Artifact Schema Version

The `artifact_schema` field identifies the schema governing the body structure. Changes to body field requirements or semantics require a new artifact schema version.

### 8.3 Compatibility

New schema versions SHOULD maintain backward compatibility with existing verification procedures when possible. Specifically, the canonicalization, hashing, and signature verification steps SHOULD remain stable across schema versions.

---

## 9. Interoperability

### 9.1 Implementation Requirements

Independent implementations MUST be able to verify CEYO artifacts using only:

- This specification
- The artifact envelope (JSON)
- The public verification key
- An RFC 8785 canonicalization library
- A SHA-256 implementation
- An ECDSA P-256 signature verification implementation

No proprietary libraries, network services, or access to the generating system are required for verification.

### 9.2 Encoding

All string values within the artifact envelope MUST be valid UTF-8. Binary values (hashes, signatures, fingerprints) MUST be encoded as base64url without padding.

### 9.3 Timestamps

All timestamps MUST be in UTC and formatted as ISO 8601: `YYYY-MM-DDTHH:MM:SSZ`.

---

## 10. Security Considerations

### 10.1 Signing Key Management

The security of the artifact sealing process depends on the confidentiality and integrity of the signing key. System operators MUST protect signing keys using appropriate key management infrastructure. See the companion Key Management document for guidance.

### 10.2 Canonicalization Correctness

Verification correctness depends on deterministic canonicalization. Implementations MUST use a conforming RFC 8785 implementation. Differences in canonicalization between sealing and verification will cause hash mismatches and verification failures.

### 10.3 Artifact Scope

CEYO artifacts record policy-scoped snapshots of AI system events. Artifacts do not provide guarantees about events that were not captured, decisions that were not recorded, or the completeness of the event record.

### 10.4 Threat Model

A comprehensive threat model is provided in the companion Threat Model document.

---

## 11. References

- **RFC 2119** — Key words for use in RFCs to Indicate Requirement Levels
- **RFC 4648** — The Base16, Base32, and Base64 Data Encodings
- **RFC 8785** — JSON Canonicalization Scheme (JCS)
- **SEC 1** — Elliptic Curve Cryptography, Certicom Research
- **FIPS 186-4** — Digital Signature Standard (DSS)
- **FIPS 180-4** — Secure Hash Standard (SHS)
