# CEYO Protocol Specification

## Status and scope

CEYO defines a portable artifact format and independent verification procedure for policy-scoped records produced around AI-supported operations.

The protocol is designed so that an artifact can be checked without access to the originating AI system. CEYO verifies defined cryptographic integrity and declared-provenance properties of the evidence that was captured and sealed. It does not determine whether an AI output was correct, fair, lawful, compliant, complete, or factually true.

This document defines the current protocol-v2 artifact envelope. Protocol-v1 artifacts remain verifiable under their original, narrower signature scope and are treated as legacy artifacts.

---

## Security invariant

A conforming protocol-v2 verifier MUST derive artifact-level validity and trust inputs only from:

1. fields contained in the signed `protected` object; or
2. independently authenticated external evidence, such as validated receipts, status/revocation evidence, or trust anchors.

Unauthenticated envelope metadata MUST NOT influence artifact trust status.

This invariant is the reason protocol v2 signs the complete `protected` object rather than only the event body.

---

## Artifact envelope

The canonical JSON Schema is:

`spec/artifact-schema.json`

A protocol-v2 artifact has three top-level components:

| Field | Type | Purpose |
|---|---|---|
| `protected` | object | Artifact identity, declared suites, signer/key binding, signer-asserted sealing time, body, and other artifact-level inputs covered by the signature. |
| `integrity` | object | Digest and digital signature calculated over `canonical(protected)`. |
| `receipts` | array | Optional external evidence appended without changing the original artifact signature. A receipt affects trust only after its own type, subject binding, issuer, and proof are validated. |

### `protected`

`protected` contains:

| Field | Description |
|---|---|
| `product` | Protocol identifier. Must be `"CEYO"`. |
| `protocol_version` | CEYO processing and trust-rule version. Current value: `"2.0"`. |
| `artifact_schema` | Name and version governing the structure of `protected.body`. |
| `artifact_id` | Stable artifact identifier. |
| `sealed_at` | Signer-asserted UTC sealing time. Signature-bound, but not independently trusted time. |
| `canonicalization_suite` | Deterministic serialization scheme and version used for `protected`. |
| `signing_suite` | Signature algorithm, encoding, and digest algorithm. |
| `key_reference` | Registry, key identifier, and public-key fingerprint committed to by the signer. |
| `body` | Policy-scoped record of the asserted event and related capture context. |

`protocol_version` and `artifact_schema` are intentionally separate. `protocol_version` controls CEYO processing and trust semantics; `artifact_schema` controls the shape of the artifact body. A protocol version may support more than one body-schema version.

### `body`

The body may contain structured fields such as:

- `event` — event identifier, event type, source-asserted occurrence time, and optional request/correlation identifier;
- `policy` — capture-policy identifier, version, and optional digest committing to the exact policy representation;
- `capture` — structured references to policy-scoped captured material;
- `disclosure_policy` — sealing-time disclosure commitment;
- `environment` — declared deployment/model/runtime metadata.

`event.occurred_at` is a source assertion about the underlying event. It is not external proof of objective time.

---

## Canonicalization

Protocol v2 canonicalizes the complete `protected` object using RFC 8785 JSON Canonicalization Scheme (JCS).

Current protocol-v2 artifacts MUST declare:

```json
{
  "canonicalization_suite": {
    "scheme": "RFC8785",
    "version": "1.0"
  }
}
```

A producer MUST NOT silently fall back to another serializer when RFC 8785 is unavailable. Failure to perform the declared canonicalization is an error.

A verifier MUST reproduce the declared supported scheme exactly and MUST NOT silently substitute a different serialization algorithm.

Legacy protocol-v1 artifacts may contain historical canonicalization declarations and are verified according to their original semantics. That compatibility behavior does not change the normative protocol-v2 canonicalization profile.

---

## Digest generation

For protocol v2:

```text
protected_bytes = RFC8785(protected)
digest = SHA-256(protected_bytes)
```

The 32-byte digest is base64url encoded without padding and stored in:

`integrity.digest.value_b64u`

The coverage descriptor is:

`canonical(protected)`

Any change to the canonical representation of `protected` produces a different digest.

---

## Signature generation

The current protocol-v2 signing suite is:

- ECDSA
- NIST P-256 / secp256r1
- SHA-256
- DER-encoded signature
- algorithm identifier `ECDSA-P256-SHA256`

The reference implementation signs the already-computed SHA-256 digest using ECDSA prehashed mode:

```text
signature = ECDSA-P256(private_key, digest, Prehashed-SHA256)
```

The signature is stored in:

`integrity.signature.value_b64u`

The signature therefore authenticates the complete canonical `protected` object, including the declared key reference, algorithm suites, artifact identity, and `sealed_at` value.

---

## Key binding

`protected.key_reference` is inside the signed scope. It contains:

- `registry`
- `key_id`
- `public_key_fingerprint`
- optional authority metadata where defined by a deployment profile

The current public-key fingerprint is SHA-256 over DER-encoded SubjectPublicKeyInfo.

Binding the key reference inside `protected` prevents artifact-store modification of signer/key-resolution metadata without invalidating the artifact digest/signature.

A fingerprint match establishes that the supplied verification key matches the key fingerprint committed to by the artifact. It does not, by itself, establish that the registry, operator, organization, or human identity associated with that key should be trusted. That determination belongs to the applicable trust profile and trust-anchor infrastructure.

---

## Time semantics

CEYO distinguishes different time claims.

### Event time

`protected.body.event.occurred_at` is the originating system's assertion about when the underlying event occurred.

### Sealing time

`protected.sealed_at` is the signer's assertion about when the artifact was sealed. Because it is signature-bound, a third party cannot edit it later without invalidating the artifact.

Signing `sealed_at` does not prove that the signer's clock was accurate and does not prevent a malicious or compromised signer from backdating at signing time.

### Externally anchored time

Stronger temporal assurance requires separately authenticated external evidence, such as an accepted transparency receipt/checkpoint profile, RFC 3161 timestamp authority, or witness mechanism.

A verification profile performing historical key-status or revocation evaluation SHOULD prefer an authenticated external time anchor when one is available and required by the profile. If only `sealed_at` exists, the verifier must treat the time basis as signer-asserted rather than independently established.

---

## Receipts

`receipts` is deliberately outside the artifact signature so external evidence can be attached after sealing without changing the original artifact signature.

Appending, removing, or modifying a receipt does not change protocol-v2 artifact signature validity.

A receipt can affect a higher-level trust decision only after its own receipt type, subject binding, issuer, and cryptographic proof have been validated by the applicable verification profile.

The base artifact schema currently reserves `receipts` as an array of objects. Typed receipt schemas and profile requirements are defined separately. An arbitrary or unknown object MUST NOT satisfy a trust requirement merely because it appears in `receipts`.

---

## Verification procedure

For protocol v2, a verifier performs at least the following artifact-validity checks:

1. Validate the envelope against the protocol-v2 schema.
2. Confirm the declared protocol, canonicalization, and signing suites are supported.
3. Load and validate the supplied ECDSA P-256 public key.
4. Canonicalize the complete `protected` object using RFC 8785.
5. Recompute SHA-256 over the canonical bytes.
6. Compare the recomputed digest with `integrity.digest.value_b64u`.
7. Verify `integrity.signature.value_b64u` against the recomputed digest.
8. Compute the public-key fingerprint and compare it with `protected.key_reference.public_key_fingerprint`.

If these checks pass, the artifact is cryptographically valid under protocol v2.

That result is intentionally narrower than a trust decision.

---

## Validity and trust are distinct

CEYO separates artifact validity from evidentiary/trust status.

```text
artifact validity
    = schema/protocol processing
    + digest verification
    + signature verification
    + protected key-fingerprint consistency

trust / evidentiary status
    = artifact validity
    + signer/key authorization or trust state
    + applicable revocation/status evidence
    + required receipts or external anchors
    + verification-profile policy
```

A cryptographically valid artifact may therefore remain insufficient for a particular trust profile.

---

## Revocation and historical trust

Revocation status is not embedded as mutable state inside the original artifact.

The artifact commits to key identity/fingerprint. A verifier resolves current or historical key status from independently authenticated external status/revocation evidence.

Historical revocation evaluation requires an acceptable time basis. Protocol-v2 `sealed_at` is integrity-protected but self-asserted. High-assurance profiles should use a validated external time anchor when required by their threat model.

---

## Protocol-v1 compatibility

Protocol-v1 artifacts used a top-level envelope in which the signature covered only `canonical(body)`.

V1 remains verifiable according to its original semantics. In particular, top-level fields such as the v1 key reference and artifact creation timestamp were not part of the v1 signature scope.

A v1 artifact therefore remains permanently v1/legacy. It MUST NOT be rewritten or re-labeled as though those historical fields were originally signature-bound.

A later independently authenticated attestation may reference an exact v1 artifact digest and add new evidence, but it does not retroactively change the guarantee of the original v1 signature.

The preserved legacy schema is:

`spec/artifact-schema-v1.json`

---

## Security boundaries

Successful protocol-v2 artifact verification can establish, subject to the declared algorithms and supplied key material:

- that the canonical `protected` object matches the recorded digest;
- that the signature verifies under the supplied public key;
- that the supplied public key matches the fingerprint committed inside `protected`;
- that modification of signature-bound fields after sealing is detectable.

Artifact verification does not establish:

- that an asserted event actually occurred in the physical or external world;
- that event or sealing timestamps are independently accurate;
- that captured information was complete before sealing;
- that the originating AI system behaved correctly;
- fairness or absence of bias;
- legal or regulatory compliance;
- legal admissibility;
- the trustworthiness or authorization of a signer, operator, registry, or organization beyond the authenticated key evidence supplied to the verifier.

Signing-key protection, key distribution, status/revocation infrastructure, capture-policy correctness, deployment integrity, and external trust anchors remain deployment responsibilities unless an applicable CEYO profile explicitly defines them.

---

## Protocol focus

CEYO defines evidence construction and independent verification mechanics. It does not define AI model behavior, make governance decisions, or replace institutional judgment.
