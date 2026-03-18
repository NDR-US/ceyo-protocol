# CEYO Verification Walkthrough

**Version:** 1.0
**Last Updated:** 2026-03-11

---

## Overview

This document walks through the complete CEYO artifact verification process step by step. Verification confirms that a sealed artifact has not been tampered with and was signed by the holder of the declared key.

Verification requires only:
- A sealed artifact envelope (JSON file)
- The public verification key (PEM file)
- Standard cryptographic libraries

No access to the AI system, the CEYO SDK, or any proprietary infrastructure is needed.

---

## Prerequisites

Install the CEYO SDK (for the built-in verifier) or implement verification independently using any language with SHA-256, ECDSA P-256, and RFC 8785 support.

```bash
pip install ceyo
```

---

## Verification Pipeline

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  Sealed Artifact (JSON)     Public Key (PEM)                 │
│         │                        │                           │
│         ▼                        │                           │
│  Step 1: Schema Validation       │                           │
│         │                        │                           │
│         ▼                        ▼                           │
│  Step 2: Load Public Key ◄───────┘                           │
│         │                                                    │
│         ▼                                                    │
│  Step 3: Canonicalize Body (RFC 8785)                        │
│         │                                                    │
│         ▼                                                    │
│  Step 4: Recompute SHA-256 Hash                              │
│         │                                                    │
│         ├──► Compare to integrity.hash.value_b64u            │
│         │    └── Mismatch? ──► FAIL: Hash mismatch           │
│         │                                                    │
│         ▼                                                    │
│  Step 5: Verify ECDSA Signature                              │
│         │                                                    │
│         ├──► Validate sig against recomputed hash            │
│         │    └── Invalid? ──► FAIL: Signature invalid         │
│         │                                                    │
│         ▼                                                    │
│  Step 6: Verify Key Fingerprint                              │
│         │                                                    │
│         ├──► SHA-256(DER(public_key)) vs fingerprint         │
│         │    └── Mismatch? ──► FAIL: Fingerprint mismatch    │
│         │                                                    │
│         ▼                                                    │
│  ✓ VERIFICATION PASSED                                       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Step 1: Load and Validate the Artifact Envelope

Load the sealed artifact JSON and validate its structure against the CEYO envelope schema.

**What to check:**
- All required top-level fields are present: `product`, `envelope_version`, `artifact_schema`, `artifact_id`, `created_at`, `body`, `canonicalization`, `integrity`, `key_reference`
- `product` equals `"CEYO"`
- `artifact_id` matches pattern `^ceyo_art_`
- `integrity.hash.alg` equals `"SHA-256"`
- `integrity.sig.alg` equals `"ECDSA-P256-SHA256"`
- `integrity.sig.format` equals `"DER"`
- `canonicalization.scheme` equals `"RFC8785"`
- `canonicalization.scope` equals `"body"`

**If validation fails:** Stop. The artifact does not conform to the CEYO protocol.

```python
import json
from ceyo.schema import validate_envelope

with open("sealed_artifact.json") as f:
    artifact = json.load(f)

errors = validate_envelope(artifact)
if errors:
    print("Schema validation FAILED:")
    for e in errors:
        print(f"  - {e}")
else:
    print("PASS: Schema valid")
```

---

## Step 2: Load the Public Verification Key

Load the PEM-encoded public key. The key must be an ECDSA P-256 (secp256r1) public key.

```python
from cryptography.hazmat.primitives import serialization

with open("public_key.pem", "rb") as f:
    public_key_pem = f.read()

public_key = serialization.load_pem_public_key(public_key_pem)
```

**If the key cannot be loaded:** Stop. Verification requires a valid public key.

**If the key is not ECDSA P-256:** Stop. CEYO requires ECDSA with the NIST P-256 curve.

---

## Step 3: Canonicalize the Artifact Body

Extract the `body` field from the artifact and canonicalize it using RFC 8785 (JSON Canonicalization Scheme).

```python
import rfc8785

body = artifact["body"]
canonical_bytes = rfc8785.dumps(body)
```

**What RFC 8785 does:**
- Sorts object keys lexicographically by Unicode code point
- Removes all whitespace between tokens
- Normalizes number representations
- Produces deterministic UTF-8 byte output

**Why this matters:** The hash was computed during sealing over the canonicalized body. To verify the hash, the verifier must produce the exact same canonical byte sequence.

---

## Step 4: Recompute the SHA-256 Hash

Compute SHA-256 over the canonical byte sequence and compare the result to the hash stored in the artifact.

```python
import hashlib
from ceyo.crypto import b64u_decode

# Recompute hash
actual_hash = hashlib.sha256(canonical_bytes).digest()

# Decode stored hash
stored_hash = b64u_decode(artifact["integrity"]["hash"]["value_b64u"])

# Compare
if actual_hash == stored_hash:
    print("PASS: Hash matches")
else:
    print("FAIL: Hash mismatch")
    print("  The artifact body has been modified since sealing.")
```

**If the hashes do not match:** Stop. The artifact body has been tampered with or the canonicalization produced different output. The artifact is invalid.

**What a hash match proves:** The body content is exactly what was present when the artifact was sealed.

---

## Step 5: Verify the ECDSA Signature

Decode the DER-encoded signature and verify it against the recomputed hash using the public key.

```python
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

sig_bytes = b64u_decode(artifact["integrity"]["sig"]["value_b64u"])

try:
    public_key.verify(
        sig_bytes,
        actual_hash,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print("PASS: Signature valid")
except InvalidSignature:
    print("FAIL: Signature invalid")
    print("  The signature does not match the hash and public key.")
```

**Note on prehashed mode:** The signature was computed over the raw SHA-256 digest (not over the canonical bytes directly). The verification must use prehashed mode to match.

**If the signature is invalid:** Stop. Either the artifact was tampered with, or it was signed by a different key. The artifact is invalid.

**What a valid signature proves:** The artifact was sealed by the holder of the private key corresponding to this public key.

---

## Step 6: Verify the Key Fingerprint

Compute the SHA-256 fingerprint of the public key and compare it to the fingerprint declared in the artifact.

```python
# Compute fingerprint of the loaded public key
pub_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
actual_fingerprint = hashlib.sha256(pub_der).digest()

# Decode stored fingerprint
stored_fingerprint = b64u_decode(
    artifact["key_reference"]["public_key_fingerprint"]["value_b64u"]
)

# Compare
if actual_fingerprint == stored_fingerprint:
    print("PASS: Key fingerprint matches")
else:
    print("FAIL: Key fingerprint mismatch")
    print("  The public key does not match the key declared in the artifact.")
```

**What a fingerprint match proves:** The public key used for verification is the same key that was declared when the artifact was sealed.

---

## Step 7: Policy Alignment Check (Optional)

If the artifact contains a `body.policy` object, verify that the declared policy identifier and version match the expected capture policy for the system being audited.

```python
policy = artifact["body"].get("policy")
if policy:
    expected_policy_id = "content-moderation-v2"
    expected_policy_version = "2.1"

    if policy.get("id") == expected_policy_id and policy.get("version") == expected_policy_version:
        print("PASS: Policy alignment confirmed")
    else:
        print(f"WARNING: Policy mismatch — expected {expected_policy_id} v{expected_policy_version}, "
              f"got {policy.get('id')} v{policy.get('version')}")
```

**What policy alignment confirms:** The artifact was generated under the expected capture policy. This is a semantic check — it does not affect cryptographic validity but is important for audit completeness.

**Note:** Policy alignment is an application-level check. The CEYO protocol defines the field structure; enforcement of policy matching is the responsibility of the verification context.

---

## Running the Built-In Verifier

### CLI

```bash
ceyo verify example_artifact/sealed_artifact.json --key example_artifact/public_key.pem
```

### Standalone Verifier Script

```bash
python3 tools/ceyo_verify.py example_artifact/sealed_artifact.json example_artifact/public_key.pem
```

### SDK

```python
from ceyo.verify import verify_artifact

with open("example_artifact/sealed_artifact.json") as f:
    artifact = json.load(f)

with open("example_artifact/public_key.pem", "rb") as f:
    pub_key_pem = f.read()

result = verify_artifact(artifact, pub_key_pem)

if result.ok:
    print("Verification PASSED")
    for msg in result.passed:
        print(f"  ✓ {msg}")
else:
    print("Verification FAILED")
    for msg in result.failed:
        print(f"  ✗ {msg}")
```

### Expected Output (Passing Verification)

```
PASS: Schema valid
PASS: Hash matches
PASS: Signature valid
PASS: Key fingerprint matches

Verification PASSED
```

---

## Implementing Verification Independently

CEYO verification can be implemented in any language. No CEYO-specific libraries are required.

**Required components:**
1. JSON parser
2. RFC 8785 canonicalization (or equivalent deterministic JSON serialization)
3. SHA-256 hash function
4. ECDSA P-256 signature verification
5. Base64url decoder
6. PEM public key loader

**Pseudocode:**

```
function verify(artifact_json, public_key_pem):
    artifact = parse_json(artifact_json)
    public_key = load_pem_public_key(public_key_pem)

    // Canonicalize
    canonical = rfc8785_canonicalize(artifact.body)

    // Hash
    hash = sha256(canonical)
    stored_hash = base64url_decode(artifact.integrity.hash.value_b64u)
    if hash != stored_hash:
        return FAIL("hash mismatch")

    // Signature
    signature = base64url_decode(artifact.integrity.sig.value_b64u)
    if not ecdsa_p256_verify(public_key, signature, hash, prehashed=true):
        return FAIL("signature invalid")

    // Fingerprint
    key_der = encode_spki_der(public_key)
    fingerprint = sha256(key_der)
    stored_fp = base64url_decode(artifact.key_reference.public_key_fingerprint.value_b64u)
    if fingerprint != stored_fp:
        return FAIL("fingerprint mismatch")

    return PASS
```
