# CEYO Verification Walkthrough

Version: 2.0-draft

## Overview

Protocol-v2 artifact verification checks the cryptographic integrity of the complete signed `protected` object. It does not, by itself, decide whether the signer should be trusted, whether a key was historically valid, whether a timestamp is independently accurate, or whether the underlying AI event was correct.

CEYO therefore distinguishes:

```text
artifact validity
    = schema/protocol processing
    + digest verification
    + signature verification
    + protected key-fingerprint consistency

trust / evidentiary status
    = artifact validity
    + signer/key authorization or trust state
    + status/revocation evidence
    + accepted receipts/anchors
    + profile policy
```

## Protocol-v2 envelope

```text
artifact
├── protected
│   ├── product
│   ├── protocol_version
│   ├── artifact_schema
│   ├── artifact_id
│   ├── sealed_at
│   ├── canonicalization_suite
│   ├── signing_suite
│   ├── key_reference
│   └── body
├── integrity
│   ├── digest
│   └── signature
└── receipts[]
```

The artifact signature authenticates `canonical(protected)`. `receipts` is intentionally outside that signature.

## Step 1 — Validate structure and version

Validate the envelope against `spec/artifact-schema.json`.

At minimum confirm:

- top-level fields are `protected`, `integrity`, and `receipts`;
- `protected.product == "CEYO"`;
- `protected.protocol_version == "2.0"`;
- the declared body schema is supported;
- artifact ID and timestamp formats are valid;
- `protected.canonicalization_suite` declares RFC 8785 / version 1.0;
- the signing suite is supported;
- the key-reference structure is valid;
- integrity coverage descriptors match the protocol-v2 scope.

A verifier should fail closed on an unsupported protocol version or algorithm suite.

## Step 2 — Load and validate the public key

Load the public verification key and confirm it is ECDSA P-256 / secp256r1.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

public_key = serialization.load_pem_public_key(public_key_pem)
assert isinstance(public_key, ec.EllipticCurvePublicKey)
assert isinstance(public_key.curve, ec.SECP256R1)
```

## Step 3 — Canonicalize `protected`

Protocol v2 uses RFC 8785 JSON Canonicalization Scheme (JCS) for the complete `protected` object.

```python
import rfc8785

protected = artifact["protected"]
canonical_bytes = rfc8785.dumps(protected)
```

A protocol-v2 verifier must not silently substitute a different serializer if RFC 8785 is unavailable. That condition is a verification error.

Historical protocol-v1 artifacts may retain earlier canonicalization declarations and are handled by the v1 compatibility path, not by changing v2 semantics.

## Step 4 — Recompute the digest

```python
import hashlib

actual_digest = hashlib.sha256(canonical_bytes).digest()
```

Decode and compare against:

`artifact["integrity"]["digest"]["value_b64u"]`

Use a timing-safe comparison where practical.

A mismatch means the presented `protected` object is not the object committed to by the recorded digest.

## Step 5 — Verify the signature

Protocol v2 currently uses ECDSA P-256 with prehashed SHA-256 and DER signature encoding.

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

signature = decode_b64u(
    artifact["integrity"]["signature"]["value_b64u"]
)

try:
    public_key.verify(
        signature,
        actual_digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
except InvalidSignature:
    raise ValueError("artifact signature invalid")
```

A valid signature demonstrates that the digest verifies under the supplied public key. It does not, by itself, establish the organizational identity or authorization of that key.

## Step 6 — Verify the protected key fingerprint

Protocol v2 commits to the key reference inside the signed scope.

Compute SHA-256 over DER-encoded SubjectPublicKeyInfo and compare it to:

`protected.key_reference.public_key_fingerprint.value_b64u`

```python
from cryptography.hazmat.primitives import serialization

pub_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
actual_fingerprint = hashlib.sha256(pub_der).digest()
```

A match establishes that the supplied public key is the key whose fingerprint was committed to by the signed artifact.

It does not prove that the key is trusted for a specific organization or role. That is a trust-anchor/profile decision.

## Step 7 — Interpret time correctly

Two time-related values appear in the protected evidence:

- `protected.body.event.occurred_at` — source-asserted event time;
- `protected.sealed_at` — signer-asserted sealing time.

Because `sealed_at` is signed, later editing is detectable. It is still not independently trusted time: a malicious signer could choose a false value when creating the artifact.

Do not use `sealed_at` as a strong historical-revocation time basis unless the applicable profile accepts signer-asserted time. High-assurance profiles should validate accepted external time evidence.

## Step 8 — Evaluate policy context separately

If the body includes `policy`, a higher-level verifier may compare its signed ID, version, and digest against an expected policy.

That comparison is a trust/profile check, not part of basic signature validity.

A `policy.digest` is useful because it can commit the artifact to an exact policy representation rather than only a reusable human-readable version label. The meaning of the digest depends on the explicitly defined `covers` representation.

## Step 9 — Evaluate receipts only when validated

`receipts` is outside the artifact signature.

Appending, removing, or changing a receipt does not change the basic artifact signature result.

A trust profile may rely on a receipt only after validating:

- a recognized receipt type/version;
- subject binding to the correct artifact/core digest;
- issuer/key identity;
- cryptographic proof/signature;
- profile-specific semantics such as acceptable timestamp authority or transparency service.

An arbitrary object in `receipts[]` has no trust value merely because it is present.

## Step 10 — Evaluate revocation/status and trust profile

After artifact validity is established, the verifier may evaluate:

- whether the key was authorized;
- whether it was revoked/suspended;
- the relevant historical time basis;
- required transparency or timestamp evidence;
- capture/disclosure-policy requirements.

A profile that requires unavailable evidence should report trust as indeterminate/unsatisfied rather than silently converting missing evidence into trusted status.

## Built-in verifier

CLI:

```bash
ceyo verify sealed_artifact.json public_key.pem
```

Python:

```python
from ceyo.verify import verify_artifact

result = verify_artifact(artifact, public_key_pem)

if result.ok:
    print("Artifact cryptographic verification PASSED")
else:
    print("Artifact cryptographic verification FAILED")
    for message in result.failed:
        print(message)
```

## Independent verifier

The repository also contains `ceyo_verify`, which does not import the CEYO SDK:

```bash
python -m ceyo_verify sealed_artifact.json public_key.pem
```

This separation makes it possible to compare verification behavior without depending on the producer SDK.

## Legacy-v1 verification

Protocol v1 used a different envelope and signed only `canonical(body)`.

Current verification tooling can recognize v1 and verify the signature according to those original semantics. A successful v1 verification must not be interpreted as proving that the v1 top-level key reference or creation timestamp was historically signature-bound.

V1 stays legacy permanently.

## Mutation expectations for v2

After sealing a valid v2 artifact:

| Mutation | Expected basic artifact result |
|---|---|
| change `protected.artifact_id` | FAIL |
| change `protected.sealed_at` | FAIL |
| change `protected.protocol_version` | FAIL |
| change `protected.artifact_schema` | FAIL |
| change `protected.canonicalization_suite` | FAIL |
| change `protected.signing_suite` | FAIL |
| change `protected.key_reference` | FAIL |
| change `protected.body` | FAIL |
| delete a required protected field | FAIL |
| append a receipt | artifact signature remains valid |
| alter a receipt | artifact signature remains valid; receipt trust validation must fail if its own proof no longer validates |

## What a passing artifact verification does not prove

A passing basic v2 verification does not establish:

- objective truth of the event;
- completeness of capture;
- independent accuracy of timestamps;
- correctness or fairness of an AI decision;
- legal/regulatory compliance;
- legal admissibility;
- historical key trust without status/revocation evidence;
- external receipt validity unless those receipts are separately checked.
