# CEYO Developer Integration Guide

Version: 2.0-draft

## 1. Purpose

This guide describes the current public reference implementation for producing protocol-v2 CEYO artifacts.

CEYO can be integrated in-process, at a gateway, or as a sidecar around an AI-supported workflow. The integration point determines what CEYO can observe; the protocol itself does not require access to model weights or raw proprietary internals.

## 2. Install

```bash
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

The reference implementation requires Python 3.10+ and uses `cryptography` and `rfc8785`.

## 3. Choose a key provider

For persistent local development:

```python
from ceyo.keys import LocalKeyProvider

keys = LocalKeyProvider(
    "keys/ceyo_private.pem",
    "keys/ceyo_public.pem",
)
```

The public reference implementation also contains an in-memory provider for testing.

Production deployments should use key-management controls appropriate to their assurance requirements. CEYO's protocol does not require CEYO itself to possess operator private keys; hardware-backed or managed signing can be implemented behind a compatible provider boundary.

Protocol v2 currently requires an ECDSA P-256 / secp256r1 signing key.

## 4. Construct a policy-scoped body

The body should contain only the evidence authorized by the capture policy.

```python
body = {
    "event": {
        "event_id": "evt_001",
        "type": "classification",
        "occurred_at": "2026-09-15T12:00:00Z",
        "request_id": "req_001",
    },
    "policy": {
        "id": "capture-policy",
        "version": "1.0",
    },
    "capture": {
        "input_ref_hash": {
            "alg": "SHA-256",
            "value_b64u": "<base64url digest>",
            "covers": "policy_scoped_input_representation",
        },
        "output_ref_hash": {
            "alg": "SHA-256",
            "value_b64u": "<base64url digest>",
            "covers": "policy_scoped_output_representation",
        },
    },
    "disclosure_policy": {
        "tier": "internal",
        "policy_id": "disclosure-policy",
        "policy_version": "1.0",
    },
    "environment": {
        "deployment_id": "prod-a",
        "model_ref": "classifier-v3",
    },
}
```

The example uses hashes/references rather than raw input/output material. That is a deployment choice and does not by itself prove privacy; operators remain responsible for deciding what their capture policy permits.

## 5. Seal a v2 artifact

```python
from ceyo.seal import seal_body

artifact = seal_body(body, keys)
```

`seal_body()` performs the current v2 process:

1. validate the body;
2. create the `protected` object;
3. place the artifact ID, `sealed_at`, protocol/body-schema versions, algorithm suites, key reference, and body inside `protected`;
4. canonicalize the complete `protected` object using RFC 8785;
5. compute SHA-256 over those canonical bytes;
6. sign the digest with ECDSA P-256 using prehashed SHA-256;
7. return `{protected, integrity, receipts}`.

Protocol v2 does not silently substitute another serializer when RFC 8785 is unavailable.

`sealed_at` is signer-asserted time. It is protected against later editing but is not an independently trusted timestamp.

## 6. Convenience event builder

The lower-level `ceyo.seal.seal()` helper can construct common event bodies:

```python
from ceyo.seal import seal

artifact = seal(
    event_id="evt_001",
    event_type="classification",
    occurred_at="2026-09-15T12:00:00Z",
    request_id="req_001",
    policy_id="capture-policy",
    policy_version="1.0",
    key_provider=keys,
)
```

For workflows with more detailed policy, capture, disclosure, or environment structures, building the body explicitly and calling `seal_body()` is clearer.

## 7. High-level client

```python
from ceyo.client import CeyoClient

client = CeyoClient(key_provider=keys)
artifact = client.seal(body, persist=False)
```

If no key provider is supplied, the reference client uses an ephemeral in-memory key and emits a warning. That mode is for development/testing; artifacts cannot be re-verified after the process exits unless the public key is retained separately.

## 8. Persist to the local reference store

```python
from ceyo.store import ArtifactStore

with ArtifactStore("artifacts.db") as store:
    client = CeyoClient(key_provider=keys, store=store)
    artifact = client.seal(body)
```

The local SQLite store records full artifact envelopes and maintains a local hash chain.

This is tamper-evident local storage, not a globally witnessed append-only ledger. Rollback or tail truncation can require an external anchor to detect reliably.

## 9. Verify

```python
from ceyo.verify import verify_artifact

result = verify_artifact(
    artifact,
    keys.get_public_key_pem(),
)

if not result.ok:
    raise RuntimeError(result.failed)
```

The SDK verifier checks protocol/schema support, RFC 8785 canonicalization, the digest/signature over `protected`, P-256 key type, and the protected public-key fingerprint.

Independent verification is also available:

```bash
python -m ceyo_verify artifact.json ceyo_public.pem
```

The `ceyo_verify` package intentionally does not import the CEYO SDK.

## 10. Trace decorator

The reference client includes a convenience decorator:

```python
from ceyo.client import CeyoClient

client = CeyoClient(key_provider=keys)

@client.trace(event_type="classification", policy_id="capture-policy")
def classify(text: str) -> str:
    return model.predict(text)
```

The decorator hashes Python representations of inputs and outputs rather than storing them directly, constructs a body, and seals it after the wrapped function returns.

That implementation is a development/reference convenience. Production capture semantics should use an explicitly defined representation and policy rather than relying on language-specific `repr()` output as a cross-system evidence format.

## 11. Disclosure policy

`body.disclosure_policy` is a sealing-time commitment. It should describe the disclosure policy/tier that applied when the artifact was sealed.

It is not a mutable field recording every later disclosure.

If a later disclosure needs evidentiary value, represent it as a separate independently signed/attested record that binds at least:

- artifact ID;
- protected/artifact subject digest;
- applicable disclosure policy/tier;
- disclosure time;
- disclosing authority.

## 12. Receipts

`artifact["receipts"]` is outside the original artifact signature.

This allows later evidence to be attached without re-signing `protected`.

A receipt must not be trusted simply because it exists in the array. A verification profile must validate the receipt's recognized type/version, subject binding, issuer/key, and proof.

Typed receipt schemas are separate from basic artifact validity and should be versioned explicitly.

## 13. Transparency log

A reference Merkle-tree transparency prototype is available:

```python
from ceyo.transparency_log import TransparencyLog

with TransparencyLog("ceyo_log.db", keys) as log:
    entry = log.append(artifact)
    checkpoint = log.checkpoint()
    proof = log.prove_inclusion(
        artifact["protected"]["artifact_id"]
    )
```

For protocol v2, the transparency subject is the stable `{protected, integrity}` core; `receipts` is excluded so later receipt attachment does not alter an existing proof subject.

The prototype can provide membership evidence relative to a signed checkpoint. It should not be treated as globally consistent, globally append-only, fresh, or independently time-trusted solely because a checkpoint is signed. Stronger deployments need additional consistency, witness, freshness, and/or trusted-time mechanisms.

## 14. Deployment patterns

### In-process

The application calls the CEYO reference implementation directly. This is simple but shares the application's trust boundary.

### Sidecar

A separate process receives explicitly scoped event material and produces artifacts. This can improve operational isolation.

### Gateway

A gateway/proxy observes requests and responses at an infrastructure boundary and applies a defined capture policy before sealing evidence.

### Restricted / sovereign deployment

The same artifact format can be produced inside a customer-controlled VPC, on-premises environment, government cloud, or restricted network. Raw data and signing keys do not need to leave that boundary for an outside verifier to check a later artifact.

## 15. Failure behavior

Failure behavior is a deployment policy, not a universal CEYO protocol rule.

A deployment may choose:

- **fail-open evidence production** — application/inference continues when evidence generation fails, accepting evidence gaps;
- **fail-closed for specific workflows** — an operation does not complete without required evidence generation;
- **degraded/queued mode** — preserve local evidence material for later sealing where the threat model permits it.

The choice should be explicit because availability and evidentiary completeness trade off against each other.

## 16. Legacy v1

New integrations should generate v2 artifacts.

Legacy v1 verification remains available for historical artifacts. V1 signed only `canonical(body)` and therefore has a weaker metadata-integrity boundary. Do not re-seal a v1 artifact and represent the result as though its historical top-level metadata had always been signature-bound.
