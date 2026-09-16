# CEYO

Neutral evidentiary infrastructure for AI systems.

CEYO defines a portable artifact format and independent verification procedure for policy-scoped records produced around AI-supported operations. The protocol is designed so an operator can retain control of its models, raw data, and signing keys while another party can independently verify defined integrity and declared-provenance properties of a sealed record.

CEYO does **not** determine whether an AI output was correct, fair, lawful, compliant, complete, or factually true. It verifies properties of the evidence that was actually captured and sealed.

## Current protocol

Protocol v2 uses a three-part envelope:

```text
artifact
├── protected     # signature-bound artifact identity, suites, key reference, time claim, body
├── integrity     # SHA-256 digest + ECDSA-P256 signature over canonical(protected)
└── receipts[]    # optional external evidence; validated separately by trust profiles
```

The central v2 invariant is:

> Artifact-level validity and trust inputs must come from authenticated `protected` fields or independently authenticated external evidence. Unauthenticated envelope metadata must not influence trust status.

Protocol-v1 artifacts remain verifiable under their original, narrower guarantee. V1 signed only `canonical(body)`; its top-level key reference and creation timestamp were not signature-bound. V1 therefore remains permanently legacy rather than being retroactively represented as v2.

## What v2 verifies

A conforming v2 verifier can check that:

- the canonical `protected` object matches the recorded SHA-256 digest;
- the ECDSA P-256 signature verifies under the supplied public key;
- the supplied public key matches the fingerprint committed inside `protected.key_reference`;
- changes to signature-bound fields after sealing are detectable.

The signed scope includes the artifact ID, protocol version, body-schema reference, signer-asserted sealing time, canonicalization suite, signing suite, key reference, and policy-scoped body.

These checks establish cryptographic validity under the protocol. They do not, by themselves, establish institutional trust, legal effect, objective truth, or completeness of the underlying event record.

## Time semantics

`protected.sealed_at` is a **signed signer assertion**. Signing it prevents later editing, but it does not prove that the signer's clock was accurate or prevent a malicious signer from backdating at signing time.

Higher-assurance historical trust evaluation requires separately authenticated external time evidence, such as an accepted transparency receipt/checkpoint profile, RFC 3161 timestamp authority, or witness mechanism. External-time assurance is intentionally separate from basic artifact validity.

## Validity and trust

CEYO keeps these concepts separate:

```text
artifact validity
    = schema/protocol processing
    + digest verification
    + signature verification
    + protected key-fingerprint consistency

trust / evidentiary status
    = artifact validity
    + signer/key authorization or trust state
    + revocation/status evidence
    + required receipts or external anchors
    + verification-profile policy
```

A cryptographically valid artifact may therefore remain insufficient for a particular trust profile.

## Architecture

```text
AI-supported operation
        ↓
Policy-scoped capture
        ↓
Build protected object
        ↓
RFC 8785 canonicalization
        ↓
SHA-256 digest
        ↓
ECDSA-P256 signature
        ↓
CEYO artifact
        ↓
Independent verification
        ↓
Optional external receipts / transparency evidence
```

CEYO does not require custody of an operator's private signing keys or raw proprietary data.

## Canonicalization

Protocol v2 uses RFC 8785 JSON Canonicalization Scheme (JCS) for the complete `protected` object.

The canonicalization declaration is itself inside `protected` and therefore signature-bound. A protocol-v2 producer must not silently substitute another serializer if RFC 8785 is unavailable; failure to perform the declared canonicalization is an error.

Legacy protocol-v1 artifacts remain verifiable according to their historical declarations and scope.

## Repository layout

```text
ceyo-protocol/
├── spec/                 # canonical protocol specification and JSON schemas
├── ceyo/                 # Python reference implementation
├── ceyo_verify/          # independent verifier; no ceyo SDK dependency
├── docs/                 # developer-facing integration and verification guides
├── tests/                # protocol/reference implementation tests
├── example_artifact/     # sample input and artifact material
└── .github/workflows/    # CI
```

Important specification files:

- `spec/protocol-specification.md`
- `spec/artifact-schema.json` — current protocol-v2 envelope
- `spec/artifact-schema-v1.json` — preserved legacy-v1 envelope
- `spec/security-model.md`
- `spec/threat-model.md`
- `spec/transparency-log.md`

## Installation

```bash
pip install .
```

For development:

```bash
pip install -e ".[dev]"
```

## CLI

Generate a key pair:

```bash
ceyo keygen --out-private ceyo_private.pem --out-public ceyo_public.pem
```

Seal a record as protocol v2:

```bash
ceyo seal example_artifact/sample_record.json --key ceyo_private.pem -o sealed_artifact.json
```

Verify it:

```bash
ceyo verify sealed_artifact.json ceyo_public.pem
```

Standalone verification:

```bash
python -m ceyo_verify sealed_artifact.json ceyo_public.pem
```

## Python

```python
from ceyo.keys import LocalKeyProvider
from ceyo.seal import seal_body
from ceyo.verify import verify_artifact

keys = LocalKeyProvider("ceyo_private.pem", "ceyo_public.pem")

body = {
    "event": {
        "event_id": "evt_001",
        "type": "classification",
        "occurred_at": "2026-09-15T12:00:00Z",
    },
    "policy": {
        "id": "capture-policy",
        "version": "1.0",
    },
}

artifact = seal_body(body, keys)
result = verify_artifact(artifact, keys.get_public_key_pem())
assert result.ok
```

## Transparency prototype

The repository contains a Merkle-tree transparency prototype with signed checkpoints and inclusion proofs. It provides independently checkable membership evidence for logged artifact subjects relative to a supplied tree root/checkpoint.

Its current guarantees are deliberately narrower than a globally witnessed append-only transparency service. Inclusion proofs and signed checkpoints do not, by themselves, prevent a log operator from maintaining inconsistent views, replaying an old valid checkpoint, or rolling back local state. Stronger global consistency requires mechanisms such as consistency proofs, witnesses, monitors, gossip, or independently anchored checkpoints.

For protocol v2, the log commits to the stable `{protected, integrity}` artifact core so later receipt attachment does not change the logged subject.

See `spec/transparency-log.md`.

## Security boundaries

CEYO artifact verification does not establish:

- objective truth of the underlying event;
- completeness of pre-seal capture;
- correctness of an AI output;
- fairness or absence of bias;
- regulatory compliance;
- legal admissibility;
- independently trusted time unless an accepted external-time proof is validated;
- organizational identity or authorization merely from possession of a cryptographic key.

See `spec/security-model.md` and `spec/threat-model.md` for the full boundary.

## Status

CEYO is an early-stage protocol and reference implementation undergoing protocol consolidation and security hardening. It should not currently be represented as production-certified security infrastructure.

Independent cryptography, security, and protocol review is welcome.

## License

All Rights Reserved. See `LICENSE`.
