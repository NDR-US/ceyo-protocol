# CEYO Protocol — Developer Documentation

This directory contains developer-facing integration and verification guides for the current CEYO protocol-v2 reference implementation.

For normative protocol semantics, schemas, architecture, threat boundaries, and transparency behavior, see [`/spec`](../spec/README.md).

## Guides

| Document | Description |
|---|---|
| [developer-integration.md](developer-integration.md) | Current Python integration patterns, v2 sealing, storage, transparency, and deployment boundaries |
| [verification-walkthrough.md](verification-walkthrough.md) | Step-by-step v2 artifact verification, validity/trust separation, receipts, and legacy-v1 behavior |

## Canonical examples

The maintained example material lives in [`/example_artifact`](../example_artifact/):

- `sample_record.json` — sample policy-scoped input body;
- `example_envelope.json` — protocol-v2 sealed example artifact;
- `example_public_key.pem` — public key that verifies the committed v2 example.

## Quick start

Install the current repository/reference implementation:

```bash
pip install .
```

Generate keys:

```bash
ceyo keygen --out-private ceyo_private.pem --out-public ceyo_public.pem
```

Seal a record as protocol v2:

```bash
ceyo seal record.json --key ceyo_private.pem -o artifact.json
```

Verify with the SDK CLI:

```bash
ceyo verify artifact.json ceyo_public.pem
```

Verify independently of the `ceyo` SDK package:

```bash
python -m ceyo_verify artifact.json ceyo_public.pem
```

Reference transparency-log operations:

```bash
ceyo log list ceyo_log.db
ceyo log checkpoint ceyo_log.db --key ceyo_private.pem --output checkpoint.json
ceyo log prove ceyo_log.db <artifact_id> --output proof.json
ceyo log verify-proof proof.json --checkpoint checkpoint.json --pubkey ceyo_public.pem
```

The transparency component is a local Merkle inclusion-log prototype. A valid inclusion proof/checkpoint does not by itself establish checkpoint freshness, globally consistent append-only history, or independently trusted time. See [`spec/transparency-log.md`](../spec/transparency-log.md) for the exact guarantees and limits.
