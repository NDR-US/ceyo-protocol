# CEYO Protocol — Developer Documentation

This directory contains developer-facing guides for integrating with and
operating the CEYO Protocol.

For the formal protocol specification, schemas, and architecture, see
[`/spec`](../spec/README.md).

## Guides

| Document | Description |
|----------|-------------|
| [developer-integration.md](developer-integration.md) | SDK integration guide for Python developers |
| [implementation-guide.md](implementation-guide.md) | Integration patterns (Sidecar, Gateway, Wrapper) |
| [key-management.md](key-management.md) | Key lifecycle, rotation, and revocation |
| [verification-walkthrough.md](verification-walkthrough.md) | Step-by-step verification with code examples |
| [verifier.md](verifier.md) | Using the standalone `ceyo_verify` package |
| [example-workflow.md](example-workflow.md) | End-to-end worked example |

## Reference

| File | Description |
|------|-------------|
| [example-artifact.json](example-artifact.json) | Example sealed artifact envelope with all fields populated |

## Quick Start

```bash
pip install ceyo

# Generate keys
ceyo keygen

# Seal a record
ceyo seal record.json --key ceyo_private.pem

# Verify a sealed artifact
ceyo verify artifact.sealed.json ceyo_private.pub.pem

# Transparency log
ceyo log list ceyo_log.db
ceyo log checkpoint ceyo_log.db --key ceyo_private.pem --output checkpoint.json
ceyo log prove ceyo_log.db <artifact_id> --output proof.json
ceyo log verify-proof proof.json --checkpoint checkpoint.json --pubkey ceyo_private.pub.pem
```
