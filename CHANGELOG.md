# Changelog

## [Unreleased] — transparency log + protocol structure

### Added

- **Transparency log** (`ceyo/transparency_log.py`) — `TransparencyLog` class backed by SQLite. Append-only Merkle tree log using RFC 6962 hash-prefix domain separation (`0x00` for leaves, `0x01` for internal nodes). `append()` records each artifact's hash as a Merkle leaf. `checkpoint()` signs the current root with ECDSA-P256-SHA256. `prove_inclusion()` generates a sibling-path inclusion proof.
- **Standalone inclusion-proof verifier** (`ceyo_verify/transparency.py`) — `verify_inclusion_proof()` recomputes the Merkle root from the sibling path, verifies the checkpoint signature, and optionally binds the proof to the original artifact envelope. Zero `ceyo` SDK dependency.
- **`CeyoClient.log`** — optional `TransparencyLog` parameter; `seal()` auto-appends each artifact when `persist=True`.
- **`ceyo log` CLI subcommands** — `list`, `checkpoint`, `prove`, `verify-proof`.
- **`ceyo_verify.verify_inclusion_proof`** — re-exported from `ceyo_verify/__init__.py`.
- **`ceyo.TransparencyLog`** — re-exported from `ceyo/__init__.py`.

### Specification

- **`spec/pipeline.md`** — full end-to-end pipeline specification: Input/Output → Canonicalization → Hash+Signature → Artifact Envelope → Transparency Log → Signed Checkpoint → Standalone Verification → Inclusion Proof Validation.
- **`spec/transparency-log.md`** — formal transparency log specification: log entries, Merkle tree construction, checkpoint structure and signing, inclusion proof generation and verification algorithms, security properties.
- **`spec/checkpoint.schema.json`** — JSON Schema (Draft 2020-12) for signed log checkpoints.
- **`spec/inclusion-proof.schema.json`** — JSON Schema (Draft 2020-12) for Merkle inclusion proofs.
- **`spec/README.md`** — specification index.

### Repository Structure

- Protocol-level documents moved from `docs/` to `spec/`: `specification.md`, `protocol-specification.md`, `architecture.md`, `architecture-diagram.md`, `artifact-lifecycle.md`, `design-principles.md`, `glossary.md`, `governance.md`, `security-model.md`, `threat-model.md`, `threat-model-diagram.md`, `verification-protocol.md`.
- `docs/` now contains only developer-facing guides: integration, key management, verification walkthrough, example workflow.
- `docs/artifact-schema.json` renamed to `docs/example-artifact.json` (it is an example artifact, not a schema).
- `docs/artifact-envelope.schema.json` removed (duplicate of `spec/artifact-schema.json`).
- `docs/README.md` added as a developer docs index.

### Tests

- 45 new tests: `TestMerkleTree`, `TestTransparencyLog`, `TestInclusionProofVerification`, `TestTransparencyLogClientIntegration`. Total: 149 tests.

---

## [Unreleased] — hardening pass

### Added

- **`ceyo_verify` standalone package** (`ceyo_verify/`) — a self-contained artifact verifier that depends only on `cryptography` and `rfc8785`, with no import from `ceyo`. Fulfills the independent-verifier requirement of the protocol. Runnable as `python -m ceyo_verify <artifact.json> <pubkey.pem>`.
- **`ceyo keygen` CLI command** — generates an ECDSA P-256 key pair and writes both PEM files. Supports `--out-private`, `--out-public`, and `--force` flags.
- **`ceyo store inspect` CLI command** — prints a single artifact from a store database by `artifact_id`.
- **Negative test suite** (`TestNegativeCases`) — explicit tests for: wrong product value, missing body, bad `artifact_id` pattern, bad `created_at` datetime, wrong hash algorithm, wrong signature algorithm, extra top-level field, missing event fields, bad `occurred_at`, tampered body, tampered hash value, corrupt signature bytes, wrong public key, and fingerprint mismatch.
- **Round-trip test suite** (`TestRoundTrip`) — seal → `store.append` → `store.get_by_seq` → `verify_artifact`, 20-entry chain integrity check, convenience `seal()` round-trip, and cross-check that standalone verifier matches SDK verifier.
- **CLI smoke tests** (`TestCLI`) — subprocess tests for `keygen`, `seal`, `verify`, `store list`, `store inspect`, `store verify-chain`, and `python -m ceyo_verify`.

### Hardened

- **Schema validation** — added ISO 8601 datetime pattern check (`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}...`) for `created_at` and `event.occurred_at`. Added base64url character pattern (`^[A-Za-z0-9_-]+$`) for all `value_b64u` fields in `integrity.hash`, `integrity.sig`, and `key_reference.public_key_fingerprint`.
- **CI workflow** — removed broken reference to deleted `seal_artifact.py`; demo job now uses `ceyo keygen` + `ceyo seal` + dual verification (`ceyo verify` and `python -m ceyo_verify`). Coverage discovery updated to `unittest discover`.
- **Coverage source** — extended to include `ceyo_verify` package.

### Fixed

- `seal` CLI output now also prints the `artifact_id` alongside the output file path and public key path.
- `examples/basic_usage.py` — removed `sys.path` hack; now imports cleanly after `pip install -e .`. Added `example_standalone_verify()` demonstrating `ceyo_verify` independence.
- README rewritten for external reviewer: accurate install instructions, full CLI reference table, artifact envelope structure, runtime-generated file table, package boundary explanation.
- `pyproject.toml` — added `pytest` to dev dependencies; added `[tool.hatch.build.targets.wheel] packages` to explicitly include both `ceyo` and `ceyo_verify`.
