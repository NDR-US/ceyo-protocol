# Changelog

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
