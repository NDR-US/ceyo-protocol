# Changelog

## [Unreleased] — protocol-v2 protected artifact envelope

### Security boundary

- Introduced the protocol-v2 artifact shape: `{protected, integrity, receipts}`.
- Widened artifact signature scope from legacy `canonical(body)` to `canonical(protected)`.
- Moved artifact identity, protocol/body-schema versions, signer-asserted sealing time, canonicalization/signing suites, key reference/fingerprint, and policy-scoped body into the signature-bound `protected` object.
- Added explicit fail-closed dispatch for unsupported protocol versions and cryptographic suites.
- Preserved protocol-v1 verification under its original narrower scope rather than retroactively representing v1 metadata as signature-bound.

### Time and trust semantics

- Replaced the v2 artifact creation timestamp concept with signature-bound `protected.sealed_at`.
- Documented `sealed_at` as signer-asserted time: later editing is detectable, but signer backdating is not prevented by the artifact signature alone.
- Separated artifact cryptographic validity from higher-level trust/evidentiary status.
- Documented that historical revocation evaluation may require independently authenticated external-time evidence under higher-assurance profiles.

### Artifact schema and verification

- Added `spec/artifact-schema-v1.json` to preserve the legacy format.
- Updated `spec/artifact-schema.json` to the protocol-v2 envelope.
- Added body support for exact policy digests and structured sealing-time `disclosure_policy` commitments.
- Updated both `ceyo.verify` and the independent `ceyo_verify` package to recognize v2 and legacy-v1 artifacts.
- Bound `key_reference` into the v2 signed scope and retained public-key fingerprint verification.
- Kept the independently implemented `ceyo_verify` package free of imports from the `ceyo` SDK.

### Receipts

- Reserved `receipts[]` outside the original artifact signature so independently authenticated evidence can be attached later without rewriting the sealed artifact.
- Defined the security rule that arbitrary receipt presence has no trust meaning until a recognized receipt validator checks subject binding, issuer/key, proof, and profile requirements.
- Typed receipt schemas and the external-time profile remain separate hardening work.

### Transparency prototype

- Retained the local Merkle inclusion-log prototype with domain-separated SHA-256 leaf/node hashing, inclusion proofs, and signed checkpoints.
- Changed the protocol-v2 transparency subject to the stable artifact core `{protected, integrity}`, excluding appendable `receipts` so later receipt attachment does not invalidate or circularly redefine existing inclusion proofs.
- Fixed transparency canonicalization to RFC 8785 for both producer and independent proof verifier rather than allowing an undeclared fallback.
- Clarified that checkpoint timestamps are signer assertions and do not by themselves establish freshness or independently trusted time.
- Clarified that the current checkpoint `key_reference` is descriptive metadata outside the checkpoint signature; the trusted checkpoint key must come from an external trust path.
- Documented that the reference transparency component does not yet provide global append-only consistency, anti-equivocation, freshness, consistency proofs, witnesses, monitors, gossip, or rollback-resistant external anchoring.

### Local storage

- Retained SQLite artifact storage with local sequence/hash chaining.
- Documented that local chain verification can detect many stored-row modifications and middle deletions but cannot, by itself, guarantee detection of tail truncation or rollback to an earlier internally consistent state.

### Documentation

- Aligned README, protocol specification, pipeline, architecture, security model, threat model, governance, glossary, developer integration, verification walkthrough, and transparency specification with the same protocol-v2 terminology and security boundaries.
- Removed claims that artifact validity alone proves AI correctness, compliance, fairness, legal admissibility, objective event truth, independently trusted time, or global transparency consistency.
- Replaced stale developer-documentation links with the maintained v2 guides and canonical example paths.
- Updated the standalone sealing utility and runnable examples for the protected-envelope format.

### Examples

- Replaced the legacy example envelope with a protocol-v2 artifact.
- Added the corresponding public verification key for independent verification of the committed example.

### Tests

- Reworked the test suite around protocol-v2 security invariants and legacy compatibility, including:
  - mutation of every top-level `protected` field;
  - nested policy/event/capture/environment/key-reference mutation;
  - required-field deletion;
  - receipt append/tamper behavior;
  - wrong-key, digest, signature, and fingerprint failures;
  - schema-disabled fail-closed protocol/suite checks;
  - deterministic canonicalization coverage;
  - committed golden-example verification;
  - explicit legacy-v1 tests demonstrating its historical unsigned-metadata boundary;
  - local-store tamper and tail-truncation behavior;
  - stable v2 transparency subjects across receipt attachment;
  - Merkle inclusion/checkpoint verification.

### CI status

- The GitHub Actions workflow remains configured for lint/type checking, Python 3.10–3.12 tests, coverage, and CLI demo verification.
- Current draft-branch workflow attempts have not produced executable job steps/logs in GitHub, so the branch must not be represented as CI-green until a workflow run actually executes successfully.
