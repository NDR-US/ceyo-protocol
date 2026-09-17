# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately to:

**security@ceyo.ai**

Include, where possible:

- a clear description of the issue;
- affected protocol or implementation component;
- reproduction steps;
- proof-of-concept material;
- likely security or evidentiary impact;
- any suggested mitigation.

Please do not publicly disclose a vulnerability before there has been a reasonable opportunity to investigate and remediate it.

## Scope

This repository contains the canonical public CEYO protocol specification and reference implementation.

Relevant security areas include:

- artifact integrity and signed scope;
- canonicalization determinism;
- cryptographic signature verification;
- key handling and fingerprint resolution;
- schema validation;
- append-only storage behavior;
- transparency-log checkpoints and inclusion proofs;
- protocol-version and downgrade behavior;
- trust-boundary and verifier inconsistencies.

## Current maturity

CEYO is an early-stage reference architecture and is **not** a production security certification.

Production deployment would require controls appropriate to the deployment context, including independent cryptographic/security review, hardened key custody, authenticated trust configuration, monitoring, operational incident response, conformance testing, and appropriate legal/institutional review.

## Project authority

CEYO is created and led by Brian Covarrubias. Security review, external testing, and vulnerability reports are encouraged, but external reviewers and development tools are not project authors or IP owners by virtue of their review activity.
