# CEYO Verification Protocol

Verification of a CEYO artifact follows a deterministic process.

## Step 1 — Retrieve Artifact

The verifier obtains the artifact envelope containing
the artifact body, canonicalization metadata,
and integrity fields.

## Step 2 — Canonicalization

The artifact body is canonicalized according to
the declared canonicalization scheme.

## Step 3 — Hash Recalculation

The verifier recomputes the cryptographic hash.

## Step 4 — Signature Validation

The verifier validates the digital signature using
the declared public verification key.

## Step 5 — Policy Alignment Check

The policy identifier and version are validated
against the referenced policy specification.
