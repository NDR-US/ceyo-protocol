# CEYO Example Workflow

## Overview

This document illustrates the lifecycle of a CEYO artifact from generation to
independent verification.

---

# Step 1: AI Event Occurs

An AI system processes a request and produces an output.

Example:

Model receives input data and generates a prediction.

---

# Step 2: Policy-Scoped Capture

The CEYO capture policy defines which fields are recorded.

Example captured fields:

• timestamp  
• request identifier  
• input reference hash  
• environment fingerprint  

These fields form the artifact body.

---

# Step 3: Canonicalization

The artifact body is serialized using deterministic canonicalization.

Canonicalization ensures identical artifact bodies produce identical serialized
representations.

---

# Step 4: Hash Generation

A cryptographic hash is computed from the canonical artifact body.

Example algorithm:

SHA-256

This hash uniquely represents the artifact body.

---

# Step 5: Digital Signature

The hash is signed using the system’s private signing key.

The resulting signature is stored in the artifact envelope.

---

# Step 6: Artifact Storage

The sealed artifact is stored in a secure record system.

The artifact now functions as a tamper-evident evidentiary record.

---

# Step 7: Independent Verification

A third party obtains the artifact.

Verification consists of:

1. canonicalizing the artifact body  
2. recomputing the hash  
3. validating the signature using the public key  

If verification succeeds, the artifact is confirmed to be authentic and
unchanged.

---

# Summary

The CEYO artifact lifecycle enables independent validation of AI events without
requiring access to the original AI system.
