# CEYO Protocol Specification

## 1. Introduction
Defines the CEYO artifact format and verification procedure for evidentiary records of AI system events.

## 2. Terminology
Artifact
Record Body
Canonicalization
Integrity Fields
Verification Key

## 3. Artifact Envelope

Artifact Structure:

{
  "product": "CEYO",
  "schema_version": "1.0",
  "body": {...},
  "canonicalization": {
      "scheme": "RFC8785",
      "scope": "body"
  },
  "integrity": {
      "hash": {...},
      "sig": {...}
  }
}

## 4. Canonicalization Rules
All artifacts MUST be canonicalized using RFC8785 JSON Canonicalization Scheme.

## 5. Hashing
Algorithm: SHA-256  
Input: canonicalized artifact body.

## 6. Signature
Algorithm: ECDSA-P256-SHA256  
Format: DER.

## 7. Verification Procedure
1. Canonicalize body.
2. Recompute SHA-256 digest.
3. Compare stored hash.
4. Validate ECDSA signature.

## 8. Security Considerations
- Tamper detection
- Replay considerations
- Key compromise scenarios
