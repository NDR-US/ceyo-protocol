CEYO Glossary

Artifact
A structured record describing an AI system event.

Artifact Body
The policy-scoped event data captured by CEYO.

Artifact Envelope
The complete sealed structure containing the artifact body, canonicalization metadata, cryptographic integrity fields, and key reference. This is the output of the sealing process.

Canonicalization
The deterministic serialization process used before hashing.

Sealing
The process of hashing and digitally signing the artifact body.

Verification
The process of recomputing the artifact hash and validating the signature.

Capture Policy
The defined rule set specifying which fields may be recorded in an artifact.

Signing Key
The private key used to generate artifact signatures.

Verification Key
The public key used to validate artifact signatures.
