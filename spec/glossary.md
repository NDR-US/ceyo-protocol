# CEYO Glossary

**Artifact**  
A portable CEYO evidence object representing a policy-scoped record of an asserted AI-supported operation together with cryptographic integrity material.

**Artifact Body**  
The policy-scoped event and contextual data contained in `protected.body`.

**Artifact Envelope**  
The complete CEYO object. Protocol v2 has three top-level components: `protected`, `integrity`, and `receipts`.

**Protected**  
The protocol-v2 object whose canonical representation is hashed and signed. It contains artifact identity, protocol/body-schema versions, signer-asserted sealing time, canonicalization/signing-suite declarations, key reference, and artifact body.

**Integrity Block**  
The protocol-v2 digest and signature material authenticating `canonical(protected)`.

**Receipt**  
Optional external evidence attached outside the original artifact signature. A receipt affects trust only after its own type, subject binding, issuer, and proof are validated under an applicable profile.

**Canonicalization**  
Deterministic serialization used to produce the bytes that are hashed. Protocol-v2 artifacts declare the supported canonicalization suite inside `protected`.

**Sealing**  
The process of building `protected`, canonicalizing it, hashing the canonical bytes, and digitally signing the resulting digest.

**Artifact Validity**  
The result of successful protocol/schema processing plus digest, signature, and key-fingerprint verification for the authenticated artifact state.

**Trust / Evidentiary Status**  
A higher-level result that can incorporate artifact validity, signer/key authorization, revocation/status evidence, accepted receipts or external anchors, and verification-profile policy.

**Verification**  
The process of validating the artifact structure, reproducing the declared canonicalization, recomputing the digest, checking the signature, and checking the protected key fingerprint. Higher-level trust evaluation is separate.

**Capture Policy**  
The rule set defining which evidence fields may be recorded or represented in an artifact.

**Disclosure Policy**  
A signed sealing-time commitment describing the disclosure policy/tier associated with the artifact. Later disclosure events are separate records rather than mutations of the original artifact.

**Signing Key**  
The private key used to create an artifact signature.

**Verification Key**  
The public key used to verify the artifact signature. A valid cryptographic key does not by itself establish organizational authorization or trust.

**Key Reference**  
The protocol-v2 signed metadata identifying the key registry/key ID and public-key fingerprint associated with the artifact.

**Event Time (`event.occurred_at`)**  
The originating system's assertion about when the underlying event occurred.

**Sealing Time (`sealed_at`)**  
The signer's assertion about when the artifact was sealed. It is signature-bound in protocol v2, so later editing is detectable, but it is not independently trusted time.

**External Time Anchor**  
Separately authenticated time evidence accepted by a verification profile, such as an appropriate transparency receipt/checkpoint, timestamp authority, or witness mechanism.

**Legacy v1 Artifact**  
A CEYO v1 artifact whose signature covered only `canonical(body)`. V1 remains verifiable under that original narrower scope and is not retroactively represented as v2.

**Transparency Inclusion Proof**  
A Merkle proof showing that a stable artifact subject is included in the tree represented by a particular root/checkpoint. Inclusion alone does not establish checkpoint freshness or global log consistency.

**Checkpoint**  
A signed assertion of a transparency tree size/root and signer-asserted creation time. The current checkpoint format does not, by itself, provide trusted time, anti-replay, or global consistency.
