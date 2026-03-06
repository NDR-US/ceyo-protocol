CEYO Verifier

The CEYO verifier demonstrates how artifacts can be validated independently.

Verification Process
	1.	Load artifact record
	2.	Canonicalize payload (RFC 8785)
	3.	Recompute SHA-256 digest
	4.	Validate digital signature
	5.	Confirm policy identifiers

Example Command

python tools/ceyo_verify.py example_artifact/sample_record.json example_artifact/sample_signature.json example_artifact/public_key.pem

Expected Result

PASS

This indicates the artifact has not been modified and the signature matches the declared verification key.

If any part of the record is altered, verification fails.
