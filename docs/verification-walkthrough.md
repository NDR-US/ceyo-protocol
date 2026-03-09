# Verification Walkthrough

## Step 1: Obtain Artifact Files

sealed_artifact.json
public_key.pem

## Step 2: Install Dependencies

pip install -r requirements.txt

## Step 3: Run Verifier

python3 tools/ceyo_verify.py example_artifact/sealed_artifact.json example_artifact/public_key.pem

Expected Output:

PASS: Hash matches
PASS: Signature valid
PASS: Key fingerprint matches

Verification PASSED
