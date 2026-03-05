# Verification Walkthrough

## Step 1: Obtain Artifact Files

sample_record.json
sample_signature.json
public_key.pem

## Step 2: Install Dependencies

pip install -r requirements.txt

## Step 3: Run Verifier

python tools/ceyo_verify.py \
example_artifact/sample_record.json \
example_artifact/sample_signature.json \
example_artifact/public_key.pem

Expected Output:

PASS
Signature validated
