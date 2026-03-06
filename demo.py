import subprocess

print(“Running CEYO demonstration”)

print(”\nStep 1: Sealing artifact”)
subprocess.run([“python3”, “seal_artifact.py”])

print(”\nStep 2: Verifying artifact”)
subprocess.run([
“python3”,
“tools/ceyo_verify.py”,
“example_artifact/sample_record.json”,
“example_artifact/sample_signature.json”,
“example_artifact/public_key.pem”
])

print(”\nDemo complete”)
