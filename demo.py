import shutil
import subprocess
import sys

print("Running CEYO demonstration")

print("\nStep 1: Sealing artifact")
subprocess.run(["python3", "seal_artifact.py"], check=True)

print("\nStep 2: Verifying artifact")
if shutil.which("python3") and subprocess.run(
    ["python3", "-c", "import importlib; importlib.import_module('tools.ceyo_verify')"],
    capture_output=True,
).returncode == 0:
    subprocess.run([
        "python3",
        "tools/ceyo_verify.py",
        "example_artifact/sample_record.json",
        "example_artifact/sample_signature.json",
        "example_artifact/public_key.pem",
    ], check=True)
else:
    print("Skipped: tools/ceyo_verify.py not found. Verification step requires the verifier tool.")

print("\nDemo complete")
