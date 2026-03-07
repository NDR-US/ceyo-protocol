#!/usr/bin/env python3
"""CEYO Protocol — end-to-end demo: seal then verify."""

import subprocess
import sys

print("Running CEYO demonstration")

print("\nStep 1: Sealing artifact")
subprocess.run([sys.executable, "seal_artifact.py"], check=True)

print("\nStep 2: Verifying artifact")
subprocess.run([
    sys.executable,
    "tools/ceyo_verify.py",
    "example_artifact/sealed_artifact.json",
    "example_artifact/public_key.pem",
], check=True)

print("\nDemo complete")
