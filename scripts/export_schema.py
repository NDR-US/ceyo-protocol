#!/usr/bin/env python3
"""Export ENVELOPE_SCHEMA to a standalone JSON Schema file."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ceyo.schema import ENVELOPE_SCHEMA

out = Path(__file__).resolve().parent.parent / "spec" / "artifact-schema.json"
out.write_text(json.dumps(ENVELOPE_SCHEMA, indent=2) + "\n")
print(f"Wrote {out}")
