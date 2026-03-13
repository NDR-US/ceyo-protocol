"""ceyo_verify — standalone CEYO artifact verifier.

This package is intentionally self-contained: it only depends on the
standard library, ``cryptography``, and ``rfc8785``. It does NOT import
from ``ceyo`` (the SDK), so it can be run independently by any third
party with nothing more than those two packages installed.

Usage (Python API)::

    from ceyo_verify import verify_artifact, load_artifact, load_pubkey

    artifact = load_artifact("sealed.json")
    pub_pem  = load_pubkey("public_key.pem")
    result   = verify_artifact(artifact, pub_pem)
    print(result)   # VerificationResult(PASSED, ...)
    assert result.ok

Usage (CLI)::

    python -m ceyo_verify sealed.json public_key.pem
"""

from ceyo_verify.verifier import VerificationResult, verify_artifact

__all__ = ["VerificationResult", "verify_artifact"]
