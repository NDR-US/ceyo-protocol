"""Tests for CEYO Protocol sealing and verification."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from seal_artifact import b64u, b64u_decode, canonicalize, sha256
from ceyo_verify import verify, canonicalize as verify_canonicalize, b64u_decode as verify_b64u_decode

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


class TestB64u(TestCase):
    def test_round_trip(self):
        data = b"hello ceyo"
        encoded = b64u(data)
        decoded = b64u_decode(encoded)
        self.assertEqual(data, decoded)

    def test_no_padding(self):
        encoded = b64u(b"\x00\x01\x02")
        self.assertNotIn("=", encoded)

    def test_url_safe(self):
        # Bytes that produce + and / in standard base64
        data = b"\xfb\xff\xfe"
        encoded = b64u(data)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)


class TestCanonicalize(TestCase):
    def test_deterministic(self):
        obj = {"z": 1, "a": 2, "m": 3}
        result1 = canonicalize(obj)
        result2 = canonicalize(obj)
        self.assertEqual(result1, result2)

    def test_key_order(self):
        obj = {"z": 1, "a": 2}
        result = canonicalize(obj)
        parsed = json.loads(result)
        keys = list(parsed.keys())
        self.assertEqual(keys, sorted(keys))

    def test_compact_separators(self):
        result = canonicalize({"key": "value"})
        self.assertNotIn(" ", result.decode())


class TestSha256(TestCase):
    def test_known_hash(self):
        data = b"ceyo"
        expected = hashlib.sha256(data).digest()
        self.assertEqual(sha256(data), expected)

    def test_length(self):
        self.assertEqual(len(sha256(b"test")), 32)


class TestSealAndVerify(TestCase):
    """End-to-end: seal a record, then verify the sealed artifact."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.body = {
            "event": {
                "event_id": "evt_test_001",
                "type": "classification",
                "occurred_at": "2026-01-01T00:00:00Z",
                "request_id": "req_test_001",
            },
            "policy": {"id": "test-policy", "version": "1.0"},
            "disclosure_tier": "internal",
        }

    def _seal(self, body: dict) -> tuple[Path, Path]:
        """Seal a body dict and return (artifact_path, pubkey_path)."""
        priv = ec.generate_private_key(ec.SECP256R1())

        canonical_bytes = canonicalize(body)
        digest = sha256(canonical_bytes)
        signature = priv.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

        pub = priv.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pub_der = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        artifact = {
            "product": "CEYO",
            "envelope_version": "1.0",
            "artifact_schema": {"name": "ceyo.artifact", "version": "1.0"},
            "artifact_id": "ceyo_art_test",
            "created_at": "2026-01-01T00:00:00Z",
            "body": body,
            "canonicalization": {
                "scheme": "RFC8785" if "rfc8785" in sys.modules else "deterministic-json-fallback",
                "version": "1.0",
                "scope": "body",
            },
            "integrity": {
                "hash": {
                    "alg": "SHA-256",
                    "value_b64u": b64u(digest),
                    "covers": "canonical(body)",
                },
                "sig": {
                    "alg": "ECDSA-P256-SHA256",
                    "format": "DER",
                    "value_b64u": b64u(signature),
                    "covers": "canonical(body)",
                },
            },
            "key_reference": {
                "registry": "local",
                "key_id": "test",
                "public_key_fingerprint": {
                    "alg": "SHA-256",
                    "value_b64u": b64u(sha256(pub_der)),
                    "covers": "public_key_spki_der",
                },
            },
        }

        artifact_path = Path(self.tmpdir) / "sealed.json"
        pubkey_path = Path(self.tmpdir) / "pub.pem"
        artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        pubkey_path.write_bytes(pub_pem)

        return artifact_path, pubkey_path

    def test_seal_then_verify(self):
        artifact_path, pubkey_path = self._seal(self.body)
        result = verify(str(artifact_path), str(pubkey_path))
        self.assertTrue(result)

    def test_tampered_body_fails(self):
        artifact_path, pubkey_path = self._seal(self.body)

        # Tamper with the body
        artifact = json.loads(artifact_path.read_text())
        artifact["body"]["event"]["type"] = "tampered"
        artifact_path.write_text(json.dumps(artifact, indent=2))

        result = verify(str(artifact_path), str(pubkey_path))
        self.assertFalse(result)

    def test_tampered_signature_fails(self):
        artifact_path, pubkey_path = self._seal(self.body)

        # Corrupt the signature
        artifact = json.loads(artifact_path.read_text())
        artifact["integrity"]["sig"]["value_b64u"] = b64u(b"\x00" * 64)
        artifact_path.write_text(json.dumps(artifact, indent=2))

        result = verify(str(artifact_path), str(pubkey_path))
        self.assertFalse(result)

    def test_wrong_key_fails(self):
        artifact_path, _ = self._seal(self.body)

        # Generate a different key
        wrong_priv = ec.generate_private_key(ec.SECP256R1())
        wrong_pub_pem = wrong_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        wrong_key_path = Path(self.tmpdir) / "wrong.pem"
        wrong_key_path.write_bytes(wrong_pub_pem)

        result = verify(str(artifact_path), str(wrong_key_path))
        self.assertFalse(result)

    def test_envelope_has_required_fields(self):
        artifact_path, _ = self._seal(self.body)
        artifact = json.loads(artifact_path.read_text())

        for field in ["product", "envelope_version", "artifact_schema",
                       "artifact_id", "created_at", "body",
                       "canonicalization", "integrity", "key_reference"]:
            self.assertIn(field, artifact, f"Missing required field: {field}")

    def test_integrity_structure(self):
        artifact_path, _ = self._seal(self.body)
        artifact = json.loads(artifact_path.read_text())

        self.assertIn("hash", artifact["integrity"])
        self.assertIn("sig", artifact["integrity"])
        self.assertEqual(artifact["integrity"]["hash"]["alg"], "SHA-256")
        self.assertEqual(artifact["integrity"]["sig"]["alg"], "ECDSA-P256-SHA256")
        self.assertEqual(artifact["integrity"]["sig"]["format"], "DER")


if __name__ == "__main__":
    main()
