"""Tests for CEYO Protocol — crypto, sealing, verification, schema, store, client."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main

from cryptography.hazmat.primitives.asymmetric import ec

from ceyo.client import CeyoClient
from ceyo.crypto import b64u, b64u_decode, canonicalize, sha256
from ceyo.keys import InMemoryKeyProvider, KeyManager, LocalKeyProvider
from ceyo.schema import ValidationError, validate_body, validate_envelope, validate_envelope_or_raise
from ceyo.seal import seal, seal_body
from ceyo.store import ArtifactStore
from ceyo.verify import verify_artifact
from ceyo_verify import verify_artifact as standalone_verify

# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------

class TestB64u(TestCase):
    def test_round_trip(self):
        data = b"hello ceyo"
        self.assertEqual(b64u_decode(b64u(data)), data)

    def test_no_padding(self):
        self.assertNotIn("=", b64u(b"\x00\x01\x02"))

    def test_url_safe(self):
        encoded = b64u(b"\xfb\xff\xfe")
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)


class TestCanonicalize(TestCase):
    def test_deterministic(self):
        obj = {"z": 1, "a": 2, "m": 3}
        self.assertEqual(canonicalize(obj), canonicalize(obj))

    def test_key_order(self):
        result = canonicalize({"z": 1, "a": 2})
        keys = list(json.loads(result).keys())
        self.assertEqual(keys, sorted(keys))

    def test_compact_separators(self):
        self.assertNotIn(" ", canonicalize({"key": "value"}).decode())


class TestSha256(TestCase):
    def test_known_hash(self):
        self.assertEqual(sha256(b"ceyo"), hashlib.sha256(b"ceyo").digest())

    def test_length(self):
        self.assertEqual(len(sha256(b"test")), 32)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchema(TestCase):
    def _make_valid_envelope(self):
        kp = InMemoryKeyProvider()
        body = {
            "event": {
                "event_id": "evt_test",
                "type": "inference",
                "occurred_at": "2026-01-01T00:00:00Z",
            },
        }
        return seal_body(body, kp)

    def test_valid_envelope_passes(self):
        errors = validate_envelope(self._make_valid_envelope())
        self.assertEqual(errors, [])

    def test_missing_field_fails(self):
        envelope = self._make_valid_envelope()
        del envelope["integrity"]
        errors = validate_envelope(envelope)
        self.assertTrue(any("integrity" in e for e in errors))

    def test_wrong_product_fails(self):
        envelope = self._make_valid_envelope()
        envelope["product"] = "NOT_CEYO"
        errors = validate_envelope(envelope)
        self.assertTrue(any("CEYO" in e for e in errors))

    def test_bad_artifact_id_fails(self):
        envelope = self._make_valid_envelope()
        envelope["artifact_id"] = "bad_id"
        errors = validate_envelope(envelope)
        self.assertTrue(any("pattern" in e for e in errors))

    def test_extra_field_rejected(self):
        envelope = self._make_valid_envelope()
        envelope["extra_field"] = "surprise"
        errors = validate_envelope(envelope)
        self.assertTrue(any("extra_field" in e for e in errors))

    def test_validate_or_raise(self):
        envelope = self._make_valid_envelope()
        del envelope["body"]
        with self.assertRaises(ValidationError):
            validate_envelope_or_raise(envelope)

    def test_valid_body(self):
        body = {"event": {"event_id": "e", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
        self.assertEqual(validate_body(body), [])

    def test_body_missing_event(self):
        errors = validate_body({"disclosure_tier": "public"})
        self.assertTrue(any("event" in e for e in errors))


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

class TestKeyProviders(TestCase):
    def test_in_memory_provider(self):
        kp = InMemoryKeyProvider()
        self.assertIsInstance(kp.get_private_key(), ec.EllipticCurvePrivateKey)
        self.assertTrue(kp.fingerprint())
        self.assertEqual(kp.registry(), "memory")

    def test_local_provider_creates_keys(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        priv_path = Path(tmpdir) / "priv.pem"
        pub_path = Path(tmpdir) / "pub.pem"
        kp = LocalKeyProvider(priv_path, pub_path)

        self.assertIsInstance(kp.get_private_key(), ec.EllipticCurvePrivateKey)
        self.assertTrue(priv_path.exists())
        self.assertTrue(pub_path.exists())

    def test_local_provider_reloads_keys(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        priv_path = Path(tmpdir) / "priv.pem"
        kp1 = LocalKeyProvider(priv_path)
        fp1 = kp1.fingerprint()

        kp2 = LocalKeyProvider(priv_path)
        self.assertEqual(fp1, kp2.fingerprint())

    def test_key_manager(self):
        km = KeyManager()
        km.register("test", InMemoryKeyProvider())
        self.assertIsNotNone(km.get("test").get_private_key())

    def test_key_manager_default(self):
        km = KeyManager()
        km.register("first", InMemoryKeyProvider())
        self.assertIsNotNone(km.default())

    def test_key_manager_missing(self):
        km = KeyManager()
        with self.assertRaises(KeyError):
            km.get("nonexistent")

    def test_key_reference_structure(self):
        ref = InMemoryKeyProvider().key_reference()
        self.assertIn("registry", ref)
        self.assertIn("key_id", ref)
        self.assertEqual(ref["public_key_fingerprint"]["alg"], "SHA-256")


# ---------------------------------------------------------------------------
# Seal and Verify
# ---------------------------------------------------------------------------

class TestSealAndVerify(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()
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

    def test_seal_then_verify(self):
        envelope = seal_body(self.body, self.kp)
        result = verify_artifact(envelope, self.kp.get_public_key_pem())
        self.assertTrue(result.ok)
        self.assertGreaterEqual(len(result.passed), 3)

    def test_tampered_body_fails(self):
        envelope = seal_body(self.body, self.kp)
        envelope["body"]["event"]["type"] = "tampered"
        result = verify_artifact(envelope, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_tampered_signature_fails(self):
        envelope = seal_body(self.body, self.kp)
        envelope["integrity"]["sig"]["value_b64u"] = b64u(b"\x00" * 64)
        result = verify_artifact(envelope, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_wrong_key_fails(self):
        envelope = seal_body(self.body, self.kp)
        wrong_kp = InMemoryKeyProvider()
        result = verify_artifact(envelope, wrong_kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_envelope_has_required_fields(self):
        envelope = seal_body(self.body, self.kp)
        for field in ["product", "envelope_version", "artifact_schema",
                       "artifact_id", "created_at", "body",
                       "canonicalization", "integrity", "key_reference"]:
            self.assertIn(field, envelope)

    def test_integrity_structure(self):
        envelope = seal_body(self.body, self.kp)
        self.assertEqual(envelope["integrity"]["hash"]["alg"], "SHA-256")
        self.assertEqual(envelope["integrity"]["sig"]["alg"], "ECDSA-P256-SHA256")
        self.assertEqual(envelope["integrity"]["sig"]["format"], "DER")

    def test_seal_convenience(self):
        envelope = seal(
            event_id="evt_001",
            event_type="inference",
            occurred_at="2026-01-01T00:00:00Z",
            request_id="req_001",
            policy_id="POL-001",
            key_provider=self.kp,
        )
        result = verify_artifact(envelope, self.kp.get_public_key_pem())
        self.assertTrue(result.ok)

    def test_custom_artifact_id(self):
        envelope = seal_body(self.body, self.kp, artifact_id="ceyo_art_custom_test")
        self.assertEqual(envelope["artifact_id"], "ceyo_art_custom_test")


# ---------------------------------------------------------------------------
# Artifact Store
# ---------------------------------------------------------------------------

class TestArtifactStore(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.kp = InMemoryKeyProvider()

    def _make_artifact(self, event_id="evt_001"):
        return seal_body(
            {"event": {"event_id": event_id, "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}},
            self.kp,
        )

    def test_append_and_retrieve(self):
        with ArtifactStore(self.db_path) as store:
            art = self._make_artifact()
            seq = store.append(art)
            self.assertEqual(seq, 1)
            retrieved = store.get(art["artifact_id"])
            self.assertEqual(retrieved["artifact_id"], art["artifact_id"])

    def test_get_by_seq(self):
        with ArtifactStore(self.db_path) as store:
            art = self._make_artifact()
            seq = store.append(art)
            self.assertEqual(store.get_by_seq(seq)["artifact_id"], art["artifact_id"])

    def test_count(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(5):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            self.assertEqual(store.count(), 5)

    def test_chain_integrity_passes(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(10):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            ok, checked = store.verify_chain()
            self.assertTrue(ok)
            self.assertEqual(checked, 10)

    def test_chain_detects_tampering(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(5):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            store._conn.execute("UPDATE artifacts SET entry_hash = 'tampered' WHERE seq = 3")
            store._conn.commit()
            ok, checked = store.verify_chain()
            self.assertFalse(ok)
            self.assertEqual(checked, 2)

    def test_recent(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(10):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            self.assertEqual(len(store.recent(3)), 3)

    def test_missing_artifact_returns_none(self):
        with ArtifactStore(self.db_path) as store:
            self.assertIsNone(store.get("nonexistent"))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class TestClient(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()

    def test_seal_and_verify(self):
        client = CeyoClient(key_provider=self.kp)
        body = {"event": {"event_id": "evt_001", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = client.seal(body, persist=False)
        self.assertTrue(client.verify(envelope).ok)

    def test_seal_with_store(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        with ArtifactStore(os.path.join(tmpdir, "client.db")) as store:
            client = CeyoClient(key_provider=self.kp, store=store)
            body = {"event": {"event_id": "evt_001", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
            client.seal(body)
            self.assertEqual(store.count(), 1)

    def test_trace_decorator(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)

        with ArtifactStore(os.path.join(tmpdir, "trace.db")) as store:
            client = CeyoClient(key_provider=self.kp, store=store)

            @client.trace(event_type="test")
            def add(a, b):
                return a + b

            self.assertEqual(add(2, 3), 5)
            self.assertEqual(store.count(), 1)

    def test_trace_decorator_bare(self):
        client = CeyoClient(key_provider=self.kp)

        @client.trace
        def greet(name):
            return f"hello {name}"

        self.assertEqual(greet("ceyo"), "hello ceyo")

    def test_default_key_provider(self):
        client = CeyoClient()
        body = {"event": {"event_id": "evt_001", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = client.seal(body, persist=False)
        self.assertTrue(client.verify(envelope).ok)


# ---------------------------------------------------------------------------
# Negative cases — malformed input, tamper, wrong key, bad signature
# ---------------------------------------------------------------------------

class TestNegativeCases(TestCase):
    """Explicit negative tests covering all documented failure modes."""

    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.body = {
            "event": {
                "event_id": "evt_neg_001",
                "type": "classification",
                "occurred_at": "2026-01-01T00:00:00Z",
            },
        }

    def _sealed(self):
        return seal_body(self.body, self.kp)

    # --- Schema failures ---

    def test_malformed_schema_wrong_product(self):
        env = self._sealed()
        env["product"] = "NOT_CEYO"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("Schema" in m for m in result.failed))

    def test_malformed_schema_missing_body(self):
        env = self._sealed()
        del env["body"]
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_schema_bad_artifact_id(self):
        env = self._sealed()
        env["artifact_id"] = "not_a_ceyo_id"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_schema_bad_datetime(self):
        env = self._sealed()
        env["created_at"] = "not-a-date"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_schema_wrong_hash_alg(self):
        env = self._sealed()
        env["integrity"]["hash"]["alg"] = "MD5"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_schema_wrong_sig_alg(self):
        env = self._sealed()
        env["integrity"]["sig"]["alg"] = "RSA-SHA256"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_schema_extra_top_level_field(self):
        env = self._sealed()
        env["extra_key"] = "injected"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_malformed_body_missing_event(self):
        errors = validate_body({"disclosure_tier": "public"})
        self.assertTrue(any("event" in e for e in errors))

    def test_malformed_body_missing_event_type(self):
        body = {"event": {"event_id": "e", "occurred_at": "2026-01-01T00:00:00Z"}}
        errors = validate_body(body)
        self.assertTrue(any("type" in e for e in errors))

    def test_malformed_body_bad_occurred_at(self):
        body = {"event": {"event_id": "e", "type": "t", "occurred_at": "yesterday"}}
        errors = validate_body(body)
        self.assertTrue(len(errors) > 0)

    # --- Crypto failures ---

    def test_tampered_body_detected(self):
        env = self._sealed()
        env["body"]["event"]["type"] = "tampered"
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("Hash" in m or "mismatch" in m for m in result.failed))

    def test_tampered_hash_value_detected(self):
        env = self._sealed()
        # Replace the stored hash with a different value
        env["integrity"]["hash"]["value_b64u"] = b64u(b"\x00" * 32)
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_signature_bytes_detected(self):
        env = self._sealed()
        env["integrity"]["sig"]["value_b64u"] = b64u(b"\xde\xad\xbe\xef" * 16)
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("Signature" in m for m in result.failed))

    def test_wrong_key_fails(self):
        env = self._sealed()
        wrong_kp = InMemoryKeyProvider()
        result = verify_artifact(env, wrong_kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_fingerprint_mismatch_fails(self):
        env = self._sealed()
        wrong_kp = InMemoryKeyProvider()
        # Use the correct key to pass hash/sig, but inject wrong fingerprint
        env["key_reference"]["public_key_fingerprint"]["value_b64u"] = wrong_kp.fingerprint()
        result = verify_artifact(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("fingerprint" in m.lower() for m in result.failed))

    def test_no_fingerprint_check_skips_that_step(self):
        env = self._sealed()
        # Inject garbage fingerprint but disable the check
        env["key_reference"]["public_key_fingerprint"]["value_b64u"] = b64u(b"\x00" * 32)
        result = verify_artifact(env, self.kp.get_public_key_pem(), check_fingerprint=False)
        self.assertTrue(result.ok)


# ---------------------------------------------------------------------------
# Round-trip tests — seal → persist → retrieve → verify
# ---------------------------------------------------------------------------

class TestRoundTrip(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.db_path = os.path.join(self.tmpdir, "rt.db")
        self.kp = InMemoryKeyProvider()

    def test_seal_persist_verify(self):
        """Full round-trip: seal → store.append → store.get → verify_artifact."""
        body = {
            "event": {
                "event_id": "evt_rt_001",
                "type": "roundtrip",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }
        envelope = seal_body(body, self.kp)

        with ArtifactStore(self.db_path) as store:
            seq = store.append(envelope)
            retrieved = store.get_by_seq(seq)

        self.assertIsNotNone(retrieved)
        result = verify_artifact(retrieved, self.kp.get_public_key_pem())
        self.assertTrue(result.ok)

    def test_multiple_seals_chain_intact(self):
        """Seal N artifacts, persist all, verify chain is intact."""
        with ArtifactStore(self.db_path) as store:
            for i in range(20):
                body = {
                    "event": {
                        "event_id": f"evt_chain_{i:04d}",
                        "type": "chain_test",
                        "occurred_at": "2026-03-01T00:00:00Z",
                    },
                }
                store.append(seal_body(body, self.kp))
            ok, checked = store.verify_chain()

        self.assertTrue(ok)
        self.assertEqual(checked, 20)

    def test_roundtrip_convenience_seal(self):
        """seal() convenience → store → verify."""
        envelope = seal(
            event_id="evt_rt_conv_001",
            event_type="inference",
            occurred_at="2026-03-01T12:00:00Z",
            policy_id="POL-RT-001",
            key_provider=self.kp,
        )
        with ArtifactStore(self.db_path) as store:
            store.append(envelope)
            retrieved = store.get(envelope["artifact_id"])

        result = verify_artifact(retrieved, self.kp.get_public_key_pem())
        self.assertTrue(result.ok)

    def test_standalone_verifier_matches_sdk(self):
        """ceyo_verify standalone verifier produces same result as ceyo.verify."""
        body = {
            "event": {
                "event_id": "evt_standalone_001",
                "type": "cross_check",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }
        envelope = seal_body(body, self.kp)
        pub_pem = self.kp.get_public_key_pem()

        sdk_result = verify_artifact(envelope, pub_pem)
        standalone_result = standalone_verify(envelope, pub_pem)

        self.assertEqual(sdk_result.ok, standalone_result.ok)
        self.assertEqual(sdk_result.passed, standalone_result.passed)

    def test_standalone_verifier_catches_tamper(self):
        """Standalone verifier detects body tampering independently."""
        body = {
            "event": {
                "event_id": "evt_standalone_tamper",
                "type": "test",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }
        envelope = seal_body(body, self.kp)
        envelope["body"]["event"]["type"] = "tampered"
        result = standalone_verify(envelope, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------

class TestCLI(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.priv = os.path.join(self.tmpdir, "test_priv.pem")
        self.pub  = os.path.join(self.tmpdir, "test_pub.pem")

    def _run(self, *args, check=True):
        return subprocess.run(
            [sys.executable, "-m", "ceyo"] + list(args),
            capture_output=True, text=True,
            check=check,
        )

    def test_keygen(self):
        r = self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(Path(self.priv).exists())
        self.assertTrue(Path(self.pub).exists())
        self.assertIn("Fingerprint:", r.stdout)

    def test_keygen_refuses_overwrite_without_force(self):
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)
        r = subprocess.run(
            [sys.executable, "-m", "ceyo", "keygen", "--out-private", self.priv, "--out-public", self.pub],
            capture_output=True, text=True,
        )
        self.assertNotEqual(r.returncode, 0)

    def test_keygen_force_overwrites(self):
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)
        r = self._run("keygen", "--out-private", self.priv, "--out-public", self.pub, "--force")
        self.assertEqual(r.returncode, 0)

    def test_seal_and_verify(self):
        # Generate keys
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)

        # Write a minimal valid record
        record_path = os.path.join(self.tmpdir, "record.json")
        Path(record_path).write_text(json.dumps({
            "event": {
                "event_id": "evt_cli_001",
                "type": "cli_test",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }), encoding="utf-8")

        # Seal
        sealed_path = os.path.join(self.tmpdir, "record.sealed.json")
        r = self._run("seal", record_path, "--key", self.priv, "-o", sealed_path)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(Path(sealed_path).exists())
        self.assertIn("Sealed:", r.stdout)

        # Verify
        r = self._run("verify", sealed_path, self.pub)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Verification PASSED", r.stdout)

    def test_verify_fails_on_tampered_artifact(self):
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)

        record_path = os.path.join(self.tmpdir, "record.json")
        Path(record_path).write_text(json.dumps({
            "event": {
                "event_id": "evt_cli_tamper",
                "type": "original",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }), encoding="utf-8")

        sealed_path = os.path.join(self.tmpdir, "tampered.sealed.json")
        self._run("seal", record_path, "--key", self.priv, "-o", sealed_path)

        # Tamper with the artifact
        art = json.loads(Path(sealed_path).read_text())
        art["body"]["event"]["type"] = "tampered"
        Path(sealed_path).write_text(json.dumps(art))

        r = subprocess.run(
            [sys.executable, "-m", "ceyo", "verify", sealed_path, self.pub],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 1)
        self.assertIn("Verification FAILED", r.stdout)

    def test_standalone_verify_cli(self):
        """python -m ceyo_verify should pass on a valid artifact."""
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)

        record_path = os.path.join(self.tmpdir, "record.json")
        Path(record_path).write_text(json.dumps({
            "event": {
                "event_id": "evt_standalone_cli",
                "type": "standalone",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }), encoding="utf-8")

        sealed_path = os.path.join(self.tmpdir, "standalone.sealed.json")
        self._run("seal", record_path, "--key", self.priv, "-o", sealed_path)

        r = subprocess.run(
            [sys.executable, "-m", "ceyo_verify", sealed_path, self.pub],
            capture_output=True, text=True,
        )
        self.assertEqual(r.returncode, 0)
        self.assertIn("Verification PASSED", r.stdout)

    def test_store_list_and_inspect(self):
        """CLI store list and inspect commands work after sealing."""
        self._run("keygen", "--out-private", self.priv, "--out-public", self.pub)

        record_path = os.path.join(self.tmpdir, "record.json")
        body = {
            "event": {
                "event_id": "evt_cli_store",
                "type": "store_test",
                "occurred_at": "2026-03-01T00:00:00Z",
            },
        }
        Path(record_path).write_text(json.dumps(body), encoding="utf-8")

        # Seal and manually persist so we can inspect
        from ceyo.keys import LocalKeyProvider as LKP
        from ceyo.seal import seal_body as sb
        kp = LKP(self.priv, self.pub)
        env = sb(body, kp)
        db_path = os.path.join(self.tmpdir, "test.db")
        with ArtifactStore(db_path) as store:
            store.append(env)

        r = self._run("store", "list", db_path)
        self.assertEqual(r.returncode, 0)
        self.assertIn(env["artifact_id"], r.stdout)

        r = self._run("store", "inspect", db_path, env["artifact_id"])
        self.assertEqual(r.returncode, 0)
        artifact_id_in_output = env["artifact_id"] in r.stdout
        self.assertTrue(artifact_id_in_output)

        r = self._run("store", "verify-chain", db_path)
        self.assertEqual(r.returncode, 0)
        self.assertIn("INTACT", r.stdout)


# ---------------------------------------------------------------------------
# Direct CLI unit tests (no subprocess — covers ceyo/cli.py)
# ---------------------------------------------------------------------------

class TestCLIDirect(TestCase):
    """Call CLI command functions directly for coverage without subprocess overhead."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.priv = os.path.join(self.tmpdir, "priv.pem")
        self.pub  = os.path.join(self.tmpdir, "pub.pem")

    def _ns(self, **kwargs):
        """Build a fake argparse.Namespace."""
        import argparse
        return argparse.Namespace(**kwargs)

    def test_cmd_keygen_creates_files(self):
        from ceyo.cli import cmd_keygen
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)
        self.assertTrue(Path(self.priv).exists())
        self.assertTrue(Path(self.pub).exists())

    def test_cmd_keygen_refuses_existing(self):
        from ceyo.cli import cmd_keygen
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)
        with self.assertRaises(SystemExit) as ctx:
            cmd_keygen(ns)
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_keygen_force_overwrites(self):
        from ceyo.cli import cmd_keygen
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)
        ns2 = self._ns(out_private=self.priv, out_public=self.pub, force=True)
        cmd_keygen(ns2)  # should not raise
        self.assertTrue(Path(self.priv).exists())

    def test_cmd_seal(self, tmp_path=None):
        from ceyo.cli import cmd_keygen, cmd_seal
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)

        record = os.path.join(self.tmpdir, "rec.json")
        sealed = os.path.join(self.tmpdir, "rec.sealed.json")
        Path(record).write_text(json.dumps({
            "event": {"event_id": "e", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"},
        }), encoding="utf-8")

        ns2 = self._ns(record=record, key=self.priv, output=sealed, no_validate=False)
        cmd_seal(ns2)
        self.assertTrue(Path(sealed).exists())

    def test_cmd_seal_missing_record(self):
        from ceyo.cli import cmd_seal
        ns = self._ns(record="/nonexistent.json", key=self.priv, output=None, no_validate=False)
        with self.assertRaises(SystemExit) as ctx:
            cmd_seal(ns)
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_seal_invalid_json(self):
        from ceyo.cli import cmd_seal
        bad = os.path.join(self.tmpdir, "bad.json")
        Path(bad).write_text("not json", encoding="utf-8")
        ns = self._ns(record=bad, key=self.priv, output=None, no_validate=False)
        with self.assertRaises(SystemExit) as ctx:
            cmd_seal(ns)
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_verify_passes(self):
        from ceyo.cli import cmd_keygen, cmd_seal, cmd_verify
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)

        record = os.path.join(self.tmpdir, "rec.json")
        sealed = os.path.join(self.tmpdir, "rec.sealed.json")
        Path(record).write_text(json.dumps({
            "event": {"event_id": "e", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"},
        }), encoding="utf-8")
        cmd_seal(self._ns(record=record, key=self.priv, output=sealed, no_validate=False))

        with self.assertRaises(SystemExit) as ctx:
            cmd_verify(self._ns(artifact=sealed, pubkey=self.pub))
        self.assertEqual(ctx.exception.code, 0)

    def test_cmd_verify_missing_artifact(self):
        from ceyo.cli import cmd_verify
        with self.assertRaises(SystemExit) as ctx:
            cmd_verify(self._ns(artifact="/no.json", pubkey=self.pub))
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_verify_missing_pubkey(self):
        from ceyo.cli import cmd_keygen, cmd_seal, cmd_verify
        ns = self._ns(out_private=self.priv, out_public=self.pub, force=False)
        cmd_keygen(ns)
        record = os.path.join(self.tmpdir, "r.json")
        sealed = os.path.join(self.tmpdir, "r.sealed.json")
        Path(record).write_text(json.dumps({
            "event": {"event_id": "e", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"},
        }), encoding="utf-8")
        cmd_seal(self._ns(record=record, key=self.priv, output=sealed, no_validate=False))
        with self.assertRaises(SystemExit) as ctx:
            cmd_verify(self._ns(artifact=sealed, pubkey="/no_key.pem"))
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_store_list_empty(self):
        from ceyo.cli import cmd_store_list
        db = os.path.join(self.tmpdir, "empty.db")
        with ArtifactStore(db):
            pass
        cmd_store_list(self._ns(db=db, limit=10))

    def test_cmd_store_inspect_found(self):
        from ceyo.cli import cmd_store_inspect
        kp = InMemoryKeyProvider()
        body = {"event": {"event_id": "e", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
        env = seal_body(body, kp)
        db = os.path.join(self.tmpdir, "insp.db")
        with ArtifactStore(db) as store:
            store.append(env)
        cmd_store_inspect(self._ns(db=db, artifact_id=env["artifact_id"]))

    def test_cmd_store_inspect_not_found(self):
        from ceyo.cli import cmd_store_inspect
        db = os.path.join(self.tmpdir, "empty.db")
        with ArtifactStore(db):
            pass
        with self.assertRaises(SystemExit) as ctx:
            cmd_store_inspect(self._ns(db=db, artifact_id="ceyo_art_notfound"))
        self.assertEqual(ctx.exception.code, 1)

    def test_cmd_store_verify_chain(self):
        from ceyo.cli import cmd_store_verify_chain
        kp = InMemoryKeyProvider()
        db = os.path.join(self.tmpdir, "chain.db")
        with ArtifactStore(db) as store:
            for i in range(3):
                body = {"event": {"event_id": f"e{i}", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
                store.append(seal_body(body, kp))
        with self.assertRaises(SystemExit) as ctx:
            cmd_store_verify_chain(self._ns(db=db))
        self.assertEqual(ctx.exception.code, 0)


# ---------------------------------------------------------------------------
# Direct ceyo_verify unit tests (covers ceyo_verify/verifier.py)
# ---------------------------------------------------------------------------

class TestStandaloneVerifier(TestCase):
    """Unit tests for ceyo_verify.verifier directly."""

    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.body = {
            "event": {
                "event_id": "evt_sv_001",
                "type": "test",
                "occurred_at": "2026-01-01T00:00:00Z",
            },
        }

    def _env(self):
        return seal_body(self.body, self.kp)

    def test_valid_artifact_passes(self):
        result = standalone_verify(self._env(), self.kp.get_public_key_pem())
        self.assertTrue(result.ok)
        self.assertEqual(len(result.failed), 0)

    def test_bool_true_on_ok(self):
        result = standalone_verify(self._env(), self.kp.get_public_key_pem())
        self.assertTrue(bool(result))

    def test_bool_false_on_fail(self):
        env = self._env()
        env["body"]["event"]["type"] = "tampered"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(bool(result))

    def test_repr_includes_status(self):
        result = standalone_verify(self._env(), self.kp.get_public_key_pem())
        self.assertIn("PASSED", repr(result))

    def test_missing_required_field(self):
        env = self._env()
        del env["integrity"]
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_wrong_product(self):
        env = self._env()
        env["product"] = "OTHER"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_artifact_id_prefix(self):
        env = self._env()
        env["artifact_id"] = "wrong_prefix_id"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_hash_alg(self):
        env = self._env()
        env["integrity"]["hash"]["alg"] = "MD5"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_sig_alg(self):
        env = self._env()
        env["integrity"]["sig"]["alg"] = "RSA"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_sig_format(self):
        env = self._env()
        env["integrity"]["sig"]["format"] = "RAW"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_bad_canon_scope(self):
        env = self._env()
        env["canonicalization"]["scope"] = "full"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_tampered_body_fails(self):
        env = self._env()
        env["body"]["event"]["type"] = "tampered"
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("Hash" in m or "mismatch" in m for m in result.failed))

    def test_bad_signature_fails(self):
        env = self._env()
        env["integrity"]["sig"]["value_b64u"] = b64u(b"\x00" * 64)
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_wrong_key_fails(self):
        env = self._env()
        wrong_kp = InMemoryKeyProvider()
        result = standalone_verify(env, wrong_kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_fingerprint_mismatch(self):
        env = self._env()
        wrong_kp = InMemoryKeyProvider()
        env["key_reference"]["public_key_fingerprint"]["value_b64u"] = wrong_kp.fingerprint()
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertFalse(result.ok)

    def test_skip_fingerprint_check(self):
        env = self._env()
        env["key_reference"]["public_key_fingerprint"]["value_b64u"] = b64u(b"\x00" * 32)
        result = standalone_verify(env, self.kp.get_public_key_pem(), check_fingerprint=False)
        self.assertTrue(result.ok)

    def test_skip_schema_check(self):
        env = self._env()
        result = standalone_verify(env, self.kp.get_public_key_pem(), check_schema=False)
        self.assertTrue(result.ok)

    def test_non_dict_root_fails(self):
        from ceyo_verify.verifier import _check_envelope
        errors = _check_envelope([])  # type: ignore[arg-type]
        self.assertTrue(len(errors) > 0)

    def test_bad_pem_fails(self):
        env = self._env()
        result = standalone_verify(env, b"not-a-pem")
        self.assertFalse(result.ok)
        self.assertTrue(any("Key load" in m for m in result.failed))

    def test_deterministic_json_fallback(self):
        """Verifier handles deterministic-json-fallback scheme."""
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives.asymmetric import utils as _utils

        from ceyo_verify.verifier import _canonicalize

        env = self._env()
        env["canonicalization"]["scheme"] = "deterministic-json-fallback"
        # Recompute hash and sig for the fallback scheme
        canon = _canonicalize(env["body"], "deterministic-json-fallback")
        digest = hashlib.sha256(canon).digest()
        env["integrity"]["hash"]["value_b64u"] = b64u(digest)
        sig = self.kp.get_private_key().sign(
            digest,
            _ec.ECDSA(_utils.Prehashed(_hashes.SHA256())),
        )
        env["integrity"]["sig"]["value_b64u"] = b64u(sig)
        result = standalone_verify(env, self.kp.get_public_key_pem())
        self.assertTrue(result.ok)


# ---------------------------------------------------------------------------
# Transparency log
# ---------------------------------------------------------------------------

from ceyo.transparency_log import (
    TransparencyLog,
    compute_inclusion_proof,
    compute_root,
    _leaf_hash,
    _node_hash,
)
from ceyo_verify.transparency import verify_inclusion_proof


class TestMerkleTree(TestCase):
    """Unit tests for the Merkle tree primitives."""

    def test_empty_tree(self):
        root = compute_root([])
        self.assertEqual(root, sha256(b"ceyo:empty-tree"))

    def test_single_leaf(self):
        leaf = sha256(b"single")
        self.assertEqual(compute_root([leaf]), leaf)

    def test_two_leaves(self):
        a = sha256(b"a")
        b_ = sha256(b"b")
        expected = _node_hash(a, b_)
        self.assertEqual(compute_root([a, b_]), expected)

    def test_three_leaves_odd_promotion(self):
        a, b_, c = sha256(b"a"), sha256(b"b"), sha256(b"c")
        root = compute_root([a, b_, c])
        # Level 1: [node(a,b), c_promoted]
        # Root: node(node(a,b), c)
        expected = _node_hash(_node_hash(a, b_), c)
        self.assertEqual(root, expected)

    def test_four_leaves(self):
        leaves = [sha256(bytes([i])) for i in range(4)]
        root = compute_root(leaves)
        l1 = _node_hash(leaves[0], leaves[1])
        l2 = _node_hash(leaves[2], leaves[3])
        expected = _node_hash(l1, l2)
        self.assertEqual(root, expected)

    def test_deterministic(self):
        leaves = [sha256(bytes([i])) for i in range(7)]
        self.assertEqual(compute_root(leaves), compute_root(leaves))

    def test_inclusion_proof_single(self):
        leaf = _leaf_hash(sha256(b"x"))
        # Tree of 1: no siblings needed
        proof = compute_inclusion_proof(0, [leaf])
        self.assertEqual(proof, [])

    def test_inclusion_proof_two_leaves(self):
        a = _leaf_hash(sha256(b"a"))
        b_ = _leaf_hash(sha256(b"b"))
        # Proof for index 0: sibling is b (right)
        proof = compute_inclusion_proof(0, [a, b_])
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0][0], "right")
        self.assertEqual(proof[0][1], b_)
        # Proof for index 1: sibling is a (left)
        proof2 = compute_inclusion_proof(1, [a, b_])
        self.assertEqual(proof2[0][0], "left")
        self.assertEqual(proof2[0][1], a)

    def test_inclusion_proof_roundtrip(self):
        """Verify that recomputing root from proof matches compute_root."""
        leaves = [_leaf_hash(sha256(bytes([i]))) for i in range(8)]
        root = compute_root(leaves)
        for idx in range(len(leaves)):
            proof_steps = compute_inclusion_proof(idx, leaves)
            current = leaves[idx]
            for direction, sibling in proof_steps:
                if direction == "right":
                    current = _node_hash(current, sibling)
                else:
                    current = _node_hash(sibling, current)
            self.assertEqual(current, root, f"Proof failed for index {idx}")

    def test_inclusion_proof_odd_tree(self):
        """Inclusion proof still reconstructs root for trees with odd counts."""
        for n in (3, 5, 7):
            leaves = [_leaf_hash(sha256(bytes([i]))) for i in range(n)]
            root = compute_root(leaves)
            for idx in range(n):
                steps = compute_inclusion_proof(idx, leaves)
                cur = leaves[idx]
                for direction, sib in steps:
                    cur = _node_hash(cur, sib) if direction == "right" else _node_hash(sib, cur)
                self.assertEqual(cur, root, f"n={n}, idx={idx}")

    def test_inclusion_proof_empty_raises(self):
        with self.assertRaises(ValueError):
            compute_inclusion_proof(0, [])

    def test_inclusion_proof_out_of_range_raises(self):
        leaf = _leaf_hash(sha256(b"x"))
        with self.assertRaises(IndexError):
            compute_inclusion_proof(5, [leaf])


class TestTransparencyLog(TestCase):
    """Integration tests for TransparencyLog."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_log.db")
        self.kp = InMemoryKeyProvider()
        self.log = TransparencyLog(self.db_path, self.kp)

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmpdir)

    def _make_artifact(self):
        return seal(
            event_id=f"evt_{os.urandom(8).hex()}",
            event_type="test",
            occurred_at="2026-03-13T12:00:00Z",
            key_provider=self.kp,
        )

    def test_append_returns_entry(self):
        art = self._make_artifact()
        entry = self.log.append(art)
        self.assertEqual(entry["artifact_id"], art["artifact_id"])
        self.assertEqual(entry["seq"], 1)
        self.assertIn("artifact_hash", entry)
        self.assertIn("leaf_hash", entry)
        self.assertIn("logged_at", entry)

    def test_tree_size(self):
        self.assertEqual(self.log.tree_size(), 0)
        self.log.append(self._make_artifact())
        self.assertEqual(self.log.tree_size(), 1)
        self.log.append(self._make_artifact())
        self.assertEqual(self.log.tree_size(), 2)

    def test_root_hash_changes_on_append(self):
        root0 = self.log.root_hash()
        self.log.append(self._make_artifact())
        root1 = self.log.root_hash()
        self.assertNotEqual(root0, root1)

    def test_get_entry(self):
        art = self._make_artifact()
        self.log.append(art)
        entry = self.log.get_entry(art["artifact_id"])
        self.assertIsNotNone(entry)
        self.assertEqual(entry["artifact_id"], art["artifact_id"])

    def test_get_entry_missing(self):
        self.assertIsNone(self.log.get_entry("ceyo_art_nonexistent"))

    def test_duplicate_append_raises(self):
        art = self._make_artifact()
        self.log.append(art)
        with self.assertRaises(Exception):  # UNIQUE constraint
            self.log.append(art)

    def test_missing_artifact_id_raises(self):
        with self.assertRaises(ValueError):
            self.log.append({"body": "no id"})

    def test_list_entries(self):
        arts = [self._make_artifact() for _ in range(3)]
        for a in arts:
            self.log.append(a)
        entries = self.log.list_entries(limit=10)
        self.assertEqual(len(entries), 3)
        # Should be in reverse order (newest first)
        self.assertEqual(entries[0]["seq"], 3)

    def test_checkpoint_structure(self):
        self.log.append(self._make_artifact())
        cp = self.log.checkpoint()
        self.assertEqual(cp["product"], "CEYO")
        self.assertEqual(cp["type"], "transparency-checkpoint")
        self.assertEqual(cp["tree_size"], 1)
        self.assertIn("root_hash", cp)
        self.assertIn("created_at", cp)
        self.assertIn("sig", cp)
        self.assertEqual(cp["sig"]["alg"], "ECDSA-P256-SHA256")
        self.assertIn("key_reference", cp)

    def test_checkpoint_signature_valid(self):
        self.log.append(self._make_artifact())
        cp = self.log.checkpoint()
        pub_pem = self.kp.get_public_key_pem()
        # Verify via standalone transparency verifier
        art = self._make_artifact()
        self.log.append(art)
        proof = self.log.prove_inclusion(art["artifact_id"])
        cp2 = self.log.checkpoint()
        result = verify_inclusion_proof(proof, cp2, pub_pem)
        self.assertTrue(result.ok, result.failed)

    def test_latest_checkpoint_none(self):
        self.assertIsNone(self.log.latest_checkpoint())

    def test_latest_checkpoint_returns_last(self):
        self.log.append(self._make_artifact())
        cp1 = self.log.checkpoint()
        self.log.append(self._make_artifact())
        cp2 = self.log.checkpoint()
        latest = self.log.latest_checkpoint()
        self.assertEqual(latest["tree_size"], cp2["tree_size"])

    def test_prove_inclusion_structure(self):
        arts = [self._make_artifact() for _ in range(4)]
        for a in arts:
            self.log.append(a)
        proof = self.log.prove_inclusion(arts[0]["artifact_id"])
        self.assertEqual(proof["artifact_id"], arts[0]["artifact_id"])
        self.assertEqual(proof["leaf_index"], 0)
        self.assertEqual(proof["tree_size"], 4)
        self.assertIn("root_hash", proof)
        self.assertIn("hashes", proof)

    def test_prove_inclusion_missing_raises(self):
        with self.assertRaises(KeyError):
            self.log.prove_inclusion("ceyo_art_nonexistent")

    def test_context_manager(self):
        art = self._make_artifact()
        db2 = os.path.join(self.tmpdir, "ctx.db")
        with TransparencyLog(db2, self.kp) as log2:
            log2.append(art)
            self.assertEqual(log2.tree_size(), 1)


class TestInclusionProofVerification(TestCase):
    """Test standalone inclusion-proof verification via ceyo_verify.transparency."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "vlog.db")
        self.kp = InMemoryKeyProvider()
        self.log = TransparencyLog(self.db_path, self.kp)

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmpdir)

    def _make_and_log(self):
        art = seal(
            event_id=f"evt_{os.urandom(8).hex()}",
            event_type="test",
            occurred_at="2026-03-13T12:00:00Z",
            key_provider=self.kp,
        )
        self.log.append(art)
        return art

    def test_proof_only_passes(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        result = verify_inclusion_proof(proof)
        self.assertTrue(result.ok, result.failed)
        self.assertIn("Merkle root matches", result.passed)

    def test_proof_with_checkpoint_passes(self):
        art = self._make_and_log()
        cp = self.log.checkpoint()
        proof = self.log.prove_inclusion(art["artifact_id"])
        pub_pem = self.kp.get_public_key_pem()
        result = verify_inclusion_proof(proof, cp, pub_pem)
        self.assertTrue(result.ok, result.failed)
        self.assertIn("Checkpoint signature valid", result.passed)
        self.assertIn("Proof root matches checkpoint root", result.passed)
        self.assertIn("Proof tree_size matches checkpoint", result.passed)

    def test_proof_with_artifact_passes(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        result = verify_inclusion_proof(proof, artifact=art)
        self.assertTrue(result.ok, result.failed)
        self.assertIn("Artifact hash matches envelope", result.passed)

    def test_tampered_artifact_hash_fails(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        proof["artifact_hash"] = b64u(sha256(b"tampered"))
        result = verify_inclusion_proof(proof)
        self.assertFalse(result.ok)

    def test_tampered_sibling_hash_fails(self):
        for _ in range(3):
            self._make_and_log()
        arts = [self._make_and_log() for _ in range(1)]
        proof = self.log.prove_inclusion(arts[0]["artifact_id"])
        if proof["hashes"]:
            proof["hashes"][0]["value_b64u"] = b64u(sha256(b"bad"))
        result = verify_inclusion_proof(proof)
        self.assertFalse(result.ok)

    def test_wrong_checkpoint_pubkey_fails(self):
        art = self._make_and_log()
        cp = self.log.checkpoint()
        proof = self.log.prove_inclusion(art["artifact_id"])
        wrong_kp = InMemoryKeyProvider()
        result = verify_inclusion_proof(proof, cp, wrong_kp.get_public_key_pem())
        self.assertFalse(result.ok)
        self.assertTrue(any("Checkpoint signature invalid" in f for f in result.failed))

    def test_checkpoint_root_mismatch_fails(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        cp = self.log.checkpoint()
        # Mutate checkpoint root after signing
        cp["root_hash"] = b64u(sha256(b"wrong_root"))
        pub_pem = self.kp.get_public_key_pem()
        result = verify_inclusion_proof(proof, cp, pub_pem)
        self.assertFalse(result.ok)

    def test_checkpoint_tree_size_mismatch_fails(self):
        art = self._make_and_log()
        cp = self.log.checkpoint()
        proof = self.log.prove_inclusion(art["artifact_id"])
        proof["tree_size"] = 999  # tamper
        pub_pem = self.kp.get_public_key_pem()
        result = verify_inclusion_proof(proof, cp, pub_pem)
        self.assertFalse(result.ok)

    def test_missing_proof_fields_fails(self):
        result = verify_inclusion_proof({"artifact_id": "x"})
        self.assertFalse(result.ok)
        self.assertTrue(any("Proof missing field" in f for f in result.failed))

    def test_checkpoint_without_pubkey_fails(self):
        art = self._make_and_log()
        cp = self.log.checkpoint()
        proof = self.log.prove_inclusion(art["artifact_id"])
        result = verify_inclusion_proof(proof, cp)  # no pubkey
        self.assertFalse(result.ok)

    def test_many_artifacts_all_proofs_valid(self):
        arts = [self._make_and_log() for _ in range(10)]
        cp = self.log.checkpoint()
        pub_pem = self.kp.get_public_key_pem()
        for art in arts:
            proof = self.log.prove_inclusion(art["artifact_id"])
            result = verify_inclusion_proof(proof, cp, pub_pem)
            self.assertTrue(result.ok, f"{art['artifact_id']}: {result.failed}")

    def test_verification_result_repr(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        result = verify_inclusion_proof(proof)
        self.assertIn("PASSED", repr(result))

    def test_verification_result_bool(self):
        art = self._make_and_log()
        proof = self.log.prove_inclusion(art["artifact_id"])
        result = verify_inclusion_proof(proof)
        self.assertTrue(bool(result))


class TestTransparencyLogClientIntegration(TestCase):
    """Test CeyoClient with optional TransparencyLog."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "client_log.db")
        self.kp = InMemoryKeyProvider()
        self.log = TransparencyLog(self.db_path, self.kp)
        self.client = CeyoClient(key_provider=self.kp, log=self.log)

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.tmpdir)

    def _body(self):
        return {
            "event": {
                "event_id": f"evt_{os.urandom(8).hex()}",
                "type": "inference",
                "occurred_at": "2026-03-13T12:00:00Z",
            },
            "disclosure_tier": "internal",
        }

    def test_seal_auto_logs(self):
        self.client.seal(self._body())
        self.assertEqual(self.log.tree_size(), 1)

    def test_seal_multiple_logged(self):
        for _ in range(5):
            self.client.seal(self._body())
        self.assertEqual(self.log.tree_size(), 5)

    def test_seal_no_persist_skips_log(self):
        self.client.seal(self._body(), persist=False)
        self.assertEqual(self.log.tree_size(), 0)

    def test_proof_verifiable_after_client_seal(self):
        env = self.client.seal(self._body())
        cp = self.log.checkpoint()
        proof = self.log.prove_inclusion(env["artifact_id"])
        pub_pem = self.kp.get_public_key_pem()
        result = verify_inclusion_proof(proof, cp, pub_pem)
        self.assertTrue(result.ok, result.failed)

    def test_client_without_log_unchanged(self):
        client_no_log = CeyoClient(key_provider=self.kp)
        self.assertIsNone(client_no_log.log)
        body = self._body()
        env = client_no_log.seal(body)
        self.assertIn("artifact_id", env)


if __name__ == "__main__":
    main()
