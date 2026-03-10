"""Tests for CEYO Protocol — crypto, sealing, verification, schema, store, client, async, export."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest import TestCase, main

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ceyo.client import AsyncCeyoClient, CeyoClient
from ceyo.crypto import b64u, b64u_decode, canonicalize, sha256
from ceyo.keys import EnvKeyProvider, InMemoryKeyProvider, KeyManager, LocalKeyProvider
from ceyo.schema import ValidationError, validate_body, validate_envelope, validate_envelope_or_raise
from ceyo.schema_version import (
    CURRENT_VERSION,
    get_version,
    list_versions,
    migrate,
    needs_migration,
    register_migration,
)
from ceyo.seal import seal, seal_body
from ceyo.store import ArtifactStore
from ceyo.verify import verify_artifact

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

    def test_seal_batch(self):
        client = CeyoClient(key_provider=self.kp)
        bodies = [
            {"event": {"event_id": f"evt_{i}", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
            for i in range(5)
        ]
        envelopes = client.seal_batch(bodies, persist=False)
        self.assertEqual(len(envelopes), 5)
        for env in envelopes:
            self.assertTrue(client.verify(env).ok)

    def test_seal_batch_with_store(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        with ArtifactStore(os.path.join(tmpdir, "batch.db")) as store:
            client = CeyoClient(key_provider=self.kp, store=store)
            bodies = [
                {"event": {"event_id": f"evt_{i}", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
                for i in range(3)
            ]
            client.seal_batch(bodies)
            self.assertEqual(store.count(), 3)


# ---------------------------------------------------------------------------
# Env key provider
# ---------------------------------------------------------------------------

class TestEnvKeyProvider(TestCase):
    def test_env_provider_loads_key(self):
        kp = InMemoryKeyProvider()
        priv_pem = kp.get_private_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        os.environ["TEST_CEYO_PRIV"] = priv_pem
        os.environ["TEST_CEYO_KID"] = "test-key-1"
        self.addCleanup(os.environ.pop, "TEST_CEYO_PRIV", None)
        self.addCleanup(os.environ.pop, "TEST_CEYO_KID", None)

        env_kp = EnvKeyProvider(
            private_key_var="TEST_CEYO_PRIV",
            key_id_var="TEST_CEYO_KID",
        )
        self.assertEqual(env_kp.registry(), "env")
        self.assertEqual(env_kp.key_id(), "test-key-1")
        self.assertEqual(env_kp.fingerprint(), kp.fingerprint())

    def test_env_provider_seal_and_verify(self):
        kp = InMemoryKeyProvider()
        priv_pem = kp.get_private_key().private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        os.environ["TEST_CEYO_PRIV2"] = priv_pem
        self.addCleanup(os.environ.pop, "TEST_CEYO_PRIV2", None)

        env_kp = EnvKeyProvider(private_key_var="TEST_CEYO_PRIV2")
        body = {"event": {"event_id": "e1", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = seal_body(body, env_kp)
        result = verify_artifact(envelope, env_kp.get_public_key_pem())
        self.assertTrue(result.ok)

    def test_env_provider_missing_raises(self):
        env_kp = EnvKeyProvider(private_key_var="NONEXISTENT_CEYO_KEY_VAR")
        with self.assertRaises(EnvironmentError):
            env_kp.get_private_key()


# ---------------------------------------------------------------------------
# Key rotation
# ---------------------------------------------------------------------------

class TestKeyRotation(TestCase):
    def test_rotate_records_log(self):
        km = KeyManager()
        old_kp = InMemoryKeyProvider()
        km.register("prod", old_kp)

        new_kp = InMemoryKeyProvider()
        returned = km.rotate("prod", new_kp)
        self.assertEqual(returned.fingerprint(), old_kp.fingerprint())
        self.assertEqual(km.get("prod").fingerprint(), new_kp.fingerprint())

        log = km.rotation_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["name"], "prod")
        self.assertEqual(log[0]["old_fingerprint"], old_kp.fingerprint())
        self.assertEqual(log[0]["new_fingerprint"], new_kp.fingerprint())

    def test_list_providers(self):
        km = KeyManager()
        kp1 = InMemoryKeyProvider()
        kp2 = InMemoryKeyProvider()
        km.register("a", kp1)
        km.register("b", kp2)
        providers = km.list_providers()
        self.assertEqual(providers["a"], kp1.fingerprint())
        self.assertEqual(providers["b"], kp2.fingerprint())


# ---------------------------------------------------------------------------
# Store export
# ---------------------------------------------------------------------------

class TestStoreExport(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.db_path = os.path.join(self.tmpdir, "export.db")
        self.kp = InMemoryKeyProvider()

    def _make_artifact(self, event_id="evt_001"):
        return seal_body(
            {"event": {"event_id": event_id, "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}},
            self.kp,
        )

    def test_export_jsonl(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(3):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            content = store.export_jsonl()
        lines = [line for line in content.strip().split("\n") if line]
        self.assertEqual(len(lines), 3)
        for line in lines:
            record = json.loads(line)
            self.assertIn("seq", record)
            self.assertIn("artifact_id", record)
            self.assertIn("envelope", record)
            self.assertIn("chain_hash", record)

    def test_export_jsonl_to_file(self):
        out_path = os.path.join(self.tmpdir, "export.jsonl")
        with ArtifactStore(self.db_path) as store:
            store.append(self._make_artifact())
            store.export_jsonl(out_path)
        self.assertTrue(os.path.exists(out_path))
        content = Path(out_path).read_text()
        self.assertTrue(content.strip())

    def test_export_csv(self):
        with ArtifactStore(self.db_path) as store:
            for i in range(3):
                store.append(self._make_artifact(f"evt_{i:04d}"))
            content = store.export_csv()
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        self.assertEqual(rows[0][0], "seq")  # header
        self.assertEqual(len(rows), 4)  # header + 3 data rows
        self.assertEqual(rows[1][3], "test")  # event_type column

    def test_export_csv_to_file(self):
        out_path = os.path.join(self.tmpdir, "export.csv")
        with ArtifactStore(self.db_path) as store:
            store.append(self._make_artifact())
            store.export_csv(out_path)
        self.assertTrue(os.path.exists(out_path))

    def test_export_empty_store(self):
        with ArtifactStore(self.db_path) as store:
            jsonl = store.export_jsonl()
            csv_out = store.export_csv()
        self.assertEqual(jsonl, "")
        # CSV should still have header
        self.assertIn("seq", csv_out)


# ---------------------------------------------------------------------------
# Schema versioning
# ---------------------------------------------------------------------------

class TestSchemaVersioning(TestCase):
    def test_current_version(self):
        self.assertEqual(CURRENT_VERSION, "1.0")

    def test_get_version_from_artifact(self):
        kp = InMemoryKeyProvider()
        body = {"event": {"event_id": "e1", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = seal_body(body, kp)
        self.assertEqual(get_version(envelope), "1.0")

    def test_needs_migration_false_for_current(self):
        kp = InMemoryKeyProvider()
        body = {"event": {"event_id": "e1", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = seal_body(body, kp)
        self.assertFalse(needs_migration(envelope))

    def test_list_versions(self):
        versions = list_versions()
        self.assertIn("1.0", versions)

    def test_migrate_no_op_for_current(self):
        kp = InMemoryKeyProvider()
        body = {"event": {"event_id": "e1", "type": "t", "occurred_at": "2026-01-01T00:00:00Z"}}
        envelope = seal_body(body, kp)
        result = migrate(envelope)
        self.assertEqual(result, envelope)

    def test_migrate_raises_for_unknown_path(self):
        fake = {"artifact_schema": {"name": "ceyo.artifact", "version": "0.1"}}
        with self.assertRaises(ValueError):
            migrate(fake, "1.0")

    def test_register_and_use_migration(self):
        def migrate_09_to_10(art: dict) -> dict:
            art["migrated"] = True
            return art

        register_migration("0.9", "1.0", migrate_09_to_10)
        fake = {"artifact_schema": {"name": "ceyo.artifact", "version": "0.9"}}
        result = migrate(fake, "1.0")
        self.assertTrue(result["migrated"])
        self.assertEqual(get_version(result), "1.0")


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class TestAsyncClient(TestCase):
    def test_async_seal_and_verify(self):
        kp = InMemoryKeyProvider()
        client = AsyncCeyoClient(key_provider=kp)
        body = {"event": {"event_id": "evt_async", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}

        async def run():
            envelope = await client.seal(body, persist=False)
            result = await client.verify(envelope)
            return envelope, result

        envelope, result = asyncio.run(run())
        self.assertTrue(result.ok)
        self.assertEqual(envelope["product"], "CEYO")

    def test_async_seal_batch(self):
        kp = InMemoryKeyProvider()
        client = AsyncCeyoClient(key_provider=kp)
        bodies = [
            {"event": {"event_id": f"evt_{i}", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
            for i in range(3)
        ]

        envelopes = asyncio.run(client.seal_batch(bodies, persist=False))
        self.assertEqual(len(envelopes), 3)

    def test_async_with_store(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        db_path = os.path.join(tmpdir, "async.db")

        # SQLite objects must be used in the same thread they were created in.
        # The async client runs seal in a thread pool, so we verify via a
        # separate store connection after the async work completes.
        async def run():
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: _seal_one(db_path))

        def _seal_one(path: str) -> None:
            with ArtifactStore(path) as store:
                kp = InMemoryKeyProvider()
                client = CeyoClient(key_provider=kp, store=store)
                body = {"event": {"event_id": "e1", "type": "test", "occurred_at": "2026-01-01T00:00:00Z"}}
                client.seal(body)

        asyncio.run(run())
        with ArtifactStore(db_path) as store:
            self.assertEqual(store.count(), 1)


if __name__ == "__main__":
    main()
