"""Security, compatibility, and integration tests for CEYO Protocol v2."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import tempfile
import warnings
from argparse import Namespace
from pathlib import Path
from unittest import TestCase, main

from cryptography.hazmat.primitives.asymmetric import ec

from ceyo.client import CeyoClient
from ceyo.crypto import b64u, b64u_decode, canon_scheme, canonicalize, sha256
from ceyo.keys import InMemoryKeyProvider, KeyManager, LocalKeyProvider
from ceyo.schema import (
    ValidationError,
    is_v2_envelope,
    validate_body,
    validate_body_or_raise,
    validate_envelope,
    validate_envelope_or_raise,
)
from ceyo.seal import seal, seal_body, seal_body_v1
from ceyo.store import ArtifactStore
from ceyo.transparency_log import (
    TransparencyLog,
    _leaf_hash,
    _node_hash,
    artifact_log_digest,
    artifact_log_subject,
    compute_inclusion_proof,
    compute_root,
)
from ceyo.verify import verify_artifact
from ceyo_verify import verify_artifact as standalone_verify
from ceyo_verify.transparency import verify_inclusion_proof


def make_body(event_id: str = "evt_test") -> dict:
    return {
        "event": {
            "event_id": event_id,
            "type": "classification",
            "occurred_at": "2026-09-15T12:00:00Z",
            "request_id": "req_test",
        },
        "policy": {
            "id": "capture-policy",
            "version": "1.0",
            "digest": {
                "alg": "SHA-256",
                "value_b64u": b64u(sha256(b"capture-policy-v1")),
                "covers": "policy_document_bytes",
            },
        },
        "capture": {
            "input_ref_hash": {
                "alg": "SHA-256",
                "value_b64u": b64u(sha256(b"input")),
                "covers": "policy_scoped_input_representation",
            },
            "output_ref_hash": {
                "alg": "SHA-256",
                "value_b64u": b64u(sha256(b"output")),
                "covers": "policy_scoped_output_representation",
            },
        },
        "disclosure_policy": {
            "tier": "internal",
            "policy_id": "disclosure-policy",
            "policy_version": "1.0",
        },
        "environment": {
            "deployment_id": "test-deployment",
            "model_ref": "opaque-model-ref",
            "nested": {"zone": "a", "labels": ["one", "two"]},
        },
    }


def artifact_id(artifact: dict) -> str:
    if "protected" in artifact:
        return artifact["protected"]["artifact_id"]
    return artifact["artifact_id"]


class TestCrypto(TestCase):
    def test_b64u_roundtrip_and_strict_decode(self):
        value = b"hello\x00ceyo"
        encoded = b64u(value)
        self.assertEqual(b64u_decode(encoded), value)
        self.assertNotIn("=", encoded)
        for invalid in ("", "%%", "é"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                b64u_decode(invalid)

    def test_sha256(self):
        self.assertEqual(sha256(b"ceyo"), hashlib.sha256(b"ceyo").digest())
        self.assertEqual(len(sha256(b"x")), 32)

    def test_rfc8785_is_normative_current_scheme(self):
        self.assertEqual(canon_scheme(), "RFC8785")

    def test_nested_canonicalization_is_deterministic(self):
        left = {
            "z": [3, {"b": "é", "a": 1}],
            "a": {"y": True, "x": None},
        }
        right = {
            "a": {"x": None, "y": True},
            "z": [3, {"a": 1, "b": "é"}],
        }
        self.assertEqual(canonicalize(left), canonicalize(right))
        self.assertNotIn(b" ", canonicalize({"z": 1, "a": 2}))


class TestKeys(TestCase):
    def test_in_memory_provider_and_reference(self):
        kp = InMemoryKeyProvider()
        self.assertIsInstance(kp.get_private_key(), ec.EllipticCurvePrivateKey)
        self.assertEqual(kp.registry(), "memory")
        self.assertTrue(kp.key_id().startswith("memory:"))
        self.assertIn(b"BEGIN PUBLIC KEY", kp.get_public_key_pem())
        ref = kp.key_reference()
        self.assertEqual(ref["registry"], "memory")
        self.assertEqual(
            ref["public_key_fingerprint"]["value_b64u"],
            kp.fingerprint(),
        )

    def test_local_provider_create_reload_and_permissions(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        private = Path(tmp) / "private.pem"
        public = Path(tmp) / "public.pem"
        first = LocalKeyProvider(private, public)
        fingerprint = first.fingerprint()
        self.assertTrue(private.exists())
        self.assertTrue(public.exists())
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(first.public_key_path, public)
        second = LocalKeyProvider(private, public)
        self.assertEqual(second.fingerprint(), fingerprint)

    def test_key_manager(self):
        manager = KeyManager()
        with self.assertRaises(KeyError):
            manager.default()
        with self.assertRaises(KeyError):
            manager.get("missing")
        kp = InMemoryKeyProvider()
        manager.register("primary", kp)
        self.assertIs(manager.get("primary"), kp)
        self.assertIs(manager.default(), kp)


class TestSchema(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.v2 = seal_body(make_body(), self.kp)
        self.v1 = seal_body_v1(make_body(), self.kp)

    def test_current_and_legacy_schema_valid(self):
        self.assertTrue(is_v2_envelope(self.v2))
        self.assertFalse(is_v2_envelope(self.v1))
        self.assertEqual(validate_envelope(self.v2), [])
        self.assertEqual(validate_envelope(self.v1), [])
        validate_envelope_or_raise(self.v2)
        validate_envelope_or_raise(self.v1)

    def test_body_validation(self):
        self.assertEqual(validate_body(make_body()), [])
        validate_body_or_raise(make_body())
        for bad in (
            {},
            {"event": {}},
            {"event": {"event_id": "e", "type": "t", "occurred_at": "bad"}},
        ):
            with self.subTest(bad=bad):
                self.assertTrue(validate_body(bad))
        with self.assertRaises(ValidationError):
            validate_body_or_raise({})

    def test_v2_requires_exact_top_level_shape(self):
        for field in ("protected", "integrity", "receipts"):
            artifact = copy.deepcopy(self.v2)
            del artifact[field]
            with self.subTest(field=field):
                self.assertTrue(validate_envelope(artifact))
        artifact = copy.deepcopy(self.v2)
        artifact["extra"] = True
        self.assertTrue(validate_envelope(artifact))

    def test_every_protected_field_is_required(self):
        for field in tuple(self.v2["protected"]):
            artifact = copy.deepcopy(self.v2)
            del artifact["protected"][field]
            with self.subTest(field=field):
                self.assertTrue(validate_envelope(artifact))

    def test_v2_rejects_version_suite_id_and_time_drift(self):
        mutations = (
            ("protocol_version", "3.0"),
            ("artifact_id", "bad"),
            ("sealed_at", "not-a-date"),
            ("canonicalization_suite", {"scheme": "other", "version": "1.0"}),
            (
                "signing_suite",
                {"alg": "ECDSA-P256-SHA256", "format": "DER", "hash": "SHA-512"},
            ),
        )
        for field, value in mutations:
            artifact = copy.deepcopy(self.v2)
            artifact["protected"][field] = value
            with self.subTest(field=field):
                self.assertTrue(validate_envelope(artifact))

    def test_v2_rejects_non_rfc8785_suite(self):
        artifact = copy.deepcopy(self.v2)
        artifact["protected"]["canonicalization_suite"] = {
            "scheme": "deterministic-json-fallback",
            "version": "1.0",
        }
        self.assertTrue(validate_envelope(artifact))

    def test_receipts_must_be_array_of_objects(self):
        artifact = copy.deepcopy(self.v2)
        artifact["receipts"] = "bad"
        self.assertTrue(validate_envelope(artifact))
        artifact = copy.deepcopy(self.v2)
        artifact["receipts"] = ["bad"]
        self.assertTrue(validate_envelope(artifact))

    def test_validation_raise(self):
        artifact = copy.deepcopy(self.v2)
        artifact["protected"]["product"] = "OTHER"
        with self.assertRaises(ValidationError):
            validate_envelope_or_raise(artifact)


class TestProtocolV2SealVerify(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.body = make_body()
        self.public = self.kp.get_public_key_pem()

    def artifact(self):
        return seal_body(copy.deepcopy(self.body), self.kp)

    def test_shape_digest_and_dual_verification(self):
        artifact = self.artifact()
        self.assertEqual(set(artifact), {"protected", "integrity", "receipts"})
        self.assertEqual(artifact["protected"]["protocol_version"], "2.0")
        self.assertEqual(
            artifact["protected"]["canonicalization_suite"],
            {"scheme": "RFC8785", "version": "1.0"},
        )
        expected = sha256(canonicalize(artifact["protected"]))
        actual = b64u_decode(artifact["integrity"]["digest"]["value_b64u"])
        self.assertEqual(actual, expected)
        self.assertTrue(verify_artifact(artifact, self.public).ok)
        self.assertTrue(standalone_verify(artifact, self.public).ok)

    def test_artifact_ids_are_unique_and_valid_custom_id_is_supported(self):
        first = self.artifact()
        second = self.artifact()
        self.assertNotEqual(artifact_id(first), artifact_id(second))
        custom = "ceyo_art_0123456789abcdef0123456789"
        artifact = seal_body(self.body, self.kp, artifact_id=custom)
        self.assertEqual(artifact_id(artifact), custom)
        self.assertTrue(verify_artifact(artifact, self.public).ok)

    def test_invalid_custom_artifact_id_is_rejected_before_signing(self):
        for value in ("bad", "ceyo_art_custom", "ceyo_art_ABCDEF0123456789abcdef0123"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                seal_body(self.body, self.kp, artifact_id=value)

    def test_non_p256_signing_key_is_rejected(self):
        provider = InMemoryKeyProvider(ec.generate_private_key(ec.SECP384R1()))
        with self.assertRaises(ValueError):
            seal_body(self.body, provider)

    def test_convenience_builder(self):
        digest = {
            "alg": "SHA-256",
            "value_b64u": b64u(sha256(b"policy")),
            "covers": "policy_document_bytes",
        }
        artifact = seal(
            event_id="evt_convenience",
            event_type="inference",
            occurred_at="2026-09-15T12:00:00Z",
            request_id="req_convenience",
            policy_id="POL-1",
            policy_version="2.0",
            policy_digest=digest,
            disclosure_policy={"tier": "restricted"},
            capture={"x": {"nested": [1, 2, 3]}},
            environment={"deployment": "a"},
            key_provider=self.kp,
        )
        body = artifact["protected"]["body"]
        self.assertEqual(body["policy"]["digest"], digest)
        self.assertEqual(body["disclosure_policy"]["tier"], "restricted")
        self.assertTrue(verify_artifact(artifact, self.public).ok)

    def test_every_protected_top_level_field_is_integrity_bound(self):
        mutations = {
            "product": "OTHER",
            "protocol_version": "3.0",
            "artifact_schema": {"name": "ceyo.artifact", "version": "9.0"},
            "artifact_id": "ceyo_art_aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sealed_at": "2026-09-15T12:00:02Z",
            "canonicalization_suite": {"scheme": "RFC8785", "version": "9.0"},
            "signing_suite": {
                "alg": "ECDSA-P256-SHA256",
                "format": "DER",
                "hash": "SHA-512",
            },
            "key_reference": {
                "registry": "changed",
                "key_id": "changed",
                "public_key_fingerprint": self.kp.key_reference()[
                    "public_key_fingerprint"
                ],
            },
            "body": make_body("evt_changed"),
        }
        for field, replacement in mutations.items():
            artifact = self.artifact()
            artifact["protected"][field] = replacement
            with self.subTest(field=field):
                self.assertFalse(
                    verify_artifact(
                        artifact, self.public, check_schema=False
                    ).ok
                )

    def test_nested_mutation_matrix(self):
        paths = (
            ("body", "event", "type"),
            ("body", "policy", "digest", "value_b64u"),
            ("body", "disclosure_policy", "tier"),
            ("body", "capture", "input_ref_hash", "covers"),
            ("body", "environment", "nested", "zone"),
            ("key_reference", "key_id"),
        )
        for path in paths:
            artifact = self.artifact()
            target = artifact["protected"]
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = "tampered"
            with self.subTest(path=path):
                self.assertFalse(
                    verify_artifact(
                        artifact, self.public, check_schema=False
                    ).ok
                )

    def test_deleting_any_protected_field_fails(self):
        source = self.artifact()
        for field in tuple(source["protected"]):
            artifact = copy.deepcopy(source)
            del artifact["protected"][field]
            with self.subTest(field=field):
                self.assertFalse(verify_artifact(artifact, self.public).ok)
                self.assertFalse(standalone_verify(artifact, self.public).ok)

    def test_receipt_append_and_tamper_do_not_change_artifact_validity(self):
        artifact = self.artifact()
        self.assertTrue(verify_artifact(artifact, self.public).ok)
        artifact["receipts"].append(
            {"type": "unvalidated-example", "proof": {"value": "one"}}
        )
        self.assertTrue(verify_artifact(artifact, self.public).ok)
        artifact["receipts"][0]["proof"]["value"] = "changed"
        self.assertTrue(verify_artifact(artifact, self.public).ok)

    def test_wrong_key_digest_signature_and_fingerprint_fail(self):
        wrong = InMemoryKeyProvider()
        self.assertFalse(
            verify_artifact(self.artifact(), wrong.get_public_key_pem()).ok
        )

        artifact = self.artifact()
        artifact["integrity"]["digest"]["value_b64u"] = b64u(b"\x00" * 32)
        self.assertFalse(verify_artifact(artifact, self.public).ok)

        artifact = self.artifact()
        artifact["integrity"]["signature"]["value_b64u"] = b64u(b"bad")
        self.assertFalse(verify_artifact(artifact, self.public).ok)

        artifact = self.artifact()
        artifact["protected"]["key_reference"]["public_key_fingerprint"][
            "value_b64u"
        ] = b64u(b"\x00" * 32)
        # This also changes the signed protected object, so it must fail even if
        # the optional fingerprint consistency check is disabled.
        self.assertFalse(verify_artifact(artifact, self.public).ok)

    def test_schema_bypass_still_enforces_trust_critical_dispatch(self):
        cases = (
            ("protocol_version", "9.0"),
            ("artifact_schema", {"name": "other", "version": "1.0"}),
            (
                "canonicalization_suite",
                {"scheme": "deterministic-json-fallback", "version": "1.0"},
            ),
            (
                "signing_suite",
                {"alg": "OTHER", "format": "DER", "hash": "SHA-256"},
            ),
        )
        for field, value in cases:
            artifact = self.artifact()
            artifact["protected"][field] = value
            with self.subTest(field=field):
                self.assertFalse(
                    verify_artifact(
                        artifact, self.public, check_schema=False
                    ).ok
                )
                self.assertFalse(
                    standalone_verify(
                        artifact, self.public, check_schema=False
                    ).ok
                )

    def test_committed_golden_example_verifies(self):
        artifact = json.loads(
            Path("example_artifact/example_envelope.json").read_text(
                encoding="utf-8"
            )
        )
        public = Path("example_artifact/example_public_key.pem").read_bytes()
        self.assertEqual(
            artifact["integrity"]["digest"]["value_b64u"],
            "u_T5FYQ1qzRrQGn0-wN1aZrD1XInKieSzCeaJPyMQQM",
        )
        self.assertTrue(verify_artifact(artifact, public).ok)
        self.assertTrue(standalone_verify(artifact, public).ok)


class TestLegacyV1(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.artifact = seal_body_v1(make_body(), self.kp)
        self.public = self.kp.get_public_key_pem()

    def test_v1_verifies_with_legacy_scope_notice(self):
        sdk = verify_artifact(self.artifact, self.public)
        independent = standalone_verify(self.artifact, self.public)
        self.assertTrue(sdk.ok)
        self.assertTrue(independent.ok)
        self.assertTrue(any("Legacy v1 scope" in item for item in sdk.passed))

    def test_v1_body_is_bound_but_timestamp_and_key_id_are_not(self):
        artifact = copy.deepcopy(self.artifact)
        artifact["body"]["event"]["type"] = "tampered"
        self.assertFalse(verify_artifact(artifact, self.public).ok)

        artifact = copy.deepcopy(self.artifact)
        artifact["created_at"] = "2026-09-16T12:00:00Z"
        self.assertTrue(verify_artifact(artifact, self.public).ok)

        artifact = copy.deepcopy(self.artifact)
        artifact["key_reference"]["key_id"] = "changed-after-seal"
        self.assertTrue(verify_artifact(artifact, self.public).ok)

    def test_v1_fingerprint_is_a_separate_consistency_check(self):
        artifact = copy.deepcopy(self.artifact)
        artifact["key_reference"]["public_key_fingerprint"][
            "value_b64u"
        ] = b64u(b"\x00" * 32)
        self.assertFalse(verify_artifact(artifact, self.public).ok)
        self.assertTrue(
            verify_artifact(
                artifact, self.public, check_fingerprint=False
            ).ok
        )


class TestArtifactStore(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.db = os.path.join(self.tmp, "artifacts.db")
        self.kp = InMemoryKeyProvider()

    def make_artifact(self, suffix="a"):
        return seal_body(make_body(f"evt_store_{suffix}"), self.kp)

    def test_append_get_recent_export_count_and_legacy(self):
        with ArtifactStore(self.db) as store:
            first = self.make_artifact("one")
            seq = store.append(first)
            self.assertEqual(seq, 1)
            self.assertEqual(store.get(artifact_id(first)), first)
            self.assertEqual(store.get_by_seq(1), first)
            self.assertIsNone(store.get("missing"))
            self.assertIsNone(store.get_by_seq(999))
            for i in range(4):
                store.append(self.make_artifact(str(i)))
            legacy = seal_body_v1(make_body("evt_legacy_store"), self.kp)
            store.append(legacy)
            self.assertEqual(store.count(), 6)
            self.assertEqual(len(store.recent(3)), 3)
            self.assertEqual(len(store.export_rows()), 6)
            self.assertEqual(store.verify_chain(), (True, 6))

    def test_chain_detects_middle_tamper_but_local_tail_truncation_is_limit(self):
        with ArtifactStore(self.db) as store:
            for i in range(4):
                store.append(self.make_artifact(str(i)))
            store._conn.execute(
                "UPDATE artifacts SET entry_hash = 'tampered' WHERE seq = 3"
            )
            store._conn.commit()
            ok, checked = store.verify_chain()
            self.assertFalse(ok)
            self.assertEqual(checked, 2)

        other = os.path.join(self.tmp, "tail.db")
        with ArtifactStore(other) as store:
            for i in range(3):
                store.append(self.make_artifact(f"tail-{i}"))
            store._conn.execute("DELETE FROM artifacts WHERE seq = 3")
            store._conn.commit()
            self.assertEqual(store.verify_chain(), (True, 2))

    def test_missing_metadata_rejected(self):
        with ArtifactStore(self.db) as store:
            with self.assertRaises(ValueError):
                store.append({"protected": {"protocol_version": "2.0"}})
            with self.assertRaises(ValueError):
                store.append({})


class _FailingSink:
    def append(self, artifact):
        del artifact
        raise RuntimeError("sink down")


class TestClient(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()

    def test_client_seal_verify_and_default_warning(self):
        client = CeyoClient(key_provider=self.kp)
        artifact = client.seal(make_body(), persist=False)
        self.assertTrue(client.verify(artifact).ok)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            default_client = CeyoClient()
        self.assertIsInstance(default_client.key_provider, InMemoryKeyProvider)
        self.assertTrue(any("ephemeral" in str(item.message) for item in caught))

    def test_client_store_log_and_persist_false(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with ArtifactStore(os.path.join(tmp, "store.db")) as store:
            with TransparencyLog(os.path.join(tmp, "log.db"), self.kp) as log:
                client = CeyoClient(key_provider=self.kp, store=store, log=log)
                artifact = client.seal(make_body("evt_both"))
                self.assertEqual(store.count(), 1)
                self.assertEqual(log.tree_size(), 1)
                self.assertIsNotNone(log.get_entry(artifact_id(artifact)))
                client.seal(make_body("evt_skip"), persist=False)
                self.assertEqual(store.count(), 1)
                self.assertEqual(log.tree_size(), 1)

    def test_sink_failures_are_explicit(self):
        with self.assertRaisesRegex(RuntimeError, "persisted"):
            CeyoClient(key_provider=self.kp, store=_FailingSink()).seal(make_body())
        with self.assertRaisesRegex(RuntimeError, "transparency log"):
            CeyoClient(key_provider=self.kp, log=_FailingSink()).seal(make_body())

    def test_trace_decorator(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        with ArtifactStore(os.path.join(tmp, "trace.db")) as store:
            client = CeyoClient(key_provider=self.kp, store=store)

            @client.trace(event_type="sum", policy_id="POL-1")
            def add(a, b):
                return a + b

            @client.trace
            def greet(name):
                return f"hello {name}"

            self.assertEqual(add(2, 3), 5)
            self.assertEqual(greet("ceyo"), "hello ceyo")
            self.assertEqual(store.count(), 2)
            for artifact in store.recent(2):
                self.assertTrue(client.verify(artifact).ok)


class TestStandaloneVerifier(TestCase):
    def setUp(self):
        self.kp = InMemoryKeyProvider()
        self.artifact = seal_body(make_body(), self.kp)
        self.public = self.kp.get_public_key_pem()

    def test_result_protocol_and_load_helpers(self):
        result = standalone_verify(self.artifact, self.public)
        self.assertTrue(result)
        self.assertIn("PASSED", repr(result))
        self.assertEqual(result.failed, [])

        from ceyo_verify.verifier import load_artifact, load_pubkey

        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        artifact_path = Path(tmp) / "artifact.json"
        key_path = Path(tmp) / "public.pem"
        artifact_path.write_text(json.dumps(self.artifact), encoding="utf-8")
        key_path.write_bytes(self.public)
        self.assertEqual(load_artifact(str(artifact_path)), self.artifact)
        self.assertEqual(load_pubkey(str(key_path)), self.public)

    def test_wrong_key_bad_pem_extra_and_missing_fail(self):
        wrong = InMemoryKeyProvider()
        self.assertFalse(
            standalone_verify(self.artifact, wrong.get_public_key_pem()).ok
        )
        self.assertFalse(standalone_verify(self.artifact, b"not-pem").ok)

        artifact = copy.deepcopy(self.artifact)
        artifact["extra"] = 1
        self.assertFalse(standalone_verify(artifact, self.public).ok)
        artifact = copy.deepcopy(self.artifact)
        del artifact["integrity"]
        self.assertFalse(standalone_verify(artifact, self.public).ok)

    def test_schema_mutation_matrix(self):
        mutations = (
            (lambda a: a["protected"].__setitem__("product", "OTHER")),
            (lambda a: a["protected"].__setitem__("protocol_version", "9.0")),
            (lambda a: a["protected"].__setitem__("artifact_id", "bad")),
            (lambda a: a["protected"].__setitem__("sealed_at", "bad")),
            (
                lambda a: a["protected"].__setitem__(
                    "canonicalization_suite",
                    {"scheme": "deterministic-json-fallback", "version": "1.0"},
                )
            ),
            (
                lambda a: a["protected"]["signing_suite"].__setitem__(
                    "hash", "SHA-512"
                )
            ),
            (lambda a: a["integrity"]["digest"].__setitem__("alg", "MD5")),
            (
                lambda a: a["integrity"]["signature"].__setitem__(
                    "format", "RAW"
                )
            ),
            (lambda a: a.__setitem__("receipts", ["bad"])),
        )
        for mutate in mutations:
            artifact = copy.deepcopy(self.artifact)
            mutate(artifact)
            with self.subTest(artifact=artifact):
                self.assertFalse(standalone_verify(artifact, self.public).ok)

    def test_check_schema_false_still_rejects_v2_suite_confusion(self):
        artifact = copy.deepcopy(self.artifact)
        artifact["protected"]["canonicalization_suite"] = {
            "scheme": "deterministic-json-fallback",
            "version": "1.0",
        }
        self.assertFalse(
            standalone_verify(
                artifact, self.public, check_schema=False
            ).ok
        )


class TestMerklePrimitives(TestCase):
    def test_roots_and_proofs(self):
        self.assertEqual(compute_root([]), sha256(b"ceyo:empty-tree"))
        for count in (1, 2, 3, 4, 7, 8):
            leaves = [_leaf_hash(sha256(bytes([i]))) for i in range(count)]
            root = compute_root(leaves)
            for index in range(count):
                current = leaves[index]
                for direction, sibling in compute_inclusion_proof(index, leaves):
                    current = (
                        _node_hash(current, sibling)
                        if direction == "right"
                        else _node_hash(sibling, current)
                    )
                self.assertEqual(current, root)

    def test_invalid_proof_index(self):
        with self.assertRaises(ValueError):
            compute_inclusion_proof(0, [])
        with self.assertRaises(IndexError):
            compute_inclusion_proof(-1, [sha256(b"x")])
        with self.assertRaises(IndexError):
            compute_inclusion_proof(2, [sha256(b"x")])


class TestTransparency(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.kp = InMemoryKeyProvider()
        self.log = TransparencyLog(os.path.join(self.tmp, "log.db"), self.kp)
        self.addCleanup(self.log.close)

    def make_artifact(self, suffix="a"):
        return seal_body(make_body(f"evt_log_{suffix}"), self.kp)

    def test_v2_log_subject_excludes_receipts_and_v1_uses_full_envelope(self):
        artifact = self.make_artifact()
        before = artifact_log_digest(artifact)
        artifact["receipts"].append({"type": "later", "proof": "x"})
        self.assertEqual(before, artifact_log_digest(artifact))
        self.assertEqual(
            set(artifact_log_subject(artifact)), {"protected", "integrity"}
        )

        legacy = seal_body_v1(make_body("evt_log_v1"), self.kp)
        self.assertIs(artifact_log_subject(legacy), legacy)

    def test_append_get_list_duplicate_and_root(self):
        root0 = self.log.root_hash()
        artifact = self.make_artifact()
        entry = self.log.append(artifact)
        self.assertEqual(entry["artifact_id"], artifact_id(artifact))
        self.assertEqual(entry["seq"], 1)
        self.assertNotEqual(root0, self.log.root_hash())
        self.assertEqual(self.log.tree_size(), 1)
        self.assertEqual(self.log.get_entry(artifact_id(artifact))["seq"], 1)
        self.assertIsNone(self.log.get_entry("missing"))
        self.assertEqual(len(self.log.list_entries(10)), 1)
        with self.assertRaises(Exception):
            self.log.append(artifact)

    def test_append_rejects_missing_or_unsupported_scope(self):
        with self.assertRaises(ValueError):
            self.log.append({})
        with self.assertRaises(ValueError):
            self.log.append(
                {
                    "protected": {"protocol_version": "9.0", "artifact_id": "x"},
                    "integrity": {},
                    "receipts": [],
                }
            )

    def test_checkpoint_and_all_inclusion_proofs_verify(self):
        artifacts = [self.make_artifact(str(index)) for index in range(6)]
        for artifact in artifacts:
            self.log.append(artifact)
        self.assertIsNone(self.log.latest_checkpoint())
        checkpoint = self.log.checkpoint()
        self.assertEqual(checkpoint["tree_size"], 6)
        self.assertEqual(
            self.log.latest_checkpoint()["root_hash"], checkpoint["root_hash"]
        )
        public = self.kp.get_public_key_pem()
        for artifact in artifacts:
            proof = self.log.prove_inclusion(artifact_id(artifact))
            result = verify_inclusion_proof(
                proof, checkpoint, public, artifact=artifact
            )
            with self.subTest(artifact=artifact_id(artifact)):
                self.assertTrue(result.ok, result.failed)

    def test_receipt_attachment_preserves_existing_proof_subject(self):
        artifact = self.make_artifact("receipt")
        self.log.append(artifact)
        proof = self.log.prove_inclusion(artifact_id(artifact))
        artifact["receipts"].append(
            {"type": "example", "root": proof["root_hash"]}
        )
        self.assertTrue(
            verify_inclusion_proof(proof, artifact=artifact).ok
        )

    def test_tamper_and_checkpoint_failure_modes(self):
        artifact = self.make_artifact("proof")
        self.log.append(artifact)
        proof = self.log.prove_inclusion(artifact_id(artifact))
        self.assertTrue(verify_inclusion_proof(proof).ok)

        tampered = copy.deepcopy(proof)
        tampered["artifact_hash"] = b64u(sha256(b"other"))
        self.assertFalse(verify_inclusion_proof(tampered).ok)

        checkpoint = self.log.checkpoint()
        self.assertFalse(verify_inclusion_proof(proof, checkpoint).ok)
        wrong = InMemoryKeyProvider()
        self.assertFalse(
            verify_inclusion_proof(
                proof, checkpoint, wrong.get_public_key_pem()
            ).ok
        )

        checkpoint = self.log.checkpoint()
        checkpoint["key_reference"]["public_key_fingerprint"][
            "value_b64u"
        ] = b64u(b"\x00" * 32)
        self.assertFalse(
            verify_inclusion_proof(
                proof, checkpoint, self.kp.get_public_key_pem()
            ).ok
        )

    def test_missing_proof_target_and_structure_fail(self):
        with self.assertRaises(KeyError):
            self.log.prove_inclusion("missing")
        self.assertFalse(verify_inclusion_proof({"artifact_id": "x"}).ok)
        proof = {
            "artifact_id": "x",
            "artifact_hash": b64u(sha256(b"x")),
            "leaf_index": -1,
            "tree_size": 1,
            "root_hash": b64u(sha256(b"root")),
            "hashes": [],
        }
        self.assertFalse(verify_inclusion_proof(proof).ok)


class TestCLI(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.private = os.path.join(self.tmp, "private.pem")
        self.public = os.path.join(self.tmp, "public.pem")

    @staticmethod
    def ns(**kwargs):
        return Namespace(**kwargs)

    def keygen(self):
        from ceyo.cli import cmd_keygen

        cmd_keygen(
            self.ns(
                out_private=self.private,
                out_public=self.public,
                force=False,
            )
        )

    def record(self, name="record.json"):
        path = os.path.join(self.tmp, name)
        Path(path).write_text(json.dumps(make_body()), encoding="utf-8")
        return path

    def seal_file(self):
        from ceyo.cli import cmd_seal

        self.keygen()
        output = os.path.join(self.tmp, "artifact.json")
        cmd_seal(
            self.ns(
                record=self.record(),
                key=self.private,
                output=output,
                no_validate=False,
            )
        )
        return output

    def test_keygen_create_refuse_and_force(self):
        from ceyo.cli import cmd_keygen

        self.keygen()
        self.assertTrue(Path(self.private).exists())
        self.assertTrue(Path(self.public).exists())
        with self.assertRaises(SystemExit) as ctx:
            cmd_keygen(
                self.ns(
                    out_private=self.private,
                    out_public=self.public,
                    force=False,
                )
            )
        self.assertEqual(ctx.exception.code, 1)
        cmd_keygen(
            self.ns(
                out_private=self.private,
                out_public=self.public,
                force=True,
            )
        )

    def test_seal_verify_and_store_commands(self):
        from ceyo.cli import (
            cmd_store_inspect,
            cmd_store_list,
            cmd_store_verify_chain,
            cmd_verify,
        )

        output = self.seal_file()
        artifact = json.loads(Path(output).read_text(encoding="utf-8"))
        self.assertEqual(artifact["protected"]["protocol_version"], "2.0")
        with self.assertRaises(SystemExit) as ctx:
            cmd_verify(self.ns(artifact=output, pubkey=self.public))
        self.assertEqual(ctx.exception.code, 0)

        db = os.path.join(self.tmp, "store.db")
        with ArtifactStore(db) as store:
            store.append(artifact)
        cmd_store_list(self.ns(db=db, limit=10))
        cmd_store_inspect(self.ns(db=db, artifact_id=artifact_id(artifact)))
        with self.assertRaises(SystemExit) as ctx:
            cmd_store_verify_chain(self.ns(db=db))
        self.assertEqual(ctx.exception.code, 0)
        with self.assertRaises(SystemExit):
            cmd_store_inspect(self.ns(db=db, artifact_id="missing"))

    def test_seal_and_verify_input_errors(self):
        from ceyo.cli import cmd_seal, cmd_verify

        with self.assertRaises(SystemExit):
            cmd_seal(
                self.ns(
                    record="/missing.json",
                    key=self.private,
                    output=None,
                    no_validate=False,
                )
            )
        bad_json = os.path.join(self.tmp, "bad.json")
        Path(bad_json).write_text("not json", encoding="utf-8")
        with self.assertRaises(SystemExit):
            cmd_seal(
                self.ns(
                    record=bad_json,
                    key=self.private,
                    output=None,
                    no_validate=False,
                )
            )
        with self.assertRaises(SystemExit):
            cmd_verify(self.ns(artifact="/missing.json", pubkey=self.public))

    def test_log_commands(self):
        from ceyo.cli import (
            cmd_log_checkpoint,
            cmd_log_list,
            cmd_log_prove,
            cmd_log_verify_proof,
        )

        self.keygen()
        kp = LocalKeyProvider(self.private, self.public)
        artifact = seal_body(make_body("evt_cli_log"), kp)
        db = os.path.join(self.tmp, "log.db")
        with TransparencyLog(db, kp) as log:
            log.append(artifact)

        cmd_log_list(self.ns(db=db, limit=10))
        checkpoint_file = os.path.join(self.tmp, "checkpoint.json")
        cmd_log_checkpoint(
            self.ns(db=db, key=self.private, output=checkpoint_file)
        )
        proof_file = os.path.join(self.tmp, "proof.json")
        cmd_log_prove(
            self.ns(
                db=db,
                artifact_id=artifact_id(artifact),
                output=proof_file,
            )
        )
        with self.assertRaises(SystemExit) as ctx:
            cmd_log_verify_proof(
                self.ns(
                    proof=proof_file,
                    checkpoint=checkpoint_file,
                    pubkey=self.public,
                )
            )
        self.assertEqual(ctx.exception.code, 0)

        with self.assertRaises(SystemExit):
            cmd_log_prove(
                self.ns(db=db, artifact_id="missing", output=None)
            )
        with self.assertRaises(SystemExit):
            cmd_log_verify_proof(
                self.ns(proof="/missing.json", checkpoint=None, pubkey=None)
            )


if __name__ == "__main__":
    main()
