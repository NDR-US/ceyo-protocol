"""Key management for CEYO Protocol.

Provides a pluggable key provider interface with local PEM, in-memory,
environment variable, and AWS KMS providers. Additional providers can be
added by implementing the KeyProvider abstract class.
"""

from __future__ import annotations

import abc
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ceyo.crypto import b64u, sha256


class KeyProvider(abc.ABC):
    """Interface for key providers."""

    @abc.abstractmethod
    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Return the signing private key."""

    @abc.abstractmethod
    def get_public_key_pem(self) -> bytes:
        """Return the public key in PEM format."""

    @abc.abstractmethod
    def get_public_key_der(self) -> bytes:
        """Return the public key in DER format (SPKI)."""

    @abc.abstractmethod
    def key_id(self) -> str:
        """Return a key identifier string."""

    @abc.abstractmethod
    def registry(self) -> str:
        """Return the registry name (e.g. 'local', 'operator', 'kms')."""

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the public key DER, base64url-encoded."""
        return b64u(sha256(self.get_public_key_der()))

    def key_reference(self) -> dict[str, Any]:
        """Build the key_reference block for an artifact envelope."""
        return {
            "registry": self.registry(),
            "key_id": self.key_id(),
            "public_key_fingerprint": {
                "alg": "SHA-256",
                "value_b64u": self.fingerprint(),
                "covers": "public_key_spki_der",
            },
        }


class LocalKeyProvider(KeyProvider):
    """Key provider backed by PEM files on disk.

    If the private key does not exist, generates a new ECDSA P-256 key pair.
    """

    def __init__(self, private_key_path: str | Path, public_key_path: Optional[str | Path] = None):
        self._priv_path = Path(private_key_path)
        self._pub_path = Path(public_key_path) if public_key_path else self._priv_path.with_suffix(".pub.pem")
        self._priv: Optional[ec.EllipticCurvePrivateKey] = None

    def _load_or_create(self) -> ec.EllipticCurvePrivateKey:
        if self._priv is not None:
            return self._priv

        if self._priv_path.exists():
            key = serialization.load_pem_private_key(
                self._priv_path.read_bytes(), password=None
            )
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise TypeError(f"Expected ECDSA private key, got {type(key).__name__}")
            self._priv = key
        else:
            self._priv_path.parent.mkdir(parents=True, exist_ok=True)
            self._priv = ec.generate_private_key(ec.SECP256R1())
            self._priv_path.write_bytes(
                self._priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        # Write public key
        self._pub_path.write_bytes(self.get_public_key_pem())
        return self._priv

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._load_or_create()

    def get_public_key_pem(self) -> bytes:
        priv = self._load_or_create()
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_key_der(self) -> bytes:
        priv = self._load_or_create()
        return priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_id(self) -> str:
        return f"local:{self._pub_path.name}"

    def registry(self) -> str:
        return "local"


class InMemoryKeyProvider(KeyProvider):
    """Key provider that holds keys in memory. Useful for testing."""

    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        self._priv = private_key or ec.generate_private_key(ec.SECP256R1())

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._priv

    def get_public_key_pem(self) -> bytes:
        return self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_key_der(self) -> bytes:
        return self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_id(self) -> str:
        return f"memory:{self.fingerprint()[:12]}"

    def registry(self) -> str:
        return "memory"


class EnvKeyProvider(KeyProvider):
    """Key provider that reads PEM-encoded keys from environment variables.

    Useful for CI/CD pipelines and container deployments where keys are
    injected via environment.

    Args:
        private_key_var: Environment variable name for the private key PEM.
        public_key_var: Optional env var for the public key PEM (derived from private if omitted).
        key_id_var: Optional env var for a custom key identifier.
    """

    def __init__(
        self,
        private_key_var: str = "CEYO_PRIVATE_KEY",
        public_key_var: Optional[str] = None,
        key_id_var: str = "CEYO_KEY_ID",
    ):
        self._priv_var = private_key_var
        self._pub_var = public_key_var
        self._kid_var = key_id_var
        self._priv: Optional[ec.EllipticCurvePrivateKey] = None

    def _load(self) -> ec.EllipticCurvePrivateKey:
        if self._priv is not None:
            return self._priv
        pem = os.environ.get(self._priv_var)
        if not pem:
            raise EnvironmentError(f"Environment variable {self._priv_var} is not set")
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(f"Expected ECDSA private key, got {type(key).__name__}")
        self._priv = key
        return self._priv

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        return self._load()

    def get_public_key_pem(self) -> bytes:
        if self._pub_var:
            pem = os.environ.get(self._pub_var)
            if pem:
                return pem.encode("utf-8")
        return self._load().public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_key_der(self) -> bytes:
        return self._load().public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def key_id(self) -> str:
        return os.environ.get(self._kid_var, f"env:{self._priv_var}")

    def registry(self) -> str:
        return "env"


class KmsKeyProvider(KeyProvider):
    """Key provider backed by AWS KMS.

    Uses an asymmetric ECDSA P-256 key managed by KMS. The private key never
    leaves KMS — signing is done via the KMS API. The public key is fetched
    once and cached.

    Requires: pip install boto3

    Args:
        key_id: AWS KMS key ID, key ARN, alias name, or alias ARN.
        region_name: AWS region (e.g. "us-east-1"). Uses default if omitted.
        profile_name: AWS profile name for credentials. Uses default if omitted.
    """

    def __init__(
        self,
        key_id: str,
        region_name: Optional[str] = None,
        profile_name: Optional[str] = None,
    ):
        self._key_id = key_id
        self._region = region_name
        self._profile = profile_name
        self._client: Any = None
        self._pub_der: Optional[bytes] = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 is required for KMS support: pip install boto3")
        session_kwargs: dict[str, str] = {}
        if self._region:
            session_kwargs["region_name"] = self._region
        if self._profile:
            session_kwargs["profile_name"] = self._profile
        session = boto3.Session(**session_kwargs)
        self._client = session.client("kms")
        return self._client

    def _fetch_public_key(self) -> bytes:
        if self._pub_der is not None:
            return self._pub_der
        client = self._get_client()
        response = client.get_public_key(KeyId=self._key_id)
        self._pub_der = response["PublicKey"]
        return self._pub_der

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        raise NotImplementedError(
            "KMS keys cannot be exported. Use seal_body() which calls sign() "
            "on the key provider — KmsKeyProvider.sign() delegates to KMS."
        )

    def sign(self, digest: bytes) -> bytes:
        """Sign a SHA-256 digest using KMS.

        This is called by seal_body when the key provider is KMS-backed.
        """
        client = self._get_client()
        response = client.sign(
            KeyId=self._key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_256",
        )
        return response["Signature"]

    def get_public_key_pem(self) -> bytes:
        der_bytes = self._fetch_public_key()
        pub = serialization.load_der_public_key(der_bytes)
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_public_key_der(self) -> bytes:
        return self._fetch_public_key()

    def key_id(self) -> str:
        return f"kms:{self._key_id}"

    def registry(self) -> str:
        return "kms"


class KeyManager:
    """Manages key providers with lookup by registry/key_id and key rotation."""

    def __init__(self) -> None:
        self._providers: dict[str, KeyProvider] = {}
        self._rotations: list[dict[str, Any]] = []

    def register(self, name: str, provider: KeyProvider) -> None:
        """Register a key provider under a name."""
        self._providers[name] = provider

    def get(self, name: str) -> KeyProvider:
        """Retrieve a registered key provider."""
        if name not in self._providers:
            raise KeyError(f"No key provider registered as {name!r}")
        return self._providers[name]

    def default(self) -> KeyProvider:
        """Return the first registered provider, or raise."""
        if not self._providers:
            raise KeyError("No key providers registered")
        return next(iter(self._providers.values()))

    def rotate(self, name: str, new_provider: KeyProvider) -> KeyProvider:
        """Rotate a key by replacing a named provider.

        The old provider's fingerprint and rotation timestamp are recorded
        in the rotation log. Returns the old provider.
        """
        old = self._providers.get(name)
        self._rotations.append({
            "name": name,
            "rotated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "old_fingerprint": old.fingerprint() if old else None,
            "new_fingerprint": new_provider.fingerprint(),
        })
        self._providers[name] = new_provider
        return old  # type: ignore[return-value]

    def rotation_log(self) -> list[dict[str, Any]]:
        """Return the rotation history."""
        return list(self._rotations)

    def list_providers(self) -> dict[str, str]:
        """Return a mapping of name → fingerprint for all providers."""
        return {name: p.fingerprint() for name, p in self._providers.items()}
