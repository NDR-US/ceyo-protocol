"""Key management for CEYO Protocol.

Provides a pluggable key provider interface with a local PEM provider
built-in. Additional providers (KMS, HSM, registry) can be added by
implementing the KeyProvider abstract class.
"""

from __future__ import annotations

import abc
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


class KeyManager:
    """Manages key providers with lookup by registry/key_id."""

    def __init__(self) -> None:
        self._providers: dict[str, KeyProvider] = {}

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
