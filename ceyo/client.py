"""High-level CEYO client with decorator, middleware, batch, and async support."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from ceyo.crypto import b64u
from ceyo.keys import InMemoryKeyProvider, KeyProvider
from ceyo.seal import seal_body
from ceyo.store import ArtifactStore
from ceyo.verify import VerificationResult, verify_artifact


class CeyoClient:
    """High-level client for sealing and verifying CEYO artifacts.

    Combines key management, sealing, verification, and optional storage.

    Usage:
        client = CeyoClient(key_provider=LocalKeyProvider("keys/private.pem"))

        # Seal directly
        envelope = client.seal(body)

        # Use as decorator
        @client.trace
        def classify(text):
            return model.predict(text)

        # Verify
        result = client.verify(envelope)
    """

    def __init__(
        self,
        key_provider: KeyProvider | None = None,
        store: ArtifactStore | None = None,
    ):
        self.key_provider = key_provider or InMemoryKeyProvider()
        self.store = store

    def seal(
        self,
        body: dict[str, Any],
        *,
        validate: bool = True,
        persist: bool = True,
    ) -> dict[str, Any]:
        """Seal an artifact body and optionally persist it.

        Args:
            body: The artifact body dict.
            validate: Whether to validate the body schema.
            persist: Whether to append to the store (if configured).

        Returns:
            The sealed artifact envelope.
        """
        envelope = seal_body(body, self.key_provider, validate=validate)
        if persist and self.store is not None:
            self.store.append(envelope)
        return envelope

    def verify(
        self,
        artifact: dict[str, Any],
        *,
        check_schema: bool = True,
    ) -> VerificationResult:
        """Verify a sealed artifact against this client's public key."""
        pub_pem = self.key_provider.get_public_key_pem()
        return verify_artifact(artifact, pub_pem, check_schema=check_schema)

    def trace(
        self,
        func: Optional[Callable] = None,
        *,
        event_type: str = "inference",
        policy_id: Optional[str] = None,
        policy_version: str = "1.0",
        disclosure_tier: str = "internal",
    ) -> Callable:
        """Decorator that seals an artifact for each function call.

        The decorated function runs normally. Before returning, CEYO
        captures a hash of the input args and the output, then seals
        an artifact recording the event.

        Usage:
            @client.trace
            def predict(text):
                return model(text)

            @client.trace(event_type="classification", policy_id="POL-001")
            def classify(text):
                return model.classify(text)
        """
        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                request_id = f"req_{uuid.uuid4().hex[:16]}"
                occurred_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                result = fn(*args, **kwargs)

                # Hash inputs and outputs (don't store raw data)
                input_repr = repr((args, kwargs)).encode("utf-8")
                output_repr = repr(result).encode("utf-8")
                input_hash = b64u(hashlib.sha256(input_repr).digest())
                output_hash = b64u(hashlib.sha256(output_repr).digest())

                body: dict[str, Any] = {
                    "event": {
                        "event_id": f"evt_{uuid.uuid4().hex[:16]}",
                        "type": event_type,
                        "occurred_at": occurred_at,
                        "request_id": request_id,
                    },
                    "disclosure_tier": disclosure_tier,
                    "capture": {
                        "input_ref_hash": {
                            "alg": "SHA-256",
                            "value_b64u": input_hash,
                            "covers": "policy_scoped_input_representation",
                        },
                        "output_ref_hash": {
                            "alg": "SHA-256",
                            "value_b64u": output_hash,
                            "covers": "policy_scoped_output_representation",
                        },
                    },
                }

                if policy_id:
                    body["policy"] = {"id": policy_id, "version": policy_version}

                self.seal(body, validate=True)
                return result

            return wrapper

        if func is not None:
            return decorator(func)
        return decorator

    def seal_batch(
        self,
        bodies: list[dict[str, Any]],
        *,
        validate: bool = True,
        persist: bool = True,
    ) -> list[dict[str, Any]]:
        """Seal multiple artifact bodies in one call.

        Args:
            bodies: List of artifact body dicts.
            validate: Whether to validate each body schema.
            persist: Whether to append each to the store.

        Returns:
            List of sealed artifact envelopes in the same order.
        """
        return [self.seal(body, validate=validate, persist=persist) for body in bodies]

    def wrap_openai(self, openai_client: Any) -> Any:
        """Wrap an OpenAI client to automatically seal artifacts for each call.

        Returns a wrapped client whose chat.completions.create() method
        produces a CEYO artifact for every completion.

        Usage:
            import openai
            raw = openai.OpenAI()
            client = CeyoClient(key_provider=LocalKeyProvider("keys/private.pem"))
            wrapped = client.wrap_openai(raw)
            response = wrapped.chat.completions.create(model="gpt-4", messages=[...])
            # Artifact is automatically sealed and stored
        """
        return _OpenAIWrapper(openai_client, self)


class _ChatCompletionsWrapper:
    """Wraps OpenAI's chat.completions to seal artifacts on create()."""

    def __init__(self, completions: Any, ceyo: CeyoClient):
        self._completions = completions
        self._ceyo = ceyo

    def create(self, **kwargs: Any) -> Any:
        request_id = f"req_{uuid.uuid4().hex[:16]}"
        occurred_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        response = self._completions.create(**kwargs)

        input_repr = repr(kwargs).encode("utf-8")
        output_repr = repr(response).encode("utf-8")
        input_hash = b64u(hashlib.sha256(input_repr).digest())
        output_hash = b64u(hashlib.sha256(output_repr).digest())

        body: dict[str, Any] = {
            "event": {
                "event_id": f"evt_{uuid.uuid4().hex[:16]}",
                "type": "inference",
                "occurred_at": occurred_at,
                "request_id": request_id,
            },
            "disclosure_tier": "internal",
            "capture": {
                "input_ref_hash": {
                    "alg": "SHA-256",
                    "value_b64u": input_hash,
                    "covers": "policy_scoped_input_representation",
                },
                "output_ref_hash": {
                    "alg": "SHA-256",
                    "value_b64u": output_hash,
                    "covers": "policy_scoped_output_representation",
                },
            },
            "environment": {
                "deployment_id": f"dep_{uuid.uuid4().hex[:12]}",
                "model_ref": kwargs.get("model", "unknown"),
                "runtime_ref": "openai-api",
            },
        }

        self._ceyo.seal(body, validate=True)
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


class _ChatWrapper:
    """Wraps OpenAI's chat namespace."""

    def __init__(self, chat: Any, ceyo: CeyoClient):
        self.completions = _ChatCompletionsWrapper(chat.completions, ceyo)

    def __getattr__(self, name: str) -> Any:
        if name == "completions":
            return self.completions
        return getattr(self._chat, name)


class _OpenAIWrapper:
    """Wraps an OpenAI client to intercept chat.completions.create()."""

    def __init__(self, client: Any, ceyo: CeyoClient):
        self._client = client
        self.chat = _ChatWrapper(client.chat, ceyo)

    def __getattr__(self, name: str) -> Any:
        if name == "chat":
            return self.chat
        return getattr(self._client, name)


class AsyncCeyoClient:
    """Async-compatible CEYO client.

    Wraps the synchronous CeyoClient and runs blocking operations
    (crypto, SQLite) in a thread pool so they don't block the event loop.

    Usage:
        async_client = AsyncCeyoClient(key_provider=LocalKeyProvider("keys/private.pem"))
        envelope = await async_client.seal(body)
        result = await async_client.verify(envelope)
    """

    def __init__(
        self,
        key_provider: KeyProvider | None = None,
        store: ArtifactStore | None = None,
        executor: ThreadPoolExecutor | None = None,
    ):
        self._sync = CeyoClient(key_provider=key_provider, store=store)
        self._executor = executor

    @property
    def key_provider(self) -> KeyProvider:
        return self._sync.key_provider

    @property
    def store(self) -> ArtifactStore | None:
        return self._sync.store

    async def seal(
        self,
        body: dict[str, Any],
        *,
        validate: bool = True,
        persist: bool = True,
    ) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._sync.seal(body, validate=validate, persist=persist),
        )

    async def verify(
        self,
        artifact: dict[str, Any],
        *,
        check_schema: bool = True,
    ) -> VerificationResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._sync.verify(artifact, check_schema=check_schema),
        )

    async def seal_batch(
        self,
        bodies: list[dict[str, Any]],
        *,
        validate: bool = True,
        persist: bool = True,
    ) -> list[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._sync.seal_batch(bodies, validate=validate, persist=persist),
        )
