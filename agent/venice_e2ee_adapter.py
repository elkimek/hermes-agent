"""Venice E2EE adapter for Hermes Agent.

Provides synchronous encryption/decryption using the venice-e2ee library.
Activated automatically when the model ID starts with "e2ee-".

Requires: pip install venice-e2ee
"""

import asyncio
import copy
import logging
import os
import time

logger = logging.getLogger(__name__)

try:
    import httpx
    from venice_e2ee.crypto import (
        decrypt_chunk,
        derive_aes_key,
        encrypt_message,
        generate_keypair,
        to_hex,
    )
    from venice_e2ee.attestation import verify_attestation
    from venice_e2ee.types import E2EESession

    _HAS_VENICE_E2EE = True
except ImportError:
    _HAS_VENICE_E2EE = False


def _require_venice_e2ee():
    if not _HAS_VENICE_E2EE:
        raise RuntimeError(
            "venice-e2ee package is required for E2EE models. "
            "Install with: pip install venice-e2ee"
        )


# ── Session creation (sync) ──────────────────────────────────────────


def create_session_sync(
    api_key: str,
    base_url: str,
    model_id: str,
    verify: bool = True,
) -> "E2EESession":
    """Create an E2EE session synchronously.

    Fetches TEE attestation via sync httpx, verifies the TDX quote,
    and derives an AES-256-GCM key via ECDH + HKDF.
    """
    _require_venice_e2ee()

    private_key, public_key, pub_key_hex = generate_keypair()
    nonce = os.urandom(32)

    base = base_url.rstrip("/")
    attestation_url = f"{base}/tee/attestation"

    with httpx.Client(timeout=30.0) as client:
        resp = client.get(
            attestation_url,
            params={"model": model_id, "nonce": nonce.hex()},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        resp.raise_for_status()
        attestation_resp = resp.json()

    model_pub_key_hex = (
        attestation_resp.get("signing_key")
        or attestation_resp.get("signing_public_key")
    )
    if not model_pub_key_hex:
        raise ValueError("No signing key in attestation response")

    attestation_result = None
    if verify:
        # verify_attestation is async; safe to use asyncio.run() here since
        # Hermes Agent calls this from a worker thread, not an event loop.
        attestation_result = asyncio.run(
            verify_attestation(attestation_resp, nonce)
        )
        if attestation_result.errors:
            raise ValueError(
                "TEE attestation verification failed:\n  - "
                + "\n  - ".join(attestation_result.errors)
            )

    aes_key = derive_aes_key(private_key, model_pub_key_hex)

    session = E2EESession(
        private_key=private_key,
        public_key=public_key,
        pub_key_hex=pub_key_hex,
        model_pub_key_hex=model_pub_key_hex,
        aes_key=aes_key,
        model_id=model_id,
        created=time.time(),
        attestation=attestation_result,
    )

    logger.info(
        "Venice E2EE session created for %s (nonce=%s, bound=%s)",
        model_id,
        getattr(attestation_result, "nonce_verified", "?"),
        getattr(attestation_result, "signing_key_bound", "?"),
    )
    return session


# ── Session caching ───────────────────────────────────────────────────


def get_or_create_session(
    api_key: str,
    base_url: str,
    model_id: str,
    existing: "E2EESession | None",
    ttl: float = 1800.0,
) -> "E2EESession":
    """Return the cached session if still valid, or create a new one."""
    if (
        existing is not None
        and existing.model_id == model_id
        and time.time() - existing.created < ttl
    ):
        return existing
    return create_session_sync(api_key, base_url, model_id)


# ── Encryption ────────────────────────────────────────────────────────


def encrypt_api_kwargs(session: "E2EESession", api_kwargs: dict) -> dict:
    """Encrypt messages and inject E2EE headers/body into api_kwargs.

    Returns a modified copy — does not mutate the original.
    """
    _require_venice_e2ee()
    kwargs = copy.deepcopy(api_kwargs)

    # Venice E2EE models don't support function calling
    kwargs.pop("tools", None)
    kwargs.pop("tool_choice", None)

    # Encrypt message contents
    messages = kwargs.get("messages", [])
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str) and content:
            msg["content"] = encrypt_message(
                session.aes_key, session.public_key, content
            )

    # E2EE headers
    kwargs["extra_headers"] = {
        **kwargs.get("extra_headers", {}),
        "X-Venice-TEE-Client-Pub-Key": session.pub_key_hex,
        "X-Venice-TEE-Model-Pub-Key": session.model_pub_key_hex,
        "X-Venice-TEE-Signing-Algo": "ecdsa",
    }

    # Venice parameters in request body
    extra_body = kwargs.get("extra_body", {})
    extra_body["venice_parameters"] = {"enable_e2ee": True}
    kwargs["extra_body"] = extra_body

    return kwargs


# ── Decryption ────────────────────────────────────────────────────────


def decrypt_delta(session: "E2EESession", text: str) -> str:
    """Decrypt a streaming chunk. Passes through non-encrypted content."""
    _require_venice_e2ee()
    return decrypt_chunk(session.private_key, text)
