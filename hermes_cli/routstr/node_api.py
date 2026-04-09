"""Routstr node API client — account creation, balance, topup, models.

All endpoints are on individual Routstr nodes (not a central server).
The node URL comes from Nostr discovery or user configuration.
"""

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)


async def create_account(
    node_url: str, cashu_token: str, client: Optional[httpx.AsyncClient] = None
) -> dict[str, Any]:
    """Create a Routstr account by depositing a Cashu token.

    Returns: {"api_key": "sk-...", "balance": int, ...}
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        # NOTE: Routstr API requires GET with token in query param.
        # This is their API design — POST is not supported for this endpoint.
        resp = await client.get(
            f"{node_url.rstrip('/')}/v1/balance/create",
            params={"initial_balance_token": cashu_token},
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        if own:
            await client.aclose()


async def get_balance(
    node_url: str, api_key: str, client: Optional[httpx.AsyncClient] = None
) -> dict[str, Any]:
    """Get account balance from a Routstr node.

    Returns: {"balance": int (msats), "total_requests": int, "total_spent": int, ...}
    Caller should convert: sats = balance // 1000
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        resp = await client.get(
            f"{node_url.rstrip('/')}/v1/balance/info",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5.0,
        )
        resp.raise_for_status()
        data = resp.json()
        # Normalize: balance is in millisatoshis
        msats = data.get("balance", 0)
        return {
            "msats": msats,
            "sats": msats // 1000,
            "total_requests": data.get("total_requests", 0),
            "total_spent": data.get("total_spent", 0),
        }
    finally:
        if own:
            await client.aclose()


async def topup_cashu(
    node_url: str, api_key: str, cashu_token: str,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, Any]:
    """Top up a Routstr account with a Cashu token.

    Returns: {"balance": int, "amount_added": int, ...}
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        resp = await client.post(
            f"{node_url.rstrip('/')}/v1/balance/topup",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"cashu_token": cashu_token},
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        if own:
            await client.aclose()


async def create_lightning_invoice(
    node_url: str, api_key: str, amount_sats: int,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, Any]:
    """Create a Lightning invoice for topping up a Routstr account.

    Returns: {"invoice_id": str, "bolt11": str, "amount_sats": int, "expires_at": int}
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        resp = await client.post(
            f"{node_url.rstrip('/')}/v1/balance/lightning/invoice",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"amount_sats": amount_sats, "purpose": "topup"},
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        if own:
            await client.aclose()


async def check_invoice_status(
    node_url: str, api_key: str, invoice_id: str,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, Any]:
    """Check the status of a Lightning invoice.

    Returns: {"status": "pending"|"paid"|"expired", ...}
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        resp = await client.get(
            f"{node_url.rstrip('/')}/v1/balance/lightning/invoice/{invoice_id}/status",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json()
    finally:
        if own:
            await client.aclose()


async def fetch_models(
    node_url: str, client: Optional[httpx.AsyncClient] = None
) -> list[str]:
    """Fetch available model IDs from a Routstr node (public, no auth).

    Returns: list of model ID strings.
    """
    own = client is None
    if own:
        client = httpx.AsyncClient()
    try:
        resp = await client.get(
            f"{node_url.rstrip('/')}/v1/models",
            timeout=5.0,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [m["id"] for m in data.get("data", []) if m.get("id")]
    except Exception:
        return []
    finally:
        if own:
            await client.aclose()
