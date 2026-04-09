"""Discover Routstr AI nodes via Nostr relays (NIP-91 / Kind 38421).

Queries multiple relays in parallel, parses provider announcements,
health-checks endpoints. Ported from getbased nostr-discovery.js.
"""

import asyncio
import json
import logging
import time
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

ROUTSTR_EVENT_KIND = 38421
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.nostr.band",
    "wss://nos.lol",
    "wss://relay.routstr.com",
]
RELAY_TIMEOUT = 5.0  # seconds per relay
HEALTH_TIMEOUT = 4.0
CACHE_TTL = 300  # 5 minutes

# Module-level cache
_cached_nodes: Optional[list[dict]] = None
_cache_time: float = 0


async def _query_relay(relay_url: str) -> list[dict]:
    """Query a single Nostr relay for Kind 38421 events."""
    try:
        import websockets
    except ImportError:
        logger.debug("websockets not installed, skipping relay %s", relay_url)
        return []

    events = []
    sub_id = f"routstr-{id(relay_url) & 0xFFFF:04x}"

    try:
        async with asyncio.timeout(RELAY_TIMEOUT):
            async with websockets.connect(relay_url, close_timeout=2) as ws:
                # Send REQ
                req = json.dumps(["REQ", sub_id, {"kinds": [ROUTSTR_EVENT_KIND], "limit": 50}])
                await ws.send(req)

                # Collect events until EOSE
                async for msg in ws:
                    try:
                        data = json.loads(msg)
                        if data[0] == "EVENT" and data[1] == sub_id and data[2]:
                            events.append(data[2])
                        elif data[0] == "EOSE":
                            break
                    except (json.JSONDecodeError, IndexError, KeyError):
                        continue
    except (asyncio.TimeoutError, Exception) as e:
        logger.debug("Relay %s: %s", relay_url, e)

    return events


def _parse_node_event(event: dict) -> dict[str, Any]:
    """Parse a Nostr event into a node descriptor."""
    tags = event.get("tags", [])
    urls = [t[1] for t in tags if len(t) >= 2 and t[0] == "u"]
    mints = [t[1] for t in tags if len(t) >= 2 and t[0] == "mint"]
    d_tag = next((t[1] for t in tags if len(t) >= 2 and t[0] == "d"), event.get("pubkey", ""))
    version = next((t[1] for t in tags if len(t) >= 2 and t[0] == "version"), None)

    name = d_tag
    about = ""
    try:
        content = json.loads(event.get("content", "{}"))
        if content.get("name"):
            name = content["name"]
        if content.get("about"):
            about = content["about"]
    except (json.JSONDecodeError, TypeError):
        pass

    return {
        "id": d_tag,
        "pubkey": event.get("pubkey", ""),
        "name": name,
        "about": about,
        "urls": [u for u in urls if u.startswith("http")],
        "onion": next((u for u in urls if ".onion" in u), None),
        "mints": mints,
        "version": version,
        "created_at": event.get("created_at", 0),
        "online": None,
        "models": [],
        "model_count": 0,
    }


def _deduplicate_nodes(events: list[dict]) -> list[dict]:
    """Deduplicate nodes by d-tag, keeping the most recent."""
    by_id: dict[str, dict] = {}
    for event in events:
        node = _parse_node_event(event)
        existing = by_id.get(node["id"])
        if not existing or node["created_at"] > existing["created_at"]:
            by_id[node["id"]] = node
    return list(by_id.values())


async def _health_check(node: dict) -> dict:
    """Check if a node is online and get its model list."""
    url = node["urls"][0] if node["urls"] else ""
    if not url or ".onion" in url or "localhost" in url:
        node["online"] = False
        return node

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url.rstrip("/") + "/v1/models",
                timeout=HEALTH_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                models = [m for m in data.get("data", []) if m.get("id") and m.get("enabled", True)]
                node["online"] = True
                node["models"] = [{"id": m["id"], "name": m.get("name", m["id"])} for m in models]
                node["model_count"] = len(models)
            else:
                node["online"] = False
    except Exception:
        node["online"] = False

    return node


async def discover_nodes(force_refresh: bool = False) -> list[dict]:
    """Discover Routstr nodes from Nostr relays.

    Returns array of node descriptors with health status.
    Caches results for 5 minutes.
    """
    global _cached_nodes, _cache_time

    if not force_refresh and _cached_nodes is not None and (time.time() - _cache_time < CACHE_TTL):
        return _cached_nodes

    logger.debug("Discovering Routstr nodes from %d relays", len(DEFAULT_RELAYS))

    # Query all relays in parallel
    results = await asyncio.gather(
        *[_query_relay(r) for r in DEFAULT_RELAYS],
        return_exceptions=True,
    )
    all_events = []
    for r in results:
        if isinstance(r, list):
            all_events.extend(r)

    logger.debug("Found %d events from relays", len(all_events))

    # Deduplicate by provider ID
    nodes = _deduplicate_nodes(all_events)

    logger.debug("Unique nodes: %d", len(nodes))

    # Health check all nodes in parallel
    await asyncio.gather(*[_health_check(n) for n in nodes])

    # Sort: online first, then by model count descending
    nodes.sort(key=lambda n: (not n.get("online", False), -(n.get("model_count", 0))))

    _cached_nodes = nodes
    _cache_time = time.time()

    return nodes


def clear_cache():
    """Clear the node cache, forcing re-discovery on next call."""
    global _cached_nodes, _cache_time
    _cached_nodes = None
    _cache_time = 0
