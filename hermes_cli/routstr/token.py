"""Cashu token encoding and decoding — V3 (cashuA) and V4 (cashuB).

V3 (cashuA): JSON + base64url
V4 (cashuB): CBOR + base64url (requires cbor2)

Both formats and the cashu: URI prefix are supported on decode.
Encoding produces V3 by default (widest compatibility).

Spec: https://github.com/cashubtc/nuts/blob/main/00.md
"""

import base64
import json
from typing import Any

PREFIX_V3 = "cashuA"
PREFIX_V4 = "cashuB"
URI_PREFIX = "cashu:"


def strip_uri_prefix(token: str) -> str:
    """Strip the cashu: URI prefix if present."""
    if token.startswith(URI_PREFIX):
        return token[len(URI_PREFIX):]
    return token


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# V3 (cashuA) — JSON + base64url
# ---------------------------------------------------------------------------

def encode_v3(mint_url: str, proofs: list[dict], unit: str = "sat") -> str:
    """Encode proofs as a V3 (cashuA) token string.

    Args:
        mint_url: The mint URL these proofs came from.
        proofs: List of proof dicts with keys: id, amount, secret, C.
        unit: Currency unit (default: "sat").

    Returns:
        Token string starting with "cashuA".
    """
    token_data = {
        "token": [{"mint": mint_url, "proofs": proofs}],
        "unit": unit,
    }
    payload = json.dumps(token_data, separators=(",", ":")).encode()
    return PREFIX_V3 + _b64url_encode(payload)


def _decode_v3(payload_str: str) -> dict[str, Any]:
    """Decode V3 payload (after stripping cashuA prefix)."""
    data = json.loads(_b64url_decode(payload_str))
    # V3 format: {"token": [{"mint": url, "proofs": [...]}], "unit": "sat"}
    tokens = data.get("token", [])
    if not tokens:
        raise ValueError("Empty V3 token")
    entry = tokens[0]
    return {
        "mint": entry.get("mint", ""),
        "proofs": entry.get("proofs", []),
        "unit": data.get("unit", "sat"),
    }


# ---------------------------------------------------------------------------
# V4 (cashuB) — CBOR + base64url
# ---------------------------------------------------------------------------

def _decode_v4(payload_str: str) -> dict[str, Any]:
    """Decode V4 payload (after stripping cashuB prefix).

    V4 CBOR format: {"m": mint_url, "u": unit, "t": [{"i": keyset_id_bytes, "p": [...]}]}
    Each proof in "p": {"a": amount, "s": secret, "c": C_bytes}
    """
    try:
        import cbor2
    except ImportError:
        raise ImportError(
            "cbor2 is required to decode cashuB (V4) tokens. "
            "Install with: pip install cbor2"
        )

    raw = cbor2.loads(_b64url_decode(payload_str))
    mint_url = raw.get("m", "")
    unit = raw.get("u", "sat")
    proofs = []

    for token_entry in raw.get("t", []):
        keyset_id = token_entry.get("i", b"")
        if isinstance(keyset_id, bytes):
            keyset_id = keyset_id.hex()
        for p in token_entry.get("p", []):
            c_val = p.get("c", b"")
            if isinstance(c_val, bytes):
                c_val = c_val.hex()
            proofs.append({
                "id": keyset_id,
                "amount": p.get("a", 0),
                "secret": p.get("s", ""),
                "C": c_val,
            })

    return {"mint": mint_url, "proofs": proofs, "unit": unit}


def extract_token(text: str) -> str | None:
    """Find and extract a Cashu token from anywhere in a string.

    Handles Discord's message.txt injection, pasted text with prefixes, etc.
    Returns the raw token string (cashuA... or cashuB...) or None.
    """
    import re
    # Strip cashu: URI prefix if present
    text = text.replace("cashu:", "")
    # Find cashuA or cashuB followed by base64url chars
    match = re.search(r'(cashu[AB][A-Za-z0-9_-]+={0,2})', text)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encode_v4(mint_url: str, proofs: list[dict], unit: str = "sat") -> str:
    """Encode proofs as a V4 (cashuB) token string using CBOR.

    V4 groups proofs by keyset ID and uses compact binary encoding.
    """
    try:
        import cbor2
    except ImportError:
        raise ImportError(
            "cbor2 is required to encode cashuB (V4) tokens. "
            "Install with: pip install cbor2"
        )

    # Group proofs by keyset ID
    by_keyset: dict[str, list[dict]] = {}
    for p in proofs:
        kid = p.get("id", "")
        by_keyset.setdefault(kid, []).append(p)

    token_entries = []
    for kid, kid_proofs in by_keyset.items():
        entry_proofs = []
        for p in kid_proofs:
            c_val = p.get("C", "")
            entry_proofs.append({
                "a": p.get("amount", 0),
                "s": p.get("secret", ""),
                "c": bytes.fromhex(c_val) if isinstance(c_val, str) else c_val,
            })
        token_entries.append({
            "i": bytes.fromhex(kid) if isinstance(kid, str) else kid,
            "p": entry_proofs,
        })

    token_data = {"m": mint_url, "u": unit, "t": token_entries}
    return PREFIX_V4 + _b64url_encode(cbor2.dumps(token_data))


def encode_token(
    mint_url: str, proofs: list[dict], unit: str = "sat",
    version: str = "v4", uri_prefix: bool = False,
) -> str:
    """Encode proofs as a Cashu token string.

    Args:
        version: "v4" (cashuB, default) or "v3" (cashuA, legacy)
        uri_prefix: If True, prepend "cashu:" URI prefix
    """
    if version == "v4":
        token = encode_v4(mint_url, proofs, unit)
    else:
        token = encode_v3(mint_url, proofs, unit)
    if uri_prefix:
        token = URI_PREFIX + token
    return token


def decode_token(token: str) -> dict[str, Any]:
    """Decode a Cashu token string. Accepts cashuA, cashuB, and cashu: prefix.

    Returns:
        {"mint": str, "proofs": [{"id", "amount", "secret", "C"}], "unit": str}

    Raises:
        ValueError: If the token format is unrecognized.
    """
    token = strip_uri_prefix(token).strip()

    if token.startswith(PREFIX_V3):
        return _decode_v3(token[len(PREFIX_V3):])
    elif token.startswith(PREFIX_V4):
        return _decode_v4(token[len(PREFIX_V4):])
    else:
        raise ValueError(
            f"Unrecognized token format. Expected cashuA... or cashuB..., "
            f"got: {token[:20]}..."
        )


def sum_proofs(proofs: list[dict]) -> int:
    """Sum the amounts of a list of proofs."""
    return sum(p.get("amount", 0) for p in proofs)
