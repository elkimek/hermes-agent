"""Cashu eCash wallet for Routstr — proof storage, mint API, mint/send operations.

Implements the Cashu NUT protocol using extracted blind signature primitives.
Supports deterministic secret derivation (NUT-13) for seed-based recovery.
No dependency on the full cashu package — just coincurve + httpx.

Storage: ~/.hermes/routstr/wallet.json
"""

import hashlib
import hmac as hmac_mod
import json
import logging
import os
import secrets as secrets_mod
from pathlib import Path
from typing import Any, Optional

import httpx

from .crypto.b_dhke import hash_to_curve, step1_alice, step3_alice
from .crypto.secp import PrivateKey, PublicKey
from .token import encode_token, decode_token, sum_proofs

logger = logging.getLogger(__name__)

DEFAULT_MINT = "https://mint.minibits.cash/Bitcoin"

def _split_amount(amount: int) -> list[int]:
    """Split an amount into powers of 2 (Cashu denomination).

    Example: 13 → [1, 4, 8], 50000 → [16, 32, 128, 16384, 32768]
    Handles arbitrarily large amounts via binary decomposition.
    """
    bits = []
    b = 1
    while amount > 0:
        if amount & 1:
            bits.append(b)
        amount >>= 1
        b <<= 1
    return bits


def _wallet_dir() -> Path:
    """Return ~/.hermes/routstr/, creating if needed."""
    try:
        from hermes_cli.config import get_hermes_home
        home = get_hermes_home()
    except Exception:
        home = Path.home() / ".hermes"
    d = home / "routstr"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _wallet_path() -> Path:
    return _wallet_dir() / "wallet.json"


class CashuWallet:
    """Minimal Cashu wallet — mints tokens, stores proofs, creates transfers.

    Supports deterministic secrets from a BIP-39 seed (NUT-13). When a seed
    is set, secrets and blinding factors are derived from HMAC-SHA256 with a
    per-keyset counter. This enables recovery via `restore()`.
    """

    def __init__(self, mint_url: str = DEFAULT_MINT):
        self.mint_url = mint_url.rstrip("/")
        self.proofs: list[dict] = []
        self.keysets: dict[str, dict] = {}  # keyset_id → {"unit", "keys": {amount: pubkey_hex}}
        self.active_keyset_id: str = ""
        self.seed: bytes = b""  # 64-byte seed from BIP-39 mnemonic
        self.counters: dict[str, int] = {}  # keyset_id → next counter value
        self._loaded = False

    # ── Persistence ──────────────────────────────────────────────────────

    def save(self):
        """Persist wallet state to disk."""
        path = _wallet_path()
        data = {
            "version": 2,
            "mint_url": self.mint_url,
            "keysets": self.keysets,
            "active_keyset_id": self.active_keyset_id,
            "proofs": self.proofs,
            "seed": self.seed.hex() if self.seed else "",
            "counters": self.counters,
        }
        path.write_text(json.dumps(data, indent=2))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def load(self) -> bool:
        """Load wallet state from disk. Returns True if file existed."""
        path = _wallet_path()
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text())
            self.mint_url = data.get("mint_url", self.mint_url)
            self.keysets = data.get("keysets", {})
            self.active_keyset_id = data.get("active_keyset_id", "")
            self.proofs = data.get("proofs", [])
            seed_hex = data.get("seed", "")
            self.seed = bytes.fromhex(seed_hex) if seed_hex else b""
            self.counters = data.get("counters", {})
            self._loaded = True
            return True
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to load wallet: %s", e)
            return False

    async def set_mint(self, mint_url: str, client: Optional[httpx.AsyncClient] = None):
        """Change the active mint. Validates it first, then loads keysets.

        Existing proofs stay tied to their original keyset — they can only
        be spent at the mint that issued them. New funding will use the new mint.
        """
        mint_url = mint_url.rstrip("/")
        own = client is None
        if own:
            client = httpx.AsyncClient()
        try:
            resp = await client.get(f"{mint_url}/v1/info", timeout=5.0)
            resp.raise_for_status()
            info = resp.json()
            if "nuts" not in info:
                raise ValueError("Not a valid Cashu mint (no 'nuts' in /v1/info)")
            self.mint_url = mint_url
            await self.load_mint(client)
            self.save()
        finally:
            if own:
                await client.aclose()

    # ── Seed + deterministic secrets (NUT-13) ──────────────────────────

    def set_seed_from_mnemonic(self, mnemonic: str):
        """Derive a 64-byte seed from a BIP-39 mnemonic phrase."""
        try:
            from mnemonic import Mnemonic
            m = Mnemonic("english")
            if not m.check(mnemonic):
                raise ValueError("Invalid mnemonic")
            self.seed = hashlib.pbkdf2_hmac(
                "sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048
            )
        except ImportError:
            raise ImportError("mnemonic package required: pip install mnemonic")

    @staticmethod
    def generate_mnemonic() -> str:
        """Generate a new 12-word BIP-39 mnemonic."""
        try:
            from mnemonic import Mnemonic
            return Mnemonic("english").generate(128)
        except ImportError:
            raise ImportError("mnemonic package required: pip install mnemonic")

    def _derive_secret_and_r(self, keyset_id: str, counter: int) -> tuple[str, PrivateKey]:
        """Derive a deterministic secret + blinding factor for NUT-13 (HMAC-SHA256).

        Path: HMAC_SHA256(seed, "Cashu_KDF_HMAC_SHA256" || keyset_id || counter || 0x00/0x01)
        """
        keyset_id_bytes = bytes.fromhex(keyset_id)
        counter_bytes = counter.to_bytes(8, byteorder="big", signed=False)
        base = b"Cashu_KDF_HMAC_SHA256" + keyset_id_bytes + counter_bytes
        secret_bytes = hmac_mod.new(self.seed, base + b"\x00", hashlib.sha256).digest()
        r_bytes = hmac_mod.new(self.seed, base + b"\x01", hashlib.sha256).digest()
        return secret_bytes.hex(), PrivateKey(r_bytes)

    def _next_counter(self, keyset_id: str, count: int = 1) -> int:
        """Reserve `count` counter values for a keyset. Returns the start value."""
        start = self.counters.get(keyset_id, 0)
        self.counters[keyset_id] = start + count
        return start

    # ── Restore from seed ────────────────────────────────────────────────

    async def restore(self, client: Optional[httpx.AsyncClient] = None) -> int:
        """Restore proofs from the mint using deterministic secrets.

        Queries POST {mint}/v1/restore with blinded messages derived from
        the seed. The mint returns blind signatures for any that were previously
        minted. We unblind them and add to the wallet.

        Returns: number of sats restored.
        """
        if not self.seed:
            raise ValueError("No seed set. Call set_seed_from_mnemonic() first.")
        if not self.active_keyset_id:
            raise ValueError("No active keyset. Call load_mint() first.")

        own = client is None
        if own:
            client = httpx.AsyncClient()

        try:
            batch_size = 100
            gap_limit = 50  # stop after this many consecutive empty batches
            start = 0
            total_restored = 0
            empty_batches = 0

            while empty_batches < gap_limit:
                # Generate blinded messages from deterministic secrets
                outputs = []
                secrets_list = []
                rs_list = []

                for i in range(batch_size):
                    counter = start + i
                    secret, r = self._derive_secret_and_r(self.active_keyset_id, counter)
                    B_, _ = step1_alice(secret, r)
                    outputs.append({
                        "amount": 1,  # amount doesn't matter for restore
                        "id": self.active_keyset_id,
                        "B_": B_.format().hex(),
                    })
                    secrets_list.append(secret)
                    rs_list.append(r)

                # Send to mint's restore endpoint
                resp = await client.post(
                    f"{self.mint_url}/v1/restore",
                    json={"outputs": outputs},
                    timeout=15.0,
                )

                if resp.status_code == 404:
                    logger.debug("Mint does not support /v1/restore")
                    break

                if resp.status_code != 200:
                    logger.debug("Restore batch failed: %s", resp.status_code)
                    break

                data = resp.json()
                signatures = data.get("signatures", [])
                restored_outputs = data.get("outputs", [])

                if not signatures:
                    empty_batches += 1
                    start += batch_size
                    continue

                empty_batches = 0  # reset gap counter

                # Unblind signatures and create proofs
                for sig in signatures:
                    # Find matching output by B_
                    sig_b = sig.get("B_", "")
                    for j, out in enumerate(outputs):
                        if out["B_"] == sig_b:
                            C_ = PublicKey(bytes.fromhex(sig["C_"]))
                            amount = sig["amount"]
                            A = self._get_mint_key(self.active_keyset_id, amount)
                            C = step3_alice(C_, rs_list[j], A)
                            proof = {
                                "id": self.active_keyset_id,
                                "amount": amount,
                                "secret": secrets_list[j],
                                "C": C.format().hex(),
                            }
                            # Don't add duplicates
                            existing_secrets = {p["secret"] for p in self.proofs}
                            if proof["secret"] not in existing_secrets:
                                self.proofs.append(proof)
                                total_restored += amount
                            break

                start += batch_size

            # Update counter to highest restored position
            if start > 0:
                self.counters[self.active_keyset_id] = max(
                    self.counters.get(self.active_keyset_id, 0), start
                )

            if total_restored > 0:
                self.save()

            return total_restored

        finally:
            if own:
                await client.aclose()

    # ── Mint info ────────────────────────────────────────────────────────

    async def load_mint(self, client: Optional[httpx.AsyncClient] = None):
        """Fetch mint info and keysets from the mint server."""
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()
        try:
            # Get active keysets
            resp = await client.get(f"{self.mint_url}/v1/keysets", timeout=10.0)
            resp.raise_for_status()
            keysets_data = resp.json()

            # Find active sat keyset
            active_id = ""
            for ks in keysets_data.get("keysets", []):
                if ks.get("active") and ks.get("unit") == "sat":
                    active_id = ks["id"]
                    break

            if not active_id:
                # Fallback: use first active keyset
                for ks in keysets_data.get("keysets", []):
                    if ks.get("active"):
                        active_id = ks["id"]
                        break

            if not active_id:
                raise ValueError("No active keyset found at mint")

            # Fetch keys for active keyset
            resp = await client.get(f"{self.mint_url}/v1/keys/{active_id}", timeout=10.0)
            resp.raise_for_status()
            keys_data = resp.json()

            # Parse keys: {amount_str: pubkey_hex}
            keys = {}
            for ks in keys_data.get("keysets", []):
                if ks["id"] == active_id:
                    keys = ks.get("keys", {})
                    break

            self.keysets[active_id] = {"unit": "sat", "keys": keys}
            self.active_keyset_id = active_id
            self._loaded = True
        finally:
            if own_client:
                await client.aclose()

    def _get_mint_key(self, keyset_id: str, amount: int) -> PublicKey:
        """Get the mint's public key for a specific amount denomination."""
        ks = self.keysets.get(keyset_id, {})
        keys = ks.get("keys", {})
        key_hex = keys.get(str(amount))
        if not key_hex:
            raise ValueError(f"No mint key for amount {amount} in keyset {keyset_id}")
        return PublicKey(bytes.fromhex(key_hex))

    # ── Funding (Lightning → tokens) ────────────────────────────────────

    async def create_funding_invoice(
        self, amount_sats: int, client: Optional[httpx.AsyncClient] = None
    ) -> dict[str, Any]:
        """Request a Lightning invoice from the mint for minting tokens.

        Returns: {"quote": str, "request": str (bolt11), "state": str}
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()
        try:
            resp = await client.post(
                f"{self.mint_url}/v1/mint/quote/bolt11",
                json={"amount": amount_sats, "unit": "sat"},
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            if own_client:
                await client.aclose()

    async def check_funding_status(
        self, quote_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> dict[str, Any]:
        """Check if a funding invoice has been paid.

        Returns: {"quote": str, "state": "UNPAID"|"PAID"|"ISSUED", ...}
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()
        try:
            resp = await client.get(
                f"{self.mint_url}/v1/mint/quote/bolt11/{quote_id}",
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            if own_client:
                await client.aclose()

    async def mint_tokens(
        self, amount: int, quote_id: str, client: Optional[httpx.AsyncClient] = None
    ) -> list[dict]:
        """Mint Cashu tokens after a Lightning invoice has been paid.

        This is the core blind signature flow:
        1. Generate secrets and blinding factors
        2. Create blinded messages (step1_alice)
        3. Send to mint, get blind signatures
        4. Unblind signatures (step3_alice)
        5. Store proofs

        Returns: list of new proofs
        """
        if not self.active_keyset_id:
            raise ValueError("No active keyset. Call load_mint() first.")

        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()

        try:
            amounts = _split_amount(amount)
            if not amounts:
                raise ValueError(f"Cannot split amount {amount} into denominations")

            # Generate secrets, blinding factors, and blinded messages
            # Use deterministic derivation if seed is available (NUT-13)
            secrets_list = []
            blinding_factors = []
            outputs = []

            if self.seed:
                counter_start = self._next_counter(self.active_keyset_id, len(amounts))
                for i, amt in enumerate(amounts):
                    secret, r = self._derive_secret_and_r(self.active_keyset_id, counter_start + i)
                    B_, _ = step1_alice(secret, r)
                    secrets_list.append(secret)
                    blinding_factors.append(r)
                    outputs.append({
                        "amount": amt,
                        "id": self.active_keyset_id,
                        "B_": B_.format().hex(),
                    })
            else:
                for amt in amounts:
                    secret = secrets_mod.token_hex(32)
                    B_, r = step1_alice(secret)
                    secrets_list.append(secret)
                    blinding_factors.append(r)
                    outputs.append({
                        "amount": amt,
                        "id": self.active_keyset_id,
                        "B_": B_.format().hex(),
                    })

            # Send blinded messages to mint
            resp = await client.post(
                f"{self.mint_url}/v1/mint/bolt11",
                json={"outputs": outputs, "quote": quote_id},
                timeout=15.0,
            )
            resp.raise_for_status()
            signatures = resp.json().get("signatures", [])

            if len(signatures) != len(amounts):
                raise ValueError(
                    f"Mint returned {len(signatures)} signatures for {len(amounts)} outputs"
                )

            # Unblind signatures and create proofs
            new_proofs = []
            for sig, secret, r, amt in zip(signatures, secrets_list, blinding_factors, amounts):
                C_hex = sig["C_"]
                C_ = PublicKey(bytes.fromhex(C_hex))
                A = self._get_mint_key(self.active_keyset_id, amt)
                C = step3_alice(C_, r, A)

                proof = {
                    "id": self.active_keyset_id,
                    "amount": amt,
                    "secret": secret,
                    "C": C.format().hex(),
                }
                new_proofs.append(proof)

            self.proofs.extend(new_proofs)
            self.save()
            return new_proofs

        finally:
            if own_client:
                await client.aclose()

    # ── Sending (proof splitting) ───────────────────────────────────────

    async def send(
        self, amount: int, client: Optional[httpx.AsyncClient] = None
    ) -> tuple[list[dict], list[dict]]:
        """Split wallet proofs into (keep, send) sets for a target amount.

        If proofs can be combined to exactly match the amount, no swap is needed.
        Otherwise, uses the mint's /v1/swap endpoint to split a larger proof.

        Returns: (keep_proofs, send_proofs)
        """
        balance = sum_proofs(self.proofs)
        if amount > balance:
            raise ValueError(f"Insufficient balance: {balance} < {amount}")

        # Try to find exact combination (greedy: largest first)
        sorted_proofs = sorted(self.proofs, key=lambda p: p["amount"], reverse=True)
        send_proofs = []
        remaining = amount

        for proof in sorted_proofs:
            if remaining <= 0:
                break
            if proof["amount"] <= remaining:
                send_proofs.append(proof)
                remaining -= proof["amount"]

        if remaining == 0:
            # Exact match — no swap needed
            send_secrets = {p["secret"] for p in send_proofs}
            keep_proofs = [p for p in self.proofs if p["secret"] not in send_secrets]
            self.proofs = keep_proofs
            self.save()
            return keep_proofs, send_proofs

        # Need to swap — use mint's /v1/swap endpoint
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()

        try:
            # Pick proofs that cover the amount
            swap_proofs = []
            swap_total = 0
            for proof in sorted_proofs:
                swap_proofs.append(proof)
                swap_total += proof["amount"]
                if swap_total >= amount:
                    break

            if swap_total < amount:
                raise ValueError(f"Cannot cover {amount} from available proofs")

            # Create outputs: target amount + change
            send_amounts = _split_amount(amount)
            change_amount = swap_total - amount
            change_amounts = _split_amount(change_amount) if change_amount > 0 else []
            all_amounts = send_amounts + change_amounts

            # Generate new secrets and blinded messages
            new_secrets = []
            new_rs = []
            outputs = []
            if self.seed:
                counter_start = self._next_counter(self.active_keyset_id, len(all_amounts))
                for i, amt in enumerate(all_amounts):
                    secret, r = self._derive_secret_and_r(self.active_keyset_id, counter_start + i)
                    B_, _ = step1_alice(secret, r)
                    new_secrets.append(secret)
                    new_rs.append(r)
                    outputs.append({
                        "amount": amt,
                        "id": self.active_keyset_id,
                        "B_": B_.format().hex(),
                    })
            else:
                for amt in all_amounts:
                    secret = secrets_mod.token_hex(32)
                    B_, r = step1_alice(secret)
                    new_secrets.append(secret)
                    new_rs.append(r)
                    outputs.append({
                        "amount": amt,
                        "id": self.active_keyset_id,
                        "B_": B_.format().hex(),
                    })

            # Swap at mint
            swap_inputs = [
                {"id": p["id"], "amount": p["amount"], "secret": p["secret"], "C": p["C"]}
                for p in swap_proofs
            ]
            resp = await client.post(
                f"{self.mint_url}/v1/swap",
                json={"inputs": swap_inputs, "outputs": outputs},
                timeout=15.0,
            )
            resp.raise_for_status()
            signatures = resp.json().get("signatures", [])

            if len(signatures) != len(all_amounts):
                raise ValueError("Swap returned wrong number of signatures")

            # Unblind all new proofs
            all_new_proofs = []
            for sig, secret, r, amt in zip(signatures, new_secrets, new_rs, all_amounts):
                C_ = PublicKey(bytes.fromhex(sig["C_"]))
                A = self._get_mint_key(self.active_keyset_id, amt)
                C = step3_alice(C_, r, A)
                all_new_proofs.append({
                    "id": self.active_keyset_id,
                    "amount": amt,
                    "secret": secret,
                    "C": C.format().hex(),
                })

            # Split into send and keep
            send_new = all_new_proofs[:len(send_amounts)]
            change_new = all_new_proofs[len(send_amounts):]

            # Update wallet: remove swapped proofs, add change
            swap_secrets = {p["secret"] for p in swap_proofs}
            keep_proofs = [p for p in self.proofs if p["secret"] not in swap_secrets]
            keep_proofs.extend(change_new)
            self.proofs = keep_proofs
            self.save()

            return keep_proofs, send_new

        finally:
            if own_client:
                await client.aclose()

    # ── Token operations ────────────────────────────────────────────────

    def export_token(self, amount: Optional[int] = None) -> str:
        """Export proofs as a cashuA token string.

        If amount is None, exports all proofs.
        """
        if amount is None:
            return encode_token(self.mint_url, self.proofs)
        # For a specific amount, pick proofs greedily
        sorted_proofs = sorted(self.proofs, key=lambda p: p["amount"], reverse=True)
        selected = []
        remaining = amount
        for proof in sorted_proofs:
            if remaining <= 0:
                break
            if proof["amount"] <= remaining:
                selected.append(proof)
                remaining -= proof["amount"]
        if remaining > 0:
            raise ValueError(f"Cannot select exactly {amount} from proofs")
        return encode_token(self.mint_url, selected)

    def import_token(self, token_str: str):
        """Import proofs from a cashuA or cashuB token string."""
        decoded = decode_token(token_str)
        self.proofs.extend(decoded["proofs"])
        self.save()
        return decoded["proofs"]

    # ── Balance ─────────────────────────────────────────────────────────

    def get_balance(self) -> int:
        """Return total balance in sats."""
        return sum_proofs(self.proofs)

    # ── Withdrawal (tokens → Lightning) ─────────────────────────────────

    async def create_melt_quote(
        self, bolt11: str, client: Optional[httpx.AsyncClient] = None
    ) -> dict[str, Any]:
        """Create a quote to pay a Lightning invoice with Cashu tokens.

        Returns: {"quote": str, "amount": int, "fee_reserve": int, "state": str}
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()
        try:
            resp = await client.post(
                f"{self.mint_url}/v1/melt/quote/bolt11",
                json={"request": bolt11, "unit": "sat"},
                timeout=10.0,
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            if own_client:
                await client.aclose()

    async def melt_tokens(
        self, quote_id: str, proofs: list[dict], client: Optional[httpx.AsyncClient] = None
    ) -> dict[str, Any]:
        """Pay a Lightning invoice using Cashu proofs.

        Returns: {"state": "PAID"|"PENDING", "change": [proofs]}
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()
        try:
            inputs = [
                {"id": p["id"], "amount": p["amount"], "secret": p["secret"], "C": p["C"]}
                for p in proofs
            ]
            resp = await client.post(
                f"{self.mint_url}/v1/melt/bolt11",
                json={"quote": quote_id, "inputs": inputs},
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()
        finally:
            if own_client:
                await client.aclose()
