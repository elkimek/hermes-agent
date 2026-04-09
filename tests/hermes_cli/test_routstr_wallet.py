"""Tests for Cashu wallet — proof storage, mint API, blind sig flow."""

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

try:
    from coincurve import PrivateKey
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False

pytestmark = pytest.mark.skipif(not HAS_COINCURVE, reason="coincurve not installed")


class TestSplitAmount:
    def test_powers_of_two(self):
        from hermes_cli.routstr.wallet import _split_amount
        assert _split_amount(1) == [1]
        assert _split_amount(2) == [2]
        assert _split_amount(4) == [4]
        assert _split_amount(8) == [8]

    def test_composite(self):
        from hermes_cli.routstr.wallet import _split_amount
        assert sorted(_split_amount(13)) == [1, 4, 8]
        assert sorted(_split_amount(15)) == [1, 2, 4, 8]

    def test_larger_amounts(self):
        from hermes_cli.routstr.wallet import _split_amount
        parts = _split_amount(1000)
        assert sum(parts) == 1000
        # All parts should be powers of 2
        for p in parts:
            assert p & (p - 1) == 0

    def test_zero(self):
        from hermes_cli.routstr.wallet import _split_amount
        assert _split_amount(0) == []


class TestWalletPersistence:
    def test_save_and_load(self, tmp_path):
        from hermes_cli.routstr.wallet import CashuWallet

        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "wallet.json"):
            w = CashuWallet("https://mint.test")
            w.proofs = [
                {"id": "ks1", "amount": 8, "secret": "s1", "C": "02aa"},
                {"id": "ks1", "amount": 4, "secret": "s2", "C": "02bb"},
            ]
            w.keysets = {"ks1": {"unit": "sat", "keys": {"8": "02cc"}}}
            w.active_keyset_id = "ks1"
            w.save()

            w2 = CashuWallet()
            assert w2.load() is True
            assert w2.mint_url == "https://mint.test"
            assert len(w2.proofs) == 2
            assert w2.get_balance() == 12
            assert w2.active_keyset_id == "ks1"

    def test_load_missing_file(self, tmp_path):
        from hermes_cli.routstr.wallet import CashuWallet

        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "nope.json"):
            w = CashuWallet()
            assert w.load() is False

    def test_save_creates_file(self, tmp_path):
        from hermes_cli.routstr.wallet import CashuWallet

        path = tmp_path / "wallet.json"
        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=path):
            w = CashuWallet("https://mint.test")
            w.save()
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["version"] == 2
            assert data["mint_url"] == "https://mint.test"


class TestWalletBalance:
    def test_empty_wallet(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        assert w.get_balance() == 0

    def test_with_proofs(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        w.proofs = [{"amount": 1}, {"amount": 4}, {"amount": 16}]
        assert w.get_balance() == 21


class TestWalletExportImport:
    def test_export_all(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet("https://mint.test")
        w.proofs = [
            {"id": "ks1", "amount": 4, "secret": "s1", "C": "02aa"},
        ]
        token = w.export_token()
        assert token.startswith("cashuA")

    def test_import_token(self, tmp_path):
        from hermes_cli.routstr.wallet import CashuWallet
        from hermes_cli.routstr.token import encode_token

        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "w.json"):
            token = encode_token("https://mint.test", [
                {"id": "ks1", "amount": 8, "secret": "s1", "C": "02bb"},
            ])
            w = CashuWallet("https://mint.test")
            imported = w.import_token(token)
            assert len(imported) == 1
            assert w.get_balance() == 8


class TestLoadMint:
    @pytest.mark.asyncio
    async def test_load_mint_parses_keysets(self):
        from hermes_cli.routstr.wallet import CashuWallet

        mock_client = AsyncMock()

        # Mock keysets response
        keysets_resp = MagicMock()
        keysets_resp.status_code = 200
        keysets_resp.json.return_value = {
            "keysets": [{"id": "abc123", "unit": "sat", "active": True}]
        }
        keysets_resp.raise_for_status = MagicMock()

        # Mock keys response
        keys_resp = MagicMock()
        keys_resp.status_code = 200
        keys_resp.json.return_value = {
            "keysets": [{
                "id": "abc123",
                "keys": {"1": "02" + "aa" * 32, "2": "02" + "bb" * 32},
            }]
        }
        keys_resp.raise_for_status = MagicMock()

        mock_client.get = AsyncMock(side_effect=[keysets_resp, keys_resp])

        w = CashuWallet("https://mint.test")
        await w.load_mint(client=mock_client)

        assert w.active_keyset_id == "abc123"
        assert "abc123" in w.keysets
        assert "1" in w.keysets["abc123"]["keys"]
        assert "2" in w.keysets["abc123"]["keys"]


class TestDeterministicSecrets:
    def test_derive_is_deterministic(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        w.seed = bytes.fromhex("aa" * 64)
        s1, r1 = w._derive_secret_and_r("00aabbccdd", 0)
        s2, r2 = w._derive_secret_and_r("00aabbccdd", 0)
        assert s1 == s2
        assert r1.to_hex() == r2.to_hex()

    def test_different_counters_different_secrets(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        w.seed = bytes.fromhex("bb" * 64)
        s1, _ = w._derive_secret_and_r("00aabbccdd", 0)
        s2, _ = w._derive_secret_and_r("00aabbccdd", 1)
        assert s1 != s2

    def test_different_keysets_different_secrets(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        w.seed = bytes.fromhex("cc" * 64)
        s1, _ = w._derive_secret_and_r("00aabbccdd", 0)
        s2, _ = w._derive_secret_and_r("00112233ff", 0)
        assert s1 != s2

    def test_counter_advances(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        start = w._next_counter("keyset1", 5)
        assert start == 0
        assert w.counters["keyset1"] == 5
        start2 = w._next_counter("keyset1", 3)
        assert start2 == 5
        assert w.counters["keyset1"] == 8

    def test_seed_from_mnemonic(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        # Use a known test mnemonic
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        w.set_seed_from_mnemonic(mnemonic)
        assert len(w.seed) == 64
        # Same mnemonic should produce same seed
        w2 = CashuWallet()
        w2.set_seed_from_mnemonic(mnemonic)
        assert w.seed == w2.seed

    def test_seed_persists(self, tmp_path):
        from hermes_cli.routstr.wallet import CashuWallet
        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "w.json"):
            w = CashuWallet()
            w.seed = bytes.fromhex("dd" * 64)
            w.counters = {"ks1": 42}
            w.save()

            w2 = CashuWallet()
            w2.load()
            assert w2.seed == w.seed
            assert w2.counters == {"ks1": 42}


class TestMintTokens:
    @pytest.mark.asyncio
    async def test_mint_tokens_creates_proofs(self, tmp_path):
        """Full mint flow: generate secrets → blind → send → unblind → proofs."""
        from hermes_cli.routstr.wallet import CashuWallet
        from hermes_cli.routstr.crypto.b_dhke import hash_to_curve, step1_alice
        from hermes_cli.routstr.crypto.secp import PrivateKey, PublicKey

        # Create a "mint" with known keys
        mint_privkey = PrivateKey()
        mint_pubkey = mint_privkey.public_key

        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "w.json"):
            w = CashuWallet("https://mint.test")
            w.active_keyset_id = "testks"
            # Set mint public key for denominations 1 and 4
            w.keysets["testks"] = {
                "unit": "sat",
                "keys": {
                    "1": mint_pubkey.format().hex(),
                    "4": mint_pubkey.format().hex(),
                },
            }

            # Mock the mint's /v1/mint/bolt11 response
            # The mint signs our blinded messages with mint_privkey
            async def mock_mint_post(url, json=None, timeout=None):
                outputs = json.get("outputs", []) if isinstance(json, dict) else []
                sigs = []
                for output in outputs:
                    B_ = PublicKey(bytes.fromhex(output["B_"]))
                    C_ = B_ * mint_privkey  # type: ignore  # mint signs
                    sigs.append({
                        "C_": C_.format().hex(),
                        "id": output["id"],
                        "amount": output["amount"],
                    })
                resp = MagicMock()
                resp.status_code = 200
                resp.json.return_value = {"signatures": sigs}
                resp.raise_for_status = MagicMock()
                return resp

            mock_client = AsyncMock()
            mock_client.post = mock_mint_post

            proofs = await w.mint_tokens(5, "test-quote", client=mock_client)

            # 5 = 1 + 4
            assert len(proofs) == 2
            amounts = sorted(p["amount"] for p in proofs)
            assert amounts == [1, 4]
            assert w.get_balance() == 5

            # Verify each proof is correctly unblinded
            for proof in proofs:
                Y = hash_to_curve(proof["secret"].encode("utf-8"))
                expected_C = Y * mint_privkey  # type: ignore
                actual_C = PublicKey(bytes.fromhex(proof["C"]))
                assert actual_C == expected_C


class TestSendProofs:
    @pytest.mark.asyncio
    async def test_send_exact_match(self, tmp_path):
        """When proofs exactly cover the amount, no swap is needed."""
        from hermes_cli.routstr.wallet import CashuWallet

        with patch("hermes_cli.routstr.wallet._wallet_path", return_value=tmp_path / "w.json"):
            w = CashuWallet("https://mint.test")
            w.proofs = [
                {"id": "ks", "amount": 1, "secret": "s1", "C": "02aa"},
                {"id": "ks", "amount": 4, "secret": "s2", "C": "02bb"},
                {"id": "ks", "amount": 8, "secret": "s3", "C": "02cc"},
            ]

            keep, send = await w.send(5)  # 1 + 4 = 5

            assert sum(p["amount"] for p in send) == 5
            assert sum(p["amount"] for p in keep) == 8
            assert w.get_balance() == 8

    @pytest.mark.asyncio
    async def test_send_insufficient_balance(self):
        from hermes_cli.routstr.wallet import CashuWallet
        w = CashuWallet()
        w.proofs = [{"amount": 2}]
        with pytest.raises(ValueError, match="Insufficient balance"):
            await w.send(10)
