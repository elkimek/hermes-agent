"""Tests for Cashu token encoding/decoding — V3 (cashuA), V4 (cashuB), cashu: prefix."""

import pytest


class TestTokenV3:
    def test_encode_produces_cashuA_prefix(self):
        from hermes_cli.routstr.token import encode_token
        token = encode_token("https://mint.example.com", [
            {"id": "abc123", "amount": 8, "secret": "secret1", "C": "02deadbeef"},
        ])
        assert token.startswith("cashuA")

    def test_round_trip(self):
        from hermes_cli.routstr.token import encode_token, decode_token
        proofs = [
            {"id": "aabbccdd", "amount": 1, "secret": "s1", "C": "02aa"},
            {"id": "aabbccdd", "amount": 4, "secret": "s2", "C": "02bb"},
        ]
        token = encode_token("https://mint.example.com", proofs)
        decoded = decode_token(token)
        assert decoded["mint"] == "https://mint.example.com"
        assert decoded["unit"] == "sat"
        assert len(decoded["proofs"]) == 2
        assert decoded["proofs"][0]["amount"] == 1
        assert decoded["proofs"][1]["secret"] == "s2"

    def test_decode_with_cashu_uri_prefix(self):
        from hermes_cli.routstr.token import encode_token, decode_token
        token = encode_token("https://mint.example.com", [
            {"id": "abc", "amount": 2, "secret": "s", "C": "02cc"},
        ])
        # Add cashu: prefix
        decoded = decode_token("cashu:" + token)
        assert decoded["mint"] == "https://mint.example.com"
        assert decoded["proofs"][0]["amount"] == 2

    def test_decode_unknown_format_raises(self):
        from hermes_cli.routstr.token import decode_token
        with pytest.raises(ValueError, match="Unrecognized token format"):
            decode_token("invalidTokenString")


class TestTokenV4:
    def test_decode_cbor_token(self):
        """Test decoding a CBOR-encoded cashuB token."""
        import base64
        try:
            import cbor2
        except ImportError:
            pytest.skip("cbor2 not installed")

        proofs_cbor = [{"a": 16, "s": "secret_v4", "c": bytes.fromhex("02" + "aa" * 32)}]
        token_data = {
            "m": "https://mint.example.com",
            "u": "sat",
            "t": [{"i": bytes.fromhex("00112233"), "p": proofs_cbor}],
        }
        payload = base64.urlsafe_b64encode(cbor2.dumps(token_data)).rstrip(b"=").decode()
        token_str = "cashuB" + payload

        from hermes_cli.routstr.token import decode_token
        decoded = decode_token(token_str)
        assert decoded["mint"] == "https://mint.example.com"
        assert decoded["unit"] == "sat"
        assert len(decoded["proofs"]) == 1
        assert decoded["proofs"][0]["amount"] == 16
        assert decoded["proofs"][0]["secret"] == "secret_v4"
        assert decoded["proofs"][0]["id"] == "00112233"

    def test_decode_v4_with_cashu_prefix(self):
        """cashu:cashuB... should work."""
        try:
            import cbor2
        except ImportError:
            pytest.skip("cbor2 not installed")

        import base64
        token_data = {"m": "https://mint.test", "u": "sat", "t": [{"i": b"\x00", "p": [{"a": 1, "s": "x", "c": b"\x02" + b"\x00" * 32}]}]}
        payload = base64.urlsafe_b64encode(cbor2.dumps(token_data)).rstrip(b"=").decode()

        from hermes_cli.routstr.token import decode_token
        decoded = decode_token("cashu:cashuB" + payload)
        assert decoded["mint"] == "https://mint.test"


class TestSumProofs:
    def test_sum_empty(self):
        from hermes_cli.routstr.token import sum_proofs
        assert sum_proofs([]) == 0

    def test_sum_multiple(self):
        from hermes_cli.routstr.token import sum_proofs
        proofs = [{"amount": 1}, {"amount": 2}, {"amount": 4}, {"amount": 8}]
        assert sum_proofs(proofs) == 15

    def test_sum_missing_amount(self):
        from hermes_cli.routstr.token import sum_proofs
        assert sum_proofs([{"id": "x"}]) == 0


class TestStripPrefix:
    def test_strips_cashu_prefix(self):
        from hermes_cli.routstr.token import strip_uri_prefix
        assert strip_uri_prefix("cashu:cashuAabc") == "cashuAabc"

    def test_no_prefix_unchanged(self):
        from hermes_cli.routstr.token import strip_uri_prefix
        assert strip_uri_prefix("cashuAabc") == "cashuAabc"
