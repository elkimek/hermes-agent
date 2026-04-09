"""Tests for Cashu token encoding/decoding — V3 (cashuA), V4 (cashuB), cashu: prefix."""

import pytest


class TestTokenV3:
    def test_encode_v3_produces_cashuA_prefix(self):
        from hermes_cli.routstr.token import encode_token
        token = encode_token("https://mint.example.com", [
            {"id": "abc123", "amount": 8, "secret": "secret1", "C": "02deadbeef"},
        ], version="v3")
        assert token.startswith("cashuA")

    def test_round_trip(self):
        from hermes_cli.routstr.token import encode_token, decode_token
        proofs = [
            {"id": "aabbccdd", "amount": 1, "secret": "s1", "C": "02aa"},
            {"id": "aabbccdd", "amount": 4, "secret": "s2", "C": "02bb"},
        ]
        token = encode_token("https://mint.example.com", proofs, version="v3")
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
        ], version="v3")
        # Add cashu: prefix
        decoded = decode_token("cashu:" + token)
        assert decoded["mint"] == "https://mint.example.com"
        assert decoded["proofs"][0]["amount"] == 2

    def test_decode_unknown_format_raises(self):
        from hermes_cli.routstr.token import decode_token
        with pytest.raises(ValueError, match="Unrecognized token format"):
            decode_token("invalidTokenString")


class TestTokenV4Encode:
    def test_encode_v4_produces_cashuB_prefix(self):
        try:
            import cbor2  # noqa: F401
        except ImportError:
            pytest.skip("cbor2 not installed")
        from hermes_cli.routstr.token import encode_token
        token = encode_token("https://mint.example.com", [
            {"id": "00aabbccdd", "amount": 8, "secret": "s1", "C": "02" + "aa" * 32},
        ], version="v4")
        assert token.startswith("cashuB")

    def test_v4_round_trip(self):
        try:
            import cbor2  # noqa: F401
        except ImportError:
            pytest.skip("cbor2 not installed")
        from hermes_cli.routstr.token import encode_token, decode_token
        proofs = [
            {"id": "00aabbccdd", "amount": 4, "secret": "s1", "C": "02" + "bb" * 32},
            {"id": "00aabbccdd", "amount": 16, "secret": "s2", "C": "02" + "cc" * 32},
        ]
        token = encode_token("https://mint.example.com", proofs, version="v4")
        decoded = decode_token(token)
        assert decoded["mint"] == "https://mint.example.com"
        assert len(decoded["proofs"]) == 2
        assert decoded["proofs"][0]["amount"] == 4
        assert decoded["proofs"][1]["amount"] == 16

    def test_uri_prefix_default_v4(self):
        try:
            import cbor2  # noqa: F401
        except ImportError:
            pytest.skip("cbor2 not installed")
        from hermes_cli.routstr.token import encode_token
        token = encode_token("https://mint.test", [
            {"id": "00aabb", "amount": 1, "secret": "s", "C": "02" + "cc" * 32},
        ], uri_prefix=True)
        assert token.startswith("cashu:cashuB")

    def test_v4_uri_prefix(self):
        try:
            import cbor2  # noqa: F401
        except ImportError:
            pytest.skip("cbor2 not installed")
        from hermes_cli.routstr.token import encode_token
        token = encode_token("https://mint.test", [
            {"id": "00aabb", "amount": 1, "secret": "s", "C": "02" + "dd" * 32},
        ], version="v4", uri_prefix=True)
        assert token.startswith("cashu:cashuB")


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


class TestExtractToken:
    def test_extract_from_plain_text(self):
        from hermes_cli.routstr.token import extract_token
        assert extract_token("cashuBabc123def") == "cashuBabc123def"

    def test_extract_from_surrounding_text(self):
        from hermes_cli.routstr.token import extract_token
        result = extract_token("here is the token cashuBabc123XYZ and some other text")
        assert result == "cashuBabc123XYZ"

    def test_extract_with_cashu_prefix(self):
        from hermes_cli.routstr.token import extract_token
        assert extract_token("cashu:cashuBabc123") == "cashuBabc123"

    def test_extract_from_discord_message_txt(self):
        from hermes_cli.routstr.token import extract_token
        discord = "[Content of message.txt]:\ncashuBeyJwcm9vZiI6W10sInVuaXQiOiJzYXQifQ"
        result = extract_token(discord)
        assert result.startswith("cashuB")

    def test_extract_cashuA(self):
        from hermes_cli.routstr.token import extract_token
        assert extract_token("cashuAeyJhYmMi").startswith("cashuA")

    def test_no_token_returns_none(self):
        from hermes_cli.routstr.token import extract_token
        assert extract_token("just some regular text") is None

    def test_empty_string(self):
        from hermes_cli.routstr.token import extract_token
        assert extract_token("") is None


class TestStripPrefix:
    def test_strips_cashu_prefix(self):
        from hermes_cli.routstr.token import strip_uri_prefix
        assert strip_uri_prefix("cashu:cashuAabc") == "cashuAabc"

    def test_no_prefix_unchanged(self):
        from hermes_cli.routstr.token import strip_uri_prefix
        assert strip_uri_prefix("cashuAabc") == "cashuAabc"
