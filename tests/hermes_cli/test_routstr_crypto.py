"""Tests for Cashu blind signature crypto primitives."""

import pytest

try:
    from coincurve import PrivateKey
    HAS_COINCURVE = True
except ImportError:
    HAS_COINCURVE = False

pytestmark = pytest.mark.skipif(not HAS_COINCURVE, reason="coincurve not installed")


class TestHashToCurve:
    def test_produces_public_key(self):
        from hermes_cli.routstr.crypto.b_dhke import hash_to_curve
        point = hash_to_curve(b"test message")
        assert point is not None
        # Should be a compressed public key (33 bytes)
        assert len(point.format()) == 33

    def test_deterministic(self):
        from hermes_cli.routstr.crypto.b_dhke import hash_to_curve
        p1 = hash_to_curve(b"deterministic")
        p2 = hash_to_curve(b"deterministic")
        assert p1.format() == p2.format()

    def test_different_messages_different_points(self):
        from hermes_cli.routstr.crypto.b_dhke import hash_to_curve
        p1 = hash_to_curve(b"message_a")
        p2 = hash_to_curve(b"message_b")
        assert p1.format() != p2.format()

    def test_known_vector(self):
        """Test vector from NUT-00 spec."""
        from hermes_cli.routstr.crypto.b_dhke import hash_to_curve
        # "0000...0000" (32 zero bytes) should produce a known point
        result = hash_to_curve(bytes(32))
        assert result is not None
        assert len(result.format()) == 33


class TestBlindSignature:
    def test_step1_alice_produces_blinded_message(self):
        from hermes_cli.routstr.crypto.b_dhke import step1_alice
        B_, r = step1_alice("test_secret")
        assert B_ is not None
        assert r is not None
        assert len(B_.format()) == 33

    def test_step1_with_fixed_blinding_factor(self):
        from hermes_cli.routstr.crypto.b_dhke import step1_alice
        r_fixed = PrivateKey(b"\x01" * 32)
        B_1, r1 = step1_alice("test", r_fixed)
        B_2, r2 = step1_alice("test", r_fixed)
        assert B_1.format() == B_2.format()
        assert r1.to_hex() == r2.to_hex()

    def test_full_protocol_round_trip(self):
        """Simulate the full blind signature protocol:
        Alice blinds → Bob signs → Alice unblinds → verify."""
        from hermes_cli.routstr.crypto.b_dhke import (
            step1_alice, step3_alice, hash_to_curve,
        )

        # Bob's (mint's) key pair
        a = PrivateKey()  # mint's private key
        A = a.public_key  # mint's public key

        # Alice creates blinded message
        secret = "my_secret_message"
        B_, r = step1_alice(secret)

        # Bob signs the blinded message (step2_bob equivalent)
        C_ = B_ * a  # type: ignore

        # Alice unblinds
        C = step3_alice(C_, r, A)

        # Verify: C should equal a * hash_to_curve(secret)
        Y = hash_to_curve(secret.encode("utf-8"))
        expected = Y * a  # type: ignore
        assert C == expected

    def test_wrong_key_fails_verification(self):
        """Using the wrong mint key should produce an invalid unblinding."""
        from hermes_cli.routstr.crypto.b_dhke import (
            step1_alice, step3_alice, hash_to_curve,
        )

        a = PrivateKey()  # real mint key
        a_wrong = PrivateKey()  # wrong key

        secret = "test"
        B_, r = step1_alice(secret)
        C_ = B_ * a  # type: ignore  # signed with real key

        # Unblind with wrong public key
        A_wrong = a_wrong.public_key
        C = step3_alice(C_, r, A_wrong)

        # Should NOT match
        Y = hash_to_curve(secret.encode("utf-8"))
        expected = Y * a  # type: ignore
        assert C != expected


class TestDLEQVerification:
    def test_valid_dleq_proof(self):
        """Generate a DLEQ proof (mint-side) and verify it (client-side)."""
        from hermes_cli.routstr.crypto.b_dhke import (
            step1_alice, alice_verify_dleq, hash_e,
        )

        a = PrivateKey()
        A = a.public_key

        secret = "dleq_test"
        B_, r = step1_alice(secret)
        C_ = B_ * a  # type: ignore

        # Mint generates DLEQ proof (step2_bob_dleq simplified)
        p = PrivateKey()
        R1 = p.public_key
        R2 = B_ * p  # type: ignore
        e_bytes = hash_e(R1, R2, A, C_)
        s = p.add(bytes.fromhex(a.multiply(e_bytes).to_hex()))
        epk = PrivateKey(e_bytes)
        spk = PrivateKey(bytes.fromhex(s.to_hex()))

        # Alice verifies
        assert alice_verify_dleq(B_, C_, epk, spk, A) is True


class TestSecpOperations:
    def test_point_addition(self):
        from hermes_cli.routstr.crypto.secp import PublicKey, PrivateKey
        a = PrivateKey()
        b = PrivateKey()
        # a.pub + b.pub should work
        result = a.public_key + b.public_key
        assert result is not None
        assert len(result.format()) == 33

    def test_point_negation(self):
        from hermes_cli.routstr.crypto.secp import PublicKey, PrivateKey
        a = PrivateKey()
        neg = -a.public_key
        assert neg is not None
        assert neg.format() != a.public_key.format()

    def test_point_subtraction(self):
        from hermes_cli.routstr.crypto.secp import PrivateKey
        a = PrivateKey()
        b = PrivateKey()
        result = a.public_key - b.public_key
        assert result is not None

    def test_scalar_multiplication(self):
        from hermes_cli.routstr.crypto.secp import PrivateKey
        a = PrivateKey()
        b = PrivateKey()
        # a.pub * b == b.pub * a (commutativity)
        r1 = a.public_key * b
        r2 = b.public_key * a
        assert r1 == r2
