"""Secp256k1 elliptic curve operations for Cashu blind signatures.

Extends coincurve.PublicKey with point arithmetic (__add__, __neg__, __sub__, __mul__).
Extracted from cashu/core/crypto/secp.py (MIT License, Cashu project).
"""

from coincurve import PrivateKey, PublicKey  # noqa: F401


class _PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self.combine([pubkey2])
        raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __neg__(self):
        serialized = self.format()
        first_byte, remainder = serialized[:1], serialized[1:]
        first_byte = {b"\x03": b"\x02", b"\x02": b"\x03"}[first_byte]
        return PublicKey(first_byte + remainder)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)
        raise TypeError(f"Can't subtract pubkey and {pubkey2.__class__}")

    def __mul__(self, privkey):
        if isinstance(privkey, PrivateKey):
            return self.multiply(bytes.fromhex(privkey.to_hex()))
        raise TypeError("Can't multiply with non-PrivateKey")

    def __eq__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self.to_data() == pubkey2.to_data()
        raise TypeError(f"Can't compare pubkey and {pubkey2.__class__}")

    def to_data(self):
        assert self.public_key
        return [self.public_key.data[i] for i in range(64)]


# Monkeypatch PublicKey with point arithmetic
PublicKey.__add__ = _PublicKeyExt.__add__  # type: ignore
PublicKey.__neg__ = _PublicKeyExt.__neg__  # type: ignore
PublicKey.__sub__ = _PublicKeyExt.__sub__  # type: ignore
PublicKey.__mul__ = _PublicKeyExt.__mul__  # type: ignore
PublicKey.__eq__ = _PublicKeyExt.__eq__  # type: ignore
PublicKey.to_data = _PublicKeyExt.to_data  # type: ignore
