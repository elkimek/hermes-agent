"""Blind Diffie-Hellman key exchange for Cashu (client-side only).

Implements the blind signature protocol from:
https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406

Alice (Client) operations:
  step1_alice: Create blinded message B' = Y + r*G
  step3_alice: Unblind signature  C  = C' - r*A
  alice_verify_dleq: Verify DLEQ proof from mint

Extracted from cashu/core/crypto/b_dhke.py (MIT License, Cashu project).
"""

import hashlib
from typing import Optional

from .secp import PrivateKey, PublicKey

DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"


def hash_to_curve(message: bytes) -> PublicKey:
    """Hash a message to a secp256k1 curve point.

    Uses SHA256 with domain separator and iterative counter until a valid
    point is found. ~50% chance per iteration; max 2^16 attempts.
    """
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            return PublicKey(b"\x02" + _hash)
        except Exception:
            counter += 1
    raise ValueError("No valid point found")


def step1_alice(
    secret_msg: str, blinding_factor: Optional[PrivateKey] = None
) -> tuple[PublicKey, PrivateKey]:
    """Create a blinded message for the mint.

    Returns (B', r) where B' = hash_to_curve(secret) + r*G
    """
    Y: PublicKey = hash_to_curve(secret_msg.encode("utf-8"))
    r = blinding_factor or PrivateKey()
    B_: PublicKey = Y + r.public_key  # type: ignore
    return B_, r


def step3_alice(C_: PublicKey, r: PrivateKey, A: PublicKey) -> PublicKey:
    """Unblind the mint's signature.

    Returns C = C' - r*A (removes the blinding factor)
    """
    C: PublicKey = C_ - A * r  # type: ignore
    return C


def hash_e(*publickeys: PublicKey) -> bytes:
    """Hash multiple public keys for DLEQ proof verification."""
    e_ = ""
    for p in publickeys:
        _p = p.format(compressed=False).hex()
        e_ += str(_p)
    return hashlib.sha256(e_.encode("utf-8")).digest()


def alice_verify_dleq(
    B_: PublicKey, C_: PublicKey, e: PrivateKey, s: PrivateKey, A: PublicKey
) -> bool:
    """Verify a DLEQ proof from the mint.

    Confirms that the same private key was used to sign B' → C'
    as was used to generate A = a*G.
    """
    R1 = s.public_key - A * e  # type: ignore
    R2 = B_ * s - C_ * e  # type: ignore
    e_bytes = bytes.fromhex(e.to_hex())
    return e_bytes == hash_e(R1, R2, A, C_)
