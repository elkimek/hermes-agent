"""Routstr provider — decentralized Bitcoin AI with Cashu eCash wallet.

Optional dependency: pip install hermes-agent[routstr]
Requires: coincurve, mnemonic, cbor2
"""

_AVAILABLE = None


def is_available() -> bool:
    """Check if Routstr dependencies are installed."""
    global _AVAILABLE
    if _AVAILABLE is None:
        try:
            import coincurve  # noqa: F401
            _AVAILABLE = True
        except ImportError:
            _AVAILABLE = False
    return _AVAILABLE


def require():
    """Raise RuntimeError if Routstr deps are missing."""
    if not is_available():
        raise RuntimeError(
            "Routstr requires additional dependencies. "
            "Install with: pip install hermes-agent[routstr]"
        )
