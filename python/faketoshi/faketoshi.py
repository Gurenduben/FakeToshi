"""Python port of ``src/Faketoshi.hs``.

The trick (see README): an ECDSA signature ``(r, s)`` can be forged for an
*arbitrary* public key ``Q`` when the message hash ``z`` is allowed to be
whatever we like, because verification only checks

    R = (z/s) * G + (r/s) * Q   and then   r == R.x (mod n).

Fixing an attacker-chosen ``a`` and ``b`` with ``b != 0``:

    R = a * G + b * Q          r = R.x mod n
    s = r / b  (mod n)         z = r * a / b  (mod n)

Verification then succeeds, yet ``z`` is the hash of a message whose pre-image
the forger cannot produce.  Hence: an existential forgery, not a real
signature.
"""

from dataclasses import dataclass
from typing import Optional

from .curve import (
    G,
    N,
    Point,
    inverse,
    is_on_curve,
    point_add,
    point_add_two_muls,
    point_base_mul,
    point_mul,
)

@dataclass(frozen=True)
class Signature:
    """``Crypto.PubKey.ECC.ECDSA.Signature`` — the pair ``(r, s)``."""

    r: int
    s: int

    def __str__(self) -> str:  # matches the Haskell Show instance
        return '(Signature %d %d)' % (self.r, self.s)


@dataclass(frozen=True)
class PublicKey:
    """``Crypto.PubKey.ECC.ECDSA.PublicKey`` restricted to secp256k1.

    The Haskell version carries the curve alongside an optional point
    (``PointO`` being the point at infinity).  Here ``q is None`` plays the
    role of ``PointO``.
    """

    q: Point

    def __str__(self) -> str:
        if self.q is None:
            return '(PublicKey 0 0)'
        return '(PublicKey %d %d)' % self.q


@dataclass(frozen=True)
class FaketoshiCredentials:
    """``Faketoshi_Credentials``: ``sig``, ``msg`` (the hash ``z``) and ``pubKey``."""

    sig: Signature
    msg: int
    pub_key: PublicKey

    def __str__(self) -> str:
        pub = self.pub_key
        q = '(0,0)' if pub.q is None else '(%d,%d)' % pub.q
        return 'Sigs: %s\nMsg Hash: %d\nPublic Key: %s' % (self.sig, self.msg, q)


def valid_forgery(credentials: FaketoshiCredentials) -> bool:
    """``valid_forgery``: does this forgery verify against the given public key?"""
    return hashless_verify(credentials.pub_key, credentials.sig, credentials.msg)


def hashless_verify(pub_key: PublicKey, sig: Signature, msg: int) -> bool:
    """ECDSA verification with the hashing step removed.

    Copied from cryptonite's ECDSA verifier, minus the hashing of the message:
    ``msg`` is used directly as ``z``, exactly as the Haskell code does.
    """
    q = pub_key.q
    if q is None:
        return False

    r, s = sig.r, sig.s
    if r < 1 or r >= N or s < 1 or s >= N:
        return False

    w = inverse(s, N)
    if w is None:
        return False

    z = msg
    u1 = z * w % N
    u2 = r * w % N

    x = point_add_two_muls(u1, G, u2, q)
    if x is None:
        return False
    return x[0] % N == r


def generate_forgery(x_coord: str, y_coord: str, randbelow=None) -> Optional[FaketoshiCredentials]:
    """``generate_forgery``: forge a signature valid for the given public key.

    ``x_coord`` and ``y_coord`` are hex strings as they appear in the Genesis
    block public key.  Returns ``None`` when the random ``b`` is not invertible
    modulo the group order (astronomically unlikely, but handled explicitly,
    just like the Haskell ``Nothing`` branch).
    """
    x_int = int(x_coord, 16)
    y_int = int(y_coord, 16)
    public_point: Point = (x_int, y_int)

    if not is_on_curve(public_point):
        raise ValueError('public key point is not on secp256k1')

    if randbelow is None:
        import secrets

        def randbelow(n: int) -> int:  # type: ignore[misc]
            return secrets.randbelow(n)

    a = randbelow(N)
    b = randbelow(N)

    inv_b = inverse(b, N)
    if inv_b is None:
        return None

    r_point = point_add(point_base_mul(a), point_mul(b, public_point))
    if r_point is None:  # pragma: no cover - would need a*G = -b*Q
        return None

    rx = r_point[0]
    sig = Signature(rx, rx * inv_b % N)
    msg = rx * a * inv_b % N
    return FaketoshiCredentials(sig=sig, msg=msg, pub_key=PublicKey(public_point))
