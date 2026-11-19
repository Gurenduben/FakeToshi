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
from typing import Optional, Tuple

from .curve import (
    G,
    N,
    Point,
    inverse,
    is_on_curve,
    point_add,
    point_add_two_muls,
    point_base_mul,
    point_from_x,
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


# ---------------------------------------------------------------------------
# Inspecting a claim: "here is my transaction hash, plus r and s"
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Inspection:
    """Result of checking a ``(r, s, z)`` triple against a claimed public key.

    ``valid`` mirrors :func:`hashless_verify` for the claimed key.  The
    ``recovered_keys`` list holds the public keys for which the same ``(r, s)``
    *does* verify — see :func:`recover_public_keys` for why that matters.
    """

    r: int
    s: int
    z: int
    claimed_key: Optional[PublicKey]
    valid: bool
    recovered_keys: Tuple[PublicKey, ...]

    def __str__(self) -> str:
        lines = [
            'r: %d' % self.r,
            's: %d' % self.s,
            'z: %d' % self.z,
            'txid: %s' % format_tx_hash(self.z),
        ]
        if self.claimed_key is not None:
            lines.append('Claimed key: %s' % self.claimed_key)
        lines.append('Valid for claimed key: %s' % ('yes' if self.valid else 'no'))
        for i, key in enumerate(self.recovered_keys):
            lines.append('Recoverable key %d: %s' % (i, key))
        return '\n'.join(lines)


def tx_hash_to_z(tx_hash: str) -> int:
    """Interpret a transaction hash as ECDSA ``z``.

    Accepts a 64-character hex string (with or without ``0x``), as printed by
    explorers, and returns it as an integer — i.e. the digest interpreted
    big-endian, which is exactly what Bitcoin's ECDSA verifier does with the
    double-SHA256 of a transaction.
    """
    text = tx_hash.strip()
    if text[:2].lower() == '0x':
        text = text[2:]
    if len(text) != 64:
        raise ValueError(
            'transaction hash must be 64 hex characters (32 bytes), got %d' % len(text)
        )
    z = int(text, 16)
    if z >= N:
        # secp256k1 verification reduces z mod n implicitly via (z * w mod n);
        # keep that reduction explicit so the printed value matches the maths.
        z %= N
    return z


def format_tx_hash(z: int) -> str:
    """Render a ``z`` value as the hex string a block explorer would show."""
    return '%064x' % z


def _parse_signature_value(value, name: str, decimal: bool = False) -> int:
    """Parse ``r`` or ``s``.

    Bare strings are read as hex (the convention for Bitcoin signatures) unless
    ``decimal`` is true; a ``0x`` prefix always means hex.  The radix is never
    guessed, because every decimal value is also a syntactically valid hex one.
    """
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text[:2].lower() == '0x':
        text = text[2:]
        decimal = False
    try:
        return int(text, 10 if decimal else 16)
    except ValueError:
        base = 'decimal' if decimal else 'hex'
        raise ValueError('could not parse %s as %s: %r' % (name, base, value)) from None


def recover_public_keys(r: int, s: int, z: int) -> Tuple[PublicKey, ...]:
    """Public keys for which ``(r, s)`` is a valid signature over ``z``.

    ECDSA verification rewrites to ``R = (z/s)·G + (r/s)·Q``.  Solving for
    ``Q`` instead:

        Q = r⁻¹ · (s·R − z·G)

    Since ``R`` is any point whose x coordinate equals ``r`` (mod n) and
    secp256k1 has two such points (y and −y), there are at most two candidate
    keys.  Given only ``(r, s, z)`` there is no way to tell which — if any —
    is the real signer, which is why a "signature" alone proves nothing about
    who produced it.
    """
    inv_r = inverse(r, N)
    if inv_r is None:
        return ()

    keys = []
    for odd in (False, True):
        big_r = point_from_x(r, odd)
        if big_r is None:
            continue
        # Q = r⁻¹ * (s*R - z*G) = (s*r⁻¹)*R + (-z*r⁻¹)*G
        q = point_add_two_muls(s * inv_r % N, big_r, (-z * inv_r) % N, G)
        if q is None or q in keys:
            continue
        keys.append(PublicKey(q))
    return tuple(keys)


def inspect_claim(
    tx_hash: str,
    r,
    s,
    x_coord: Optional[str] = None,
    y_coord: Optional[str] = None,
    decimal: bool = False,
) -> Inspection:
    """Decode a claimed signature and check it against a public key.

    ``tx_hash`` is the 32-byte hex transaction hash used as ``z`` (the message
    hash), ``r`` and ``s`` are the signature values as ints or hex strings, and
    the optional coordinates identify the key being claimed.  When omitted,
    the Genesis block key is used.
    """
    r_int = _parse_signature_value(r, 'r', decimal)
    s_int = _parse_signature_value(s, 's', decimal)
    z = tx_hash_to_z(tx_hash)

    if x_coord is None or y_coord is None:
        claimed: Optional[PublicKey] = None
    else:
        point: Point = (int(x_coord, 16), int(y_coord, 16))
        if not is_on_curve(point):
            raise ValueError('public key point is not on secp256k1')
        claimed = PublicKey(point)

    sig = Signature(r_int, s_int)
    valid = claimed is not None and hashless_verify(claimed, sig, z)
    return Inspection(
        r=r_int,
        s=s_int,
        z=z,
        claimed_key=claimed,
        valid=valid,
        recovered_keys=recover_public_keys(r_int, s_int, z),
    )
