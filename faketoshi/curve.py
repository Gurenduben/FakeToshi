"""Minimal secp256k1 arithmetic.

This replaces the parts of the Haskell ``cryptonite`` package that the original
Faketoshi code relied on (``Crypto.PubKey.ECC.Prim`` / ``.Types``):

    * the curve parameters (``ecc_n``, ``ecc_g``, ``common_curve``)
    * ``pointAdd``, ``pointMul``, ``pointBaseMul``, ``pointAddTwoMuls``
    * ``inverse`` (modular inverse, from ``Crypto.Number.ModArithmetic``)

Points are ``None`` for the point at infinity and ``(x, y)`` tuples otherwise.
"""

from typing import Optional, Tuple

Point = Optional[Tuple[int, int]]

# secp256k1 domain parameters (SEC 2, "SEC_p256k1" in cryptonite).
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G: Tuple[int, int] = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def inverse(a: int, m: int) -> Optional[int]:
    """Modular inverse of ``a`` modulo ``m``, or ``None`` if it does not exist.

    Mirrors cryptonite's ``inverse``, which returns ``Nothing`` for
    non-invertible inputs instead of raising.
    """
    a %= m
    if a == 0:
        return None
    try:
        return pow(a, -1, m)
    except ValueError:  # not coprime with m
        return None


# ``pow(a, -1, m)`` is only available on Python >= 3.8; provide a portable
# fallback so the module stays usable on older interpreters.
try:  # pragma: no cover - trivial
    pow(3, -1, 7)
except TypeError:  # pragma: no cover

    def _inverse_via_egcd(a: int, m: int) -> int:
        old_r, r = a % m, m
        old_s, s = 1, 0
        while r:
            q = old_r // r
            old_r, r = r, old_r - q * r
            old_s, s = s, old_s - q * s
        if old_r != 1:
            raise ValueError("not invertible")
        return old_s % m

    def inverse(a: int, m: int) -> Optional[int]:  # type: ignore[misc]
        a %= m
        if a == 0:
            return None
        try:
            return _inverse_via_egcd(a, m)
        except ValueError:
            return None


def point_from_x(x: int, odd: bool) -> Optional[Tuple[int, int]]:
    """Recover a curve point from its x coordinate, choosing the y parity.

    secp256k1 has ``p % 4 == 3``, so a square root of ``alpha`` is
    ``alpha ** ((p + 1) // 4)``.  Returns ``None`` when ``x`` is not the
    abscissa of any point on the curve.
    """
    if x < 0 or x >= P:
        return None
    alpha = (x * x * x + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if (y * y - alpha) % P != 0:
        return None
    if (y % 2 == 1) != odd:
        y = P - y
    return (x, y)


def is_on_curve(point: Point) -> bool:
    """True if ``point`` satisfies ``y^2 = x^3 + 7 (mod P)``."""
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + 7)) % P == 0


def _double(point: Tuple[int, int]) -> Point:
    x, y = point
    if y == 0:
        return None
    lam = (3 * x * x) * inverse(2 * y, P) % P
    x3 = (lam * lam - 2 * x) % P
    return x3, (lam * (x - x3) - y) % P


def _add_points(a: Tuple[int, int], b: Tuple[int, int]) -> Point:
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None  # a == -b
        return _double(a)
    lam = (b[1] - a[1]) * inverse(b[0] - a[0], P) % P
    x3 = (lam * lam - a[0] - b[0]) % P
    return x3, (lam * (a[0] - x3) - a[1]) % P


def point_add(a: Point, b: Point) -> Point:
    """``pointAdd``: add two curve points (``None`` is the identity)."""
    if a is None:
        return b
    if b is None:
        return a
    return _add_points(a, b)


def point_mul(k: int, point: Point) -> Point:
    """``pointMul``: scalar multiplication ``k * point``."""
    k %= N
    if point is None or k == 0:
        return None
    result: Point = None
    addend: Point = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = _double(addend) if addend is not None else None
        k >>= 1
    return result


def point_base_mul(k: int) -> Point:
    """``pointBaseMul``: scalar multiplication of the generator ``G``."""
    return point_mul(k, G)


def point_add_two_muls(u1: int, p1: Point, u2: int, p2: Point) -> Point:
    """``pointAddTwoMuls``: ``u1 * p1 + u2 * p2`` (Shamir's trick)."""
    u1 %= N
    u2 %= N
    if p1 is None and p2 is None:
        return None
    result: Point = None
    for i in range(max(u1.bit_length(), u2.bit_length()) - 1, -1, -1):
        result = _double(result) if result is not None else None
        if (u1 >> i) & 1:
            result = point_add(result, p1)
        if (u2 >> i) & 1:
            result = point_add(result, p2)
    return result
