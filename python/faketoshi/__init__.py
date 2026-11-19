"""A dependency-free Python port of the Faketoshi Haskell library."""

from .curve import G, N, P, is_on_curve, point_add, point_add_two_muls, point_base_mul, point_mul
from .faketoshi import (
    FaketoshiCredentials,
    PublicKey,
    Signature,
    generate_forgery,
    hashless_verify,
    valid_forgery,
)

__all__ = [
    'FaketoshiCredentials',
    'PublicKey',
    'Signature',
    'G',
    'N',
    'P',
    'generate_forgery',
    'hashless_verify',
    'is_on_curve',
    'point_add',
    'point_add_two_muls',
    'point_base_mul',
    'point_mul',
    'valid_forgery',
]
