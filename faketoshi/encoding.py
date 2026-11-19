"""Byte-level helpers: hashing, encodings, key/address formatting.

Standard library only — ``hashlib`` already ships RIPEMD160 in most builds, but
OpenSSL 3 dropped it from some, so a small pure-Python fallback is included.
"""

from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()


def dsha256(data: bytes) -> bytes:
    """Double SHA256, the hash Bitcoin uses everywhere."""
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — the hash160 used in addresses."""
    return ripemd160(sha256(data))


# --- RIPEMD160 -------------------------------------------------------------

_RMD_R = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RMD_RP = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_RMD_S = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_RMD_SP = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
_RMD_K = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RMD_KP = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _rmd_f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rotl(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ripemd160(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160 (fallback / reference implementation)."""
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    msg = bytearray(data)
    bit_len = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, 'little')

    for off in range(0, len(msg), 64):
        x = [int.from_bytes(msg[off + 4 * i:off + 4 * i + 4], 'little') for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = _rotl(al + _rmd_f(j, bl, cl, dl) + x[_RMD_R[j]] + _RMD_K[rnd], _RMD_S[j]) + el
            t &= 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, _rotl(cl, 10), bl, t
            t = _rotl(ar + _rmd_f(79 - j, br, cr, dr) + x[_RMD_RP[j]] + _RMD_KP[rnd], _RMD_SP[j]) + er
            t &= 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, _rotl(cr, 10), br, t
        t = (h[1] + cl + dr) & 0xFFFFFFFF
        h[1] = (h[2] + dl + er) & 0xFFFFFFFF
        h[2] = (h[3] + el + ar) & 0xFFFFFFFF
        h[3] = (h[4] + al + br) & 0xFFFFFFFF
        h[4] = (h[0] + bl + cr) & 0xFFFFFFFF
        h[0] = t
    return b''.join(v.to_bytes(4, 'little') for v in h)


# ---------------------------------------------------------------------------
# varint / script helpers
# ---------------------------------------------------------------------------


def encode_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError('varint cannot be negative')
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xFFFFFFFF:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Return ``(value, new_offset)``."""
    if offset >= len(data):
        raise ValueError('truncated varint')
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if offset + 1 + size > len(data):
        raise ValueError('truncated varint')
    return int.from_bytes(data[offset + 1:offset + 1 + size], 'little'), offset + 1 + size


def push_data(data: bytes) -> bytes:
    """Minimal push opcode for a data blob (as used in scriptSig / witness)."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b'\x4c' + bytes([n]) + data
    if n <= 0xFFFF:
        return b'\x4d' + n.to_bytes(2, 'little') + data
    return b'\x4e' + n.to_bytes(4, 'little') + data


# ---------------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------------

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode_check(payload: bytes) -> str:
    data = payload + dsha256(payload)[:4]
    num = int.from_bytes(data, 'big')
    out = ''
    while num:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    pad = len(data) - len(data.lstrip(b'\x00'))
    return '1' * pad + out


def b58decode_check(text: str) -> bytes:
    num = 0
    for char in text:
        if char not in _B58_ALPHABET:
            raise ValueError('invalid base58 character: %r' % char)
        num = num * 58 + _B58_ALPHABET.index(char)
    raw = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    pad = len(text) - len(text.lstrip('1'))
    data = b'\x00' * pad + raw
    payload, checksum = data[:-4], data[-4:]
    if dsha256(payload)[:4] != checksum:
        raise ValueError('bad base58 checksum')
    return payload


# ---------------------------------------------------------------------------
# Bech32 (BIP173) for segwit addresses
# ---------------------------------------------------------------------------

_BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _bech32_polymod(values) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits: int, tobits: int, pad: bool = True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError('invalid padding in bech32 data')
    return ret


def segwit_encode(hrp: str, witver: int, program: bytes) -> str:
    data = [witver] + _convertbits(program, 8, 5)
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(_BECH32_CHARSET[d] for d in data + checksum)


def segwit_decode(address: str) -> Tuple[str, int, bytes]:
    if address.lower() != address and address.upper() != address:
        raise ValueError('mixed-case bech32 address')
    address = address.lower()
    pos = address.rfind('1')
    if pos < 1 or pos + 7 > len(address) or len(address) > 90:
        raise ValueError('invalid bech32 address')
    hrp, data_part = address[:pos], address[pos + 1:]
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError('invalid bech32 hrp')
    data = []
    for char in data_part:
        if char not in _BECH32_CHARSET:
            raise ValueError('invalid bech32 character: %r' % char)
        data.append(_BECH32_CHARSET.index(char))
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != 1:
        raise ValueError('bad bech32 checksum')
    witver = data[0]
    if witver > 16:
        raise ValueError('invalid witness version')
    program = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    return hrp, witver, program


# ---------------------------------------------------------------------------
# Output scripts and addresses
# ---------------------------------------------------------------------------

#: network name -> (p2pkh version, p2sh version, wif version, bech32 hrp)
NETWORKS = {
    'mainnet': (0x00, 0x05, 0x80, 'bc'),
    'testnet': (0x6F, 0xC4, 0xEF, 'tb'),
    'regtest': (0x6F, 0xC4, 0xEF, 'bcrt'),
}


def network_params(network: str):
    try:
        return NETWORKS[network]
    except KeyError:
        raise ValueError(
            'unknown network %r (choose from %s)' % (network, ', '.join(NETWORKS))
        ) from None


def p2pkh_script(pubkey: bytes) -> bytes:
    """``OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG``."""
    return b'\x76\xa9' + push_data(hash160(pubkey)) + b'\x88\xac'


def p2wpkh_script(pubkey: bytes) -> bytes:
    """``OP_0 <hash160(pubkey)>`` — the witness program."""
    return b'\x00' + push_data(hash160(pubkey))


def p2pkh_address(pubkey: bytes, network: str = 'mainnet') -> str:
    version = network_params(network)[0]
    return b58encode_check(bytes([version]) + hash160(pubkey))


def p2wpkh_address(pubkey: bytes, network: str = 'mainnet') -> str:
    hrp = network_params(network)[3]
    return segwit_encode(hrp, 0, hash160(pubkey))


def script_to_address(script: bytes, network: str = 'mainnet') -> Optional[str]:
    """Best-effort reverse mapping, for display purposes."""
    p2pkh_version, p2sh_version, _, hrp = network_params(network)
    if len(script) == 25 and script[:3] == b'\x76\xa9\x14' and script[23:] == b'\x88\xac':
        return b58encode_check(bytes([p2pkh_version]) + script[3:23])
    if len(script) == 23 and script[0] == 0xA9 and script[1] == 0x14 and script[22] == 0x87:
        return b58encode_check(bytes([p2sh_version]) + script[2:22])
    if len(script) == 22 and script[:2] == b'\x00\x14':
        return segwit_encode(hrp, 0, script[2:])
    if len(script) == 34 and script[0] == 0x00:
        return segwit_encode(hrp, 0, script[2:])
    return None
