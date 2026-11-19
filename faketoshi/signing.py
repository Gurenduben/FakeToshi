"""Signing, verification and Bitcoin transaction construction.

This is the *legitimate* half of the story: with a private key you control you
can sign any message hash you like — including a real Bitcoin sighash — and the
resulting ``(r, s, z)`` verifies for the matching public key. Nothing here
breaks ECDSA; it just does what a wallet does.

Contents:

    * RFC 6979 deterministic nonces
    * low-s normalised ECDSA signing and verification, over a given ``z``
    * DER encoding/decoding of signatures with the trailing sighash byte
    * legacy (pre-segwit) and BIP143 (segwit v0) sighash computation
    * minimal transaction parsing/serialisation and a witness-aware txid
"""

import hmac
import hashlib
from dataclasses import dataclass, field, replace
from typing import List, Optional, Sequence, Tuple

from .curve import G, N, Point, inverse, is_on_curve, point_add_two_muls, point_base_mul
from .encoding import (
    decode_varint,
    dsha256,
    encode_varint,
    push_data,
    script_to_address,
    sha256,
)

#: SIGHASH types (BIP143 / consensus).
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

#: Bitcoin Core's ``uint256::ONE``: the bytes ``01 00 00 ... 00``.  For the
#: broken SIGHASH_SINGLE case ``SignatureHash`` returns this constant instead of
#: a hash, and it is consumed as a big-endian 256-bit value, i.e. ``2**248``
#: (not the integer 1).
HASH_ONE = b'\x01' + b'\x00' * 31
SIGHASH_SINGLE_BUG_DIGEST = int.from_bytes(HASH_ONE, 'big')  # 2**248


# ---------------------------------------------------------------------------
# RFC 6979 deterministic nonces
# ---------------------------------------------------------------------------


def _bits2int(data: bytes) -> int:
    value = int.from_bytes(data, 'big')
    excess = len(data) * 8 - N.bit_length()
    if excess > 0:
        value >>= excess
    return value


def _bits2octets(data: bytes) -> bytes:
    z1 = _bits2int(data)
    z2 = (z1 - N) if z1 >= N else z1
    return z2.to_bytes((N.bit_length() + 7) // 8, 'big')


def rfc6979_nonces(private_key: int, z: int, extra_entropy: bytes = b''):
    """Yield deterministic nonces ``k`` per RFC 6979 (section 3.2, HMAC-SHA256).

    Deterministic nonces remove the reliance on a good RNG, which is where most
    real-world ECDSA key leaks have come from.
    """
    hash_len = 32
    x = private_key.to_bytes(hash_len, 'big')
    h1 = (z % N).to_bytes(hash_len, 'big')

    v = b'\x01' * hash_len
    k = b'\x00' * hash_len
    k = hmac.new(k, v + b'\x00' + x + _bits2octets(h1) + extra_entropy, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + _bits2octets(h1) + extra_entropy, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = _bits2int(v)
        if 1 <= candidate < N:
            yield candidate
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


def private_key_to_public_key(private_key: int, compressed: bool = True) -> bytes:
    """SEC1 encoding of the public key for ``private_key``."""
    if not 1 <= private_key < N:
        raise ValueError('private key must be in [1, n-1]')
    point = point_base_mul(private_key)
    assert point is not None
    return encode_point(point, compressed)


def encode_point(point: Point, compressed: bool = True) -> bytes:
    if point is None:
        raise ValueError('cannot encode the point at infinity')
    x, y = point
    if compressed:
        return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def decode_point(data: bytes) -> Point:
    """Parse a SEC1 public key (compressed or uncompressed)."""
    from .curve import point_from_x

    if len(data) == 33 and data[0] in (0x02, 0x03):
        point = point_from_x(int.from_bytes(data[1:], 'big'), data[0] == 0x03)
    elif len(data) == 65 and data[0] == 0x04:
        point = (int.from_bytes(data[1:33], 'big'), int.from_bytes(data[33:], 'big'))
    else:
        raise ValueError('unsupported public key encoding')
    if point is None or not is_on_curve(point):
        raise ValueError('public key is not a valid curve point')
    return point


def private_key_to_wif(private_key: int, network: str = 'mainnet', compressed: bool = True) -> str:
    from .encoding import b58encode_check, network_params

    version = network_params(network)[2]
    payload = bytes([version]) + private_key.to_bytes(32, 'big')
    if compressed:
        payload += b'\x01'
    return b58encode_check(payload)


def wif_to_private_key(text: str) -> Tuple[int, bool]:
    """Return ``(private_key, compressed_flag)``."""
    from .encoding import b58decode_check

    payload = b58decode_check(text.strip())
    if len(payload) == 33:
        return int.from_bytes(payload[1:], 'big'), False
    if len(payload) == 34 and payload[-1] == 0x01:
        return int.from_bytes(payload[1:33], 'big'), True
    raise ValueError('unsupported WIF payload length')


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def sign_z(private_key: int, z: int, deterministic: bool = True) -> Tuple[int, int]:
    """Sign the message hash ``z`` directly, returning normalised ``(r, s)``.

    ``z`` is used as-is: no hashing is applied, so this pairs with
    :func:`sighash_legacy` / :func:`sighash_segwit_v0`, which already hash.
    """
    if not 1 <= private_key < N:
        raise ValueError('private key must be in [1, n-1]')

    if deterministic:
        nonces = rfc6979_nonces(private_key, z)
        take = lambda: next(nonces)  # noqa: E731
    else:
        import secrets

        def take() -> int:
            return 1 + secrets.randbelow(N - 1)

    while True:
        k = take()
        point = point_base_mul(k)
        if point is None:
            continue
        r = point[0] % N
        if r == 0:
            continue
        s = (pow(k, -1, N) * (z + r * private_key)) % N
        if s == 0:
            continue
        if s > N // 2:  # low-s normalisation: required by Bitcoin policy/consensus
            s = N - s
        return r, s


def verify_z(public_key: Point, r: int, s: int, z: int) -> bool:
    """Standard ECDSA verification over the given ``z``."""
    if public_key is None:
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = inverse(s, N)
    if w is None:
        return False
    point = point_add_two_muls(z * w % N, G, r * w % N, public_key)
    return point is not None and point[0] % N == r


# ---------------------------------------------------------------------------
# DER encoding
# ---------------------------------------------------------------------------


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return b'\x02' + bytes([len(raw)]) + raw


def der_encode(r: int, s: int, sighash_type: int = SIGHASH_ALL) -> bytes:
    """``0x30 <len> 0x02 <r> 0x02 <s>`` plus the trailing sighash type byte."""
    body = _der_int(r) + _der_int(s)
    return b'\x30' + bytes([len(body)]) + body + bytes([sighash_type & 0xFF])


def der_decode(data: bytes, has_sighash_byte: bool = True) -> Tuple[int, int, Optional[int]]:
    """Return ``(r, s, sighash_type)``."""
    if len(data) < 8 or data[0] != 0x30:
        raise ValueError('not a DER sequence')
    if data[1] + 2 + (1 if has_sighash_byte else 0) != len(data):
        raise ValueError('bad DER length prefix')
    body = data[2:2 + data[1]]
    if len(body) != data[1]:
        raise ValueError('truncated DER body')
    if body[0] != 0x02:
        raise ValueError('expected DER INTEGER for r')
    rlen = body[1]
    r = int.from_bytes(body[2:2 + rlen], 'big')
    rest = body[2 + rlen:]
    if not rest or rest[0] != 0x02:
        raise ValueError('expected DER INTEGER for s')
    slen = rest[1]
    s = int.from_bytes(rest[2:2 + slen], 'big')
    if rest[2 + slen:]:
        raise ValueError('trailing data inside the DER sequence')

    # Bitcoin appends the sighash type byte *after* the DER sequence.
    tail = data[2 + data[1]:]
    sighash = None
    if has_sighash_byte:
        if len(tail) != 1:
            raise ValueError('missing sighash byte after the DER sequence')
        sighash = tail[0]
    elif tail:
        raise ValueError('trailing data after the DER sequence')
    return r, s, sighash


def compact_encode(r: int, s: int) -> bytes:
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------


@dataclass
class TxIn:
    """A transaction input. ``script_sig`` / ``witness`` are filled when signing."""

    prev_txid: str  # hex, big-endian as explorers display it
    prev_vout: int
    sequence: int = 0xFFFFFFFF
    script_sig: bytes = b''
    witness: Tuple[bytes, ...] = ()

    def outpoint(self) -> bytes:
        return bytes.fromhex(self.prev_txid)[::-1] + self.prev_vout.to_bytes(4, 'little')


@dataclass
class TxOut:
    value: int  # satoshis
    script_pubkey: bytes

    def serialize(self) -> bytes:
        return self.value.to_bytes(8, 'little') + encode_varint(len(self.script_pubkey)) + self.script_pubkey


@dataclass
class Transaction:
    version: int = 2
    inputs: List[TxIn] = field(default_factory=list)
    outputs: List[TxOut] = field(default_factory=list)
    locktime: int = 0

    # -- serialisation ------------------------------------------------------

    def serialize(self, with_witness: bool = True) -> bytes:
        segwit = with_witness and any(i.witness for i in self.inputs)
        out = self.version.to_bytes(4, 'little')
        if segwit:
            out += b'\x00\x01'
        out += encode_varint(len(self.inputs))
        for txin in self.inputs:
            out += txin.outpoint()
            out += encode_varint(len(txin.script_sig)) + txin.script_sig
            out += txin.sequence.to_bytes(4, 'little')
        out += encode_varint(len(self.outputs))
        for txout in self.outputs:
            out += txout.serialize()
        if segwit:
            for txin in self.inputs:
                out += encode_varint(len(txin.witness))
                for item in txin.witness:
                    out += encode_varint(len(item)) + item
        out += self.locktime.to_bytes(4, 'little')
        return out

    def txid(self) -> str:
        """Txid: the double-SHA256 of the *non-witness* serialisation, reversed."""
        return dsha256(self.serialize(with_witness=False))[::-1].hex()

    def wtxid(self) -> str:
        return dsha256(self.serialize(with_witness=True))[::-1].hex()

    def hex(self) -> str:
        return self.serialize(with_witness=True).hex()

    def is_segwit(self) -> bool:
        return any(i.witness for i in self.inputs)

    # -- sighashes ----------------------------------------------------------

    def sighash_legacy(self, index: int, script_code: bytes, sighash_type: int = SIGHASH_ALL) -> int:
        """Pre-segwit signature digest (``OP_CHECKSIG`` semantics)."""
        base = sighash_type & 0x1F
        anyonecanpay = bool(sighash_type & SIGHASH_ANYONECANPAY)

        if not 0 <= index < len(self.inputs):
            raise ValueError('input index %d out of range' % index)
        if base == SIGHASH_SINGLE and index >= len(self.outputs):
            # Bitcoin Core: return uint256::ONE for the "nOut out of range" case.
            return SIGHASH_SINGLE_BUG_DIGEST

        inputs = [self.inputs[index]] if anyonecanpay else list(self.inputs)
        if anyonecanpay:
            selected = 0
        else:
            selected = index

        payload = self.version.to_bytes(4, 'little')
        payload += encode_varint(len(inputs))
        for i, txin in enumerate(inputs):
            payload += txin.outpoint()
            if i == selected:
                payload += encode_varint(len(script_code)) + script_code
            else:
                payload += b'\x00'  # empty script for the other inputs
            if base in (SIGHASH_NONE, SIGHASH_SINGLE) and i != selected:
                payload += b'\x00\x00\x00\x00'
            else:
                payload += txin.sequence.to_bytes(4, 'little')

        if base == SIGHASH_NONE:
            outputs: Sequence[TxOut] = []
        elif base == SIGHASH_SINGLE:
            outputs = [TxOut(0xFFFFFFFFFFFFFFFF, b'')] * index + [self.outputs[index]]
        else:
            outputs = self.outputs

        payload += encode_varint(len(outputs))
        for txout in outputs:
            payload += txout.serialize()

        payload += self.locktime.to_bytes(4, 'little')
        payload += (sighash_type & 0xFF).to_bytes(4, 'little')
        return int.from_bytes(dsha256(payload), 'big')

    def sighash_segwit_v0(
        self,
        index: int,
        script_code: bytes,
        amount: int,
        sighash_type: int = SIGHASH_ALL,
    ) -> int:
        """BIP143 digest for segwit v0 inputs (P2WPKH and P2WSH)."""
        base = sighash_type & 0x1F
        anyonecanpay = bool(sighash_type & SIGHASH_ANYONECANPAY)

        if not 0 <= index < len(self.inputs):
            raise ValueError('input index %d out of range' % index)

        zero = b'\x00' * 32
        hash_prevouts = (
            zero
            if anyonecanpay
            else dsha256(b''.join(i.outpoint() for i in self.inputs))
        )
        hash_sequence = (
            zero
            if anyonecanpay or base in (SIGHASH_SINGLE, SIGHASH_NONE)
            else dsha256(b''.join(i.sequence.to_bytes(4, 'little') for i in self.inputs))
        )
        if base == SIGHASH_ALL:
            hash_outputs = dsha256(b''.join(o.serialize() for o in self.outputs))
        elif base == SIGHASH_SINGLE and index < len(self.outputs):
            hash_outputs = dsha256(self.outputs[index].serialize())
        else:
            # BIP143 has no constant-digest bug: a missing matching output just
            # means hashOutputs is the zero hash.
            hash_outputs = zero

        txin = self.inputs[index]
        preimage = self.version.to_bytes(4, 'little')
        preimage += hash_prevouts
        preimage += hash_sequence
        preimage += txin.outpoint()
        preimage += encode_varint(len(script_code)) + script_code
        preimage += amount.to_bytes(8, 'little')
        preimage += txin.sequence.to_bytes(4, 'little')
        preimage += hash_outputs
        preimage += self.locktime.to_bytes(4, 'little')
        preimage += (sighash_type & 0xFF).to_bytes(4, 'little')
        return int.from_bytes(dsha256(preimage), 'big')


# ---------------------------------------------------------------------------
# Script-type helpers for the signing workflow
# ---------------------------------------------------------------------------


def generate_private_key() -> int:
    """A fresh private key from the OS CSPRNG."""
    import secrets

    while True:
        candidate = 1 + secrets.randbelow(N - 1)
        if 1 <= candidate < N:
            return candidate


class InputKind:
    P2PKH = 'p2pkh'
    P2WPKH = 'p2wpkh'
    P2SH_P2WPKH = 'p2sh-p2wpkh'


def detect_input_kind(script_pubkey: bytes) -> str:
    if len(script_pubkey) == 25 and script_pubkey[:3] == b'\x76\xa9\x14' and script_pubkey[23:] == b'\x88\xac':
        return InputKind.P2PKH
    if len(script_pubkey) == 22 and script_pubkey[:2] == b'\x00\x14':
        return InputKind.P2WPKH
    if len(script_pubkey) == 23 and script_pubkey[0] == 0xA9 and script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87:
        return InputKind.P2SH_P2WPKH  # cannot tell from the script alone; caller confirms
    raise ValueError(
        'unsupported scriptPubKey %s: this tool signs P2PKH, P2WPKH and P2SH-P2WPKH only'
        % script_pubkey.hex()
    )


@dataclass
class SignatureInfo:
    """Everything about one signed input, including the requested ``r``/``s``/``z``."""

    index: int
    kind: str
    r: int
    s: int
    z: int
    sighash_type: int
    der: bytes  # DER + sighash byte, as pushed into scriptSig / witness
    script_pubkey: bytes
    amount: Optional[int] = None

    def __str__(self) -> str:
        return (
            'input %d (%s)\n'
            '  r: %d\n'
            '  s: %d\n'
            '  z: %d\n'
            '  z (hex): %064x\n'
            '  sighash type: 0x%02x\n'
            '  signature: %s'
            % (
                self.index,
                self.kind,
                self.r,
                self.s,
                self.z,
                self.z,
                self.sighash_type,
                self.der.hex(),
            )
        )


def sign_transaction(
    tx: Transaction,
    private_key: int,
    prevouts: Sequence[Tuple[bytes, int]],
    kind: str = InputKind.P2WPKH,
    sighash_type: int = SIGHASH_ALL,
    compressed: bool = True,
) -> Tuple[Transaction, List[SignatureInfo]]:
    """Sign every input with one key, returning the signed tx and signature details.

    ``prevouts[index]`` is ``(script_pubkey, amount_sats)`` of the coin being
    spent.  ``kind`` selects how the signature is wrapped; ``p2pkh`` and
    ``p2sh-p2wpkh`` use the legacy digest, ``p2wpkh`` uses BIP143.  The amount
    matters for segwit signing and must come from the actual previous output.
    """
    if kind == InputKind.P2SH_P2WPKH:
        raise ValueError('use sign_transaction_kinds for p2sh-p2wpkh inputs')

    pubkey = private_key_to_public_key(private_key, compressed)
    if len(prevouts) != len(tx.inputs):
        raise ValueError('need one (scriptPubKey, amount) entry per input')

    infos: List[SignatureInfo] = []
    signed_inputs: List[TxIn] = []
    for index, (txin, (script_pubkey, amount)) in enumerate(zip(tx.inputs, prevouts)):
        if kind == InputKind.P2PKH:
            z = tx.sighash_legacy(index, script_pubkey, sighash_type)
        else:
            z = tx.sighash_segwit_v0(index, p2pkh_script_code(pubkey), amount, sighash_type)
        r, s = sign_z(private_key, z)
        der = der_encode(r, s, sighash_type)

        if kind == InputKind.P2PKH:
            script_sig = push_data(der) + push_data(pubkey)
            new_in = replace(txin, script_sig=script_sig, witness=())
        else:
            new_in = replace(txin, script_sig=b'', witness=(der, pubkey))
        signed_inputs.append(new_in)
        infos.append(
            SignatureInfo(
                index=index,
                kind=kind,
                r=r,
                s=s,
                z=z,
                sighash_type=sighash_type,
                der=der,
                script_pubkey=script_pubkey,
                amount=amount,
            )
        )

    return replace(tx, inputs=signed_inputs), infos


def p2pkh_script_code(pubkey: bytes) -> bytes:
    """BIP143 ``scriptCode`` for P2WPKH: ``OP_DUP OP_HASH160 <hash160> ...``."""
    from .encoding import hash160

    return b'\x76\xa9' + push_data(hash160(pubkey)) + b'\x88\xac'


def sign_transaction_kinds(
    tx: Transaction,
    private_key: int,
    prevouts: Sequence[Tuple[bytes, int]],
    kinds: Sequence[str],
    sighash_type: int = SIGHASH_ALL,
    compressed: bool = True,
) -> Tuple[Transaction, List[SignatureInfo]]:
    """Like :func:`sign_transaction` but with a script kind per input."""
    if not (len(prevouts) == len(kinds) == len(tx.inputs)):
        raise ValueError('need matching counts of inputs, prevouts and kinds')

    pubkey = private_key_to_public_key(private_key, compressed)
    signed: List[TxIn] = []
    infos: List[SignatureInfo] = []
    for index, (txin, (script_pubkey, amount), kind) in enumerate(
        zip(tx.inputs, prevouts, kinds)
    ):
        if kind == InputKind.P2PKH:
            z = tx.sighash_legacy(index, script_pubkey, sighash_type)
            script_sig = push_data(b'')  # placeholder, filled below
            witness: Tuple[bytes, ...] = ()
        elif kind == InputKind.P2WPKH:
            z = tx.sighash_segwit_v0(index, p2pkh_script_code(pubkey), amount, sighash_type)
            script_sig = b''
            witness = ()
        elif kind == InputKind.P2SH_P2WPKH:
            redeem = b'\x00\x14' + p2pkh_script_code(pubkey)[3:23]
            z = tx.sighash_segwit_v0(index, p2pkh_script_code(pubkey), amount, sighash_type)
            script_sig = push_data(redeem)
            witness = ()
        else:
            raise ValueError('unknown input kind %r' % (kind,))

        r, s = sign_z(private_key, z)
        der = der_encode(r, s, sighash_type)

        if kind == InputKind.P2PKH:
            script_sig = push_data(der) + push_data(pubkey)
            witness = ()
        elif kind == InputKind.P2WPKH:
            witness = (der, pubkey)
        else:
            witness = (der, pubkey)

        signed.append(replace(txin, script_sig=script_sig, witness=witness))
        infos.append(
            SignatureInfo(
                index=index,
                kind=kind,
                r=r,
                s=s,
                z=z,
                sighash_type=sighash_type,
                der=der,
                script_pubkey=script_pubkey,
                amount=amount,
            )
        )

    return replace(tx, inputs=signed), infos


# ---------------------------------------------------------------------------
# Parsing (enough to inspect and re-serialise a transaction)
# ---------------------------------------------------------------------------


def parse_transaction(raw: bytes) -> Transaction:
    """Parse a serialised transaction, including the segwit marker/flag."""
    offset = 0

    def read(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(raw):
            raise ValueError('truncated transaction')
        chunk = raw[offset:offset + n]
        offset += n
        return chunk

    version = int.from_bytes(read(4), 'little')
    segwit = raw[offset:offset + 2] == b'\x00\x01'
    if segwit:
        read(2)

    n_in, offset = decode_varint(raw, offset)
    inputs: List[TxIn] = []
    for _ in range(n_in):
        prev_hash = read(32)[::-1].hex()
        vout = int.from_bytes(read(4), 'little')
        script_len, offset = decode_varint(raw, offset)
        script_sig = read(script_len)
        sequence = int.from_bytes(read(4), 'little')
        inputs.append(TxIn(prev_hash, vout, sequence, script_sig))

    n_out, offset = decode_varint(raw, offset)
    outputs: List[TxOut] = []
    for _ in range(n_out):
        value = int.from_bytes(read(8), 'little')
        script_len, offset = decode_varint(raw, offset)
        outputs.append(TxOut(value, read(script_len)))

    if segwit:
        for txin in inputs:
            count, offset = decode_varint(raw, offset)
            items = []
            for _ in range(count):
                size, offset = decode_varint(raw, offset)
                items.append(read(size))
            txin.witness = tuple(items)

    locktime = int.from_bytes(read(4), 'little')
    if offset != len(raw):
        raise ValueError('trailing bytes after transaction')
    return Transaction(version, inputs, outputs, locktime)


def describe_transaction(tx: Transaction, network: str = 'mainnet') -> str:
    lines = ['txid:   %s' % tx.txid()]
    if tx.is_segwit():
        lines.append('wtxid:  %s' % tx.wtxid())
    lines.append('version: %d, locktime: %d' % (tx.version, tx.locktime))
    for i, txin in enumerate(tx.inputs):
        lines.append('input %d: %s:%d sequence=0x%08x' % (i, txin.prev_txid, txin.prev_vout, txin.sequence))
    for i, txout in enumerate(tx.outputs):
        address = script_to_address(txout.script_pubkey, network)
        lines.append(
            'output %d: %d sats -> %s'
            % (i, txout.value, address or txout.script_pubkey.hex())
        )
    return '\n'.join(lines)
