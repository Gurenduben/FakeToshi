"""A tiny testnet wallet: create the tx, sign it, print everything.

Answers the workflow "I have a private key, I want a transaction whose ``r``,
``s`` and ``z`` match it":

    1. send coins to the address derived from your private key
    2. build the unsigned transaction with this tool
    3. sign it — ``z`` is the BIP143 (or legacy) digest, ``r``/``s`` the ECDSA
       signature over it; all three verify against your public key
    4. broadcast, and the txid of the broadcast transaction is the one that
       carries that signature

Note the ordering: the *signature's* ``z`` is not the txid. A transaction's
txid hashes the whole transaction, including the signature, so it cannot be
known before signing. ``z`` is a per-input sighash; ``txid`` identifies the
finished transaction.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .curve import N
from .encoding import (
    NETWORKS,
    hash160,
    p2pkh_address,
    p2wpkh_address,
    p2wpkh_script,
    p2pkh_script,
    script_to_address,
    segwit_decode,
    network_params,
)
from .signing import (
    InputKind,
    SignatureInfo,
    Transaction,
    TxIn,
    TxOut,
    describe_transaction,
    detect_input_kind,
    private_key_to_public_key,
    private_key_to_wif,
    sign_transaction_kinds,
    wif_to_private_key,
    generate_private_key,
)

#: Fixed coinbase transaction id used by every regtest chain (``bitcoind -regtest``).
REGTEST_COINBASE_TXID = '4a5e1e4baab89f3a32518a88c31e8d5b2ade2f2f4ae1b5a597a15c3a1b8d2ab4'
REGTEST_COINBASE_SCRIPT = bytes.fromhex(
    '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac'
)


@dataclass
class BuiltTransaction:
    """A signed transaction plus everything needed to audit or broadcast it."""

    transaction: Transaction
    signatures: List[SignatureInfo]
    private_key: int
    network: str
    address: str
    wif: str
    pubkey_hex: str
    amount_in: int

    # -- convenience -------------------------------------------------------

    @property
    def txid(self) -> str:
        return self.transaction.txid()

    @property
    def hex(self) -> str:
        return self.transaction.hex()

    def fee(self) -> int:
        return self.amount_in - sum(o.value for o in self.transaction.outputs)

    def report(self) -> str:
        """Human-readable summary including the requested r/s/z values."""
        lines = [
            'network:   %s' % self.network,
            'address:   %s' % self.address,
            'pubkey:    %s' % self.pubkey_hex,
            'wif:       %s' % self.wif,
            '',
            describe_transaction(self.transaction, self.network),
            '',
            'fee:       %d sats' % self.fee(),
        ]
        for info in self.signatures:
            lines.extend(['', str(info)])
        return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Address / script helpers
# ---------------------------------------------------------------------------


#: bech32 prefixes actually in use, so base58 addresses are never mistaken
#: for segwit ones (some base58 addresses contain a ``1`` and only use
#: characters from the bech32 alphabet).
BECH32_HRPS = ('bcrt', 'bc', 'tb')


def _looks_like_bech32(text: str) -> bool:
    lowered = text.lower()
    for prefix in BECH32_HRPS:
        if lowered.startswith(prefix + '1'):
            return True
    return False


def address_to_script(address: str, network: str = 'mainnet') -> bytes:
    """scriptPubKey for a base58 P2PKH/P2SH or bech32 v0 address."""
    p2pkh_version, p2sh_version, _, hrp = network_params(network)
    text = address.strip()

    if _looks_like_bech32(text):
        try:
            addr_hrp, witver, program = segwit_decode(text)
        except ValueError as exc:
            raise ValueError('invalid bech32 address %r: %s' % (text, exc)) from None
        if addr_hrp != hrp:
            raise ValueError(
                'address belongs to %r, but the network is %r (hrp %r)'
                % (addr_hrp, network, hrp)
            )
        if witver != 0 or len(program) not in (20, 32):
            raise ValueError('only v0 P2WPKH/P2WSH addresses are supported')
        return b'\x00' + bytes([len(program)]) + program

    from .encoding import b58decode_check, push_data

    payload = b58decode_check(text)
    version, body = payload[0], payload[1:]
    if len(body) != 20:
        raise ValueError('unsupported address payload')
    if version == p2pkh_version:
        return b'\x76\xa9' + push_data(body) + b'\x88\xac'
    if version == p2sh_version:
        return b'\xa9' + push_data(body) + b'\x87'
    raise ValueError('address version does not match network %r' % network)


def script_kind_from_script(script_pubkey: bytes) -> str:
    """Classify a scriptPubKey the tool can sign."""
    if len(script_pubkey) == 22 and script_pubkey[:2] == b'\x00\x14':
        return InputKind.P2WPKH
    if (
        len(script_pubkey) == 25
        and script_pubkey[:3] == b'\x76\xa9\x14'
        and script_pubkey[23:] == b'\x88\xac'
    ):
        return InputKind.P2PKH
    raise ValueError('unsupported scriptPubKey: %s' % script_pubkey.hex())


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def resolve_private_key(wif: Optional[str] = None, key: Optional[str] = None) -> int:
    """Parse a WIF or hex private key, or generate one when neither is given."""
    if wif and key:
        raise ValueError('give either --wif or --key, not both')
    if wif:
        private_key, compressed = wif_to_private_key(wif)
        if not compressed:
            raise ValueError('uncompressed WIF keys are not supported')
        return private_key
    if key:
        text = key.strip()
        if text[:2].lower() == '0x':
            text = text[2:]
        try:
            private_key = int(text, 16)
        except ValueError:
            raise ValueError('private key must be hex') from None
        if not 1 <= private_key < N:
            raise ValueError('private key out of range')
        return private_key
    return generate_private_key()


def key_info(
    private_key: int,
    network: str = 'mainnet',
    kind: str = InputKind.P2PKH,
) -> Tuple[str, str, bytes]:
    """Return ``(address, wif, pubkey_bytes)`` for a private key.

    ``kind`` selects the address type and defaults to P2PKH (legacy, base58),
    matching the default script type this tool signs.  Pass ``p2wpkh`` for a
    bech32 address instead.  Keeping the two in step matters: change is paid to
    this address, so a bech32 default with a P2PKH spend would mix script types
    for no reason.
    """
    pubkey = private_key_to_public_key(private_key)
    if kind == InputKind.P2WPKH:
        address = p2wpkh_address(pubkey, network)
    elif kind == InputKind.P2PKH:
        address = p2pkh_address(pubkey, network)
    else:
        raise ValueError('unsupported address kind %r' % (kind,))
    return address, private_key_to_wif(private_key, network), pubkey


# ---------------------------------------------------------------------------
# Building transactions
# ---------------------------------------------------------------------------


def _parse_output(spec: str, network: str) -> TxOut:
    """``address:amount`` or ``script:amount`` (amount in satoshis)."""
    address, _, amount_text = spec.rpartition(':')
    if not address or not amount_text:
        raise ValueError('expected ADDRESS:SATS, got %r' % spec)
    try:
        amount = int(amount_text)
    except ValueError:
        raise ValueError('amount must be an integer number of satoshis: %r' % amount_text) from None
    if amount < 0:
        raise ValueError('amount cannot be negative')
    if address.lower().startswith('script:'):
        script = bytes.fromhex(address.split(':', 1)[1])
    else:
        script = address_to_script(address, network)
    return TxOut(amount, script)


def _parse_input(spec: str) -> Tuple[TxIn, int]:
    """``TXID:VOUT:AMOUNT_SATS[:SEQUENCE]`` -> ``(TxIn, amount)``.

    The amount is mandatory: segwit (BIP143) signatures commit to the value of
    the coin being spent, so signing with the wrong amount produces a
    transaction that nodes reject.
    """
    parts = spec.split(':')
    if len(parts) not in (3, 4):
        raise ValueError(
            'expected TXID:VOUT:AMOUNT_SATS[:SEQUENCE], got %r' % spec
        )
    txid, vout_text, amount_text = parts[0], parts[1], parts[2]
    if len(txid) != 64:
        raise ValueError('prev txid must be 64 hex characters: %r' % txid)
    int(txid, 16)  # validate
    try:
        vout = int(vout_text)
    except ValueError:
        raise ValueError('vout must be an integer: %r' % vout_text) from None
    try:
        amount = int(amount_text)
    except ValueError:
        raise ValueError('amount must be an integer number of satoshis: %r' % amount_text) from None
    sequence = int(parts[3], 0) if len(parts) == 4 else 0xFFFFFFFF
    return TxIn(prev_txid=txid.lower(), prev_vout=vout, sequence=sequence), amount


def build_transaction(
    inputs: Sequence[str],
    outputs: Sequence[str],
    private_key: int,
    network: str = 'mainnet',
    kind: Optional[str] = None,
    sighash_type: int = 0x01,
    version: int = 2,
    locktime: int = 0,
    regtest: bool = False,
) -> BuiltTransaction:
    """Build and sign a transaction spending P2PKH coins by default.

    ``kind`` selects the script type (P2PKH unless overridden, P2WPKH for
    segwit coins).  With
    ``regtest=True`` the single input's previous output is assumed to be the
    regtest coinbase from :data:`REGTEST_COINBASE_SCRIPT`, which is handy for
    experiments without a real chain.
    """
    if not inputs:
        raise ValueError('at least one input is required')
    if not outputs:
        raise ValueError('at least one output is required')

    parsed = [_parse_input(spec) for spec in inputs]
    tx = Transaction(
        version=version,
        inputs=[txin for txin, _ in parsed],
        outputs=[_parse_output(spec, network) for spec in outputs],
        locktime=locktime,
    )
    if regtest:
        if len(tx.inputs) != 1:
            raise ValueError('regtest coinbase mode supports exactly one input')
        coinbase_txid = REGTEST_COINBASE_TXID
        if tx.inputs[0].prev_txid != coinbase_txid:
            raise ValueError(
                'regtest mode expects the coinbase outpoint %s:0' % coinbase_txid
            )

    kind = kind or InputKind.P2PKH
    address, wif, pubkey = key_info(private_key, network, kind)

    if kind == InputKind.P2PKH:
        script_pubkey = p2pkh_script(pubkey)
    elif kind == InputKind.P2WPKH:
        script_pubkey = p2wpkh_script(pubkey)
    else:
        raise ValueError('default signing supports p2pkh and p2wpkh inputs')

    if regtest:
        prevouts = [(REGTEST_COINBASE_SCRIPT, 50 * 100_000_000)]
    else:
        prevouts = [(script_pubkey, amount) for _, amount in parsed]

    signed, infos = sign_transaction_kinds(
        tx,
        private_key,
        prevouts,
        [kind] * len(tx.inputs),
        sighash_type=sighash_type,
    )
    amount_in = sum(amount for _, amount in prevouts)
    return BuiltTransaction(
        transaction=signed,
        signatures=infos,
        private_key=private_key,
        network=network,
        address=address,
        wif=wif,
        pubkey_hex=pubkey.hex(),
        amount_in=amount_in,
    )


def sign_raw_transaction(
    raw_hex: str,
    private_key: int,
    prevouts: Sequence[Tuple[bytes, int]],
    kinds: Optional[Sequence[str]] = None,
    sighash_type: int = 0x01,
) -> BuiltTransaction:
    """Sign an existing unsigned transaction hex, one key for all inputs."""
    tx = parse_transaction_hex(raw_hex)
    if kinds is None:
        kinds = [script_kind_from_script(spk) for spk, _ in prevouts]
    signed, infos = sign_transaction_kinds(tx, private_key, prevouts, kinds, sighash_type)
    address, wif, pubkey = key_info(private_key, kind=kinds[0] if kinds else InputKind.P2PKH)
    return BuiltTransaction(
        transaction=signed,
        signatures=infos,
        private_key=private_key,
        network='mainnet',
        address=address,
        wif=wif,
        pubkey_hex=pubkey.hex(),
        amount_in=sum(amount for _, amount in prevouts),
    )


def parse_transaction_hex(raw_hex: str) -> Transaction:
    from .signing import parse_transaction

    text = raw_hex.strip()
    if text[:2].lower() == '0x':
        text = text[2:]
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        raise ValueError('transaction hex is not valid hex') from None
    return parse_transaction(raw)


def make_unsigned(
    inputs: Sequence[str],
    outputs: Sequence[str],
    network: str = 'mainnet',
    version: int = 2,
    locktime: int = 0,
) -> Transaction:
    """Build an unsigned transaction for external signing."""
    return Transaction(
        version=version,
        inputs=[txin for txin, _ in (_parse_input(spec) for spec in inputs)],
        outputs=[_parse_output(spec, network) for spec in outputs],
        locktime=locktime,
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
