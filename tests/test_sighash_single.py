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


if __name__ == '__main__':
    unittest.main()
