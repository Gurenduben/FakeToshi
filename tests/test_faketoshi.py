"""Tests for the Python Faketoshi port.

Run with:  python -m unittest discover -s tests -t .
(no third-party test framework required)
"""

import unittest

from faketoshi import (
    G,
    N,
    PublicKey,
    Signature,
    generate_forgery,
    hashless_verify,
    inspect_claim,
    is_on_curve,
    point_add,
    point_base_mul,
    recover_public_keys,
    tx_hash_to_z,
    valid_forgery,
)
from faketoshi.__main__ import GENESIS_X, GENESIS_Y, main


class CurveTest(unittest.TestCase):
    def test_generator_is_on_curve(self):
        self.assertTrue(is_on_curve(G))

    def test_group_order(self):
        self.assertIsNone(point_base_mul(N))

    def test_known_multiple(self):
        # 2 * G, cross-checked against SEC 2 / bitcoin test vectors.
        double_g = point_add(G, G)
        self.assertEqual(
            double_g[0],
            0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        )
        self.assertEqual(
            double_g[1],
            0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
        )


class ForgeryTest(unittest.TestCase):
    def test_genesis_forgery_validates(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        self.assertIsNotNone(forgery)
        self.assertTrue(valid_forgery(forgery))

    def test_deterministic_seeds_still_validate(self):
        # randbelow is injectable so tests do not depend on randomness.
        seq = iter([1234567, 89])
        forgery = generate_forgery(GENESIS_X, GENESIS_Y, randbelow=lambda n: next(seq) % n)
        self.assertIsNotNone(forgery)
        self.assertTrue(valid_forgery(forgery))

    def test_tampered_message_is_rejected(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        tampered = type(forgery)(
            sig=forgery.sig, msg=forgery.msg + 1, pub_key=forgery.pub_key
        )
        self.assertFalse(valid_forgery(tampered))

    def test_tampered_signature_is_rejected(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        tampered = type(forgery)(
            sig=Signature(forgery.sig.r, forgery.sig.s + 1),
            msg=forgery.msg,
            pub_key=forgery.pub_key,
        )
        self.assertFalse(valid_forgery(tampered))

    def test_point_at_infinity_public_key_is_rejected(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        infinity = type(forgery.pub_key)(None)
        self.assertFalse(valid_forgery(type(forgery)(forgery.sig, forgery.msg, infinity)))

    def test_out_of_range_signature_is_rejected(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        bad = type(forgery)(
            sig=Signature(0, forgery.sig.s), msg=forgery.msg, pub_key=forgery.pub_key
        )
        self.assertFalse(valid_forgery(bad))

    def test_non_invertible_b_returns_none(self):
        seq = iter([1, 0])  # inverse(0) does not exist -> Nothing branch
        self.assertIsNone(
            generate_forgery(GENESIS_X, GENESIS_Y, randbelow=lambda n: next(seq) % n)
        )

    def test_unrelated_key_does_not_verify(self):
        # A signature forged for the Genesis key must not verify against another key.
        other = generate_forgery('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                                 '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
        genesis = generate_forgery(GENESIS_X, GENESIS_Y)
        swapped = type(other)(other.sig, other.msg, genesis.pub_key)
        self.assertFalse(valid_forgery(swapped))


def _sign(private_key: int, z: int, nonce: int = 424242):
    """Textbook ECDSA signer, used to check that key recovery finds the signer."""
    r = point_base_mul(nonce)[0] % N
    s = pow(nonce, -1, N) * (z + r * private_key) % N
    return Signature(r, s), public_key_for(private_key)


def public_key_for(private_key: int):
    return PublicKey(point_base_mul(private_key))


class InspectTest(unittest.TestCase):
    TXID = 'aa' * 32

    def test_z_from_txid(self):
        self.assertEqual(tx_hash_to_z(self.TXID), int('aa' * 32, 16))
        self.assertEqual(tx_hash_to_z('0x' + self.TXID), int('aa' * 32, 16))
        self.assertEqual(tx_hash_to_z('0X' + self.TXID), int('aa' * 32, 16))

    def test_z_rejects_bad_input(self):
        for bad in ['', 'aa', 'zz' * 32, 'aa' * 31]:
            with self.assertRaises(ValueError):
                tx_hash_to_z(bad)

    def test_z_is_reduced_mod_n(self):
        self.assertLess(tx_hash_to_z('ff' * 32), N)

    def test_forged_triple_validates_and_recovers_genesis_key(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        result = inspect_claim(
            '%064x' % forgery.msg,
            forgery.sig.r,
            forgery.sig.s,
            GENESIS_X,
            GENESIS_Y,
        )
        self.assertTrue(result.valid)
        self.assertEqual(result.z, forgery.msg)
        self.assertIn(PublicKey((int(GENESIS_X, 16), int(GENESIS_Y, 16))), result.recovered_keys)

    def test_hex_and_decimal_parsing_agree(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        txid = '%064x' % forgery.msg
        as_hex = inspect_claim(txid, '%x' % forgery.sig.r, '%x' % forgery.sig.s, GENESIS_X, GENESIS_Y)
        as_dec = inspect_claim(
            txid, str(forgery.sig.r), str(forgery.sig.s), GENESIS_X, GENESIS_Y, decimal=True
        )
        self.assertEqual(as_hex, as_dec)
        self.assertTrue(as_hex.valid)

    def test_hex_prefix_is_honoured(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        result = inspect_claim(
            '%064x' % forgery.msg,
            '0x%x' % forgery.sig.r,
            '0x%x' % forgery.sig.s,
            GENESIS_X,
            GENESIS_Y,
        )
        self.assertTrue(result.valid)

    def test_wrong_key_is_reported_as_invalid(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        result = inspect_claim(
            '%064x' % forgery.msg,
            forgery.sig.r,
            forgery.sig.s,
            '%064x' % G[0],  # generator, not the claimed signer
            '%064x' % G[1],
        )
        self.assertFalse(result.valid)
        # Recovery is independent of the claimed key: every recovered key must
        # genuinely verify, and the claimed one must not be among them here.
        for key in result.recovered_keys:
            self.assertTrue(hashless_verify(key, Signature(result.r, result.s), result.z))
        self.assertNotIn(PublicKey((G[0], G[1])), result.recovered_keys)

    def test_recovery_finds_a_real_signer(self):
        private_key = 0xC0FFEE
        z = tx_hash_to_z('11' * 32)
        sig, expected = _sign(private_key, z)
        recovered = recover_public_keys(sig.r, sig.s, z)
        self.assertIn(expected, recovered)
        for key in recovered:
            self.assertTrue(hashless_verify(key, sig, z))

    def test_recovery_of_forgery_keys_all_verify(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        keys = recover_public_keys(forgery.sig.r, forgery.sig.s, forgery.msg)
        self.assertEqual(len(keys), 2)
        for key in keys:
            self.assertTrue(hashless_verify(key, forgery.sig, forgery.msg))

    def test_non_invertible_r_recovers_nothing(self):
        self.assertEqual(recover_public_keys(0, 12345, 999), ())

    def test_off_curve_claimed_key_raises(self):
        with self.assertRaises(ValueError):
            inspect_claim(self.TXID, 1, 1, '01', '02')

    def test_text_output_mentions_txid(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        result = inspect_claim('%064x' % forgery.msg, forgery.sig.r, forgery.sig.s, GENESIS_X, GENESIS_Y)
        text = str(result)
        self.assertIn('txid: ', text)
        self.assertIn('Valid for claimed key: yes', text)
        self.assertIn('Recoverable key', text)


class LauncherTest(unittest.TestCase):
    """`python faketoshi.py` from the repo root must work without installing."""

    def setUp(self):
        import os

        self.root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.launcher = os.path.join(self.root, 'faketoshi.py')

    def test_launcher_exists_and_is_executable(self):
        import os
        import stat

        self.assertTrue(os.path.isfile(self.launcher))
        mode = os.stat(self.launcher).st_mode
        self.assertTrue(mode & stat.S_IXUSR, 'launcher should be executable')

    def test_launcher_runs_from_repo_root(self):
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, self.launcher, '--help'],
            cwd=self.root,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('usage: faketoshi', result.stdout)

    def test_launcher_runs_from_another_directory(self):
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as elsewhere:
            result = subprocess.run(
                [sys.executable, self.launcher, 'keygen', '--json'],
                cwd=elsewhere,
                capture_output=True,
                text=True,
                timeout=120,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"address"', result.stdout)

    def test_module_prints_a_helpful_error_when_run_by_path(self):
        import os
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, 'faketoshi.py'],
            cwd=os.path.join(self.root, 'faketoshi'),  # the module, not the launcher
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('ImportError', result.stderr)
        self.assertIn('cannot be run by path', result.stderr)
        self.assertIn('python -m faketoshi', result.stderr)


class CliTest(unittest.TestCase):
    def test_cli_prints_forgery(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([])
        self.assertEqual(rc, 0)
        self.assertIn('Sigs: (Signature ', buf.getvalue())
        self.assertIn('Msg Hash: ', buf.getvalue())

    def test_cli_json(self):
        import contextlib
        import io
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(['--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertIn('r', payload)
        self.assertIn('msg_hash', payload)


class VerifyCliTest(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _forged(self):
        forgery = generate_forgery(GENESIS_X, GENESIS_Y)
        return [
            'verify',
            '--txid', '%064x' % forgery.msg,
            '--r', '%x' % forgery.sig.r,
            '--s', '%x' % forgery.sig.s,
        ]

    def test_valid_claim_exits_zero(self):
        rc, out, _ = self._run(self._forged())
        self.assertEqual(rc, 0)
        self.assertIn('Valid for claimed key: yes', out)

    def test_invalid_claim_exits_one(self):
        argv = self._forged()
        argv[argv.index('--r') + 1] = '1'
        rc, out, _ = self._run(argv)
        self.assertEqual(rc, 1)
        self.assertIn('Valid for claimed key: no', out)

    def test_bad_txid_exits_two(self):
        rc, _, err = self._run(['verify', '--txid', 'nothex', '--r', '1', '--s', '1'])
        self.assertEqual(rc, 2)
        self.assertIn('error:', err)

    def test_json_shape(self):
        import json

        argv = self._forged() + ['--json']
        rc, out, _ = self._run(argv)
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(len(payload['txid']), 64)
        self.assertTrue(payload['valid_for_claimed_key'])
        self.assertEqual(len(payload['recovered_keys']), 2)
        self.assertIn('x', payload['claimed_key'])

    def test_forge_json_includes_hex_and_txid(self):
        import json

        rc, out, _ = self._run(['--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(int(payload['r_hex'], 16), int(payload['r']))
        self.assertEqual(int(payload['txid'], 16), int(payload['msg_hash']))



class AddressAllCliTest(unittest.TestCase):
    """`address --all` should list every address a key controls."""

    KEY = '11' * 32

    def _run(self, argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_all_lists_the_four_address_types(self):
        rc, out, _ = self._run(['address', '--key', self.KEY, '--all'])
        self.assertEqual(rc, 0)
        self.assertIn('1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9', out)
        self.assertIn('bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5', out)
        self.assertIn('1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a', out)
        self.assertIn('3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x', out)

    def test_all_states_the_key_format(self):
        rc, out, _ = self._run(['address', '--key', self.KEY, '--all'])
        self.assertEqual(rc, 0)
        self.assertIn('compressed', out)
        self.assertIn('signing with: p2pkh', out)

    def test_all_marks_the_default_kind(self):
        rc, out, _ = self._run(['address', '--key', self.KEY, '--all'])
        self.assertEqual(rc, 0)
        import re

        # Address lines look like "* p2pkh    <address>"; skip the legend line.
        starred = [
            line for line in out.splitlines()
            if re.match(r'^\* \S+\s{2,}\S+$', line)
        ]
        self.assertEqual(len(starred), 1)
        self.assertRegex(starred[0], r'^\* p2pkh\s')
        self.assertNotIn('uncompressed', starred[0])

    def test_all_json(self):
        import json

        rc, out, _ = self._run(['address', '--key', self.KEY, '--all', '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload['network'], 'mainnet')
        self.assertTrue(payload['compressed'])
        self.assertEqual(
            set(payload['addresses']),
            {'p2pkh', 'p2wpkh', 'p2pkh-uncompressed', 'p2sh-p2wpkh'},
        )
        self.assertEqual(
            payload['addresses']['p2pkh']['address'],
            '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9',
        )

    def test_without_all_only_the_default_address_is_printed(self):
        rc, out, _ = self._run(['address', '--key', self.KEY, '--json'])
        self.assertEqual(rc, 0)
        import json

        payload = json.loads(out)
        self.assertNotIn('addresses', payload)
        self.assertEqual(payload['address'], '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9')


class SpendFromCliTest(unittest.TestCase):
    """`spend --from` should confirm (or refuse) the address being spent."""

    KEY = '11' * 32
    P2PKH = '1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9'
    P2WPKH = 'bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5'
    P2PKH_UNCOMPRESSED = '1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a'
    P2SH = '3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x'

    def _run(self, argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_matching_address_is_accepted(self):
        # Stops at the first interactive prompt, which is enough to prove the
        # --from check passed.
        import builtins
        from unittest import mock

        with mock.patch.object(builtins, 'input', side_effect=EOFError):
            rc, out, _ = self._run(['spend', '--key', self.KEY, '--from', self.P2PKH])
        self.assertIn('matches your key', out)

    def test_unknown_address_is_refused_and_lists_candidates(self):
        rc, out, err = self._run(
            ['spend', '--key', self.KEY, '--from', '1BoatSLRHtKNngkdXEeobR76b53LETtpyT']
        )
        self.assertEqual(rc, 2)
        text = out + err
        self.assertIn('is not an address this key controls', text)
        self.assertIn(self.P2PKH, text)

    def test_uncompressed_address_is_refused_with_the_right_one(self):
        rc, out, err = self._run(
            ['spend', '--key', self.KEY, '--from', self.P2PKH_UNCOMPRESSED]
        )
        self.assertEqual(rc, 2)
        text = out + err
        self.assertIn('uncompressed', text)
        self.assertIn(self.P2PKH, text)

    def test_segwit_address_needs_the_matching_kind(self):
        rc, out, err = self._run(
            ['spend', '--key', self.KEY, '--from', self.P2WPKH]
        )
        self.assertEqual(rc, 2)
        self.assertIn('--kind p2wpkh', out + err)

    def test_wrapped_segwit_address_points_at_signraw(self):
        rc, out, err = self._run(['spend', '--key', self.KEY, '--from', self.P2SH])
        self.assertEqual(rc, 2)
        text = out + err
        self.assertIn('wrapped-segwit', text)
        self.assertIn('signraw --redeem-script', text)


class SignRawRedeemScriptCliTest(unittest.TestCase):
    """Spending P2SH-P2WPKH coins requires passing the redeemScript."""

    KEY = '11' * 32

    def _run(self, argv):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _fixture(self):
        from faketoshi.encoding import hash160, push_data
        from faketoshi.signing import private_key_to_public_key
        from faketoshi.wallet import make_unsigned

        pubkey = private_key_to_public_key(int(self.KEY, 16), compressed=True)
        redeem = b'\x00\x14' + hash160(pubkey)
        spk = b'\xa9' + push_data(hash160(redeem)) + b'\x87'
        unsigned = make_unsigned(
            ['aa' * 32 + ':0:100000'], ['1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9:90000']
        )
        return unsigned.hex(), spk.hex(), redeem.hex()

    def test_redeem_script_produces_a_segwit_signature(self):
        import json

        raw, spk, redeem = self._fixture()
        rc, out, err = self._run(
            [
                'signraw', '--key', self.KEY, '--raw', raw,
                '--prevout', '%s:100000' % spk,
                '--redeem-script', redeem, '--json',
            ]
        )
        self.assertEqual(rc, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload['address'], '3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x')
        self.assertIn('p2sh-p2wpkh', json.dumps(payload))

    def test_p2sh_prevout_without_redeem_script_explains_the_fix(self):
        raw, spk, _ = self._fixture()
        rc, out, err = self._run(
            ['signraw', '--key', self.KEY, '--raw', raw, '--prevout', '%s:100000' % spk]
        )
        self.assertEqual(rc, 2)
        self.assertIn('--redeem-script', out + err)

    def test_mismatched_redeem_script_is_refused(self):
        raw, _, _ = self._fixture()
        rc, out, err = self._run(
            [
                'signraw', '--key', self.KEY, '--raw', raw,
                '--prevout', '%s:100000' % ('76a914' + '11' * 20 + '88ac'),
                '--redeem-script', '0014' + '22' * 20,
            ]
        )
        self.assertEqual(rc, 2)
        self.assertIn('no --prevout matches that redeemScript', out + err)


if __name__ == '__main__':
    unittest.main()
