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


if __name__ == '__main__':
    unittest.main()
