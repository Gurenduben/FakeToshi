"""Tests for the Python Faketoshi port.

Run with:  python -m unittest discover -s tests -t .
(no third-party test framework required)
"""

import unittest

from faketoshi import (
    G,
    N,
    Signature,
    generate_forgery,
    is_on_curve,
    point_add,
    point_base_mul,
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


if __name__ == '__main__':
    unittest.main()
