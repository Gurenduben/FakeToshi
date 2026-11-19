"""Tests for signing, sighashes and transaction assembly.

Vectors are taken from BIP143 (official worked examples), plus RFC 6979
determinism checks and serialisation round trips.
"""

import unittest

from faketoshi.curve import N
from faketoshi.encoding import (
    b58decode_check,
    b58encode_check,
    hash160,
    p2pkh_address,
    p2wpkh_address,
    ripemd160,
    segwit_decode,
    segwit_encode,
)
from faketoshi.signing import (
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    decode_point,
    der_decode,
    der_encode,
    parse_transaction,
    p2pkh_script_code,
    private_key_to_public_key,
    private_key_to_wif,
    rfc6979_nonces,
    sign_z,
    verify_z,
    wif_to_private_key,
)
from faketoshi.wallet import (
    address_to_script,
    build_transaction,
    key_info,
    make_unsigned,
    parse_transaction_hex,
    sign_raw_transaction,
)

# --- BIP143, example 1: native P2WPKH --------------------------------------
BIP143_1_UNSIGNED = (
    '0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000'
    '0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100'
    '000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d59'
    '88ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000'
)
BIP143_1_KEY = 0x619C335025C7F4012E556C2A58B2506E30B8511B53ADE95EA316FD8C3286FEB9
BIP143_1_SIGHASH = 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'
BIP143_1_SIG = (
    '304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220'
    '573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01'
)

# --- BIP143, example 2: P2SH-P2WPKH ---------------------------------------
BIP143_2_UNSIGNED = (
    '0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000'
    '0000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d9638'
    '8ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000'
)
BIP143_2_KEY = 0xEB696A065EF48A2192DA5B28B694F87544B30FAE8327C4510137A922F32C6DCF
BIP143_2_SIGHASH = '64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6'
BIP143_2_SIG = (
    '3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220'
    '217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01'
)

# --- BIP143 example 1, first input: legacy P2PK ---------------------------
BIP143_1_P2PK_SCRIPTPUBKEY = bytes.fromhex(
    '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac'
)
BIP143_1_P2PK_KEY = 0xBBC27228DDCB9209D7FD6F36B02F7DFA6252AF40BB2F1CBC7A557DA8027FF866
BIP143_1_P2PK_SIG = (
    '30450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be0220'
    '40529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01'
)

# --- BIP143 example 1, fully signed transaction ---------------------------
BIP143_1_SIGNED = (
    '01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00'
    '000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd3'
    '0be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffff'
    'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffff'
    'ff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d'
    '000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e1'
    '7b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561'
    '406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7a'
    'cafcdb3566bb0ad253f62fc70f07aeee635711000000'
)


class EncodingTest(unittest.TestCase):
    def test_ripemd160_vectors(self):
        self.assertEqual(ripemd160(b'').hex(), '9c1185a5c5e9fc54612808977ee8f548b2258d31')
        self.assertEqual(ripemd160(b'abc').hex(), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
        self.assertEqual(ripemd160(b'message digest').hex(), '5d0689ef49d2fae572b881b123a85ffa21595f36')

    def test_base58_check_round_trip(self):
        payload = b'\x00' + b'\x01' * 20
        self.assertEqual(b58decode_check(b58encode_check(payload)), payload)

    def test_known_addresses_for_generator_point(self):
        pubkey = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        self.assertEqual(p2pkh_address(pubkey), '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH')
        self.assertEqual(p2wpkh_address(pubkey), 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')

    def test_bech32_round_trip(self):
        program = bytes.fromhex('751e76e8199196d454941c45d1b3a323f1433bd6')
        address = segwit_encode('bc', 0, program)
        self.assertEqual(segwit_decode(address), ('bc', 0, program))

    def test_base58_address_is_not_mistaken_for_bech32(self):
        # A real testnet P2PKH address whose characters also fit the bech32
        # alphabet; it must be parsed as base58.
        pubkey = private_key_to_public_key(int('11' * 32, 16))
        from faketoshi.encoding import p2pkh_address

        address = p2pkh_address(pubkey, 'testnet')
        self.assertEqual(
            address_to_script(address, 'testnet').hex(), '76a914' + hash160(pubkey).hex() + '88ac'
        )

    def test_bech32_address_for_wrong_network_is_rejected(self):
        pubkey = private_key_to_public_key(int('11' * 32, 16))
        mainnet = p2wpkh_address(pubkey, 'mainnet')
        with self.assertRaises(ValueError) as ctx:
            address_to_script(mainnet, 'testnet')
        self.assertIn('belongs to', str(ctx.exception))

    def test_address_to_script(self):
        pubkey = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
        self.assertEqual(
            address_to_script(p2pkh_address(pubkey), 'mainnet').hex(),
            '76a914' + hash160(pubkey).hex() + '88ac',
        )
        self.assertEqual(
            address_to_script(p2wpkh_address(pubkey), 'mainnet').hex(),
            '0014' + hash160(pubkey).hex(),
        )


class SighashTest(unittest.TestCase):
    def test_bip143_p2wpkh_sighash_and_signature(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        pubkey = private_key_to_public_key(BIP143_1_KEY)
        self.assertEqual(
            pubkey.hex(), '025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'
        )
        z = tx.sighash_segwit_v0(1, p2pkh_script_code(pubkey), 600000000)
        self.assertEqual('%064x' % z, BIP143_1_SIGHASH)
        r, s = sign_z(BIP143_1_KEY, z)
        self.assertEqual(der_encode(r, s).hex(), BIP143_1_SIG)

    def test_bip143_p2sh_p2wpkh_sighash_and_signature(self):
        tx = parse_transaction(bytes.fromhex(BIP143_2_UNSIGNED))
        pubkey = private_key_to_public_key(BIP143_2_KEY)
        self.assertEqual(
            pubkey.hex(), '03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873'
        )
        z = tx.sighash_segwit_v0(0, p2pkh_script_code(pubkey), 1000000000)
        self.assertEqual('%064x' % z, BIP143_2_SIGHASH)
        r, s = sign_z(BIP143_2_KEY, z)
        self.assertEqual(der_encode(r, s).hex(), BIP143_2_SIG)

    def test_legacy_p2pk_signature(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        z = tx.sighash_legacy(0, BIP143_1_P2PK_SCRIPTPUBKEY)
        r, s = sign_z(BIP143_1_P2PK_KEY, z)
        self.assertEqual(der_encode(r, s).hex(), BIP143_1_P2PK_SIG)

    def test_legacy_sighash_respects_sighash_types(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        script = BIP143_1_P2PK_SCRIPTPUBKEY
        base = tx.sighash_legacy(0, script, SIGHASH_ALL)
        variants = {
            tx.sighash_legacy(0, script, SIGHASH_NONE),
            tx.sighash_legacy(0, script, SIGHASH_SINGLE),
            tx.sighash_legacy(0, script, SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            tx.sighash_legacy(1, script, SIGHASH_ALL),
        }
        self.assertEqual(len(variants), 4)
        self.assertNotIn(base, variants)

    def test_segwit_sighash_respects_sighash_types(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        script = p2pkh_script_code(private_key_to_public_key(BIP143_1_KEY))
        base = tx.sighash_segwit_v0(1, script, 600000000, SIGHASH_ALL)
        others = {
            tx.sighash_segwit_v0(1, script, 600000000, SIGHASH_NONE),
            tx.sighash_segwit_v0(1, script, 600000000, SIGHASH_SINGLE),
            tx.sighash_segwit_v0(1, script, 600000000, SIGHASH_ALL | SIGHASH_ANYONECANPAY),
            tx.sighash_segwit_v0(1, script, 600000001, SIGHASH_ALL),
        }
        self.assertEqual(len(others), 4)
        self.assertNotIn(base, others)

    def test_sighash_single_bug_returns_uint256_one(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        # Input 1 exists but the transaction has two outputs, so build a
        # one-output variant to trigger "nOut out of range".
        from faketoshi.signing import Transaction

        short = Transaction(tx.version, tx.inputs, tx.outputs[:1], tx.locktime)
        self.assertEqual(
            short.sighash_legacy(1, BIP143_1_P2PK_SCRIPTPUBKEY, SIGHASH_SINGLE), 2 ** 248
        )
        # Segwit v0 does not have the bug: with a valid input index that has no
        # matching output, the digest is still a real hash of the transaction.
        segwit_single = tx.sighash_segwit_v0(1, BIP143_1_P2PK_SCRIPTPUBKEY, 600000000, SIGHASH_SINGLE)
        self.assertNotEqual(segwit_single, 2 ** 248)
        self.assertNotEqual(segwit_single, 1)

    def test_out_of_range_input_index_is_rejected(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        with self.assertRaises(ValueError):
            tx.sighash_legacy(9, BIP143_1_P2PK_SCRIPTPUBKEY, SIGHASH_ALL)
        with self.assertRaises(ValueError):
            tx.sighash_segwit_v0(9, BIP143_1_P2PK_SCRIPTPUBKEY, 1, SIGHASH_ALL)


class SignatureTest(unittest.TestCase):
    def test_rfc6979_is_deterministic(self):
        first = sign_z(BIP143_1_KEY, 12345)
        second = sign_z(BIP143_1_KEY, 12345)
        self.assertEqual(first, second)
        self.assertNotEqual(first, sign_z(BIP143_1_KEY, 12346))

    def test_low_s_normalisation(self):
        for z in range(1, 12):
            _, s = sign_z(BIP143_1_KEY, z * 987654321)
            self.assertLessEqual(s, N // 2)

    def test_signatures_verify_and_reject_tampering(self):
        pubkey = decode_point(private_key_to_public_key(BIP143_1_KEY))
        r, s = sign_z(BIP143_1_KEY, 999)
        self.assertTrue(verify_z(pubkey, r, s, 999))
        self.assertFalse(verify_z(pubkey, r, s, 1000))
        self.assertFalse(verify_z(pubkey, r + 1, s, 999))
        self.assertFalse(verify_z(pubkey, r, s + 1, 999))

    def test_der_round_trip(self):
        r, s = sign_z(BIP143_1_KEY, 424242)
        encoded = der_encode(r, s, SIGHASH_ALL)
        self.assertEqual(encoded[-1], SIGHASH_ALL)
        self.assertEqual(der_decode(encoded), (r, s, SIGHASH_ALL))

    def test_der_pads_high_bit_values(self):
        # A value with the top bit set needs a leading zero byte.
        encoded = der_encode(0x80, 0x01, SIGHASH_ALL)
        self.assertEqual(encoded.hex(), '30070202008002010101')
        self.assertEqual(der_decode(encoded), (0x80, 0x01, SIGHASH_ALL))

    def test_der_rejects_garbage(self):
        for bad in (b'', b'\x31\x00', bytes.fromhex('3006020101020101')):
            with self.assertRaises(ValueError):
                der_decode(bad)

    def test_rfc6979_nonce_stream_is_in_range(self):
        stream = rfc6979_nonces(BIP143_1_KEY, 1)
        for _ in range(5):
            k = next(stream)
            self.assertTrue(1 <= k < N)


class TransactionTest(unittest.TestCase):
    def test_parse_and_reserialise(self):
        raw = bytes.fromhex(BIP143_1_UNSIGNED)
        self.assertEqual(parse_transaction(raw).serialize(), raw)

    def test_parse_signed_transaction_and_read_witness(self):
        tx = parse_transaction(bytes.fromhex(BIP143_1_SIGNED))
        self.assertTrue(tx.is_segwit())
        self.assertEqual(tx.serialize().hex(), BIP143_1_SIGNED)
        witness_sig = tx.inputs[1].witness[0]
        r, s, sighash = der_decode(witness_sig)
        self.assertEqual(sighash, SIGHASH_ALL)
        self.assertEqual(r, int(BIP143_1_SIG[8:72], 16))
        # The witness signature really is valid for the input it signs.
        pubkey = decode_point(tx.inputs[1].witness[1])
        self.assertTrue(verify_z(pubkey, r, s, int(BIP143_1_SIGHASH, 16)))

    def test_txid_ignores_witness(self):
        signed = parse_transaction(bytes.fromhex(BIP143_1_SIGNED))
        stripped = parse_transaction(bytes.fromhex(BIP143_1_UNSIGNED))
        for idx, txin in enumerate(stripped.inputs):
            stripped.inputs[idx] = type(txin)(
                txin.prev_txid, txin.prev_vout, txin.sequence, signed.inputs[idx].script_sig
            )
        self.assertEqual(stripped.txid(), signed.txid())

    def test_wif_round_trip(self):
        key = int('11' * 32, 16)
        wif = private_key_to_wif(key, 'testnet')
        self.assertEqual(wif_to_private_key(wif), (key, True))


class WalletTest(unittest.TestCase):
    KEY = int('11' * 32, 16)
    ADDRESS = 'tb1ql3e9pgs3mmwuwrh95fecme0s0qtn28804khrk8'

    def test_key_info(self):
        address, wif, pubkey = key_info(self.KEY, 'testnet')
        self.assertEqual(address, self.ADDRESS)
        self.assertEqual(
            pubkey.hex(), '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa'
        )
        self.assertEqual(wif_to_private_key(wif), (self.KEY, True))

    def test_signed_transaction_verifies_against_own_key(self):
        built = build_transaction(
            ['aa' * 32 + ':0:100000'], [self.ADDRESS + ':90000'], self.KEY, network='testnet'
        )
        self.assertEqual(built.fee(), 10000)
        self.assertEqual(len(built.signatures), 1)
        info = built.signatures[0]
        pubkey = decode_point(bytes.fromhex(built.pubkey_hex))
        self.assertTrue(verify_z(pubkey, info.r, info.s, info.z))

    def test_regtest_coinbase_mode(self):
        from faketoshi.wallet import REGTEST_COINBASE_TXID

        regtest_address = key_info(self.KEY, 'regtest')[0]
        built = build_transaction(
            [REGTEST_COINBASE_TXID + ':0:5000000000'],
            [regtest_address + ':4999990000'],
            self.KEY,
            network='regtest',
            regtest=True,
        )
        self.assertEqual(built.fee(), 10000)
        pubkey = decode_point(bytes.fromhex(built.pubkey_hex))
        self.assertTrue(verify_z(pubkey, *[(i.r, i.s, i.z) for i in built.signatures][0]))

    def test_regtest_rejects_other_outpoints(self):
        with self.assertRaises(ValueError):
            build_transaction(
                ['bb' * 32 + ':0:1000'], [self.ADDRESS + ':900'], self.KEY, regtest=True
            )

    def test_input_requires_amount(self):
        with self.assertRaises(ValueError):
            build_transaction(['aa' * 32 + ':0'], [self.ADDRESS + ':90000'], self.KEY)

    def test_unsigned_then_signraw_matches_tx(self):
        unsigned = make_unsigned(
            ['aa' * 32 + ':0:100000'], [self.ADDRESS + ':90000'], network='testnet'
        )
        direct = build_transaction(
            ['aa' * 32 + ':0:100000'], [self.ADDRESS + ':90000'], self.KEY, network='testnet'
        )
        script = address_to_script(self.ADDRESS, 'testnet')
        signed = sign_raw_transaction(unsigned.hex(), self.KEY, [(script, 100000)])
        self.assertEqual(signed.txid, direct.txid)

    def test_p2pkh_transaction_verifies(self):
        built = build_transaction(
            ['aa' * 32 + ':0:100000'],
            [self.ADDRESS + ':90000'],
            self.KEY,
            network='testnet',
            kind='p2pkh',
        )
        info = built.signatures[0]
        self.assertTrue(
            verify_z(decode_point(bytes.fromhex(built.pubkey_hex)), info.r, info.s, info.z)
        )
        self.assertFalse(built.transaction.is_segwit())
        self.assertEqual(parse_transaction_hex(built.hex).txid(), built.txid)


class SigningCliTest(unittest.TestCase):
    """End-to-end through the command line."""

    KEY = int('11' * 32, 16)

    def _run(self, argv):
        import contextlib
        import io

        from faketoshi.__main__ import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_keygen(self):
        import json

        rc, out, _ = self._run(['keygen', '--network', 'testnet', '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertTrue(payload['address'].startswith('tb1q'))
        self.assertTrue(payload['wif'].startswith('c'))
        self.assertEqual(len(payload['private_key']), 64)

    def test_address_from_wif(self):
        wif = private_key_to_wif(self.KEY, 'testnet')
        rc, out, _ = self._run(['address', '--wif', wif, '--network', 'testnet'])
        self.assertEqual(rc, 0)
        self.assertIn('tb1ql3e9pgs3mmwuwrh95fecme0s0qtn28804khrk8', out)

    def test_sign_then_verify_round_trip(self):
        import json

        txid = 'ab' * 32
        rc, out, _ = self._run(['sign', '--key', '%064x' % self.KEY, '--txid', txid, '--json'])
        self.assertEqual(rc, 0)
        signed = json.loads(out)

        from faketoshi.signing import decode_point, verify_z

        pubkey = decode_point(bytes.fromhex(signed['public_key']))
        self.assertTrue(
            verify_z(pubkey, int(signed['r']), int(signed['s']), int(signed['z']))
        )

    def test_sign_requires_a_key(self):
        rc, _, err = self._run(['sign', '--txid', 'ab' * 32])
        self.assertEqual(rc, 2)
        self.assertIn('need --key or --wif', err)

    def test_sign_requires_a_payload(self):
        rc, _, err = self._run(['sign', '--key', '%064x' % self.KEY])
        self.assertEqual(rc, 2)
        self.assertIn('need --txid or --message', err)

    def test_tx_and_decode(self):
        import json

        address = key_info(self.KEY, 'testnet')[0]
        rc, out, _ = self._run(
            [
                'tx',
                '--key', '%064x' % self.KEY,
                '--network', 'testnet',
                '--input', 'aa' * 32 + ':0:100000',
                '--output', address + ':90000',
                '--json',
            ]
        )
        self.assertEqual(rc, 0)
        built = json.loads(out)
        self.assertEqual(built['fee'], 10000)
        self.assertEqual(len(built['signatures']), 1)

        rc, out, _ = self._run(['decode', built['hex'], '--json'])
        self.assertEqual(rc, 0)
        decoded = json.loads(out)
        self.assertEqual(decoded['txid'], built['txid'])
        self.assertEqual(decoded['outputs'][0]['value'], 90000)

    def test_cli_reports_bad_input(self):
        rc, _, err = self._run(['tx', '--key', '%064x' % self.KEY, '--input', 'bad', '--output', 'x:1'])
        self.assertEqual(rc, 2)
        self.assertIn('error:', err)


if __name__ == '__main__':
    unittest.main()
