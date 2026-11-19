"""Tests for the BlockCypher client.

No network access: the client takes an injectable transport, so every request
is answered by a local stub. Payloads follow BlockCypher's documented shapes.
"""

import json
import os
import unittest
from unittest import mock

from faketoshi.blockcypher import (
    BlockCypherClient,
    BlockCypherError,
    BroadcastResult,
    Utxo,
    chain_path,
    resolve_token,
)
from faketoshi.__main__ import main
from tests.test_signing import BIP143_1_SIGNED

ADDRESS = '1PuwQ6uWXNeGcEnLCAXmRJozdLZ9M4NWQ7'

ADDRESS_PAYLOAD = {
    'address': ADDRESS,
    'total_received': 311681777,
    'total_sent': 0,
    'balance': 311681777,
    'final_balance': 311681777,
    'n_tx': 3,
    'txrefs': [
        {
            'tx_hash': '0d7ac056a96ffc200f53f2a64291a967e5f696c43997f877ef42cb871bb07231',
            'tx_input_n': 1,
            'tx_output_n': -1,  # an input, not spendable
            'value': 283181777,
            'spent': True,
            'confirmations': 62385,
        },
        {
            'tx_hash': 'aa' * 32,
            'tx_input_n': -1,
            'tx_output_n': 0,
            'value': 500000,
            'spent': False,
            'confirmations': 12,
        },
        {
            'tx_hash': 'bb' * 32,
            'tx_input_n': -1,
            'tx_output_n': 1,
            'value': 900000,
            'spent': True,  # already spent, must be filtered out
            'confirmations': 3,
        },
    ],
    'unconfirmed_txrefs': [
        {
            'tx_hash': 'cc' * 32,
            'tx_input_n': -1,
            'tx_output_n': 2,
            'value': 25000,
            'spent': False,
            'confirmations': 0,
        }
    ],
}


def make_transport(address_payload=None, push_status=201, push_payload=None, decode_payload=None):
    """Build a stub transport and record the requests it receives."""
    calls = []

    def transport(method, url, body):
        calls.append({'method': method, 'url': url, 'body': body})
        if 'unspentOnly' in url:
            return 200, json.dumps(address_payload or ADDRESS_PAYLOAD)
        if '/balance' in url:
            return 200, json.dumps({'address': ADDRESS, 'balance': 1000, 'final_balance': 1000})
        if 'txs/push' in url:
            payload = push_payload if push_payload is not None else {'tx': {'hash': 'f' * 64}}
            return push_status, json.dumps(payload)
        if 'txs/decode' in url:
            return 200, json.dumps(decode_payload or {'hash': 'a' * 64})
        return 404, json.dumps({'error': 'not found'})

    transport.calls = calls
    return transport


class TokenTest(unittest.TestCase):
    def test_explicit_token_wins(self):
        self.assertEqual(resolve_token('abc'), 'abc')

    def test_env_var_is_used(self):
        with mock.patch.dict(os.environ, {'BLOCKCYPHER_TOKEN': 'envtoken'}):
            self.assertEqual(resolve_token(), 'envtoken')

    def test_absent_token_is_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(resolve_token())

    def test_token_is_sent_as_query_parameter(self):
        transport = make_transport()
        BlockCypherClient(token='s3cret', transport=transport).unspent_outputs(ADDRESS)
        self.assertIn('token=s3cret', transport.calls[0]['url'])

    def test_no_token_means_no_parameter(self):
        transport = make_transport()
        client = BlockCypherClient(token=None, transport=transport)
        client.token = None
        client.unspent_outputs(ADDRESS)
        self.assertNotIn('token=', transport.calls[0]['url'])

    def test_token_is_never_echoed_in_errors(self):
        def transport(method, url, body):
            return 401, json.dumps({'error': 'API key required'})

        client = BlockCypherClient(token='s3cret', transport=transport)
        with self.assertRaises(BlockCypherError) as ctx:
            client.unspent_outputs(ADDRESS)
        self.assertNotIn('s3cret', str(ctx.exception))

    def test_token_is_stripped_from_unreachable_url(self):
        client = BlockCypherClient(token='s3cret')
        with mock.patch('urllib.request.urlopen', side_effect=OSError('boom')):
            import urllib.error

            with mock.patch(
                'urllib.request.urlopen',
                side_effect=urllib.error.URLError('connection refused'),
            ):
                with self.assertRaises(BlockCypherError) as ctx:
                    client.unspent_outputs(ADDRESS)
        self.assertNotIn('s3cret', str(ctx.exception))
        self.assertIn(ADDRESS, str(ctx.exception))

    def test_chains(self):
        self.assertEqual(chain_path('mainnet'), 'btc/main')
        self.assertEqual(chain_path('testnet'), 'btc/test3')
        with self.assertRaises(ValueError):
            chain_path('regtest')


class UnspentTest(unittest.TestCase):
    def setUp(self):
        self.client = BlockCypherClient(token='t', transport=make_transport())

    def test_filters_inputs_and_spent_outputs(self):
        utxos = self.client.unspent_outputs(ADDRESS)
        self.assertEqual([u.tx_output_n for u in utxos], [0, 2])
        self.assertTrue(all(u.value in (500000, 25000) for u in utxos))

    def test_sorted_by_value_descending(self):
        values = [u.value for u in self.client.unspent_outputs(ADDRESS)]
        self.assertEqual(values, sorted(values, reverse=True))

    def test_unconfirmed_can_be_excluded(self):
        utxos = self.client.unspent_outputs(ADDRESS, include_unconfirmed=False)
        self.assertEqual(len(utxos), 1)
        self.assertEqual(utxos[0].value, 500000)

    def test_input_spec_matches_the_tx_cli(self):
        utxo = Utxo(tx_hash='ab' * 32, tx_output_n=3, value=1234)
        self.assertEqual(utxo.input_spec(), '%s:3:1234' % ('ab' * 32))
        self.assertEqual(utxo.input_spec(sequence=5), '%s:3:1234:5' % ('ab' * 32))

    def test_empty_address(self):
        client = BlockCypherClient(token='t', transport=make_transport({'txrefs': []}))
        self.assertEqual(client.unspent_outputs(ADDRESS), [])

    def test_api_error_raises(self):
        client = BlockCypherClient(
            token='t',
            transport=lambda m, u, b: (429, json.dumps({'error': 'rate limit exceeded'})),
        )
        with self.assertRaises(BlockCypherError) as ctx:
            client.unspent_outputs(ADDRESS)
        self.assertEqual(ctx.exception.status, 429)
        self.assertIn('rate limit', str(ctx.exception))

    def test_non_json_response_is_reported(self):
        client = BlockCypherClient(token='t', transport=lambda m, u, b: (502, '<html>bad gateway'))
        with self.assertRaises(BlockCypherError):
            client.unspent_outputs(ADDRESS)


class PushTest(unittest.TestCase):
    def test_push_posts_the_hex(self):
        transport = make_transport()
        result = BlockCypherClient(token='t', transport=transport).push(BIP143_1_SIGNED)
        self.assertIsInstance(result, BroadcastResult)
        self.assertEqual(result.tx_hash, 'f' * 64)
        self.assertEqual(transport.calls[0]['method'], 'POST')
        self.assertEqual(json.loads(transport.calls[0]['body'])['tx'], BIP143_1_SIGNED)

    def test_push_strips_0x_prefix(self):
        transport = make_transport()
        BlockCypherClient(token='t', transport=transport).push('0x' + BIP143_1_SIGNED)
        self.assertEqual(json.loads(transport.calls[0]['body'])['tx'], BIP143_1_SIGNED)

    def test_push_rejects_bad_hex(self):
        client = BlockCypherClient(token='t', transport=make_transport())
        for bad in ('', 'abc', 'zz', '0x12345'):
            with self.assertRaises(ValueError):
                client.push(bad)

    def test_push_error_is_raised(self):
        client = BlockCypherClient(
            token='t',
            transport=make_transport(push_status=400, push_payload={'error': 'bad-txns-inputs-missingorspent'}),
        )
        with self.assertRaises(BlockCypherError) as ctx:
            client.push(BIP143_1_SIGNED)
        self.assertIn('missingorspent', str(ctx.exception))

    def test_decode(self):
        client = BlockCypherClient(token='t', transport=make_transport())
        self.assertEqual(client.decode(BIP143_1_SIGNED), {'hash': 'a' * 64})


class CliTest(unittest.TestCase):
    def _run(self, argv, stdin_text=None):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        stdout_ctx = contextlib.redirect_stdout(out)
        with stdout_ctx, contextlib.redirect_stderr(err):
            if stdin_text is not None:
                with mock.patch('sys.stdin', io.StringIO(stdin_text)):
                    rc = main(argv)
            else:
                rc = main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _patch_client(self, transport):
        return mock.patch(
            'faketoshi.__main__._client',
            lambda args: BlockCypherClient(token='t', transport=transport),
        )

    def test_unspent_text(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['unspent', ADDRESS])
        self.assertEqual(rc, 0)
        self.assertIn('500000 sats', out)
        self.assertIn('2 output(s)', out)

    def test_unspent_input_specs(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['unspent', ADDRESS, '--input-specs'])
        self.assertEqual(rc, 0)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], '%s:0:500000' % ('aa' * 32))

    def test_unspent_min_confirmations(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['unspent', ADDRESS, '--min-confirmations', '1', '--input-specs'])
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip().splitlines(), ['%s:0:500000' % ('aa' * 32)])

    def test_unspent_json(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['unspent', ADDRESS, '--json'])
        self.assertEqual(rc, 0)
        payload = json.loads(out)
        self.assertEqual(payload[0]['value'], 500000)
        self.assertIn('input_spec', payload[0])

    def test_balance(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['balance', ADDRESS])
        self.assertEqual(rc, 0)
        self.assertIn('1000 sats', out)

    def test_api_errors_exit_two(self):
        failing = lambda m, u, b: (500, json.dumps({'error': 'boom'}))
        with self._patch_client(failing):
            rc, _, err = self._run(['unspent', ADDRESS])
        self.assertEqual(rc, 2)
        self.assertIn('boom', err)

    def test_broadcast_requires_confirmation(self):
        # Non-interactive stdin and no --yes: must refuse, and never call the API.
        transport = make_transport()
        with self._patch_client(transport):
            rc, _, err = self._run(['broadcast', BIP143_1_SIGNED, '--network', 'testnet'], stdin_text='')
        self.assertEqual(rc, 2)
        self.assertIn('refusing to broadcast', err)
        self.assertEqual(transport.calls, [])

    def test_broadcast_with_yes(self):
        transport = make_transport()
        with self._patch_client(transport):
            rc, out, _ = self._run(['broadcast', BIP143_1_SIGNED, '--yes'])
        self.assertEqual(rc, 0)
        self.assertIn('txid:', out)
        self.assertEqual(transport.calls[0]['method'], 'POST')

    def test_broadcast_reports_mismatched_txid(self):
        with self._patch_client(make_transport()):
            rc, out, _ = self._run(['broadcast', BIP143_1_SIGNED, '--yes'])
        self.assertEqual(rc, 0)
        self.assertIn('warning: the node reported a different txid', out)

    def test_broadcast_reads_stdin(self):
        transport = make_transport()
        with self._patch_client(transport):
            rc, _, _ = self._run(['broadcast', '-', '--yes', '--json'], stdin_text=BIP143_1_SIGNED)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(transport.calls[0]['body'])['tx'], BIP143_1_SIGNED)

    def test_broadcast_rejects_bad_hex(self):
        with self._patch_client(make_transport()):
            rc, _, err = self._run(['broadcast', 'nothex', '--yes'])
        self.assertEqual(rc, 2)
        self.assertIn('error:', err)


if __name__ == '__main__':
    unittest.main()
