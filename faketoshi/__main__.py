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
    keygen.add_argument('--network', default='testnet', help='mainnet, testnet or regtest')
    keygen.add_argument('--json', action='store_true')

    address = subparsers.add_parser(
        'address', help='show the address/public key for a private key'
    )
    _add_key_source(address)
    address.add_argument('--network', default='testnet')
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
    tx.add_argument('--network', default='testnet')
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
        default=InputKind.P2WPKH,
        choices=[InputKind.P2WPKH, InputKind.P2PKH],
        help='script type of the coins being spent',
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
    unsigned.add_argument('--network', default='testnet')
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
    signraw.add_argument('--sighash', type=lambda v: int(v, 0), default=0x01)
    signraw.add_argument('--json', action='store_true')

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
    address, wif, pubkey = _key_info(private_key, args.network)
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
        address, wif, pubkey = key_info(private_key, args.network)
    except ValueError as exc:
        return _fail(exc)
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
        built = sign_raw_transaction(args.raw, private_key, prevouts, sighash_type=args.sighash)
    except ValueError as exc:
        return _fail(exc)
    _report_built(built, args.json)
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


_HANDLERS = {
    'keygen': _keygen,
    'address': _address,
    'sign': _sign,
    'tx': _tx,
    'unsigned': _unsigned,
    'signraw': _signraw,
    'decode': _decode,
}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == 'verify':
        return _verify(args)
    handler = _HANDLERS.get(args.command)
    if handler is not None:
        return handler(args)
    return _forge(args)


if __name__ == '__main__':
    sys.exit(main())
