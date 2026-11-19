"""Command line interface for Faketoshi.

Usage:
    python -m faketoshi                     # forge for the Genesis block pubkey
    python -m faketoshi --x <hex> --y <hex> --json   # any other Satoshi pubkey
    python -m faketoshi verify --txid <hash> --r <hex> --s <hex>
    python -m faketoshi verify --txid <hash> --r <hex> --s <hex> --x <hex> --y <hex>
"""

import argparse
import json
import sys

from .faketoshi import (
    generate_forgery,
    inspect_claim,
    format_tx_hash,
    valid_forgery,
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
    return parser


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


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == 'verify':
        return _verify(args)
    return _forge(args)


if __name__ == '__main__':
    sys.exit(main())
