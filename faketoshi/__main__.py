"""Python port of ``app/Main.hs``.

Usage:
    python -m faketoshi                  # forge for the Genesis block pubkey
    python -m faketoshi --x <hex> --y <hex> --json
"""

import argparse
import json
import sys

from .faketoshi import generate_forgery, valid_forgery

# xCoord / yCoord from the Genesis Block Pubkey (Satoshi's, never spent).
GENESIS_X = '3cd11937548f77df0b56c251ddacc81510e025235416e1d42b454202b482e22d'
GENESIS_Y = '1f7c3dfe0601d9f0d3b9317a8e7b84b7ec4b4f0d2661c881338efaa07d315de4'


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='faketoshi',
        description='Forge an ECDSA signature that validates against a Satoshi public key.',
    )
    parser.add_argument('--x', default=GENESIS_X, help='public key x coordinate (hex)')
    parser.add_argument('--y', default=GENESIS_Y, help='public key y coordinate (hex)')
    parser.add_argument(
        '--json', action='store_true', help='emit the forgery as JSON instead of text'
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

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
                    'msg_hash': str(forgery.msg),
                    'pubkey': {'x': args.x, 'y': args.y},
                },
                indent=2,
            )
        )
    else:
        print(forgery)
    return 0


if __name__ == '__main__':
    sys.exit(main())
