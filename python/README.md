# Faketoshi — Python port

A dependency-free Python port of the Haskell original in the repository root
(`src/Faketoshi.hs` and `app/Main.hs`).

It produces an ECDSA signature `(r, s)` that **validates** against the Genesis
block public key — even though nobody can produce the message that hashes to
the forged "message hash". It is an *existential* forgery: the pre-image of the
hash is unknown, so it can never be a real Bitcoin transaction signature. The
point of the original project (and of this port) is to show that "I can sign
with Satoshi's key" claims are worthless on their own.

## Why it works

Verification only checks that `R = (z/s)·G + (r/s)·Q` has `R.x ≡ r (mod n)`,
where `z` is the message hash. Pick any `a`, `b ≠ 0`:

```
R = a·G + b·Q        r = R.x mod n
s = r·b⁻¹ mod n      z = r·a·b⁻¹ mod n
```

`(r, s)` now verifies for the hash `z`, but the forger cannot invert `z` to a
message. Verification here is "hashless": `z` is used directly, exactly as in
the Haskell `hashless_verify`.

## Requirements

Python 3.8+, standard library only. No `pip install` needed.

## Usage

```bash
cd python
python -m faketoshi                 # Genesis block public key
python -m faketoshi --json          # machine-readable output
python -m faketoshi --x <hex> --y <hex>
```

Sample output:

```
Sigs: (Signature 55413754737060266788854219512747294282411347075991670361274469493548857431872 93424288091486440220806836718410580011785069658824898026182133842707477669022)
Msg Hash: 38046050126674939701030028154132070444279826456685416136631938925359101037341
Public Key: (27508215986895653998444253056742679122811041256676723492045000752796524536365,14241215197100020720497056274756249375352291733590383593029593693896383225316)
```

As a library:

```python
from faketoshi import generate_forgery, valid_forgery
from faketoshi.__main__ import GENESIS_X, GENESIS_Y

forgery = generate_forgery(GENESIS_X, GENESIS_Y)
assert valid_forgery(forgery)
print(forgery.sig.r, forgery.sig.s, forgery.msg)
```

Install as a command (`faketoshi`) if you want:

```bash
pip install -e python
faketoshi
```

## Tests

```bash
cd python
python -m unittest discover -s tests -t . -v
```

The suite covers the curve arithmetic (including a known `2G` vector), valid
forgeries, rejection of tampered signatures/messages, the point-at-infinity
public key, out-of-range `r`/`s`, the non-invertible-`b` branch, and the CLI.
Forgeries have also been cross-checked against the third-party
[`ecdsa`](https://pypi.org/project/ecdsa/) library.

## Layout and Haskell mapping

| Haskell | Python |
| --- | --- |
| `src/Faketoshi.hs` | `faketoshi/faketoshi.py` |
| `app/Main.hs` | `faketoshi/__main__.py` |
| `Crypto.PubKey.ECC.Prim` / `.Types` | `faketoshi/curve.py` |
| `Faketoshi_Credentials{..}` | `FaketoshiCredentials` dataclass |
| `Signature r s` | `Signature(r, s)` |
| `generateMax` + `MonadRandom` | `secrets.randbelow` (injectable via `randbelow=`) |

Differences from the Haskell version: no `cryptonite` dependency, the curve is
fixed to secp256k1 (the original only ever used `SEC_p256k1`), `--x/--y/--json`
flags replace the hard-coded coordinates, and a point that is not on the curve
raises `ValueError` instead of silently producing garbage.
