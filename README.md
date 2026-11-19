# Faketoshi


With everyone seemingly trying to prove they are Satoshi (looking at you [Craig Wright](https://en.bitcoin.it/wiki/Craig_Wright) and the recent["faketoshi twitter"](https://archive.fo/Br5Tl)), we've decided to make it easier for other people to make similar claims.

Credit to Greg Maxwell and Pieter Wuille whose various posts (
[here](https://www.reddit.com/r/btc/comments/9xpivk/satoshi_i_do_not_want_to_be_public_but_there_is/e9uo87m/), 
[here](https://twitter.com/pwuille/status/1063582706288586752), and 
[here](https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau) 
) gave us enough of an understanding to implement our own Faketoshi-forger. We encourage you to check these resources out to understand why these continued Satoshi claims are nothing more than frauds.

The following implementation creates a signature (s) from a message hash (H(m)) that will validate against the public key from the genesis block. (Although it can easily be extended for **any Satoshi public key**). The trick is that the message (m), the pre-image of the message hash, itself cannot be known or derived. Thus this, and the other claims using the construction, is an existensial forgery.

You can browse to https://albacore.io/faketoshi for an generator in js that uses a similar construction.

### How to use
```
git clone git@github.com:albacorelabs/Faketoshi.git
cd Faketoshi

# No dependencies: Python 3.8+ and the standard library only.
python -m faketoshi          # forge for the Genesis block pubkey
python -m faketoshi --json   # machine-readable output
python -m faketoshi --x <hex> --y <hex>   # any other Satoshi pubkey

# Inspect a claim: your transaction hash plus r and s
python -m faketoshi verify --txid <64-hex-txid> --r <hex> --s <hex>

# Optionally install the `faketoshi` command
pip install -e .
faketoshi

/* Optional */
Post output on twitter claiming to be Satoshi
```

Example output:

```
Sigs: (Signature 55413754737060266788854219512747294282411347075991670361274469493548857431872 93424288091486440220806836718410580011785069658824898026182133842707477669022)
Msg Hash: 38046050126674939701030028154132070444279826456685416136631938925359101037341
Public Key: (27508215986895653998444253056742679122811041256676723492045000752796524536365,14241215197100020720497056274756249375352291733590383593029593693896383225316)
```

### Why it works

ECDSA verification only checks that `R = (z/s)·G + (r/s)·Q` has `R.x ≡ r (mod n)`,
where `z` is the message hash. Pick any `a` and `b ≠ 0`:

```
R = a·G + b·Q        r = R.x mod n
s = r·b⁻¹ mod n      z = r·a·b⁻¹ mod n
```

`(r, s)` then verifies for the hash `z`, but the forger cannot invert `z` to a
message. Verification here is "hashless": `z` is used directly, with no hashing
step, exactly as in the original implementation.

### Checking a claim (tx hash → r, s, z)

Already have a transaction hash and someone's `r`/`s`? `verify` decodes them and
tells you whether they actually validate for the claimed key:

```
$ python -m faketoshi verify --txid <64-hex-txid> --r 0x<hex> --s 0x<hex>
r: 104292152526504073417039695267310701787131548716728747048188210357489653668428
s: 15304645249139486252745633290151691593355992781340320034292527119815455925986
z: 27492682039654594488495269414934967390315654912485842810069785923538281112352
txid: 3cc84e7d342c83a523972674cf40faecd3b68ad687bbaffb7bc4d680de112320
Claimed key: (PublicKey 27508215986895653998444253056742679122811041256676723492045000752796524536365 14241215197100020720497056274756249375352291733590383593029593693896383225316)
Valid for claimed key: yes
Recoverable key 0: (PublicKey 91115180070214885452469887462397640982075413200794526559784006358321412533085 95129171953199970708625660034647388438999789667275228803567994047138938480436)
Recoverable key 1: (PublicKey 27508215986895653998444253056742679122811041256676723492045000752796524536365 14241215197100020720497056274756249375352291733590383593029593693896383225316)
```

- `--txid` is interpreted as `z`: the 32-byte hash read big-endian, exactly how
  Bitcoin's verifier treats the double-SHA256 of a transaction (`0x` optional).
- `--r` / `--s` are hex by default (with or without `0x`); add `--dec` to read
  them as decimal. The radix is never guessed — every decimal number is also a
  valid hex one, so guessing would silently change the values.
- `--x` / `--y` are the claimed public key; they default to the Genesis key.
- `--json` emits the same information as structured data.
- Exit codes: `0` valid for the claimed key, `1` not valid, `2` bad input.

The `Recoverable key` lines are the public keys for which those exact `r`, `s`
and `z` *do* verify. Verification rewrites to `R = (z/s)·G + (r/s)·Q`, so
solving for the key gives `Q = r⁻¹·(s·R − z·G)` with `R` any point whose x
coordinate equals `r` — at most two candidates, and no way to tell which one
signed. **A signature on its own therefore proves nothing about who made it**;
only checking it against a known public key does. (This is the same reason
"hand me a signature and I'll tell you it's Satoshi" claims are hollow.)

Note that this checks a signature *you already have*. It cannot produce valid
`(r, s)` for a transaction hash of your choosing under someone else's public
key — that is the ECDSA problem itself.

### As a library

```python
from faketoshi import generate_forgery, valid_forgery
from faketoshi.__main__ import GENESIS_X, GENESIS_Y

forgery = generate_forgery(GENESIS_X, GENESIS_Y)
assert valid_forgery(forgery)
print(forgery.sig.r, forgery.sig.s, forgery.msg)
```

```python
from faketoshi import inspect_claim, recover_public_keys, tx_hash_to_z, format_tx_hash

result = inspect_claim(txid, r_hex, s_hex, GENESIS_X, GENESIS_Y)   # radix = hex
result.valid            # does it verify for that key?
result.z, result.r      # decoded values
str(result)             # the human-readable report shown above

recover_public_keys(r, s, tx_hash_to_z(txid))   # the keys it does verify for
format_tx_hash(z)                                # hex form of a z value
```

### Tests

```
python -m unittest discover -s tests -t . -v
```

### Implementation notes

This repository was originally written in Haskell against the `cryptonite`
package; it is now plain Python with no third-party dependencies. The secp256k1
arithmetic lives in `faketoshi/curve.py`, the forging and verification logic in
`faketoshi/faketoshi.py`, and the CLI in `faketoshi/__main__.py`. Key recovery
lives in `recover_public_keys`, and point decompression (needed to recover keys
from `r`) in `curve.point_from_x`. The curve is
fixed to secp256k1 (the only curve the original used), and a public key point
that is not on the curve raises `ValueError` instead of producing garbage.