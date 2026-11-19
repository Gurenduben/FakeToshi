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

# Your own key: r/s/z for a hash, and real signed transactions
python -m faketoshi keygen --network testnet
python -m faketoshi address --wif <wif> --network testnet
python -m faketoshi sign --key <hex> --txid <64-hex>
python -m faketoshi tx --key <hex> --network testnet \
    --input <TXID>:<VOUT>:<AMOUNT_SATS> --output <ADDRESS>:<SATS>
python -m faketoshi unsigned --input ... --output ...   # then:
python -m faketoshi signraw --key <hex> --raw <txhex> --prevout <SCRIPT>:<AMOUNT>
python -m faketoshi decode <txhex>

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

### Signing with your own key

Given your *own* private key, signing is ordinary ECDSA — no forgery involved,
and it works for any hash you like. Two distinct things are worth separating:

| | what it is | where it comes from |
| --- | --- | --- |
| `z` | the sighash: a hash of the transaction *and* the coin being spent | computed from the unsigned transaction |
| `r`, `s` | the ECDSA signature over that `z` | produced with your private key |
| `txid` | the id of the finished transaction | the double-SHA256 of the signed tx |

**`z` is not the txid.** A transaction's txid covers the whole transaction
including its signatures, so it cannot exist until after signing. The literal
"make `r`, `s`, `z` match a given txid" is therefore not a thing that exists —
and forcing a signature to verify under *someone else's* public key for a hash
*you* chose is the ECDSA problem itself, i.e. infeasible for any key you do not
control.

What does work, and is what this tool now does:

```
$ python -m faketoshi keygen --network testnet
network:     testnet
private_key: 41192f4f30bdb35a94c4f2c3b6d9e5ad9f70edc8f06a786e110da070aaa8495a
wif:         cPmF8MHddMc8nHEwxGSGGyH3Ffdptvf6jkrF3ZaVxBWpFQG4ptWB
public_key:  03cd26fcd4836fbec4b6017ac3775b8719a0f239dc52d7e7dbd4ec7e8b005d21a3
address:     tb1qxm6r2en8qua3eyzhry5lca2k7tagpgzdnf48xh

$ python -m faketoshi sign --key 41192f... --txid <64-hex hash>
r:            41394527160349269893567719044975991464542403203770718342843697060277985947166
s:            7079218598044748467707557541805724605987585697785694657053360430583559637789
z:            77648812782670860460512307594061302913369283834606025297048026922953510464427
public key:   034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
verified:     yes (against the public key above)
```

Build a real, broadcastable transaction and see the `r`/`s`/`z` of every input
signature:

```
$ python -m faketoshi tx --key <hex> --network testnet \
      --input <TXID>:0:100000 --output tb1q...:90000
network:   testnet
address:   tb1ql3e9pgs3mmwuwrh95fecme0s0qtn28804khrk8
...
txid:   2ad83856c35e86d6e2f9ee2d2e7f9218b32a337a7b216c579a411327c3fdfc58
wtxid:  2fa3a5dd7ba68e8dcdb73e52a2b00a722e6bedea45bcbe8bbbdca81d6f8e7130
input 0: aaaaaaaa...:0 sequence=0xffffffff
output 0: 90000 sats -> tb1ql3e9pgs3mmwuwrh95fecme0s0qtn28804khrk8
fee:      10000 sats

input 0 (p2wpkh)
  r: 7069007047506188436161873630490348643309926360255327021123589326885453870944
  s: 2452233303911921295559025361392836845077180123795995340953098431890553879292
  z: 24151005605303636859332393517207570533580414753563346217044012279647103940690
  sighash type: 0x01
  signature: 304402200fa0ea...

raw transaction: 02000000000101aaaaaaaa...
```

Details that matter:

- **The prevout amount is mandatory** in `--input`. Segwit signatures commit to
  the value of the coin being spent (BIP143), so signing with a wrong amount
  produces a transaction nodes reject.
- Signing is **RFC 6979 deterministic**: the same key and transaction always
  give the same signature, so you can re-run and compare. `s` is low-s
  normalised, as consensus/policy requires.
- Supported spend types: **P2WPKH** (default), **P2PKH**, and P2SH-P2WPKH via
  the library (`sign_transaction_kinds`). Taproot (Schnorr) is *not* supported.
- `--sighash` accepts `1` (ALL), `2` (NONE), `3` (SINGLE), `+0x80` for
  ANYONECANPAY; the legacy and BIP143 rules are both implemented, including the
  known `SIGHASH_SINGLE` bug.
- `unsigned` + `signraw` let you build the transaction with one tool and sign it
  elsewhere; `decode` prints a transaction and extracts the `r`/`s` from each
  witness.
- **Testnet/regtest only for real use.** Never paste a mainnet key into a tool
  you have not audited, and remember these are hot keys.

### The real signature-forgery condition: the SIGHASH_SINGLE bug

The other half of the story is a *genuine* signature-forgery bug, not an
existential one. With `SIGHASH_SINGLE` a signature commits to input `i` and
output `i`. When the transaction has **no output at index `i`**, Bitcoin Core's
`SignatureHash` returns the constant `uint256::ONE` — the bytes `01 00 … 00`,
i.e. `2**248` — instead of a hash of the transaction.

A signature over that constant is valid for **every** transaction that keeps the
input at an index without a matching output, so it commits to no amount,
destination or other input. Anyone who obtains such a signature can spend the
coin anywhere. This is the flaw behind the BitPay/Copay multisig losses.

```
$ python -m faketoshi sighash-single-demo
SIGHASH_SINGLE bug demonstration
================================
wallet (2-of-3 P2SH multisig)
  redeemScript: 5221020463...
  address:      355ruwEdjxaxYsecyiBgBBNRBEqQn3knut

step 1 - a transaction where input 1 has no matching output
  inputs: 2, outputs: 1
  digest for input 0 (SIGHASH_ALL):    8106667232...dc2087
  digest for input 1 (SIGHASH_SINGLE): uint256::ONE (01 00 ... 00)
  -> the bug: the digest is the constant uint256::ONE, not a hash

step 2 - a *different* transaction, built by someone else
  destination: 16Y48h9KAzppPPER9weEcuzHFEagjkPZh7
  scriptSig: 00483045022100e3595770...

step 3 - verification
  signature 0 valid in the attacker tx: True
  signature 1 valid in the attacker tx: True
  same signature with SIGHASH_ALL valid in the attacker tx: False
```

The same signature, lifted out of the first transaction, validates in a second
one that pays a different address — and the `SIGHASH_ALL` comparison shows the
signature failing to carry over, which is exactly the protection the bug
removes. The demonstration is entirely offline on synthetic outpoints.

Details that matter:

- **`uint256::ONE` is `2**248`, not the integer `1`** in ECDSA terms, because it
  is the 32 bytes `01 00…00` read big-endian. Implementations that use `1` here
  describe the bug loosely but compute the wrong digest.
- **Segwit v0 (BIP143) does not have this bug**: a missing matching output just
  means a zero `hashOutputs`, so the signature still commits to the transaction.
- Fixes are simple: never sign `SIGHASH_SINGLE`, require
  `len(outputs) >= len(inputs)`, and prefer `SIGHASH_ALL`/segwit.
- `analyse_sighash_single(tx, prevouts)` scans a raw transaction for
  `SIGHASH_SINGLE` signatures and reports whether the bug condition triggers.

`scriptsig`, `redeemscript`, `pubkey`, `decodesig` and `serialize` mirror the
inspection helpers of the reference tooling this was modelled on. For example,
the article's 2-of-3 script decodes to its published address:

```
$ python -m faketoshi redeemscript 5221023927b5cd...53ae
2-of-3 multisig redeemScript
  key 0: 023927b5cd7facefa7b85d02f73d1e1632b3aaf8dd15d4f9f359e37e39f0561196
  ...
  hash160: 06612b7cb2027e80ec340f9e02ffe4a9a59ba762
  P2SH spk: a91406612b7cb2027e80ec340f9e02ffe4a9a59ba76287
$ python -m faketoshi decode <that spk as an output>
output 0: 300000 sats -> 32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe
```

⚠️ A note on the reference material: the article it is modelled on
(`demining/Digital-Signature-Forgery-Attack`) mixes the genuine SIGHASH_SINGLE
bug with claims about CVE-2025-29774/29775, which are **XML signature
verification bypasses in the Node.js `xml-crypto` library** — unrelated to
Bitcoin. Its notebook only shells out to a prebuilt binary downloaded from a
third-party site. Nothing here executes that binary or relies on it; all the
cryptography is this repository's own, checked against the vectors above.

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

```python
from faketoshi import (
    build_transaction, key_info, make_unsigned, sign_raw_transaction,
    sign_z, verify_z, private_key_to_public_key, address_to_script,
)

private_key = int('11' * 32, 16)
address, wif, pubkey = key_info(private_key, 'testnet')

# Sign any 32-byte hash with your own key
r, s = sign_z(private_key, int('ab' * 32, 16))

# Build, sign and inspect a transaction
built = build_transaction(
    inputs=['aa' * 32 + ':0:100000'],
    outputs=[address + ':90000'],
    private_key=private_key,
    network='testnet',
)
built.txid, built.hex, built.fee()
for info in built.signatures:
    print(info.r, info.s, info.z)
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
from `r`) in `curve.point_from_x`.

Signing and transactions are separate from the forgery code:

| module | contents |
| --- | --- |
| `faketoshi/signing.py` | RFC 6979 nonces, `sign_z`/`verify_z`, DER, legacy and BIP143 sighashes, tx parsing/serialisation, `txid`/`wtxid` |
| `faketoshi/wallet.py` | address ↔ script, WIF, `build_transaction`, `sign_raw_transaction`, `make_unsigned` |
| `faketoshi/encoding.py` | hashes (incl. pure-Python RIPEMD160 fallback), varints, base58check, bech32 |
| `faketoshi/sighash_single.py` | multisig scripts, scriptSig parsing, the SIGHASH_SINGLE demo, `analyse_sighash_single`, `replay_signature` |

Signatures and sighashes were cross-checked against the third-party
`python-bitcointx` library: identical digests and txids, and the emitted DER
signatures verify independently. The SIGHASH_SINGLE behaviour follows Bitcoin
Core's `SignatureHash` (`src/script/interpreter.cpp`) and `uint256::ONE`
(`src/uint256.cpp`). The curve is
fixed to secp256k1 (the only curve the original used), and a public key point
that is not on the curve raises `ValueError` instead of producing garbage.