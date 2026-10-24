# bip110-tools

Tools to **audit** which on-chain funds of your LND nodes exist on the BLAKE2b
chain that came out of BIP-110, and to **move them** by signing locally, without
closing channels and without the tool broadcasting anything on its own.

Everything is Python and shell, with no node dependency for signing: the node is
only used to read and, optionally, to revalidate before broadcasting.

> ⚠️ **Unaudited.** This is a custom signer: secp256k1, BIP32, BIP340, BIP86 and
> AEZ implemented by hand. It is validated against public vectors (see
> [Verification](#verification)), but that is not an audit. Use it with funds
> you can afford to lose.

---

## What it does

**Phase 1 — read-only.** `bip110_check.sh` asks where each node and each LND
runs, compares the two nodes around the split, takes a snapshot of the LND
wallet (xpubs, `listunspent`), scans with descriptors on both chains, validates
UTXO by UTXO against LND and writes a `summary.txt` per instance.

It classifies every UTXO as:

| Class | Meaning |
|---|---|
| **BLAKE2b only** | The outpoint no longer exists on SHA256 (already spent there). No replay risk |
| **On both chains** | The same outpoint is still unspent on both chains. A normal signature would be replayable |

**Phase 2 — sign and move.** `05_sweep.py` reads that folder, revalidates the
UTXOs against the BLAKE2b node, builds the transaction, signs it with
`SIGHASH_UNIFIED` (`0x21`) and writes the hex to disk. **It does not broadcast.**

`check_key.py` is the step before: it derives each UTXO's key and compares it
with its `scriptPubKey`, without signing anything.

**Phase 0 — check the environment.** Every module ships a `selftest` with public
vectors.

---

## What it does **not** do

- **It does not broadcast.** It prints the `sendrawtransaction` command; the
  last step is yours.
- **It does not build PSBTs.** That is a design decision, not a missing feature
  (see [Why no PSBT](#why-no-psbt)).
- **It does not touch channels.** Only on-chain UTXOs of the wallet, single-sig.
- **It is not multisig** and does not support taproot script paths.
- **It does not support testnet** from the CLI (the modules accept `hrp`, but
  the flow assumes mainnet).
- **It is not a wallet.** It keeps no state, manages no addresses, makes no
  change.

---

## Requirements

- `bash` 4.4 or newer (phase 1).
- `python3` 3.8+ (tested on 3.12 and 3.14).
- [`cryptography`](https://cryptography.io/) — **only** for the AES in
  `lib_aezeed.py`:

  ```bash
  python3 -m pip install cryptography
  # or, on Debian/Ubuntu: sudo apt install python3-cryptography
  ```

- For phase 1: `lncli`, and access to the nodes via `kubectl`, `ssh` or
  JSON-RPC.
- No network in phase 2, unless you pass `--node-url` to revalidate.

---

## Installation

```bash
git clone https://github.com/mmzgc776/bip110-tools.git bip110-tools
cd bip110-tools

python3 lib_aezeed.py selftest
python3 lib_secp256k1.py selftest
python3 lib_unified_sighash.py selftest
python3 lib_tx.py selftest
```

All four must end with `ALL OK`.

---

## Usage

### 1. Analyze (read-only)

```bash
./bip110_check.sh
```

It asks where each node and each LND runs. It leaves a folder
`bip110-YYYYMMDD-HHMMSS/` with mode `700`, a `summary.txt` per instance, the
scans and the LND snapshot. **That folder is not committed** (see `.gitignore`).

To skip the questions, export the variables with prefix `CORE_`, `KNOTS_`,
`BTC_`, `REF_` or `LND_` (see the headers of `lib_node.sh` and `lib_lnd.sh`).

### 2. Check the key before signing

This is the step that prevents signing with the wrong key. It does not print the
phrase or the derived private key; only the output key (which is already public,
it comes from the `scriptPubKey`).

```bash
read -rsp 'aezeed phrase: ' BIP110_AEZEED; echo
export BIP110_AEZEED
# if the wallet has a passphrase:
# read -rsp 'Passphrase: ' BIP110_PASS; echo; export BIP110_PASS

python3 check_key.py --all                 # every UTXO in the analysis
python3 check_key.py --all --instance lnd1 # one instance only
python3 check_key.py <txid:vout>           # one specific UTXO

unset BIP110_AEZEED BIP110_PASS
```

Each LND instance has its own seed: check them separately.

### 3. Sign

```bash
python3 05_sweep.py bip110-YYYYMMDD-HHMMSS \
  --dest bc1p... --feerate 5 --mode one-by-one --instance lnd1
```

Main options:

| Option | What it does |
|---|---|
| `--dest` | Destination address (mainnet; legacy, P2SH, segwit v0 or taproot) |
| `--feerate` | sat/vB |
| `--mode` | `one-by-one` (one tx per UTXO) or `sweep` (one tx per instance) |
| `--instance` | Limit to one instance (each LND has its own seed) |
| `--only` | Move a single outpoint; useful to test with the smallest one |
| `--include-shared` | Include the **on both chains** UTXOs (replay risk; see below) |
| `--path` | Base account (default `m/86'/0'/0'`; coin and index come from the descriptor) |
| `--dry-run` | Show without signing or writing |
| `--node-url` / `--node-user` / `--node-pass` / `--node-cookie` | Revalidate with `gettxout` before signing |

Keys are read **only** from the environment (never from argv, which ends up in
the shell history):

| Variable | Contents |
|---|---|
| `BIP110_AEZEED` | LND cipher seed (24 words) |
| `BIP110_PASS` | Phrase passphrase (BIP39 or aezeed) |
| `BIP110_MNEMONIC` | BIP39 phrase |
| `BIP110_XPRV` | Extended key of the taproot account |
| `BIP110_SECKEY` | Raw private key in hex (single UTXO) |

If none is present, the tool asks for it on the terminal without echo.

### 4. Broadcast (the step that is yours)

```bash
F=bip110-YYYYMMDD-HHMMSS/sweep/<outpoint_prefix>.hex

bitcoin-cli testmempoolaccept "[\"$(cat $F)\"]"   # must say "allowed": true

RES=$(bitcoin-cli testmempoolaccept "[\"$(cat $F)\"]")
echo "$RES" | grep -q '"allowed": true' \
  && bitcoin-cli sendrawtransaction "$(cat $F)" \
  || echo "not broadcast"
```

`testmempoolaccept` is not optional in practice: it is the only check that the
node accepts the unified signature.

---

## Why no PSBT

A PSBT's `sighash_type` field would carry `0x21`, and no standard signer
(Bitcoin Core, Sparrow, Specter…) implements `UnifiedSighash`: they would sign
the normal taproot digest and produce a signature that a Knots node rejects.
That is why the tool signs in-process and outputs a raw transaction. To inspect
it, use `bitcoin-cli decoderawtransaction <hex>`.

---

## How signing works

- **BIP86** (taproot key path): the internal key is the derived one; the output
  key is `internal + H_TapTweak(internal)`.
- **`SIGHASH_UNIFIED` (`0x21`)** = `SIGHASH_ALL | 0x20`. The digest uses the
  `UnifiedSighash` tagged hash and carries the locktime in **5 bytes**, not 4.
- The witness is `[64-byte signature + 1 hashtype byte]`, so the serialized
  signature is **65 bytes and ends in `21`**. That byte is the mark that the
  signature is unified.
- `nVersion = 2`, `nSequence = 0xFFFFFFFF`, `nLockTime = 0`: the transaction is
  **final and has no RBF**. If the fee is too low it cannot be replaced; pick
  the feerate with some margin.
- A single output, no change: it is a sweep.

**Replay.** For a *BLAKE2b only* UTXO the `0x21` makes no difference (there is
no copy on SHA256). For one *on both chains*, it is what prevents the
transaction from being replayed to SHA256: a SHA256 node does not understand
that hashtype. It requires `--include-shared`.

---

## aezeed: what is verified

The 24 words from `lncli create` **are not BIP39**. They share the 2048-word
list, but the checksum is CRC32-C (Castagnoli) over 33 bytes, not the BIP39
checksum. Notes that took a while to find, kept here for the next person:

- **The internal version is not the encryption one.** Byte 0 of the plaintext is
  `InternalVersion`: `0` = `KeyDerivationVersionLegacy`, `1` =
  `KeyDerivationVersionTaproot` (enables BIP86). LND accepts both
  (`keychain.IsKnownVersion`). A taproot wallet carries **1**; the public LND
  vectors are old and carry `0`.
- **The BIP32 seed is the raw 16-byte entropy**, not a BIP39 PBKDF2
  (`config_builder.go` passes `cipherSeed.Entropy[:]` to `loader.CreateNewWallet`).
- **An empty passphrase means the literal `aezeed`**.
- **AEZ: `tau` is multiplied by 8** when calling `aezHash` (`CipherTextExpansion
  * 8`), and the MAC check is that the 4 bytes of the decrypted tag are **all
  zero** — not a re-encryption compared with the ciphertext, which gives a false
  positive with any passphrase.
- In `aezHash`, `I` is doubled **after** the block whose index is a multiple of
  8 (the `i%8 == 0` check happens before incrementing `i`). It only shows up
  with inputs longer than 8 blocks.

---

## Privacy

Worth knowing what gets written when you use this:

- **`0x21` is an enumerable beacon.** Being an opt-in, non-standard hashtype, the
  set of all transactions with `0x21` can be listed exhaustively. It works as
  public proof of participation in the chain.
- **The tool's fingerprint is recognizable**: final `nSequence`, locktime 0, a
  single output, exact vsize, 65-byte witness ending in `21`. It groups
  transactions by tool, not by person.
- **Do not consolidate.** Spending two recovered UTXOs in the same transaction
  links them forever (common-input-ownership). Equally bad: sending them to the
  same address.
- **The strong privacy event is not the sweep, it is the deposit to a KYC
  exchange**, which ties identity, address and amount together.

---

## Verification

| Module | Covers | Result |
|---|---|---|
| `lib_secp256k1.py` | secp256k1, BIP32, BIP340, BIP39, BIP86 | BIP340 8/8, BIP39 288/288, BIP32 6/6, BIP86 2/2 |
| `lib_unified_sighash.py` | `UnifiedSighash` digest | 166/166 Knots vectors |
| `lib_aezeed.py` | AEZ, scrypt, aezeed | 2/2 LND vectors, `aez_hash` 27/27, versions 0 and 1 |
| `lib_tx.py` | Serialization, addresses, fee | round-trip + vsize |

```bash
for m in lib_secp256k1 lib_unified_sighash lib_aezeed lib_tx; do
  python3 $m.py selftest || break
done
```

---

## Layout

| File | What it does |
|---|---|
| `bip110_check.sh` | Full phase 1 flow |
| `01_lnd_snapshot.sh` | LND snapshot: `getinfo`, `walletbalance`, `listunspent` |
| `02_classify.py` | Classifies UTXOs as BEFORE / AFTER / UNCONF relative to the split |
| `03_check_blake2b.sh` | `gettxout` on Knots for the pre-split outpoints |
| `04_scan_blake2b.sh` | Standalone `scantxoutset` on one chain |
| `05_sweep.py` | Builds and signs the transactions (does not broadcast) |
| `check_key.py` | Checks that a key matches a UTXO |
| `lib_k3s.sh` / `lib_node.sh` / `lib_lnd.sh` | k3s, node and LND access |
| `lib_rpc.py` | Minimal JSON-RPC client (password via environment) |
| `lib_descriptors.py` | xpubs → descriptors and scan report |
| `lib_summary.py` | Final per-instance summary |
| `lib_secp256k1.py` | Curve, BIP32, BIP340, BIP39, BIP86 |
| `lib_unified_sighash.py` | `UnifiedSighash` digest |
| `lib_tx.py` | Transaction serialization, addresses, fee |
| `lib_aezeed.py` | LND cipher seed decryption |

Development notes: [`CONTEXTO.md`](CONTEXTO.md) (context and findings) and
[`PLAN_SWEEP.md`](PLAN_SWEEP.md) (signing phase plan).

---

## Known limitations

- The UTXOs to move must be **P2TR**; the tool aborts on anything else.
- **The BLAKE2b node must implement `UnifiedSighash`** (Knots 29.4.x with PR 357
  or later). A normal Bitcoin Core rejects `0x21`.
- **One seed per run**: use `--instance` so you do not mix nodes.
- **No RBF** (see [How signing works](#how-signing-works)).
- Node revalidation is optional; without it, an already-spent UTXO makes the tx
  fail at broadcast time.
- `05_sweep.py` assumes account `m/86'/0'/0'` (BIP86, account 0). Another account
  needs `--path`.

---

## License

MIT — free to use, modify and redistribute, **with attribution**: keep the
copyright notice and this permission notice in all copies or substantial
portions. See [`LICENSE`](LICENSE).

## Disclaimer

This moves real funds and signs with real keys. Check the hex before
broadcasting: a transaction with the wrong destination or a high fee is
irreversible. Always verify against your own nodes; nothing here replaces that
check.
