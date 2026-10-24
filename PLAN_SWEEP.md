# Plan — bip110-sweep: signing our own BLAKE2b UTXO sweep

## Context

The existing tools are **read-only**: they identify which funds of the LND
instances exist on the BLAKE2b chain (the BIP-110 fork, split at block 961,632).
The analysis output folder (`bip110-<date>/`) contains the taproot (`tr`) UTXOs
identified against `scan-blake2b.json` / `scan-sha256.json`.

What was missing is the blocked part: **moving those UTXOs**. Decisions taken:

- **Python, minimal dependencies**: standard library plus `cryptography` (only
  for the AES inside AEZ). It matches the style of the existing scripts
  (`bip110_check.sh` + Python helpers).
- **We sign ourselves**, without relying on the node to sign. The node is used
  only (optionally) to validate the tx before broadcasting.
- We use **SIGHASH_UNIFIED** (bit `0x20`, hash type `0x21`), the Knots PR 357
  opt-in, which gives replay protection towards SHA256. The chantools PSBT fork
  does not implement it, so we do it by hand — the full specification is in
  `doc/unified-sighash.md` from Knots v29.4.1.knots20260508.
- **chantools stays as a reference**, not as a runtime dependency. It was cloned
  to read the taproot signing and transaction-building patterns.

### Hard decisions (already made)

- Go binary → **discarded**. Python, a handful of UTXOs, no need for speed.
- PSBT → **discarded as an output format**. We serialize a raw transaction
  (Bitcoin native format). It is ~80 lines and the user signs with their own key.
- Signing through the node (`signrawtransactionwithkey`) → **discarded**. Node
  independence.
- UTXOs that are "on both chains" are moved **only with SIGHASH_UNIFIED**; if the
  unified signature does not validate, they are not moved (the sweep warns and
  leaves them out, it does not fail silently).

## Scope of this iteration

Only **build and sign** the transactions. **No broadcasting** (that is a later
phase, with its own confirmation). The output is one tx hex file per sweep,
ready for `sendrawtransaction` if the user wants it.

## Pieces

### 1. `lib_secp256k1.py` — curve and signatures

- secp256k1 arithmetic in pure Python: point add/double (jacobian for speed),
  scalar multiplication, modular inversion.
- BIP32: `xprv → child xprv` derivation via HMAC-SHA512 (hardened and normal).
  Reuses the base58 parsing that already existed for descriptors (xpub/ypub/zpub
  versions), extended for xprv.
- BIP340 Schnorr: `sign(msg32, seckey, aux_rand)` and `verify`. Nonce per BIP340
  (tagged hash with the random aux), even-Y normalization at point R.
- BIP86: internal key = pubkey of the derived key, output key = internal +
  tweak(H_TapTweak(internal_x)), with the tweak from the BIP341 tap tweak.
- **Mandatory verification:** public BIP340 vectors (the ones in the BIP) and a
  sign→verify round-trip with a random key.

### 2. `lib_unified_sighash.py` — UNIFIED digest

Implements the *Specification → Message* section of `unified-sighash.md`:

- The 5 aggregates (`sha_prevouts`, `sha_amounts`, `sha_scripts`,
  `sha_sequences`, `sha_outputs`) with **plain SHA256**.
- Header: `epoch(1) + hashtype(1) + version(4 LE) + locktime(5 LE)`.
  Note: locktime is **5 bytes**, not 4.
- `script type = 2` (taproot key path), input index 4 bytes LE, annex bit `0`
  (no annex).
- Final digest: `TaggedHash("UnifiedSighash", message)` = double SHA256 with a
  double tag prefix, like BIP340.
- **Mandatory verification:** the 166 vectors from
  `src/test/data/unified_sighash.json`. We skip `scriptType` 0 and 1
  (legacy/segwit v0 — not applicable) and run types 2 and 3. All must match byte
  for byte.

### 3. `lib_tx.py` — transaction serialization

- Minimal `wire.MsgTx`: version, inputs (outpoint + sequence + empty scriptSig),
  outputs (value + scriptPubKey), locktime, plus the witness separately.
- Standard Bitcoin serialization. For taproot the witness is
  `[64-byte signature]` (key path, no script path).
- Addresses: parse the destination with pure `bech32`/`bech32m` (needed for
  `bc1p...`). Reuse the bech32 family if it already exists, otherwise write it
  (~40 lines).
- Fee: weight estimation with `P2TR key path input = 57.5 vbytes`, output =
  43 vbytes, base 10.5.

### 4. `05_sweep.py` — the wizard (entrypoint)

Chained to the existing flow. It reads from the analysis folder
(`bip110-YYYYMMDD-HHMMSS/`) — the same format `lib_summary.py` uses:

1. **Read** `lnd*/scan-blake2b.json` and `lnd*/scan-sha256.json`, rebuild the
   "blake2b only" / "both chains" classification (same logic as `lib_summary.py`,
   section 2).
2. **Revalidate live:** for each candidate UTXO, `gettxout` against the BLAKE2b
   node (reuses `lib_node.sh` / `node_call`, `ssh`/`rpc`/`k3s` mode). If it is
   already spent, it is dropped. This is read-only and uses the infrastructure
   that already exists.
3. **Ask for:** destination address (validate that it is mainnet bech32m), fee
   rate (sat/vB), and mode:
   - one tx per UTXO, or
   - a single tx with all the UTXOs (sweep).
   It distinguishes "blake2b only" from "both chains" and explicitly warns about
   replay risk on the latter.
4. **Sign:** takes the taproot account xprv **from the environment**
   (`BIP110_XPRV`), never from argv and never written to disk. Derives the BIP86
   key for each input, computes the UNIFIED digest, signs, builds the witness.
5. **Write** the tx hex files into the results folder (already git-ignored) and
   show the summary: what goes in, what comes out, fee, txid.
6. **Do not broadcast.** It prints the `sendrawtransaction` command for the user
   to run if they want.

### 5. Documentation

- `CONTEXTO.md`: drop the "Blocked" section and describe the new phase.
- `.gitignore`: already covers `bip110-*/`; verify the output hex files fall
  inside it.

## Work order

1. `lib_secp256k1.py` + tests (BIP340 vectors) — the base of everything.
2. `lib_unified_sighash.py` + the 166 vectors — the highest-risk piece.
3. `lib_tx.py` + serialization round-trip.
4. `05_sweep.py` — orchestration and CLI.
5. End-to-end test with one real UTXO (without broadcasting).
6. Commit.

## Verification

- **Unit:** BIP340 vectors (known signature) and the 166 unified-sighash ones.
- **Round-trip:** sign and verify with our own implementation.
- **End to end:** build the tx for the smallest UTXO and check that the BLAKE2b
  node's `decoderawtransaction` / `testmempoolaccept` accept it. This validates
  serialization and signature without risking funds.
- **Never** write the xprv, the seed or the passphrase to disk or to a chat.
