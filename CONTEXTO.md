# bip110-tools — context notes

Last updated: 2026-10-22.

## Goal

Find out which on-chain funds of your LND nodes (which run only on the SHA256
chain) are available on the BLAKE2b chain that came out of BIP-110, **without
closing channels**.

## BIP-110 / BLAKE2b context (summary of what was researched)

- BIP-110: a user-activated soft fork; it needed 55% signalling and reached
  ~2.53%. The nodes that enforced it split off on **2026-08-08 at block
  961,632** (last shared block: 961,631). They then changed the proof of work to
  BLAKE2b.
- Reference implementation: Bitcoin Knots `29.4.x.knots20260508`.
- The BLAKE2b chain shares the genesis block, network magic, ports and address
  format (`bc1…`). The same keys and addresses work on both chains.
- `SIGHASH_UNIFIED` (Knots PR #357): bit `0x20`, `UnifiedSighash` tagged hash. It
  is opt-in per signature and gives replay protection in one direction only.
  Normal signatures are still valid on both chains.
- Technical sources come mostly from the fork project itself. Always verify
  against your own nodes.

## Environment

- **Nodes**: one SHA256 (Bitcoin Core) and one BLAKE2b (Knots).
- **LND**: two instances, SHA256 only, on k3s. Each one has its own seed.
- The signing step runs wherever the keys already live; the tool is stateless
  and assumes no particular host.

## Tools, all read-only

| File | What it does |
|---|---|
| `bip110_check.sh` | **Full flow.** Asks where each node and each LND runs, compares the nodes around the split, takes the LND snapshot, scans with descriptors on both chains, validates UTXO by UTXO against LND and writes a `summary.txt` per instance. |
| `01_lnd_snapshot.sh` | LND snapshot: `getinfo`, `walletbalance`, `listunspent`. |
| `02_classify.py` | Classifies current UTXOs as BEFORE, AFTER or UNCONF relative to the split. |
| `03_check_blake2b.sh` | `gettxout` on Knots for the pre-split outpoints. Only useful if you have not moved funds. |
| `04_scan_blake2b.sh` | Standalone scan (`scantxoutset`) on one chain. |
| `lib_k3s.sh` | Namespace, pod and container selection, and prompts (`ask`). |
| `lib_node.sh` | Node access (`k3s`, `local`, `ssh`, `rpc`), `split_check`, `identity_check`, `scan_descriptors`. |
| `lib_lnd.sh` | LND access (`k3s`, `local`, `ssh`) with a macaroon. |
| `lib_rpc.py` | Minimal JSON-RPC client (`rpc` mode). The password comes from the environment, never from argv. |
| `lib_descriptors.py` | `lncli wallet accounts list` xpubs → descriptors, and the scan report. |
| `lib_summary.py` | Final summary: SHA256 validation and BLAKE2b classification ("blake2b only" / "both chains"). |

Typical use:

```bash
./bip110_check.sh
```

Requirements: bash 4.4 or newer, and `python3` plus `cryptography` (the latter
only for the AES inside the aezeed module).

### Design notes

- **LND descriptors:**
  - `WITNESS_PUBKEY_HASH` → `wpkh`
  - `HYBRID_NESTED_WITNESS_PUBKEY_HASH` (m/49') → `sh(wpkh)` for receive and
    `wpkh` for change
  - `TAPROOT_PUBKEY` → `tr`
  - ypub/zpub are converted to xpub. The range is each account's counter plus
    `GAP` (100).
- **Chain identity:** block `SPLIT_HEIGHT-1` must match on both nodes and
  `SPLIT_HEIGHT` must differ. Otherwise the script stops.
- **Variables to skip the questions:** prefixes `CORE_`, `KNOTS_`, `BTC_`,
  `REF_`, `LND_` (see the library headers). If a variable is still exported the
  question is skipped; clear it with `unset`.
- **Privacy:** the result folders (mode 700) contain xpubs and UTXOs and are not
  shared. When asking for help, share only the totals.
- **Tested** with simulated nodes, `kubectl`, `ssh` and `lncli`, including a real
  pty. It has been run end to end against real nodes on both chains, with
  "blake2b only" UTXOs found.

## Status and pending work

- Done: full read-only analysis (above).
- **Done: signing phase.** `05_sweep.py` builds and signs transactions with
  SIGHASH_UNIFIED (0x21) without depending on the node. Components:
  - `lib_secp256k1.py` — secp256k1, BIP32, BIP340, BIP86 (official vectors OK).
  - `lib_unified_sighash.py` — UNIFIED digest (166/166 Knots vectors).
  - `lib_tx.py` — transaction serialization and fee.
  - `lib_aezeed.py` — LND cipher seed decryption (aezeed, not BIP39).
    **Verified: 2/2 LND vectors and 27/27 `aez_hash`** (Yawning/aez).
- **Key sources** (environment only, never argv, never on disk):
  `BIP110_XPRV`, `BIP110_MNEMONIC` (BIP39), `BIP110_AEZEED` (LND cipher seed,
  24 words + `--passphrase`), `BIP110_SECKEY` (a single UTXO). If none is set,
  the wizard asks for the phrase without echo.
- The derived key is compared against the UTXO's `scriptPubKey` before signing;
  if it does not match, the tool aborts and shows the derived output key.
- **It does not broadcast.** It writes the hex files to `<results>/sweep/` (mode
  600) and prints the `sendrawtransaction` command for the user to run.
- Read-only pending (offered, not done): resume a previous analysis from its
  folder, revalidate the UTXOs live (`gettxout` on both nodes) and show the
  summary without scanning again.
- Never paste the seed, passwords or macaroons into a chat.

## How to verify the key before signing (mandatory step)

`check_key.py` derives each UTXO's key and compares it with its `scriptPubKey`
without signing or writing anything. It prints only `OK` / `NO MATCH` and the
derived output key (which is public). **Run it on the machine that holds the
seed**, and keep the seed there:

```bash
read -rsp 'aezeed phrase (24 words): ' BIP110_AEZEED; echo
export BIP110_AEZEED
# if the wallet has a passphrase:
# read -rsp 'Passphrase: ' BIP110_PASS; export BIP110_PASS

python3 check_key.py --all                 # every UTXO, the phrase only once
python3 check_key.py --all --instance lnd2 # one instance only

unset BIP110_AEZEED BIP110_PASS
```

Each LND has its own seed: `lnd1` and `lnd2` are checked separately.

## Derivation chain (verified against LND)

- LND uses the **raw aezeed entropy (16 bytes) as the BIP32 seed**
  (`config_builder.go`: `cipherSeed.Entropy[:]` → `loader.CreateNewWallet`).
  There is no BIP39 PBKDF2 in between.
- The seed's **internal version** (byte 0 of the plaintext) is a different
  thing: `0` = `KeyDerivationVersionLegacy`, `1` =
  `KeyDerivationVersionTaproot` (enables BIP86). LND accepts both
  (`keychain.IsKnownVersion`). The public LND vectors are old and carry 0;
  **a taproot wallet carries 1**. `decipher_ex` returns the version and the
  birthday so it can be checked.
- Default taproot account: **`m/86'/0'/0'`** (confirmed in both instances'
  `accounts.json`). A UTXO's full path is `m/86'/0'/0'/<coin>/<index>`, with
  `coin=0` receive and `coin=1` change.
- The default aezeed passphrase is the literal **`aezeed`**; `decipher()`
  applies it when none is given.
