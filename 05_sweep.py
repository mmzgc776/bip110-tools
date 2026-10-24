#!/usr/bin/env python3
"""bip110-sweep: moves the 'BLAKE2b only' UTXOs to an address you control.

Continues the analysis from bip110_check.sh. Reads a results folder
(bip110-YYYYMMDD-HHMMSS/), rebuilds the classification, revalidates every UTXO
against the BLAKE2b node with gettxout, and builds transactions signed with
SIGHASH_UNIFIED (the Knots PR 357 opt-in, which protects against replay towards
the SHA256 chain).

It does NOT broadcast anything. It writes the hex to a file and tells you what
to do with it. The signature is yours and local.

Usage:
  ./05_sweep.py <results_dir> [options]

Examples:
  # One transaction per UTXO, to one address, 5 sat/vB fee
  ./05_sweep.py bip110-YYYYMMDD-HHMMSS \
      --dest bc1p... --feerate 5 --mode one-by-one

  # Sweep: all UTXOs in a single transaction
  BIP110_MNEMONIC="word word ..." ./05_sweep.py bip110-YYYYMMDD-HHMMSS \
      --dest bc1p... --feerate 5 --mode sweep

Private key (one of these, via environment variables, NEVER via argv):
  BIP110_XPRV       extended key (xprv...) of the taproot account
  BIP110_MNEMONIC   BIP39 phrase (uses --path and optionally --passphrase)
  BIP110_AEZEED     LND aezeed cipher seed (24 words; optional --passphrase
                    — if omitted, the literal "aezeed" is used)
  BIP110_SECKEY     raw private key in hex (for a single UTXO)

If none is present in the environment, the wizard asks for the phrase in the
terminal without echo. The 24 words printed by `lncli create` are aezeed,
NOT BIP39: they are validated with CRC32-C, not with the BIP39 checksum.

Options:
  --dest ADDR       destination address (required)
  --feerate N       fee in sat/vB (required)
  --mode MODE       'one-by-one' or 'sweep' (asks if omitted)
  --path PATH       derivation path when using BIP110_MNEMONIC
                    (default m/86'/0'/0'/0/<UTXO index>)
  --passphrase P    phrase passphrase (empty by default)
  --include-shared  also include the 'on both chains' UTXOs (DANGER: a normal
                    tx can be replayed to SHA256; only the unified sighash
                    protects them)
  --dry-run         show what it would do without signing or writing anything
  --node-url URL    BLAKE2b node to revalidate against (e.g. http://host:8332)
  --node-user U     RPC user
  --node-pass P     RPC password
  --node-cookie F   .cookie file
  --split-height N  split height (default 961632)

The private key is never written to disk and never appears in the output
files.
"""

import argparse
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib_secp256k1 import TaprootKey  # noqa: E402
from lib_unified_sighash import (  # noqa: E402
    unified_sighash, ST_TAPROOT, SIGHASH_UNIFIED,
)
from lib_tx import (  # noqa: E402
    Transaction, TxIn, TxOut, OutPoint, AddressError,
    decode_address, scriptpubkey_from_address, estimate_fee,
    estimate_taproot_sweep_weight,
)

DEFAULT_SPLIT_HEIGHT = 961_632
DEFAULT_GAP = 100

# ---------------------------------------------------------------------------
# Reading the analysis folder
# ---------------------------------------------------------------------------


def load_analysis(results_dir):
    """Reads the results folder and returns the list of instances."""
    d = Path(results_dir)
    if not d.is_dir():
        raise SystemExit(f"Folder does not exist: {d}")
    instances = []
    for sub in sorted(d.iterdir()):
        if not sub.is_dir():
            continue
        scan_b = sub / "scan-blake2b.json"
        scan_s = sub / "scan-sha256.json"
        descs = sub / "descriptors.json"
        if not (scan_b.exists() and scan_s.exists()):
            continue
        with open(scan_b) as f:
            blake = json.load(f)
        with open(scan_s) as f:
            sha = json.load(f)
        descriptors = []
        if descs.exists():
            with open(descs) as f:
                descriptors = json.load(f)
        instances.append({
            "name": sub.name,
            "blake": blake,
            "sha": sha,
            "descriptors": descriptors,
            "dir": sub,
        })
    if not instances:
        raise SystemExit(
            f"No analysis found in {d}. Run bip110_check.sh first.")
    return instances


def classify_utxos(instances, split_height):
    """Rebuilds the 'blake2b only' / 'both chains' classification."""
    rows = []
    for inst in instances:
        sha_set = {f"{u['txid']}:{u['vout']}" for u in
                   inst["sha"].get("unspents", [])}
        for u in inst["blake"].get("unspents", []):
            op = f"{u['txid']}:{u['vout']}"
            rows.append({
                "instance": inst["name"],
                "txid": u["txid"],
                "vout": u["vout"],
                "outpoint": op,
                "amount_sat": round(u["amount"] * 1e8),
                "height": u.get("height", 0),
                "scriptPubKey": u["scriptPubKey"],
                "desc": u.get("desc", ""),
                "kind": "both chains" if op in sha_set else "blake2b only",
                "confirmations": u.get("confirmations", 0),
            })
    rows.sort(key=lambda r: (r["kind"] != "blake2b only", r["amount_sat"]))
    return rows


# ---------------------------------------------------------------------------
# Live revalidation against the BLAKE2b node (read-only)
# ---------------------------------------------------------------------------


class NodeRPC:
    """Minimal JSON-RPC client (urllib, no dependencies)."""

    def __init__(self, url, user=None, password=None, cookie=None):
        self.url = url
        self.user = user or ""
        self.password = password or ""
        self.cookie = cookie

    def _call(self, method, params):
        import urllib.request
        body = json.dumps({"jsonrpc": "1.0", "id": "bip110",
                           "method": method, "params": params}).encode()
        user, password = self.user, self.password
        if self.cookie:
            with open(self.cookie) as f:
                user, _, password = f.read().strip().partition(":")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Basic {token}"})
        import urllib.error
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                reply = json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit("RPC 401 from the node: wrong user or password.")
            raise SystemExit(f"HTTP error {e.code} from the node.")
        except urllib.error.URLError as e:
            raise SystemExit(f"Could not connect to {self.url}: {e.reason}")
        if reply.get("error"):
            raise RuntimeError(reply["error"].get("message", "RPC error"))
        return reply.get("result")

    def gettxout(self, txid, vout):
        return self._call("gettxout", [txid, vout, True])

    def getblockchaininfo(self):
        return self._call("getblockchaininfo", [])


def revalidate(rows, node):
    """Queries gettxout for each UTXO. Returns (alive, spent)."""
    alive, spent = [], []
    for r in rows:
        try:
            out = node.gettxout(r["txid"], r["vout"])
        except RuntimeError as e:
            print(f"  ? {r['outpoint']}: query failed ({e})", file=sys.stderr)
            continue
        if out is None:
            spent.append(r)
        else:
            r["live_amount_sat"] = round(out.get("value", 0) * 1e8)
            r["live_confirmations"] = out.get("confirmations", 0)
            if r["live_amount_sat"] != r["amount_sat"]:
                print(f"  ! {r['outpoint']}: the node reports "
                      f"{r['live_amount_sat']} sat, not {r['amount_sat']}",
                      file=sys.stderr)
            alive.append(r)
    return alive, spent


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def verify_key_matches_utxo(key, utxo):
    """Checks that the derived key matches the UTXO's scriptPubKey.

    This is the defense against the most expensive mistake in the flow: signing
    with the wrong key. Returns True if the derived output key matches the one
    in the UTXO's taproot scriptPubKey.
    """
    try:
        spk = bytes.fromhex(utxo["scriptPubKey"])
    except (ValueError, KeyError):
        return False
    if len(spk) != 34 or spk[0] != 0x51 or spk[1] != 0x20:
        return False  # not P2TR, we cannot verify it
    return spk[2:] == key.output_x32


def build_key_source(args, utxo_indices):
    """Returns a callable utxo -> TaprootKey, or None if there is no key.

    The callable receives the UTXO dict (not an index), so it can read its
    descriptor and verify that the derived key corresponds to it.

    Key sources (from the environment, never from argv):
      BIP110_XPRV       extended key (xprv...) of the taproot account
      BIP110_MNEMONIC   BIP39 phrase (uses --path and optionally --passphrase)
      BIP110_AEZEED     LND aezeed cipher seed (24 words + optional
                        --passphrase; if omitted, the literal "aezeed" is used)
      BIP110_SECKEY     raw private key in hex (for a single UTXO)
    """
    xprv = os.environ.get("BIP110_XPRV")
    mnemonic = os.environ.get("BIP110_MNEMONIC")
    seckey_hex = os.environ.get("BIP110_SECKEY")
    aezeed = os.environ.get("BIP110_AEZEED")

    if seckey_hex:
        if len(utxo_indices) > 1:
            raise SystemExit(
                "BIP110_SECKEY only works for a single key; use --mode "
                "one-by-one or BIP110_XPRV / BIP110_MNEMONIC / "
                "BIP110_AEZEED for the sweep.")
        sk = int(seckey_hex, 16)
        key = TaprootKey(sk)

        def from_seckey(u):
            if not verify_key_matches_utxo(key, u):
                raise SystemExit(
                    f"The BIP110_SECKEY key does NOT match UTXO "
                    f"{u['outpoint'][:24]}...\nThe derived output key does "
                    f"not match its scriptPubKey. Nothing was signed.\n")
            return key
        return from_seckey

    if xprv:
        # The path is built from each UTXO's descriptor:
        # m/86'/0'/0'/<coin>/<addr_idx>, where coin=0 is receive, coin=1 change.
        base = args.path or "m/86'/0'/0'"
        keys = {}

        def from_xprv(u):
            coin, idx = parse_derivation_path(u.get("desc", ""))
            if idx is None:
                raise SystemExit(
                    f"Could not read the descriptor path of UTXO "
                    f"{u['outpoint'][:20]}... Use --path manually.")
            k = (coin, idx)
            if k not in keys:
                key = TaprootKey.from_xprv(xprv, f"{base}/{coin}/{idx}")
                if not verify_key_matches_utxo(key, u):
                    raise SystemExit(
                        f"The key derived from {base}/{coin}/{idx} does NOT "
                        f"match UTXO {u['outpoint'][:24]}...\n"
                        f"Check that the xprv belongs to the taproot account "
                        f"of this instance and that --path is correct.\n"
                        f"  derived output key: {key.output_x32.hex()}\n"
                        f"Nothing was signed.")
                keys[k] = key
            return keys[k]
        return from_xprv

    if mnemonic:
        base = args.path or "m/86'/0'/0'"
        keys = {}

        def from_mnemonic(u):
            coin, idx = parse_derivation_path(u.get("desc", ""))
            if idx is None:
                raise SystemExit(
                    f"Could not read the descriptor path of UTXO "
                    f"{u['outpoint'][:20]}... Use --path manually.")
            k = (coin, idx)
            if k not in keys:
                key = TaprootKey.from_mnemonic(
                    mnemonic, f"{base}/{coin}/{idx}", args.passphrase)
                if not verify_key_matches_utxo(key, u):
                    raise SystemExit(
                        f"The key derived from the phrase does NOT match "
                        f"UTXO {u['outpoint'][:24]}...\n"
                        f"Check: (1) that the phrase is correct, (2) the "
                        f"passphrase, (3) that --path is '{base}'.\n"
                        f"  derived output key: {key.output_x32.hex()}\n"
                        f"Nothing was signed.")
                keys[k] = key
            return keys[k]
        return from_mnemonic

    if aezeed:
        from lib_aezeed import (INTERNAL_VERSIONS, AezeedError,
                                birthday_to_date, decipher_ex)
        base = args.path or "m/86'/0'/0'"
        passphrase = args.passphrase or ""
        try:
            entropy, birthday, version = decipher_ex(aezeed, passphrase)
        except AezeedError as e:
            raise SystemExit(
                f"Could not decrypt the aezeed cipher seed: {e}\n"
                f"Check the 24 words and the --passphrase.")
        print(f"  aezeed: internal version {version} "
              f"({INTERNAL_VERSIONS[version]}), "
              f"birthday {birthday_to_date(birthday)}")
        keys = {}

        def from_aezeed(u):
            coin, idx = parse_derivation_path(u.get("desc", ""))
            if idx is None:
                raise SystemExit(
                    f"Could not read the descriptor path of UTXO "
                    f"{u['outpoint'][:20]}... Use --path manually.")
            k = (coin, idx)
            if k not in keys:
                key = TaprootKey.from_seed(entropy, f"{base}/{coin}/{idx}")
                if not verify_key_matches_utxo(key, u):
                    raise SystemExit(
                        f"The key derived from the aezeed cipher seed does NOT "
                        f"match UTXO {u['outpoint'][:24]}...\n"
                        f"Check: (1) that the 24 words are correct, (2) the "
                        f"--passphrase, (3) that --path is '{base}'.\n"
                        f"  derived output key: {key.output_x32.hex()}\n"
                        f"Nothing was signed.\n")
                keys[k] = key
            return keys[k]
        return from_aezeed

    return None


def parse_derivation_path(desc):
    """Extracts the full derivation path from the descriptor.

    scantxoutset format: tr([fingerprint/coin/addr_idx]key)
    where coin=0 is receive and coin=1 is change. LND's taproot path
    is m/86'/0'/0'/<coin>/<addr_idx> (BIP86, account 0).

    Returns (coin, addr_idx) or (None, None).
    """
    if not desc:
        return None, None
    try:
        inner = desc[desc.index("[") + 1:desc.index("]")]
        parts = inner.split("/")
        return int(parts[-2]), int(parts[-1])
    except (ValueError, IndexError):
        return None, None


def parse_derivation_index(desc):
    """Address index (kept for compatibility)."""
    _coin, idx = parse_derivation_path(desc)
    return idx


# ---------------------------------------------------------------------------
# Transaction construction
# ---------------------------------------------------------------------------


def build_single_tx(utxo, key, dest_spk, feerate, change_spk=None):
    """A tx that spends one UTXO to an address (with change if needed)."""
    txid_bytes = bytes.fromhex(utxo["txid"])[::-1]  # display -> internal order
    vin = [TxIn(OutPoint(txid_bytes, utxo["vout"]), 0xFFFFFFFF)]
    fee = int(estimate_fee(1, 1, int(feerate), change=change_spk is not None))
    out_value = utxo["amount_sat"] - fee
    if out_value < 546:
        raise ValueError(
            f"UTXO of {utxo['amount_sat']} sat does not cover the fee ({fee} "
            f"sat) and the dust limit.")
    vout = [TxOut(out_value, dest_spk)]
    if change_spk is not None:
        change_value = utxo["amount_sat"] - fee - out_value
        if change_value >= 546:
            vout.append(TxOut(change_value, change_spk))
    tx = Transaction(version=2, vin=vin, vout=vout, locktime=0)
    return tx


def build_sweep_tx(utxos, keys, dest_spk, feerate, change_spk=None):
    """A single tx that spends all UTXOs to an address."""
    vin = []
    total = 0
    for u in utxos:
        txid_bytes = bytes.fromhex(u["txid"])[::-1]
        vin.append(TxIn(OutPoint(txid_bytes, u["vout"]), 0xFFFFFFFF))
        total += u["amount_sat"]
    fee = int(estimate_fee(len(utxos), 1, int(feerate),
                           change=change_spk is not None))
    out_value = total - fee
    if out_value < 546:
        raise ValueError(
            f"Total {total} sat does not cover the fee ({fee} sat) and the "
            f"dust limit.")
    vout = [TxOut(out_value, dest_spk)]
    tx = Transaction(version=2, vin=vin, vout=vout, locktime=0)
    return tx


def sign_taproot(tx, utxos, keys, get_key):
    """Signs each input with SIGHASH_UNIFIED and builds the witness.

    get_key receives the UTXO dict and returns a TaprootKey.
    """
    spent = [(u["amount_sat"], bytes.fromhex(u["scriptPubKey"]))
             for u in utxos]
    ht = 0x01 | SIGHASH_UNIFIED  # ALL | UNIFIED = 0x21
    for i, u in enumerate(utxos):
        sighash = unified_sighash(b"", tx, i, ht, ST_TAPROOT, spent)
        key = get_key(u)
        sig = key.sign(sighash)
        tx.vin[i].witness = [sig + bytes([ht])]
    return tx


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def fmt_sat(n):
    return f"{n:,} sat"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results_dir")
    ap.add_argument("--dest", help="destination address (bech32m mainnet)")
    ap.add_argument("--feerate", type=float, help="fee in sat/vB")
    ap.add_argument("--mode", choices=["one-by-one", "sweep"],
                    help="one transaction per UTXO or one single transaction "
                         "for all of them (asks if omitted)")
    ap.add_argument("--interactive-key", action="store_true",
                    help="ask for the BIP39 phrase in the terminal (no echo, "
                         "with checksum validation) instead of reading it from "
                         "the environment")
    ap.add_argument("--word-by-word", action="store_true",
                    help="ask for the phrase word by word, validating each one "
                         "against the BIP39 list (default when there is no key "
                         "in the environment)")
    ap.add_argument("--only", metavar="OUTPOINT",
                    help="move ONLY this UTXO (txid:vout). Useful to test "
                         "with a small one before the sweep.")
    ap.add_argument("--instance",
                    help="limit to one instance (the analysis subfolder name, "
                         "e.g. lnd1). Each LND has its own seed: moving "
                         "several in one pass is not possible with one key")
    ap.add_argument("--path", help="base derivation path "
                                   "(default m/86'/0'/0'; the coin and the "
                                   "index come from each UTXO's descriptor)")
    ap.add_argument("--passphrase", default="",
                    help="phrase passphrase (BIP39 or aezeed; if omitted the "
                         "empty one is used, which for aezeed means the literal "
                         "'aezeed')")
    ap.add_argument("--include-shared", action="store_true",
                    help="also include the 'both chains' UTXOs")
    ap.add_argument("--dry-run", action="store_true",
                    help="show without signing or writing")
    ap.add_argument("--node-url", help="BLAKE2b node to revalidate against")
    ap.add_argument("--node-user")
    ap.add_argument("--node-pass")
    ap.add_argument("--node-cookie")
    ap.add_argument("--split-height", type=int, default=DEFAULT_SPLIT_HEIGHT)
    args = ap.parse_args()

    # ---- 1. Read and classify -------------------------------------------
    print("== Reading the analysis ==")
    instances = load_analysis(args.results_dir)
    rows = classify_utxos(instances, args.split_height)
    if args.instance:
        rows = [r for r in rows if r["instance"] == args.instance]
        if not rows:
            raise SystemExit(
                f"No UTXOs in {args.instance} inside {args.results_dir}.")
    only_blake = [r for r in rows if r["kind"] == "blake2b only"]
    shared = [r for r in rows if r["kind"] == "both chains"]

    print(f"  instances: {', '.join(i['name'] for i in instances)}")
    print(f"  UTXOs on BLAKE2b: {len(rows)} "
          f"({len(only_blake)} blake2b only, {len(shared)} both chains)")
    for r in rows:
        print(f"    [{r['kind']:<12}] {r['instance']:<6} "
              f"{r['outpoint'][:20]}... {fmt_sat(r['amount_sat'])}")
    total_only = sum(r["amount_sat"] for r in only_blake)
    print(f"  total blake2b only: {fmt_sat(total_only)}")

    targets = list(only_blake)
    if args.include_shared:
        print("\n  WARNING: including 'shared' UTXOs. A signature WITHOUT the "
              "unified\n  bit would be replayable to the SHA256 chain. This "
              "tool uses\n  SIGHASH_UNIFIED.")
        targets += shared

    if args.only:
        want = args.only.strip()
        match = [r for r in targets if r["outpoint"] == want]
        if not match:
            # It may be one of the excluded ones: warn clearly.
            in_shared = [r for r in shared if r["outpoint"] == want]
            if in_shared:
                raise SystemExit(
                    f"{want} is a 'both chains' UTXO. Moving it carries replay "
                    f"risk to SHA256.\nAdd --include-shared if you really want "
                    f"it (the unified signature protects it one way).")
            raise SystemExit(
                f"Could not find UTXO {want} among the candidates.")
        targets = match
        print(f"\n  --only: limited to {want} "
              f"({fmt_sat(targets[0]['amount_sat'])})")

    if not targets:
        raise SystemExit("There are no UTXOs to move.")

    # ---- 2. Revalidate live ---------------------------------------------
    if args.node_url:
        print("\n== Revalidating against the BLAKE2b node ==")
        node = NodeRPC(args.node_url, args.node_user, args.node_pass,
                       args.node_cookie)
        try:
            info = node.getblockchaininfo()
            print(f"  node: {info.get('chain')} height {info.get('blocks')}")
        except SystemExit:
            raise
        except Exception as e:
            print(f"  warning: could not read getblockchaininfo ({e})")
        alive, spent = revalidate(targets, node)
        if spent:
            print(f"  already spent ({len(spent)}):")
            for r in spent:
                print(f"    {r['outpoint'][:24]}... {fmt_sat(r['amount_sat'])}")
        targets = alive
        if not targets:
            raise SystemExit("Every target UTXO is already spent.")

    # ---- 3. Validate destination ----------------------------------------
    if not args.dest:
        args.dest = input("\nDestination address (bc1p...): ").strip()
    try:
        kind, _payload = decode_address(args.dest)
    except AddressError as e:
        raise SystemExit(f"Invalid destination address: {e}")
    dest_spk = scriptpubkey_from_address(args.dest)
    print(f"\n  destination: {args.dest}  ({kind})")

    # ---- 4. Fee and mode ------------------------------------------------
    if args.feerate is None:
        raw = input("Fee in sat/vB [5]: ").strip() or "5"
        args.feerate = float(raw)
    if args.feerate <= 0:
        raise SystemExit("The fee must be positive.")

    if not args.mode:
        if len(targets) == 1:
            args.mode = "one-by-one"
        else:
            ans = input("One transaction per UTXO or one single one for "
                        "all? (one-by-one/sweep) [sweep]: ").strip()
            args.mode = ans or "sweep"
    print(f"  mode: {args.mode}   fee: {args.feerate} sat/vB")

    # ---- 5. Key ---------------------------------------------------------
    # If there is no key in the environment, it is asked for in the terminal.
    # It never goes through argv or the shell history.
    have_env_key = any(os.environ.get(v) for v in
                       ("BIP110_XPRV", "BIP110_MNEMONIC", "BIP110_SECKEY",
                        "BIP110_AEZEED"))
    if not args.dry_run and not have_env_key:
        from lib_secp256k1 import prompt_mnemonic, prompt_mnemonic_words
        from lib_aezeed import prompt_aezeed
        print("\nThere is no key in the environment. I will ask for it here.")
        print("The 24 words from `lncli create` are aezeed, not BIP39.")
        ans = input("Which kind of phrase? (aezeed/bip39) [aezeed]: ")
        ans = ans.strip().lower() or "aezeed"
        if ans == "aezeed":
            os.environ["BIP110_AEZEED"] = prompt_aezeed()
        else:
            if args.interactive_key:
                os.environ["BIP110_MNEMONIC"] = prompt_mnemonic(confirm=True)
            else:
                os.environ["BIP110_MNEMONIC"] = prompt_mnemonic_words()

    key_source = build_key_source(args, list(range(len(targets))))
    if key_source is None and not args.dry_run:
        print("\nI need a key to sign. Options:")
        print("  (none)                         I ask for it word by word")
        print("  export BIP110_XPRV=xprv...     (extended key)")
        print("  export BIP110_MNEMONIC='...'   (BIP39 phrase)")
        print("  export BIP110_AEZEED='...'     (LND aezeed cipher seed)")
        print("  export BIP110_SECKEY=<hex>     (single UTXO)")
        raise SystemExit("No key, no signature. Nothing was written.")

    # ---- 6. Build and sign ----------------------------------------------
    print("\n== Building transactions ==")
    txs = []
    if args.mode == "one-by-one":
        for u in targets:
            tx = build_single_tx(u, None, dest_spk, args.feerate)
            txs.append((u, tx))
    else:
        # The sweep joins all UTXOs from ONE instance (each instance's
        # descriptors belong to different keys).
        by_inst = {}
        for u in targets:
            by_inst.setdefault(u["instance"], []).append(u)
        for inst, us in by_inst.items():
            tx = build_sweep_tx(us, None, dest_spk, args.feerate)
            txs.append(({"instance": inst, "utxos": us}, tx))

    if not args.dry_run:
        # Each key's derivation path comes from the UTXO descriptor.
        for entry, tx in txs:
            us = entry.get("utxos", [entry]) if isinstance(entry, dict) else [entry]
            sign_taproot(tx, us, None, key_source)

    # ---- 7. Write -------------------------------------------------------
    out_dir = Path(args.results_dir) / "sweep"
    written = []
    print("\n== Result ==")
    for entry, tx in txs:
        us = entry.get("utxos", [entry]) if isinstance(entry, dict) else [entry]
        total_in = sum(u["amount_sat"] for u in us)
        total_out = sum(o.value for o in tx.vout)
        fee = total_in - total_out
        inst = entry["instance"] if isinstance(entry, dict) else entry["instance"]
        # Unsigned there is no witness yet: the real vsize is larger, so in
        # dry-run we show the estimate from the same calculation that set the fee.
        if args.dry_run:
            vb = (estimate_taproot_sweep_weight(len(us), len(tx.vout)) + 3) // 4
        else:
            vb = tx.vsize()
        label = inst if args.mode == "sweep" else us[0]["outpoint"][:16]
        print(f"  [{label}] {len(us)} input(s) -> "
              f"{fmt_sat(total_in)} total, fee {fmt_sat(fee)} "
              f"({fee / max(vb, 1):.1f} sat/vB), "
              f"{vb} vB")
        print(f"     txid: {tx.txid().hex()}")
        if not args.dry_run:
            out_dir.mkdir(exist_ok=True)
            fname = out_dir / f"{label}.hex"
            fname.write_text(tx.serialize().hex())
            fname.chmod(0o600)
            written.append(fname)

    if args.dry_run:
        print("\n  (dry-run: nothing was signed or written)")
    else:
        print(f"\n  {len(written)} file(s) in {out_dir} (mode 600)")
        print("\n  To broadcast, on your BLAKE2b node:")
        for f in written:
            print(f"    bitcoin-cli sendrawtransaction $(cat {f})")
        print("\n  NEVER broadcast without checking the hex. A tx with a high "
              "fee or the\n  wrong destination is irreversible.")

    # Final summary
    total_moved = sum(sum(u["amount_sat"] for u in
                          (e.get("utxos", [e]) if isinstance(e, dict) else [e]))
                      for e, _ in txs)
    print(f"\n  Total to move: {fmt_sat(total_moved)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
