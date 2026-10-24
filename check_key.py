#!/usr/bin/env python3
"""Checks that a derived key corresponds to a UTXO, without exposing secrets.

Usage:
  python3 check_key.py [outpoint] [--results DIR] [--instance NAME]
  python3 check_key.py --all

Without an outpoint or --all, checks the first one it finds. Reads the key from
BIP110_AEZEED / BIP110_MNEMONIC / BIP110_XPRV (environment) and compares the
derived output key with the scriptPubKey of each UTXO in the analysis folder.
It does not print the key or the phrase; only OK / NO MATCH and the derived
output key (which is public, it comes from the scriptPubKey).

The 24 words from `lncli create` are aezeed, NOT BIP39: they are validated with
CRC32-C, not with the BIP39 checksum.

Writes nothing to disk.
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib_secp256k1 import TaprootKey  # noqa: E402

def find_results_dir(given):
    """Analysis folder: the one given, or the most recent bip110-*."""
    if given:
        return Path(given)
    base = Path(__file__).resolve().parent
    candidates = sorted(base.glob("bip110-*"))
    if not candidates:
        raise SystemExit(
            "Cannot find any bip110-* analysis folder. Point to it with "
            "--results.")
    return candidates[-1]


def load_targets(results_dir, outpoint, instance):
    """Returns [(instance, utxo)] for the P2TR UTXOs in the analysis."""
    found = []
    for sub in sorted(Path(results_dir).iterdir()):
        scan = sub / "scan-blake2b.json"
        if scan.exists():
            if instance and sub.name != instance:
                continue
            with open(scan, encoding="utf-8") as f:
                data = json.load(f)
            for u in data.get("unspents", []):
                op = f"{u['txid']}:{u['vout']}"
                if outpoint and op != outpoint:
                    continue
                found.append((sub.name, u))
    if outpoint and not found:
        raise SystemExit(f"Could not find {outpoint} in {results_dir}")
    return found


def load_key():
    """Returns (callable path -> TaprootKey, source, detail)."""
    mnemonic = os.environ.get("BIP110_MNEMONIC")
    xprv = os.environ.get("BIP110_XPRV")
    aezeed = os.environ.get("BIP110_AEZEED")
    passphrase = os.environ.get("BIP110_PASS", "")

    if aezeed:
        from lib_aezeed import (INTERNAL_VERSIONS, AezeedError,
                                birthday_to_date, decipher_ex)
        try:
            entropy, birthday, version = decipher_ex(aezeed, passphrase)
        except AezeedError as e:
            raise SystemExit(f"aezeed: {e}")
        detail = (f"internal version {version} "
                   f"({INTERNAL_VERSIONS[version]}), "
                   f"birthday {birthday_to_date(birthday)}")
        return (lambda path: TaprootKey.from_seed(entropy, path),
                "BIP110_AEZEED", detail)
    if mnemonic:
        return (lambda path: TaprootKey.from_mnemonic(mnemonic, path,
                                                      passphrase),
                "BIP110_MNEMONIC", "")
    if xprv:
        return (lambda path: TaprootKey.from_xprv(xprv, path),
                "BIP110_XPRV", "")

    raise SystemExit(
        "Export a key first:\n"
        "  read -rsp 'aezeed phrase: ' BIP110_AEZEED && export BIP110_AEZEED\n"
        "  (the 24 words from lncli create are aezeed, NOT BIP39)\n"
        "  if it has a passphrase: read -rsp 'Passphrase: ' BIP110_PASS && "
        "export BIP110_PASS")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("outpoint", nargs="?",
                    help="txid:vout to check (if omitted, all or the first "
                         "one)")
    ap.add_argument("--all", action="store_true",
                    help="check ALL UTXOs (each UTXO once, the phrase only "
                         "once)")
    ap.add_argument("--instance",
                    help="limit to one instance (the analysis subfolder "
                         "name, e.g. lnd1)")
    ap.add_argument("--results",
                    help="analysis folder (default: the latest bip110-* "
                         "found)")
    ap.add_argument("--path", default="m/86'/0'/0'",
                    help="taproot account base path")
    ap.add_argument("--passphrase", default="",
                    help="passphrase (BIP39 or aezeed; empty by default)")
    args = ap.parse_args()

    if args.passphrase and not os.environ.get("BIP110_PASS"):
        os.environ["BIP110_PASS"] = args.passphrase

    results_dir = find_results_dir(args.results)
    targets = load_targets(results_dir, args.outpoint, args.instance)
    if not targets:
        raise SystemExit("There are no UTXOs to check.")
    if not args.all and not args.outpoint:
        targets = targets[:1]

    derive, source, detail = load_key()
    print(f"folder    : {results_dir}")
    print(f"source    : {source}")
    if detail:
        print(f"aezeed    : {detail}")
    print(f"utxos     : {len(targets)}")

    bad = 0
    for inst, u in targets:
        spk = bytes.fromhex(u["scriptPubKey"])
        op = f"{u['txid']}:{u['vout']}"
        amount = round(u["amount"] * 1e8)
        if len(spk) != 34 or spk[0] != 0x51 or spk[1] != 0x20:
            print(f"\n[{inst}] {op}  {amount:,} sat")
            print("  skipped: not P2TR (cannot verify it)")
            continue
        want_x = spk[2:]

        desc = u.get("desc", "")
        try:
            inner = desc[desc.index("[") + 1:desc.index("]")]
            parts = inner.split("/")
            coin, idx = int(parts[-2]), int(parts[-1])
        except (ValueError, IndexError):
            print(f"\n[{inst}] {op}")
            print(f"  skipped: could not read the descriptor path: {desc}")
            continue

        path = f"{args.path}/{coin}/{idx}"
        key = derive(path)
        ok = key.output_x32 == want_x
        print(f"\n[{inst}] {op}  {amount:,} sat")
        print(f"  path      : {path}")
        print(f"  expected  : {want_x.hex()}")
        print(f"  derived   : {key.output_x32.hex()}")
        print(f"  result    : {'OK' if ok else 'NO MATCH'}")
        if not ok:
            bad += 1

    if bad:
        print("\nCheck, in this order:")
        print("  1. that the phrase is complete and well written (24 words)")
        print("  2. the passphrase (many wallets have one and it is easy to "
              "forget)")
        print("  3. that the phrase is from THIS instance and not the other")
        print(f"  4. that the account is '{args.path}'")
        return 1
    print("\nAll keys match their UTXOs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
