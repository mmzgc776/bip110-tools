#!/usr/bin/env python3
"""Final summary for bip110_check.sh. Reads local files only; no network access.

  python3 lib_summary.py <instance_dir> <split_height>

Expects in the directory: snapshot/walletbalance.json, snapshot/listunspent.json,
scan-sha256.json and scan-blake2b.json.
"""

import json
import sys
from pathlib import Path


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def outpoint(u):
    op = u.get("outpoint")
    if isinstance(op, str):
        return op
    if isinstance(op, dict):
        return f"{op.get('txid_str') or op.get('txid')}:{as_int(op.get('output_index'))}"
    return f"{u.get('txid')}:{u.get('vout')}"


def sat(btc):
    return round(btc * 1e8)


def fmt(n):
    return f"{n:>15,} sat  ({n / 1e8:.8f} BTC)"


def main():
    d = Path(sys.argv[1])
    split = int(sys.argv[2])
    listunspent = json.load(open(d / "snapshot" / "listunspent.json")).get("utxos", [])
    balance = json.load(open(d / "snapshot" / "walletbalance.json"))
    sha = json.load(open(d / "scan-sha256.json"))
    blake = json.load(open(d / "scan-blake2b.json"))

    lnd_conf = {outpoint(u): as_int(u.get("amount_sat")) for u in listunspent
                if as_int(u.get("confirmations")) > 0}
    lnd_unconf = sum(as_int(u.get("amount_sat")) for u in listunspent
                     if as_int(u.get("confirmations")) <= 0)
    sha_set = {f"{u['txid']}:{u['vout']}": sat(u["amount"]) for u in sha.get("unspents", [])}
    blake_rows = blake.get("unspents", [])

    print("=" * 72)
    print(" 1. SHA256 validation: does the scan see the same as LND?")
    print("=" * 72)
    missing = set(lnd_conf) - set(sha_set)
    extra = set(sha_set) - set(lnd_conf)
    print(f"  LND (confirmed):          {len(lnd_conf):>4} UTXO {fmt(sum(lnd_conf.values()))}")
    print(f"  SHA256 node scan:         {len(sha_set):>4} UTXO {fmt(sum(sha_set.values()))}")
    if lnd_unconf:
        print(f"  (LND unconfirmed, not counted: {lnd_unconf:,} sat)")
    valid = not missing and not extra
    if valid:
        print("  OK: they match UTXO by UTXO. The descriptors cover the wallet.")
    else:
        print("  WARNING: they do not match. The BLAKE2b result is NOT validated.")
        for op in sorted(missing):
            print(f"    missing from the scan: {op}  {lnd_conf[op]:,} sat")
        for op in sorted(extra):
            print(f"    extra in the scan: {op}  {sha_set[op]:,} sat")
        print("  Typical causes: a new block between the snapshot and the scan (run")
        print("  it again), a short GAP, or an account type the descriptors miss.")

    print()
    print("=" * 72)
    print(" 2. Available on the BLAKE2b chain")
    print("=" * 72)
    shared = [u for u in blake_rows if f"{u['txid']}:{u['vout']}" in sha_set]
    only_blake = [u for u in blake_rows if f"{u['txid']}:{u['vout']}" not in sha_set]

    print(f"  {'type':<14} {'height':>8} {'amount (sat)':>14}  outpoint")
    print("  " + "-" * 100)
    for u in sorted(blake_rows, key=lambda r: r.get("height", 0)):
        key = f"{u['txid']}:{u['vout']}"
        kind = "both chains" if key in sha_set else "blake2b only"
        print(f"  {kind:<14} {u.get('height', 0):>8} {sat(u['amount']):>14,}  {key}")

    total_only = sum(sat(u["amount"]) for u in only_blake)
    total_shared = sum(sat(u["amount"]) for u in shared)
    post_split = [u for u in blake_rows if u.get("height", 0) >= split]
    print()
    print(f"  BLAKE2b only (already moved on SHA256): {len(only_blake):>4} UTXO {fmt(total_only)}")
    print(f"  On both chains (not moved):             {len(shared):>4} UTXO {fmt(total_shared)}")
    print(f"  TOTAL on BLAKE2b:                       {len(blake_rows):>4} UTXO "
          f"{fmt(total_only + total_shared)}")
    if post_split:
        print(f"  Note: {len(post_split)} UTXOs were created on BLAKE2b after the "
              "split (broadcast or replayed there).")

    print()
    print("=" * 72)
    print(" 3. Before moving anything on BLAKE2b")
    print("=" * 72)
    print("  - 'Both chains' are the same coins on the two chains: a normal")
    print("    transaction made on BLAKE2b can be replayed on SHA256 and move them")
    print("    there as well.")
    print("  - Only a SIGHASH_UNIFIED signature protects against that (and only in")
    print("    that direction).")
    print("  - Funds inside channels are not in this summary.")
    print(f"\n  LND confirmed walletbalance: {fmt(as_int(balance.get('confirmed_balance')))}")
    print(f"  Validation: {'OK' if valid else 'NOT VALIDATED'}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    main()
