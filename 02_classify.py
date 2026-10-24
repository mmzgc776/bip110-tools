#!/usr/bin/env python3
"""Classifies the UTXOs of a 01_lnd_snapshot.sh snapshot against the BIP-110 split.

  - "BEFORE"  : created before the split  -> exists on both chains
                (unless it has already been spent on the BLAKE2b chain).
  - "AFTER"   : created at or after the split -> main chain only
                (unless someone has replayed the transaction).
  - "UNCONF"  : not confirmed yet.

Usage:
  python3 02_classify.py <snapshot_dir> [--split-height N]

Reads local files only; no network access.
"""

import argparse
import json
import sys
from pathlib import Path

# First block where the chains diverge (2026-08-08). Anything created at
# heights < SPLIT_HEIGHT is part of the shared history. Sources do not fully
# agree: 03_check_blake2b.sh confirms actual presence.
DEFAULT_SPLIT_HEIGHT = 961_632


def as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_outpoint(utxo):
    op = utxo.get("outpoint")
    if isinstance(op, str) and ":" in op:
        txid, vout = op.rsplit(":", 1)
        return txid, as_int(vout)
    if isinstance(op, dict):
        txid = op.get("txid_str") or op.get("txid")
        return txid, as_int(op.get("output_index"))
    return None, None


def load(path):
    with open(path) as f:
        return json.load(f)


def fmt_sat(sat):
    return f"{sat:>15,} sat  ({sat / 1e8:.8f} BTC)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot_dir")
    ap.add_argument("--split-height", type=int, default=DEFAULT_SPLIT_HEIGHT)
    args = ap.parse_args()

    d = Path(args.snapshot_dir)
    info = load(d / "getinfo.json")
    info_end = load(d / "getinfo_end.json") if (d / "getinfo_end.json").exists() else info
    balance = load(d / "walletbalance.json")
    unspent = load(d / "listunspent.json")

    tip = as_int(info.get("block_height"))
    tip_end = as_int(info_end.get("block_height"))
    chains = info.get("chains") or []
    network = chains[0].get("network") if chains else "?"

    if network != "mainnet":
        print(f"WARNING: the node reports network '{network}', not 'mainnet'.",
              file=sys.stderr)
    if not info.get("synced_to_chain", False):
        print("WARNING: LND is not synced; heights may be wrong.",
              file=sys.stderr)
    if tip != tip_end:
        print(f"WARNING: a block arrived during the snapshot ({tip} -> "
              f"{tip_end}); heights may be off by ±1.", file=sys.stderr)

    rows = []
    for u in unspent.get("utxos", []):
        txid, vout = parse_outpoint(u)
        confs = as_int(u.get("confirmations"))
        amount = as_int(u.get("amount_sat"))
        if confs <= 0:
            height, cls = None, "UNCONF"
        else:
            height = tip - confs + 1
            cls = "BEFORE" if height < args.split_height else "AFTER"
        rows.append({
            "txid": txid, "vout": vout, "amount_sat": amount,
            "confirmations": confs, "height": height, "class": cls,
            "address": u.get("address", ""), "address_type": u.get("address_type", ""),
        })

    rows.sort(key=lambda r: (r["height"] is None, r["height"] or 0))

    print(f"Network: {network}   LND height: {tip}   Split used: {args.split_height}")
    print()
    print(f"{'class':<9} {'height':>8} {'amount (sat)':>14}  {'type':<24} outpoint")
    print("-" * 110)
    for r in rows:
        h = str(r["height"]) if r["height"] is not None else "-"
        print(f"{r['class']:<9} {h:>8} {r['amount_sat']:>14,}  {r['address_type']:<24} "
              f"{r['txid']}:{r['vout']}")

    totals = {}
    for r in rows:
        totals[r["class"]] = totals.get(r["class"], 0) + r["amount_sat"]

    print()
    print("Totals by class:")
    for cls in ("BEFORE", "AFTER", "UNCONF"):
        n = sum(1 for r in rows if r["class"] == cls)
        print(f"  {cls:<9} {n:>3} UTXO  {fmt_sat(totals.get(cls, 0))}")

    print()
    print("LND walletbalance (for comparison):")
    for key in ("confirmed_balance", "unconfirmed_balance", "locked_balance",
                "reserved_balance_anchor_chan", "total_balance"):
        if key in balance:
            print(f"  {key:<30} {fmt_sat(as_int(balance[key]))}")

    pre_fork = [r for r in rows if r["class"] == "BEFORE"]
    out = d / "pre_fork_outpoints.txt"
    out.write_text("".join(f"{r['txid']} {r['vout']} {r['amount_sat']}\n" for r in pre_fork))
    out.chmod(0o600)
    print()
    print(f"{len(pre_fork)} pre-split outpoints saved to {out}")
    print("Next step (optional, on your BLAKE2b node): ./03_check_blake2b.sh", out)


if __name__ == "__main__":
    main()
