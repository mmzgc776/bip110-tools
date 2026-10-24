#!/usr/bin/env python3
"""Helper for 04_scan_blake2b.sh. Processes local files only; no network access.

  build  <accounts.json> <gap>                       -> descriptors (JSON) to stdout
  report <scan.json> <descriptors.json> <split_h>    -> table and totals
"""

import hashlib
import json
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ypub/zpub (and their testnet versions) are converted to xpub/tpub, which is
# the only thing Bitcoin Core/Knots descriptors accept.
VERSION_TO_PLAIN = {
    "0488b21e": "0488b21e",  # xpub
    "049d7cb2": "0488b21e",  # ypub
    "04b24746": "0488b21e",  # zpub
    "043587cf": "043587cf",  # tpub
    "044a5262": "043587cf",  # upub
    "045f1cf6": "043587cf",  # vpub
}

# LND address_type -> (receive template, change template).
# HYBRID is LND's default m/49' account: it receives on P2SH-P2WKH but
# produces change on native P2WKH.
TEMPLATES = {
    "WITNESS_PUBKEY_HASH": ("wpkh({k}/0/*)", "wpkh({k}/1/*)"),
    "NESTED_WITNESS_PUBKEY_HASH": ("sh(wpkh({k}/0/*))", "sh(wpkh({k}/1/*))"),
    "HYBRID_NESTED_WITNESS_PUBKEY_HASH": ("sh(wpkh({k}/0/*))", "wpkh({k}/1/*)"),
    "TAPROOT_PUBKEY": ("tr({k}/0/*)", "tr({k}/1/*)"),
}


def b58decode_check(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    data, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4] != chk:
        raise ValueError("invalid base58 checksum")
    return data


def b58encode_check(data):
    data = data + hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def to_plain_xpub(key):
    data = b58decode_check(key)
    version = data[:4].hex()
    if version not in VERSION_TO_PLAIN:
        raise ValueError(f"unknown extended key version: {version}")
    return b58encode_check(bytes.fromhex(VERSION_TO_PLAIN[version]) + data[4:])


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def build(accounts_path, gap):
    with open(accounts_path) as f:
        accounts = json.load(f).get("accounts", [])
    out = []
    for a in accounts:
        atype = a.get("address_type", "")
        path = a.get("derivation_path", "")
        name = a.get("name", "?")
        if atype not in TEMPLATES:
            print(f"Skipping account '{name}' ({atype} {path}): unsupported type.",
              file=sys.stderr)
            continue
        key = to_plain_xpub(a["extended_public_key"])
        ext_t, int_t = TEMPLATES[atype]
        for branch, tmpl, count in (
            ("receive", ext_t, as_int(a.get("external_key_count"))),
            ("change", int_t, as_int(a.get("internal_key_count"))),
        ):
            out.append({
                "desc": tmpl.format(k=key),
                "range": [0, count + gap],
                "label": f"{name} {path} {branch}",
            })
    if not out:
        print("No usable accounts found in the file.", file=sys.stderr)
        sys.exit(1)
    json.dump(out, sys.stdout, indent=2)
    print()


def report(scan_path, descs_path, split_height):
    with open(scan_path) as f:
        scan = json.load(f)
    with open(descs_path) as f:
        descs = json.load(f)

    if not scan.get("success", False):
        print("The scan did not finish successfully.", file=sys.stderr)
        sys.exit(1)

    print("Scanned descriptors:")
    for d in descs:
        print(f"  {d['label']:<45} range 0-{d['range'][1]}")
    print()

    rows = sorted(scan.get("unspents", []), key=lambda u: u.get("height", 0))
    tip = scan.get("height")
    print(f"Node height at scan time: {tip}   Split used: {split_height}")
    print()
    print(f"{'origin':<8} {'height':>8} {'amount (sat)':>14}  outpoint")
    print("-" * 100)
    total_pre = total_post = 0
    for u in rows:
        sat = round(u["amount"] * 1e8)
        h = u.get("height", 0)
        origin = "BEFORE" if h < split_height else "AFTER"
        if origin == "BEFORE":
            total_pre += sat
        else:
            total_post += sat
        print(f"{origin:<8} {h:>8} {sat:>14,}  {u['txid']}:{u['vout']}")

    print()
    print(f"UTXOs found: {len(rows)}")
    print(f"  created BEFORE the split  {total_pre:>15,} sat")
    print(f"  created AFTER the split   {total_post:>15,} sat")
    print(f"  total                     {total_pre + total_post:>15,} sat  "
          f"({(total_pre + total_post) / 1e8:.8f} BTC)")
    print()
    print("On the BLAKE2b chain, anything created AFTER the split comes from")
    print("transactions broadcast (or replayed) on that chain; check it carefully.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "build" and len(sys.argv) == 4:
        build(sys.argv[2], int(sys.argv[3]))
    elif cmd == "report" and len(sys.argv) == 5:
        report(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
