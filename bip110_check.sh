#!/usr/bin/env bash
# Full read-only flow to find out which on-chain funds of your LND nodes are
# available on the BLAKE2b chain (BIP-110) without closing channels.
#
#   ./bip110_check.sh [output_dir]
#
# It asks where each piece is (k3s, this machine, SSH or RPC by IP) and does:
#   1. Connect your SHA256 node (Core) and your BLAKE2b node (Knots) and
#      confirm, by comparing them, that each is on its chain.
#   2. For each LND instance:
#        a. wallet snapshot (getinfo, walletbalance, listunspent)
#        b. accounts/xpubs (wallet accounts list) -> descriptors
#        c. scan on SHA256 and validation against LND, UTXO by UTXO
#        d. scan on BLAKE2b
#        e. summary: what is on BLAKE2b, what is only there and what is on both
#
# Nothing signs, nothing broadcasts, nothing touches channels. It does not use
# the seed. Optional variables: SPLIT_HEIGHT (961632), GAP (100) and the ones
# from lib_node.sh / lib_lnd.sh with prefixes CORE_, KNOTS_ and LND_ to skip
# questions.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "I need bash 4.4 or newer (you have $BASH_VERSION)." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_k3s.sh
source "$HERE/lib_k3s.sh"
# shellcheck source=lib_node.sh
source "$HERE/lib_node.sh"
# shellcheck source=lib_lnd.sh
source "$HERE/lib_lnd.sh"

SPLIT_HEIGHT="${SPLIT_HEIGHT:-961632}"
GAP="${GAP:-100}"
OUT="${1:-./bip110-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
chmod 700 "$OUT"

title() {
  echo
  echo "################################################################"
  echo "  $*"
  echo "################################################################"
}

node_ready() {
  local pfx="$1" desc="$2"
  node_call "$pfx" getblockchaininfo | python3 -c '
import json, sys
i = json.load(sys.stdin)
print("  %s: blocks=%s headers=%s verification=%.4f" % (
    sys.argv[1], i.get("blocks"), i.get("headers"), i.get("verificationprogress", 0)))
if i.get("initialblockdownload") or i.get("blocks") != i.get("headers"):
    print("  STOP: %s is not synced; the scans would not be reliable." % sys.argv[1])
    sys.exit(1)
' "$desc"
}

cat <<EOF

This flow is READ-ONLY: it does not sign, broadcast or touch channels.
It will ask where your SHA256 node, your BLAKE2b node and each LND run.
Results in: $OUT
EOF

# ---------- 1. Nodes ----------
title "Step 1 of 2: Bitcoin nodes"
node_setup CORE sha256 "your SHA256 node (Core)"
node_setup KNOTS blake2b "your BLAKE2b node (Knots)"

echo
echo "== Sync status =="
node_ready CORE "SHA256 node"
node_ready KNOTS "BLAKE2b node"

echo
echo "== Comparison between the two nodes =="
split_check KNOTS CORE
MAINNET_SPLIT_HASH="$(node_call CORE getblockhash "$SPLIT_HEIGHT")"
echo "$MAINNET_SPLIT_HASH" > "$OUT/mainnet_split_hash.txt"

# ---------- 2. LND instances ----------
instance=0
SUMMARIES=()
while true; do
  instance=$((instance + 1))
  title "Step 2 of 2: LND, instance $instance"

  if (( instance > 1 )); then
    unset LND_WHERE LND_NS LND_TARGET LND_CONTAINER LND_MACAROON LND_EXTRA_ARGS LND_SSH LND_NAME
  fi
  ask LND_NAME "Short name for this instance (used as the folder name)" "lnd$instance"
  dir="$OUT/$LND_NAME"
  mkdir -p "$dir/snapshot"
  chmod 700 "$dir" "$dir/snapshot"

  lnd_setup

  echo
  echo "== a. Wallet snapshot =="
  lnd_call getinfo > "$dir/snapshot/getinfo.json"
  lnd_call walletbalance > "$dir/snapshot/walletbalance.json"
  lnd_call listunspent --min_confs=0 > "$dir/snapshot/listunspent.json"
  lnd_call getinfo > "$dir/snapshot/getinfo_end.json"
  python3 "$HERE/02_classify.py" "$dir/snapshot" > "$dir/snapshot/classify.txt" 2>&1
  sed -n '/Totals by class/,/^$/p' "$dir/snapshot/classify.txt"

  echo "== b. Accounts and descriptors =="
  lnd_call wallet accounts list > "$dir/accounts.json"
  python3 "$HERE/lib_descriptors.py" build "$dir/accounts.json" "$GAP" > "$dir/descriptors.json"
  echo "  $(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$dir/descriptors.json") descriptors."

  echo
  echo "== c. Scan on SHA256 =="
  scan_descriptors CORE "$dir/descriptors.json" "$dir/scan-sha256.json"

  echo
  echo "== d. Scan on BLAKE2b =="
  scan_descriptors KNOTS "$dir/descriptors.json" "$dir/scan-blake2b.json"

  chmod 600 "$dir"/*.json "$dir"/snapshot/*

  echo
  echo "== e. Summary for $LND_NAME =="
  python3 "$HERE/lib_summary.py" "$dir" "$SPLIT_HEIGHT" | tee "$dir/summary.txt"
  SUMMARIES+=("$dir/summary.txt")

  unset ANOTHER
  ask ANOTHER "Analyze another LND instance? (y/n)" "n"
  [[ "${ANOTHER,,}" == "y" || "${ANOTHER,,}" == "yes" ]] || break
done

title "Done"
echo "Summaries:"
printf '  %s\n' "${SUMMARIES[@]}"
echo
echo "Folder $OUT contains your xpubs, addresses and UTXOs: do not share it."
echo "If you want help interpreting it, share only the totals sections."
