#!/usr/bin/env bash
# Checks on your BLAKE2b chain node (Bitcoin Knots) whether the outpoints
# from before the split are still unspent on that chain.
# Uses read-only RPCs only: getblockchaininfo, getblockhash, gettxout.
#
# Note: it only checks the UTXOs LND has TODAY (output of 02_classify.py).
# If you already moved the funds after the split, use 04_scan_blake2b.sh,
# which scans every wallet address.
#
# Usage:
#   ./03_check_blake2b.sh <pre_fork_outpoints.txt>
#
# It asks where each node runs (k3s, local, ssh or rpc by IP with credentials).
# Variables to skip the questions: the ones from lib_node.sh and lib_k3s.sh,
# plus
#   SPLIT_HEIGHT        split height (default 961632)
#   MAINNET_SPLIT_HASH  hash of block SPLIT_HEIGHT on the SHA256 chain. If you
#                       do not provide it, the script asks where your Core node
#                       is and gets it by comparing both nodes.
#
# Do not use public explorers for this: querying your outpoints one by one
# links all your addresses to a third party.

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "I need bash 4.4 or newer (you have $BASH_VERSION)." >&2
  exit 1
fi

FILE="${1:?Usage: $0 <pre_fork_outpoints.txt>}"
[[ -r "$FILE" ]] || { echo "Cannot read $FILE." >&2; exit 1; }
SPLIT_HEIGHT="${SPLIT_HEIGHT:-961632}"
MAINNET_SPLIT_HASH="${MAINNET_SPLIT_HASH:-}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib_k3s.sh
source "$HERE/lib_k3s.sh"
# shellcheck source=lib_node.sh
source "$HERE/lib_node.sh"

node_setup BTC blake2b "your BLAKE2b node (Knots)"
bcli() { node_call BTC "$@"; }
identity_check blake2b

echo
echo "== Outpoints =="
present=0; spent=0; total_present=0
while read -r txid vout amount; do
  [[ -z "${txid:-}" ]] && continue
  res="$(bcli gettxout "$txid" "$vout" true < /dev/null || true)"
  if [[ -n "$res" ]]; then
    echo "  UNSPENT     $amount sat  $txid:$vout"
    present=$((present + 1)); total_present=$((total_present + amount))
  else
    echo "  SPENT/NO    $amount sat  $txid:$vout"
    spent=$((spent + 1))
  fi
done < "$FILE"

echo
echo "Unspent on the BLAKE2b chain: $present UTXO, $total_present sat"
echo "Spent or non-existent:        $spent UTXO"
