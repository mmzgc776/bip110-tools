#!/usr/bin/env bash
# Searches a Bitcoin node (Knots BLAKE2b or the SHA256 one) for every UTXO that
# currently exists on THAT chain for the keys of LND's on-chain wallet.
#
# Read-only at all times:
#   LND:  lncli wallet accounts list   (public keys only, onchain:read macaroon)
#   Node: getblockchaininfo, getblockhash, getdescriptorinfo, scantxoutset
# It does not use the seed, does not sign, does not touch channels, does not
# move funds.
#
# Usage:
#   ./04_scan_blake2b.sh [options] [output_dir]
#
# Options:
#   --accounts-file F   use an already saved "lncli wallet accounts list"
#                       (does not query LND)
#   --lnd-local         LND on this machine, without asking
#   --node-local        node to scan on this machine, without asking
#
# It asks, in this order:
#   1. which chain the node to scan is on (blake2b/sha256)
#   2. where LND runs: k3s, this machine or SSH (skipped with --accounts-file)
#   3. where the node to scan runs: k3s, this machine, SSH or RPC by IP
#   4. where the other chain's node runs, for comparison (k3s/local/ssh/rpc)
#
# Variables to skip the questions (besides the ones from lib_k3s.sh):
#   CHAIN=blake2b|sha256       which chain the node follows
#   LND_WHERE=k3s|local|ssh and the rest from lib_lnd.sh
#   BTC_WHERE=k3s|local|ssh|rpc (node to scan) and REF_WHERE (the other
#   chain's node, for comparison); the rest in lib_node.sh
#   GAP=100                    extra addresses to scan after the last used index
#   SPLIT_HEIGHT=961632
#   MAINNET_SPLIT_HASH=<hash>  hash of block SPLIT_HEIGHT on the SHA256 chain.
#                              If you do not provide it, the script asks where
#                              the other chain's node is and gets it by
#                              comparing both.

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

ACCOUNTS_FILE=""
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --accounts-file) ACCOUNTS_FILE="$2"; shift 2;;
    --lnd-local) LND_WHERE="local"; shift;;
    --node-local) BTC_WHERE="local"; shift;;
    -h|--help) sed -n '2,30p' "$0"; exit 0;;
    -*) echo "Unknown option: $1" >&2; exit 2;;
    *) OUT="$1"; shift;;
  esac
done

GAP="${GAP:-100}"
SPLIT_HEIGHT="${SPLIT_HEIGHT:-961632}"
MAINNET_SPLIT_HASH="${MAINNET_SPLIT_HASH:-}"

ask CHAIN "Which chain does the node you are going to scan follow? (blake2b/sha256)" "blake2b"
if [[ "$CHAIN" != "blake2b" && "$CHAIN" != "sha256" ]]; then
  echo "CHAIN must be blake2b or sha256." >&2
  exit 2
fi

OUT="${OUT:-./scan-$CHAIN-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"
chmod 700 "$OUT"

# ---------- 1. LND accounts (xpubs) ----------
if [[ -n "$ACCOUNTS_FILE" ]]; then
  cp "$ACCOUNTS_FILE" "$OUT/accounts.json"
  echo "Using accounts from $ACCOUNTS_FILE (LND is not queried)."
else
  lnd_setup
  echo "Reading LND accounts..."
  lnd_call wallet accounts list > "$OUT/accounts.json"
fi
chmod 600 "$OUT/accounts.json"

python3 "$HERE/lib_descriptors.py" build "$OUT/accounts.json" "$GAP" > "$OUT/descriptors.json"
chmod 600 "$OUT/descriptors.json"

# ---------- 2. Bitcoin node ----------
node_setup BTC "$CHAIN" "the node to scan ($CHAIN)"
identity_check "$CHAIN"
node_call BTC getblockchaininfo > "$OUT/blockchaininfo.json"
echo "$MAINNET_SPLIT_HASH" > "$OUT/mainnet_split_hash.txt"

# ---------- 3. Scan ----------
scan_descriptors BTC "$OUT/descriptors.json" "$OUT/scan.json"

echo
python3 "$HERE/lib_descriptors.py" report "$OUT/scan.json" "$OUT/descriptors.json" "$SPLIT_HEIGHT" \
  | tee "$OUT/report.txt"
echo
echo "Results in $OUT (they contain your xpubs and UTXOs: do not share them)."
