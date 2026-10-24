#!/usr/bin/env bash
# Takes a read-only "snapshot" of LND's on-chain wallet.
# Uses read-only RPCs only: getinfo, walletbalance, listunspent.
# It does not sign, open or close channels, or move funds.
#
# Usage:
#   ./01_lnd_snapshot.sh [--local] [output_dir]
#
# It asks where LND runs (k3s, this machine or SSH) and which macaroon to use.
# With --local it does not ask for the location. To skip every question:
#   LND_WHERE=k3s LND_NS=lightning LND_TARGET=lnd-0 LND_CONTAINER=lnd \
#   LND_MACAROON=/root/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon \
#   LND_EXTRA_ARGS=- ./01_lnd_snapshot.sh ./snap

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "I need bash 4.4 or newer (you have $BASH_VERSION)." >&2
  exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == "--local" ]]; then
  LND_WHERE="local"
  shift
fi
OUT="${1:-./snapshot-$(date +%Y%m%d-%H%M%S)}"

# shellcheck source=lib_k3s.sh
source "$HERE/lib_k3s.sh"
# shellcheck source=lib_lnd.sh
source "$HERE/lib_lnd.sh"
lnd_setup
run() { lnd_call "$@"; }

mkdir -p "$OUT"
chmod 700 "$OUT"

echo
echo "Reading getinfo..."
run getinfo > "$OUT/getinfo.json"

echo "Reading walletbalance..."
run walletbalance > "$OUT/walletbalance.json"

echo "Reading listunspent (includes unconfirmed)..."
run listunspent --min_confs=0 > "$OUT/listunspent.json"

# The height is read again at the end: if it changed during the snapshot, the
# heights computed for the UTXOs may be off by one block.
run getinfo > "$OUT/getinfo_end.json"

chmod 600 "$OUT"/*.json

echo
echo "Done. Files in: $OUT"
echo "They contain your wallet addresses and amounts: do not share them."
echo "Next step: python3 02_classify.py \"$OUT\""
