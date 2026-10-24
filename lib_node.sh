#!/usr/bin/env bash
# Connection to Bitcoin nodes no matter where they run. Requires lib_k3s.sh loaded.
#
#   node_setup <PFX> <blake2b|sha256> <description>
#       Asks where the node runs and prepares access. Then:
#   node_call <PFX> <method> [parameters...]
#       Used like bitcoin-cli.
#   split_check <PFX_scanned> <PFX_reference>
#       Compares the two nodes around SPLIT_HEIGHT.
#
# PFX is a variable prefix: BTC (node to scan) or REF (reference node).
# Locations:
#   k3s    cluster pod (asks for namespace/pod/container)
#   local  bitcoin-cli on this machine (variable <PFX>_BCLI, default bitcoin-cli)
#   ssh    bitcoin-cli on another machine over SSH
#   rpc    direct connection by IP:port with user/password or cookie;
#          does not need bitcoin-cli installed
#
# Variables to skip the questions (replace BTC_ with REF_ for the reference node):
#   BTC_WHERE, BTC_CLI_ARGS, BTC_SSH,
#   BTC_RPC_HOST, BTC_RPC_PORT, BTC_RPC_AUTH (pass|cookie),
#   BTC_RPC_USER, BTC_RPC_PASS, BTC_RPC_COOKIE,
#   BTC_NS, BTC_TARGET, BTC_CONTAINER (k3s)

node_setup() {
  local pfx="$1" chain="$2" desc="$3" hint
  if [[ "$chain" == "blake2b" ]]; then
    hint='knots|blake'
  else
    hint='core|bitcoind|bitcoin|btc'
  fi

  local where_var="${pfx}_WHERE" args_var="${pfx}_CLI_ARGS"
  echo
  echo "Where does $desc run?"
  echo "  k3s    inside a cluster pod"
  echo "  local  on this machine"
  echo "  ssh    on another machine reachable over SSH"
  echo "  rpc    on another machine, direct RPC connection by IP"
  ask "$where_var" "Location (k3s/local/ssh/rpc)" "k3s"
  local where="${!where_var}"

  declare -g -a "${pfx}_EXTRA"
  local -n extra_ref="${pfx}_EXTRA"
  extra_ref=()
  if [[ "$where" != "rpc" ]]; then
    ask "$args_var" "Extra bitcoin-cli arguments (e.g. -datadir=/data, empty: -)" "-"
    [[ "${!args_var}" == "-" ]] && printf -v "$args_var" '%s' ""
    [[ -n "${!args_var}" ]] && read -r -a extra_ref <<< "${!args_var}"
  fi

  case "$where" in
    k3s)
      k3s_pick "$pfx" bitcoin-cli "$hint"
      ;;
    local)
      local bcli_var="${pfx}_BCLI"
      [[ -n "${!bcli_var:-}" ]] || printf -v "$bcli_var" '%s' "bitcoin-cli"
      ;;
    ssh)
      ask "${pfx}_SSH" "Node SSH host (user@host or a ~/.ssh/config alias)"
      ;;
    rpc)
      local host_var="${pfx}_RPC_HOST" port_var="${pfx}_RPC_PORT" auth_var="${pfx}_RPC_AUTH"
      local user_var="${pfx}_RPC_USER" pass_var="${pfx}_RPC_PASS" cookie_var="${pfx}_RPC_COOKIE"
      ask "$host_var" "Node IP or host"
      ask "$port_var" "RPC port" "8332"
      ask "$auth_var" "Authentication: pass (rpcuser/rpcpassword) or cookie (.cookie file)" "pass"
      if [[ "${!auth_var}" == "cookie" ]]; then
        ask "$cookie_var" "Path to the .cookie file on THIS machine"
        [[ -r "${!cookie_var}" ]] || { echo "Cannot read ${!cookie_var}." >&2; exit 1; }
      else
        ask "$user_var" "RPC user (rpcuser)"
        if [[ -z "${!pass_var:-}" ]]; then
          local pw
          read -r -s -p "RPC password (not shown): " pw \
            || { echo >&2; echo "Input ended." >&2; exit 1; }
          echo
          printf -v "$pass_var" '%s' "$pw"
        fi
      fi
      printf -v "${pfx}_RPC_URL" '%s' "http://${!host_var}:${!port_var}"
      local url_var="${pfx}_RPC_URL"
      echo "  RPC: ${!url_var} (RPC traffic is unencrypted; use it only on your local network or over a VPN)"
      ;;
    *)
      echo "Location must be k3s, local, ssh or rpc." >&2
      exit 2
      ;;
  esac

  if ! node_call "$pfx" getblockchaininfo > /dev/null; then
    echo "Could not query $desc. Check the location and the credentials." >&2
    exit 1
  fi
  local version
  version="$(node_call "$pfx" getnetworkinfo | python3 -c 'import json,sys; print(json.load(sys.stdin).get("subversion","?"))')"
  echo "  Connection OK: $version"
}

node_call() {
  local pfx="$1"; shift
  local where_var="${pfx}_WHERE"
  local -n extra_ref="${pfx}_EXTRA"
  case "${!where_var}" in
    k3s)
      local -n exec_ref="${pfx}_EXEC"
      "${exec_ref[@]}" bitcoin-cli "${extra_ref[@]}" "$@"
      ;;
    local)
      local bcli_var="${pfx}_BCLI" cmd
      read -r -a cmd <<< "${!bcli_var}"
      "${cmd[@]}" "${extra_ref[@]}" "$@"
      ;;
    ssh)
      # The remote shell re-interprets the line: each argument is escaped so
      # the scantxoutset JSON arrives intact.
      local ssh_var="${pfx}_SSH" line
      line="$(printf '%q ' bitcoin-cli "${extra_ref[@]}" "$@")"
      ssh -o BatchMode=yes "${!ssh_var}" "$line" < /dev/null
      ;;
    rpc)
      local url_var="${pfx}_RPC_URL" user_var="${pfx}_RPC_USER" pass_var="${pfx}_RPC_PASS"
      local cookie_var="${pfx}_RPC_COOKIE"
      BTC_RPC_URL="${!url_var}" BTC_RPC_USER="${!user_var:-}" BTC_RPC_PASS="${!pass_var:-}" \
        BTC_RPC_COOKIE="${!cookie_var:-}" python3 "$HERE/lib_rpc.py" "$@"
      ;;
  esac
}

# split_check <PFX_scanned> <PFX_reference>
# Block SPLIT_HEIGHT-1 must match (shared history) and SPLIT_HEIGHT must differ
# (each node on its own chain). It leaves the reference hash in
# MAINNET_SPLIT_HASH when the reference is the SHA256 node.
split_check() {
  local scan="$1" ref="$2" h_prev="$((SPLIT_HEIGHT - 1))"
  local scan_prev scan_split ref_prev ref_split
  scan_prev="$(node_call "$scan" getblockhash "$h_prev")"
  scan_split="$(node_call "$scan" getblockhash "$SPLIT_HEIGHT")"
  ref_prev="$(node_call "$ref" getblockhash "$h_prev")" \
    || { echo "The reference node does not have block $h_prev (pruned or not synced?)." >&2; exit 1; }
  ref_split="$(node_call "$ref" getblockhash "$SPLIT_HEIGHT")" \
    || { echo "The reference node does not have block $SPLIT_HEIGHT." >&2; exit 1; }

  echo "  block $h_prev   scanned: $scan_prev"
  echo "                  reference: $ref_prev"
  echo "  block $SPLIT_HEIGHT   scanned: $scan_split"
  echo "                  reference: $ref_split"

  if [[ "$scan_prev" != "$ref_prev" ]]; then
    echo "  STOP: the nodes already differ at block $h_prev. Either the split was" >&2
    echo "  before $SPLIT_HEIGHT (adjust SPLIT_HEIGHT), or one node is not what you think." >&2
    exit 1
  fi
  if [[ "$scan_split" == "$ref_split" ]]; then
    echo "  STOP: both nodes have the same block $SPLIT_HEIGHT: they are on the same chain." >&2
    exit 1
  fi
  echo "  OK: shared history up to $h_prev and different chains from $SPLIT_HEIGHT."
}

# identity_check <blake2b|sha256>
# Confirms which chain the BTC node is on by comparing it with the node of the
# other chain (REF), asked for here. If MAINNET_SPLIT_HASH is already set, it
# compares against that hash without asking for a second node.
identity_check() {
  local chain="$1" other split_hash
  if [[ "$chain" == "blake2b" ]]; then other="sha256"; else other="blake2b"; fi

  echo
  echo "== Node identity ($chain) =="
  node_call BTC getblockchaininfo | python3 -c '
import json, sys
i = json.load(sys.stdin)
print("  chain=%s blocks=%s headers=%s verification=%.4f" % (
    i.get("chain"), i.get("blocks"), i.get("headers"), i.get("verificationprogress", 0)))
if i.get("initialblockdownload"):
    print("  STOP: the node is still in initial block download; results would not be reliable.")
    sys.exit(1)
'

  if [[ -n "${MAINNET_SPLIT_HASH:-}" ]]; then
    split_hash="$(node_call BTC getblockhash "$SPLIT_HEIGHT")"
    echo "  block $SPLIT_HEIGHT on this node: $split_hash"
    echo "  MAINNET_SPLIT_HASH given:      $MAINNET_SPLIT_HASH"
    if [[ "$chain" == "blake2b" && "$split_hash" == "$MAINNET_SPLIT_HASH" ]]; then
      echo "  STOP: it matches the SHA256 chain. This node does NOT follow BLAKE2b." >&2
      exit 1
    fi
    if [[ "$chain" == "sha256" && "$split_hash" != "$MAINNET_SPLIT_HASH" ]]; then
      echo "  STOP: it does not match the given SHA256 hash. This node is not the SHA256 one." >&2
      exit 1
    fi
    echo "  OK: the node is on the $chain chain."
    return
  fi

  if [[ "$chain" == "sha256" ]]; then
    ask COMPARE_OTHER "Compare against your BLAKE2b node to confirm the chain? (y/n)" "y"
    if [[ "$COMPARE_OTHER" != "y" && "$COMPARE_OTHER" != "s" ]]; then
      MAINNET_SPLIT_HASH="$(node_call BTC getblockhash "$SPLIT_HEIGHT")"
      echo "  Not compared. Hash of block $SPLIT_HEIGHT on this node: $MAINNET_SPLIT_HASH"
      return
    fi
  fi

  node_setup REF "$other" "your reference node ($other)"
  echo
  echo "== Comparison with the $other node =="
  split_check BTC REF
  if [[ "$chain" == "blake2b" ]]; then
    MAINNET_SPLIT_HASH="$(node_call REF getblockhash "$SPLIT_HEIGHT")"
  else
    MAINNET_SPLIT_HASH="$(node_call BTC getblockhash "$SPLIT_HEIGHT")"
  fi
  echo "  To skip the comparison next time: export MAINNET_SPLIT_HASH=$MAINNET_SPLIT_HASH"
}

# scan_descriptors <PFX> <descriptors.json> <scan_output.json>
# Adds each descriptor's checksum (computed by the node itself) and runs
# scantxoutset. Read-only.
scan_descriptors() {
  local pfx="$1" descs="$2" out="$3" count i desc sums
  sums="$(mktemp)"
  echo "  Computing descriptor checksums..."
  count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$descs")"
  for ((i = 0; i < count; i++)); do
    desc="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[int(sys.argv[2])]["desc"])' \
      "$descs" "$i")"
    node_call "$pfx" getdescriptorinfo "$desc" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["checksum"])' >> "$sums"
  done

  local scanobjects
  scanobjects="$(python3 - "$descs" "$sums" <<'PYEOF'
import json, sys
descs = json.load(open(sys.argv[1]))
sums = open(sys.argv[2]).read().split()
print(json.dumps([{"desc": d["desc"] + "#" + c, "range": d["range"]} for d, c in zip(descs, sums)]))
PYEOF
)"
  rm -f "$sums"

  echo "  Scanning the UTXO set (this can take several minutes)..."
  if ! node_call "$pfx" scantxoutset start "$scanobjects" > "$out" 2> "$out.err"; then
    cat "$out.err" >&2
    if grep -qi "in progress" "$out.err"; then
      echo "A scan is already running on that node. Wait or cancel it with: scantxoutset abort" >&2
    fi
    exit 1
  fi
  rm -f "$out.err"
  chmod 600 "$out"
}
