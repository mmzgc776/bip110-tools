#!/usr/bin/env bash
# Access to lncli no matter where LND runs. Requires lib_k3s.sh loaded.
#
#   lnd_setup        asks where LND runs and which macaroon to use
#   lnd_call ARGS    used like lncli (read-only commands only)
#
# Locations:
#   k3s    cluster pod (asks for namespace/pod/container)
#   local  lncli on this machine (variable LNCLI, default lncli)
#   ssh    lncli on another machine over SSH
#
# Variables to skip the questions:
#   LND_WHERE, LND_MACAROON, LND_EXTRA_ARGS, LND_SSH, LNCLI,
#   LND_NS, LND_TARGET, LND_CONTAINER (k3s)

lnd_setup() {
  echo
  echo "Where does LND run?"
  echo "  k3s    inside a cluster pod"
  echo "  local  on this machine"
  echo "  ssh    on another machine reachable over SSH"
  ask LND_WHERE "LND location (k3s/local/ssh)" "k3s"

  local mac_default="/root/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon"
  case "$LND_WHERE" in
    k3s)
      k3s_pick LND lncli lnd
      ask LND_MACAROON "Macaroon path INSIDE the container (use readonly)" "$mac_default"
      ;;
    local)
      LNCLI="${LNCLI:-lncli}"
      ask LND_MACAROON "Macaroon path on this machine (use readonly)" \
        "$HOME/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon"
      ;;
    ssh)
      ask LND_SSH "LND SSH host (user@host or a ~/.ssh/config alias)"
      ask LND_MACAROON "Macaroon path on THAT machine (use readonly)" \
        "~/.lnd/data/chain/bitcoin/mainnet/readonly.macaroon"
      ;;
    *)
      echo "LND location must be k3s, local or ssh." >&2
      exit 2
      ;;
  esac

  ask LND_EXTRA_ARGS "Extra lncli arguments (e.g. --rpcserver=localhost:10009, empty: -)" "-"
  [[ "$LND_EXTRA_ARGS" == "-" ]] && LND_EXTRA_ARGS=""
  LND_EXTRA=()
  [[ -n "$LND_EXTRA_ARGS" ]] && read -r -a LND_EXTRA <<< "$LND_EXTRA_ARGS"

  [[ "$LND_MACAROON" == *readonly.macaroon ]] \
    || echo "  WARNING: not readonly.macaroon; these commands only read, but prefer a read-only one."

  if ! lnd_call getinfo > /dev/null; then
    echo "Could not query LND. Check the location, the macaroon and the arguments." >&2
    echo "To find the macaroon: find / -name '*.macaroon' 2>/dev/null (where LND runs)" >&2
    exit 1
  fi
  echo "  LND connection OK."
}

lnd_call() {
  case "$LND_WHERE" in
    k3s)
      "${LND_EXEC[@]}" lncli --macaroonpath="$LND_MACAROON" "${LND_EXTRA[@]}" "$@"
      ;;
    local)
      local cmd
      read -r -a cmd <<< "$LNCLI"
      "${cmd[@]}" --macaroonpath="$LND_MACAROON" "${LND_EXTRA[@]}" "$@"
      ;;
    ssh)
      # The macaroon path is left unescaped so the remote shell expands "~".
      local line
      line="lncli --macaroonpath=$LND_MACAROON $(printf '%q ' "${LND_EXTRA[@]}" "$@")"
      ssh -o BatchMode=yes "$LND_SSH" "$line" < /dev/null
      ;;
  esac
}
