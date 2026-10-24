#!/usr/bin/env bash
# Shared functions to run commands inside a k3s pod.
# Loaded with: source lib_k3s.sh
#
# Uses read-only Kubernetes operations only (get, exec of read commands).
# It does not create, delete or restart anything.
#
# Any question can be skipped by setting the environment variable:
#   KUBECTL     kubectl command (auto-detects "kubectl", "k3s kubectl", "sudo k3s kubectl")
#   <PFX>_NS, <PFX>_TARGET, <PFX>_CONTAINER   (PFX = LND or BTC)

KUBECTL_CMD=()

ask() {
  # ask <variable> <question> [default_value]
  local __var="$1" __q="$2" __def="${3:-}" __ans
  if [[ -n "${!__var:-}" ]]; then
    return 0
  fi
  if [[ -n "$__def" ]]; then
    read -r -p "$__q [$__def]: " __ans || { echo >&2; echo "Input ended." >&2; exit 1; }
    __ans="${__ans:-$__def}"
  else
    while [[ -z "${__ans:-}" ]]; do
      read -r -p "$__q: " __ans || { echo >&2; echo "Input ended." >&2; exit 1; }
    done
  fi
  printf -v "$__var" '%s' "$__ans"
}

detect_kubectl() {
  if [[ -n "${KUBECTL:-}" ]]; then
    read -r -a KUBECTL_CMD <<< "$KUBECTL"
  else
    local candidate
    for candidate in "kubectl" "k3s kubectl" "sudo k3s kubectl"; do
      read -r -a KUBECTL_CMD <<< "$candidate"
      if command -v "${KUBECTL_CMD[0]}" > /dev/null 2>&1 \
        && "${KUBECTL_CMD[@]}" get namespaces > /dev/null 2>&1; then
        break
      fi
      KUBECTL_CMD=()
    done
  fi
  if [[ ${#KUBECTL_CMD[@]} -eq 0 ]] || ! "${KUBECTL_CMD[@]}" get namespaces > /dev/null 2>&1; then
    echo "Could not talk to the cluster. Try KUBECTL=\"sudo k3s kubectl\"" >&2
    echo "or export KUBECONFIG=/etc/rancher/k3s/k3s.yaml." >&2
    exit 1
  fi
  echo "Using: ${KUBECTL_CMD[*]}"
}

kc() {
  "${KUBECTL_CMD[@]}" "$@"
}

# k3s_pick <PFX> <binary> <name_hint>
# Asks for the namespace, workload/pod and container; leaves the exec prefix
# in the global array <PFX>_EXEC, ready for: "${LND_EXEC[@]}" lncli getinfo
k3s_pick() {
  local pfx="$1" bin="$2" hint="$3"
  local ns_var="${pfx}_NS" target_var="${pfx}_TARGET" ctr_var="${pfx}_CONTAINER"

  [[ ${#KUBECTL_CMD[@]} -gt 0 ]] || detect_kubectl

  echo
  echo "== Pod selection with $bin =="

  local guess_ns
  guess_ns="$(kc get pods -A --no-headers 2>/dev/null | awk -v h="$hint" '$2 ~ h {print $1; exit}')"
  if [[ -z "${!ns_var:-}" ]]; then
    echo "Namespaces:"
    kc get namespaces --no-headers | awk '{print "  " $1}'
  fi
  ask "$ns_var" "Namespace" "$guess_ns"
  local ns="${!ns_var}"

  local guess_target
  guess_target="$(kc -n "$ns" get pods --no-headers 2>/dev/null | awk -v h="$hint" '$1 ~ h && $3 == "Running" {print $1; exit}')"
  if [[ -z "${!target_var:-}" ]]; then
    echo "Workloads in $ns:"
    kc -n "$ns" get deployments,statefulsets --no-headers 2>/dev/null | awk '{print "  " $1}' || true
    echo "Pods in $ns:"
    kc -n "$ns" get pods --no-headers | awk '{print "  " $1 "  (" $3 ")"}'
    echo "You can type a pod, deploy/<name> or statefulset/<name>."
  fi
  ask "$target_var" "Pod or workload" "$guess_target"
  local target="${!target_var}"

  # For deploy/ or statefulset/, resolve a concrete pod just to list containers.
  local pod="$target"
  if [[ "$target" == */* ]]; then
    local selector
    selector="$(kc -n "$ns" get "$target" -o jsonpath='{.spec.selector.matchLabels}' \
      | python3 -c 'import json,sys; print(",".join(f"{k}={v}" for k,v in json.load(sys.stdin).items()))')"
    pod="$(kc -n "$ns" get pods -l "$selector" --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}')"
    if [[ -z "$pod" ]]; then
      echo "Could not find a Running pod for $target." >&2
      exit 1
    fi
    echo "  $target -> pod $pod"
  fi

  local containers guess_ctr
  containers="$(kc -n "$ns" get pod "$pod" -o jsonpath='{.spec.containers[*].name}')"
  if [[ "$(wc -w <<< "$containers")" -eq 1 ]]; then
    printf -v "$ctr_var" '%s' "$containers"
  else
    guess_ctr="$(tr ' ' '\n' <<< "$containers" | awk -v h="$hint" '$0 ~ h {print; exit}')"
    [[ -z "${!ctr_var:-}" ]] && echo "Containers in the pod: $containers"
    ask "$ctr_var" "Container" "${guess_ctr:-${containers%% *}}"
  fi
  local ctr="${!ctr_var}"
  echo "  container: $ctr"

  local -n exec_ref="${pfx}_EXEC"
  exec_ref=("${KUBECTL_CMD[@]}" -n "$ns" exec "$target" -c "$ctr" --)

  if ! "${exec_ref[@]}" sh -c "command -v $bin" > /dev/null 2>&1; then
    echo "Container '$ctr' does not have '$bin' in PATH." >&2
    exit 1
  fi
  echo "  $bin found in the container."
}

# k3s_file_exists <PFX> <path>: checks that a path is readable inside the container.
k3s_file_exists() {
  local -n exec_ref="${1}_EXEC"
  "${exec_ref[@]}" test -r "$2"
}
