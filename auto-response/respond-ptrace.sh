#!/bin/bash

set -u
KUBECTL="microk8s kubectl"
NS=dvwa
DRY=${DRY:-0}
pod=$1; port=$2; inc=$3

log() { echo "$(date -Is) [ptrace] $*"; }
run() { if [ "$DRY" = 1 ]; then echo "DRY: $*"; else "$@"; fi; }

log "incident $inc: quarantine $pod, port $port"
run $KUBECTL label pod "$pod" -n $NS quarantine=true --overwrite

pids=$(ss -H -tlnp "sport = :$port" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
[ -z "$pids" ] && log "incident $inc: nothing is listening on port $port"
for pid in $pids; do
  [ "$pid" -gt 1 ] || continue
  log "incident $inc: killing PID $pid: $(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null)"
  run kill "$pid"; sleep 3
  [ -d "/proc/$pid" ] && run kill -9 "$pid"
done
log "incident $inc: ready"
