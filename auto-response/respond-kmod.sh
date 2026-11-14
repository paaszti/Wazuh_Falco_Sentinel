#!/bin/bash

set -u
KUBECTL="microk8s kubectl"
NS=dvwa
DRY=${DRY:-0}
EVIDENCE=/var/lib/soc-responder/evidence
pod=$1 
port=$2 
inc=$3 
module_file=${4:-}

log() { echo "$(date -Is) [kmod] $*"; }
run() { if [ "$DRY" = 1 ]; then echo "DRY: $*"; else "$@"; fi; }

pod_ip=$($KUBECTL get pod "$pod" -n $NS -o jsonpath='{.status.podIP}' 2>/dev/null)
if [[ ! $pod_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  log "incident $inc: cannot resolve IP of pod $pod"
  exit 1
fi

ko_name=$(basename "$module_file")
mod=
if [[ $ko_name =~ ^[A-Za-z0-9_]{1,56}\.ko$ ]]; then
  mod=$(basename "$ko_name" .ko)
else
  log "incident $inc: invalid module file name '$module_file'"
fi

log "incident $inc: quarantine $pod ($pod_ip)"
run $KUBECTL label pod "$pod" -n $NS quarantine=true --overwrite

if [ -n "$mod" ]; then
  cid=$($KUBECTL get pod "$pod" -n $NS -o jsonpath='{.status.containerStatuses[0].containerID}' 2>/dev/null)
  cid=${cid#*://}
  cpid=
  [ -n "$cid" ] && cpid=$(grep -l "$cid" /proc/[0-9]*/cgroup 2>/dev/null | head -1 | cut -d/ -f3)
  ko=
  [ -n "$cpid" ] && ko=$(find "/proc/$cpid/root/" -xdev -maxdepth 6 -type f -name "$ko_name" 2>/dev/null | head -1)
  if [ -n "$ko" ]; then
    dir="$EVIDENCE/$inc"
    install -d -m 700 "$dir"
    cp "$ko" "$dir/$ko_name"
    chmod 400 "$dir/$ko_name"
    log "incident $inc: module file ${ko#/proc/$cpid/root} saved to $dir/$ko_name"
  else
    log "incident $inc: module file $ko_name not found in container"
  fi
fi

pids=$(ss -Htnp state established dst "$pod_ip:$port" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
if [ -z "$pids" ]; then
  log "incident $inc: no connection to $pod_ip:$port"
else
  for pid in $pids; do
    [ "$pid" -gt 1 ] || continue
    log "incident $inc: killing PID $pid ($(tr '\0' ' ' </proc/$pid/cmdline 2>/dev/null)), PPID $(ps -o ppid= -p "$pid")"
    run pkill -TERM -P "$pid"
    run kill "$pid"
  done
  sleep 3
  for pid in $pids; do
    [ -d "/proc/$pid" ] && run kill -9 "$pid"
  done
fi

if [ -z "$mod" ]; then
  log "incident $inc: module not removed (no valid name)"
elif [ ! -d "/sys/module/$mod" ]; then
  log "incident $inc: module $mod is not loaded"
elif ! grep -q O "/sys/module/$mod/taint" 2>/dev/null; then
  log "incident $inc: module $mod is not out-of-tree, refusing to remove"
else
  log "incident $inc: removing module $mod"
  run rmmod "$mod"
fi

log "incident $inc: ready"
