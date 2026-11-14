#!/bin/bash

set -u
KUBECTL="microk8s kubectl"
NS=dvwa
DRY=${DRY:-0}
EVIDENCE=/var/lib/soc-responder/evidence
pod=$1 
port=$2 
inc=$3

log() { 
	echo "$(date -Is) [mount] $*" 
}

run() { 
	if [ "$DRY" = 1 ]; then 
		echo "DRY: $*" 
	else "$@" 
	fi 
}

pod_ip=$($KUBECTL get pod "$pod" -n $NS -o jsonpath='{.status.podIP}' 2>/dev/null)
if [[ ! $pod_ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
  log "incident $inc: cannot resolve IP of pod $pod"
  exit 1
fi

log "incident $inc: quarantine $pod ($pod_ip)"
run $KUBECTL label pod "$pod" -n $NS quarantine=true --overwrite

for f in $(grep -rlF "$pod_ip" /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null); do
  grep -qF "$port" "$f" || continue
  log "incident $inc: removing cron entries for $pod_ip from $f"
  run mkdir -p "$EVIDENCE/$inc"
  run cp -p "$f" "$EVIDENCE/$inc/"
  run sed -i "\|${pod_ip//./\\.}|d" "$f"
done

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
