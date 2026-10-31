#!/bin/bash

set -u
KUBECTL="microk8s kubectl"
NS=dvwa
DRY=${DRY:-0}

log() {
	echo "$(date -Is) $*";
}
run() {
	if [ "$DRY" = 1 ]; then
		echo "DRY: $*"
	else
		"$@"
	fi
}

while true; do
  xml=$(curl -s "$QUEUE_URL/messages?numofmessages=1&visibilitytimeout=10&$SAS")
  id=$(echo "$xml" | sed -n 's:.*<MessageId>\(.*\)</MessageId>.*:\1:p')
  if [ -z "$id" ]; then
	  sleep 10
	  continue
  fi
  pop=$(echo "$xml" | sed -n 's:.*<PopReceipt>\(.*\)</PopReceipt>.*:\1:p')
  text=$(echo "$xml" | sed -n 's:.*<MessageText>\(.*\)</MessageText>.*:\1:p' | sed 's/&quot;/"/g')
  if [[ $text != \{* ]]; then
    text=$(echo "$text" | base64 -d 2>/dev/null)
  fi
  pod=$(echo "$text" | jq -r .pod); node=$(echo "$text" | jq -r .node)
  port=$(echo "$text" | jq -r .port); inc=$(echo "$text" | jq -r .incident)

  if [[ $node =~ ^[0-9.]+$ ]] && ! hostname -I | grep -qw -- "$node"; then
    continue
  fi

  bad=0
  [[ $pod =~ ^dvwa-[a-z0-9-]+$ ]] || bad=1
  [[ $port =~ ^[0-9]{4,5}$ ]] || bad=1
  case $port in (1338|7472|7946|9099|10248|10249|10250|10256|10257|10259|16443|19001|25000) bad=1;; esac

  if [ "$bad" = 1 ]; then
    log "message rejected: pod='$pod' port='$port'"
  else
    log "incident $inc: quarantine $pod, port $port"
    run $KUBECTL label pod "$pod" -n $NS quarantine=true --overwrite
    #run $KUBECTL delete pod "$pod" -n $NS --grace-period=1 --wait=true --timeout=40s
    pids=$(ss -H -tlnp "sport = :$port" | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
    if [ -z "$pids" ]; then
      log "nothing is listening on port $port"
    fi
    for pid in $pids; do
      [ "$pid" -gt 1 ] || continue
      log "killing PID $pid: $(tr '\0' ' ' </proc/$pid/cmdline)"
      run kill "$pid"; sleep 3
      [ -d "/proc/$pid" ] && run kill -9 "$pid"
    done
    log "incident $inc: ready"
  fi

  curl -s -X DELETE "$QUEUE_URL/messages/$id?popreceipt=$(echo "$pop" | jq -Rr @uri)&$SAS" >/dev/null
done

