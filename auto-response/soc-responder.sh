#!/bin/bash

set -u
BASE=$(dirname "$(readlink -f "$0")")
DRY=${DRY:-0}
export DRY

log() { echo "$(date -Is) $*"; }

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
  type=$(echo "$text" | jq -r .type)
  pod=$(echo "$text" | jq -r .pod)
  node=$(echo "$text" | jq -r .node)
  port=$(echo "$text" | jq -r .port)
  inc=$(echo "$text" | jq -r .incident)
  module=$(echo "$text" | jq -r '.module // empty')

  if [[ $node =~ ^[0-9.]+$ ]]; then
    hostname -I | grep -qw -- "$node" || continue
  else
    [ "$node" = "$(hostname -s)" ] || continue
  fi

  bad=0
  script=
  [[ $pod =~ ^dvwa-[a-z0-9-]+$ ]] || bad=1
  [[ $port =~ ^[0-9]{4,5}$ ]] || bad=1
  case $port in (1338|7472|7946|9099|10248|10249|10250|10256|10257|10259|16443|19001|25000) bad=1;; esac
  case $type in
    ptrace) script=respond-ptrace.sh ;;
    mount)  script=respond-mount.sh ;;
    kmod)   script=respond-kmod.sh ;;
    *)      bad=1 ;;
  esac

  if [ "$bad" = 1 ]; then
    log "message rejected: type='$type' pod='$pod' port='$port'"
  else
    log "incident $inc: type $type, running $script"
    "$BASE/$script" "$pod" "$port" "$inc" "$module"
  fi

  curl -s -X DELETE "$QUEUE_URL/messages/$id?popreceipt=$(echo "$pop" | jq -Rr @uri)&$SAS" >/dev/null
done
