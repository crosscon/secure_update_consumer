#!/usr/bin/env sh

cat $@ | grep WARNING
CHECK=$(cat $@ | grep "step\|assume")
[ -z "$CHECK" ] && echo "; WARNING: Empty proof"

../ethos/ethos $@
