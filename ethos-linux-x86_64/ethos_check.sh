#!/usr/bin/env bash

cat $@ | grep WARNING
CHECK=$(cat $@ | grep "step\|assume")
[ -z "$CHECK" ] && echo "; WARNING: Empty proof"

../ethos-linux-x86_64/ethos $@
