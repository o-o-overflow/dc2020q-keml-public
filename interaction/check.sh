#!/bin/bash -e

exit 0

# TODO:

RESULT=$(echo "ls -1 /\nexit\n" | nc "$1" "$2")

echo "---------" >/dev/stderr
echo "$RESULT" >/dev/stderr
echo "----------" >/dev/stderr

echo "$RESULT" | grep -i "seconds"
echo "$RESULT" | grep "etc"
echo "$RESULT" | grep "root"
