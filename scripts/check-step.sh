#!/bin/sh
# Compact successful offline checks; preserve the complete log on failure.
set -eu

label=$1
shift
if [ "${CHECK_DRY_RUN:-0}" = 1 ]; then
    exec "$@"
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if "$@" >"$log" 2>&1; then
    # Warnings remain visible even when the command exits successfully.
    if awk '/WARNING|[[:alnum:]]*Warning:/ {found=1} END {exit !found}' "$log"; then
        cat "$log" >&2
    fi
    count=$(sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' "$log")
    printf '%-20s PASS' "$label"
    if [ -n "$count" ]; then
        printf ' (%s tests)' "$count"
    fi
    printf '\n'
else
    status=$?
    printf '%-20s FAIL\n' "$label" >&2
    cat "$log" >&2
    exit "$status"
fi
