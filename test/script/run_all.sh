#!/bin/sh
# Run every test/script/<feature>/run.sh against an opensips binary.
# Usage: run_all.sh [path-to-opensips-binary]
DIR="$(dirname "$0")"
BIN="${1:-./opensips}"
fail=0

for t in "$DIR"/*/run.sh; do
	echo "=== $t"
	sh "$t" "$BIN" || fail=1
done

exit $fail
