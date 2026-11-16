# Shared helpers for the script tests under test/script/<feature>/run.sh.
# Source it from a run.sh:
#
#     . "$(dirname "$0")/../lib.sh"
#     script_init "$@"
#     check_parse accept "my case" 'route { xlog("L_ERR", "hi\n"); }'
#     ...
#     finish
#
# Each check prints "ok" or "FAIL" and records failures; finish exits non-zero
# if any check failed.

# minimal config needed for 'opensips -c' and for short test runs; proto_udp
# is built into the core, but must still be loaded for the socket to be valid
CFG_PRELUDE='loadmodule "proto_udp.so"
socket = udp:127.0.0.1:15060'

# script_init [opensips-binary]  (default ./opensips)
script_init() {
	OPENSIPS="${1:-./opensips}"
	TMP="$(mktemp -d)"
	trap 'rm -rf "$TMP"' EXIT
	fail=0
}

# result <description> <exit status of the check>
result() {
	if [ "$2" -eq 0 ]; then
		echo "ok   $1"
	else
		echo "FAIL $1"
		fail=1
	fi
}

# check_parse_file <accept|reject> <description> <cfg file>
# 'opensips -c' must exit 0 for accept, non-zero for reject.
check_parse_file() {
	"$OPENSIPS" -c -f "$3" >"$TMP/parse.out" 2>&1
	rc=$?
	if [ "$1" = accept ]; then [ $rc -eq 0 ]; else [ $rc -ne 0 ]; fi
	ok=$?
	result "parse: $2 -> $1" $ok
	# show the parser output when the result was unexpected
	[ $ok -eq 0 ] || cat "$TMP/parse.out"
}

# check_parse <accept|reject> <description> <config body>
# Same as check_parse_file, with CFG_PRELUDE prepended to the given body.
check_parse() {
	printf '%s\n\n%s\n' "$CFG_PRELUDE" "$3" > "$TMP/parse.cfg"
	check_parse_file "$1" "$2" "$TMP/parse.cfg"
}

# run_for <seconds> <cfg file> <output file>
# Run opensips in the foreground for a few seconds, capturing stdout+stderr.
# Use with startup_route to exercise runtime behaviour without traffic.
run_for() {
	timeout "$1" "$OPENSIPS" -F -f "$2" >"$3" 2>&1
}

finish() {
	exit $fail
}
