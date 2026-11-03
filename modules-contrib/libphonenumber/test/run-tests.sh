#!/usr/bin/env bash
#
# libphonenumber module - functional test bundle runner
#
# Usage (from the OpenSIPS source tree root, after building the module):
#   make modules=modules-contrib/libphonenumber modules-contrib
#   modules-contrib/libphonenumber/test/run-tests.sh
#
# Environment:
#   OPENSIPS  - opensips binary to use (default: ./opensips)
#   MPATH     - directory holding libphonenumber.so
#               (default: the directory of this bundle's module)
#   PORT      - UDP port to bind on 127.0.0.1 (default: 15060)
#   TIMEOUT   - seconds to wait for the tests to complete (default: 30)
#   VERBOSE   - set to 1 to print the full OpenSIPS log
#

set -u

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OPENSIPS=${OPENSIPS:-./opensips}
MPATH=${MPATH:-$(dirname "$TEST_DIR")}
PORT=${PORT:-15060}

TIMEOUT=${TIMEOUT:-30}
VERBOSE=${VERBOSE:-0}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

failures=0

fail() {
	echo "FAIL: $*"
	failures=$((failures + 1))
}

pass() {
	echo "PASS: $*"
}

if [ ! -x "$OPENSIPS" ]; then
	echo "opensips binary not found at '$OPENSIPS' (set OPENSIPS=...)" >&2
	exit 2
fi
if [ ! -f "$MPATH/libphonenumber.so" ]; then
	echo "libphonenumber.so not found in '$MPATH' (set MPATH=...)" >&2
	exit 2
fi

# render_cfg <template> <output> [extra sed expressions...]
render_cfg() {
	local in=$1 out=$2
	shift 2
	sed -e "s|@MPATH@|$MPATH/|g" -e "s|@PORT@|$PORT|g" "$@" "$in" > "$out"
}

# run_startup <cfg> <log>: runs OpenSIPS in the foreground until the test
# summary line is logged (or it exits / times out), then stops it
run_startup() {
	local cfg=$1 log=$2 pid i
	"$OPENSIPS" -F -f "$cfg" -w "$WORK" > "$log" 2>&1 &
	pid=$!
	for ((i = 0; i < TIMEOUT * 10; i++)); do
		grep -q "LIBPHONENUMBER TESTS DONE" "$log" && break
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	kill -TERM "$pid" 2>/dev/null
	wait "$pid" 2>/dev/null
	return 0
}

# expect_startup_failure <name> <cfg> <log message>: module parameters and
# function parameters are only validated during a real startup ("-c" skips
# the module initialization), so OpenSIPS is started and must refuse to run
expect_startup_failure() {
	local name=$1 cfg=$2 msg=$3 log="$WORK/$1.log" pid i
	"$OPENSIPS" -F -f "$cfg" -w "$WORK" > "$log" 2>&1 &
	pid=$!
	for ((i = 0; i < TIMEOUT * 10; i++)); do
		kill -0 "$pid" 2>/dev/null || break
		sleep 0.1
	done
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
		fail "$name: OpenSIPS accepted an invalid configuration"
		return
	fi
	wait "$pid" 2>/dev/null
	if ! grep -q -- "$msg" "$log"; then
		fail "$name: expected error '$msg' not found"
		cat "$log"
	else
		pass "$name"
	fi
}

echo "== libphonenumber functional tests"
render_cfg "$TEST_DIR/libphonenumber.cfg" "$WORK/test.cfg"
run_startup "$WORK/test.cfg" "$WORK/test.log"
[ "$VERBOSE" = 1 ] && cat "$WORK/test.log"

grep -o '\[FAIL\].*' "$WORK/test.log"
summary=$(grep -o 'LIBPHONENUMBER TESTS DONE: .*' "$WORK/test.log")
if [ -z "$summary" ]; then
	fail "functional tests did not complete"
	cat "$WORK/test.log"
else
	echo "$summary"
	passed=$(sed -n 's/.*passed=\([0-9]*\).*/\1/p' <<< "$summary")
	failed=$(sed -n 's/.*failed=\([0-9]*\).*/\1/p' <<< "$summary")
	if [ "$failed" != 0 ] || [ "$passed" = 0 ]; then
		fail "functional tests: $failed failed"
	else
		pass "functional tests: $passed checks"
	fi
fi
if grep -q 'libphonenumber: ' "$WORK/test.log" && [ "$VERBOSE" = 1 ]; then
	echo "note: libphonenumber emitted warnings (see log above)"
fi

echo "== configuration checks"
render_cfg "$TEST_DIR/libphonenumber.cfg" "$WORK/bad_region.cfg" \
	-e 's|"default_region", "GB"|"default_region", "XY"|'
expect_startup_failure bad_default_region "$WORK/bad_region.cfg" \
	"invalid default_region <XY>"

cat > "$WORK/ro_var.cfg" <<EOF
stderror_enabled = yes
syslog_enabled = no
socket = udp:127.0.0.1:$PORT
mpath = "$MPATH/"
loadmodule "proto_udp.so"
loadmodule "libphonenumber.so"
route {
	pn_format("+16502530000", "E164", \$ci);
}
EOF
expect_startup_failure readonly_output_var "$WORK/ro_var.cfg" \
	"output parameter must be a writable variable"

cat > "$WORK/missing_param.cfg" <<EOF
stderror_enabled = yes
syslog_enabled = no
socket = udp:127.0.0.1:$PORT
mpath = "$MPATH/"
loadmodule "proto_udp.so"
loadmodule "libphonenumber.so"
route {
	pn_format("+16502530000", \$var(out));
}
EOF
expect_startup_failure missing_mandatory_param "$WORK/missing_param.cfg" \
	"too few parameters for command <pn_format>"

echo
if [ "$failures" -ne 0 ]; then
	echo "RESULT: $failures failure(s)"
	exit 1
fi
echo "RESULT: all tests passed"
exit 0
