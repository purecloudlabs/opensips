#!/bin/sh
# Tests for the xlog() per-call format override.
#  1. parse: the config parser accepts valid format names and rejects others
#  2. runtime: with each configured stderr format, xlog() without a format
#     follows the configured one and xlog() with a format overrides it
# Usage: run.sh [path-to-opensips-binary]
DIR="$(dirname "$0")"
. "$DIR/../lib.sh"
script_init "$@"

# ---- 1. parse ---------------------------------------------------------------

xlog_fmt() { # <accept|reject> <format arg>
	check_parse "$1" "xlog format '$2'" "route { xlog(\"L_ERR\", \"msg\\n\", \"$2\"); }"
}

xlog_fmt accept plain_text
xlog_fmt accept json
xlog_fmt accept json_cee
xlog_fmt reject bogus
xlog_fmt reject JSON
xlog_fmt reject plain
xlog_fmt reject json-cee
xlog_fmt reject ""

check_parse accept "no format arg, pseudo-variable message" \
	'route { xlog("L_ERR", "msg $rU\n"); xlog("L_ERR", "msg $rU\n", "json"); }'

# ---- 2. runtime -------------------------------------------------------------

is_plain() { grep -F "$1" "$2" | grep -v '^{' | grep -qF "$1"; }
is_json()  { grep -F "$1" "$2" | grep '^{' | grep -qF '"message": "'; }
is_cee()   { grep -F "$1" "$2" | grep '^{' | grep -qF '"msg": "'; }

for configured in plain_text json json_cee; do
	cfg="$TMP/$configured.cfg"
	out="$TMP/$configured.out"
	{ echo "$CFG_PRELUDE"; echo "stderror_log_format = \"$configured\""; cat "$DIR/xlog-test.cfg"; } > "$cfg"
	run_for 5 "$cfg" "$out"

	# no format argument: follows the configured format
	case "$configured" in
	plain_text) is_plain MARK_DEFAULT "$out" ;;
	json)       is_json  MARK_DEFAULT "$out" ;;
	json_cee)   is_cee   MARK_DEFAULT "$out" ;;
	esac
	result "runtime: configured=$configured, no override -> $configured" $?

	# explicit format argument: wins over the configured format
	is_plain MARK_PLAIN "$out"
	result "runtime: configured=$configured, override plain_text" $?
	is_json MARK_JSON "$out"
	result "runtime: configured=$configured, override json" $?
	is_cee MARK_CEE "$out"
	result "runtime: configured=$configured, override json_cee" $?

	if [ $fail -ne 0 ]; then
		echo "--- output for configured=$configured:"
		cat "$out"
	fi
done

finish
