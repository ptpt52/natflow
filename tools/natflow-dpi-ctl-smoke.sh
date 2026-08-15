#!/bin/sh

set -eu

CTL=${NATFLOW_DPI_CTL:-/dev/natflow_dpi_ctl}
original_enable=

usage()
{
	cat <<EOF
Usage: NATFLOW_DPI_CTL=/dev/natflow_dpi_ctl $0

Runs a destructive DPI static-control smoke test. The script clears event
counters and restores the original enable state before exit.
EOF
}

fail()
{
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

write_cmd()
{
	printf '%s\n' "$1" >"$CTL"
}

field()
{
	awk -F= -v key="$1" '$1 == key { print $2; found = 1; exit }
		END { if (!found) exit 1 }' "$CTL"
}

expect_field()
{
	key=$1
	expected=$2
	actual=$(field "$key") || fail "missing control field: $key"
	[ "$actual" = "$expected" ] ||
		fail "$key expected $expected, got $actual"
}

cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	set +e
	if [ -n "$original_enable" ]; then
		write_cmd "enable=$original_enable" 2>/dev/null
	fi
	exit "$status"
}

case ${1:-} in
-h|--help)
	usage
	exit 0
	;;
"")
	;;
*)
	usage >&2
	exit 2
	;;
esac

[ -r "$CTL" ] || fail "$CTL is not readable"
[ -w "$CTL" ] || fail "$CTL is not writable"

original_enable=$(field enable) || fail "missing control field: enable"
[ "$original_enable" = 0 ] || [ "$original_enable" = 1 ] ||
	fail "invalid enable state: $original_enable"
expect_field catalog_revision 2
expect_field catalog_apps 27

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for removed_command in \
	"rules_begin" \
	"domain id=900001 app=900001 kind=exact host=natflow-smoke.invalid" \
	"proto id=900002 app=900002 proto=ssh" \
	"rules_commit" \
	"rules_abort" \
	"rules_clear" \
	"__natflow_invalid_command__"; do
	if write_cmd "$removed_command" 2>/dev/null; then
		fail "removed or unknown command unexpectedly succeeded: $removed_command"
	fi
done

write_cmd enable=0
expect_field enable 0
write_cmd enable=1
expect_field enable 1
write_cmd events_clear

write_cmd "enable=$original_enable"
printf 'PASS: DPI static control smoke test\n'
