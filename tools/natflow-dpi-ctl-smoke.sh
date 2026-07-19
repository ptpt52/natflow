#!/bin/sh

set -eu

CTL=${NATFLOW_DPI_CTL:-/dev/natflow_dpi_ctl}
original_enable=
temporary_rules=0

usage()
{
	cat <<EOF
Usage: NATFLOW_DPI_CTL=/dev/natflow_dpi_ctl $0

Runs a destructive DPI control transaction smoke test. The current ruleset
must be empty. The script restores the original enable state before exit.
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
	write_cmd rules_abort 2>/dev/null
	if [ "$temporary_rules" = 1 ]; then
		write_cmd rules_clear 2>/dev/null
	fi
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
expect_field rules 0
expect_field txn_active 0

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if write_cmd __natflow_invalid_command__ 2>/dev/null; then
	fail "unknown command unexpectedly succeeded"
fi

write_cmd rules_begin
expect_field txn_active 1
write_cmd rules_abort
expect_field txn_active 0

write_cmd enable=0
write_cmd events_clear
generation_before=$(field generation) || fail "missing generation"

write_cmd rules_begin
temporary_rules=1
write_cmd "domain id=900001 app=900001 kind=exact host=natflow-smoke.invalid"
write_cmd "proto id=900002 app=900002 proto=ssh"
write_cmd rules_commit

generation_after=$(field generation) || fail "missing generation after commit"
[ "$generation_after" -gt "$generation_before" ] ||
	fail "generation did not increase after commit"
expect_field rules 2
expect_field domain_rules 1
expect_field proto_rules 1
expect_field txn_active 0

write_cmd rules_clear
temporary_rules=0
expect_field rules 0
expect_field domain_rules 0
expect_field proto_rules 0
expect_field txn_active 0

write_cmd "enable=$original_enable"
printf 'PASS: DPI control transaction smoke test\n'
