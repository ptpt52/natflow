#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MAKE=${MAKE:-make}

cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	"$MAKE" -C "$REPO_DIR" clean >/dev/null || true
	exit "$status"
}

run_case()
{
	name=$1
	shift

	printf '\n==> build: %s\n' "$name"
	"$MAKE" -C "$REPO_DIR" clean
	"$MAKE" -C "$REPO_DIR" "$@"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_case base
run_case urllogger \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_URLLOGGER"
run_case dpi \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_DPI"
run_case path-dpi \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_DPI"
run_case urllogger-dpi \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_URLLOGGER -DCONFIG_NATFLOW_DPI"
run_case full \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER -DCONFIG_NATFLOW_DPI"
run_case full-no-debug \
	NO_DEBUG=1 \
	"EXTRA_CFLAGS=-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER -DCONFIG_NATFLOW_DPI"

printf '\nAll build matrix cases passed.\n'
