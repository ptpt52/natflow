#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
control_test_tmp=$(mktemp -d /tmp/natflow-control-test.XXXXXX)
# Compile the production implementation, not a separately maintained parser.
sed '/^#include /d' "$repo_dir/natflow_control.h" > "$control_test_tmp/natflow_control_test.h"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -pthread -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-I"$control_test_tmp" "$repo_dir/tests/control/input.c" \
	-o "$control_test_tmp/input-test"
"$control_test_tmp/input-test"
printf 'Test binary: %s/input-test\n' "$control_test_tmp"
