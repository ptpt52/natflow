#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
qos_test_tmp=$(mktemp -d /tmp/natflow-qos-test.XXXXXX)
# Compile the production reservation code with mocked time and bucket locks.
python3 - "$repo_dir" "$qos_test_tmp" <<'PY'
from pathlib import Path
import sys
repo, out = map(Path, sys.argv[1:])
header = '\n'.join(line for line in (repo / 'natflow_qos.h').read_text().splitlines()
                   if not line.startswith('#include '))
user_header = (repo / 'natflow_user.h').read_text()
start = user_header.index('struct token_ctrl {')
bucket = user_header[start:user_header.index('};', start) + 2]
source = (repo / 'natflow_user.c').read_text()
start = source.index('static int natflow_token_schedule(')
end = source.index('\n}\n', start) + 3
(out / 'production.h').write_text(header + '\n' + bucket + '\n' + source[start:end])
PY
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -pthread -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-I"$qos_test_tmp" "$repo_dir/tests/qos/schedule.c" \
	-o "$qos_test_tmp/schedule-test"
"$qos_test_tmp/schedule-test"
printf 'Test binary: %s/schedule-test\n' "$qos_test_tmp"
