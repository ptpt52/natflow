#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
qos_test_tmp=$(mktemp -d /tmp/natflow-qos-test.XXXXXX)
# Compile production reservation and queue code with kernel primitive models.
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
queue = '\n'.join(line for line in (repo / 'natflow_qos.c').read_text().splitlines()
                  if not line.startswith('#include '))
(out / 'production-queue.h').write_text(header + '\n' + queue)
PY
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -pthread -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-I"$qos_test_tmp" "$repo_dir/tests/qos/schedule.c" \
	-o "$qos_test_tmp/schedule-test"
"$qos_test_tmp/schedule-test"
printf 'Test binary: %s/schedule-test\n' "$qos_test_tmp"
${CC:-cc} -std=gnu11 -Wall -Wextra -Werror -pthread -g \
	-fsanitize=address,undefined -fno-omit-frame-pointer \
	-I"$qos_test_tmp" "$repo_dir/tests/qos/cpu-affinity.c" \
	-o "$qos_test_tmp/cpu-affinity-test"
timeout 30 "$qos_test_tmp/cpu-affinity-test"
printf 'Test binary: %s/cpu-affinity-test\n' "$qos_test_tmp"
