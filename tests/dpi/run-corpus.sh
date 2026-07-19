#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CTL=${NATFLOW_DPI_CTL:-/dev/natflow_dpi_ctl}
QUEUE=${NATFLOW_DPI_QUEUE:-/dev/natflow_dpi_queue}
CC=${CC:-cc}
CLIENT_IP=198.18.0.2
SERVER_IP=198.19.0.2
CLIENT_GW=198.18.0.1
SERVER_GW=198.19.0.1
CLIENT_NS=ndpc$$
SERVER_NS=ndps$$
CLIENT_IF=ndci$$
CLIENT_PEER=ndcp$$
SERVER_IF=ndsi$$
SERVER_PEER=ndsp$$
TMP_DIR=${TMPDIR:-/tmp}/natflow-dpi-corpus.$$
ASSERT_BIN=$TMP_DIR/natflow-dpi-corpus
TRAFFIC_BIN=$TMP_DIR/natflow-dpi-traffic
original_enable=
original_forward=
rules_installed=0
topology_installed=0
firewall_installed=0

usage()
{
	cat <<EOF
Usage: $0 case-file [case-file ...]
       $0 --check case-file [case-file ...]

Case format, one pipe-separated record per line:
  name|proto|transport|direction|port|payload_hex|expectation

Blank lines and lines beginning with # are ignored. This destructive test
requires an empty DPI ruleset and root privileges.
EOF
}

fail()
{
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

need_command()
{
	command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

field()
{
	awk -F= -v key="$1" '$1 == key { print $2; found = 1; exit }
		END { if (!found) exit 1 }' "$CTL"
}

write_ctl()
{
	printf '%s\n' "$1" >"$CTL"
}

cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	set +e
	write_ctl rules_abort 2>/dev/null
	if [ "$rules_installed" = 1 ]; then
		write_ctl rules_clear 2>/dev/null
	fi
	if [ -n "$original_enable" ]; then
		write_ctl "enable=$original_enable" 2>/dev/null
	fi
	if [ "$firewall_installed" = 1 ]; then
		iptables -D FORWARD -i "$CLIENT_IF" -o "$SERVER_IF" -j ACCEPT 2>/dev/null
		iptables -D FORWARD -i "$SERVER_IF" -o "$CLIENT_IF" -j ACCEPT 2>/dev/null
	fi
	if [ "$topology_installed" = 1 ]; then
		ip netns del "$CLIENT_NS" 2>/dev/null
		ip netns del "$SERVER_NS" 2>/dev/null
		if [ -n "$original_forward" ]; then
			printf '%s\n' "$original_forward" >/proc/sys/net/ipv4/ip_forward 2>/dev/null
		fi
	fi
	rm -rf "$TMP_DIR"
	exit "$status"
}

proto_values()
{
	case $1 in
	dns) printf '%s\n' '4 7101 6101' ;;
	ssh) printf '%s\n' '5 7102 6102' ;;
	wireguard) printf '%s\n' '6 7103 6103' ;;
	stun) printf '%s\n' '7 7104 6104' ;;
	turn) printf '%s\n' '8 7105 6105' ;;
	bittorrent) printf '%s\n' '9 7106 6106' ;;
	*) return 1 ;;
	esac
}

validate_case()
{
	case_file=$1
	name=$2
	proto=$3
	l4=$4
	direction=$5
	port=$6
	payload=$7
	expectation=$8
	extra=$9

	[ -n "$name" ] || fail "$case_file: empty case name"
	[ -z "$extra" ] || fail "$case_file: malformed case: $name"
	values=$(proto_values "$proto") ||
		fail "$case_file: unknown protocol in $name"
	set -- $values
	source_id=$1
	app_id=$2
	rule_id=$3
	case $l4 in tcp|udp) ;; *) fail "$case_file: invalid L4 in $name" ;; esac
	case $proto:$l4 in
	ssh:udp|wireguard:tcp) fail "$case_file: invalid protocol/L4 pair in $name" ;;
	esac
	case $direction in original|reply) ;; *) fail "$case_file: invalid direction in $name" ;; esac
	case $port in ""|*[!0-9]*) fail "$case_file: invalid port in $name" ;; esac
	[ "$port" -gt 0 ] && [ "$port" -le 65535 ] ||
		fail "$case_file: port out of range in $name"
	case $payload in ""|*[!0-9a-fA-F]*) fail "$case_file: invalid payload hex in $name" ;; esac
	[ $((${#payload} % 2)) -eq 0 ] ||
		fail "$case_file: odd payload hex length in $name"
	case $expectation in
	positive) negative= ;;
	negative) negative=-N ;;
	*) fail "$case_file: invalid expectation in $name" ;;
	esac
}

check_case_files()
{
	check_count=0
	for case_file in "$@"; do
		[ -r "$case_file" ] || fail "cannot read case file: $case_file"
		while IFS='|' read -r name proto l4 direction port payload expectation extra; do
			case $name in
			""|'#'*) continue ;;
			esac
			validate_case "$case_file" "$name" "$proto" "$l4" \
				"$direction" "$port" "$payload" "$expectation" "$extra"
			check_count=$((check_count + 1))
		done <"$case_file"
	done
	[ "$check_count" -gt 0 ] || fail "no corpus cases were loaded"
	printf 'PASS: checked %u DPI corpus case(s)\n' "$check_count"
}

wait_ready()
{
	ready_file=$1
	count=0
	while [ ! -e "$ready_file" ]; do
		count=$((count + 1))
		[ "$count" -le 100 ] || return 1
		sleep 0.02
	done
}

inject_case()
{
	l4=$1
	direction=$2
	port=$3
	payload=$4
	ready_file=$TMP_DIR/ready.$$

	rm -f "$ready_file"
	ip netns exec "$SERVER_NS" "$TRAFFIC_BIN" server "$l4" \
		"$SERVER_IP" "$port" "$direction" "$payload" "$ready_file" &
	server_pid=$!
	if ! wait_ready "$ready_file"; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
		fail "traffic server did not become ready"
	fi
	if ! ip netns exec "$CLIENT_NS" "$TRAFFIC_BIN" client "$l4" \
		"$SERVER_IP" "$port" "$direction" "$payload"; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
		fail "traffic client failed"
	fi
	wait "$server_pid" || fail "traffic server failed"
}

if [ "${1:-}" = __inject ]; then
	shift
	[ "$#" -eq 8 ] || fail "invalid internal injector arguments"
	CLIENT_NS=$1
	SERVER_NS=$2
	TRAFFIC_BIN=$3
	TMP_DIR=$4
	shift 4
	inject_case "$@"
	exit 0
fi

case ${1:-} in
-h|--help)
	usage
	exit 0
	;;
"")
	usage >&2
	exit 2
	;;
esac

if [ "$1" = --check ]; then
	shift
	[ "$#" -gt 0 ] || fail "no case files supplied"
	check_case_files "$@"
	exit 0
fi

[ "$(id -u)" = 0 ] || fail "root privileges are required"
[ -r "$CTL" ] && [ -w "$CTL" ] || fail "$CTL is not readable and writable"
[ -r "$QUEUE" ] && [ -w "$QUEUE" ] || fail "$QUEUE is not readable and writable"
need_command awk
need_command ip
need_command iptables
need_command "$CC"

original_enable=$(field enable) || fail "missing DPI enable field"
[ "$original_enable" = 0 ] || [ "$original_enable" = 1 ] ||
	fail "invalid DPI enable field: $original_enable"
[ "$(field rules)" = 0 ] || fail "DPI ruleset must be empty"
[ "$(field txn_active)" = 0 ] || fail "DPI transaction is already active"
original_forward=$(cat /proc/sys/net/ipv4/ip_forward)

mkdir "$TMP_DIR" || fail "temporary directory already exists: $TMP_DIR"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$ASSERT_BIN" "$REPO_DIR/tools/natflow-dpi-corpus.c"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$TRAFFIC_BIN" "$REPO_DIR/tools/natflow-dpi-traffic.c"

ip netns add "$CLIENT_NS"
topology_installed=1
ip netns add "$SERVER_NS"
ip link add "$CLIENT_IF" type veth peer name "$CLIENT_PEER"
ip link set "$CLIENT_PEER" netns "$CLIENT_NS"
ip link add "$SERVER_IF" type veth peer name "$SERVER_PEER"
ip link set "$SERVER_PEER" netns "$SERVER_NS"
ip address add "$CLIENT_GW/24" dev "$CLIENT_IF"
ip address add "$SERVER_GW/24" dev "$SERVER_IF"
ip link set "$CLIENT_IF" up
ip link set "$SERVER_IF" up
ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" address add "$CLIENT_IP/24" dev "$CLIENT_PEER"
ip -n "$CLIENT_NS" link set "$CLIENT_PEER" up
ip -n "$CLIENT_NS" route add default via "$CLIENT_GW"
ip -n "$SERVER_NS" link set lo up
ip -n "$SERVER_NS" address add "$SERVER_IP/24" dev "$SERVER_PEER"
ip -n "$SERVER_NS" link set "$SERVER_PEER" up
ip -n "$SERVER_NS" route add default via "$SERVER_GW"
printf '1\n' >/proc/sys/net/ipv4/ip_forward
iptables -I FORWARD -i "$CLIENT_IF" -o "$SERVER_IF" -j ACCEPT
firewall_installed=1
iptables -I FORWARD -i "$SERVER_IF" -o "$CLIENT_IF" -j ACCEPT

write_ctl enable=0
write_ctl events_clear
write_ctl rules_begin
rules_installed=1
write_ctl "proto id=6101 app=7101 proto=dns"
write_ctl "proto id=6102 app=7102 proto=ssh"
write_ctl "proto id=6103 app=7103 proto=wireguard"
write_ctl "proto id=6104 app=7104 proto=stun"
write_ctl "proto id=6105 app=7105 proto=turn"
write_ctl "proto id=6106 app=7106 proto=bittorrent"
write_ctl rules_commit
write_ctl enable=1

case_count=0
for case_file in "$@"; do
	[ -r "$case_file" ] || fail "cannot read case file: $case_file"
	while IFS='|' read -r name proto l4 direction port payload expectation extra; do
		case $name in
		""|'#'*) continue ;;
		esac
		validate_case "$case_file" "$name" "$proto" "$l4" \
			"$direction" "$port" "$payload" "$expectation" "$extra"

		printf 'CASE: %s\n' "$name"
		"$ASSERT_BIN" -d "$QUEUE" -S "$CLIENT_IP" -T "$SERVER_IP" \
			-P "$l4" -p "$port" -s "$source_id" -D "$direction" \
			-a "$app_id" -r "$rule_id" $negative -- \
			"$0" __inject "$CLIENT_NS" "$SERVER_NS" "$TRAFFIC_BIN" \
			"$TMP_DIR" "$l4" "$direction" "$port" "$payload"
		case_count=$((case_count + 1))
	done <"$case_file"
done

[ "$case_count" -gt 0 ] || fail "no corpus cases were loaded"
printf 'PASS: %u DPI corpus case(s)\n' "$case_count"
