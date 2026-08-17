#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CTL=${NATFLOW_DPI_CTL:-/dev/natflow_dpi_ctl}
QUEUE=${NATFLOW_DPI_QUEUE:-/dev/natflow_dpi_queue}
CC=${CC:-cc}
CLIENT_NS=ndldn$$
ROOT_IF=ndldr$$
CLIENT_IF=ndldc$$
ROOT_IP=198.18.53.1
CLIENT_IP=198.18.53.2
REDIRECT_IP=203.0.113.53
REDIRECT_PORT=53053
DIRECT_SOURCE_PORT=$((30000 + ($$ % 30000)))
REDIRECT_SOURCE_PORT=$((DIRECT_SOURCE_PORT + 1))
DNS_YOUTUBE_QUERY=1234010000010000000000000377777707796f757475626503636f6d0000010001
TMP_DIR=${TMPDIR:-/tmp}/natflow-dpi-local-dns.$$
ASSERT_BIN=$TMP_DIR/natflow-dpi-corpus
TRAFFIC_BIN=$TMP_DIR/natflow-dpi-traffic
original_enable=
topology_installed=0
input_rule_installed=0
redirect_rule_installed=0
cleanup_done=0

fail()
{
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
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

cleanup_error()
{
	printf 'CLEANUP FAIL: %s\n' "$*" >&2
	cleanup_failed=1
}

namespace_exists()
{
	printf '%s\n' "$2" |
		awk -v name="$1" '$1 == name { found = 1 }
			END { exit !found }'
}

cleanup_resources()
{
	cleanup_failed=0
	set +e

	if [ -n "$original_enable" ]; then
		if ! write_ctl "enable=$original_enable" 2>/dev/null; then
			cleanup_error "could not restore DPI enable=$original_enable"
		fi
	fi
	if [ "$redirect_rule_installed" = 1 ]; then
		if ! iptables -t nat -D PREROUTING -i "$ROOT_IF" -d "$REDIRECT_IP" \
			-p udp --dport 53 -j REDIRECT --to-ports "$REDIRECT_PORT" \
			2>/dev/null; then
			cleanup_error "could not remove the DNS REDIRECT rule"
		fi
	fi
	if [ "$input_rule_installed" = 1 ]; then
		if ! iptables -D INPUT -i "$ROOT_IF" -p udp \
			-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT \
			2>/dev/null; then
			cleanup_error "could not remove the DNS INPUT rule"
		fi
	fi
	if [ "$topology_installed" = 1 ]; then
		ip netns del "$CLIENT_NS" 2>/dev/null
		ip link del "$ROOT_IF" 2>/dev/null
	fi
	rm -rf "$TMP_DIR"

	if [ -n "$original_enable" ]; then
		actual_enable=$(field enable 2>/dev/null)
		if [ "$actual_enable" != "$original_enable" ]; then
			cleanup_error "enable is ${actual_enable:-unreadable}, expected $original_enable"
		fi
	fi
	netns_list=$(ip netns list 2>/dev/null)
	netns_status=$?
	if [ "$netns_status" -ne 0 ]; then
		cleanup_error "could not inspect network namespaces"
	elif namespace_exists "$CLIENT_NS" "$netns_list"; then
		cleanup_error "network namespace $CLIENT_NS still exists"
	fi
	if ! ip link show >/dev/null 2>&1; then
		cleanup_error "could not inspect root network interfaces"
	elif ip link show dev "$ROOT_IF" >/dev/null 2>&1; then
		cleanup_error "root interface $ROOT_IF still exists"
	fi
	if [ -e "$TMP_DIR" ]; then
		cleanup_error "temporary directory $TMP_DIR still exists"
	fi

	cleanup_done=1
	[ "$cleanup_failed" = 0 ]
}

exit_cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	set +e
	if [ "$cleanup_done" != 1 ]; then
		cleanup_resources
		cleanup_status=$?
		if [ "$status" -eq 0 ] && [ "$cleanup_status" -ne 0 ]; then
			status=1
		fi
	fi
	exit "$status"
}

assert_dns_query()
{
	destination=$1
	source_port=$2

	"$ASSERT_BIN" -d "$QUEUE" -S "$CLIENT_IP" -T "$destination" \
		-P udp -p 53 -s 4 -D original -a 1 -c 1 -r 0 -- \
		ip netns exec "$CLIENT_NS" "$TRAFFIC_BIN" client udp \
		"$destination" 53 original "$DNS_YOUTUBE_QUERY" "$source_port"
}

case ${1:-} in
-h|--help)
	printf '%s\n' \
		"Usage: $0" \
		"Tests IPv4 DNS-only LOCAL_IN classification for direct and REDIRECT traffic."
	exit 0
	;;
"")
	;;
*)
	fail "unexpected argument: $1"
	;;
esac

[ "$(id -u)" = 0 ] || fail "root privileges are required"
[ -r "$CTL" ] && [ -w "$CTL" ] || fail "$CTL is not readable and writable"
[ -r "$QUEUE" ] && [ -w "$QUEUE" ] || fail "$QUEUE is not readable and writable"
command -v awk >/dev/null 2>&1 || fail "missing command: awk"
command -v ip >/dev/null 2>&1 || fail "missing command: ip"
command -v iptables >/dev/null 2>&1 || fail "missing command: iptables"
command -v "$CC" >/dev/null 2>&1 || fail "missing compiler: $CC"

original_enable=$(field enable) || fail "missing DPI enable field"
[ "$original_enable" = 0 ] || [ "$original_enable" = 1 ] ||
	fail "invalid DPI enable field: $original_enable"

mkdir "$TMP_DIR" || fail "temporary directory already exists: $TMP_DIR"
trap exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$ASSERT_BIN" "$REPO_DIR/tools/natflow-dpi-corpus.c"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$TRAFFIC_BIN" "$REPO_DIR/tools/natflow-dpi-traffic.c"

ip netns add "$CLIENT_NS"
topology_installed=1
ip link add "$ROOT_IF" type veth peer name "$CLIENT_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip address add "$ROOT_IP/24" dev "$ROOT_IF"
ip link set "$ROOT_IF" up
ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" address add "$CLIENT_IP/24" dev "$CLIENT_IF"
ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$CLIENT_NS" route add default via "$ROOT_IP"

iptables -I INPUT -i "$ROOT_IF" -p udp \
	-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
input_rule_installed=1
iptables -t nat -I PREROUTING -i "$ROOT_IF" -d "$REDIRECT_IP" \
	-p udp --dport 53 -j REDIRECT --to-ports "$REDIRECT_PORT"
redirect_rule_installed=1

write_ctl enable=0
write_ctl events_clear
write_ctl enable=1

assert_dns_query "$ROOT_IP" "$DIRECT_SOURCE_PORT"
assert_dns_query "$REDIRECT_IP" "$REDIRECT_SOURCE_PORT"

matches_dns=$(field matches_dns)
dns_app_intents=$(field dns_app_intents)
packet_matches=$(field packet_match_original)
[ "$matches_dns" -eq 2 ] || fail "matches_dns=$matches_dns, expected 2"
[ "$dns_app_intents" -eq 2 ] ||
	fail "dns_app_intents=$dns_app_intents, expected 2"
[ "$packet_matches" -eq 2 ] ||
	fail "packet_match_original=$packet_matches, expected 2"

set +e
cleanup_resources
cleanup_status=$?
set -e
[ "$cleanup_status" -eq 0 ] || fail "local DNS cleanup verification failed"
printf '%s\n' \
	'PASS: direct and REDIRECT DNS queries matched in the LOCAL_IN hook'
