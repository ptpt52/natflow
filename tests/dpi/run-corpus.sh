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
ADDRESS_PREFIX=24
FIREWALL=iptables
FIREWALL_CTSTATE=NEW,ESTABLISHED,RELATED
FORWARD_CTL=/proc/sys/net/ipv4/ip_forward
CLIENT_NS=ndpc$$
SERVER_NS=ndps$$
CLIENT_IF=ndci$$
CLIENT_PEER=ndcp$$
SERVER_IF=ndsi$$
SERVER_PEER=ndsp$$
TMP_DIR=${TMPDIR:-/tmp}/natflow-dpi-corpus.$$
ASSERT_BIN=$TMP_DIR/natflow-dpi-corpus
TRAFFIC_BIN=$TMP_DIR/natflow-dpi-traffic
PRESSURE_BIN=$TMP_DIR/natflow-dpi-queue-pressure
PRESSURE_CACHE_DEFAULT=8
PRESSURE_EVENTS_DEFAULT=32
PRESSURE_PORT_BASE=42000
PRESSURE_PAYLOAD=000100002112a442000102030405060708090a0b
STREAM_CACHE_DEFAULT=64
STREAM_EVENTS_DEFAULT=128
STREAM_PARALLEL_DEFAULT=16
STREAM_TIMEOUT_MS=15000
original_enable=
original_forward=
topology_installed=0
firewall_installed=0
cleanup_done=0
pressure_mode=0
pressure_cache=$PRESSURE_CACHE_DEFAULT
pressure_events=$PRESSURE_EVENTS_DEFAULT
stream_mode=0
stream_cache=$STREAM_CACHE_DEFAULT
stream_events=$STREAM_EVENTS_DEFAULT
stream_parallel=$STREAM_PARALLEL_DEFAULT
ipv6_mode=0

usage()
{
	cat <<EOF
Usage: $0 case-file [case-file ...]
       $0 --check case-file [case-file ...]
       $0 --ipv6 case-file [case-file ...]
       $0 --queue-pressure [cache [generated]]
       $0 --queue-stream [cache [generated [parallel]]]

Case format, one pipe-separated record per line:
  name|proto|transport|direction|port|payload_hex|expectation

Blank lines and lines beginning with # are ignored. This destructive test
requires an empty DPI domain ruleset and root privileges. Queue pressure defaults to
cache=$PRESSURE_CACHE_DEFAULT and generated=$PRESSURE_EVENTS_DEFAULT.
Queue stream defaults to cache=$STREAM_CACHE_DEFAULT,
generated=$STREAM_EVENTS_DEFAULT and parallel=$STREAM_PARALLEL_DEFAULT.
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

validate_count()
{
	name=$1
	value=$2

	case $value in
	??????*) fail "$name is too large: $value" ;;
	0|[1-9]|[1-9][0-9]*) ;;
	*) fail "invalid $name: $value" ;;
	esac
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
	for expected_field in rules domain_rules txn_active; do
		actual_value=$(field "$expected_field" 2>/dev/null)
		if [ "$actual_value" != 0 ]; then
			cleanup_error "$expected_field is ${actual_value:-unreadable}, expected 0"
		fi
	done
	if [ -n "$original_enable" ]; then
		actual_value=$(field enable 2>/dev/null)
		if [ "$actual_value" != "$original_enable" ]; then
			cleanup_error "enable is ${actual_value:-unreadable}, expected $original_enable"
		fi
	fi

	if [ "$firewall_installed" = 1 ]; then
		"$FIREWALL" -D FORWARD -i "$CLIENT_IF" -o "$SERVER_IF" \
			-m conntrack --ctstate "$FIREWALL_CTSTATE" -j ACCEPT 2>/dev/null
		"$FIREWALL" -D FORWARD -i "$SERVER_IF" -o "$CLIENT_IF" \
			-m conntrack --ctstate "$FIREWALL_CTSTATE" -j ACCEPT 2>/dev/null
		if ! "$FIREWALL" -S FORWARD >/dev/null 2>&1; then
			cleanup_error "could not inspect the FORWARD chain"
		else
			if "$FIREWALL" -C FORWARD -i "$CLIENT_IF" -o "$SERVER_IF" \
				-m conntrack --ctstate "$FIREWALL_CTSTATE" \
				-j ACCEPT >/dev/null 2>&1; then
				cleanup_error "client-to-server FORWARD rule remains installed"
			fi
			if "$FIREWALL" -C FORWARD -i "$SERVER_IF" -o "$CLIENT_IF" \
				-m conntrack --ctstate "$FIREWALL_CTSTATE" \
				-j ACCEPT >/dev/null 2>&1; then
				cleanup_error "server-to-client FORWARD rule remains installed"
			fi
		fi
	fi

	if [ "$topology_installed" = 1 ]; then
		ip netns del "$CLIENT_NS" 2>/dev/null
		ip netns del "$SERVER_NS" 2>/dev/null
		ip link del "$CLIENT_IF" 2>/dev/null
		ip link del "$SERVER_IF" 2>/dev/null
		if [ -n "$original_forward" ]; then
			printf '%s\n' "$original_forward" >"$FORWARD_CTL" 2>/dev/null
		fi
		netns_list=$(ip netns list 2>/dev/null)
		netns_status=$?
		if [ "$netns_status" -ne 0 ]; then
			cleanup_error "could not inspect network namespaces"
		else
			if namespace_exists "$CLIENT_NS" "$netns_list"; then
				cleanup_error "network namespace $CLIENT_NS still exists"
			fi
			if namespace_exists "$SERVER_NS" "$netns_list"; then
				cleanup_error "network namespace $SERVER_NS still exists"
			fi
		fi
		if ! ip link show >/dev/null 2>&1; then
			cleanup_error "could not inspect root network interfaces"
		else
			if ip link show dev "$CLIENT_IF" >/dev/null 2>&1; then
				cleanup_error "root interface $CLIENT_IF still exists"
			fi
			if ip link show dev "$SERVER_IF" >/dev/null 2>&1; then
				cleanup_error "root interface $SERVER_IF still exists"
			fi
		fi
		if [ -n "$original_forward" ]; then
			actual_value=$(cat "$FORWARD_CTL" 2>/dev/null)
			if [ "$actual_value" != "$original_forward" ]; then
				cleanup_error "IP forwarding is ${actual_value:-unreadable}, expected $original_forward"
			fi
		fi
	fi

	rm -rf "$TMP_DIR"
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

finish_cleanup()
{
	set +e
	cleanup_resources
	cleanup_status=$?
	set -e
	[ "$cleanup_status" -eq 0 ] ||
		fail "corpus cleanup verification failed"
	printf 'PASS: cleanup restored DPI and network state\n'
}

dump_failure_state()
{
	printf '%s\n' '--- DPI ctl failure snapshot ---' >&2
	cat "$CTL" >&2
	printf '%s\n' '--- FORWARD failure snapshot ---' >&2
	"$FIREWALL" -vnL FORWARD 2>/dev/null |
		awk -v client="$CLIENT_IF" -v server="$SERVER_IF" \
			'NR <= 2 || index($0, client) || index($0, server)' >&2
	if [ "$ipv6_mode" = 1 ] && command -v conntrack >/dev/null 2>&1; then
		printf '%s\n' '--- IPv6 conntrack failure snapshot ---' >&2
		conntrack -L -f ipv6 2>/dev/null |
			awk -v client="$CLIENT_IP" -v server="$SERVER_IP" \
				'index($0, client) || index($0, server)' >&2
	fi
}

proto_values()
{
	case $1 in
	dns) printf '%s\n' '4 1 1 0' ;;
	ssh) printf '%s\n' '5 2 2 0' ;;
	wireguard) printf '%s\n' '6 3 3 0' ;;
	stun) printf '%s\n' '7 4 4 0' ;;
	turn) printf '%s\n' '8 5 4 0' ;;
	bittorrent) printf '%s\n' '9 6 5 0' ;;
	ftp) printf '%s\n' '10 7 6 0' ;;
	smtp) printf '%s\n' '11 8 7 0' ;;
	pop3) printf '%s\n' '12 9 7 0' ;;
	imap) printf '%s\n' '13 10 7 0' ;;
	sip) printf '%s\n' '14 11 8 0' ;;
	rtsp) printf '%s\n' '15 12 4 0' ;;
	mqtt) printf '%s\n' '16 13 9 0' ;;
	resp) printf '%s\n' '17 14 10 0' ;;
	mysql) printf '%s\n' '18 15 10 0' ;;
	postgresql) printf '%s\n' '19 16 10 0' ;;
	rdp) printf '%s\n' '20 17 2 0' ;;
	smb) printf '%s\n' '21 18 5 0' ;;
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
	category_id=$3
	rule_id=$4
	case $l4 in tcp|udp) ;; *) fail "$case_file: invalid L4 in $name" ;; esac
	case $proto:$l4 in
	ssh:udp|wireguard:tcp|ftp:udp|smtp:udp|pop3:udp|imap:udp|rtsp:udp|mqtt:udp|resp:udp|mysql:udp|postgresql:udp|rdp:udp|smb:udp)
		fail "$case_file: invalid protocol/L4 pair in $name" ;;
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
	ready_file=$TMP_DIR/ready.$$.${port}

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

inject_pressure()
{
	count=$1
	base_port=$2
	payload=$3
	pids=
	failed=0
	index=0

	while [ "$index" -lt "$count" ]; do
		inject_case udp original "$((base_port + index))" "$payload" &
		pids="$pids $!"
		index=$((index + 1))
	done
	for child_pid in $pids; do
		wait "$child_pid" || failed=1
	done
	[ "$failed" = 0 ] || fail "one or more pressure flows failed"
}

inject_stream()
{
	count=$1
	base_port=$2
	payload=$3
	parallel=$4
	index=0

	while [ "$index" -lt "$count" ]; do
		pids=
		failed=0
		batch=0
		while [ "$batch" -lt "$parallel" ] &&
			[ "$index" -lt "$count" ]; do
			inject_case udp original "$((base_port + index))" \
				"$payload" &
			pids="$pids $!"
			index=$((index + 1))
			batch=$((batch + 1))
		done
		for child_pid in $pids; do
			wait "$child_pid" || failed=1
		done
		[ "$failed" = 0 ] ||
			fail "one or more stream flows failed"
	done
}

if [ "${1:-}" = __inject ]; then
	shift
	[ "$#" -eq 9 ] || fail "invalid internal injector arguments"
	CLIENT_NS=$1
	SERVER_NS=$2
	TRAFFIC_BIN=$3
	TMP_DIR=$4
	SERVER_IP=$5
	shift 5
	inject_case "$@"
	exit 0
fi

if [ "${1:-}" = __pressure_inject ]; then
	shift
	[ "$#" -eq 7 ] || fail "invalid internal pressure injector arguments"
	CLIENT_NS=$1
	SERVER_NS=$2
	TRAFFIC_BIN=$3
	TMP_DIR=$4
	pressure_events=$5
	pressure_port_base=$6
	pressure_payload=$7
	inject_pressure "$pressure_events" "$pressure_port_base" "$pressure_payload"
	exit 0
fi

if [ "${1:-}" = __stream_inject ]; then
	shift
	[ "$#" -eq 8 ] || fail "invalid internal stream injector arguments"
	CLIENT_NS=$1
	SERVER_NS=$2
	TRAFFIC_BIN=$3
	TMP_DIR=$4
	stream_events=$5
	stream_port_base=$6
	stream_payload=$7
	stream_parallel=$8
	inject_stream "$stream_events" "$stream_port_base" \
		"$stream_payload" "$stream_parallel"
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

if [ "$1" = --ipv6 ]; then
	ipv6_mode=1
	shift
	[ "$#" -gt 0 ] || fail "no IPv6 corpus case files supplied"
	CLIENT_IP=2001:db8:18::2
	SERVER_IP=2001:db8:19::2
	CLIENT_GW=2001:db8:18::1
	SERVER_GW=2001:db8:19::1
	ADDRESS_PREFIX=64
	FIREWALL=ip6tables
	FORWARD_CTL=/proc/sys/net/ipv6/conf/all/forwarding
	case ${1:-} in
	--queue-pressure|--queue-stream)
		fail "IPv6 cannot be combined with queue pressure or stream mode"
		;;
	esac
fi

if [ "$1" = --queue-pressure ]; then
	pressure_mode=1
	shift
	[ "$#" -le 2 ] || fail "queue pressure accepts at most cache and generated"
	if [ "$#" -ge 1 ]; then
		pressure_cache=$1
	fi
	if [ "$#" -eq 2 ]; then
		pressure_events=$2
	fi
	validate_count "queue pressure cache" "$pressure_cache"
	validate_count "generated event count" "$pressure_events"
	[ "$pressure_cache" -gt 0 ] ||
		fail "queue pressure cache must be positive"
	[ "$pressure_events" -gt "$pressure_cache" ] ||
		fail "generated events must exceed the cache limit"
	[ "$pressure_events" -le 256 ] ||
		fail "queue pressure is limited to 256 concurrent flows"
	[ "$((PRESSURE_PORT_BASE + pressure_events))" -le 65535 ] ||
		fail "queue pressure port range exceeds 65535"
fi

if [ "$1" = --queue-stream ]; then
	stream_mode=1
	shift
	[ "$#" -le 3 ] ||
		fail "queue stream accepts at most cache, generated, and parallel"
	if [ "$#" -ge 1 ]; then
		stream_cache=$1
	fi
	if [ "$#" -ge 2 ]; then
		stream_events=$2
	fi
	if [ "$#" -eq 3 ]; then
		stream_parallel=$3
	fi
	validate_count "queue stream cache" "$stream_cache"
	validate_count "stream event count" "$stream_events"
	validate_count "stream parallel count" "$stream_parallel"
	[ "$stream_cache" -gt 0 ] ||
		fail "queue stream cache must be positive"
	[ "$stream_cache" -le 256 ] ||
		fail "queue stream cache is limited to 256 events"
	[ "$stream_events" -gt 0 ] ||
		fail "stream event count must be positive"
	[ "$stream_events" -le 256 ] ||
		fail "queue stream is limited to 256 flows"
	[ "$stream_parallel" -gt 0 ] &&
		[ "$stream_parallel" -le 64 ] ||
		fail "stream parallel count must be between 1 and 64"
	[ "$stream_parallel" -le "$stream_events" ] ||
		fail "stream parallel count exceeds generated events"
	[ "$stream_cache" -ge "$stream_parallel" ] ||
		fail "queue stream cache must cover one parallel batch"
	[ "$((PRESSURE_PORT_BASE + stream_events))" -le 65535 ] ||
		fail "queue stream port range exceeds 65535"
fi

[ "$(id -u)" = 0 ] || fail "root privileges are required"
[ -r "$CTL" ] && [ -w "$CTL" ] || fail "$CTL is not readable and writable"
[ -r "$QUEUE" ] && [ -w "$QUEUE" ] || fail "$QUEUE is not readable and writable"
need_command awk
need_command ip
need_command "$FIREWALL"
need_command "$CC"

original_enable=$(field enable) || fail "missing DPI enable field"
[ "$original_enable" = 0 ] || [ "$original_enable" = 1 ] ||
	fail "invalid DPI enable field: $original_enable"
[ "$(field rules)" = 0 ] || fail "DPI ruleset must be empty"
[ "$(field txn_active)" = 0 ] || fail "DPI transaction is already active"
original_forward=$(cat "$FORWARD_CTL")

mkdir "$TMP_DIR" || fail "temporary directory already exists: $TMP_DIR"
trap exit_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$ASSERT_BIN" "$REPO_DIR/tools/natflow-dpi-corpus.c"
"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
	-o "$TRAFFIC_BIN" "$REPO_DIR/tools/natflow-dpi-traffic.c"
if [ "$pressure_mode" = 1 ] || [ "$stream_mode" = 1 ]; then
	"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
		-o "$PRESSURE_BIN" \
		"$REPO_DIR/tools/natflow-dpi-queue-pressure.c"
fi

ip netns add "$CLIENT_NS"
topology_installed=1
ip netns add "$SERVER_NS"
ip link add "$CLIENT_IF" type veth peer name "$CLIENT_PEER"
ip link set "$CLIENT_PEER" netns "$CLIENT_NS"
ip link add "$SERVER_IF" type veth peer name "$SERVER_PEER"
ip link set "$SERVER_PEER" netns "$SERVER_NS"
ip link set "$CLIENT_IF" up
ip link set "$SERVER_IF" up
ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" link set "$CLIENT_PEER" up
ip -n "$SERVER_NS" link set lo up
ip -n "$SERVER_NS" link set "$SERVER_PEER" up
if [ "$ipv6_mode" = 1 ]; then
	ip -6 address add "$CLIENT_GW/$ADDRESS_PREFIX" dev "$CLIENT_IF" nodad
	ip -6 address add "$SERVER_GW/$ADDRESS_PREFIX" dev "$SERVER_IF" nodad
	ip -n "$CLIENT_NS" -6 address add \
		"$CLIENT_IP/$ADDRESS_PREFIX" dev "$CLIENT_PEER" nodad
	ip -n "$CLIENT_NS" -6 route add default via "$CLIENT_GW"
	ip -n "$SERVER_NS" -6 address add \
		"$SERVER_IP/$ADDRESS_PREFIX" dev "$SERVER_PEER" nodad
	ip -n "$SERVER_NS" -6 route add default via "$SERVER_GW"
else
	ip address add "$CLIENT_GW/$ADDRESS_PREFIX" dev "$CLIENT_IF"
	ip address add "$SERVER_GW/$ADDRESS_PREFIX" dev "$SERVER_IF"
	ip -n "$CLIENT_NS" address add \
		"$CLIENT_IP/$ADDRESS_PREFIX" dev "$CLIENT_PEER"
	ip -n "$CLIENT_NS" route add default via "$CLIENT_GW"
	ip -n "$SERVER_NS" address add \
		"$SERVER_IP/$ADDRESS_PREFIX" dev "$SERVER_PEER"
	ip -n "$SERVER_NS" route add default via "$SERVER_GW"
fi
printf '1\n' >"$FORWARD_CTL"
"$FIREWALL" -I FORWARD -i "$CLIENT_IF" -o "$SERVER_IF" \
	-m conntrack --ctstate "$FIREWALL_CTSTATE" -j ACCEPT
firewall_installed=1
"$FIREWALL" -I FORWARD -i "$SERVER_IF" -o "$CLIENT_IF" \
	-m conntrack --ctstate "$FIREWALL_CTSTATE" -j ACCEPT

write_ctl enable=0
write_ctl events_clear
write_ctl enable=1

if [ "$pressure_mode" = 1 ]; then
	"$PRESSURE_BIN" -d "$QUEUE" -c "$pressure_cache" \
		-n "$pressure_events" -S "$CLIENT_IP" -T "$SERVER_IP" \
		-p "$PRESSURE_PORT_BASE" -a 4 -C 4 -r 0 -- \
		"$0" __pressure_inject "$CLIENT_NS" "$SERVER_NS" \
		"$TRAFFIC_BIN" "$TMP_DIR" "$pressure_events" \
		"$PRESSURE_PORT_BASE" "$PRESSURE_PAYLOAD"

	expected_lost=$((pressure_events - pressure_cache))
	actual_matches=$(field matches)
	actual_events=$(field events)
	actual_suppressed=$(field events_suppressed)
	actual_lost=$(field events_lost)
	actual_matches_stun=$(field matches_stun)
	actual_events_stun=$(field events_stun)
	[ "$actual_matches" -eq "$pressure_events" ] ||
		fail "matches=$actual_matches, expected $pressure_events"
	[ "$actual_events" -eq "$pressure_cache" ] ||
		fail "events=$actual_events, expected $pressure_cache"
	[ "$actual_suppressed" -eq 0 ] ||
		fail "events_suppressed=$actual_suppressed, expected 0"
	[ "$actual_lost" -eq "$expected_lost" ] ||
		fail "events_lost=$actual_lost, expected $expected_lost"
	[ "$actual_matches_stun" -eq "$pressure_events" ] ||
		fail "matches_stun=$actual_matches_stun, expected $pressure_events"
	[ "$actual_events_stun" -eq "$pressure_cache" ] ||
		fail "events_stun=$actual_events_stun, expected $pressure_cache"
	[ "$actual_matches" -eq \
		"$((actual_events + actual_suppressed + actual_lost))" ] ||
		fail "DPI event counters violate the accounting invariant"

	finish_cleanup
	printf 'PASS: DPI queue pressure cache=%u generated=%u lost=%u\n' \
		"$pressure_cache" "$pressure_events" "$expected_lost"
	exit 0
fi

if [ "$stream_mode" = 1 ]; then
	"$PRESSURE_BIN" -d "$QUEUE" -c "$stream_cache" \
		-n "$stream_events" -S "$CLIENT_IP" -T "$SERVER_IP" \
		-p "$PRESSURE_PORT_BASE" -a 4 -C 4 -r 0 \
		-w "$STREAM_TIMEOUT_MS" -- \
		"$0" __stream_inject "$CLIENT_NS" "$SERVER_NS" \
		"$TRAFFIC_BIN" "$TMP_DIR" "$stream_events" \
		"$PRESSURE_PORT_BASE" "$PRESSURE_PAYLOAD" "$stream_parallel"

	actual_matches=$(field matches)
	actual_events=$(field events)
	actual_suppressed=$(field events_suppressed)
	actual_lost=$(field events_lost)
	actual_matches_stun=$(field matches_stun)
	actual_events_stun=$(field events_stun)
	[ "$actual_matches" -eq "$stream_events" ] ||
		fail "matches=$actual_matches, expected $stream_events"
	[ "$actual_events" -eq "$stream_events" ] ||
		fail "events=$actual_events, expected $stream_events"
	[ "$actual_suppressed" -eq 0 ] ||
		fail "events_suppressed=$actual_suppressed, expected 0"
	[ "$actual_lost" -eq 0 ] ||
		fail "events_lost=$actual_lost, expected 0"
	[ "$actual_matches_stun" -eq "$stream_events" ] ||
		fail "matches_stun=$actual_matches_stun, expected $stream_events"
	[ "$actual_events_stun" -eq "$stream_events" ] ||
		fail "events_stun=$actual_events_stun, expected $stream_events"
	[ "$actual_matches" -eq \
		"$((actual_events + actual_suppressed + actual_lost))" ] ||
		fail "DPI event counters violate the accounting invariant"

	finish_cleanup
	printf 'PASS: DPI queue stream cache=%u generated=%u parallel=%u\n' \
		"$stream_cache" "$stream_events" "$stream_parallel"
	exit 0
fi

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
		if ! "$ASSERT_BIN" -d "$QUEUE" -S "$CLIENT_IP" -T "$SERVER_IP" \
			-P "$l4" -p "$port" -s "$source_id" -D "$direction" \
			-a "$app_id" -c "$category_id" -r "$rule_id" $negative -- \
			"$0" __inject "$CLIENT_NS" "$SERVER_NS" "$TRAFFIC_BIN" \
			"$TMP_DIR" "$SERVER_IP" "$l4" "$direction" "$port" "$payload"; then
			dump_failure_state
			fail "corpus case failed: $name"
		fi
		case_count=$((case_count + 1))
	done <"$case_file"
done

[ "$case_count" -gt 0 ] || fail "no corpus cases were loaded"
finish_cleanup
if [ "$ipv6_mode" = 1 ]; then
	printf 'PASS: %u IPv6 DPI corpus case(s)\n' "$case_count"
else
	printf 'PASS: %u DPI corpus case(s)\n' "$case_count"
fi
