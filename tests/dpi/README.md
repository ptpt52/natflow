# DPI Corpus

`run-corpus.sh` creates two network namespaces and routes IPv4 or IPv6 traffic
through the root namespace so the loaded natflow `FORWARD` hook sees each
fixture. It enables the compiled-in protocol catalog, opens the DPI queue
before injection, and checks the v3 event against the fixed catalog revision,
`app_id`, category, `rule_id=0`, original tuple and expected evidence direction.

The runner is destructive to the DPI test state: it clears event counters and
temporarily changes DPI enable. It also
inserts two interface-specific firewall rules and temporarily
enables forwarding for the selected address family. Before reporting the final
PASS, cleanup restores and verifies the DPI enable value, forwarding value,
firewall-rule removal, namespace and
veth removal, and temporary-directory removal. Signal and failure exits
attempt the same cleanup and report any failed postcondition as `CLEANUP FAIL`.

Run as root on a disposable test host with the DPI-enabled module loaded:

```sh
tests/dpi/run-corpus.sh tests/dpi/cases/dns-ssh.cases
```

The interface-specific firewall rules include a conntrack state match so the
selected address family has conntrack enabled even when the natflow path is
globally disabled and no other firewall or NAT rule requires conntrack.

Run the same fixtures through an IPv6 routed topology with:

```sh
sudo tests/dpi/run-corpus.sh --ipv6 tests/dpi/cases/*.cases
```

IPv6 mode uses documentation-prefix addresses, `ip6tables`, and the IPv6
forwarding sysctl. It verifies the full 16-byte original tuple in each event.

The conntrack packet-limit lifecycle can be tested with:

```sh
sudo tests/dpi/run-corpus.sh --packet-limit
```

This IPv4-only mode temporarily enables `net.netfilter.nf_conntrack_acct` and
restores its original value during cleanup. It sends 256 and 257 empty UDP
datagrams on separate single flows to verify the exact boundary, checks that
`events_clear` resets `context_cleared_acct_limit`, and injects valid
zero-payload TCP ACKs while the socket remains open. Empty packets must not
produce an event or increment either payload-inspection counter. TCP ACK
injection requires `CAP_NET_ADMIN` for TCP repair and `CAP_NET_RAW` for its raw
IPv4 socket.

Fixture files can be checked without root, a loaded module, or network setup:

```sh
tests/dpi/run-corpus.sh --check tests/dpi/cases/*.cases
```

Queue-full accounting and concurrent producer traffic can be tested with:

```sh
sudo tests/dpi/run-corpus.sh --queue-pressure
sudo tests/dpi/run-corpus.sh --queue-pressure 8 32
```

The optional values are the cache limit and number of generated flows. The
runner opens one reader, does not read while the flows run concurrently, then
requires exactly `cache` valid STUN events and verifies the ctl counters:
`matches=generated`, `events=cache`, `events_lost=generated-cache`,
`events_suppressed=0`, and the corresponding STUN source counters. This mode
has the same isolated-host, state-restoration, and final cleanup
requirements as the native-machine corpus.

Concurrent reader/producer operation can be tested with:

```sh
sudo tests/dpi/run-corpus.sh --queue-stream
sudo tests/dpi/run-corpus.sh --queue-stream 64 128 16
```

The optional values are the cache limit, total generated flows, and maximum
parallel flows per producer batch. One reader continuously polls and batch
reads while each producer batch runs. Every generated port must appear exactly
once, the queue must be empty afterward, and ctl must report
`matches=events=generated` with zero suppressed or lost events. The cache must
cover at least one parallel batch.

Case files use seven pipe-separated fields:

```text
name|proto|tcp-or-udp|original-or-reply-or-either|server-port|payload|positive-or-negative
```

Every case uses a new connection. Positive cases require the expected source,
fixed `app_id`, category, `rule_id=0`, catalog revision, original tuple, and evidence direction. `either` is only valid for a TCP sequence whose concurrent terminal direction is intentionally unspecified. A payload is normally hex; `seq:` introduces a comma-separated client-view TCP script where `sHEX` sends, `rHEX` receives, and `xCLIENTHEX/SERVERHEX` exchanges both payloads concurrently. Negative cases
fail on any DPI event for that tuple. IPv4 and base IPv6 TCP/UDP are supported;
IPv6 extension headers are outside the supported DPI scope. Exact TCP
segmentation, non-linear skb, and long-duration soak are deferred. Failure
injection remains separate integration work. Queue pressure, stream, and
packet-limit modes currently use the IPv4 topology.

The checked-in corpus has 196 cases: 51 for the A-tier DNS, SSH, WireGuard,
STUN/TURN, and BitTorrent subsets, 31 positive/negative cases for the 12
B-tier text, database, IoT, RDP, and SMB native machines, 28 HTTP Host/App
parser cases for the nine fixed applications, and 13 nDPI-derived DingTalk,
QQ/OICQ, and iQIYI native application cases. The second batch adds 36 common
application hostname/payload cases and 37 NTP, SNMP, RADIUS, TFTP, LDAP, NFS,
SOCKS, and CoAP cases.

Current fixtures:

- `cases/domain-apps.cases`: static application exact/suffix matching, hostname
  normalization, root/subdomain acceptance, label-boundary negatives, and
  bounded HTTP App parser request/reply boundaries.

- `cases/mobile-apps.cases`: DingTalk TCP structure, QQ fixed UDP/OICQ forms,
  iQIYI UDP `PPStream`, both evidence directions, and length/constant/keyword
  negatives.

- `cases/common-apps-v2.cases`: ten common applications, Meta/Tencent child
  domain precedence, label-boundary negatives, WhatsApp segmented prefix, and
  Discord/Spotify/Zoom direct payload evidence. An optional eighth fixture
  field binds the injector source port for endpoint-sensitive signatures such
  as Spotify UDP.

- `cases/network-protocols-v2.cases`: eight added protocols, including strict
  BER/declared-length negatives, TCP/UDP NFS RPC, bidirectional evidence,
  dynamic-TID TFTP OACK, STUN/uTP/WireGuard collision precedence, SOCKS handshake
  ordering, and CoAP token/port boundaries.

- `cases/dns-ssh.cases`: DNS UDP/TCP original/reply, compressed question,
  malformed pointer/header/length and wrong-port negatives; SSH original/reply
  banners, supported version form, port-only, truncated and malformed banners.
- `cases/udp-protocols.cases`: WireGuard message types and length/reserved-byte
  negatives; STUN/TURN UDP/TCP headers, method, length and cookie cases;
  BitTorrent TCP handshake, UDP uTP and DHT positive/negative cases.
- `cases/b-tier.cases`: single-packet B-tier signatures plus RDP compact
  automaton sequences covering ordered, reversed, concurrent, retransmitted,
  budget-exhausted, transport-end, and malformed-confirm flows; SMB negatives
  include an NBSS header whose declared payload is too short for SMB2.
