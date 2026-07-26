# DPI Corpus

`run-corpus.sh` creates two network namespaces and routes IPv4 or IPv6 traffic
through the root namespace so the loaded natflow `FORWARD` hook sees each
fixture. It installs one audit-only rule for every current protocol detector,
opens the DPI queue before injection, and checks the v3 event against the
original tuple and expected evidence direction.

The runner is destructive to the DPI test state: it requires an empty ruleset,
clears event counters, increments generation, and temporarily changes DPI
enable. It also inserts two interface-specific firewall rules and temporarily
enables forwarding for the selected address family. Before reporting the final
PASS, cleanup restores and verifies the DPI enable value, empty ruleset and
inactive transaction, forwarding value, firewall-rule removal, namespace and
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
has the same empty-ruleset, isolated-host, state-restoration, and final cleanup
requirements as the detector corpus.

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
name|proto|tcp-or-udp|original-or-reply|server-port|payload-hex|positive-or-negative
```

Every case uses a new connection. Positive cases require the expected source,
`app_id`, `rule_id`, original tuple, and evidence direction. Negative cases
fail on any DPI event for that tuple. IPv4 and base IPv6 TCP/UDP are supported;
IPv6 extension headers are outside the supported DPI scope. Exact TCP
segmentation, non-linear skb, and long-duration soak are deferred. Failure
injection remains separate integration work. Queue pressure and stream modes
currently use the IPv4 topology.

Current fixtures:

- `cases/dns-ssh.cases`: DNS UDP/TCP original/reply, compressed question,
  malformed pointer/header/length and wrong-port negatives; SSH original/reply
  banners, supported version form, port-only, truncated and malformed banners.
- `cases/udp-protocols.cases`: WireGuard message types and length/reserved-byte
  negatives; STUN/TURN UDP/TCP headers, method, length and cookie cases;
  BitTorrent TCP handshake, UDP uTP and DHT positive/negative cases.
