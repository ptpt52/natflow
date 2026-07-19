# DPI Corpus

`run-corpus.sh` creates two network namespaces and routes IPv4 traffic through
the root namespace so the loaded natflow `FORWARD` hook sees each fixture. It
installs one audit-only rule for every current protocol detector, opens the DPI
queue before injection, and checks the v3 event against the original tuple and
expected evidence direction.

The runner is destructive to the DPI test state: it requires an empty ruleset,
clears event counters, increments generation, and temporarily changes DPI
enable. It also inserts two interface-specific `iptables` FORWARD rules and
temporarily enables IPv4 forwarding. Exit cleanup restores enable and
forwarding, clears temporary rules, removes firewall entries, and deletes both
namespaces.

Run as root on a disposable test host with the DPI-enabled module loaded:

```sh
tests/dpi/run-corpus.sh tests/dpi/cases/dns-ssh.cases
```

Case files use seven pipe-separated fields:

```text
name|proto|tcp-or-udp|original-or-reply|server-port|payload-hex|positive-or-negative
```

Every case uses a new connection. Positive cases require the expected source,
`app_id`, `rule_id`, original tuple, and evidence direction. Negative cases
fail on any DPI event for that tuple. The first implementation is IPv4-only;
IPv6, exact TCP segmentation, queue-full pressure, and non-linear skb coverage
remain separate integration work.
