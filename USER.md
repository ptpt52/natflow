# NATflow User Control Interface Guide (USER.md)

This document is based on the current implementation and covers these character-device interfaces:

- `/dev/userinfo_ctl`: user status query and control
- `/dev/qos_ctl`: QoS rate-limit rule management

> Note: Every command written to these control devices **must end with a newline (`\n`)**. Otherwise, the kernel keeps waiting for more input. Overly long lines return an error.

---

## 1. `/dev/userinfo_ctl`

### 1.1 Read all current users (connections)

Command:

```bash
cat /dev/userinfo_ctl
```

Per-line output format:

```text
ip_or_ipv6,mac,auth_type,auth_status,rule_id,timeout,rx_pkts:rx_bytes,tx_pkts:tx_bytes,rx_speed_pkts:rx_speed_bytes,tx_speed_pkts:tx_speed_bytes
```

Field description:

- `ip_or_ipv6`: user source address (IPv4 or IPv6)
- `mac`: user MAC address
- `auth_type`: authentication type, **printed in hex** (for example `0x1`)
- `auth_status`: authentication status, **printed in hex** (for example `0x5`)
- `rule_id`: auth rule ID (decimal)
- `timeout`: remaining connection timeout (seconds)
- `rx_* / tx_*`: cumulative packet/byte counters
- `*_speed_*`: speed counters (sliding-window style stats in code)

Definitions:

```c
auth_status:
    AUTH_NONE = 0,
    AUTH_OK = 1,
    AUTH_BYPASS = 2,
    AUTH_REQ = 3,
    AUTH_NOAUTH = 4,
    AUTH_VIP = 5,
    AUTH_BLOCK = 6,
    AUTH_UNKNOWN = 15,

auth_type:
    AUTH_TYPE_UNKNOWN = 0
    AUTH_TYPE_AUTO = 1
    AUTH_TYPE_WEB = 2

rule_id:
    0~254, 255 = INVALID
```

---

### 1.2 Kick all users

Command:

```bash
echo 'kickall' >/dev/userinfo_ctl
```

Effect: clears auth state and counters for all tracked users (including packet/byte stats).

---

### 1.3 Kick a single user (IPv4 / IPv6)

Command:

```bash
echo 'kick <ip_or_ipv6>' >/dev/userinfo_ctl
```

Examples:

```bash
echo 'kick 1.2.3.4' >/dev/userinfo_ctl
echo 'kick 2001:db8:0:1:2:3:4:5' >/dev/userinfo_ctl
```

If the target user does not exist, the kernel returns `-ENOENT`.

---

### 1.4 Change user auth status (IPv4 / IPv6)

Command:

```bash
echo 'set-status <ip_or_ipv6> <status>' >/dev/userinfo_ctl
```

Example:

```bash
echo 'set-status 1.2.3.4 5' >/dev/userinfo_ctl
```

Notes:

- `<status>` is an integer (usually one of the `AUTH_*` enum values above)
- this command updates only `auth_status`

---

### 1.5 Per-user token control (IPv4 / IPv6)

Command:

```bash
echo 'set-token-ctrl <ip_or_ipv6> <rxbytes> <txbytes>' >/dev/userinfo_ctl
```

Example (for `192.168.15.100`, about 10 Mbps RX and 5 Mbps TX):

```bash
echo 'set-token-ctrl 192.168.15.100 1310720 655360' >/dev/userinfo_ctl
```

Notes:

- unit is **Bytes/s**
- if either `rxbytes` or `txbytes` is non-zero, token control is enabled for the user
- if both are zero, token control is disabled for the user

---

## 2. `/dev/qos_ctl`

### 2.1 Show current rules and usage hints

Command:

```bash
cat /dev/qos_ctl
```

Output contains:

- usage comments
- current `tc_classid_mode` value
- current rule list (each line in `add ...` format)

---

### 2.2 Clear all rules

```bash
echo 'clear' >/dev/qos_ctl
```

---

### 2.3 Toggle tc classid mode

```bash
echo 'tc_classid_mode=1' >/dev/qos_ctl   # enable
echo 'tc_classid_mode=0' >/dev/qos_ctl   # disable
```

When enabled, matching QoS rules can cooperate with `tc` using QoS/classid marking behavior.

---

### 2.4 Add a QoS rule

Template:

```bash
echo 'add user=<ipset/ip/ipcidr>,user_port=<portset/port>,remote=<ipset/ip/ipcidr>,remote_port=<portset/port>,proto=<tcp/udp>,rxbytes=<Bytes>,txbytes=<Bytes>' >/dev/qos_ctl
```

Parameter details:

- `user=` can be:
  - IPv4 (for example `192.168.1.10`)
  - IPv4 CIDR (for example `192.168.1.0/24`)
  - set name (for example `staff_group`)
- `user_port=`: port number or port-set name
- `remote=`: IPv4 / IPv4 CIDR / set name
- `remote_port=`: port number or port-set name
- `proto=`: `tcp` / `udp` / empty (empty means any)
- `rxbytes`, `txbytes`: Bytes/s

Example:

```bash
echo 'add user=192.168.1.0/24,user_port=,remote=,remote_port=,proto=tcp,rxbytes=1310720,txbytes=655360' >/dev/qos_ctl
```

Additional notes:

- capacity is limited by kernel constant `QOS_TOKEN_CTRL_GROUP_MAX`
- parser is strict; invalid format returns `-EINVAL`

---

### 2.5 Example: integration with tc

```bash
# 1) Enable natflow tc classid cooperation
echo 'tc_classid_mode=1' >/dev/qos_ctl

# 2) LAN side example: qos_id=1, download 10 Mbps
for lan in lan1 lan2 lan3 lan4 lan5 lan6 lan7 lan8 wan2; do
    tc qdisc del dev $lan root
    tc qdisc add dev $lan root handle 1: htb
    tc class add dev $lan parent 1: classid 1:1 htb rate 1310720Bps
    tc filter add dev $lan parent 1: protocol ip prio 1 handle 1 fw classid 1:1
    tc filter add dev $lan parent 1: protocol 0x8864 prio 2 handle 1 fw classid 1:1
done

# 3) WAN side example: qos_id=1, upload 5 Mbps
for wan in wan1; do
    tc qdisc del dev $wan root
    tc qdisc add dev $wan root handle 1: htb
    tc class add dev $wan parent 1: classid 1:1 htb rate 655360Bps
    tc filter add dev $wan parent 1: protocol ip prio 1 handle 1 fw classid 1:1
    tc filter add dev $wan parent 1: protocol 0x8864 prio 2 handle 1 fw classid 1:1
done
```

---

## 3. FAQ

1. **Command appears to do nothing**
   - Check whether the command string ends with newline (`echo` does by default, `echo -n` does not).

2. **`Invalid argument` returned**
   - Usually means a format problem (IP/CIDR/port/proto/`rxbytes,txbytes` syntax).

3. **`No such file or directory` returned**
   - Common for `kick` / `set-status` / `set-token-ctrl` when the target user is not found (kernel returns `-ENOENT`).
