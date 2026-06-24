# NATflow Core and System Control Guide (CORE_CTL.md)

[← Back to Main README](README.md)

This document covers the core system, zone classification, and debugging interfaces for NATflow.

## 1. `/dev/natflow_ctl`

This is the primary global control interface for NATflow fast-path engine and hardware offloading configurations.

### 1.1 Show current configuration

```bash
cat /dev/natflow_ctl
```

### 1.2 Configuration Commands

> Note: Make sure to terminate commands with `\n` when writing scripts.

- **Enable/Disable NATflow:**
  `echo 'disabled=1' > /dev/natflow_ctl` (Disable)
  `echo 'disabled=0' > /dev/natflow_ctl` (Enable)

- **Set Debug Level:**
  `echo 'debug=<num>' > /dev/natflow_ctl`

- **Hardware Acceleration:** (Available on supported MediaTek platforms)
  `echo 'hwnat=1' > /dev/natflow_ctl`
  `echo 'hwnat_wed_disabled=1' > /dev/natflow_ctl`

- **Vline and Relay mappings:**
  `echo 'vline_add=<ifname>,<ifname>,<family>' > /dev/natflow_ctl` (family: ipv4/ipv6/all)
  `echo 'relay_add=<ifname>,<ifname>,<family>' > /dev/natflow_ctl`
  `echo 'vline_apply' > /dev/natflow_ctl`
  `echo 'vline_clear' > /dev/natflow_ctl`

---

## 2. `/dev/natflow_zone_ctl`

Defines which network interfaces belong to LAN vs. WAN zones. NATflow caches this classification internally (using `dev->name` padding or structural flags) to accelerate processing.

### 2.1 View Zones

```bash
cat /dev/natflow_zone_ctl
```

### 2.2 Manage Zones

- **Set LAN Zone:**
  `echo 'lan_zone <id>=<if_name>' > /dev/natflow_zone_ctl`
  *(e.g., `echo 'lan_zone 1=eth0' > /dev/natflow_zone_ctl`)*

- **Set WAN Zone:**
  `echo 'wan_zone <id>=<if_name>' > /dev/natflow_zone_ctl`

- **Wildcard interfaces:** You can use `+` to match multiple interfaces (e.g., `eth+`).

- **Apply/Update:**
  `echo 'update_match' > /dev/natflow_zone_ctl`

- **Clear all:**
  `echo 'clean' > /dev/natflow_zone_ctl`

---

## 3. `/dev/conntrackinfo_ctl`

Used to dump the internal connection tracking snapshot.

```bash
cat /dev/conntrackinfo_ctl
```

This interface is read-only and will stream the details of active TCP/UDP connections that NATflow is accelerating, including packet and byte counts, statuses, timeouts, and corresponding NAT properties.
