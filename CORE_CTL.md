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
  Range: `0..63`. Combine bits by summing them. Bits: `1=error`, `2=warn`, `4=info`, `8=debug`, `16=fixme`, `32=debug_ratelimited`.

- **Hardware Acceleration:** (Available on supported MediaTek platforms)
  `echo 'hwnat=1' > /dev/natflow_ctl`
  `echo 'hwnat_wed_disabled=1' > /dev/natflow_ctl`

- **Vline and Relay mappings:**
  `echo 'vline_add=<src_ifname>,<dst_ifname>,<family>' > /dev/natflow_ctl`
  `echo 'relay_add=<src_ifname>,<dst_ifname>,<family>' > /dev/natflow_ctl`
  `echo 'vline_apply' > /dev/natflow_ctl`
  `echo 'vline_clear' > /dev/natflow_ctl`

  Vline/relay parameters and limits:

  - `<src_ifname>` is the source-side interface and `<dst_ifname>` is the peer interface. The mapping is installed in both directions when `vline_apply` succeeds.
  - Interface names are matched exactly against kernel `net_device->name`. Each name must fit Linux `IFNAMSIZ`: at most 15 visible characters, no comma.
  - Both named devices must already exist in `init_net` when `vline_apply` runs.
  - Do not pass an enslaved lower device as `<src_ifname>` or `<dst_ifname>`; devices with a master upper device are rejected. For bridge setups, pass the bridge master name (for example `br-lan`) and NATflow will install map entries on its lower ports.
  - Every actual ingress device that receives a map entry must have `ifindex < 64`. For a non-bridge endpoint this is the named device itself; for a bridge endpoint this applies to each lower port of the bridge.
  - `family` must be exactly one of `ipv4`, `ipv6`, or `all`.
  - `IFF_NOARP` devices are restricted: the source endpoint must not be `IFF_NOARP`; `relay_add` also requires the destination endpoint to not be `IFF_NOARP`. Plain `vline_add` allows an `IFF_NOARP` destination only when `family=ipv6`.
  - At most 8 vline/relay rules can be queued before `vline_apply`.
  - `vline_add` and `relay_add` only update the pending configuration. Use `vline_apply` to rebuild the runtime forwarding map, and `vline_clear` to clear both pending config and runtime vline state.

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
