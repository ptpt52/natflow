# Host ACL and URL Logging Guide

This document explains how to manage Host ACL rules through `/dev/hostacl_ctl` and how to verify rule hits through `urllogger`. It covers rule query/add/clear operations, optional IPSET integration, log field definitions, timestamp conversion, and a practical troubleshooting workflow.

---

## 1. Overview

Host ACL applies actions to connections based on **hostname (host)** matching.

- Control interface: `/dev/hostacl_ctl`
- URL logger switch: `/proc/sys/urllogger_store/enable`
- URL logger queue: `/dev/urllogger_queue`

> If URL logger is disabled, ACL-related observations are limited. Enable logger first when troubleshooting.

---

## 2. ACL Rule Model

Each rule is represented as: `<id>,<act>,<host>`

- `id`: Rule slot index, range `0~31`
- `act`: Action type, range `0~3`
  - `0` = `record`
  - `1` = `drop`
  - `2` = `reset`
  - `3` = `redirect`
- `host`: Hostname to match (for example: `baidu.com`)

You can append multiple hosts under the same `id`.

---

## 3. Read Current ACL Rules

### Command

```sh
cat /dev/hostacl_ctl
```

### Typical Output

```text
# Usage:
#    clear -- clear all existing acl rule(s)
#    add acl=<id>,<act>,<host> --add one rule
#    IPSET format: host_acl_rule<id>_<fml>
#    <fml>=ipv4/ipv6/mac
#

ACL0=
ACL1=
...
ACL31=
```

If `ACLx=` is empty, that slot currently has no rule.

---

## 4. Add ACL Rules

### Command Format

```sh
echo add acl=<id>,<act>,<host> >/dev/hostacl_ctl
```

### Examples

Add `baidu.com` into ACL slot `0` with action `reset(2)`:

```sh
echo add acl=0,2,baidu.com >/dev/hostacl_ctl
```

Append additional hosts to ACL0:

```sh
echo add acl=0,2,qq.com >/dev/hostacl_ctl
echo add acl=0,2,sina.com >/dev/hostacl_ctl
```

---

## 5. Clear All ACL Rules

```sh
echo clear >/dev/hostacl_ctl
```

> This removes all ACL rules. Confirm before running in production.

---

## 6. Optional: IPSET Integration

If an IPSET with the expected naming convention exists, ACL checks that IPSET before applying the configured action after host match.

Naming convention:

```text
host_acl_rule<id>_<fml>
```

Where:

- `<id>`: ACL rule ID (`0~31`)
- `<fml>`: `ipv4` / `ipv6` / `mac`

### Example 1: Apply ACL0 only to selected IPv4 sources

```sh
ipset create host_acl_rule0_ipv4 hash:net family inet
ipset add host_acl_rule0_ipv4 192.168.15.100
ipset add host_acl_rule0_ipv4 192.168.15.101
```

### Example 2: Apply ACL0 only to selected IPv6 sources

```sh
ipset create host_acl_rule0_ipv6 hash:net family inet6
ipset add host_acl_rule0_ipv6 2400::123
```

### Example 3: Apply ACL0 only to selected MAC sources

```sh
ipset create host_acl_rule0_mac hash:mac
ipset add host_acl_rule0_mac 11:22:33:aa:bb:cc
```

---

## 7. Enable URL Logger

URL logging should be enabled for ACL verification and debugging:

```sh
echo 1 >/proc/sys/urllogger_store/enable
```

Verify current status:

```sh
cat /proc/sys/urllogger_store/enable
```

---

## 8. Read ACL/URL Logs

### Command

```sh
cat /dev/urllogger_queue
```

### Log Format

```text
timestamp,mac,sip,sport,dip,dport,hits,method,type,acl_idx,acl_action,url
```

### Field Definitions

- `timestamp`: Uptime-based seconds (not Unix epoch)
- `mac`: Source MAC address
- `sip/sport`: Source IP / source port
- `dip/dport`: Destination IP / destination port
- `hits`: Hit count
- `method`: HTTP method (`NONE` for non-HTTP traffic)
- `type`: Traffic type (for example `HTTP`, `SSL`)
- `acl_idx`: Matched ACL rule ID
- `acl_action`: Executed ACL action code
- `url`: Parsed URL / host

> `acl_idx=64` means no ACL rule matched.

### Sample Output

```text
15682,74:8F:AA:BB:BE:CD,192.168.16.101,61938,129.226.103.123,443,1,NONE,SSL,64,0,otheve.beacon.qq.com
15684,74:8F:AA:BB:BE:CD,fd57:538a:7ca5:0000:18c5:8212:7bc2:086f,61940,240e:097c:002f:0002:0000:0000:0000:005c,443,1,NONE,SSL,64,0,tpstelemetry.tencent.com
15693,74:8F:AA:BB:BE:CD,192.168.16.101,61957,8.8.8.8,443,4,NONE,SSL,64,0,dns.google
15694,74:8F:AA:BB:BE:CD,fd57:538a:7ca5:0000:18c5:8212:7bc2:086f,61963,2402:4e00:0036:2fff:0000:0000:0000:008a,443,1,NONE,SSL,64,0,cube.weixinbridge.com
15694,74:8F:AA:BB:BE:CD,fd57:538a:7ca5:0000:18c5:8212:7bc2:086f,61964,2402:4e00:1020:262a:0000:9966:18c7:41fe,443,1,NONE,SSL,64,0,doc.weixin.qq.com
15694,74:8F:AA:BB:BE:CD,fd57:538a:7ca5:0000:18c5:8212:7bc2:086f,61965,240e:097c:002f:0001:0000:0000:0000:006e,443,1,NONE,SSL,64,0,aegis.qq.com
15698,74:8F:AA:BB:BE:CD,192.168.16.101,61968,18.182.251.125,443,1,NONE,SSL,64,0,fx-webws.gateio.live
15701,74:8F:AA:BB:BE:CD,192.168.16.101,61970,113.240.75.249,443,1,NONE,SSL,64,0,tpstelemetry.tencent.com
15720,24:0A:AA:CC:8D:4E,192.168.16.224,53230,185.125.190.96,80,1,GET,HTTP,64,0,connectivity-check.ubuntu.com/
```

---

## 9. Convert `timestamp` to Date-Time

`timestamp` is based on system uptime seconds. Use the following shell snippet to convert it into wall-clock time:

```sh
# Example: time=timestamp from log
time=15682

UP=$(cat /proc/uptime | cut -d. -f1)
UP=$((UP & 0xffffffff))
NOW=$(date +%s)
T=$((NOW + time - UP))
date "+%Y-%m-%d %H:%M:%S" -d "@$T"
```

---

## 10. Recommended Troubleshooting Workflow

1. Run `cat /proc/sys/urllogger_store/enable` and confirm it is `1`.
2. Run `cat /dev/hostacl_ctl` and verify `id/act/host` values are expected.
3. If using IPSET, verify exact set naming: `host_acl_rule<id>_<fml>`.
4. Run `cat /dev/urllogger_queue` and check whether target host appears.
5. If `acl_idx` remains `64`, focus on host spelling, traffic type, and slot/action configuration.
