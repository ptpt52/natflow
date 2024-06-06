# ACL Management and URL Logging Guide

This document outlines the steps for managing Access Control Lists (ACL) and enabling URL logging. It includes commands for reading, adding, and clearing ACLs, as well as enabling the URL logger and reading URL logs.

## Read All ACLs

**API:** `cat /dev/hostacl_ctl`

**Output Example:**
```
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

### Definitions:

**id:** 0~31

**act:** 0~3
  - 0 = record
  - 1 = drop
  - 2 = reset
  - 3 = redirect

**host:** Hostname

### IPSET Integration

If the system creates an **ipset**, each ACL rule will match the **ipset** before applying ACL controls. The **ipset** format is `host_acl_rule<id>_<fml>`, where `<id>` is the ACL rule ID and `<fml>` can be `ipv4`, `ipv6`, or `mac`.

Example 1: Create an **ipset** `host_acl_rule0_ipv4` to make ACL0 apply controls only after matching an IPv4 address.
```
ipset create host_acl_rule0_ipv4 hash:net family inet
ipset add host_acl_rule0_ipv4 192.168.15.100
ipset add host_acl_rule0_ipv4 192.168.15.101
```

Example 2: Create an **ipset** `host_acl_rule0_ipv6` to make ACL0 apply controls only after matching an IPv6 address.
```
ipset create host_acl_rule0_ipv6 hash:net family inet6
ipset add host_acl_rule0_ipv6 2400::123
```

Example 3: Create an **ipset** `host_acl_rule0_mac` to make ACL0 apply controls only after matching an MAC address.
```
ipset create host_acl_rule0_mac hash:mac
ipset add host_acl_rule0_mac 11:22:33:aa:bb:cc
```

## Add One ACL

**API:** `echo add acl=<id>,<act>,<host> >/dev/hostacl_ctl`

**Example:** Add `baidu.com` to ACL with rule ID 0 and action 2 (reset).
```
echo add acl=0,2,baidu.com >/dev/hostacl_ctl
```

Add more to ACL0:
```
echo add acl=0,2,qq.com >/dev/hostacl_ctl
echo add acl=0,2,sina.com >/dev/hostacl_ctl
```

## Clear All ACLs

**API:** `echo clear >/dev/hostacl_ctl`

## Enable URL Logger

This step is necessary to make hostacl work.

**API:** `echo "1" >/proc/sys/urllogger_store/enable`

## Read URL Log (ACL Log)

**API:** `cat /dev/urllogger_queue`

### URL Log Format:
```
timestamp,mac,sip,sport,dip,dport,hits,method,type,acl_idx,acl_action,url
```

### Example Output:
```
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
**Note:** `acl_idx=64` indicates no ACL matched.

timestamp is uptime seconds, convert timestamp to date time:
```sh
#example time=timestamp
time=15682

UP=$(cat /proc/uptime | cut -d\. -f1)
UP=$((UP&0xffffffff))
NOW=$(date +%s)
T=$((NOW+time-UP))
T=$(date "+%Y-%m-%d %H:%M:%S" -d @$T)
echo $T
```
