## read all ACL

API: `cat /dev/hostacl_ctl`

OUTPUT:
```
# Usage:
#    clear -- clear all existing acl rule(s)
#    add acl=<id>,<act>,<host> --add one rule
#

ACL=:
```

define:
```
<id>: 0~31

<act>: 0~3
	0 = record
	1 = drop
	2 = reset
	3 = redirct

<host>: Hostname
```

## add one ACL

API: `echo add acl=<id>,<act>,<host> >/dev/hostacl_ctl`

EXAMPLE: add baidu.com to ACL, rule id = 0, action = 2(reset)
```
echo add acl=0,2,baidu.com >/dev/hostacl_ctl
```

## clear all ACL

API: `echo clear >/dev/hostacl_ctl`

## enable urllogger

This is needed to make hostacl work.

API: `echo "1" >/proc/sys/urllogger_store/enable`

## read url log (ACL log)

API: `cat /dev/urllogger_queue`

URL log format:
```
timestamp,mac,sip,sport,dip,dport,hits,method,type,acl_idx,acl_action,url

example:
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
Note: `acl_idx=64` indicates no ACL matched.
