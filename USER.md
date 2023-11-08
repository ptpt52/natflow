## read all userinfo

API: `cat /dev/userinfo_ctl`

OUTPUT: `ip,mac,auth_type,auth_status,rule_id,timeout,rx_pkts:rx_bytes,tx_pkts:tx_bytes,rx_speed_pkts:rx_speed_bytes,tx_speed_pkts:tx_speed_bytes`

define:
```
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
	AUTH_TYPE_UNKNOWN 0
	AUTH_TYPE_AUTO 1
	AUTH_TYPE_WEB 2

rule_id: 0~254, 255=INVALID
```

## kick all users

API: `echo kickall >/dev/userinfo_ctl`

## kick user

API: `echo kick ip >/dev/userinfo_ctl`

example: `echo kick 1.2.3.4 >/dev/userinfo_ctl`

## change user status

API: `echo set-status ip status >/dev/userinfo_ctl`

example: `echo set-status 1.2.3.4 5 >/dev/userinfo_ctl`

## token ctrl

API: `echo set-token-ctrl ip rxbytes txbytes >/dev/userinfo_ctl`

e.g. rx rate 10Mbps tx rate 5Mbps for 192.168.15.100:
```
echo set-token-ctrl 192.168.15.100 1310720 655360 >/dev/userinfo_ctl
```

## qos rules

API:
1. clear all rules:
```
echo clear >/dev/qos_ctl
```
2. add one rule:
```
echo add user=<ipset/ip/ipcidr>,user_port=<portset/port>,remote=<ipset/ip/ipcidr>,remote_port=<portset/port>,proto=<tcp/udp>,rxbytes=0,txbytes=0 >/dev/qos_ctl
```
3. natflow QoS rules work in conjunction with tc
```
# Filter the flow/packets using natflow and set the skb->mark to a specified QoS identifier
echo tc_classid_mode=1 >/dev/qos_ctl

# Set the tc QoS for qos_id=1 on LAN for a download speed of 10Mbps
for lan in lan1 lan2 lan3 lan4 lan5 lan6 lan7 lan8 wan2; do
	tc qdisc del dev $lan root
	tc qdisc add dev $lan root handle 1: htb
	tc class add dev $lan parent 1: classid 1:1 htb rate 1310720Bps
	tc filter add dev $lan parent 1: protocol ip prio 1 handle 1 fw classid 1:1
	tc filter add dev $lan parent 1: protocol 0x8864 prio 2 handle 1 fw classid 1:1
done

# Set the tc QoS for qos_id=1 on WAN for an upload speed of 5Mbps
for wan in wan1; do
	tc qdisc del dev $wan root
	tc qdisc add dev $wan root handle 1: htb
	tc class add dev $wan parent 1: classid 1:1 htb rate 655360Bps
	tc filter add dev $wan parent 1: protocol ip prio 1 handle 1 fw classid 1:1
	tc filter add dev $wan parent 1: protocol 0x8864 prio 2 handle 1 fw classid 1:1
done
```
