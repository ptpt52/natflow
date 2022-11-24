
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
