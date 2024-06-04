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
