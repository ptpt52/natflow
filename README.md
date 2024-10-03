# NATflow

A fast forwarding stanalone kernel module with zero-patch to kernel. It could be a lite replacement of kmod-ipt-offload.

## Notes
Only work for x-wrt(https://github.com/x-wrt/x-wrt)

hwnat support for mt7621/mt7622/MT7981/MT7986

hwnat with wed support for mt7622/MT7981/MT7986
```
port--port hwnat supported:
port-->ppe-->port
port<--ppe<--port

wifi--port hwnat supported:
wifi-->cpu-->ppe-->port
wifi<--cpu<--ppe<--port

wifi-port hwnat with wed supported:
wifi-->cpu-->ppe-->port
wifi<--ppe<--port
```

## build
To build with path and urllogger module run:
```
make EXTRA_CFLAGS="-DCONFIG_NATFLOW_PATH -DCONFIG_NATFLOW_URLLOGGER"
```

`CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH` option to make hwnat ext dev work via vlan hash mode, this mode would disable bridge vlan filter. this is required on MT7622 if hwnat ext dev is needed.
```
make EXTRA_CFLAGS="-DCONFIG_HWNAT_EXTDEV_USE_VLAN_HASH"
```

`CONFIG_HWNAT_EXTDEV_DISABLED` option to disable hwnat ext dev. if this is set, bridge vlan filter could be sure to work on MT7622.
```
make EXTRA_CFLAGS="-DCONFIG_HWNAT_EXTDEV_DISABLED"
```

## Warnning
Since `kernel < 4.10` cannot handle NF_STOLEN in ingress hook correctly, so kernel patch needed:
```diff
diff --git a/include/linux/netfilter_ingress.h b/include/linux/netfilter_ingress.h
index 5fcd375ef175..b407128a35c0 100644
--- a/include/linux/netfilter_ingress.h
+++ b/include/linux/netfilter_ingress.h
@@ -17,11 +17,15 @@ static inline bool nf_hook_ingress_active(const struct sk_buff *skb)
 static inline int nf_hook_ingress(struct sk_buff *skb)
 {
        struct nf_hook_state state;
+       int ret;
 
        nf_hook_state_init(&state, &skb->dev->nf_hooks_ingress,
                           NF_NETDEV_INGRESS, INT_MIN, NFPROTO_NETDEV,
                           skb->dev, NULL, NULL, dev_net(skb->dev), NULL);
-       return nf_hook_slow(skb, &state);
+       ret = nf_hook_slow(skb, &state);
+       if (ret == 0)
+               return -1;
+       return ret;
 }
 
 static inline void nf_hook_ingress_init(struct net_device *dev)
diff --git a/net/netfilter/core.c b/net/netfilter/core.c
index f39276d1c2d7..905597547b08 100644
--- a/net/netfilter/core.c
+++ b/net/netfilter/core.c
@@ -320,6 +320,8 @@ next_hook:
                                goto next_hook;
                        kfree_skb(skb);
                }
+       } else if (verdict == NF_STOLEN) {
+               ret = 0;
        }
        rcu_read_unlock();
        return ret;
```

## Donate
Buy me a beer!

[<img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif">](https://paypal.me/ptpt52)

BITCOIN ADDR: `3CJ5VwxL8ageKpA3jJ561rvhkFW4FmZiqc`
