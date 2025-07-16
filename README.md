# NATflow

NATflow works by matching packets against a hash table to quickly determine forwarding information, performing necessary NAT and MAC modifications, and directly sending matched packets to the NIC, while unmatched packets follow the traditional slow path for processing.

## Graph

Fast Path with natflow:
```mermaid
graph TB
    A[NIC] ==> B[nf_ingress]
    B ==> K[natflow: Match hash table for info]
    K --> |If not matched| C[PRE_ROUTING]
    subgraph SlowPath
        direction TB
         C --> D[Routing Decision]
        D --> E[FORWARD]
        E --> F[POST_ROUTING]
        D -.-> I[LOCAL_IN]
        J[LOCAL_OUT] -.-> F
    end
    F --> G[nf_hook_egress]
    G --> H[NIC]
    K ==> |If matched| L["Modify packet (NAT & MAC)"]
    L ==> |sends directly to NIC| H
    A --> |ppe: hardware offload forward| H
```

## Notes
**natflow** is a versatile and high-performance network acceleration solution that provides the following key features:

1. **Fastpath for High-Speed Packet Forwarding** :
  * Implements a software-based fast path for rapid packet forwarding.
  * Works on any platform, delivering exceptional forwarding performance.
2. **Hardware NAT (hwnat) Support** :
  * For specific platforms like **MT7621** , **MT7622** , **MT7981** , **MT7986** , and others, **natflow** provides hardware NAT support, enabling hardware-based acceleration for even higher performance.
  * Requires kernel patches for proper integration.
3. **User Identification and Traffic Auditing** :
  * Identifies individual IP users and monitors their traffic and speed.
  * Provides detailed traffic auditing for user-level insights.
4. **Traffic Control (QoS)** :
  * Enables bandwidth management and traffic shaping for users.
  * Ensures fair usage and optimized network performance.
5. **Internet Access Control** :
  * Allows or blocks internet access for specific users based on policies.
6. **URL Auditing (urllogger)** :
  * Monitors and logs the domains or URLs accessed by users.
  * Offers visibility into user browsing behavior.
7. **Website Access Control** :
  * Matches user traffic against defined rules to restrict access to specific websites.

**natflow** combines software fast path, hardware acceleration (on supported platforms), and advanced user management and auditing features, making it ideal for performance-critical and policy-driven network environments.

## Natflow Hardware Acceleration Overview

### Hardware Acceleration Support on X-WRT

**Natflow** now supports hardware acceleration on [X-WRT](https://github.com/x-wrt/x-wrt), providing high-performance NAT and packet forwarding capabilities.

---

### Supported Platforms

1. Hardware NAT (Hwnat) Support:
- Platforms: **MT7621**, **MT7622**, **MT7981**, **MT7986**
- Enables efficient hardware-based NAT forwarding.

2. Hwnat with WED Support:
- Platforms: **MT7622**, **MT7981**, **MT7986**
- Combines hardware NAT acceleration with WED (Wireless Ethernet Dispatch) support to optimize both WiFi and wired traffic.

---

### Supported Forwarding Paths

1. **Port-to-Port Hwnat Forwarding**
- **Forwarding Path**:
  - `Port --> PPE --> Port`
  - `Port <-- PPE <-- Port`

2. **WiFi-to-Port Hwnat Forwarding**
- **Forwarding Path**:
  - `WiFi --> CPU --> PPE --> Port`
  - `WiFi <-- CPU <-- PPE <-- Port`

3. **WiFi-to-Port Hwnat Forwarding with WED Support**
- **Forwarding Path**:
  - `WiFi --> CPU --> PPE --> Port`
  - `WiFi <-- PPE <-- Port`

---

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
