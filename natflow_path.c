/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 May 2018 14:49:40 +0800
 */
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <net/ndisc.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
#include <net/netfilter/nf_flow_table.h>
#endif
#include "natflow_common.h"
#include "natflow_path.h"
#include "natflow_user.h"

#ifndef ARPHRD_RAWIP
#define ARPHRD_RAWIP 519
#endif

#define VLINE_FWD_MAX_NUM 64
#define VLINE_FWD_MAP_CONFIG_NUM 8
static struct net_device *vline_fwd_map[VLINE_FWD_MAX_NUM];
static unsigned char vline_fwd_map_config[VLINE_FWD_MAP_CONFIG_NUM][2][IFNAMSIZ];
static unsigned char vline_fwd_map_family_config[VLINE_FWD_MAP_CONFIG_NUM];

unsigned char (*vline_fwd_map_config_get(unsigned int idx, unsigned char *family))[2][IFNAMSIZ]
{
	if  (idx >= VLINE_FWD_MAP_CONFIG_NUM || vline_fwd_map_config[idx][0][0] == 0)
		return NULL;
	*family = vline_fwd_map_family_config[idx];
	return &vline_fwd_map_config[idx];
}

int vline_fwd_map_config_add(const unsigned char *dst_ifname, const unsigned char *src_ifname, unsigned char family)
{
	int i;
	for (i = 0; i < VLINE_FWD_MAP_CONFIG_NUM; i++) {
		if (vline_fwd_map_config[i][0][0] == 0) {
			strncpy(vline_fwd_map_config[i][0], src_ifname, IFNAMSIZ);
			strncpy(vline_fwd_map_config[i][1], dst_ifname, IFNAMSIZ);
			vline_fwd_map_family_config[i] = family;
			return 0;
		}
	}
	return -ENOMEM;
}

void vline_fwd_map_config_clear(void)
{
	int i;
	for (i = 0; i < VLINE_FWD_MAP_CONFIG_NUM; i++) {
		vline_fwd_map_config[i][0][0] = 0;
	}
}

static inline int vline_fwd_map_add(const unsigned char *dst_ifname, const unsigned char *src_ifname, unsigned char family, int is_relay)
{
	int ret = 0;
	struct net_device *dev;
	struct net_device *dst_dev = NULL, *src_dev = NULL;

	rcu_read_lock();
	dev = first_net_device(&init_net);
	while (dev) {
		if (strncmp(dev->name, dst_ifname, IFNAMSIZ) == 0) {
			if (netdev_master_upper_dev_get_rcu(dev)) {
				rcu_read_unlock();
				NATFLOW_println("vline config invalid dst %s,%s,%s",
				                src_ifname, dst_ifname,
				                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
				return -EINVAL;
			}
			if ((dev->flags & IFF_NOARP) && family != VLINE_FAMILY_IPV6) {
				rcu_read_unlock();
				NATFLOW_println("vline config invalid dst %s,%s,%s should not be IFF_NOARP, or family should be ipv6 only",
				                src_ifname, dst_ifname,
				                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
				return -EINVAL;
			}
			dst_dev = dev;
		} else if (strncmp(dev->name, src_ifname, IFNAMSIZ) == 0) {
			if (netdev_master_upper_dev_get_rcu(dev)) {
				rcu_read_unlock();
				NATFLOW_println("vline config invalid src %s,%s,%s",
				                src_ifname, dst_ifname,
				                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
				return -EINVAL;
			}
			if ((dev->flags & IFF_NOARP) && family != VLINE_FAMILY_IPV6) {
				rcu_read_unlock();
				NATFLOW_println("vline config invalid src %s,%s,%s should not be IFF_NOARP, or family should be ipv6 only",
				                src_ifname, dst_ifname,
				                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
				return -EINVAL;
			}
			src_dev = dev;
		}
		if (src_dev && dst_dev) {
			break;
		}
		dev = next_net_device(dev);
	}

	if (src_dev && dst_dev) {
		src_dev->flags |= IFF_IS_LAN;
		dst_dev->flags &= ~IFF_IS_LAN;
		if ((src_dev->flags & IFF_NOARP)) {
			rcu_read_unlock();
			NATFLOW_println("vline config invalid %s,%s,%s src_dev should not be IFF_NOARP",
			                src_ifname, dst_ifname,
			                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
			return -EINVAL;
		}

		if (is_relay) {
			if ((dst_dev->flags & IFF_NOARP)) {
				rcu_read_unlock();
				NATFLOW_println("vline relay config invalid %s,%s,%s dev should not be IFF_NOARP",
				                src_ifname, dst_ifname,
				                family == VLINE_FAMILY_IPV4 ? "ipv4" : family == VLINE_FAMILY_IPV6 ? "ipv6" : "all");
				return -EINVAL;
			}
			src_dev->flags |= IFF_VLINE_RELAY;
			dst_dev->flags |= IFF_VLINE_RELAY;
		} else {
			src_dev->flags &= ~IFF_VLINE_RELAY;
			dst_dev->flags &= ~IFF_VLINE_RELAY;
		}

		if (family == VLINE_FAMILY_IPV4) {
			src_dev->flags &= ~IFF_VLINE_FAMILY_IPV6;
			src_dev->flags |= IFF_VLINE_FAMILY_IPV4;
			dst_dev->flags &= ~IFF_VLINE_FAMILY_IPV6;
			dst_dev->flags |= IFF_VLINE_FAMILY_IPV4;
		} else if (family == VLINE_FAMILY_IPV6) {
			src_dev->flags &= ~IFF_VLINE_FAMILY_IPV4;
			src_dev->flags |= IFF_VLINE_FAMILY_IPV6;
			dst_dev->flags &= ~IFF_VLINE_FAMILY_IPV4;
			dst_dev->flags |= IFF_VLINE_FAMILY_IPV6;
		} else {
			src_dev->flags &= ~(IFF_VLINE_FAMILY_IPV4 | IFF_VLINE_FAMILY_IPV6);
			dst_dev->flags &= ~(IFF_VLINE_FAMILY_IPV4 | IFF_VLINE_FAMILY_IPV6);
		}

		if (netif_is_bridge_master(src_dev)) {
			struct net_device *upper_dev;
			dev = first_net_device(&init_net);
			while (dev) {
				upper_dev = netdev_master_upper_dev_get_rcu(dev);
				if (upper_dev == src_dev) {
					dev->flags |= IFF_IS_LAN;
					dev->flags |= IFF_VLINE_L2_PORT;
					if (family == VLINE_FAMILY_IPV4) {
						dev->flags &= ~IFF_VLINE_FAMILY_IPV6;
						dev->flags |= IFF_VLINE_FAMILY_IPV4;
					} else if (family == VLINE_FAMILY_IPV6) {
						dev->flags &= ~IFF_VLINE_FAMILY_IPV4;
						dev->flags |= IFF_VLINE_FAMILY_IPV6;
					} else {
						dev->flags &= ~(IFF_VLINE_FAMILY_IPV4 | IFF_VLINE_FAMILY_IPV6);
					}
					if (dev->ifindex >= VLINE_FWD_MAX_NUM) {
						NATFLOW_println("update %s(%s)->%s failed, ifindex(%u) >= %u", dev->name, src_dev->name, dst_dev->name, dev->ifindex, VLINE_FWD_MAX_NUM);
						rcu_read_unlock();
						return -EINVAL;
					}
					vline_fwd_map[dev->ifindex] = dst_dev;
					NATFLOW_println("update %s(%s)->%s", dev->name, src_dev->name, dst_dev->name);
				}
				dev = next_net_device(dev);
			}
		} else {
			src_dev->flags &= ~IFF_VLINE_L2_PORT;
			if (src_dev->ifindex >= VLINE_FWD_MAX_NUM) {
				NATFLOW_println("update %s->%s failed, ifindex(%u) >= %u", src_dev->name, dst_dev->name, src_dev->ifindex, VLINE_FWD_MAX_NUM);
				rcu_read_unlock();
				return -EINVAL;
			}
			vline_fwd_map[src_dev->ifindex] = dst_dev;
			NATFLOW_println("update %s->%s", src_dev->name, dst_dev->name);
		}

		if (netif_is_bridge_master(dst_dev)) {
			struct net_device *upper_dev;
			dev = first_net_device(&init_net);
			while (dev) {
				upper_dev = netdev_master_upper_dev_get_rcu(dev);
				if (upper_dev == dst_dev) {
					dev->flags &= ~IFF_IS_LAN;
					dev->flags |= IFF_VLINE_L2_PORT;
					if (family == VLINE_FAMILY_IPV4) {
						dev->flags &= ~IFF_VLINE_FAMILY_IPV6;
						dev->flags |= IFF_VLINE_FAMILY_IPV4;
					} else if (family == VLINE_FAMILY_IPV6) {
						dev->flags &= ~IFF_VLINE_FAMILY_IPV4;
						dev->flags |= IFF_VLINE_FAMILY_IPV6;
					} else {
						dev->flags &= ~(IFF_VLINE_FAMILY_IPV4 | IFF_VLINE_FAMILY_IPV6);
					}
					if (dev->ifindex >= VLINE_FWD_MAX_NUM) {
						NATFLOW_println("update %s(%s)->%s failed, ifindex(%u) >= %u", dev->name, dst_dev->name, src_dev->name, dev->ifindex, VLINE_FWD_MAX_NUM);
						rcu_read_unlock();
						return -EINVAL;
					}
					vline_fwd_map[dev->ifindex] = src_dev;
					NATFLOW_println("update %s(%s)->%s", dev->name, dst_dev->name, src_dev->name);
				}
				dev = next_net_device(dev);
			}
		} else {
			dst_dev->flags &= ~IFF_VLINE_L2_PORT;
			if (dst_dev->ifindex >= VLINE_FWD_MAX_NUM) {
				NATFLOW_println("update %s->%s failed, ifindex(%u) >= %u", dst_dev->name, src_dev->name, dst_dev->ifindex, VLINE_FWD_MAX_NUM);
				rcu_read_unlock();
				return -EINVAL;
			}
			vline_fwd_map[dst_dev->ifindex] = src_dev;
			NATFLOW_println("update %s->%s", dst_dev->name, src_dev->name);
		}
	} else {
		ret = -ENODEV;
	}
	rcu_read_unlock();

	return ret;
}

int vline_fwd_map_config_apply(void)
{
	int i;
	int err = 0, ret = 0;
	for (i = 0; i < VLINE_FWD_MAX_NUM; i++) {
		vline_fwd_map[i] = NULL;
	}
	NATFLOW_println("apply config");
	for (i = 0; i < VLINE_FWD_MAP_CONFIG_NUM; i++) {
		if (vline_fwd_map_config[i][0][0] == 0) {
			break;
		}
		err = vline_fwd_map_add(vline_fwd_map_config[i][1], vline_fwd_map_config[i][0],
		                        vline_fwd_map_family_config[i] & VLINE_FAMILY_MASK,
		                        !!(vline_fwd_map_family_config[i] & VLINE_RELAY_MASK));
		if (err != 0)
			ret = err;
	}
	return ret;
}

static inline int vline_fwd_map_ifup_handle(struct net_device *dev)
{
	int i;
	struct net_device *upper_dev;

	/*
	if (netif_is_bridge_master(dev) || netif_is_bond_master(dev) || netif_is_team_master(dev) || netif_is_ovs_master(dev)) {
		return -EINVAL;
	}
	*/

	rcu_read_lock();
	upper_dev = netdev_master_upper_dev_get_rcu(dev);
	for (i = 0; i < VLINE_FWD_MAP_CONFIG_NUM; i++) {
		if (vline_fwd_map_config[i][0][0] == 0) {
			break;
		}
		if (upper_dev) {
			if (strncmp(upper_dev->name, vline_fwd_map_config[i][0], IFNAMSIZ) == 0 ||
			        strncmp(upper_dev->name, vline_fwd_map_config[i][1], IFNAMSIZ) == 0) {
				rcu_read_unlock();
				NATFLOW_println("handle event for dev=%s", dev->name);
				return vline_fwd_map_add(vline_fwd_map_config[i][1], vline_fwd_map_config[i][0],
				                         vline_fwd_map_family_config[i] & VLINE_FAMILY_MASK,
				                         !!(vline_fwd_map_family_config[i] & VLINE_RELAY_MASK));
			}
		}
		if (strncmp(dev->name, vline_fwd_map_config[i][0], IFNAMSIZ) == 0 ||
		        strncmp(dev->name, vline_fwd_map_config[i][1], IFNAMSIZ) == 0) {
			rcu_read_unlock();
			NATFLOW_println("handle event for dev=%s", dev->name);
			return vline_fwd_map_add(vline_fwd_map_config[i][1], vline_fwd_map_config[i][0],
			                         vline_fwd_map_family_config[i] & VLINE_FAMILY_MASK,
			                         !!(vline_fwd_map_family_config[i] & VLINE_RELAY_MASK));
		}
	}
	rcu_read_unlock();

	return 0;
}

static inline int vline_fwd_map_unregister_handle(struct net_device *dev)
{
	int i;

	if (dev->ifindex >= VLINE_FWD_MAX_NUM) {
		return 0;
	}
	if (vline_fwd_map[dev->ifindex] != NULL) {
		vline_fwd_map[dev->ifindex] = NULL;
		NATFLOW_println("handle event for dev=%s", dev->name);
	}

	for (i = 0; i < VLINE_FWD_MAX_NUM; i++) {
		if (vline_fwd_map[i] == dev) {
			vline_fwd_map[i] = NULL;
		}
	}

	return 0;
}

void list_net_device_debug(void)
{
	struct net_device *dev;
	rcu_read_lock();
	dev = first_net_device(&init_net);
	while (dev) {
		NATFLOW_println("dev=%s (%d): flags=0x%08x", dev->name, dev->ifindex, dev->flags);
		dev = next_net_device(dev);
	}
	rcu_read_unlock();
}

static inline struct net_device *vlan_find_dev_rcu(struct net_device *real_dev,
        __be16 vlan_proto, u16 vlan_id)
{
	if (real_dev->vlan_info)
		return __vlan_find_dev_deep_rcu(real_dev, vlan_proto, vlan_id);
	return NULL;
}

#define fastnat_for_all 0
#define fastnat_ifname_group_only 1
#define fastnat_ifname_group_bypass 2
int ifname_group_type = fastnat_for_all;

int ifname_group_add(const unsigned char *ifname)
{
	int ret = -ENOENT;
	struct net_device *dev;

	rcu_read_lock();
	dev = first_net_device(&init_net);
	while (dev) {
		if (strncmp(dev->name, ifname, IFNAMSIZ) == 0) {
			dev->flags |= IFF_IFNAME_GROUP;
			NATFLOW_println("Success ifname_group_add %s", ifname);
			ret = 0;
			break;
		}
		dev = next_net_device(dev);
	}
	rcu_read_unlock();

	return ret;
}

void ifname_group_clear(void)
{
	struct net_device *dev = NULL;

	rcu_read_lock();
	dev = first_net_device(&init_net);
	while (dev) {
		if ((dev->flags & IFF_IFNAME_GROUP)) {
			dev->flags &= ~IFF_IFNAME_GROUP;
		}
		dev = next_net_device(dev);
	}
	rcu_read_unlock();
}

struct net_device *ifname_group_get(int idx)
{
	int idx_cnt = 0;
	struct net_device *dev = NULL;

	rcu_read_lock();
	dev = first_net_device(&init_net);
	while (dev) {
		if ((dev->flags & IFF_IFNAME_GROUP)) {
			idx_cnt++;
			if (idx_cnt == idx + 1) {
				dev_hold(dev);
				break;
			}
		}
		dev = next_net_device(dev);
	}
	rcu_read_unlock();

	return dev;
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
unsigned short hwnat = 1;
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
unsigned short hwnat_wed_disabled = 0;
#else
unsigned short hwnat_wed_disabled = 1;
#endif
#endif
unsigned int delay_pkts = 0;
unsigned int go_slowpath_if_no_qos = 0;

static int disabled = 1;
void natflow_disabled_set(int v)
{
	disabled = v;
}
int natflow_disabled_get(void)
{
	return disabled;
}

static unsigned short natflow_path_magic = 0;
void natflow_update_magic(int init)
{
	if (init) {
		natflow_path_magic = jiffies + get_random_u32();
	} else {
		natflow_path_magic++;
	}
}

#ifdef CONFIG_NETFILTER_INGRESS
static natflow_fastnat_node_t *natflow_fast_nat_table = NULL;

static inline void natflow_update_ct_timeout(struct nf_conn *ct, unsigned long extra_jiffies)
{
	if (!nf_ct_is_confirmed(ct)) {
		/* nothing to do */
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		extra_jiffies += ct->timeout.expires;
		if (extra_jiffies - ct->timeout.expires >= HZ) {
			mod_timer_pending(&ct->timeout, extra_jiffies);
		}
#else
		extra_jiffies += ct->timeout;
		ct->timeout = extra_jiffies;
#endif
	}
}

static inline natflow_fastnat_node_t *nfn_invert_get(natflow_fastnat_node_t *nfn) {
	unsigned int hash;
	unsigned long diff_jiffies;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = nfn->saddr;
	tuple.src.u.all = nfn->source;
	tuple.dst.u3.ip = nfn->daddr;
	tuple.dst.u.all = nfn->dest;
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = NFN_PROTO_DEC(nfn->flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		int d = !NF_CT_DIRECTION(h);
		__be32 saddr = ct->tuplehash[d].tuple.src.u3.ip;
		__be32 daddr = ct->tuplehash[d].tuple.dst.u3.ip;
		__be16 source = ct->tuplehash[d].tuple.src.u.all;
		__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
		__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;

		hash = natflow_hash_v4(saddr, daddr, source, dest);
		nfn = &natflow_fast_nat_table[hash];
		if (nfn->saddr != saddr || nfn->daddr != daddr ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (nfn->saddr != saddr || nfn->daddr != daddr ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
		if (nfn->saddr != saddr || nfn->daddr != daddr ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
#endif
		diff_jiffies = ulongmindiff(jiffies, nfn->jiffies);
		if (nfn->magic == natflow_path_magic &&
		        (u32)diff_jiffies < NATFLOW_FF_TIMEOUT_LOW &&
		        nfn->saddr == saddr && nfn->daddr == daddr &&
		        nfn->source == source && nfn->dest == dest &&
		        NFN_PROTO_DEC(nfn->flags) == protonum) {
			nf_ct_put(ct);
			return nfn;
		}
		nf_ct_put(ct);
	}

	return NULL;
}

static inline natflow_fastnat_node_t *nfn_invert_get6(natflow_fastnat_node_t *nfn) {
	unsigned int hash;
	unsigned long diff_jiffies;
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;

	memset(&tuple, 0, sizeof(tuple));
	memcpy(tuple.src.u3.ip6, nfn->saddr6, 16);
	tuple.src.u.all = nfn->source;
	memcpy(tuple.dst.u3.ip6, nfn->daddr6, 16);
	tuple.dst.u.all = nfn->dest;
	tuple.src.l3num = AF_INET6;
	tuple.dst.protonum = NFN_PROTO_DEC(nfn->flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		int d = !NF_CT_DIRECTION(h);
		struct in6_addr saddr = ct->tuplehash[d].tuple.src.u3.in6;
		struct in6_addr daddr = ct->tuplehash[d].tuple.dst.u3.in6;
		__be16 source = ct->tuplehash[d].tuple.src.u.all;
		__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
		__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;

		hash = natflow_hash_v6(saddr.s6_addr32, daddr.s6_addr32, source, dest);
		nfn = &natflow_fast_nat_table[hash];
		if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
		if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
		        nfn->source != source || nfn->dest != dest ||
		        NFN_PROTO_DEC(nfn->flags) != protonum) {
			hash += 1;
			nfn = &natflow_fast_nat_table[hash];
		}
#endif
		diff_jiffies = ulongmindiff(jiffies, nfn->jiffies);
		if (nfn->magic == natflow_path_magic &&
		        (u32)diff_jiffies < NATFLOW_FF_TIMEOUT_LOW &&
		        memcmp(nfn->saddr6, saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, daddr.s6_addr32, 16) == 0 &&
		        nfn->source == source && nfn->dest == dest &&
		        NFN_PROTO_DEC(nfn->flags) == protonum) {
			nf_ct_put(ct);
			return nfn;
		}
		nf_ct_put(ct);
	}

	return NULL;
}

static int natflow_offload_keepalive(unsigned int hash, unsigned long bytes, unsigned long packets, unsigned int *speed_bytes, unsigned int *speed_packets, int hw, unsigned long current_jiffies)
{
	struct nf_conn_acct *acct;
	natflow_fastnat_node_t *nfn, *nfn_i = NULL;
	unsigned long diff_jiffies = 0;

	hash = hash % NATFLOW_FASTNAT_TABLE_SIZE;
	nfn = &natflow_fast_nat_table[hash];

	diff_jiffies = ulongmindiff(current_jiffies, nfn->jiffies);
	if (nfn->magic == natflow_path_magic && (u32)diff_jiffies < NATFLOW_FF_TIMEOUT_LOW) {
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;

		nfn->jiffies = current_jiffies;

		memset(&tuple, 0, sizeof(tuple));
		if (NFN_L3NUM_DEC(nfn->flags) == AF_INET6) {
			goto __keepalive_ipv6_main;
		}

		tuple.src.u3.ip = nfn->saddr;
		tuple.src.u.all = nfn->source;
		tuple.dst.u3.ip = nfn->daddr;
		tuple.dst.u.all = nfn->dest;
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = NFN_PROTO_DEC(nfn->flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
			int d = !NF_CT_DIRECTION(h);
			__be32 saddr = ct->tuplehash[d].tuple.src.u3.ip;
			__be32 daddr = ct->tuplehash[d].tuple.dst.u3.ip;
			__be16 source = ct->tuplehash[d].tuple.src.u.all;
			__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
			__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;

			if (d == 1) {
				diff_jiffies = ulongmindiff(current_jiffies, nfn->keepalive_jiffies);
				nfn->keepalive_jiffies = current_jiffies;
				NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] ct%d diff_jiffies=%u HZ=%u bytes=%lu hw=%d\n",
				             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), !d, (unsigned int)diff_jiffies, HZ, bytes, hw);
				natflow_update_ct_timeout(ct, diff_jiffies);
			}

			nfn_i = nfn;
			hash = natflow_hash_v4(saddr, daddr, source, dest);
			nfn = &natflow_fast_nat_table[hash];
			if (nfn->saddr != saddr || nfn->daddr != daddr ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (nfn->saddr != saddr || nfn->daddr != daddr ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
			if (nfn->saddr != saddr || nfn->daddr != daddr ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
#endif
			diff_jiffies = ulongmindiff(current_jiffies, nfn->jiffies);
			if ((u32)diff_jiffies < NATFLOW_FF_TIMEOUT_LOW &&
			        nfn->saddr == saddr && nfn->daddr == daddr &&
			        nfn->source == source && nfn->dest == dest &&
			        NFN_PROTO_DEC(nfn->flags) == protonum) {
				nfn->jiffies = current_jiffies;
				if (d == 0) {
					diff_jiffies = ulongmindiff(current_jiffies, nfn->keepalive_jiffies);
					nfn->keepalive_jiffies = current_jiffies;
					NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] ct%d diff_jiffies=%u HZ=%u bytes=%lu hw=%d\n",
					             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), !d, (unsigned int)diff_jiffies, HZ, bytes, hw);
					natflow_update_ct_timeout(ct, diff_jiffies);
				}
			}

			acct = nf_conn_acct_find(ct);
			if (acct) {
				struct nf_conn_counter *counter = acct->counter;
				atomic64_add(packets, &counter[!d].packets);
				atomic64_add(bytes, &counter[!d].bytes);
			}
			/* stats to net_device */
			do {
				struct natflow_t *nf;
				nf = natflow_session_get(ct);
				if (nf) {
					struct net_device *dev;

					dev = nf->rroute[!d].outdev;
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (hw && (((nf->status & NF_FF_ORIGINAL_DSA) && d == NF_FF_DIR_REPLY) ||
					           ((nf->status & NF_FF_REPLY_DSA) && d == NF_FF_DIR_ORIGINAL))) {
						struct net_device_stats *stats = &dev->stats;
						stats->tx_bytes += bytes;
						stats->tx_packets += packets;
					}
#endif
					if (nf->rroute[!d].vlan_present) {
						dev = vlan_lookup_dev(dev, nf->rroute[!d].vlan_tci);
						if (dev) {
							struct vlan_pcpu_stats *vpstats = this_cpu_ptr(vlan_dev_priv(dev)->vlan_pcpu_stats);
							u64_stats_update_begin(&vpstats->syncp);
							compat_u64_stats_add(&vpstats->tx_bytes, bytes);
							compat_u64_stats_add(&vpstats->tx_packets, packets);
							u64_stats_update_end(&vpstats->syncp);
						}
					}

					dev = nf->rroute[d].outdev;
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (hw && (((nf->status & NF_FF_ORIGINAL_DSA) && (!d) == NF_FF_DIR_REPLY) ||
					           ((nf->status & NF_FF_REPLY_DSA) && (!d) == NF_FF_DIR_ORIGINAL))) {
						struct net_device_stats *stats = &dev->stats;
						stats->rx_bytes += bytes;
						stats->rx_packets += packets;
					}
#endif
					if (nf->rroute[d].vlan_present) {
						dev = vlan_lookup_dev(dev, nf->rroute[d].vlan_tci);
						if (dev) {
							struct vlan_pcpu_stats *vpstats = this_cpu_ptr(vlan_dev_priv(dev)->vlan_pcpu_stats);
							u64_stats_update_begin(&vpstats->syncp);
							compat_u64_stats_add(&vpstats->rx_bytes, bytes);
							compat_u64_stats_add(&vpstats->rx_packets, packets);
							u64_stats_update_end(&vpstats->syncp);
						}
					}
				}
			} while(0);
			/* stats to user */
			do {
				unsigned int hw_speed_bytes[4] = {0, 0, 0, 0};
				unsigned int hw_speed_packets[4] = {0, 0, 0, 0};
				natflow_fakeuser_t *user;
				struct fakeuser_data_t *fud;
				user = natflow_user_get(ct);
				if (NULL == user) {
					break;
				}
				if (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[!d].tuple.src.u3.ip)
					d = 0; /* download */
				else
					d = 1; /* upload */
				acct = nf_conn_acct_find(user);
				if (acct) {
					struct nf_conn_counter *counter = acct->counter;
					atomic64_add(packets, &counter[d].packets);
					atomic64_add(bytes, &counter[d].bytes);
				}
				if (hw == 2 && !speed_bytes) {
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int per_i = (unsigned int)current_jiffies % (HZ * 2);
					speed_bytes = hw_speed_bytes;
					speed_packets = hw_speed_packets;
					speed_bytes[i] = bytes * per_i / (HZ * 2);
					speed_packets[i] = packets * per_i / (HZ * 2);
					i = (i + 3) % 4;
					speed_bytes[i] = bytes * (HZ * 2 - per_i + 1) / (HZ * 2);
					speed_packets[i] = packets * (HZ * 2 - per_i + 1) / (HZ * 2);
				}
				if (!speed_bytes) {
					break;
				}
				fud = natflow_fakeuser_data(user);
				if (d == 0) {
					unsigned int rx_speed_jiffies = atomic_xchg(&fud->rx_speed_jiffies, (unsigned int)current_jiffies);
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int j = (rx_speed_jiffies/HZ/2) % 4;
					int diff = 0;
					diff_jiffies = uintmindiff(current_jiffies, rx_speed_jiffies);
					if (diff_jiffies >= HZ * 2 * 4) {
						for(j = 0; j < 4; j++) {
							atomic_set(&fud->rx_speed_bytes[j], 0);
							atomic_set(&fud->rx_speed_packets[j], 0);
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						atomic_set(&fud->rx_speed_bytes[j], speed_bytes[j]);
						atomic_set(&fud->rx_speed_packets[j], speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						atomic_add(speed_bytes[j], &fud->rx_speed_bytes[j]);
						atomic_add(speed_packets[j], &fud->rx_speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
				} else {
					unsigned int tx_speed_jiffies = atomic_xchg(&fud->tx_speed_jiffies, (unsigned int)current_jiffies);
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int j = (tx_speed_jiffies/HZ/2) % 4;
					int diff = 0;
					diff_jiffies = uintmindiff(current_jiffies, tx_speed_jiffies);
					if (diff_jiffies >= HZ * 2 * 4) {
						for(j = 0; j < 4; j++) {
							atomic_set(&fud->tx_speed_bytes[j], 0);
							atomic_set(&fud->tx_speed_packets[j], 0);
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						atomic_set(&fud->tx_speed_bytes[j], speed_bytes[j]);
						atomic_set(&fud->tx_speed_packets[j], speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						atomic_add(speed_bytes[j], &fud->tx_speed_bytes[j]);
						atomic_add(speed_packets[j], &fud->tx_speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
				}
				if (fud->auth_status == AUTH_BLOCK) {
					struct natflow_t *nf;
					nf = natflow_session_get(ct);

					/* tell FF do not emit pkts */
					if (nf && !(nf->status & NF_FF_USER_USE)) {
						/* tell FF -user- need to use this conn */
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
					}
					clear_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					nfn_i->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;

					NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u user is AUTH_BLOCK\n",
					             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
					nf_ct_put(ct);
					return -1;
				}
			} while (0);
			nf_ct_put(ct);
			return 0;
		}
		NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u ct not found\n",
		             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
		nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
		return -1;

__keepalive_ipv6_main:

		memcpy(tuple.src.u3.ip6, nfn->saddr6, 16);
		tuple.src.u.all = nfn->source;
		memcpy(tuple.dst.u3.ip6, nfn->daddr6, 16);
		tuple.dst.u.all = nfn->dest;
		tuple.src.l3num = AF_INET6;
		tuple.dst.protonum = NFN_PROTO_DEC(nfn->flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
			int d = !NF_CT_DIRECTION(h);
			struct in6_addr saddr = ct->tuplehash[d].tuple.src.u3.in6;
			struct in6_addr daddr = ct->tuplehash[d].tuple.dst.u3.in6;
			__be16 source = ct->tuplehash[d].tuple.src.u.all;
			__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
			__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;

			if (d == 1) {
				diff_jiffies = ulongmindiff(current_jiffies, nfn->keepalive_jiffies);
				nfn->keepalive_jiffies = current_jiffies;
				NATFLOW_INFO("keepalive[%u] nfn[%pI6.%u->%pI6.%u] ct%d diff_jiffies=%u HZ=%u bytes=%lu hw=%d\n",
				             hash, nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest), !d, (unsigned int)diff_jiffies, HZ, bytes, hw);
				natflow_update_ct_timeout(ct, diff_jiffies);
			}

			nfn_i = nfn;
			hash = natflow_hash_v6(saddr.s6_addr32, daddr.s6_addr32, source, dest);
			nfn = &natflow_fast_nat_table[hash];
			if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
			if (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
			        nfn->source != source || nfn->dest != dest ||
			        NFN_PROTO_DEC(nfn->flags) != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}
#endif
			diff_jiffies = ulongmindiff(current_jiffies, nfn->jiffies);
			if ((u32)diff_jiffies < NATFLOW_FF_TIMEOUT_LOW &&
			        memcmp(nfn->saddr6, saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, daddr.s6_addr32, 16) == 0 &&
			        nfn->source == source && nfn->dest == dest &&
			        NFN_PROTO_DEC(nfn->flags) == protonum) {
				nfn->jiffies = current_jiffies;
				if (d == 0) {
					diff_jiffies = ulongmindiff(current_jiffies, nfn->keepalive_jiffies);
					nfn->keepalive_jiffies = current_jiffies;
					NATFLOW_INFO("keepalive[%u] nfn[%pI6.%u->%pI6.%u] ct%d diff_jiffies=%u HZ=%u bytes=%lu hw=%d\n",
					             hash, nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest), !d, (unsigned int)diff_jiffies, HZ, bytes, hw);
					natflow_update_ct_timeout(ct, diff_jiffies);
				}
			}

			acct = nf_conn_acct_find(ct);
			if (acct) {
				struct nf_conn_counter *counter = acct->counter;
				atomic64_add(packets, &counter[!d].packets);
				atomic64_add(bytes, &counter[!d].bytes);
			}
			/* stats to net_device */
			do {
				struct natflow_t *nf;
				nf = natflow_session_get(ct);
				if (nf) {
					struct net_device *dev;

					dev = nf->rroute[!d].outdev;
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (hw && (((nf->status & NF_FF_ORIGINAL_DSA) && d == NF_FF_DIR_REPLY) ||
					           ((nf->status & NF_FF_REPLY_DSA) && d == NF_FF_DIR_ORIGINAL))) {
						struct net_device_stats *stats = &dev->stats;
						stats->tx_bytes += bytes;
						stats->tx_packets += packets;
					}
#endif
					if (nf->rroute[!d].vlan_present) {
						dev = vlan_lookup_dev(dev, nf->rroute[!d].vlan_tci);
						if (dev) {
							struct vlan_pcpu_stats *vpstats = this_cpu_ptr(vlan_dev_priv(dev)->vlan_pcpu_stats);
							u64_stats_update_begin(&vpstats->syncp);
							compat_u64_stats_add(&vpstats->tx_bytes, bytes);
							compat_u64_stats_add(&vpstats->tx_packets, packets);
							u64_stats_update_end(&vpstats->syncp);
						}
					}

					dev = nf->rroute[d].outdev;
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (hw && (((nf->status & NF_FF_ORIGINAL_DSA) && (!d) == NF_FF_DIR_REPLY) ||
					           ((nf->status & NF_FF_REPLY_DSA) && (!d) == NF_FF_DIR_ORIGINAL))) {
						struct net_device_stats *stats = &dev->stats;
						stats->rx_bytes += bytes;
						stats->rx_packets += packets;
					}
#endif
					if (nf->rroute[d].vlan_present) {
						dev = vlan_lookup_dev(dev, nf->rroute[d].vlan_tci);
						if (dev) {
							struct vlan_pcpu_stats *vpstats = this_cpu_ptr(vlan_dev_priv(dev)->vlan_pcpu_stats);
							u64_stats_update_begin(&vpstats->syncp);
							compat_u64_stats_add(&vpstats->rx_bytes, bytes);
							compat_u64_stats_add(&vpstats->rx_packets, packets);
							u64_stats_update_end(&vpstats->syncp);
						}
					}
				}
			} while(0);
			/* stats to user */
			do {
				unsigned int hw_speed_bytes[4] = {0, 0, 0, 0};
				unsigned int hw_speed_packets[4] = {0, 0, 0, 0};
				natflow_fakeuser_t *user;
				struct fakeuser_data_t *fud;
				user = natflow_user_get(ct);
				if (NULL == user) {
					break;
				}
				if (memcmp(&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3, &ct->tuplehash[!d].tuple.src.u3, sizeof(union nf_inet_addr)) != 0)
					d = 0; /* download */
				else
					d = 1; /* upload */
				acct = nf_conn_acct_find(user);
				if (acct) {
					struct nf_conn_counter *counter = acct->counter;
					atomic64_add(packets, &counter[d].packets);
					atomic64_add(bytes, &counter[d].bytes);
				}
				if (hw == 2 && !speed_bytes) {
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int per_i = (unsigned int)current_jiffies % (HZ * 2);
					speed_bytes = hw_speed_bytes;
					speed_packets = hw_speed_packets;
					speed_bytes[i] = bytes * per_i / (HZ * 2);
					speed_packets[i] = packets * per_i / (HZ * 2);
					i = (i + 3) % 4;
					speed_bytes[i] = bytes * (HZ * 2 - per_i + 1) / (HZ * 2);
					speed_packets[i] = packets * (HZ * 2 - per_i + 1) / (HZ * 2);
				}
				if (!speed_bytes) {
					break;
				}
				fud = natflow_fakeuser_data(user);
				if (d == 0) {
					unsigned int rx_speed_jiffies = atomic_xchg(&fud->rx_speed_jiffies, (unsigned int)current_jiffies);
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int j = (rx_speed_jiffies/HZ/2) % 4;
					int diff = 0;
					diff_jiffies = uintmindiff(current_jiffies, rx_speed_jiffies);
					if (diff_jiffies >= HZ * 2 * 4) {
						for(j = 0; j < 4; j++) {
							atomic_set(&fud->rx_speed_bytes[j], 0);
							atomic_set(&fud->rx_speed_packets[j], 0);
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						atomic_set(&fud->rx_speed_bytes[j], speed_bytes[j]);
						atomic_set(&fud->rx_speed_packets[j], speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						atomic_add(speed_bytes[j], &fud->rx_speed_bytes[j]);
						atomic_add(speed_packets[j], &fud->rx_speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
				} else {
					unsigned int tx_speed_jiffies = atomic_xchg(&fud->tx_speed_jiffies, (unsigned int)current_jiffies);
					unsigned int i = ((unsigned int)current_jiffies/HZ/2) % 4;
					unsigned int j = (tx_speed_jiffies/HZ/2) % 4;
					int diff = 0;
					diff_jiffies = uintmindiff(current_jiffies, tx_speed_jiffies);
					if (diff_jiffies >= HZ * 2 * 4) {
						for(j = 0; j < 4; j++) {
							atomic_set(&fud->tx_speed_bytes[j], 0);
							atomic_set(&fud->tx_speed_packets[j], 0);
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						atomic_set(&fud->tx_speed_bytes[j], speed_bytes[j]);
						atomic_set(&fud->tx_speed_packets[j], speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						atomic_add(speed_bytes[j], &fud->tx_speed_bytes[j]);
						atomic_add(speed_packets[j], &fud->tx_speed_packets[j]);
						speed_bytes[j] = speed_packets[j] = 0;
					}
				}
				if (fud->auth_status == AUTH_BLOCK) {
					struct natflow_t *nf;
					nf = natflow_session_get(ct);

					/* tell FF do not emit pkts */
					if (nf && !(nf->status & NF_FF_USER_USE)) {
						/* tell FF -user- need to use this conn */
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
					}
					clear_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					nfn_i->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;

					NATFLOW_INFO("keepalive[%u] nfn[%pI6.%u->%pI6.%u] diff_jiffies=%u ct not found\n",
					             hash, nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest), (unsigned int)diff_jiffies);
					nf_ct_put(ct);
					return -1;
				}
			} while (0);
			nf_ct_put(ct);
			return 0;
		}
		NATFLOW_INFO("keepalive[%u] nfn[%pI6.%u->%pI6.%u] diff_jiffies=%u ct not found\n",
		             hash, nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest), (unsigned int)diff_jiffies);
		nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
		return -1;
	}

	if (NFN_L3NUM_DEC(nfn->flags) == AF_INET6) {
		NATFLOW_INFO("keepalive[%u] nfn[%pI6.%u->%pI6.%u] diff_jiffies=%u timeout\n",
		             hash, nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest), (unsigned int)diff_jiffies);
	} else {
		NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u timeout\n",
		             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
	}

	return -2;
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
static struct net_device *ppe_dev = NULL;
#if defined(NATFLOW_OFFLOAD_HWNAT_FAKE)
#else
typedef struct flow_offload flow_offload_t;
typedef struct flow_offload_tuple flow_offload_tuple_t;
typedef struct flow_offload_hw_path flow_offload_hw_path_t;
typedef enum flow_offload_type flow_offload_type_t;
#endif
struct natflow_offload {
	flow_offload_t flow;
};

static struct natflow_offload *natflow_offload_alloc(struct nf_conn *ct, natflow_t *nf)
{
	static struct natflow_offload natflow_offload[NR_CPUS];

	int dir;
	flow_offload_tuple_t *ft;
	struct nf_conntrack_tuple *ctt;
	struct natflow_offload *natflow = &natflow_offload[smp_processor_id()];
	flow_offload_t *flow = &natflow->flow;
	int orig_hash, reply_hash;
	natflow_fastnat_node_t *nfn;

	dir = 0;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	if (ctt->src.l3num == AF_INET) {
		ft->src_v4 = ctt->src.u3.in;
		ft->dst_v4 = ctt->dst.u3.in;
	} else {
		ft->src_v6 = ctt->src.u3.in6;
		ft->dst_v6 = ctt->dst.u3.in6;
	}
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.all;
	ft->dst_port = ctt->dst.u.all;

	if (ctt->src.l3num == AF_INET) {
		orig_hash = natflow_hash_v4(ft->src_v4.s_addr, ft->dst_v4.s_addr, ft->src_port, ft->dst_port);
		nfn = &natflow_fast_nat_table[orig_hash];
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
#endif
	} else {
		orig_hash = natflow_hash_v6(ft->src_v6.s6_addr32, ft->dst_v6.s6_addr32, ft->src_port, ft->dst_port);
		nfn = &natflow_fast_nat_table[orig_hash];
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			orig_hash += 1;
			nfn = &natflow_fast_nat_table[orig_hash];
		}
#endif
	}

	dir = 1;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	if (ctt->src.l3num == AF_INET) {
		ft->src_v4 = ctt->src.u3.in;
		ft->dst_v4 = ctt->dst.u3.in;
	} else {
		ft->src_v6 = ctt->src.u3.in6;
		ft->dst_v6 = ctt->dst.u3.in6;
	}
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.all;
	ft->dst_port = ctt->dst.u.all;

	if (ctt->src.l3num == AF_INET) {
		reply_hash = natflow_hash_v4(ft->src_v4.s_addr, ft->dst_v4.s_addr, ft->src_port, ft->dst_port);
		nfn = &natflow_fast_nat_table[reply_hash];
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
		if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
#endif
	} else {
		reply_hash = natflow_hash_v6(ft->src_v6.s6_addr32, ft->dst_v6.s6_addr32, ft->src_port, ft->dst_port);
		nfn = &natflow_fast_nat_table[reply_hash];
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
		if (memcmp(nfn->saddr6, ft->src_v6.s6_addr32, 16) || memcmp(nfn->daddr6, ft->dst_v6.s6_addr32, 16) ||
		        nfn->source != ft->src_port || nfn->dest != ft->dst_port ||
		        NFN_PROTO_DEC(nfn->flags) != ft->l4proto)
		{
			reply_hash += 1;
			nfn = &natflow_fast_nat_table[reply_hash];
		}
#endif
	}

	/*XXX: in fact ppe don't care flags  */
	flow->flags = 0;
	if ((void *)flow->priv != (void *)natflow_offload_keepalive) {
		flow->priv = (void *)natflow_offload_keepalive;
	}

	flow->timeout = (orig_hash << 16) | reply_hash;

	return natflow;
}
#endif
#endif

void natflow_session_learn(struct sk_buff *skb, struct nf_conn *ct, natflow_t *nf, int dir)
{
	int magic = natflow_path_magic;
	struct iphdr *iph = ip_hdr(skb);
	struct net_device *dev;

	if (!skb->dev) {
		return;
	}
	dev = skb->dev;
#ifdef CONFIG_NETFILTER_INGRESS
	if (netif_is_bridge_master(dev) ||
	        netif_is_ovs_master(dev) ||
	        netif_is_bond_master(dev) ||
	        netif_is_macvlan(dev)) {
		return;
	}
	if (dev->type == ARPHRD_PPP) {
		if ((dev->flags & IFF_PPPOE))
			return;
		if (*(__be16 *)((void *)ip_hdr(skb) - 2) == __constant_htons(PPP_IP) || *(__be16 *)((void *)ip_hdr(skb) - 2) == __constant_htons(PPP_IPV6))
			return;
	}
#endif
	if (nf->magic != magic) {
		simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);

		simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
		nf->magic = magic;
	}

	if (dir == IP_CT_DIR_ORIGINAL) {
		if (!(nf->status & NF_FF_REPLY) && !simple_test_and_set_bit(NF_FF_REPLY_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (dev->type == ARPHRD_PPP || dev->type == ARPHRD_NONE) {
				l2_len = 0;
			}
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_REPLY].l2_head_len = l2_len;
				if (l2_len >= ETH_HLEN) {
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH(l2)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH(l2)->h_source, ETH_ALEN);
					ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_proto = ETH(l2)->h_proto;
					memcpy(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN, l2 + ETH_HLEN, l2_len - ETH_HLEN);
				}
				nf->rroute[NF_FF_DIR_REPLY].outdev = dev;
				if ((dev->flags & IFF_IFNAME_GROUP)) {
					nf->rroute[NF_FF_DIR_REPLY].ifname_group = 1;
				}
				if (skb_vlan_tag_present(skb)) {
					struct net_device *vlan_dev = vlan_find_dev_rcu(dev, skb->vlan_proto, skb_vlan_tag_get_id(skb));
					if (vlan_dev && (vlan_dev->flags & IFF_IFNAME_GROUP)) {
						nf->rroute[NF_FF_DIR_REPLY].ifname_group = 1;
					}
					nf->rroute[NF_FF_DIR_REPLY].vlan_present = 1;
					nf->rroute[NF_FF_DIR_REPLY].vlan_tci = skb_vlan_tag_get_id(skb);
					if (skb->vlan_proto == htons(ETH_P_8021Q))
						nf->rroute[NF_FF_DIR_REPLY].vlan_proto = FF_ETH_P_8021Q;
					else if (skb->vlan_proto == htons(ETH_P_8021AD))
						nf->rroute[NF_FF_DIR_REPLY].vlan_proto = FF_ETH_P_8021AD;
				}
				nf->rroute[NF_FF_DIR_REPLY].ttl_in = iph->version == 4 ? ip_hdr(skb)->ttl : ipv6_hdr(skb)->hop_limit;
				simple_set_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			}
		}
	} else {
		if (!(nf->status & NF_FF_ORIGINAL) && !simple_test_and_set_bit(NF_FF_ORIGINAL_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (dev->type == ARPHRD_PPP || dev->type == ARPHRD_NONE) {
				l2_len = 0;
			}
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len = l2_len;
				if (l2_len >= ETH_HLEN) {
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH(l2)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH(l2)->h_source, ETH_ALEN);
					ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_proto = ETH(l2)->h_proto;
					memcpy(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN, l2 + ETH_HLEN, l2_len - ETH_HLEN);
				}
				nf->rroute[NF_FF_DIR_ORIGINAL].outdev = dev;
				if ((dev->flags & IFF_IFNAME_GROUP)) {
					nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group = 1;
				}
				if (skb_vlan_tag_present(skb)) {
					struct net_device *vlan_dev = vlan_find_dev_rcu(dev, skb->vlan_proto, skb_vlan_tag_get_id(skb));
					if (vlan_dev && (vlan_dev->flags & IFF_IFNAME_GROUP)) {
						nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group = 1;
					}
					nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present = 1;
					nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci = skb_vlan_tag_get_id(skb);
					if (skb->vlan_proto == htons(ETH_P_8021Q))
						nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto = FF_ETH_P_8021Q;
					else if (skb->vlan_proto == htons(ETH_P_8021AD))
						nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto = FF_ETH_P_8021AD;
				}
				nf->rroute[NF_FF_DIR_ORIGINAL].ttl_in = iph->version == 4 ? ip_hdr(skb)->ttl : ipv6_hdr(skb)->hop_limit;
				simple_set_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			}
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_path_pre_ct_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = PF_INET;
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = ops->pf;
#endif
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = state->pf;
#endif
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_pre_ct_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = state->pf;
#endif
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *out = state->out;
#endif
#endif
	int dir = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_acct *acct;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	natflow_t *nf;
	int ret = NF_ACCEPT;
	int d;
#ifdef CONFIG_NETFILTER_INGRESS
	unsigned int re_learn = 0;
#else
	int bridge = 0;
#endif
	unsigned int ingress_pad_len = 0;
	unsigned int ingress_trim_off = 0;

	if (disabled)
		return NF_ACCEPT;

#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		u32 _I;
		u32 hash;
		natflow_fastnat_node_t *nfn;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		/* XXX: check MTK_CPU_REASON_HIT_BIND_FORCE_CPU
		 * nated-skb come to cpu from ppe, we just forward to ext dev(Wi-Fi)
		 * skb->hash stored the hash key
		 */
		if (hwnat && skb->dev->netdev_ops->ndo_flow_offload &&
		        (skb->vlan_tci & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC &&
		        (skb->hash & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC) {
			if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
			        pppoe_proto(skb) == __constant_htons(PPP_IPV6) /* Internet Protocol version 6 */) {
				goto __hook_ipv6_main;
			} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
				goto __hook_ipv6_main;
			}
			_I = (skb->hash & HWNAT_QUEUE_MAPPING_HASH_MASK) % NATFLOW_FASTNAT_TABLE_SIZE;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
			if (hwnat_wed_disabled) {
				if (_I == 0) _I = (skb->vlan_tci & HWNAT_QUEUE_MAPPING_HASH_MASK) % NATFLOW_FASTNAT_TABLE_SIZE;
			}
#endif
			nfn = &natflow_fast_nat_table[_I];
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);

			if (nfn->outdev && _I <= NATFLOW_FF_TIMEOUT_LOW && nfn->magic == natflow_path_magic) {
				if (!(nfn->flags & FASTNAT_BRIDGE_FWD) && skb_is_gso(skb)) {
					if (unlikely(skb_shinfo(skb)->gso_size > nfn->mss)) {
						skb_shinfo(skb)->gso_size = nfn->mss;
					}
				}
				//nfn->jiffies = jiffies; /* we update jiffies in keepalive */
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
				if (hwnat_wed_disabled) {
					__vlan_hwaccel_clear_tag(skb);
				} else {
					if (!skb_vlan_tag_present(skb) && nfn->vlan_present) { /* revert vlan_present if uses_dsa */
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					}
					if (skb_vlan_tag_present(skb))
						skb->vlan_tci &= ~HWNAT_QUEUE_MAPPING_MAGIC;
				}
#else
				if (eth_hdr(skb)->h_proto != htons(ETH_P_8021Q)) {
					if (!skb_vlan_tag_present(skb) && nfn->vlan_present) { /* revert vlan_present if uses_dsa */
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					}
					if (skb_vlan_tag_present(skb))
						skb->vlan_tci &= ~HWNAT_QUEUE_MAPPING_MAGIC;
				} /* else hardware rx vlan offload disabled */
#endif
				if (skb_is_gso(skb) || (nfn->flags & FASTNAT_NO_ARP)) {
					goto fast_output;
				}
				skb->dev = nfn->outdev;
				skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
				skb_reset_mac_header(skb);
				dev_queue_xmit(skb);
				return NF_STOLEN;
			}
			/* Strict conditions can determine that it is a specially marked skb
			 * so it is safe to drop
			 */
			if (skb->dev->netdev_ops->ndo_flow_offload_check) {
				flow_offload_hw_path_t del = {
					.dev = skb->dev,
					.flags = FLOW_OFFLOAD_PATH_ETHERNET | FLOW_OFFLOAD_PATH_DEL,
				};

				del.vlan_proto = (unsigned short)(nfn - natflow_fast_nat_table);
				nfn = nfn_invert_get(nfn);
				if (nfn) {
					del.vlan_id = (unsigned short)(nfn - natflow_fast_nat_table);
					skb->dev->netdev_ops->ndo_flow_offload_check(&del);
				}
			}
			return NF_DROP;
		}
#endif

		if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
		        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
			ingress_pad_len = PPPOE_SES_HLEN;
		} else if (skb->protocol == __constant_htons(ETH_P_IP)) {
			ingress_pad_len = 0;
		} else {
			if (skb->protocol == __constant_htons(ETH_P_ARP)) {
				goto out;
			}
			/* XXX: deliver ipv6 pkts to __hook_ipv6_main */
			if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
			        pppoe_proto(skb) == __constant_htons(PPP_IPV6) /* Internet Protocol version 6 */) {
				goto __hook_ipv6_main;
			} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
				goto __hook_ipv6_main;
			}

			goto out6;
		}

		if (ingress_pad_len > 0) {
			if (ingress_pad_len > skb->len) {
				return NF_ACCEPT;
			}
			skb_pull_rcsum(skb, ingress_pad_len);
			skb->network_header += ingress_pad_len;
		}

		if (unlikely(nf_ct_get(skb, &ctinfo) != NULL)) {
			goto out;
		}

		if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
			goto out;
		}

		if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);

		if (iph->ihl < 5 || iph->version != 4 || ip_is_fragment(iph)) {
			goto out;
		}

		if (ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr)) {
			goto out;
		}

		_I = ntohs(iph->tot_len);
		if (skb->len < _I || _I < (iph->ihl * 4)) {
			goto out;
		}
		if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
			goto out;
		}

		if (!pskb_may_pull(skb, iph->ihl * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl))) {
			return NF_DROP;
		}

		ingress_trim_off = skb->len - _I;
		if (pskb_trim_rcsum(skb, _I)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);

		skb->protocol = __constant_htons(ETH_P_IP);
		skb->transport_header = skb->network_header + ip_hdr(skb)->ihl * 4;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
		/* XXX:
		 * MT7622 hwnat cannot handle vlan for ext dev
		 * Route forwarding: all good
		 * Bridge forwarding: cannot handle vlan tag packets, pppoe tag is good
		 */
		if (hwnat_wed_disabled) {
			if (skb_vlan_tag_present(skb) && !(skb->dev->netdev_ops->ndo_flow_offload || skb->dev->netdev_ops->ndo_flow_offload_check)) {
				goto out;
			}
		}
#endif
#endif
		/* skip for defrag-skb or large packets */
		if (skb_is_nonlinear(skb) || ntohs(iph->tot_len) > 1500 - ingress_pad_len) {
			if (iph->protocol == IPPROTO_UDP || !skb_is_gso(skb))
				goto slow_fastpath;
		}

		if (iph->protocol == IPPROTO_TCP) {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest);
			nfn = &natflow_fast_nat_table[_I];
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#endif
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == TCPH(l4)->source && nfn->dest == TCPH(l4)->dest &&
			        (nfn->flags & FASTNAT_PROTO_TCP)) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 1;
					goto slow_fastpath;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				if (unlikely((u16)skb->dev->ifindex != nfn->ifindex))
					goto slow_fastpath;
				if (unlikely(TCPH(l4)->fin || TCPH(l4)->rst)) {
					nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					nfn = nfn_invert_get(nfn);
					if (nfn && (u32)ulongmindiff(jiffies, nfn->jiffies) <= NATFLOW_FF_TIMEOUT_LOW)
						nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					/* just in case bridge to make sure conntrack_in */
					goto slow_fastpath;
				}

				nfn->jiffies = jiffies;

				/* sample up to slow path every 2s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets, 0, jiffies);
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (bytes >= NATFLOW_FF_SAMPLE_TIME * 4*1024*1024/8) {
						if (hwnat && !(nfn->flags & FASTNAT_EXT_HWNAT_FLAG))
							re_learn = 2;
					} else if (bytes < NATFLOW_FF_SAMPLE_TIME * 1*1024*1024/8) {
						re_learn = 3;
					}
#endif
					goto slow_fastpath;
				}
				_I = (nfn->jiffies / HZ / 2) % 4;
				nfn->speed_bytes[_I] += skb->len;
				nfn->speed_packets[_I] += 1;
				nfn->flow_bytes += skb->len;
				nfn->flow_packets += 1;

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD) && skb_is_gso(skb)) {
					if (unlikely(skb_shinfo(skb)->gso_size > nfn->mss)) {
						skb_shinfo(skb)->gso_size = nfn->mss;
					}
				}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					if (hwnat_wed_disabled) {
						__vlan_hwaccel_clear_tag(skb);
					} else {
						if (nfn->vlan_present) {
							if (nfn->vlan_proto == FF_ETH_P_8021Q)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
							else if (nfn->vlan_proto == FF_ETH_P_8021AD)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
						} else if (skb_vlan_tag_present(skb))
							__vlan_hwaccel_clear_tag(skb);
					}
					skb->dev = nfn->outdev;
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb)) {
						if (!ppe_dev) {
							__vlan_hwaccel_clear_tag(skb);
						}
					} else if (ppe_dev) {
						__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), 1);
					}
					skb->dev = ppe_dev ? : nfn->outdev;
#endif
					if (skb->mac_len != ETH_HLEN && skb->mac_len != ETH_HLEN + PPPOE_SES_HLEN) { /* fake ether header for tun */
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
					} else {
						skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
						skb_reset_mac_header(skb);
					}
					if (unlikely(ingress_pad_len == PPPOE_SES_HLEN)) {
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
					}
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}
#endif

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (iph->ttl <= 1) {
						return NF_DROP;
					}
					ip_decrease_ttl(iph);
				}
				if (TCPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_tcp(skb, iph->ihl * 4, TCPH(l4)->source, nfn->nat_source);
					TCPH(l4)->source = nfn->nat_source;
				}
				if (TCPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_tcp(skb, iph->ihl * 4, TCPH(l4)->dest, nfn->nat_dest);
					TCPH(l4)->dest = nfn->nat_dest;
				}
				if (iph->saddr != nfn->nat_saddr) {
					csum_replace4(&iph->check, iph->saddr, nfn->nat_saddr);
					natflow_nat_ip_tcp(skb, iph->ihl * 4, iph->saddr, nfn->nat_saddr);
					iph->saddr = nfn->nat_saddr;
				}
				if (iph->daddr != nfn->nat_daddr) {
					csum_replace4(&iph->check, iph->daddr, nfn->nat_daddr);
					natflow_nat_ip_tcp(skb, iph->ihl * 4, iph->daddr, nfn->nat_daddr);
					iph->daddr = nfn->nat_daddr;
				}

fast_output:
				_I = ETH_HLEN;
				if ((nfn->flags & FASTNAT_PPPOE_FLAG)) {
					_I += PPPOE_SES_HLEN;
				} else if ((nfn->flags & FASTNAT_NO_ARP)) {
					_I = 0;
				}

				if (skb_is_gso(skb)) {
					/* XXX: to xmit gso directly
					 * 1. hw offload features needed
					 * 2. hw csum features needed
					 * 3. ether type only
					 */
					netdev_features_t features = nfn->outdev->features;
					if (nfn->vlan_present)
						features = netdev_intersect_features(features,
						                                     nfn->outdev->vlan_features | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX);
					ingress_trim_off = (NFN_PROTO_DEC(nfn->flags) == IPPROTO_TCP && (features & NETIF_F_TSO)) && \
					                   (features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)) && \
					                   _I == ETH_HLEN;
					if (!ingress_trim_off) {
						struct sk_buff *segs;
						skb->ip_summed = CHECKSUM_PARTIAL;
						skb->dev = nfn->outdev;
						segs = skb_gso_segment(skb, 0);
						if (IS_ERR(segs)) {
							return NF_DROP;
						}
						consume_skb(skb);
						skb = segs;
					}
				}

				do {
					struct sk_buff *next = skb->next;
					if (_I > skb_headroom(skb) && pskb_expand_head(skb, _I, skb_tailroom(skb), GFP_ATOMIC)) {
						kfree_skb_list(skb);
						return NF_STOLEN;
					}
					skb_push(skb, _I);
					skb_reset_mac_header(skb);
					if (_I >= ETH_HLEN) {
						memcpy(eth_hdr(skb)->h_source, nfn->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, nfn->h_dest, ETH_ALEN);
					}
					if (_I == ETH_HLEN + PPPOE_SES_HLEN) {
						struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_PPP_SES);
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
						ph->ver = 1;
						ph->type = 1;
						ph->code = 0;
						ph->sid = nfn->pppoe_sid;
						ph->length = htons(ntohs(ip_hdr(skb)->tot_len) + 2);
						*(__be16 *)((void *)ph + sizeof(struct pppoe_hdr)) = __constant_htons(PPP_IP);
					} else if (_I == ETH_HLEN) {
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
					}
					skb->dev = nfn->outdev;
					if (_I == 0 && skb->dev->type == ARPHRD_ETHER) {
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
					}
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb))
						__vlan_hwaccel_clear_tag(skb);
					skb->next = NULL;
					dev_queue_xmit(skb);
					skb = next;
				} while (skb);

				return NF_STOLEN;
			}
			/* for TCP */
		} else {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, UDPH(l4)->source, UDPH(l4)->dest);
			nfn = &natflow_fast_nat_table[_I];
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#endif
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == UDPH(l4)->source && nfn->dest == UDPH(l4)->dest &&
			        (nfn->flags & FASTNAT_PROTO_UDP)) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 1;
					goto slow_fastpath;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				if (unlikely((u16)skb->dev->ifindex != nfn->ifindex)) {
					goto slow_fastpath;
				}

				nfn->jiffies = jiffies;

				/* sample up to slow path every 2s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets, 0, jiffies);
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (bytes >= NATFLOW_FF_SAMPLE_TIME * 4*1024*1024/8) {
						if (hwnat && !(nfn->flags & FASTNAT_EXT_HWNAT_FLAG))
							re_learn = 2;
					} else if (bytes < NATFLOW_FF_SAMPLE_TIME * 1*1024*1024/8) {
						re_learn = 3;
					}
#endif
					goto slow_fastpath;
				}
				_I = (nfn->jiffies / HZ / 2) % 4;
				nfn->speed_bytes[_I] += skb->len;
				nfn->speed_packets[_I] += 1;
				nfn->flow_bytes += skb->len;
				nfn->flow_packets += 1;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					if (hwnat_wed_disabled) {
						__vlan_hwaccel_clear_tag(skb);
					} else {
						if (nfn->vlan_present) {
							if (nfn->vlan_proto == FF_ETH_P_8021Q)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
							else if (nfn->vlan_proto == FF_ETH_P_8021AD)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
						} else if (skb_vlan_tag_present(skb))
							__vlan_hwaccel_clear_tag(skb);
					}
					skb->dev = nfn->outdev;
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb)) {
						if (!ppe_dev) {
							__vlan_hwaccel_clear_tag(skb);
						}
					} else if (ppe_dev) {
						__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), 1);
					}
					skb->dev = ppe_dev ? : nfn->outdev;
#endif
					if (skb->mac_len != ETH_HLEN && skb->mac_len != ETH_HLEN + PPPOE_SES_HLEN) { /* fake ether header for tun */
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
					} else {
						skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
						skb_reset_mac_header(skb);
					}
					if (unlikely(ingress_pad_len == PPPOE_SES_HLEN)) {
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
					}
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}
#endif

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (iph->ttl <= 1) {
						return NF_DROP;
					}
					ip_decrease_ttl(iph);
				}
				if (UDPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_udp(skb, iph->ihl * 4, UDPH(l4)->source, nfn->nat_source);
					UDPH(l4)->source = nfn->nat_source;
				}
				if (UDPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_udp(skb, iph->ihl * 4, UDPH(l4)->dest, nfn->nat_dest);
					UDPH(l4)->dest = nfn->nat_dest;
				}
				if (iph->saddr != nfn->nat_saddr) {
					csum_replace4(&iph->check, iph->saddr, nfn->nat_saddr);
					natflow_nat_ip_udp(skb, iph->ihl * 4, iph->saddr, nfn->nat_saddr);
					iph->saddr = nfn->nat_saddr;
				}
				if (iph->daddr != nfn->nat_daddr) {
					csum_replace4(&iph->check, iph->daddr, nfn->nat_daddr);
					natflow_nat_ip_udp(skb, iph->ihl * 4, iph->daddr, nfn->nat_daddr);
					iph->daddr = nfn->nat_daddr;
				}

				goto fast_output;
			}
			/* for UDP */
		}
		/* fall to slow fastnat path */

slow_fastpath:
		ret = nf_conntrack_in_compat(dev_net(skb->dev), PF_INET, NF_INET_PRE_ROUTING, skb);
		if (ret != NF_ACCEPT) {
			goto out;
		}
	}
#else
	/* only bridge come here */
	if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IP);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
		ingress_pad_len = PPPOE_SES_HLEN;
	} else if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	           pppoe_proto(skb) == __constant_htons(PPP_IPV6) /* Internet Protocol version 6 */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IPV6);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
		ingress_pad_len = PPPOE_SES_HLEN;
	} else if (skb->protocol != __constant_htons(ETH_P_IP) && skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return NF_ACCEPT;
	}
#endif
	if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		goto __hook_ipv6_main;
	}

	if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST)
		goto out;

	if (skb->protocol != __constant_htons(ETH_P_IP))
		goto out;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		goto out;
	}
	l4 = (void *)iph + iph->ihl * 4;
	if (ipv4_is_multicast(iph->daddr) || ipv4_is_lbcast(iph->daddr)) {
		goto out;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}
	if (iph->protocol == IPPROTO_TCP && (TCPH(l4)->fin || TCPH(l4)->rst)) {
		goto out;
	}
	/*
	 * XXX: FIXME:
	 * we assume ct->ext->len > 24(=NATFLOW_MAX_OFF / NATFLOW_FACTOR) is always true
	 * after the nf_conntrack_in() call
	 * ct->ext->len <= 24 means natflow_session is ready
	 */
	nf = natflow_session_in(ct);
	if (NULL == nf) {
		goto out;
	}

	dir = CTINFO2DIR(ctinfo);
#ifdef CONFIG_NETFILTER_INGRESS
	if (re_learn == 1) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		} else {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		}
	}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	else if (re_learn == 2 && !(nf->status & NF_FF_ORIGINAL_OFFLOAD) && !(nf->status & NF_FF_REPLY_OFFLOAD)) {
		simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
	} else if (re_learn == 3) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			if ((nf->status & NF_FF_ORIGINAL_OFFLOAD))
				simple_clear_bit(NF_FF_ORIGINAL_OFFLOAD_BIT, &nf->status);
		} else {
			if ((nf->status & NF_FF_REPLY_OFFLOAD))
				simple_clear_bit(NF_FF_REPLY_OFFLOAD_BIT, &nf->status);
		}
	}
#endif
#endif
	natflow_session_learn(skb, ct, nf, dir);
	if (!nf_ct_is_confirmed(ct)) {
		goto out;
	}

	if ((ct->status & IPS_NATFLOW_FF_STOP) || (nf->status & NF_FF_BUSY_USE)) {
		goto out;
	}
	if (iph->protocol == IPPROTO_TCP && ct->proto.tcp.state != 3 /* ESTABLISHED */) {
		goto out;
	}

	//if (!(nf->status & NF_FF_OFFLOAD)) {
	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_TCP_ARG(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		case IPPROTO_UDP:
			NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_UDP_ARG(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		}
		goto out;
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		int packets = atomic64_read(&counter[0].packets) + atomic64_read(&counter[1].packets);
		if (delay_pkts && packets <= delay_pkts) {
			goto out;
		}
		/* skip 1/256 packets to slow path */
		if (packets % 256 == 63) {
			goto out;
		}
	}

	if (!(nf->status & NF_FF_TOKEN_CTRL)) {
		if (ifname_group_type != fastnat_for_all && !simple_test_and_set_bit(NF_FF_IFNAME_MATCH_BIT, &nf->status)) {
			if (
			    (ifname_group_type == fastnat_ifname_group_only &&
			     !(nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group == 1 &&
			       nf->rroute[NF_FF_DIR_REPLY].ifname_group == 1))
			    ||
			    (ifname_group_type == fastnat_ifname_group_bypass &&
			     (nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group == 1 &&
			      nf->rroute[NF_FF_DIR_REPLY].ifname_group == 1))
			) {
				/* ifname not matched, skip fastnat for this conn */
				struct nf_conn_help *help = nfct_help(ct);
				if (help && !help->helper) {
					/* this conn do not need helper, clear it for nss */
					ct->ext->offset[NF_CT_EXT_HELPER] = 0;
				}

				switch (iph->protocol) {
				case IPPROTO_TCP:
					NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": ifname filter orig dev=%s(vlan:%d) reply dev=%s(vlan:%d) go slowpath\n",
					             DEBUG_TCP_ARG(iph,l4),
					             nf->rroute[NF_FF_DIR_ORIGINAL].outdev->name,
					             nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present ? (int)nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci : -1,
					             nf->rroute[NF_FF_DIR_REPLY].outdev->name,
					             nf->rroute[NF_FF_DIR_REPLY].vlan_present ? (int)nf->rroute[NF_FF_DIR_REPLY].vlan_tci : -1);
					break;
				case IPPROTO_UDP:
					NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": ifname filter orig dev=%s(vlan:%d) reply dev=%s(vlan:%d) go slowpath\n",
					             DEBUG_UDP_ARG(iph,l4),
					             nf->rroute[NF_FF_DIR_ORIGINAL].outdev->name,
					             nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present ? (int)nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci : -1,
					             nf->rroute[NF_FF_DIR_REPLY].outdev->name,
					             nf->rroute[NF_FF_DIR_REPLY].vlan_present ? (int)nf->rroute[NF_FF_DIR_REPLY].vlan_tci : -1);
					break;
				}
				set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
				goto out;
			}

			simple_set_bit(NF_FF_FORCE_FASTNAT_BIT, &nf->status);
		}

		if (go_slowpath_if_no_qos && !(nf->status & NF_FF_FORCE_FASTNAT)) {
			struct nf_conn_help *help = nfct_help(ct);
			if (help && !help->helper) {
				/* this conn do not need helper, clear it for nss */
				ct->ext->offset[NF_CT_EXT_HELPER] = 0;
			}
			set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			goto out;
		}
	}

	/* skip for defrag-skb or large packets */
	if (skb_is_nonlinear(skb) || ntohs(iph->tot_len) > 1500 - ingress_pad_len) {
		if (iph->protocol == IPPROTO_UDP || !skb_is_gso(skb))
			goto out;
	}

	if (!simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status)) {
		if (skb->len > nf->rroute[dir].mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU)) {
			if (!skb_is_gso(skb)) {
				switch (iph->protocol) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": pmtu=%u FRAG=%p\n",
					              DEBUG_TCP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": pmtu=%u FRAG=%p\n",
					              DEBUG_UDP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
					break;
				}
				goto out;
			} else {
				if (unlikely(skb_shinfo(skb)->gso_size > nf->rroute[dir].mtu - sizeof(struct iphdr) - sizeof(struct tcphdr))) {
					skb_shinfo(skb)->gso_size = nf->rroute[dir].mtu - sizeof(struct iphdr) - sizeof(struct tcphdr);
				}
			}
		}

		if (iph->ttl <= 1) {
			return NF_DROP;
		}
		ip_decrease_ttl(iph);
	}

	do {
		natflow_fakeuser_t *user;
		struct fakeuser_data_t *fud;
		user = natflow_user_get(ct);
		if (NULL == user) {
			break;
		}
		if (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[dir].tuple.src.u3.ip) {
			d = 0;
		} else {
			d = 1;
		}

		fud = natflow_fakeuser_data(user);
		if (d == 0) {
			if (rx_token_ctrl(skb, fud, nf) < 0) {
				return NF_DROP;
			} else {
				/* download */
				unsigned int rx_speed_jiffies = atomic_xchg(&fud->rx_speed_jiffies, jiffies);
				unsigned int i = ((unsigned int)jiffies/HZ/2) % 4;
				unsigned int j = (rx_speed_jiffies/HZ/2) % 4;
				unsigned int diff_jiffies = uintmindiff(jiffies, rx_speed_jiffies);
				if (diff_jiffies >= HZ * 2 * 4) {
					for(j = 0; j < 4; j++) {
						atomic_set(&fud->rx_speed_bytes[j], 0);
						atomic_set(&fud->rx_speed_packets[j], 0);
					}
					j = i;
				}
				for (; j != i; ) {
					j = (j + 1) % 4;
					atomic_set(&fud->rx_speed_bytes[j], 0);
					atomic_set(&fud->rx_speed_packets[j], 0);
				}
				atomic_inc(&fud->rx_speed_packets[j]);
				atomic_add(skb->len, &fud->rx_speed_bytes[j]);
			}
		} else {
			if (tx_token_ctrl(skb, fud, nf) < 0) {
				return NF_DROP;
			} else {
				/* upload */
				unsigned int tx_speed_jiffies = atomic_xchg(&fud->tx_speed_jiffies, jiffies);
				unsigned int i = ((unsigned int)jiffies/HZ/2) % 4;
				unsigned int j = (tx_speed_jiffies/HZ/2) % 4;
				unsigned int diff_jiffies = uintmindiff(jiffies, tx_speed_jiffies);
				if (diff_jiffies >= HZ * 2 * 4) {
					for(j = 0; j < 4; j++) {
						atomic_set(&fud->tx_speed_bytes[j], 0);
						atomic_set(&fud->tx_speed_packets[j], 0);
					}
					j = i;
				}
				for (; j != i; ) {
					j = (j + 1) % 4;
					atomic_set(&fud->tx_speed_bytes[j], 0);
					atomic_set(&fud->tx_speed_packets[j], 0);
				}
				atomic_inc(&fud->tx_speed_packets[j]);
				atomic_add(skb->len, &fud->tx_speed_bytes[j]);
			}
		}

		acct = nf_conn_acct_find(user);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;
			atomic64_inc(&counter[d].packets);
			atomic64_add(skb->len, &counter[d].bytes);
		}
	} while (0);

	if ((ct->status & IPS_DST_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do DNAT
			if (natflow_do_dnat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do SNAT
			if (natflow_do_snat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}

	if ((ct->status & IPS_SRC_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do SNAT
			if (natflow_do_snat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do DNAT
			if (natflow_do_dnat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		goto out;
	}

#ifdef CONFIG_NETFILTER_INGRESS
	if (!(nf->status & NF_FF_FAIL) && !(nf->status & NF_FF_TOKEN_CTRL)) {
		for (d = 0; d < NF_FF_DIR_MAX; d++) {
			if (d == NF_FF_DIR_ORIGINAL) {
				if (!(nf->status & NF_FF_ORIGINAL_CHECK) && !simple_test_and_set_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status)) {
fastnat_check:
					do {
						__be32 saddr = ct->tuplehash[d].tuple.src.u3.ip;
						__be32 daddr = ct->tuplehash[d].tuple.dst.u3.ip;
						__be16 source = ct->tuplehash[d].tuple.src.u.all;
						__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
						__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;
						u32 hash = natflow_hash_v4(saddr, daddr, source, dest);
						natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];
						struct ethhdr *eth = (struct ethhdr *)nf->rroute[d].l2_head;

						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (nfn->saddr != saddr || nfn->daddr != daddr ||
						          nfn->source != source || nfn->dest != dest ||
						          NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (nfn->saddr != saddr || nfn->daddr != daddr ||
						          nfn->source != source || nfn->dest != dest ||
						          NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (nfn->saddr != saddr || nfn->daddr != daddr ||
						          nfn->source != source || nfn->dest != dest ||
						          NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
#endif
						if (!natflow_hash_skip(hash) &&
						        (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH ||
						         (nfn->saddr == saddr && nfn->daddr == daddr &&
						          nfn->source == source && nfn->dest == dest &&
						          NFN_PROTO_DEC(nfn->flags) == protonum))) {

							if (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH) {
								nfn->status = 0;
								nfn->flow_bytes = 0;
								nfn->flow_packets = 0;
								memset(nfn->speed_bytes, 0, sizeof(*nfn->speed_bytes) * 4);
								memset(nfn->speed_packets, 0, sizeof(*nfn->speed_packets) * 4);
							}

							nfn->flags = 0;
							nfn->saddr = saddr;
							nfn->daddr = daddr;
							nfn->source = source;
							nfn->dest = dest;
							nfn->flags |= NFN_PROTO_ENC(protonum);

							nfn->nat_saddr = ct->tuplehash[!d].tuple.dst.u3.ip;
							nfn->nat_daddr = ct->tuplehash[!d].tuple.src.u3.ip;
							nfn->nat_source = ct->tuplehash[!d].tuple.dst.u.all;
							nfn->nat_dest = ct->tuplehash[!d].tuple.src.u.all;

							nfn->outdev = nf->rroute[d].outdev;
							nfn->ifindex = (u16)nf->rroute[!d].outdev->ifindex;
							nfn->mss = nf->rroute[d].mtu - sizeof(struct iphdr) - sizeof(struct tcphdr);
							if (nf->rroute[d].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
								struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth + ETH_HLEN);
								nfn->pppoe_sid = ph->sid;
								nfn->flags |= FASTNAT_PPPOE_FLAG;
								nfn->flags &= ~FASTNAT_NO_ARP;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
							} else if (nf->rroute[d].l2_head_len == ETH_HLEN) {
								nfn->pppoe_sid = 0;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
								nfn->flags &= ~FASTNAT_NO_ARP;
							} else {
								nfn->flags |= FASTNAT_NO_ARP;
							}
							if (simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status))
								nfn->flags |= FASTNAT_BRIDGE_FWD;

							nfn->vlan_present = nf->rroute[d].vlan_present;
							nfn->vlan_proto = nf->rroute[d].vlan_proto;
							nfn->vlan_tci = nf->rroute[d].vlan_tci;
							nfn->magic = natflow_path_magic;
							nfn->jiffies = jiffies;
							nfn->keepalive_jiffies = jiffies;

							switch (iph->protocol) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d) l2_len=%d\n",
								             DEBUG_TCP_ARG(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)ntohs(nfn->pppoe_sid) : -1, nf->rroute[d].l2_head_len);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d) l2_len=%d\n",
								             DEBUG_UDP_ARG(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)ntohs(nfn->pppoe_sid) : -1, nf->rroute[d].l2_head_len);
								break;
							}
						} else {
							/* mark FF_FAIL so never try FF */
							simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
							switch (iph->protocol) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": dir=%d skip hash=%d\n", DEBUG_TCP_ARG(iph,l4), d, hash);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": dir=%d skip hash=%d\n", DEBUG_UDP_ARG(iph,l4), d, hash);
								break;
							}
						}

						if ((nf->status & NF_FF_ORIGINAL_CHECK) && (nf->status & NF_FF_REPLY_CHECK)) {
							if (nfn->magic == natflow_path_magic &&
							        ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
							        (nfn->saddr == saddr && nfn->daddr == daddr &&
							         nfn->source == source && nfn->dest == dest &&
							         NFN_PROTO_DEC(nfn->flags) == protonum)) {
								natflow_fastnat_node_t *nfn_i;
								saddr = ct->tuplehash[!d].tuple.src.u3.ip;
								daddr = ct->tuplehash[!d].tuple.dst.u3.ip;
								source = ct->tuplehash[!d].tuple.src.u.all;
								dest = ct->tuplehash[!d].tuple.dst.u.all;
								protonum = ct->tuplehash[!d].tuple.dst.protonum;
								hash = natflow_hash_v4(saddr, daddr, source, dest);
								nfn_i = &natflow_fast_nat_table[hash];

								if (nfn_i->saddr != saddr || nfn_i->daddr != daddr ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
								if (nfn_i->saddr != saddr || nfn_i->daddr != daddr ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
								if (nfn_i->saddr != saddr || nfn_i->daddr != daddr ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
#endif
								if (nfn_i->magic == natflow_path_magic && ulongmindiff(jiffies, nfn_i->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
								        (nfn_i->saddr == saddr && nfn_i->daddr == daddr &&
								         nfn_i->source == source && nfn_i->dest == dest && NFN_PROTO_DEC(nfn_i->flags) == protonum)) {
									nfn_i->jiffies = jiffies;
									nfn_i->keepalive_jiffies = jiffies;
									if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) {
										ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
										ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
									}
									if (d != NF_FF_DIR_ORIGINAL) {
										nfn = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
										nfn_i = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
										nfn = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
									}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
									if (hwnat && (re_learn == 2 || iph->protocol == IPPROTO_UDP)) {
										/* hwnat enabled */
										struct net_device *orig_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
										struct net_device *reply_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_REPLY].outdev);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
										__be16 orig_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
										__be16 reply_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_REPLY].outdev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) /* no dsa support before kernel 5.4 in openwrt */
										/* hwnat ready to go */
										u16 orig_dsa_port = 0xffff;
										u16 reply_dsa_port = 0xffff;
										if (!orig_dev->netdev_ops->ndo_flow_offload && orig_dev->netdev_ops->ndo_flow_offload_check) {
											flow_offload_hw_path_t orig = {
												.dev = orig_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
											};
											orig_dev->netdev_ops->ndo_flow_offload_check(&orig);
											if (orig.dev != orig_dev) {
												orig_dev = orig.dev;
												orig_dsa_port = orig.dsa_port;
											}
											if ((orig.flags & FLOW_OFFLOAD_PATH_DSA))
												simple_set_bit(NF_FF_ORIGINAL_DSA_BIT, &nf->status);
										}
										if (!reply_dev->netdev_ops->ndo_flow_offload && reply_dev->netdev_ops->ndo_flow_offload_check) {
											flow_offload_hw_path_t reply = {
												.dev = reply_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
											};
											reply_dev->netdev_ops->ndo_flow_offload_check(&reply);
											if (reply.dev != reply_dev) {
												reply_dev = reply.dev;
												reply_dsa_port = reply.dsa_port;
											}
											if ((reply.flags & FLOW_OFFLOAD_PATH_DSA))
												simple_set_bit(NF_FF_REPLY_DSA_BIT, &nf->status);
										}
#endif
										simple_set_bit(NF_FF_ORIGINAL_OFFLOAD_BIT, &nf->status);
										simple_set_bit(NF_FF_REPLY_OFFLOAD_BIT, &nf->status);

										if (orig_dev->netdev_ops->ndo_flow_offload) {
											/* xxx: orig_dev has offload api */
											if (orig_dev == reply_dev || reply_dev->netdev_ops->ndo_flow_offload) {
												/* xxx: both orig_dev and reply_dev has offload api */
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);

												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}

												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (unlikely(!ppe_dev)) {
													ppe_dev = orig_dev;
												}
												if (orig_dev->netdev_ops->ndo_flow_offload(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload1 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             &nfn_i->saddr, ntohs(nfn_i->source),
													             &nfn_i->daddr, ntohs(nfn_i->dest));
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (iph->protocol) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
														             ": dir%d set hwnat offload1 failed\n",
														             DEBUG_TCP_ARG(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
														             ": dir%d set hwnat offload1 failed\n",
														             DEBUG_UDP_ARG(iph,l4), dir);
														break;
													}
												}
												/* end: both orig_dev and reply_dev has offload api */
											}
#if !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
											else
											{
												/* xxx: olny orig_dev has offload api */
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												/* no vlan for ext dev */
												reply_dev = nf->rroute[NF_FF_DIR_REPLY].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												if (hwnat_wed_disabled) {
													reply_vid = (natflow->flow.timeout) & 0xffff;
												}
#endif
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												if (hwnat_wed_disabled) {
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto =
														    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													/* must set reply_vid */
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto = htons(ETH_P_8021Q);
													reply.vlan_id = reply_vid;
												} else {
#endif
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto =
														    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
														reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
														reply.vlan_proto =
														    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
													}
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												}
#endif
												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (unlikely(!ppe_dev)) {
													ppe_dev = orig_dev;
												}
												if (orig_dev->netdev_ops->ndo_flow_offload(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload2 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             &nfn_i->saddr, ntohs(nfn_i->source),
													             &nfn_i->daddr, ntohs(nfn_i->dest));
													if (nf->rroute[NF_FF_DIR_REPLY].outdev == nfn->outdev) {
														nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
													} else {
														nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
													}
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (iph->protocol) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
														             ": dir%d set hwnat offload2 failed\n",
														             DEBUG_TCP_ARG(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
														             ": dir%d set hwnat offload2 failed\n",
														             DEBUG_UDP_ARG(iph,l4), dir);
														break;
													}
												}
												/* end: olny orig_dev has offload api */
											}
											/* end: orig_dev has offload api */
										} else if (reply_dev->netdev_ops->ndo_flow_offload) {
											/* xxx: only reply_dev has offload api */
											struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
											flow_offload_hw_path_t orig = {
												.dev = orig_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
												| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
												| FLOW_OFFLOAD_PATH_WED_DIS
#endif
												,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
												.dsa_port = orig_dsa_port,
#endif
											};
											flow_offload_hw_path_t reply = {
												.dev = reply_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
												.dsa_port = reply_dsa_port,
#endif
											};
											/* no vlan for ext dev */
											orig_dev = nf->rroute[NF_FF_DIR_ORIGINAL].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											if (hwnat_wed_disabled) {
												orig_vid = (natflow->flow.timeout >> 16) & 0xffff;
											}
#endif
											if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
												orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
											}
											memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
											memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
											memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
											memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											if (hwnat_wed_disabled) {
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}
												/* must set orig_vid */
												orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
												orig.vlan_proto = htons(ETH_P_8021Q);
												orig.vlan_id = orig_vid;
											} else {
#endif
												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											}
#endif
											if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
												orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
												orig.pppoe_sid =
												    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
											}
											if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
												reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
												reply.pppoe_sid =
												    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
											}
											if (unlikely(!ppe_dev)) {
												ppe_dev = reply_dev;
											}
											if (reply_dev->netdev_ops->ndo_flow_offload(
											            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
												NATFLOW_INFO("(PCO) dir%d set hwnat offload3 orig=[%s(vlan:%d pppoe:%d)"
												             " %pI4:%u->%pI4:%u] reply=[%s(vlan:%d pppoe:%d)"
												             " %pI4:%u->%pI4:%u]\n",
												             dir, nfn_i->outdev->name,
												             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
												             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
												             (int)ntohs(nfn_i->pppoe_sid) : -1,
												             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
												             nfn->outdev->name,
												             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
												             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
												             (int)ntohs(nfn->pppoe_sid) : -1,
												             &nfn_i->saddr, ntohs(nfn_i->source),
												             &nfn_i->daddr, ntohs(nfn_i->dest));
												if (nf->rroute[NF_FF_DIR_ORIGINAL].outdev == nfn->outdev) {
													nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
												} else {
													nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
												}
											} else {
												/* mark FF_FAIL so never try FF */
												simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
												switch (iph->protocol) {
												case IPPROTO_TCP:
													NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
													             ": dir%d set hwnat offload3 failed\n",
													             DEBUG_TCP_ARG(iph,l4), dir);
													break;
												case IPPROTO_UDP:
													NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
													             ": dir%d set hwnat offload3 failed\n",
													             DEBUG_UDP_ARG(iph,l4), dir);
													break;
												}
											}
											/* end: only reply_dev has offload api */
										} else {
#endif /* !defined(CONFIG_HWNAT_EXTDEV_DISABLED) */
											/* xxx: neither orig_dev nor reply_dev has offload api */
											if (flow_offload_add_extdev &&
											        (orig_dev->netdev_ops->ndo_fill_forward_path ||
											         reply_dev->netdev_ops->ndo_fill_forward_path)) {
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);

												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}

												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (flow_offload_add_extdev && flow_offload_add_extdev(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload4 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI4:%u->%pI4:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             &nfn_i->saddr, ntohs(nfn_i->source),
													             &nfn_i->daddr, ntohs(nfn_i->dest));
													nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
													nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (iph->protocol) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
														             ": dir%d set hwnat offload4 failed\n",
														             DEBUG_TCP_ARG(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
														             ": dir%d set hwnat offload4 failed\n",
														             DEBUG_UDP_ARG(iph,l4), dir);
														break;
													}
												}
											}
											/* end: neither orig_dev nor reply_dev has offload api */
										}
									} else {
										/* hwnat is not enabled */
									}
#endif
								} else {
									/* nfn is ready, but nfn_i is not */
								}
							} else {
								/* nfn is not ready */
							}
						} else {
							/* either NF_FF_ORIGINAL_CHECK or NF_FF_REPLY_CHECK is not ready */
						}
					} while (0);
				}
			} else {
				if (!(nf->status & NF_FF_REPLY_CHECK) && !simple_test_and_set_bit(NF_FF_REPLY_CHECK_BIT, &nf->status)) {
					goto fastnat_check;
				}
			}
		} /* for (d = 0; d < NF_FF_DIR_MAX; d++) */
	} else {
		/* NF_FF_FAIL: loop try FF every 8 seconds */
		if (!(nf->status & NF_FF_RETRY)) {
			if ( ((jiffies + (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip^ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip)) / HZ) % 8 == 0 ) {
				simple_clear_bit(NF_FF_FAIL_BIT, &nf->status);
				simple_set_bit(NF_FF_RETRY_BIT, &nf->status);
			}
		} else {
			if ( ((jiffies + (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip^ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip)) / HZ) % 8 == 3 )
				simple_clear_bit(NF_FF_RETRY_BIT, &nf->status);
		}
	}
#endif

	if (skb_is_gso(skb)) {
		/* XXX: to xmit gso directly
		 * 1. hw offload features needed
		 * 2. hw csum features needed
		 * 3. ether type only
		 */
		netdev_features_t features = nf->rroute[dir].outdev->features;
		if (nf->rroute[dir].vlan_present)
			features = netdev_intersect_features(features,
			                                     nf->rroute[dir].outdev->vlan_features | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX);
		ingress_trim_off = (iph->protocol == IPPROTO_TCP && (features & NETIF_F_TSO)) && \
		                   (features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)) && \
		                   nf->rroute[dir].l2_head_len == ETH_HLEN;
		if (!ingress_trim_off) {
			struct sk_buff *segs;
			skb->ip_summed = CHECKSUM_PARTIAL;
			segs = skb_gso_segment(skb, 0);
			if (IS_ERR(segs)) {
				return NF_DROP;
			}
			consume_skb(skb);
			skb = segs;
		}
	}

	do {
		struct sk_buff *next = skb->next;
		if (nf->rroute[dir].l2_head_len > skb_headroom(skb) && pskb_expand_head(skb, nf->rroute[dir].l2_head_len, skb_tailroom(skb), GFP_ATOMIC)) {
			kfree_skb_list(skb);
			return NF_STOLEN;
		}
		skb_push(skb, nf->rroute[dir].l2_head_len);
		skb_reset_mac_header(skb);
		memcpy(skb_mac_header(skb), nf->rroute[dir].l2_head, nf->rroute[dir].l2_head_len);
		skb->dev = nf->rroute[dir].outdev;
		if (nf->rroute[dir].l2_head_len == 0 && skb->dev->type == ARPHRD_ETHER) {
			skb_push(skb, ETH_HLEN);
			skb->mac_len = ETH_HLEN;
			skb_reset_mac_header(skb);
			eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
		}
		if ((nf->status & NF_FF_TOKEN_CTRL)) { /* for tc working on bridge interface */
			skb->dev = netdev_master_upper_dev_get_rcu(nf->rroute[dir].outdev);
			if (!skb->dev)
				skb->dev = nf->rroute[dir].outdev;
		}
#ifdef CONFIG_NETFILTER_INGRESS
		if (nf->rroute[dir].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
			struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
			ph->length = htons(ntohs(ip_hdr(skb)->tot_len) + 2);
			skb->protocol = __constant_htons(ETH_P_PPP_SES);
		}
		if (nf->rroute[dir].vlan_present) {
			if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021Q)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nf->rroute[dir].vlan_tci);
			else if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021AD)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nf->rroute[dir].vlan_tci);
		} else if (skb_vlan_tag_present(skb))
			__vlan_hwaccel_clear_tag(skb);
#endif
		skb->next = NULL;
		dev_queue_xmit(skb);
		skb = next;
	} while (skb);

	return NF_STOLEN;

out:
#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		struct net_device *outdev;
		int vline_filter = 0;

		if (skb->protocol == __constant_htons(ETH_P_IP) && skb->dev->ifindex < VLINE_FWD_MAX_NUM && (outdev = vline_fwd_map[skb->dev->ifindex]) != NULL) {
			if (IP_SET_test_dst_netport(state, in, out, skb, "vline_filter_dst_netport") > 0 ||
			        IP_SET_test_dst_ip(state, in, out, skb, "vline_filter_dst") > 0 ||
			        IP_SET_test_src_ip(state, in, out, skb, "vline_filter_src") > 0 ||
			        IP_SET_test_src_mac(state, in, out, skb, "vline_filter_src_mac") > 0) {
				vline_filter = 1;
			}
		}

		if (ingress_pad_len == PPPOE_SES_HLEN) {
			skb->protocol = cpu_to_be16(ETH_P_PPP_SES);
			skb_push_rcsum(skb, PPPOE_SES_HLEN);
			skb->network_header -= PPPOE_SES_HLEN;
		}
		if (ingress_trim_off) {
			skb->len += ingress_trim_off;
		}

		if (vline_filter) {
			return ret;
		}
		//XXXXXXXX
		if (skb->dev->ifindex < VLINE_FWD_MAX_NUM && (outdev = vline_fwd_map[skb->dev->ifindex]) != NULL) {
			if (!(skb->dev->flags & IFF_VLINE_FAMILY_IPV6)) {
				//XXX: relay
				if ((outdev->flags & IFF_VLINE_RELAY)) {
					natflow_fakeuser_t *user;
					if (skb->protocol == __constant_htons(ETH_P_IP)) {
						iph = (void *)ip_hdr(skb);
						l4 = (void *)iph + iph->ihl * 4;
						//DHCP Discover,DHCP Request, change unicast to broadcast
						if (iph->protocol == IPPROTO_UDP && UDPH(l4)->dest == htons(67)) {
							unsigned char *flags_ptr = l4 + sizeof(struct udphdr) + 10; //BOOTP Flags offset in DHCP payload
							if (flags_ptr[0] == 0x00 && flags_ptr[1] == 0x00) {
								flags_ptr[0] = 0x80;  // Set MSB to 1: 0x8000
								//update UDP check
								if (UDPH(l4)->check || skb->ip_summed == CHECKSUM_PARTIAL) {
									inet_proto_csum_replace2(&UDPH(l4)->check, skb, htons(0x0000),
									                         htons(0x8000), true);
									if (!UDPH(l4)->check)
										UDPH(l4)->check = CSUM_MANGLED_0;
								}
							}
						}
					}
					if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST ||
					        skb->protocol == __constant_htons(ETH_P_ARP)) {
						if (!pskb_may_pull(skb, skb->len) || skb_try_make_writable(skb, skb->len)) {
							return NF_DROP;
						}
						skb = skb_copy(skb, GFP_ATOMIC);
						if (!skb) {
							return ret;
						}

						do {
							uint8_t macaddr[ETH_ALEN];
							__be32 ipaddr;
							struct ethhdr *eth = eth_hdr(skb);
							ether_addr_copy(eth->h_source, outdev->dev_addr);
							if (skb->protocol == __constant_htons(ETH_P_ARP)) {
								struct arphdr *arph = arp_hdr(skb);
								ipaddr = get_byte4((void *)arph + 8 + ETH_ALEN); //sip
								get_byte6((void *)arph + 8, macaddr); //sha
								user = natflow_user_in_get(ipaddr, macaddr); //learn or update macaddr cache
								if (user) {
									struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
									if ((skb->dev->flags & IFF_IS_LAN)) {
										if (fud->vline_lan != 1) fud->vline_lan = 1;
									} else {
										if (fud->vline_lan != 0) fud->vline_lan = 0;
									}
								}
								natflow_user_release_put(user);
								if (arph->ar_op == htons(ARPOP_REPLY)) {
									ipaddr = get_byte4((void *)arph + 8 + ETH_ALEN + 4 + ETH_ALEN); //tip
									user = natflow_user_find_get(ipaddr);
									if (user) {
										struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
										ether_addr_copy((void *)arph + 8 + ETH_ALEN + 4, fud->macaddr); //tha
										ether_addr_copy(eth->h_dest, fud->macaddr);
										natflow_user_release_put(user);
									}
								} else if (arph->ar_op == htons(ARPOP_REQUEST)) {
									if (skb->pkt_type != PACKET_BROADCAST) {
										ipaddr = get_byte4((void *)arph + 8 + ETH_ALEN + 4 + ETH_ALEN); //tip
										user = natflow_user_find_get(ipaddr);
										if (user) {
											struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
											ether_addr_copy(eth->h_dest, fud->macaddr);
											natflow_user_release_put(user);
										} else {
											skb->pkt_type = PACKET_BROADCAST;
											ether_addr_copy(eth->h_dest, "\xff\xff\xff\xff\xff\xff");
										}
									}
								}
								ether_addr_copy((void *)arph + 8, outdev->dev_addr);
							}
						} while (0);
						skb_push(skb, ETH_HLEN);
						skb_reset_mac_header(skb);
						skb->dev = outdev;
						dev_queue_xmit(skb);
						return ret;
					}

					iph = (void *)ip_hdr(skb);
					user = natflow_user_find_get(iph->daddr);
					if (user) {
						struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
						if (((skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 0) ||
						        (!(skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 1)) {
							struct ethhdr *eth = eth_hdr(skb);
							ether_addr_copy(eth->h_dest, fud->macaddr);
							natflow_user_release_put(user);
						} else {
							//go kernel route path
							return ret;
						}
					} else {
						//go kernel route path
						return ret;
					}

					ct = nf_ct_get(skb, &ctinfo);
					if (ct) {
						unsigned int mtu;
						dir = CTINFO2DIR(ctinfo);
						nf = natflow_session_get(ct);
						if (nf) {
							if (!(nf->status & (NF_FF_BRIDGE | NF_FF_ROUTE))) {
								simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
							}
							if (skb_dst(skb)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
								mtu = ip_skb_dst_mtu(skb);
#else
								mtu = ip_skb_dst_mtu(NULL, skb);
#endif
								if (nf->rroute[dir].mtu != mtu) {
									nf->rroute[dir].mtu = mtu;
								}
							}
						}
					}

					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						return ret;
					}

					skb_push(skb, ETH_HLEN);
					skb_reset_mac_header(skb);
					skb->dev = outdev;
					do {
						struct ethhdr *eth = eth_hdr(skb);
						ether_addr_copy(eth->h_source, outdev->dev_addr);
					} while (0);
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}

				//XXX: vline
				if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST ||
				        skb->protocol == __constant_htons(ETH_P_ARP)) {
					skb = skb_clone(skb, GFP_ATOMIC);
					if (!skb) {
						return ret;
					}
					skb_push(skb, ETH_HLEN);
					skb_reset_mac_header(skb);
					skb->dev = outdev;
					dev_queue_xmit(skb);
					return ret;
				}

				if (!(skb->dev->flags & IFF_NOARP)) {
					if ((skb->dev->flags & IFF_VLINE_L2_PORT)) {
						struct net_device *upper_dev = netdev_master_upper_dev_get_rcu(skb->dev);
						if (upper_dev && ether_addr_equal(upper_dev->dev_addr, eth_hdr(skb)->h_dest)) {
							return  ret;
						}
					} else if (ether_addr_equal(skb->dev->dev_addr, eth_hdr(skb)->h_dest)) {
						return ret;
					}
				}

				ct = nf_ct_get(skb, &ctinfo);
				if (ct) {
					unsigned int mtu;
					dir = CTINFO2DIR(ctinfo);
					nf = natflow_session_get(ct);
					if (nf) {
						if (!(nf->status & (NF_FF_BRIDGE | NF_FF_ROUTE))) {
							simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
						}
						if (skb_dst(skb)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
							mtu = ip_skb_dst_mtu(skb);
#else
							mtu = ip_skb_dst_mtu(NULL, skb);
#endif
							if (nf->rroute[dir].mtu != mtu) {
								nf->rroute[dir].mtu = mtu;
							}
						}
					}
				}

				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}

				skb_push(skb, ETH_HLEN);
				skb_reset_mac_header(skb);
				skb->dev = outdev;
				dev_queue_xmit(skb);
				return NF_STOLEN;
			}
		}
	}
#else
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}
#endif
	return ret;

	/*
	 * XXX: IPv6 main hook
	 */
__hook_ipv6_main:

#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		u32 _I;
		u32 hash;
		natflow_fastnat_node_t *nfn;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		/* XXX: check MTK_CPU_REASON_HIT_BIND_FORCE_CPU
		 * nated-skb come to cpu from ppe, we just forward to ext dev(Wi-Fi)
		 * skb->hash stored the hash key
		 */
		if (hwnat && skb->dev->netdev_ops->ndo_flow_offload &&
		        (skb->vlan_tci & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC &&
		        (skb->hash & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC) {
			_I = (skb->hash & HWNAT_QUEUE_MAPPING_HASH_MASK) % NATFLOW_FASTNAT_TABLE_SIZE;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
			if (hwnat_wed_disabled) {
				if (_I == 0) _I = (skb->vlan_tci & HWNAT_QUEUE_MAPPING_HASH_MASK) % NATFLOW_FASTNAT_TABLE_SIZE;
			}
#endif
			nfn = &natflow_fast_nat_table[_I];
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);

			if (nfn->outdev && _I <= NATFLOW_FF_TIMEOUT_LOW && nfn->magic == natflow_path_magic) {
				if (!(nfn->flags & FASTNAT_BRIDGE_FWD) && skb_is_gso(skb)) {
					if (unlikely(skb_shinfo(skb)->gso_size > nfn->mss)) {
						skb_shinfo(skb)->gso_size = nfn->mss;
					}
				}
				//nfn->jiffies = jiffies; /* we update jiffies in keepalive */
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
				if (hwnat_wed_disabled) {
					__vlan_hwaccel_clear_tag(skb);
				} else {
					if (!skb_vlan_tag_present(skb) && nfn->vlan_present) { /* revert vlan_present if uses_dsa */
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					}
					if (skb_vlan_tag_present(skb))
						skb->vlan_tci &= ~HWNAT_QUEUE_MAPPING_MAGIC;
				}
#else
				if (eth_hdr(skb)->h_proto != htons(ETH_P_8021Q)) {
					if (!skb_vlan_tag_present(skb) && nfn->vlan_present) { /* revert vlan_present if uses_dsa */
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					}
					if (skb_vlan_tag_present(skb))
						skb->vlan_tci &= ~HWNAT_QUEUE_MAPPING_MAGIC;
				} /* else hardware rx vlan offload disabled */
#endif
				if (skb_is_gso(skb) || (nfn->flags & FASTNAT_NO_ARP)) {
					goto fast_output6;
				}
				skb->dev = nfn->outdev;
				skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
				skb_reset_mac_header(skb);
				dev_queue_xmit(skb);
				return NF_STOLEN;
			}
			/* Strict conditions can determine that it is a specially marked skb
			 * so it is safe to drop
			 */
			if (skb->dev->netdev_ops->ndo_flow_offload_check) {
				flow_offload_hw_path_t del = {
					.dev = skb->dev,
					.flags = FLOW_OFFLOAD_PATH_ETHERNET | FLOW_OFFLOAD_PATH_DEL,
				};

				del.vlan_proto = (unsigned short)(nfn - natflow_fast_nat_table);
				nfn = nfn_invert_get6(nfn);
				if (nfn) {
					del.vlan_id = (unsigned short)(nfn - natflow_fast_nat_table);
					skb->dev->netdev_ops->ndo_flow_offload_check(&del);
				}
			}
			return NF_DROP;
		}
#endif

		if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
		        pppoe_proto(skb) == __constant_htons(PPP_IPV6) /* Internet Protocol version 6 */) {
			ingress_pad_len = PPPOE_SES_HLEN;
		} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
			ingress_pad_len = 0;
		} else {
			return NF_ACCEPT;
		}

		if (ingress_pad_len > 0) {
			if (ingress_pad_len > skb->len) {
				return NF_ACCEPT;
			}
			skb_pull_rcsum(skb, ingress_pad_len);
			skb->network_header += ingress_pad_len;
		}

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr))) {
			return NF_DROP;
		}
		iph = (void *)ipv6_hdr(skb);

		if (IPV6H->version != 6) {
			goto out6;
		}

		if (ipv6_addr_is_multicast(&IPV6H->daddr)) {
			goto out6;
		}

		_I = ntohs(IPV6H->payload_len) + sizeof(struct ipv6hdr);
		if (skb->len < _I) {
			goto out6;
		}
		if (IPV6H->nexthdr != IPPROTO_TCP && IPV6H->nexthdr != IPPROTO_UDP) {
			goto out6;
		}

		ingress_trim_off = skb->len - _I;
		if (pskb_trim_rcsum(skb, _I)) {
			return NF_DROP;
		}
		iph = (void *)ipv6_hdr(skb);

		skb->protocol = __constant_htons(ETH_P_IPV6);
		skb->transport_header = skb->network_header + sizeof(struct ipv6hdr);

		/* skip for defrag-skb or large packets */
		if (skb_is_nonlinear(skb) || _I > 1500 - ingress_pad_len) {
			if (IPV6H->nexthdr == IPPROTO_UDP || !skb_is_gso(skb))
				goto slow_fastpath6;
		}

		if (IPV6H->nexthdr == IPPROTO_TCP) {
			if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr)) || skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = (void *)ipv6_hdr(skb);
			l4 = (void *)iph + sizeof(struct ipv6hdr);
			_I = natflow_hash_v6(IPV6H->saddr.s6_addr32, IPV6H->daddr.s6_addr32, TCPH(l4)->source, TCPH(l4)->dest);
			nfn = &natflow_fast_nat_table[_I];
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_TCP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#endif
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) == 0 &&
			        nfn->source == TCPH(l4)->source && nfn->dest == TCPH(l4)->dest &&
			        (nfn->flags & FASTNAT_PROTO_TCP)) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 1;
					goto slow_fastpath6;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				if (unlikely((u16)skb->dev->ifindex != nfn->ifindex))
					goto slow_fastpath6;
				if (unlikely(TCPH(l4)->fin || TCPH(l4)->rst)) {
					nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					nfn = nfn_invert_get6(nfn);
					if (nfn && (u32)ulongmindiff(jiffies, nfn->jiffies) <= NATFLOW_FF_TIMEOUT_LOW)
						nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
					/* just in case bridge to make sure conntrack_in */
					goto slow_fastpath6;
				}

				nfn->jiffies = jiffies;

				/* sample up to slow path every 2s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets, 0, jiffies);
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (bytes >= NATFLOW_FF_SAMPLE_TIME * 4*1024*1024/8) {
						if (hwnat && !(nfn->flags & FASTNAT_EXT_HWNAT_FLAG))
							re_learn = 2;
					} else if (bytes < NATFLOW_FF_SAMPLE_TIME * 1*1024*1024/8) {
						re_learn = 3;
					}
#endif
					goto slow_fastpath6;
				}
				_I = (nfn->jiffies / HZ / 2) % 4;
				nfn->speed_bytes[_I] += skb->len;
				nfn->speed_packets[_I] += 1;
				nfn->flow_bytes += skb->len;
				nfn->flow_packets += 1;

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD) && skb_is_gso(skb)) {
					if (unlikely(skb_shinfo(skb)->gso_size > nfn->mss)) {
						skb_shinfo(skb)->gso_size = nfn->mss;
					}
				}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					if (hwnat_wed_disabled) {
						__vlan_hwaccel_clear_tag(skb);
					} else {
						if (nfn->vlan_present) {
							if (nfn->vlan_proto == FF_ETH_P_8021Q)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
							else if (nfn->vlan_proto == FF_ETH_P_8021AD)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
						} else if (skb_vlan_tag_present(skb))
							__vlan_hwaccel_clear_tag(skb);
					}
					skb->dev = nfn->outdev;
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb)) {
						if (!ppe_dev) {
							__vlan_hwaccel_clear_tag(skb);
						}
					} else if (ppe_dev) {
						__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), 1);
					}
					skb->dev = ppe_dev ? : nfn->outdev;
#endif
					if (skb->mac_len != ETH_HLEN && skb->mac_len != ETH_HLEN + PPPOE_SES_HLEN) { /* fake ether header for tun */
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IPV6);
					} else {
						skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
						skb_reset_mac_header(skb);
					}
					if (unlikely(ingress_pad_len == PPPOE_SES_HLEN)) {
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
					}
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}
#endif

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (IPV6H->hop_limit <= 1) {
						return NF_DROP;
					}
					IPV6H->hop_limit--;
				}

				if (TCPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_tcp(skb, sizeof(struct ipv6hdr), TCPH(l4)->source, nfn->nat_source);
					TCPH(l4)->source = nfn->nat_source;
				}
				if (TCPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_tcp(skb, sizeof(struct ipv6hdr), TCPH(l4)->dest, nfn->nat_dest);
					TCPH(l4)->dest = nfn->nat_dest;
				}
				for (_I = 0; _I < 4; _I++) {
					if (IPV6H->saddr.s6_addr32[_I] == nfn->nat_saddr6[_I])
						continue;
					natflow_nat_ip_tcp(skb, sizeof(struct ipv6hdr), IPV6H->saddr.s6_addr32[_I], nfn->nat_saddr6[_I]);
					IPV6H->saddr.s6_addr32[_I] = nfn->nat_saddr6[_I];
				}
				for (_I = 0; _I < 4; _I++) {
					if (IPV6H->daddr.s6_addr32[_I] == nfn->nat_daddr6[_I])
						continue;
					natflow_nat_ip_tcp(skb, sizeof(struct ipv6hdr), IPV6H->daddr.s6_addr32[_I], nfn->nat_daddr6[_I]);
					IPV6H->daddr.s6_addr32[_I] = nfn->nat_daddr6[_I];
				}

fast_output6:
				_I = ETH_HLEN;
				if ((nfn->flags & FASTNAT_PPPOE_FLAG)) {
					_I += PPPOE_SES_HLEN;
				} else if ((nfn->flags & FASTNAT_NO_ARP)) {
					_I = 0;
				}

				if (skb_is_gso(skb)) {
					/* XXX: to xmit gso directly
					 * 1. hw offload features needed
					 * 2. hw csum features needed
					 * 3. ether type only
					 */
					netdev_features_t features = nfn->outdev->features;
					if (nfn->vlan_present)
						features = netdev_intersect_features(features,
						                                     nfn->outdev->vlan_features | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX);
					ingress_trim_off = (NFN_PROTO_DEC(nfn->flags) == IPPROTO_TCP && (features & NETIF_F_TSO)) && \
					                   (features & (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM)) && \
					                   _I == ETH_HLEN;
					if (!ingress_trim_off) {
						struct sk_buff *segs;
						skb->ip_summed = CHECKSUM_PARTIAL;
						skb->dev = nfn->outdev;
						segs = skb_gso_segment(skb, 0);
						if (IS_ERR(segs)) {
							return NF_DROP;
						}
						consume_skb(skb);
						skb = segs;
					}
				}

				do {
					struct sk_buff *next = skb->next;
					if (_I > skb_headroom(skb) && pskb_expand_head(skb, _I, skb_tailroom(skb), GFP_ATOMIC)) {
						kfree_skb_list(skb);
						return NF_STOLEN;
					}
					skb_push(skb, _I);
					skb_reset_mac_header(skb);
					if (_I >= ETH_HLEN) {
						memcpy(eth_hdr(skb)->h_source, nfn->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, nfn->h_dest, ETH_ALEN);
					}
					if (_I == ETH_HLEN + PPPOE_SES_HLEN) {
						struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_PPP_SES);
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
						ph->ver = 1;
						ph->type = 1;
						ph->code = 0;
						ph->sid = nfn->pppoe_sid;
						ph->length = htons(ntohs(ipv6_hdr(skb)->payload_len) + sizeof(struct ipv6hdr) + 2);
						*(__be16 *)((void *)ph + sizeof(struct pppoe_hdr)) = __constant_htons(PPP_IPV6);
					} else if (_I == ETH_HLEN) {
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IPV6);
					}
					skb->dev = nfn->outdev;
					if (_I == 0 && skb->dev->type == ARPHRD_ETHER) {
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IPV6);
					}
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb))
						__vlan_hwaccel_clear_tag(skb);
					skb->next = NULL;
					dev_queue_xmit(skb);
					skb = next;
				} while (skb);

				return NF_STOLEN;
			}
			/* for TCP */
		} else {
			if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)) || skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr))) {
				return NF_DROP;
			}
			iph = (void *)ipv6_hdr(skb);
			l4 = (void *)iph + sizeof(struct ipv6hdr);
			_I = natflow_hash_v6(IPV6H->saddr.s6_addr32, IPV6H->daddr.s6_addr32, UDPH(l4)->source, UDPH(l4)->dest);
			nfn = &natflow_fast_nat_table[_I];
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			if (memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) || memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        !(nfn->flags & FASTNAT_PROTO_UDP)) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
#endif
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        memcmp(nfn->saddr6, IPV6H->saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, IPV6H->daddr.s6_addr32, 16) == 0 &&
			        nfn->source == UDPH(l4)->source && nfn->dest == UDPH(l4)->dest &&
			        (nfn->flags & FASTNAT_PROTO_UDP)) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 1;
					goto slow_fastpath6;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				if (unlikely((u16)skb->dev->ifindex != nfn->ifindex)) {
					goto slow_fastpath6;
				}

				nfn->jiffies = jiffies;

				/* sample up to slow path every 2s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets, 0, jiffies);
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
					if (bytes >= NATFLOW_FF_SAMPLE_TIME * 4*1024*1024/8) {
						if (hwnat && !(nfn->flags & FASTNAT_EXT_HWNAT_FLAG))
							re_learn = 2;
					} else if (bytes < NATFLOW_FF_SAMPLE_TIME * 1*1024*1024/8) {
						re_learn = 3;
					}
#endif
					goto slow_fastpath6;
				}
				_I = (nfn->jiffies / HZ / 2) % 4;
				nfn->speed_bytes[_I] += skb->len;
				nfn->speed_packets[_I] += 1;
				nfn->flow_bytes += skb->len;
				nfn->flow_packets += 1;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					if (hwnat_wed_disabled) {
						__vlan_hwaccel_clear_tag(skb);
					} else {
						if (nfn->vlan_present) {
							if (nfn->vlan_proto == FF_ETH_P_8021Q)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
							else if (nfn->vlan_proto == FF_ETH_P_8021AD)
								__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
						} else if (skb_vlan_tag_present(skb))
							__vlan_hwaccel_clear_tag(skb);
					}
					skb->dev = nfn->outdev;
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else if (skb_vlan_tag_present(skb)) {
						if (!ppe_dev) {
							__vlan_hwaccel_clear_tag(skb);
						}
					} else if (ppe_dev) {
						__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), 1);
					}
					skb->dev = ppe_dev ? : nfn->outdev;
#endif
					if (skb->mac_len != ETH_HLEN && skb->mac_len != ETH_HLEN + PPPOE_SES_HLEN) { /* fake ether header for tun */
						skb_push(skb, ETH_HLEN);
						skb->mac_len = ETH_HLEN;
						skb_reset_mac_header(skb);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IPV6);
					} else {
						skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
						skb_reset_mac_header(skb);
					}
					if (unlikely(ingress_pad_len == PPPOE_SES_HLEN)) {
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
					}
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}
#endif

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (IPV6H->hop_limit <= 1) {
						return NF_DROP;
					}
					IPV6H->hop_limit--;
				}

				if (UDPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_udp(skb, sizeof(struct ipv6hdr), UDPH(l4)->source, nfn->nat_source);
					UDPH(l4)->source = nfn->nat_source;
				}
				if (UDPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_udp(skb, sizeof(struct ipv6hdr), UDPH(l4)->dest, nfn->nat_dest);
					UDPH(l4)->dest = nfn->nat_dest;
				}
				for (_I = 0; _I < 4; _I++) {
					if (IPV6H->saddr.s6_addr32[_I] == nfn->nat_saddr6[_I])
						continue;
					natflow_nat_ip_udp(skb, sizeof(struct ipv6hdr), IPV6H->saddr.s6_addr32[_I], nfn->nat_saddr6[_I]);
					IPV6H->saddr.s6_addr32[_I] = nfn->nat_saddr6[_I];
				}
				for (_I = 0; _I < 4; _I++) {
					if (IPV6H->daddr.s6_addr32[_I] == nfn->nat_daddr6[_I])
						continue;
					natflow_nat_ip_udp(skb, sizeof(struct ipv6hdr), IPV6H->daddr.s6_addr32[_I], nfn->nat_daddr6[_I]);
					IPV6H->daddr.s6_addr32[_I] = nfn->nat_daddr6[_I];
				}

				goto fast_output6;
			}
			/* for UDP */
		}
		/* fall to slow fastnat path */

slow_fastpath6:
		ret = nf_conntrack_in_compat(dev_net(skb->dev), AF_INET6, NF_INET_PRE_ROUTING, skb);
		if (ret != NF_ACCEPT) {
			goto out6;
		}
	}
#endif
	if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST)
		goto out6;

	iph = (void *)ipv6_hdr(skb);
	if (IPV6H->nexthdr != IPPROTO_TCP && IPV6H->nexthdr != IPPROTO_UDP) {
		goto out6;
	}
	l4 = (void *)iph + sizeof(struct ipv6hdr);
	if (ipv6_addr_is_multicast(&IPV6H->daddr)) {
		goto out6;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out6;
	}
	if (IPV6H->nexthdr == IPPROTO_TCP && (TCPH(l4)->fin || TCPH(l4)->rst)) {
		goto out6;
	}

	nf = natflow_session_in(ct);
	if (NULL == nf) {
		goto out6;
	}

	dir = CTINFO2DIR(ctinfo);
#ifdef CONFIG_NETFILTER_INGRESS
	if (re_learn == 1) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		} else {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		}
	}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	else if (re_learn == 2 && !(nf->status & NF_FF_ORIGINAL_OFFLOAD) && !(nf->status & NF_FF_REPLY_OFFLOAD)) {
		simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
	} else if (re_learn == 3) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			if ((nf->status & NF_FF_ORIGINAL_OFFLOAD))
				simple_clear_bit(NF_FF_ORIGINAL_OFFLOAD_BIT, &nf->status);
		} else {
			if ((nf->status & NF_FF_REPLY_OFFLOAD))
				simple_clear_bit(NF_FF_REPLY_OFFLOAD_BIT, &nf->status);
		}
	}
#endif
#endif
	natflow_session_learn(skb, ct, nf, dir);
	if (!nf_ct_is_confirmed(ct)) {
		goto out6;
	}

	if ((ct->status & IPS_NATFLOW_FF_STOP) || (nf->status & NF_FF_BUSY_USE)) {
		goto out6;
	}
	if (IPV6H->nexthdr == IPPROTO_TCP && ct->proto.tcp.state != 3 /* ESTABLISHED */) {
		goto out6;
	}

	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		switch (IPV6H->nexthdr) {
		case IPPROTO_TCP:
			NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT6 ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_TCP_ARG6(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		case IPPROTO_UDP:
			NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT6 ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_UDP_ARG6(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		}
		goto out6;
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		int packets = atomic64_read(&counter[0].packets) + atomic64_read(&counter[1].packets);
		if (delay_pkts && packets <= delay_pkts) {
			goto out6;
		}
		/* skip 1/256 packets to slow path */
		if (packets % 256 == 63) {
			goto out6;
		}
	}

	if (!(nf->status & NF_FF_TOKEN_CTRL)) {
		if (ifname_group_type != fastnat_for_all && !simple_test_and_set_bit(NF_FF_IFNAME_MATCH_BIT, &nf->status)) {
			if (
			    (ifname_group_type == fastnat_ifname_group_only &&
			     !(nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group == 1 &&
			       nf->rroute[NF_FF_DIR_REPLY].ifname_group == 1))
			    ||
			    (ifname_group_type == fastnat_ifname_group_bypass &&
			     (nf->rroute[NF_FF_DIR_ORIGINAL].ifname_group == 1 &&
			      nf->rroute[NF_FF_DIR_REPLY].ifname_group == 1))
			) {
				/* ifname not matched, skip fastnat for this conn */
				struct nf_conn_help *help = nfct_help(ct);
				if (help && !help->helper) {
					/* this conn do not need helper, clear it for nss */
					ct->ext->offset[NF_CT_EXT_HELPER] = 0;
				}

				switch (IPV6H->nexthdr) {
				case IPPROTO_TCP:
					NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6 ": ifname filter orig dev=%s(vlan:%d) reply dev=%s(vlan:%d) not matched\n",
					             DEBUG_TCP_ARG6(iph,l4),
					             nf->rroute[NF_FF_DIR_ORIGINAL].outdev->name,
					             nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present ? (int)nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci : -1,
					             nf->rroute[NF_FF_DIR_REPLY].outdev->name,
					             nf->rroute[NF_FF_DIR_REPLY].vlan_present ? (int)nf->rroute[NF_FF_DIR_REPLY].vlan_tci : -1);
					break;
				case IPPROTO_UDP:
					NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6 ": ifname filter orig dev=%s(vlan:%d) reply dev=%s(vlan:%d) not matched\n",
					             DEBUG_UDP_ARG6(iph,l4),
					             nf->rroute[NF_FF_DIR_ORIGINAL].outdev->name,
					             nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present ? (int)nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci : -1,
					             nf->rroute[NF_FF_DIR_REPLY].outdev->name,
					             nf->rroute[NF_FF_DIR_REPLY].vlan_present ? (int)nf->rroute[NF_FF_DIR_REPLY].vlan_tci : -1);
					break;
				}
				set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
				goto out6;
			}

			simple_set_bit(NF_FF_FORCE_FASTNAT_BIT, &nf->status);
		}

		if (go_slowpath_if_no_qos && !(nf->status & NF_FF_FORCE_FASTNAT)) {
			struct nf_conn_help *help = nfct_help(ct);
			if (help && !help->helper) {
				/* this conn do not need helper, clear it for nss */
				ct->ext->offset[NF_CT_EXT_HELPER] = 0;
			}
			set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			goto out6;
		}
	}

	/* skip for defrag-skb or large packets */
	if (skb_is_nonlinear(skb) || ntohs(IPV6H->payload_len) + sizeof(struct ipv6hdr) > 1500 - ingress_pad_len) {
		if (IPV6H->nexthdr == IPPROTO_UDP || !skb_is_gso(skb))
			goto out6;
	}

	if (!simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status)) {
		if (skb->len > nf->rroute[dir].mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU)) {
			if (!skb_is_gso(skb)) {
				switch (IPV6H->nexthdr) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT6 ": pmtu=%u FRAG=%p\n",
					              DEBUG_TCP_ARG6(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT6 ": pmtu=%u FRAG=%p\n",
					              DEBUG_UDP_ARG6(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
					break;
				}
				goto out6;
			} else {
				if (unlikely(skb_shinfo(skb)->gso_size > nf->rroute[dir].mtu - sizeof(struct ipv6hdr) - sizeof(struct tcphdr))) {
					skb_shinfo(skb)->gso_size = nf->rroute[dir].mtu - sizeof(struct ipv6hdr) - sizeof(struct tcphdr);
				}
			}
		}

		if (IPV6H->hop_limit <= 1) {
			return NF_DROP;
		}
		IPV6H->hop_limit--;
	}

	do {
		natflow_fakeuser_t *user;
		struct fakeuser_data_t *fud;
		user = natflow_user_get(ct);
		if (NULL == user) {
			break;
		}
		if (memcmp(&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3, &ct->tuplehash[dir].tuple.src.u3, sizeof(union nf_inet_addr)) != 0) {
			d = 0;
		} else {
			d = 1;
		}

		fud = natflow_fakeuser_data(user);
		if (d == 0) {
			if (0 && rx_token_ctrl(skb, fud, nf) < 0) {
				return NF_DROP;
			} else {
				/* download */
				unsigned int rx_speed_jiffies = atomic_xchg(&fud->rx_speed_jiffies, jiffies);
				unsigned int i = ((unsigned int)jiffies/HZ/2) % 4;
				unsigned int j = (rx_speed_jiffies/HZ/2) % 4;
				unsigned int diff_jiffies = uintmindiff(jiffies, rx_speed_jiffies);
				if (diff_jiffies >= HZ * 2 * 4) {
					for(j = 0; j < 4; j++) {
						atomic_set(&fud->rx_speed_bytes[j], 0);
						atomic_set(&fud->rx_speed_packets[j], 0);
					}
					j = i;
				}
				for (; j != i; ) {
					j = (j + 1) % 4;
					atomic_set(&fud->rx_speed_bytes[j], 0);
					atomic_set(&fud->rx_speed_packets[j], 0);
				}
				atomic_inc(&fud->rx_speed_packets[j]);
				atomic_add(skb->len, &fud->rx_speed_bytes[j]);
			}
		} else {
			if (0 && tx_token_ctrl(skb, fud, nf) < 0) {
				return NF_DROP;
			} else {
				/* upload */
				unsigned int tx_speed_jiffies = atomic_xchg(&fud->tx_speed_jiffies, jiffies);
				unsigned int i = ((unsigned int)jiffies/HZ/2) % 4;
				unsigned int j = (tx_speed_jiffies/HZ/2) % 4;
				unsigned int diff_jiffies = uintmindiff(jiffies, tx_speed_jiffies);
				if (diff_jiffies >= HZ * 2 * 4) {
					for(j = 0; j < 4; j++) {
						atomic_set(&fud->tx_speed_bytes[j], 0);
						atomic_set(&fud->tx_speed_packets[j], 0);
					}
					j = i;
				}
				for (; j != i; ) {
					j = (j + 1) % 4;
					atomic_set(&fud->tx_speed_bytes[j], 0);
					atomic_set(&fud->tx_speed_packets[j], 0);
				}
				atomic_inc(&fud->tx_speed_packets[j]);
				atomic_add(skb->len, &fud->tx_speed_bytes[j]);
			}
		}

		acct = nf_conn_acct_find(user);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;
			atomic64_inc(&counter[d].packets);
			atomic64_add(skb->len, &counter[d].bytes);
		}
	} while (0);

	if ((ct->status & IPS_DST_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do DNAT
			if (natflow_do_dnat6(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do SNAT
			if (natflow_do_snat6(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}

	if ((ct->status & IPS_SRC_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do SNAT
			if (natflow_do_snat6(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do DNAT
			if (natflow_do_dnat6(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		goto out6;
	}

#ifdef CONFIG_NETFILTER_INGRESS
	if (!(nf->status & NF_FF_FAIL)) {
		for (d = 0; d < NF_FF_DIR_MAX; d++) {
			if (d == NF_FF_DIR_ORIGINAL) {
				if (!(nf->status & NF_FF_ORIGINAL_CHECK) && !simple_test_and_set_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status)) {
fastnat_check6:
					do {
						struct in6_addr saddr = ct->tuplehash[d].tuple.src.u3.in6;
						struct in6_addr daddr = ct->tuplehash[d].tuple.dst.u3.in6;
						__be16 source = ct->tuplehash[d].tuple.src.u.all;
						__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
						__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;
						u32 hash = natflow_hash_v6(saddr.s6_addr32, daddr.s6_addr32, source, dest);
						natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];
						struct ethhdr *eth = (struct ethhdr *)nf->rroute[d].l2_head;

						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
						          nfn->source != source || nfn->dest != dest || NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
						          nfn->source != source || nfn->dest != dest || NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (memcmp(nfn->saddr6, saddr.s6_addr32, 16) || memcmp(nfn->daddr6, daddr.s6_addr32, 16) ||
						          nfn->source != source || nfn->dest != dest || NFN_PROTO_DEC(nfn->flags) != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
#endif
						if (!natflow_hash_skip(hash) &&
						        (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH ||
						         (memcmp(nfn->saddr6, saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, daddr.s6_addr32, 16) == 0 &&
						          nfn->source == source && nfn->dest == dest && NFN_PROTO_DEC(nfn->flags) == protonum))) {

							if (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH) {
								nfn->status = 0;
								nfn->flow_bytes = 0;
								nfn->flow_packets = 0;
								memset(nfn->speed_bytes, 0, sizeof(*nfn->speed_bytes) * 4);
								memset(nfn->speed_packets, 0, sizeof(*nfn->speed_packets) * 4);
							}

							nfn->flags = FASTNAT_L3NUM_IPV6;
							memcpy(nfn->saddr6, &saddr, 16);
							memcpy(nfn->daddr6, &daddr, 16);
							nfn->source = source;
							nfn->dest = dest;
							nfn->flags |= NFN_PROTO_ENC(protonum);

							memcpy(nfn->nat_saddr6, &ct->tuplehash[!d].tuple.dst.u3.in6, 16);
							memcpy(nfn->nat_daddr6, &ct->tuplehash[!d].tuple.src.u3.in6, 16);
							nfn->nat_source = ct->tuplehash[!d].tuple.dst.u.all;
							nfn->nat_dest = ct->tuplehash[!d].tuple.src.u.all;

							nfn->outdev = nf->rroute[d].outdev;
							nfn->ifindex = (u16)nf->rroute[!d].outdev->ifindex;
							nfn->mss = nf->rroute[d].mtu - sizeof(struct ipv6hdr) - sizeof(struct tcphdr);
							if (nf->rroute[d].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
								struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth + ETH_HLEN);
								nfn->pppoe_sid = ph->sid;
								nfn->flags |= FASTNAT_PPPOE_FLAG;
								nfn->flags &= ~FASTNAT_NO_ARP;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
							} else if (nf->rroute[d].l2_head_len == ETH_HLEN) {
								nfn->pppoe_sid = 0;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
								nfn->flags &= ~FASTNAT_NO_ARP;
							} else {
								nfn->flags |= FASTNAT_NO_ARP;
							}
							if (simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status))
								nfn->flags |= FASTNAT_BRIDGE_FWD;

							nfn->vlan_present = nf->rroute[d].vlan_present;
							nfn->vlan_proto = nf->rroute[d].vlan_proto;
							nfn->vlan_tci = nf->rroute[d].vlan_tci;
							nfn->magic = natflow_path_magic;
							nfn->jiffies = jiffies;
							nfn->keepalive_jiffies = jiffies;

							switch (IPV6H->nexthdr) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6 ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d)\n",
								             DEBUG_TCP_ARG6(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)ntohs(nfn->pppoe_sid) : -1);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6 ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d)\n",
								             DEBUG_UDP_ARG6(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)ntohs(nfn->pppoe_sid) : -1);
								break;
							}
						} else {
							/* mark FF_FAIL so never try FF */
							simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
							switch (IPV6H->nexthdr) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6 ": dir=%d skip hash=%d\n", DEBUG_TCP_ARG6(iph,l4), d, hash);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6 ": dir=%d skip hash=%d\n", DEBUG_UDP_ARG6(iph,l4), d, hash);
								break;
							}
						}

						if ((nf->status & NF_FF_ORIGINAL_CHECK) && (nf->status & NF_FF_REPLY_CHECK)) {
							if (nfn->magic == natflow_path_magic && ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
							        (memcmp(nfn->saddr6, saddr.s6_addr32, 16) == 0 && memcmp(nfn->daddr6, daddr.s6_addr32, 16) == 0 &&
							         nfn->source == source && nfn->dest == dest && NFN_PROTO_DEC(nfn->flags) == protonum)) {
								natflow_fastnat_node_t *nfn_i;
								saddr = ct->tuplehash[!d].tuple.src.u3.in6;
								daddr = ct->tuplehash[!d].tuple.dst.u3.in6;
								source = ct->tuplehash[!d].tuple.src.u.all;
								dest = ct->tuplehash[!d].tuple.dst.u.all;
								protonum = ct->tuplehash[!d].tuple.dst.protonum;
								hash = natflow_hash_v6(saddr.s6_addr32, daddr.s6_addr32, source, dest);
								nfn_i = &natflow_fast_nat_table[hash];

								if (memcmp(nfn_i->saddr6, saddr.s6_addr32, 16) || memcmp(nfn_i->daddr6, daddr.s6_addr32, 16) ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
#if (defined(CONFIG_PINCTRL_MT7988) || defined(CONFIG_PINCTRL_MT7986) || defined(CONFIG_PINCTRL_MT7981)) && (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
								if (memcmp(nfn_i->saddr6, saddr.s6_addr32, 16) || memcmp(nfn_i->daddr6, daddr.s6_addr32, 16) ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
								if (memcmp(nfn_i->saddr6, saddr.s6_addr32, 16) || memcmp(nfn_i->daddr6, daddr.s6_addr32, 16) ||
								        nfn_i->source != source || nfn_i->dest != dest || NFN_PROTO_DEC(nfn_i->flags) != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
#endif
								if (nfn_i->magic == natflow_path_magic && ulongmindiff(jiffies, nfn_i->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
								        (memcmp(nfn_i->saddr6, saddr.s6_addr32, 16) == 0 && memcmp(nfn_i->daddr6, daddr.s6_addr32, 16) == 0 &&
								         nfn_i->source == source && nfn_i->dest == dest && NFN_PROTO_DEC(nfn_i->flags) == protonum)) {
									nfn_i->jiffies = jiffies;
									nfn_i->keepalive_jiffies = jiffies;
									if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) {
										ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
										ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
									}
									if (d != NF_FF_DIR_ORIGINAL) {
										nfn = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
										nfn_i = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
										nfn = (void *)(((unsigned long)nfn) ^ ((unsigned long)nfn_i));
									}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
									if (hwnat && (re_learn == 2 || IPV6H->nexthdr == IPPROTO_UDP) && !(ct->status & (IPS_DST_NAT | IPS_SRC_NAT))) {
										/* hwnat enabled */
										struct net_device *orig_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
										struct net_device *reply_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_REPLY].outdev);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
										__be16 orig_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
										__be16 reply_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_REPLY].outdev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) /* no dsa support before kernel 5.4 in openwrt */
										/* hwnat ready to go */
										u16 orig_dsa_port = 0xffff;
										u16 reply_dsa_port = 0xffff;
										if (!orig_dev->netdev_ops->ndo_flow_offload && orig_dev->netdev_ops->ndo_flow_offload_check) {
											flow_offload_hw_path_t orig = {
												.dev = orig_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
											};
											orig_dev->netdev_ops->ndo_flow_offload_check(&orig);
											if (orig.dev != orig_dev) {
												orig_dev = orig.dev;
												orig_dsa_port = orig.dsa_port;
											}
											if ((orig.flags & FLOW_OFFLOAD_PATH_DSA))
												simple_set_bit(NF_FF_ORIGINAL_DSA_BIT, &nf->status);
										}
										if (!reply_dev->netdev_ops->ndo_flow_offload && reply_dev->netdev_ops->ndo_flow_offload_check) {
											flow_offload_hw_path_t reply = {
												.dev = reply_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
											};
											reply_dev->netdev_ops->ndo_flow_offload_check(&reply);
											if (reply.dev != reply_dev) {
												reply_dev = reply.dev;
												reply_dsa_port = reply.dsa_port;
											}
											if ((reply.flags & FLOW_OFFLOAD_PATH_DSA))
												simple_set_bit(NF_FF_REPLY_DSA_BIT, &nf->status);
										}
#endif
										simple_set_bit(NF_FF_ORIGINAL_OFFLOAD_BIT, &nf->status);
										simple_set_bit(NF_FF_REPLY_OFFLOAD_BIT, &nf->status);

										if (orig_dev->netdev_ops->ndo_flow_offload) {
											/* xxx: orig_dev has offload api */
											if (orig_dev == reply_dev || reply_dev->netdev_ops->ndo_flow_offload) {
												/* xxx: both orig_dev and reply_dev has offload api */
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);

												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}

												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (unlikely(!ppe_dev)) {
													ppe_dev = orig_dev;
												}
												if (orig_dev->netdev_ops->ndo_flow_offload(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload1 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             nfn_i->saddr6, ntohs(nfn_i->source),
													             nfn_i->daddr6, ntohs(nfn_i->dest));
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (IPV6H->nexthdr) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6
														             ": dir%d set hwnat offload1 failed\n",
														             DEBUG_TCP_ARG6(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6
														             ": dir%d set hwnat offload1 failed\n",
														             DEBUG_UDP_ARG6(iph,l4), dir);
														break;
													}
												}
												/* end: both orig_dev and reply_dev has offload api */
											}
#if !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
											else
											{
												/* xxx: olny orig_dev has offload api */
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												/* no vlan for ext dev */
												reply_dev = nf->rroute[NF_FF_DIR_REPLY].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												if (hwnat_wed_disabled) {
													reply_vid = (natflow->flow.timeout) & 0xffff;
												}
#endif
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												if (hwnat_wed_disabled) {
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto =
														    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													/* must set reply_vid */
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto = htons(ETH_P_8021Q);
													reply.vlan_id = reply_vid;
												} else {
#endif
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto =
														    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
														reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
														reply.vlan_proto =
														    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
														    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
													}
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
												}
#endif
												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (unlikely(!ppe_dev)) {
													ppe_dev = orig_dev;
												}
												if (orig_dev->netdev_ops->ndo_flow_offload(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload2 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             nfn_i->saddr6, ntohs(nfn_i->source),
													             nfn_i->daddr6, ntohs(nfn_i->dest));
													if (nf->rroute[NF_FF_DIR_REPLY].outdev == nfn->outdev) {
														nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
													} else {
														nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
													}
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (IPV6H->nexthdr) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6
														             ": dir%d set hwnat offload2 failed\n",
														             DEBUG_TCP_ARG6(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6
														             ": dir%d set hwnat offload2 failed\n",
														             DEBUG_UDP_ARG6(iph,l4), dir);
														break;
													}
												}
												/* end: olny orig_dev has offload api */
											}
											/* end: orig_dev has offload api */
										} else if (reply_dev->netdev_ops->ndo_flow_offload) {
											/* xxx: only reply_dev has offload api */
											struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
											flow_offload_hw_path_t orig = {
												.dev = orig_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
												| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
												| FLOW_OFFLOAD_PATH_WED_DIS
#endif
												,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
												.dsa_port = orig_dsa_port,
#endif
											};
											flow_offload_hw_path_t reply = {
												.dev = reply_dev,
												.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
												.dsa_port = reply_dsa_port,
#endif
											};
											/* no vlan for ext dev */
											orig_dev = nf->rroute[NF_FF_DIR_ORIGINAL].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											if (hwnat_wed_disabled) {
												orig_vid = (natflow->flow.timeout >> 16) & 0xffff;
											}
#endif
											if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
												orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
											}
											memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
											memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
											memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
											memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											if (hwnat_wed_disabled) {
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}
												/* must set orig_vid */
												orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
												orig.vlan_proto = htons(ETH_P_8021Q);
												orig.vlan_id = orig_vid;
											} else {
#endif
												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH)
											}
#endif
											if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
												orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
												orig.pppoe_sid =
												    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
											}
											if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
												reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
												reply.pppoe_sid =
												    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
											}
											if (unlikely(!ppe_dev)) {
												ppe_dev = reply_dev;
											}
											if (reply_dev->netdev_ops->ndo_flow_offload(
											            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
												NATFLOW_INFO("(PCO) dir%d set hwnat offload3 orig=[%s(vlan:%d pppoe:%d)"
												             " %pI6:%u->%pI6:%u] reply=[%s(vlan:%d pppoe:%d)"
												             " %pI6:%u->%pI6:%u]\n",
												             dir, nfn_i->outdev->name,
												             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
												             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
												             (int)ntohs(nfn_i->pppoe_sid) : -1,
												             nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest),
												             nfn->outdev->name,
												             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
												             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
												             (int)ntohs(nfn->pppoe_sid) : -1,
												             nfn_i->saddr6, ntohs(nfn_i->source),
												             nfn_i->daddr6, ntohs(nfn_i->dest));
												if (nf->rroute[NF_FF_DIR_ORIGINAL].outdev == nfn->outdev) {
													nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
												} else {
													nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
												}
											} else {
												/* mark FF_FAIL so never try FF */
												simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
												switch (IPV6H->nexthdr) {
												case IPPROTO_TCP:
													NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6
													             ": dir%d set hwnat offload3 failed\n",
													             DEBUG_TCP_ARG6(iph,l4), dir);
													break;
												case IPPROTO_UDP:
													NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6
													             ": dir%d set hwnat offload3 failed\n",
													             DEBUG_UDP_ARG6(iph,l4), dir);
													break;
												}
											}
											/* end: only reply_dev has offload api */
										} else {
#endif /* !defined(CONFIG_HWNAT_EXTDEV_DISABLED) */
											/* xxx: neither orig_dev nor reply_dev has offload api */
											if (flow_offload_add_extdev &&
											        (orig_dev->netdev_ops->ndo_fill_forward_path ||
											         reply_dev->netdev_ops->ndo_fill_forward_path)) {
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET
#if defined(CONFIG_NET_MEDIATEK_SOC_WED)
													| (hwnat_wed_disabled * FLOW_OFFLOAD_PATH_WED_DIS)
#else
													| FLOW_OFFLOAD_PATH_WED_DIS
#endif
													,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												if ((nfn->flags & FASTNAT_BRIDGE_FWD)) {
													orig.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
													reply.flags |= FLOW_OFFLOAD_PATH_BRIDGE;
												}
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);

												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto =
													    nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto =
													    nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													    htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}

												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (flow_offload_add_extdev && flow_offload_add_extdev(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) dir%d set hwnat offload4 orig=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u] reply=[%s(vlan:%d pppoe:%d)"
													             " %pI6:%u->%pI6:%u]\n",
													             dir, nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn_i->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn_i->pppoe_sid) : -1,
													             nfn->saddr6, ntohs(nfn->source), nfn->daddr6, ntohs(nfn->dest),
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ?
													             (int)ntohs(nfn->pppoe_sid) : -1,
													             nfn_i->saddr6, ntohs(nfn_i->source),
													             nfn_i->daddr6, ntohs(nfn_i->dest));
													nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
													nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (IPV6H->nexthdr) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT6
														             ": dir%d set hwnat offload4 failed\n",
														             DEBUG_TCP_ARG6(iph,l4), dir);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT6
														             ": dir%d set hwnat offload4 failed\n",
														             DEBUG_UDP_ARG6(iph,l4), dir);
														break;
													}
												}
											}
											/* end: neither orig_dev nor reply_dev has offload api */
										}
									} else {
										/* hwnat is not enabled */
									}
#endif
								} else {
									/* nfn is ready, but nfn_i is not */
								}
							} else {
								/* nfn is not ready */
							}
						} else {
							/* either NF_FF_ORIGINAL_CHECK or NF_FF_REPLY_CHECK is not ready */
						}
					} while (0);
				}
			} else {
				if (!(nf->status & NF_FF_REPLY_CHECK) && !simple_test_and_set_bit(NF_FF_REPLY_CHECK_BIT, &nf->status)) {
					goto fastnat_check6;
				}
			}
		} /* for (d = 0; d < NF_FF_DIR_MAX; d++) */
	} else {
		/* NF_FF_FAIL: loop try FF every 8 seconds */
		if (!(nf->status & NF_FF_RETRY)) {
			if ( ((jiffies + (((unsigned long)ct)^NATCAP_MAGIC)) / HZ) % 8 == 0 ) {
				simple_clear_bit(NF_FF_FAIL_BIT, &nf->status);
				simple_set_bit(NF_FF_RETRY_BIT, &nf->status);
			}
		} else {
			if ( ((jiffies + (((unsigned long)ct)^NATCAP_MAGIC)) / HZ) % 8 == 3 )
				simple_clear_bit(NF_FF_RETRY_BIT, &nf->status);
		}
	}
#endif

	if (skb_is_gso(skb)) {
		/* XXX: to xmit gso directly
		 * 1. hw offload features needed
		 * 2. hw csum features needed
		 * 3. ether type only
		 */
		netdev_features_t features = nf->rroute[dir].outdev->features;
		if (nf->rroute[dir].vlan_present)
			features = netdev_intersect_features(features,
			                                     nf->rroute[dir].outdev->vlan_features | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX);
		ingress_trim_off = (IPV6H->nexthdr == IPPROTO_TCP && (features & NETIF_F_TSO)) && \
		                   (features & (NETIF_F_HW_CSUM | NETIF_F_IPV6_CSUM)) && \
		                   nf->rroute[dir].l2_head_len == ETH_HLEN;
		if (!ingress_trim_off) {
			struct sk_buff *segs;
			skb->ip_summed = CHECKSUM_PARTIAL;
			segs = skb_gso_segment(skb, 0);
			if (IS_ERR(segs)) {
				return NF_DROP;
			}
			consume_skb(skb);
			skb = segs;
		}
	}

	do {
		struct sk_buff *next = skb->next;
		if (nf->rroute[dir].l2_head_len > skb_headroom(skb) && pskb_expand_head(skb, nf->rroute[dir].l2_head_len, skb_tailroom(skb), GFP_ATOMIC)) {
			kfree_skb_list(skb);
			return NF_STOLEN;
		}
		skb_push(skb, nf->rroute[dir].l2_head_len);
		skb_reset_mac_header(skb);
		memcpy(skb_mac_header(skb), nf->rroute[dir].l2_head, nf->rroute[dir].l2_head_len);
		skb->dev = nf->rroute[dir].outdev;
		if (nf->rroute[dir].l2_head_len == 0 && skb->dev->type == ARPHRD_ETHER) {
			skb_push(skb, ETH_HLEN);
			skb->mac_len = ETH_HLEN;
			skb_reset_mac_header(skb);
			eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IPV6);
		}
#ifdef CONFIG_NETFILTER_INGRESS
		if (nf->rroute[dir].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
			struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
			ph->length = htons(ntohs(ipv6_hdr(skb)->payload_len) + sizeof(struct ipv6hdr) + 2);
			skb->protocol = __constant_htons(ETH_P_PPP_SES);
		}
		if (nf->rroute[dir].vlan_present) {
			if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021Q)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nf->rroute[dir].vlan_tci);
			else if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021AD)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nf->rroute[dir].vlan_tci);
		} else if (skb_vlan_tag_present(skb))
			__vlan_hwaccel_clear_tag(skb);
#endif
		skb->next = NULL;
		dev_queue_xmit(skb);
		skb = next;
	} while (skb);

	return NF_STOLEN;

out6:
#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		struct net_device *outdev;
		int vline_filter = 0;

		if (skb->protocol == __constant_htons(ETH_P_IPV6) && skb->dev->ifindex < VLINE_FWD_MAX_NUM && (outdev = vline_fwd_map[skb->dev->ifindex]) != NULL) {
			if (IP_SET_test_dst_netport(state, in, out, skb, "vline_filter6_dst_netport") > 0 ||
			        IP_SET_test_dst_ip(state, in, out, skb, "vline_filter6_dst") > 0 ||
			        IP_SET_test_src_ip(state, in, out, skb, "vline_filter6_src") > 0 ||
			        IP_SET_test_src_mac(state, in, out, skb, "vline_filter_src_mac") > 0) {
				vline_filter = 1;
			}
		}

		if (ingress_pad_len == PPPOE_SES_HLEN) {
			skb->protocol = cpu_to_be16(ETH_P_PPP_SES);
			skb_push_rcsum(skb, PPPOE_SES_HLEN);
			skb->network_header -= PPPOE_SES_HLEN;
		}
		if (ingress_trim_off) {
			skb->len += ingress_trim_off;
		}
		if (vline_filter) {
			return ret;
		}
		//XXXXXXXX
		if (skb->dev->ifindex < VLINE_FWD_MAX_NUM && (outdev = vline_fwd_map[skb->dev->ifindex]) != NULL) {
			if (!(skb->dev->flags & IFF_VLINE_FAMILY_IPV4) ||
			        skb->protocol == __constant_htons(ETH_P_PPP_DISC) ||
			        skb->protocol == __constant_htons(ETH_P_PPP_SES) ||
			        skb->protocol != __constant_htons(ETH_P_IPV6) /* for unknown packets */) {
				//XXX: relay
				if ((outdev->flags & IFF_VLINE_RELAY)) {
					natflow_fakeuser_t *user;
					if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
						iph = (void *)ipv6_hdr(skb);
						l4 = (void *)iph + sizeof(struct ipv6hdr);

						if (IPV6H->nexthdr == IPPROTO_ICMPV6
						        && (ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
						            ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT ||
						            ICMP6H(l4)->icmp6_type == NDISC_ROUTER_SOLICITATION ||
						            ICMP6H(l4)->icmp6_type == NDISC_ROUTER_ADVERTISEMENT)) {
							struct ethhdr *eth;
							user = natflow_user_find_get6((union nf_inet_addr *)&IPV6H->daddr);
							if (user) {
								struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
								if (((skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 0) ||
								        (!(skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 1)) {
									eth = eth_hdr(skb);
									ether_addr_copy(eth->h_dest, fud->macaddr);
									natflow_user_release_put(user);
									ret = NF_STOLEN;
								} else {
									skb = skb_copy(skb, GFP_ATOMIC);
									if (!skb) {
										natflow_user_release_put(user);
										return ret;
									}
									eth = eth_hdr(skb);
									ether_addr_copy(eth->h_dest, fud->macaddr);
									natflow_user_release_put(user);
								}
							} else {
								skb = skb_copy(skb, GFP_ATOMIC);
								if (!skb) {
									return ret;
								}
							}

							if (!pskb_may_pull(skb, skb->len) || skb_try_make_writable(skb, skb->len)) {
								return ret;
							}
							iph = (void *)ipv6_hdr(skb);
							l4 = (void *)iph + sizeof(struct ipv6hdr);

							do {
								unsigned char *opt_ptr;
								eth = eth_hdr(skb);
								user = natflow_user_in_get6((union nf_inet_addr *)&IPV6H->saddr, eth->h_source);
								if (user) {
									struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
									if ((skb->dev->flags & IFF_IS_LAN)) {
										if (fud->vline_lan != 1) fud->vline_lan = 1;
									} else {
										if (fud->vline_lan != 0) fud->vline_lan = 0;
									}
								}
								natflow_user_release_put(user);
								ether_addr_copy(eth->h_source, outdev->dev_addr);

								opt_ptr = (unsigned char *)(l4 + 8); //RS ptr options
								if (ICMP6H(l4)->icmp6_type == NDISC_ROUTER_ADVERTISEMENT) {
									opt_ptr = (unsigned char *)(l4 + 16);
								} else if (ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
								           ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT) {
									opt_ptr = (unsigned char *)(l4 + 24);
								}

								while (opt_ptr + 2 <= skb_tail_pointer(skb)) {
									u8 opt_type = opt_ptr[0];
									u8 opt_len = opt_ptr[1] * 8;
									if (opt_len == 0 || opt_ptr + opt_len > skb_tail_pointer(skb))
										break;
									if ((opt_type == 1 || opt_type == 2 /* NA */) && opt_len >= 8) {
										memcpy(opt_ptr + 2, outdev->dev_addr, ETH_ALEN);
										ICMP6H(l4)->icmp6_cksum = 0;
										ICMP6H(l4)->icmp6_cksum = csum_ipv6_magic(&IPV6H->saddr,
										                          &IPV6H->daddr,
										                          skb->len - sizeof(struct ipv6hdr),
										                          IPPROTO_ICMPV6,
										                          csum_partial(l4, skb->len - sizeof(struct ipv6hdr), 0));
										break;
									}
									opt_ptr += opt_len;
								}
							} while (0);
							skb_push(skb, ETH_HLEN);
							skb_reset_mac_header(skb);
							skb->dev = outdev;
							dev_queue_xmit(skb);
							return ret;
						}
					}

					if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
						if (!pskb_may_pull(skb, skb->len) || skb_try_make_writable(skb, skb->len)) {
							return NF_DROP;
						}
						skb = skb_copy(skb, GFP_ATOMIC);
						if (!skb) {
							return ret;
						}
						skb_push(skb, ETH_HLEN);
						skb_reset_mac_header(skb);
						skb->dev = outdev;
						do {
							struct ethhdr *eth = eth_hdr(skb);
							ether_addr_copy(eth->h_source, outdev->dev_addr);
						} while (0);
						dev_queue_xmit(skb);
						return ret;
					}

					if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
						iph = (void *)ipv6_hdr(skb);
						user = natflow_user_find_get6((union nf_inet_addr *)&IPV6H->daddr);
						if (user) {
							struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
							if (((skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 0) ||
							        (!(skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 1)) {
								struct ethhdr *eth = eth_hdr(skb);
								ether_addr_copy(eth->h_dest, fud->macaddr);
								natflow_user_release_put(user);
							} else {
								//go kernel route path
								return ret;
							}
						} else {
							//go kernel route path
							return ret;
						}
					}

					ct = nf_ct_get(skb, &ctinfo);
					if (ct) {
						unsigned int mtu;
						dir = CTINFO2DIR(ctinfo);
						nf = natflow_session_get(ct);
						if (nf) {
							if (!(nf->status & (NF_FF_BRIDGE | NF_FF_ROUTE))) {
								simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
							}
							if (skb_dst(skb)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
								mtu = ip_skb_dst_mtu(skb);
#else
								mtu = ip_skb_dst_mtu(NULL, skb);
#endif
								if (nf->rroute[dir].mtu != mtu) {
									nf->rroute[dir].mtu = mtu;
								}
							}
						}
					}

					ret = nf_conntrack_confirm(skb);
					if (ret != NF_ACCEPT) {
						return ret;
					}

					skb_push(skb, ETH_HLEN);
					skb_reset_mac_header(skb);
					skb->dev = outdev;
					do {
						struct ethhdr *eth = eth_hdr(skb);
						ether_addr_copy(eth->h_source, outdev->dev_addr);
					} while (0);
					dev_queue_xmit(skb);
					return NF_STOLEN;
				}

				//XXX: vline
				if (!(skb->dev->flags & IFF_NOARP) && unlikely(is_link_local_ether_addr(eth_hdr(skb)->h_dest))) {
					switch (eth_hdr(skb)->h_dest[5]) {
					case 0x01: /* IEEE MAC (Pause) */
						return ret;
					case 0x00: /* Bridge Group Address */
					case 0x0E: /* 802.1AB LLDP */
					default: /* Allow selective forwarding for most other protocols */
						if (!(outdev->flags & IFF_NOARP)) {
							skb_push(skb, ETH_HLEN);
							skb_reset_mac_header(skb);
							skb->dev = outdev;
							dev_queue_xmit(skb);
							return NF_STOLEN;
						}
					}
					return ret;
				}

				if ((skb->dev->flags & IFF_NOARP)) {
					if (!(outdev->flags & IFF_NOARP)) { /* in:IFF_NOARP --> out:!IFF_NOARP */
						if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
							int dest_found = 0;
							struct ethhdr *eth;

							iph = (void *)ipv6_hdr(skb);
							eth = (void *)((unsigned char *)iph - ETH_HLEN);

							eth->h_proto = __constant_htons(ETH_P_IPV6);
							if (IPV6H->saddr.s6_addr16[0] == __constant_htons(0xfe80)
							        // && IPV6H->saddr.s6_addr[11] == 0xff
							        // && IPV6H->saddr.s6_addr[12] == 0xfe // XXX: fake EUI-64 even it is not */
							   ) {
								eth->h_source[0] = IPV6H->saddr.s6_addr[8] ^ 0x02;
								eth->h_source[1] = IPV6H->saddr.s6_addr[9];
								eth->h_source[2] = IPV6H->saddr.s6_addr[10];
								eth->h_source[3] = IPV6H->saddr.s6_addr[13];
								eth->h_source[4] = IPV6H->saddr.s6_addr[14];
								eth->h_source[5] = IPV6H->saddr.s6_addr[15];
							} else {
								ether_addr_copy(eth->h_source, outdev->dev_addr);
							}

							if (IPV6H->daddr.s6_addr[11] == 0xff && IPV6H->daddr.s6_addr[12] == 0xfe) {
								eth->h_dest[0] = IPV6H->daddr.s6_addr[8] ^ 0x02;
								eth->h_dest[1] = IPV6H->daddr.s6_addr[9];
								eth->h_dest[2] = IPV6H->daddr.s6_addr[10];
								eth->h_dest[3] = IPV6H->daddr.s6_addr[13];
								eth->h_dest[4] = IPV6H->daddr.s6_addr[14];
								eth->h_dest[5] = IPV6H->daddr.s6_addr[15];
								skb->pkt_type = PACKET_MULTICAST; /* fake PACKET_MULTICAST */
								dest_found = 1;
							} else if (ipv6_addr_is_multicast(&IPV6H->daddr)) {
								eth->h_dest[0] = 0x33;
								eth->h_dest[1] = 0x33;
								eth->h_dest[2] = IPV6H->daddr.s6_addr[12];
								eth->h_dest[3] = IPV6H->daddr.s6_addr[13];
								eth->h_dest[4] = IPV6H->daddr.s6_addr[14];
								eth->h_dest[5] = IPV6H->daddr.s6_addr[15];
								skb->pkt_type = PACKET_MULTICAST;
								dest_found = 1;
							}

							do {
								/* try fetch h_dest from user info */
								natflow_fakeuser_t *user;
								struct fakeuser_data_t *fud;
								user = natflow_user_find_get6((union nf_inet_addr *)&IPV6H->daddr);
								if (user) {
									fud = natflow_fakeuser_data(user);
									ether_addr_copy(eth->h_dest, fud->macaddr);
									natflow_user_release_put(user);
								} else if (dest_found == 0) {
									return ret;
								}
							} while (0);
						}
					}
				}

				if ((outdev->flags & IFF_NOARP)) {
					do {
						//received Neighbor Solicitation
						//fake and reply Neighbor Advertisement for link local address
						if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
							unsigned char *ta;
							iph = (void *)ipv6_hdr(skb);
							l4 = (void *)iph + sizeof(struct ipv6hdr);
							if (IPV6H->nexthdr != IPPROTO_ICMPV6 || ICMP6H(l4)->icmp6_type != NDISC_NEIGHBOUR_SOLICITATION) {
								break;
							}

							if (!pskb_may_pull(skb, skb->len) || skb_try_make_writable(skb, skb->len)) {
								return NF_DROP;
							}
							iph = (void *)ipv6_hdr(skb);
							l4 = (void *)iph + sizeof(struct ipv6hdr);

							if (skb->len >= sizeof(struct ipv6hdr) + 8 + 16) {
								struct ethhdr *eth;

								if (skb->len < sizeof(struct ipv6hdr) + 8 + 16 + 8 &&
								        pskb_expand_head(skb, skb_headroom(skb), sizeof(struct ipv6hdr) + 8 + 16 + 8 - skb->len, GFP_ATOMIC)) {
									break;
								}
								iph = (void *)ipv6_hdr(skb);
								l4 = (void *)iph + sizeof(struct ipv6hdr);

								skb->len = sizeof(struct ipv6hdr) + 8 + 16 + 8;

								ta = l4 + 8;
								if (!(ta[0] == 0xfe && ta[1] == 0x80 && ta[11] == 0xff && ta[12] == 0xfe)) {
									break;
								}

								eth = eth_hdr(skb);

								ICMP6H(l4)->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
								ICMP6H(l4)->icmp6_code = 0;
								ICMP6H(l4)->icmp6_cksum = 0;

								ICMP6H(l4)->icmp6_router = 1;
								ICMP6H(l4)->icmp6_solicited = 1;
								ICMP6H(l4)->icmp6_override = 0;
								ICMP6H(l4)->icmp6_ndiscreserved = 0;

								IPV6H->daddr = IPV6H->saddr;
								memcpy(&IPV6H->saddr, ta, 16);

								ether_addr_copy(eth->h_dest, eth->h_source);
								eth->h_source[0] = ta[8] ^ 0x02;
								eth->h_source[1] = ta[9];
								eth->h_source[2] = ta[10];
								eth->h_source[3] = ta[13];
								eth->h_source[4] = ta[14];
								eth->h_source[5] = ta[15];

								ta[16] = 1; //Type: Source link-layer address
								ta[17] = 1; //Length: 8 bytes
								ether_addr_copy(ta + 18, eth->h_source);

								ICMP6H(l4)->icmp6_cksum = csum_ipv6_magic(&IPV6H->saddr,
								                          &IPV6H->daddr,
								                          skb->len - sizeof(struct ipv6hdr),
								                          IPPROTO_ICMPV6,
								                          csum_partial(l4, skb->len - sizeof(struct ipv6hdr), 0));

								skb_push(skb, ETH_HLEN);
								dev_queue_xmit(skb);
								return NF_STOLEN;
							}
						}
					} while (0);
				}

				if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
					skb = skb_clone(skb, GFP_ATOMIC);
					if (!skb) {
						return ret;
					}
					if (!(outdev->flags & IFF_NOARP)) {
						skb_push(skb, ETH_HLEN);
						skb_reset_mac_header(skb);
					}
					skb->dev = outdev;
					dev_queue_xmit(skb);
					return ret;
				}

				if (!(skb->dev->flags & IFF_NOARP)) {
					if ((skb->dev->flags & IFF_VLINE_L2_PORT)) {
						struct net_device *upper_dev = netdev_master_upper_dev_get_rcu(skb->dev);
						if (upper_dev && ether_addr_equal(upper_dev->dev_addr, eth_hdr(skb)->h_dest)) {
							return  ret;
						}
					} else if (ether_addr_equal(skb->dev->dev_addr, eth_hdr(skb)->h_dest)) {
						return ret;
					}
				}

				if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
					natflow_fakeuser_t *user;
					struct fakeuser_data_t *fud;

					iph = (void *)ipv6_hdr(skb);
					l4 = (void *)iph + sizeof(struct ipv6hdr);

					if ((skb->dev->flags & IFF_IS_LAN)) {
						struct inet6_dev *idev;
						struct inet6_ifaddr *ifp;

						idev = __in6_dev_get(outdev);
						if (idev) {
							read_lock_bh(&idev->lock);
							list_for_each_entry(ifp, &idev->addr_list, if_list) {
								if (ifp->addr.s6_addr16[0] == __constant_htons(0xfe80)) {
									continue;
								}
								if (ipv6_prefix_equal(&IPV6H->daddr, &ifp->addr, ifp->prefix_len)) {
									read_unlock_bh(&idev->lock);
									return ret;
								}
							}
							read_unlock_bh(&idev->lock);
						}
					}

					user = natflow_user_find_get6((union nf_inet_addr *)&IPV6H->saddr);
					if (user) {
						fud = natflow_fakeuser_data(user);
						if ((skb->dev->flags & IFF_IS_LAN)) {
							if (fud->vline_lan != 1) fud->vline_lan = 1;
						} else {
							if (fud->vline_lan != 0) fud->vline_lan = 0;
						}
						natflow_user_release_put(user);
					}

					user = natflow_user_find_get6((union nf_inet_addr *)&IPV6H->daddr);
					if (user) {
						fud = natflow_fakeuser_data(user);
						if (((skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 1)
						        || (!(skb->dev->flags & IFF_IS_LAN) && fud->vline_lan == 0)) {
							natflow_user_release_put(user);
							return ret;
						}
						natflow_user_release_put(user);
					}

					if (IPV6H->nexthdr == IPPROTO_ICMPV6
					        && (ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
					            ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT ||
					            ICMP6H(l4)->icmp6_type == NDISC_ROUTER_SOLICITATION ||
					            ICMP6H(l4)->icmp6_type == NDISC_ROUTER_ADVERTISEMENT)) {
						// flood NS/NA/RS/RA packets
						skb = skb_clone(skb, GFP_ATOMIC);
						if (!skb) {
							return ret;
						}
						if (!(outdev->flags & IFF_NOARP)) {
							skb_push(skb, ETH_HLEN);
							skb_reset_mac_header(skb);
						}
						skb->dev = outdev;
						dev_queue_xmit(skb);
						return ret;
					}
				}

				ct = nf_ct_get(skb, &ctinfo);
				if (!ct) {
					if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
						iph = (void *)ipv6_hdr(skb);
						l4 = (void *)iph + sizeof(struct ipv6hdr);
						if (IPV6H->nexthdr == IPPROTO_ICMPV6
						        && !(ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION ||
						             ICMP6H(l4)->icmp6_type == NDISC_NEIGHBOUR_ADVERTISEMENT ||
						             ICMP6H(l4)->icmp6_type == NDISC_ROUTER_SOLICITATION ||
						             ICMP6H(l4)->icmp6_type == NDISC_ROUTER_ADVERTISEMENT)) {
							ret = nf_conntrack_in_compat(dev_net(skb->dev), AF_INET6, NF_INET_PRE_ROUTING, skb);
							if (ret != NF_ACCEPT) {
								return ret;
							}
							ct = nf_ct_get(skb, &ctinfo);
						}
					}
				}
				if (ct) {
					unsigned int mtu;
					dir = CTINFO2DIR(ctinfo);
					nf = natflow_session_get(ct);
					if (nf) {
						if (!(nf->status & (NF_FF_BRIDGE | NF_FF_ROUTE))) {
							simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
						}
						if (skb_dst(skb)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
							mtu = ip_skb_dst_mtu(skb);
#else
							mtu = ip_skb_dst_mtu(NULL, skb);
#endif
							if (nf->rroute[dir].mtu != mtu) {
								nf->rroute[dir].mtu = mtu;
							}
						}
					}
					if ((skb->dev->flags & IFF_IS_LAN)) {
						natflow_fakeuser_t *user;
						struct fakeuser_data_t *fud;

						user = natflow_user_in(ct, dir);
						if (user) {
							fud = natflow_fakeuser_data(user);
							if (timestamp_offset(fud->timestamp, jiffies) >= 8 * HZ) {
								if (memcmp(eth_hdr(skb)->h_source, fud->macaddr, ETH_ALEN) != 0) {
									memcpy(fud->macaddr, eth_hdr(skb)->h_source, ETH_ALEN);
								}
								fud->timestamp = jiffies;
								natflow_user_timeout_touch(user);
							}
						}
					}
				}

				ret = nf_conntrack_confirm(skb);
				if (ret != NF_ACCEPT) {
					return ret;
				}

				if (!(outdev->flags & IFF_NOARP)) {
					skb_push(skb, ETH_HLEN);
					skb_reset_mac_header(skb);
				}
				skb->dev = outdev;
				dev_queue_xmit(skb);
				return NF_STOLEN;
			}
		}
	}
#else
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}
#endif
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_path_post_ct_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_post_ct_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	natflow_t *nf;
	unsigned int mtu;
	int dir = 0;
	int ret = NF_ACCEPT;
	int bridge = 0;

	if (disabled)
		return NF_ACCEPT;

	/* only bridge come here */
	if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IP);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
	} else if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	           pppoe_proto(skb) == __constant_htons(PPP_IPV6) /* Internet Protocol version 6 */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IPV6);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
	} else if (skb->protocol != __constant_htons(ETH_P_IP) && skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return NF_ACCEPT;
	}


	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}
	nf = natflow_session_get(ct);
	if (NULL == nf) {
		goto out;
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		goto out;
	}
	/* must reload ct after confirm */
	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}
	nf = natflow_session_get(ct);
	if (NULL == nf) {
		goto out;
	}
	iph = iph->version == 4 ? ip_hdr(skb) : (void *)ipv6_hdr(skb);
	l4 = (void *)iph + (iph->version == 4 ? iph->ihl * 4 : sizeof(struct ipv6hdr));

	dir = CTINFO2DIR(ctinfo);
	if (!((dir == IP_CT_DIR_ORIGINAL && (nf->status & NF_FF_REPLY_OK)) ||
	        (dir == IP_CT_DIR_REPLY && (nf->status & NF_FF_ORIGINAL_OK))))
		goto out;

	/* fastnat in learning state */
	if (!(nf->status & (NF_FF_BRIDGE | NF_FF_ROUTE))) {
		struct nf_conn_help *help = nfct_help(ct);
		if (help && help->helper) {
			/* this conn need helper */
			set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
		}
		if (iph->version == 4) {
			if (nf->rroute[!dir].ttl_in == iph->ttl) {
				/* ttl no change, so assume bridge forward */
				simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
				switch (iph->protocol) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": dir=%d ttl %d -> %d no change, pf=%d\n",
					              DEBUG_TCP_ARG(iph,l4), dir, nf->rroute[!dir].ttl_in, iph->ttl, pf);
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": dir=%d ttl %d -> %d no change, pf=%d\n",
					              DEBUG_UDP_ARG(iph,l4), dir, nf->rroute[!dir].ttl_in, iph->ttl, pf);
					break;
				}
			} else {
				simple_set_bit(NF_FF_ROUTE_BIT, &nf->status);
				switch (iph->protocol) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": dir=%d ttl %d -> %d, pf=%d\n",
					              DEBUG_TCP_ARG(iph,l4), dir, nf->rroute[!dir].ttl_in, iph->ttl, pf);
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": dir=%d ttl %d -> %d, pf=%d\n",
					              DEBUG_UDP_ARG(iph,l4), dir, nf->rroute[!dir].ttl_in, iph->ttl, pf);
					break;
				}
			}
		} else {
			if (nf->rroute[!dir].ttl_in == IPV6H->hop_limit) {
				/* ttl no change, so assume bridge forward */
				simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
				switch (IPV6H->nexthdr) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT6 ": dir=%d ttl %d -> %d no change, pf=%d\n",
					              DEBUG_TCP_ARG6(iph,l4), dir, nf->rroute[!dir].ttl_in, IPV6H->hop_limit, pf);
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT6 ": dir=%d ttl %d -> %d no change, pf=%d\n",
					              DEBUG_UDP_ARG6(iph,l4), dir, nf->rroute[!dir].ttl_in, IPV6H->hop_limit, pf);
					break;
				}
			} else {
				simple_set_bit(NF_FF_ROUTE_BIT, &nf->status);
				switch (IPV6H->nexthdr) {
				case IPPROTO_TCP:
					NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT6 ": dir=%d ttl %d -> %d, pf=%d\n",
					              DEBUG_TCP_ARG6(iph,l4), dir, nf->rroute[!dir].ttl_in, IPV6H->hop_limit, pf);
					break;
				case IPPROTO_UDP:
					NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT6 ": dir=%d ttl %d -> %d, pf=%d\n",
					              DEBUG_UDP_ARG6(iph,l4), dir, nf->rroute[!dir].ttl_in, IPV6H->hop_limit, pf);
					break;
				}
			}
		}
	}

	if (!skb_dst(skb))
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	mtu = ip_skb_dst_mtu(skb);
#else
	mtu = ip_skb_dst_mtu(NULL, skb);
#endif
	if (nf->rroute[dir].mtu != mtu) {
		if (iph->version == 4) {
			switch (iph->protocol) {
			case IPPROTO_TCP:
				NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": update pmtu from %u to %u\n", DEBUG_TCP_ARG(iph,l4), nf->rroute[dir].mtu, mtu);
				break;
			case IPPROTO_UDP:
				NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": update pmtu from %u to %u\n", DEBUG_UDP_ARG(iph,l4), nf->rroute[dir].mtu, mtu);
				break;
			}
		} else {
			switch (IPV6H->nexthdr) {
			case IPPROTO_TCP:
				NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT6 ": update pmtu from %u to %u\n", DEBUG_TCP_ARG6(iph,l4), nf->rroute[dir].mtu, mtu);
				break;
			case IPPROTO_UDP:
				NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT6 ": update pmtu from %u to %u\n", DEBUG_UDP_ARG6(iph,l4), nf->rroute[dir].mtu, mtu);
				break;
			}
		}
		nf->rroute[dir].mtu = mtu;
	}

out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}
	return ret;
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
static void natflow_hwnat_stop(struct net_device *dev)
{

	flow_offload_hw_path_t stop = {
		.dev = dev,
		.flags = FLOW_OFFLOAD_PATH_ETHERNET | FLOW_OFFLOAD_PATH_STOP,
	};

	if (dev->netdev_ops && dev->netdev_ops->ndo_flow_offload && dev->netdev_ops->ndo_flow_offload_check) {
		dev->netdev_ops->ndo_flow_offload_check(&stop);
	}
}
#endif

static struct nf_hook_ops path_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 + 8,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = AF_INET6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 + 8,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 + 8,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_pre_ct_in_hook,
		.pf = AF_INET6,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
#ifndef CONFIG_NETFILTER_INGRESS
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_pre_ct_in_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
#endif
};

#ifdef CONFIG_NETFILTER_INGRESS
struct natflow_hook_t {
	struct hlist_node list;
	struct nf_hook_ops ops;
};

static HLIST_HEAD(natflow_hooks);
static DEFINE_SPINLOCK(natflow_hooks_lock);

static struct natflow_hook_t *natflow_lookup_hook(struct net_device *dev)
{
	struct natflow_hook_t *hook;

	hlist_for_each_entry(hook, &natflow_hooks, list) {
		if (hook->ops.dev == dev)
			return hook;
	}

	return NULL;
}

static void natflow_check_device(struct net_device *dev)
{
	struct nf_hook_ops *ops = NULL;
	struct natflow_hook_t *hook;

	spin_lock_bh(&natflow_hooks_lock);
	hook = natflow_lookup_hook(dev);
	if (!hook) {
		hook = kzalloc(sizeof(*hook), GFP_ATOMIC);
		if (hook) {
			ops = &hook->ops;
			ops->pf = NFPROTO_NETDEV;
			ops->hooknum = NF_NETDEV_INGRESS;
			ops->priority = 9;
			ops->hook = natflow_path_pre_ct_in_hook;
			ops->dev = dev;

			hlist_add_head(&hook->list, &natflow_hooks);
		}
	}
	spin_unlock_bh(&natflow_hooks_lock);

	if (ops)
		nf_register_net_hook(dev_net(dev), ops);
}

static void natflow_unhook_device(struct net_device *dev)
{
	struct natflow_hook_t *hook;
	spin_lock_bh(&natflow_hooks_lock);
	hook = natflow_lookup_hook(dev);
	if (hook) {
		hlist_del(&hook->list);
	}
	spin_unlock_bh(&natflow_hooks_lock);
	if (hook) {
		nf_unregister_net_hook(dev_net(dev), &hook->ops);
		kfree(hook);
	}
}
#endif

static int natflow_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event == NETDEV_UP || event == NETDEV_CHANGE) {
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		if (dev->type == ARPHRD_PPP && dev->netdev_ops->ndo_flow_offload_check) {
			flow_offload_hw_path_t path = {
				.dev = dev,
				.flags = FLOW_OFFLOAD_PATH_ETHERNET,
			};
			dev->netdev_ops->ndo_flow_offload_check(&path);
			if ((path.flags & FLOW_OFFLOAD_PATH_PPPOE)) {
				dev->flags |= IFF_PPPOE;
				NATFLOW_println("catch event %lu for dev=%s : set flags IFF_PPPOE", event, dev->name);
			}
		}
		if (!ppe_dev) {
			if (dev->netdev_ops->ndo_flow_offload) {
				ppe_dev = dev;
			}
		}
#else
		if (dev->type == ARPHRD_PPP &&
		        (dev->name[0] == 'p' && dev->name[1] == 'p' && dev->name[2] == 'p' && dev->name[3] == 'o' && dev->name[4] == 'e')) {
			dev->flags |= IFF_PPPOE;
			NATFLOW_println("catch event %lu for dev=%s : set flags IFF_PPPOE", event, dev->name);
		}
#endif
		vline_fwd_map_ifup_handle(dev);
	}

#ifdef CONFIG_NETFILTER_INGRESS
	if (event == NETDEV_UP) {
		if (!((dev->flags & IFF_LOOPBACK) ||
		        netif_is_bridge_master(dev) ||
		        netif_is_ovs_master(dev) ||
		        netif_is_bond_master(dev) ||
		        netif_is_macvlan(dev)) ||
		        dev->type == ARPHRD_RAWIP) {
			netdev_features_t features = dev->features;
			netdev_features_t vlan_features = netdev_intersect_features(features, dev->vlan_features | NETIF_F_HW_VLAN_CTAG_TX | NETIF_F_HW_VLAN_STAG_TX);
			NATFLOW_println("catch NETDEV_UP event for dev=%s(tso=%d,%d,hw_csum=%d,%d), add ingress hook",
			                dev->name,
			                !!(features & NETIF_F_TSO),
			                !!(vlan_features & NETIF_F_TSO),
			                !!(features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)),
			                !!(vlan_features & (NETIF_F_HW_CSUM | NETIF_F_IP_CSUM)));
			natflow_check_device(dev);
		}
		return NOTIFY_DONE;
	}
#endif

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

#ifdef CONFIG_NETFILTER_INGRESS
	natflow_unhook_device(dev);
#endif

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	natflow_hwnat_stop(dev);
#endif
	natflow_update_magic(0);
	vline_fwd_map_unregister_handle(dev);

	NATFLOW_println("catch NETDEV_UNREGISTER event for dev=%s", dev->name);

	synchronize_net();

	return NOTIFY_DONE;
}

static struct notifier_block natflow_netdev_notifier = {
	.notifier_call  = natflow_netdev_event,
};

int natflow_path_init(void)
{
	int ret = 0;

	natflow_probe_ct_ext();

#ifdef CONFIG_NETFILTER_INGRESS
	natflow_fast_nat_table = kmalloc(sizeof(natflow_fastnat_node_t) * NATFLOW_FASTNAT_TABLE_SIZE, GFP_KERNEL);
	if (natflow_fast_nat_table == NULL) {
		return -ENOMEM;
	}
#endif

	vline_fwd_map_config_clear();
	vline_fwd_map_config_apply();
	need_conntrack();
	natflow_update_magic(1);

	register_netdevice_notifier(&natflow_netdev_notifier);

	ret = nf_register_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	return 0;
nf_register_hooks_failed:
	unregister_netdevice_notifier(&natflow_netdev_notifier);
#ifdef CONFIG_NETFILTER_INGRESS
	kfree(natflow_fast_nat_table);
#endif
	return ret;
}

void natflow_path_exit(void)
{
	disabled = 1;
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	unregister_netdevice_notifier(&natflow_netdev_notifier);
#ifdef CONFIG_NETFILTER_INGRESS
	synchronize_rcu();
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	if (ppe_dev) {
		int i;
		flow_offload_hw_path_t del = {
			.dev = ppe_dev,
			.flags = FLOW_OFFLOAD_PATH_ETHERNET | FLOW_OFFLOAD_PATH_DEL,
		};
		natflow_hwnat_stop(ppe_dev);
		for (i = 0; i < NATFLOW_FASTNAT_TABLE_SIZE / 2; i++) {
			del.vlan_id = (unsigned short)i;
			del.vlan_proto = NATFLOW_FASTNAT_TABLE_SIZE - 1 - i;
			ppe_dev->netdev_ops->ndo_flow_offload_check(&del);
		}
		synchronize_rcu();
	}
#endif
	kfree(natflow_fast_nat_table);
#else
	synchronize_rcu();
#endif
}
