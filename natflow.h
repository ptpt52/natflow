/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:46 +0800
 */
#ifndef _NATFLOW_H_
#define _NATFLOW_H_

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>

#define MAX_IOCTL_LEN 256

typedef struct natflow_route_t {
	/* max L2 len supoorted
	 * mac + pppoe (=14 + 8)
	 */
#define NF_L2_MAX_LEN (14 + 8)
	unsigned short mtu;
#define FF_ETH_P_8021Q 0
#define FF_ETH_P_8021AD 1
	unsigned short vlan_present:1;
	unsigned short vlan_proto:3;
	unsigned short vlan_tci:12;
	unsigned char l2_head[NF_L2_MAX_LEN];
	unsigned short l2_head_len;
	unsigned short ttl_in;
	struct net_device *outdev;
} natflow_route_t;

#define NF_FF_OFFLOAD_BIT 0
#define NF_FF_OFFLOAD (1 << NF_FF_OFFLOAD_BIT)

#define NF_FF_ORIGINAL_DSA_BIT 1
#define NF_FF_ORIGINAL_DSA (1 << NF_FF_ORIGINAL_DSA_BIT)

#define NF_FF_REPLY_DSA_BIT 2
#define NF_FF_REPLY_DSA (1 << NF_FF_REPLY_DSA_BIT)

#define NF_FF_ORIGINAL_BIT 8
#define NF_FF_ORIGINAL (1 << NF_FF_ORIGINAL_BIT)
#define NF_FF_REPLY_BIT 9
#define NF_FF_REPLY (1 << NF_FF_REPLY_BIT)
#define NF_FF_ORIGINAL_OK_BIT 10
#define NF_FF_ORIGINAL_OK (1 << NF_FF_ORIGINAL_OK_BIT)
#define NF_FF_REPLY_OK_BIT 11
#define NF_FF_REPLY_OK (1 << NF_FF_REPLY_OK_BIT)

#define NF_FF_ORIGINAL_CHECK_BIT 12
#define NF_FF_ORIGINAL_CHECK (1 << NF_FF_ORIGINAL_CHECK_BIT)
#define NF_FF_REPLY_CHECK_BIT 13
#define NF_FF_REPLY_CHECK (1 << NF_FF_REPLY_CHECK_BIT)

#define NF_FF_FAIL_BIT 14
#define NF_FF_FAIL (1 << NF_FF_FAIL_BIT)

#define NF_FF_BRIDGE_BIT 15
#define NF_FF_BRIDGE (1 << NF_FF_BRIDGE_BIT)

#define NF_FF_ROUTE_BIT 16
#define NF_FF_ROUTE (1 << NF_FF_ROUTE_BIT)

#define NF_FF_RETRY_BIT 17
#define NF_FF_RETRY (1 << NF_FF_RETRY_BIT)

#define NF_FF_USER_USE_BIT 18
#define NF_FF_USER_USE (1 << NF_FF_USER_USE_BIT)

#define NF_FF_URLLOGGER_USE_BIT 19
#define NF_FF_URLLOGGER_USE (1 << NF_FF_URLLOGGER_USE_BIT)

/* XXX: ALL DONE */
#define NF_FF_BUSY_USE (NF_FF_USER_USE | NF_FF_URLLOGGER_USE)

typedef struct natflow_t {
	unsigned short magic;
	unsigned int status;
#define NF_FF_DIR_ORIGINAL 0
#define NF_FF_DIR_REPLY 1
#define NF_FF_DIR_MAX 2
	struct natflow_route_t rroute[NF_FF_DIR_MAX];
} natflow_t;

/*XXX don't change */
#define NATCAP_MAGIC 0x43415099
struct nat_key_t {
	unsigned int magic;
	unsigned int ext_magic;
	unsigned int len;
	unsigned short natcap_off;
	unsigned short natflow_off;
};
/*XXX refer to drivers/nos/src/nos.h */
#define IPS_NATFLOW_USER_BIT 16
#define IPS_NATFLOW_USER (1 << IPS_NATFLOW_USER_BIT)

#define IPS_NATFLOW_USER_BYPASS_BIT 15
#define IPS_NATFLOW_USER_BYPASS (1 << IPS_NATFLOW_USER_BYPASS_BIT)

#define IPS_NATFLOW_USER_DROP_BIT 17
#define IPS_NATFLOW_USER_DROP (1 << IPS_NATFLOW_USER_DROP_BIT)

#define IPS_NATFLOW_FF_STOP_BIT 18
#define IPS_NATFLOW_FF_STOP (1 << IPS_NATFLOW_FF_STOP_BIT)

#define IPS_NATFLOW_URLLOGGER_HANDLED_BIT 19
#define IPS_NATFLOW_URLLOGGER_HANDLED (1 << IPS_NATFLOW_URLLOGGER_HANDLED_BIT)

#define IPS_NATFLOW_SKIP_BRIDGE_BIT 20
#define IPS_NATFLOW_SKIP_BRIDGE (1 << IPS_NATFLOW_SKIP_BRIDGE_BIT)

/*XXX refer to natcap/natcap.h */
#define IPS_NATCAP_PEER_BIT 22
#define IPS_NATCAP_PEER (1 << IPS_NATCAP_PEER_BIT)

#define IPS_NATCAP_BIT 25
#define IPS_NATCAP (1 << IPS_NATCAP_BIT)

#define IPS_NATCAP_DUAL_BIT 29
#define IPS_NATCAP_DUAL (1 << IPS_NATCAP_DUAL_BIT)

static inline int simple_test_bit(int nr, const unsigned int *addr)
{
	return 1U & (addr[nr/32] >> (nr & (32-1)));
}

static inline void simple_clear_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	*p &= ~mask;
}

static inline void simple_set_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	*p |= mask;
}

static inline int simple_test_and_set_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	unsigned int old;
	old = *p;
	*p |= mask;
	return (old & mask) != 0;
}

static inline unsigned long ulongmindiff(unsigned long a, unsigned long b)
{
	return ((long)((b) - (a)) < 0) ? (a - b) : (b - a);
}

static inline unsigned int uintmindiff(unsigned int a, unsigned int b)
{
	return ((int)((b) - (a)) < 0) ? (a - b) : (b - a);
}

static inline unsigned short ushortmindiff(unsigned short a, unsigned short b)
{
	return ((short)((b) - (a)) < 0) ? (a - b) : (b - a);
}

static inline unsigned char ucharmindiff(unsigned char a, unsigned char b)
{
	return ((char)((b) - (a)) < 0) ? (a - b) : (b - a);
}

typedef struct natflow_fastnat_node_t natflow_fastnat_node_t;

struct natflow_fastnat_node_t {
	union {
		struct net_device *outdev;
		unsigned int _pad0[2];
	};
	union {
		unsigned long jiffies;
		unsigned int _pad1[2];
	};
	unsigned short magic;
	unsigned short vlan_present:1;
	unsigned short vlan_proto:3;
	unsigned short vlan_tci:12;
#define FASTNAT_EXT_HWNAT_FLAG 0x01
#define FASTNAT_PPPOE_FLAG 0x02
#define FASTNAT_NO_ARP     0x04
#define FASTNAT_BRIDGE_FWD 0x08
#define FASTNAT_PROTO_TCP  0x10
#define FASTNAT_PROTO_UDP  0x20
#define NFN_PROTO_DEC(flags)    (((flags) & FASTNAT_PROTO_TCP) ? IPPROTO_TCP : IPPROTO_UDP)
#define NFN_PROTO_ENC(protonum) ((protonum) == IPPROTO_TCP ? FASTNAT_PROTO_TCP : FASTNAT_PROTO_UDP)
	unsigned char flags;
	unsigned char count;
	unsigned short ifindex;
	__be32 saddr,
	       daddr;
	__be16 source,
	       dest;
	__be16 nat_source,
	       nat_dest;
	__be32 nat_saddr,
	       nat_daddr;
	unsigned char h_source[ETH_ALEN];
	u16 mss;
	unsigned char h_dest[ETH_ALEN];
	__be16 pppoe_sid;
	/* XXX: -- 64 bytes above -- */
	unsigned long keepalive_jiffies;
	unsigned long status;
	unsigned int flow_bytes;
	unsigned int flow_packets;
	unsigned int speed_bytes[4];
	unsigned int speed_packets[4];
	void *ptr; /* user ptr */
} __attribute__((__aligned__(SMP_CACHE_BYTES)));

#define NATFLOW_FF_TIMEOUT_HIGH (30 * HZ)
#define NATFLOW_FF_TIMEOUT_LOW (25 * HZ)
#define NATFLOW_FF_SAMPLE_TIME 2

/* MAX 65536 for now we use 4096 */
#if defined(CONFIG_64BIT) || defined(CONFIG_X86) || defined(CONFIG_X86_64) || defined(CONFIG_ARM) || defined(CONFIG_ARM64)
#define NATFLOW_FASTNAT_TABLE_SIZE 4096
#else
#define NATFLOW_FASTNAT_TABLE_SIZE 4096
#endif

static inline u32 natflow_hash_v4(__be32 saddr, __be32 daddr, __be16 source, __be16 dest, __be16 proto)
{
	u32 hv1, hv2, hv3;
	u32 hash;

	hv1 = ntohs(source) << 16 | ntohs(dest);
	hv2 = ntohl(daddr);
	hv3 = ntohl(saddr);

	hash = (hv1 & hv2) | ((~hv1) & hv3);
	hash = (hash >> 24) | ((hash & 0xffffff) << 8);
	hash ^= hv1 ^ hv2 ^ hv3;
	hash ^= hash >> 16;
	hash &= NATFLOW_FASTNAT_TABLE_SIZE - 1;
	hash <<= 1;

	return hash;
}

static inline int natflow_hash_skip(u32 hash)
{
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	static const u8 skip[] = { 12, 25, 38, 51, 76, 89, 102 };
	u32 i = hash % 128;
	int k;

	if (!IS_ENABLED(CONFIG_SOC_MT7621))
		return 0;

	for (k = 0; k < ARRAY_SIZE(skip); k++) {
		if (i == skip[k]) {
			return 1;
		}
	}
#endif

	return 0;
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
#define HWNAT_QUEUE_MAPPING_MAGIC      0x8000
#define HWNAT_QUEUE_MAPPING_MAGIC_MASK 0xe000
#define HWNAT_QUEUE_MAPPING_HASH_MASK  0x1fff
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
static inline void __vlan_hwaccel_clear_tag(struct sk_buff *skb)
{
	skb->vlan_tci &= ~VLAN_TAG_PRESENT;
}
#endif

#endif /* _NATFLOW_H_ */
