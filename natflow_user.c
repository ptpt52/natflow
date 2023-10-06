/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/netdevice.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include "natflow.h"
#include "natflow_common.h"
#include "natflow_user.h"
#include "natflow_zone.h"

struct userinfo {
	struct list_head list;
	unsigned int timeout;
	__be32 ip;
	uint8_t macaddr[ETH_ALEN];
	uint8_t auth_type;
	uint8_t auth_status;
	uint16_t auth_rule_id;
	unsigned long long rx_packets;
	unsigned long long rx_bytes;
	unsigned long long tx_packets;
	unsigned long long tx_bytes;
	unsigned int rx_speed_packets;
	unsigned int rx_speed_bytes;
	unsigned int tx_speed_packets;
	unsigned int tx_speed_bytes;
};

struct userinfo_event {
	spinlock_t lock;
	struct list_head head;
	wait_queue_head_t wait;
#define USERINFO_EVENT_STOPPED 0
#define USERINFO_EVENT_RUNNING 1
	unsigned int stage;
};

static struct userinfo_event userinfo_event_store;

static inline void userinfo_event_store_init(void)
{
	spin_lock_init(&userinfo_event_store.lock);
	INIT_LIST_HEAD(&userinfo_event_store.head);
	init_waitqueue_head(&userinfo_event_store.wait);
	userinfo_event_store.stage = USERINFO_EVENT_STOPPED;
}

static inline void userinfo_event_store_exit(void)
{
	struct userinfo *user_i, *n;
	list_for_each_entry_safe(user_i, n, &userinfo_event_store.head, list) {
		list_del(&user_i->list);
		kfree(user_i);
	}
}

static int natflow_user_major = 0;
static int natflow_user_minor = 0;
static struct cdev natflow_user_cdev;
const char *natflow_user_dev_name = "natflow_user_ctl";
static struct class *natflow_user_class;
static struct device *natflow_user_dev;

static uint16_t auth_conf_magic = 0;

static inline void auth_conf_update_magic(int init)
{
	if (init) {
		auth_conf_magic = jiffies;
	} else {
		auth_conf_magic++;
	}
}

static struct auth_conf *auth_conf = NULL;

static inline int auth_rule_add_one(struct auth_rule_t *rule)
{
	if (auth_conf->num < MAX_AUTH) {
		memcpy(&auth_conf->auth[auth_conf->num], rule, sizeof(struct auth_rule_t));
		auth_conf->num++;
		return 0;
	}

	return -ENOMEM;
}

static int disabled = 1;
void natflow_user_disabled_set(int v)
{
	disabled = v;
}
int natflow_user_disabled_get(void)
{
	return disabled;
}

static int qos_major = 0;
static int qos_minor = 0;
static struct cdev qos_cdev;
const char *qos_dev_name = "qos_ctl";
static struct class *qos_class;
static struct device *qos_dev;

#define QOS_TOKEN_CTRL_GROUP_MAX 64
static struct {
	struct token_ctrl rx;
	struct token_ctrl tx;
} qos_token_ctrl[QOS_TOKEN_CTRL_GROUP_MAX];

static struct qos_rule {
	union {
		unsigned char name[16];
		__be32 ip;
		struct {
			__be32 ip;
			__be32 mask;
		} ipcidr;
	} user;

	union {
		unsigned char name[16];
		__be16 port;
	} user_port;

	union {
		unsigned char name[16];
		__be32 ip;
		struct {
			__be32 ip;
			__be32 mask;
		} ipcidr;
	} remote;

	union {
		unsigned char name[16];
		__be16 port;
	} remote_port;

	unsigned short proto;

#define USER_TYPE_IP     BIT(0)
#define USER_TYPE_IPCIDR BIT(1)
#define USER_TYPE_SET    BIT(2)
#define USER_TYPE_MASK   (USER_TYPE_IP|USER_TYPE_IPCIDR|USER_TYPE_SET)

#define USER_PORT_TYPE_PORT BIT(3)
#define USER_PORT_TYPE_SET  BIT(4)
#define USER_PORT_TYPE_MASK (USER_PORT_TYPE_PORT|USER_PORT_TYPE_SET)

#define REMOTE_TYPE_IP     BIT(5)
#define REMOTE_TYPE_IPCIDR BIT(6)
#define REMOTE_TYPE_SET    BIT(7)
#define REMOTE_TYPE_MASK   (REMOTE_TYPE_IP|REMOTE_TYPE_IPCIDR|REMOTE_TYPE_SET)

#define REMOTE_PORT_TYPE_PORT BIT(8)
#define REMOTE_PORT_TYPE_SET  BIT(9)
#define REMOTE_PORT_TYPE_MASK (REMOTE_PORT_TYPE_PORT|REMOTE_PORT_TYPE_SET)
	unsigned short flag;

	unsigned int rxbytes;
	unsigned int txbytes;
} qos_token_ctrl_rule[QOS_TOKEN_CTRL_GROUP_MAX];

unsigned int tc_classid_mode = 0;
static int qos_token_ctrl_num = 0;

static void qos_token_ctrl_init(void)
{
	int i;

	memset(&qos_token_ctrl, 0, sizeof(*qos_token_ctrl) * QOS_TOKEN_CTRL_GROUP_MAX);

	memset(&qos_token_ctrl_rule, 0, sizeof(*qos_token_ctrl_rule) * QOS_TOKEN_CTRL_GROUP_MAX);

	for (i = 0; i < QOS_TOKEN_CTRL_GROUP_MAX; i++) {
		spin_lock_init(&qos_token_ctrl[i].rx.lock);
		spin_lock_init(&qos_token_ctrl[i].tx.lock);
	}
}

static int natflow_token_ctrl(struct sk_buff *skb, struct token_ctrl *tc)
{
	int feed_jiffies = 0;
	unsigned int current_jiffies = (unsigned int)jiffies;
	int ret = 0;
	int len = skb->len;
	struct iphdr *iph = ip_hdr(skb);
	void *l4 = (void *)iph + iph->ihl * 4;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		len -= iph->ihl * 4 + TCPH(l4)->doff * 4;
		break;
	case IPPROTO_UDP:
		len -= iph->ihl * 4 + sizeof(struct udphdr);
		break;
	}

	if (len <= 0) return 0;

	if (tc->tokens_per_jiffy == 0) return 0;

	spin_lock_bh(&tc->lock);
	if (tc->tokens > 0) {
		tc->tokens -= len;
		ret = 0;
		goto out;
	}

	current_jiffies = jiffies;
	feed_jiffies = uintmindiff(current_jiffies, tc->jiffies);
	if (feed_jiffies > HZ) {
		feed_jiffies = HZ/8 + 1;
	}

	ret = tc->tokens + (int)(tc->tokens_per_jiffy * feed_jiffies);

	if (feed_jiffies <= HZ) {
		tc->tokens = ret;
	} else {
		if (ret <= 0) {
			tc->tokens = ret;
		} else {
			tc->tokens = 0;
		}
	}

	if (tc->tokens >= 0) {
		tc->tokens -= len;
		ret = 0;
	}
	tc->jiffies = current_jiffies;

out:
	spin_unlock_bh(&tc->lock);
	return ret;
}

int rx_token_ctrl(struct sk_buff *skb, struct fakeuser_data_t *fud, natflow_t *nf)
{
	int ret = 0;

	if (tc_classid_mode && nf && nf->qos_id) {
		skb->mark = nf->qos_id;
		return 0;
	}

	if (nf && nf->qos_id && nf->qos_id <= qos_token_ctrl_num) {
		ret = natflow_token_ctrl(skb, &qos_token_ctrl[nf->qos_id - 1].rx);
	}

	if (fud->tc.rx.tokens_per_jiffy == 0 || ret < 0) {
		return ret;
	}

	return natflow_token_ctrl(skb, &fud->tc.rx);
}

int tx_token_ctrl(struct sk_buff *skb, struct fakeuser_data_t *fud, natflow_t *nf)
{
	int ret = 0;

	if (tc_classid_mode && nf && nf->qos_id) {
		skb->mark = nf->qos_id;
		return 0;
	}

	if (nf && nf->qos_id && nf->qos_id <= qos_token_ctrl_num) {
		ret = natflow_token_ctrl(skb, &qos_token_ctrl[nf->qos_id - 1].tx);
	}

	if (fud->tc.tx.tokens_per_jiffy == 0 || ret < 0) {
		return ret;
	}

	return natflow_token_ctrl(skb, &fud->tc.tx);
}

static unsigned int auth_open_weixin_reply = 0;

static unsigned short https_redirect_port = __constant_htons(443);
static unsigned int https_redirect_en = 0;

/*XXX: default redirect_ip 10.10.10.10 */
unsigned int redirect_ip = __constant_htonl((10<<24)|(10<<16)|(10<<8)|(10<<0));

/* user timeout 1800s */
static unsigned int natflow_user_timeout = 1800;
#define NATFLOW_USER_TIMEOUT 300

static struct sk_buff *natflow_user_uskbs[NR_CPUS];
#define NATFLOW_USKB_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define NATFLOW_FAKEUSER_DADDR __constant_htonl(0x7fffffff)

static inline struct sk_buff *uskb_of_this_cpu(int id)
{
	BUG_ON(id >= NR_CPUS);
	if (!natflow_user_uskbs[id]) {
		natflow_user_uskbs[id] = __alloc_skb(NATFLOW_USKB_SIZE, GFP_ATOMIC, 0, numa_node_id());
	}
	return natflow_user_uskbs[id];
}

void natflow_user_timeout_touch(natflow_fakeuser_t *nfu)
{
	struct fakeuser_data_t *fud;

	fud = natflow_fakeuser_data(nfu);
	if (fud->auth_type != AUTH_TYPE_UNKNOWN) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		unsigned long newtimeout = jiffies + natflow_user_timeout * HZ;
		if (newtimeout - nfu->timeout.expires > HZ) {
			mod_timer_pending(&nfu->timeout, newtimeout);
		}
#else
		nfu->timeout = jiffies + natflow_user_timeout * HZ;
#endif
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		unsigned long newtimeout = jiffies + NATFLOW_USER_TIMEOUT * HZ;
		if (newtimeout - nfu->timeout.expires > HZ) {
			mod_timer_pending(&nfu->timeout, newtimeout);
		}
#else
		nfu->timeout = jiffies + NATFLOW_USER_TIMEOUT * HZ;
#endif
	}
}

natflow_fakeuser_t *natflow_user_get(struct nf_conn *ct)
{
	natflow_fakeuser_t *user = NULL;

	if (ct->master) {
		if ((IPS_NATFLOW_USER & ct->master->status)) {
			if (unlikely(nf_ct_is_dying(ct->master))) {
				return NULL;
			}
			user = ct->master;
		} else if (ct->master->master && (IPS_NATFLOW_USER & ct->master->master->status)) {
			if (unlikely(nf_ct_is_dying(ct->master->master))) {
				return NULL;
			}
			user = ct->master->master;
		}
	}

	return user;
}

natflow_fakeuser_t *natflow_user_find_get(__be32 ip)
{
	natflow_fakeuser_t *user = NULL;

	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.u3.ip = ip;
	tuple.src.u.udp.port = __constant_htons(0);
	tuple.dst.u3.ip = NATFLOW_FAKEUSER_DADDR;
	tuple.dst.u.udp.port = __constant_htons(65535);
	tuple.src.l3num = PF_INET;
	tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
	h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
	if (h) {
		struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
		if (!(IPS_NATFLOW_USER & ct->status) || NF_CT_DIRECTION(h) != IP_CT_DIR_ORIGINAL) {
			nf_ct_put(ct);
		} else {
			user = ct;
		}
	}

	return user;
}

void natflow_user_put(natflow_fakeuser_t *user)
{
	nf_ct_put(user);
}

natflow_fakeuser_t *natflow_user_in(struct nf_conn *ct, int dir)
{
	natflow_fakeuser_t *user = NULL;

	user = natflow_user_get(ct);
	if (user)
		return user;

	/* FIXME: cannot use ct->master for user since destroy_gre_conntrack() may double free gre helper in master */
	if (unlikely(nf_ct_protonum(ct) == IPPROTO_GRE)) {
		return NULL;
	}

	if (!nf_ct_is_confirmed(ct) && !user && (!ct->master || !ct->master->master)) {
		struct nf_ct_ext *new = NULL;
		unsigned int newoff = 0;
		int ret;
		struct sk_buff *uskb;
		struct iphdr *iph;
		struct udphdr *udph;
		enum ip_conntrack_info ctinfo;

		uskb = uskb_of_this_cpu(smp_processor_id());
		if (uskb == NULL) {
			return NULL;
		}
		skb_reset_transport_header(uskb);
		skb_reset_network_header(uskb);
		skb_reset_mac_len(uskb);

		uskb->protocol = __constant_htons(ETH_P_IP);
		skb_set_tail_pointer(uskb, NATFLOW_USKB_SIZE);
		uskb->len = NATFLOW_USKB_SIZE;
		uskb->pkt_type = PACKET_HOST;
		uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

		iph = ip_hdr(uskb);
		iph->version = 4;
		iph->ihl = 5;
		iph->saddr = ct->tuplehash[dir].tuple.src.u3.ip;
		iph->daddr = NATFLOW_FAKEUSER_DADDR;
		iph->tos = 0;
		iph->tot_len = htons(NATFLOW_USKB_SIZE);
		iph->ttl=255;
		iph->protocol = IPPROTO_UDP;
		iph->id = __constant_htons(0xDEAD);
		iph->frag_off = 0;
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);

		udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
		udph->source = __constant_htons(0);
		udph->dest = __constant_htons(65535);
		udph->len = __constant_htons(sizeof(struct udphdr));
		udph->check = 0;

		ret = nf_conntrack_in_compat(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
		if (ret != NF_ACCEPT) {
			return NULL;
		}
		user = nf_ct_get(uskb, &ctinfo);

		if (!user) {
			NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, ctinfo=%x\n",
			              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all), (unsigned int)ctinfo);
			return NULL;
		}

		if (!user->ext) {
			NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, user->ext is NULL\n",
			              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
			              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
			              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
			              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all));
			skb_nfct_reset(uskb);
			return NULL;
		}
		if (!nf_ct_is_confirmed(user) && !(IPS_NATFLOW_USER & user->status) && !test_and_set_bit(IPS_NATFLOW_USER_BIT, &user->status)) {
			struct fakeuser_data_t *fud;
			newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
			new = __krealloc(user->ext, newoff + sizeof(struct fakeuser_data_t), GFP_ATOMIC);
#else
			new = krealloc(user->ext, newoff + sizeof(struct fakeuser_data_t), GFP_ATOMIC);
#endif
			if (!new) {
				NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, realloc user->ext failed\n",
				              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all));
				skb_nfct_reset(uskb);
				return NULL;
			}
			if (user->ext != new) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
				kfree_rcu(user->ext, rcu);
				user->ext = new;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
				kfree_rcu(user->ext, rcu);
				rcu_assign_pointer(user->ext, new);
#else
				user->ext = new;
#endif
			}
			new->len = newoff;
			memset((void *)new + newoff, 0, sizeof(struct fakeuser_data_t));
			fud = (struct fakeuser_data_t *)((void *)new + newoff);
			spin_lock_init(&fud->tc.rx.lock);
			spin_lock_init(&fud->tc.tx.lock);
		}
#ifdef CONFIG_NF_CONNTRACK_EVENTS
		do {
			struct nf_conntrack_ecache *e = nf_ct_ecache_find(user);
			if (e) {
				user->ext->offset[NF_CT_EXT_ECACHE] = 0;
			}
		} while (0);
#endif

		ret = nf_conntrack_confirm(uskb);
		if (ret != NF_ACCEPT) {
			skb_nfct_reset(uskb);
			return NULL;
		}
		/* XXX: in race loser_ct may be replaced in nf_conntrack_confirm,
		 * here reload ct(user) from uskb, and it can't be NULL
		 */
		user = nf_ct_get(uskb, &ctinfo);
		if (!user || nf_ct_is_dying(user)) {
			skb_nfct_reset(uskb);
			return NULL;
		}

		natflow_user_timeout_touch(user);

		if (ct->master && !(IPS_NATFLOW_USER & ct->master->status)) {
			if (!test_and_set_bit(IPS_NATFLOW_MASTER_BIT, &ct->master->status)) {
				nf_conntrack_get(&user->ct_general);
				ct->master->master = user;
			}
		} else {
			if (!test_and_set_bit(IPS_NATFLOW_MASTER_BIT, &ct->status)) {
				nf_conntrack_get(&user->ct_general);
				ct->master = user;
			}
		}

		skb_nfct_reset(uskb);

		NATFLOW_DEBUG("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] user[%pI4]\n",
		              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
		              &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
		              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
		              &ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
		              &user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip
		             );
	}

	return natflow_user_get(ct);
}

static inline void natflow_auth_reply_payload_fin(const char *payload, int payload_len, struct sk_buff *oskb, const struct net_device *dev, int pppoe_hdr)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum;
	int offset, header_len;
	char *data;
	int pppoe_len = 0;

	if (pppoe_hdr) {
		pppoe_len = PPPOE_SES_HLEN;
		skb_push(oskb, PPPOE_SES_HLEN);
		oskb->protocol = __constant_htons(ETH_P_PPP_SES);
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl*4);

	offset = pppoe_len + sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATFLOW_ERROR("alloc_skb fail\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	//setup mac header
	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}
	//setup ip header
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len - pppoe_len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;
	ip_send_check(niph);
	//setup payload
	data = (char *)ip_hdr(nskb) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	memcpy(data, payload, payload_len);
	//setup tcp header
	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->psh = 1;
	ntcph->fin = 1;
	ntcph->window = 65535;
	//sum check
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	//ready to send out
	skb_push(nskb, (char *)niph - (char *)neth - pppoe_len);
	if (pppoe_hdr) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(nskb) + ETH_HLEN);
		ph->length = htons(ntohs(ip_hdr(nskb)->tot_len) + 2);
	}
	nskb->dev = (struct net_device *)dev;
	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	dev_queue_xmit(nskb);
out:
	if (pppoe_hdr) {
		oskb->protocol = __constant_htons(ETH_P_IP);
		skb_pull(oskb, PPPOE_SES_HLEN);
	}
}

static void natflow_auth_http_302(const struct net_device *dev, struct sk_buff *skb, natflow_fakeuser_t *user, int pppoe_hdr)
{
	struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
	const char *http_header_fmt = ""
	                              "HTTP/1.1 302 Moved Temporarily\r\n"
	                              "Connection: close\r\n"
	                              "Cache-Control: no-cache\r\n"
	                              "Content-Type: text/html; charset=UTF-8\r\n"
	                              "Location: %s\r\n"
	                              "Content-Length: %u\r\n"
	                              "\r\n";
	const char *http_data_fmt = ""
	                            "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\r\n"
	                            "<TITLE>302 Moved</TITLE></HEAD><BODY>\r\n"
	                            "<H1>302 Moved</H1>\r\n"
	                            "The document has moved\r\n"
	                            "<A HREF=\"%s\">here</A>.\r\n"
	                            "</BODY></HTML>\r\n";
	int n = 0;
	struct {
		char location[128];
		char data[384];
		char header[384];
		char payload[0];
	} *http = kmalloc(2048, GFP_ATOMIC);
	if (!http)
		return;

	snprintf(http->location, sizeof(http->location), "http://%pI4/index.html?ip=%pI4&mac=%02X-%02X-%02X-%02X-%02X-%02X&rid=%u&_t=%lu",
	         &redirect_ip, &user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
	         fud->macaddr[0], fud->macaddr[1], fud->macaddr[2],
	         fud->macaddr[3], fud->macaddr[4], fud->macaddr[5],
	         fud->auth_rule_id, jiffies);
	http->location[sizeof(http->location) - 1] = 0;
	n = snprintf(http->data, sizeof(http->data), http_data_fmt, http->location);
	http->data[sizeof(http->data) - 1] = 0;
	snprintf(http->header, sizeof(http->header), http_header_fmt, http->location, n);
	http->header[sizeof(http->header) - 1] = 0;
	n = sprintf(http->payload, "%s%s", http->header, http->data);

	natflow_auth_reply_payload_fin(http->payload, n, skb, dev, pppoe_hdr);
	kfree(http);
}

static inline void natflow_auth_open_weixin_reply(const struct net_device *dev, struct sk_buff *skb, int pppoe_hdr)
{
	const char *http_header_fmt = ""
	                              "HTTP/1.1 200 OK\r\n"
	                              "Connection: close\r\n"
	                              "Cache-Control: no-cache\r\n"
	                              "Content-Type: text/html; charset=UTF-8\r\n"
	                              "Content-Length: %u\r\n"
	                              "\r\n";
	const char *http_data_fmt = ""
	                            "<!DOCTYPE html>\r\n"
	                            "<html class='no-js'>\r\n"
	                            "<head>\r\n"
	                            "<meta charset='utf-8'>\r\n"
	                            "<meta name='viewport' content='initial-scale=1.0, maximum-scale=1.0, user-scalable=no'>\r\n"
	                            "<script type='text/javascript' src='http://%pI4/admin/js/guanzhu.js?%u'></script>\r\n"
	                            "</head>\r\n"
	                            "<body>\r\n"
	                            "</body>\r\n"
	                            "</html>\r\n";
	int n = 0;
	struct {
		char data[384];
		char header[384];
		char payload[0];
	} *http = kmalloc(2048, GFP_ATOMIC);
	if (!http)
		return;

	n = snprintf(http->data, sizeof(http->data), http_data_fmt, &redirect_ip, jiffies);
	http->data[sizeof(http->data) - 1] = 0;
	snprintf(http->header, sizeof(http->header), http_header_fmt, n);
	http->header[sizeof(http->header) - 1] = 0;
	n = sprintf(http->payload, "%s%s", http->header, http->data);

	natflow_auth_reply_payload_fin(http->payload, n, skb, dev, pppoe_hdr);
	kfree(http);
}

static inline void natflow_auth_convert_tcprst(struct sk_buff *skb)
{
	int offset = 0;
	int len;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return;
	if (skb->len < ntohs(iph->tot_len))
		return;
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	offset = iph->ihl * 4 + sizeof(struct tcphdr) - skb->len;
	if (offset > 0)
		return;
	if (pskb_trim(skb, skb->len + offset))
		return;

	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->fin = 0;
	tcph->urg = 0;
	tcph->ece = 0;
	tcph->cwr = 0;
	tcph->window = __constant_htons(0);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	iph->tot_len = htons(skb->len);
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;

	len = ntohs(iph->tot_len);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		tcph->check = 0;
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		skb->csum = 0;
		tcph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
	}
}

static inline void natflow_auth_tcp_reply_finack(const struct net_device *dev, struct sk_buff *oskb, int pppoe_hdr)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum;
	int offset, header_len;
	int pppoe_len = 0;

	if (pppoe_hdr) {
		pppoe_len = PPPOE_SES_HLEN;
		skb_push(oskb, PPPOE_SES_HLEN);
		oskb->protocol = __constant_htons(ETH_P_PPP_SES);
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl*4);

	offset = pppoe_len + sizeof(struct iphdr) + sizeof(struct tcphdr) - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATFLOW_ERROR("alloc_skb fail\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("pskb_trim fail: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	//setup mac header
	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}
	//setup ip header
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = oiph->daddr;
	niph->daddr = oiph->saddr;
	niph->version = oiph->version;
	niph->ihl = 5;
	niph->tos = 0;
	niph->tot_len = htons(nskb->len - pppoe_len);
	niph->ttl = 0x80;
	niph->protocol = oiph->protocol;
	niph->id = __constant_htons(0xDEAD);
	niph->frag_off = 0x0;
	ip_send_check(niph);
	//setup tcp header
	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = otcph->dest;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2) + 1);
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->rst = 1;
	ntcph->psh = 0;
	ntcph->fin = 0;
	ntcph->window = 0;
	//sum check
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	//ready to send out
	skb_push(nskb, (char *)niph - (char *)neth - pppoe_len);
	if (pppoe_hdr) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(nskb) + ETH_HLEN);
		ph->length = htons(ntohs(ip_hdr(nskb)->tot_len) + 2);
	}
	nskb->dev = (struct net_device *)dev;
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	dev_queue_xmit(nskb);
out:
	if (pppoe_hdr) {
		oskb->protocol = __constant_htons(ETH_P_IP);
		skb_pull(oskb, PPPOE_SES_HLEN);
	}
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_user_pre_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_user_pre_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_user_pre_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natflow_user_pre_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *out = state->out;
#endif
#endif
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	const struct net_device *br_in = NULL;
#endif
	struct fakeuser_data_t *fud;
	natflow_fakeuser_t *user;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
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
	} else if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}

	if ((ct->status & IPS_NATFLOW_USER_BYPASS)) {
		goto out;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL ||
	        ipv4_is_zeronet(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) ||
	        ipv4_is_loopback(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) ||
	        ipv4_is_multicast(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) ||
	        ipv4_is_lbcast(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)) {
		goto out;
	}

	if (in == NULL)
		in = skb->dev;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	br_in = nf_bridge_get_physindev(skb);
#endif
	if (!natflow_is_lan_zone(in)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	        && (br_in == NULL || !natflow_is_lan_zone(br_in))
#endif
	   ) {
		goto out;
	}

	user = natflow_user_in(ct, IP_CT_DIR_ORIGINAL);
	if (NULL == user) {
		goto out;
	}
	fud = natflow_fakeuser_data(user);

	if ( fud->auth_status == AUTH_NONE ||
	        (fud->auth_rule_magic != auth_conf_magic && fud->auth_status != AUTH_OK && fud->auth_status != AUTH_VIP && fud->auth_status != AUTH_BLOCK) ) {
		int i;
		int zid = natflow_zone_id_get_safe(in);
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		int br_zid = natflow_zone_id_get_safe(br_in);
#endif

		fud->auth_rule_magic = auth_conf_magic;
		fud->auth_type = AUTH_TYPE_UNKNOWN;
		fud->auth_rule_id = INVALID_AUTH_RULE_ID;

		if (zid == INVALID_ZONE_ID
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		        && br_zid == INVALID_ZONE_ID
#endif
		   ) {
			goto out;
		}

		for (i = 0; i < auth_conf->num; i++) {
			if (zid == auth_conf->auth[i].src_zone_id
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
			        || br_zid == auth_conf->auth[i].src_zone_id
#endif
			   ) {
				//zone match ok
				if (IP_SET_test_src_ip(state, in, out, skb, auth_conf->auth[i].src_ipgrp_name) > 0) {
					//ipgrp match ok
					fud->auth_rule_id = auth_conf->auth[i].id;

					if (auth_conf->auth[i].auth_type == AUTH_TYPE_AUTO) {
						fud->auth_type = AUTH_TYPE_AUTO;
						fud->auth_status = AUTH_OK;
						//TODO notify user
					} else {
						fud->auth_type = AUTH_TYPE_WEB;
						fud->auth_status = AUTH_REQ;

						//check src_whitelist or mac_whitelist
						if (auth_conf->auth[i].src_whitelist_name[0] != 0 &&
						        IP_SET_test_src_ip(state, in, out, skb, auth_conf->auth[i].src_whitelist_name) > 0) {
							fud->auth_status = AUTH_VIP;
							//TODO notify user
						} else if (auth_conf->auth[i].mac_whitelist_name[0] != 0 &&
						           IP_SET_test_src_mac(state, in, out, skb, auth_conf->auth[i].mac_whitelist_name) > 0) {
							fud->auth_status = AUTH_VIP;
							//TODO notify user
						}
					}

#if defined(CONFIG_NF_CONNTRACK_MARK)
					user->mark = fud->auth_type;
#endif
					break;
				}
			}
		}
	}

	if (timestamp_offset(fud->timestamp, jiffies) >= 32 * HZ) {
		if (memcmp(eth_hdr(skb)->h_source, fud->macaddr, ETH_ALEN) != 0) {
			memcpy(fud->macaddr, eth_hdr(skb)->h_source, ETH_ALEN);
		}
		fud->timestamp = jiffies;
		natflow_user_timeout_touch(user);
		//TODO notify user update
		if (userinfo_event_store.stage == USERINFO_EVENT_RUNNING) {
			struct nf_conn_acct *acct = nf_conn_acct_find(user);
			if (acct) {
				struct userinfo *user_i = kmalloc(sizeof(struct userinfo), GFP_ATOMIC);
				if (user_i) {
					INIT_LIST_HEAD(&user_i->list);
					user_i->timeout = nf_ct_expires(user)  / HZ;
					user_i->ip = user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
					memcpy(user_i->macaddr, fud->macaddr, ETH_ALEN);
					user_i->auth_type = fud->auth_type;
					user_i->auth_status = fud->auth_status;
					user_i->auth_rule_id = fud->auth_rule_id;
					user_i->rx_packets = atomic64_read(&acct->counter[0].packets);
					user_i->rx_bytes = atomic64_read(&acct->counter[0].bytes);
					user_i->tx_packets = atomic64_read(&acct->counter[1].packets);
					user_i->tx_bytes = atomic64_read(&acct->counter[1].bytes);

					do {
						unsigned int rx_speed_jiffies = atomic_read(&fud->rx_speed_jiffies);
						unsigned int tx_speed_jiffies = atomic_read(&fud->tx_speed_jiffies);
						int x = (jiffies/HZ/2) % 4;
						unsigned int diff = uintmindiff(jiffies, rx_speed_jiffies);
						if (diff > HZ * 2 * 4) {
							user_i->rx_speed_packets = 0;
							user_i->rx_speed_bytes = 0;
						} else {
							int rx_p2;
							int rx_b2;
							x = (x + 2) % 4;
							rx_p2 = atomic_read(&fud->rx_speed_packets[x]) + 1;
							rx_b2 = atomic_read(&fud->rx_speed_bytes[x]) + 1;
							user_i->rx_speed_packets = rx_p2 / 2;
							user_i->rx_speed_bytes = rx_b2 / 2;
						}

						x = (jiffies/HZ/2) % 4;
						diff = uintmindiff(jiffies, tx_speed_jiffies);
						if (diff > HZ * 2 * 4) {
							user_i->tx_speed_packets = 0;
							user_i->tx_speed_bytes = 0;
						} else {
							int tx_p2;
							int tx_b2;
							x = (x + 2) % 4;
							tx_p2 = atomic_read(&fud->tx_speed_packets[x]) + 1;
							tx_b2 = atomic_read(&fud->tx_speed_bytes[x]) + 1;
							user_i->tx_speed_packets = tx_p2 / 2;
							user_i->tx_speed_bytes = tx_b2 / 2;
						}
					} while (0);
					spin_lock(&userinfo_event_store.lock);
					list_add_tail(&user_i->list, &userinfo_event_store.head);
					spin_unlock(&userinfo_event_store.lock);

					wake_up(&userinfo_event_store.wait);
				}
			}
		}
	}

	if (fud->auth_status == AUTH_REQ && fud->auth_type == AUTH_TYPE_WEB && https_redirect_en != 0) {
		struct iphdr *iph = ip_hdr(skb);
		void *l4 = (void *)iph + iph->ihl * 4;

		if (iph->protocol == IPPROTO_TCP) {
			if (TCPH(l4)->dest == __constant_htons(443)) {
				if (auth_conf->dst_bypasslist_name[0] != 0 &&
				        IP_SET_test_dst_ip(state, in, out, skb, auth_conf->dst_bypasslist_name) > 0) {
					set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					goto out;
				} else if (auth_conf->src_bypasslist_name[0] != 0 &&
				           IP_SET_test_src_ip(state, in, out, skb, auth_conf->src_bypasslist_name) > 0) {
					set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					goto out;
				}

				do {
					__be32 newdst = 0;
					struct in_device *indev;
					struct in_ifaddr *ifa;

					rcu_read_lock();
					indev = __in_dev_get_rcu(in);
					if (indev && indev->ifa_list) {
						ifa = indev->ifa_list;
						newdst = ifa->ifa_local;
					}
					rcu_read_unlock();

					if (newdst) {
						NATFLOW_DEBUG(DEBUG_TCP_FMT ": new connection https redirect to %pI4:%u\n", DEBUG_TCP_ARG(iph,l4), &newdst, ntohs(https_redirect_port));
						natflow_dnat_setup(ct, newdst, https_redirect_port);
						set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					}
				} while (0);
			}
		}
	}
out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	return NF_ACCEPT;
}


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_user_forward_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_user_forward_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_user_forward_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natflow_user_forward_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *out = state->out;
#endif
#endif
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	const struct net_device *br_in = NULL;
#endif
	natflow_t *nf = NULL;
	struct fakeuser_data_t *fud;
	natflow_fakeuser_t *user;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	unsigned int ret = NF_ACCEPT;
	int bridge = 0;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IP);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
	} else if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	if (in == NULL)
		in = skb->dev;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	br_in = nf_bridge_get_physindev(skb);
#endif

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}
	nf = natflow_session_get(ct);

	if ((ct->status & IPS_NATFLOW_USER_DROP)) {
		struct iphdr *iph = ip_hdr(skb);
		void *l4 = (void *)iph + iph->ihl * 4;

		if (iph->protocol == IPPROTO_TCP && TCPH(l4)->fin && TCPH(l4)->ack) {
			natflow_auth_tcp_reply_finack(in, skb, bridge);
		}
		ret = NF_DROP;
		goto out;
	}
	if ((ct->status & IPS_NATFLOW_USER_BYPASS)) {
		goto out;
	}

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		goto out;
	}

	user = natflow_user_get(ct);
	if (NULL == user) {
		if (!natflow_is_lan_zone(in)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		        && (br_in == NULL || !natflow_is_lan_zone(br_in))
#endif
		   ) {
			//TODO check flow from wan to user
			goto out;
		}
		goto out;
	}
	fud = natflow_fakeuser_data(user);
	if (nf && !(nf->status & NF_FF_TOKEN_CTRL) && (IPS_NATFLOW_USER_TOKEN_CTRL & user->status)) {
		/* tell FF this conn need token ctrl */
		simple_set_bit(NF_FF_TOKEN_CTRL_BIT, &nf->status);
	}
	if (nf && !(nf->status & NF_FF_QOS_TESTED)) {
		int i;
		struct iphdr *iph = ip_hdr(skb);
		void *l4 = (void *)iph + iph->ihl * 4;

		simple_set_bit(NF_FF_QOS_TESTED_BIT, &nf->status);

		for (i = 0; i < qos_token_ctrl_num; i++) {
			struct qos_rule *qr = &qos_token_ctrl_rule[i];
			if (qr->proto) {
				if (qr->proto != iph->protocol) {
					continue;
				}
			}

			if ((qr->flag & USER_TYPE_MASK)) {
				if ((qr->flag & USER_TYPE_IP)) {
					if (qr->user.ip != user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						continue;
					}
				} else if ((qr->flag & USER_TYPE_IPCIDR)) {
					if (qr->user.ipcidr.ip != (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip & qr->user.ipcidr.mask)) {
						continue;
					}
				} else {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (IP_SET_test_src_ip(state, in, out, skb, qr->user.name) <= 0) {
							continue;
						}
					} else {
						if (IP_SET_test_dst_ip(state, in, out, skb, qr->user.name) <= 0) {
							continue;
						}
					}
				}
			}

			if ((qr->flag & USER_PORT_TYPE_MASK)) {
				if ((qr->flag & USER_PORT_TYPE_PORT)) {
					if (iph->protocol == IPPROTO_TCP) {
						if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
							if (qr->user_port.port != TCPH(l4)->source) {
								continue;
							}
						} else {
							if (qr->user_port.port != TCPH(l4)->dest) {
								continue;
							}
						}
					} else if (iph->protocol == IPPROTO_UDP) {
						if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
							if (qr->user_port.port != UDPH(l4)->source) {
								continue;
							}
						} else {
							if (qr->user_port.port != UDPH(l4)->dest) {
								continue;
							}
						}
					}
				} else {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (IP_SET_test_src_port(state, in, out, skb, qr->user_port.name) <= 0) {
							continue;
						}
					} else {
						if (IP_SET_test_dst_port(state, in, out, skb, qr->user_port.name) <= 0) {
							continue;
						}
					}
				}
			}

			if ((qr->flag & REMOTE_TYPE_MASK)) {
				if ((qr->flag & REMOTE_TYPE_IP)) {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (qr->remote.ip != iph->daddr) {
							continue;
						}
					} else {
						if (qr->remote.ip != iph->saddr) {
							continue;
						}
					}
				} else if ((qr->flag & REMOTE_TYPE_IPCIDR)) {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (qr->remote.ipcidr.ip != (iph->daddr & qr->remote.ipcidr.mask)) {
							continue;
						}
					} else {
						if (qr->remote.ipcidr.ip != (iph->saddr & qr->remote.ipcidr.mask)) {
							continue;
						}
					}
				} else {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (IP_SET_test_dst_ip(state, in, out, skb, qr->remote.name) <= 0) {
							continue;
						}
					} else {
						if (IP_SET_test_src_ip(state, in, out, skb, qr->remote.name) <= 0) {
							continue;
						}
					}
				}
			}

			if ((qr->flag & REMOTE_PORT_TYPE_MASK)) {
				if ((qr->flag & REMOTE_PORT_TYPE_PORT)) {
					if (iph->protocol == IPPROTO_TCP) {
						if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
							if (qr->remote_port.port != TCPH(l4)->dest) {
								continue;
							}
						} else {
							if (qr->remote_port.port != TCPH(l4)->source) {
								continue;
							}
						}
					} else if (iph->protocol == IPPROTO_UDP) {
						if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
							if (qr->remote_port.port != UDPH(l4)->dest) {
								continue;
							}
						} else {
							if (qr->remote_port.port != UDPH(l4)->source) {
								continue;
							}
						}
					}
				} else {
					if (iph->saddr == user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
						if (IP_SET_test_dst_port(state, in, out, skb, qr->remote_port.name) <= 0) {
							continue;
						}
					} else {
						if (IP_SET_test_src_port(state, in, out, skb, qr->remote_port.name) <= 0) {
							continue;
						}
					}
				}
			}

			nf->qos_id = i + 1;

			if (nf->qos_id) {
				switch (iph->protocol) {
				case IPPROTO_TCP:
					NATFLOW_INFO("(NUF)" DEBUG_TCP_FMT ": matched qos id=%d\n",
					             DEBUG_TCP_ARG(iph,l4), nf->qos_id);
					break;
				case IPPROTO_UDP:
					NATFLOW_INFO("(NUF)" DEBUG_UDP_FMT ": matched qos id=%d\n",
					             DEBUG_UDP_ARG(iph,l4), nf->qos_id);
					break;
				}

				simple_set_bit(NF_FF_TOKEN_CTRL_BIT, &nf->status);
				break;
			}
		}
	}

	switch(fud->auth_status) {
	case AUTH_REQ:
		if (fud->auth_type == AUTH_TYPE_WEB) {
			int data_len;
			unsigned char *data;
			struct iphdr *iph = ip_hdr(skb);
			void *l4 = (void *)iph + iph->ihl * 4;

			/* tell FF do not emit pkts */
			if (nf && !(nf->status & NF_FF_USER_USE)) {
				/* tell FF -user- need to use this conn */
				simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
			}

			if (iph->daddr == redirect_ip) {
				set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
				goto out;
			}
			if (auth_conf->dst_bypasslist_name[0] != 0 &&
			        IP_SET_test_dst_ip(state, in, out, skb, auth_conf->dst_bypasslist_name) > 0) {
				set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
				goto out;
			} else if (auth_conf->src_bypasslist_name[0] != 0 &&
			           IP_SET_test_src_ip(state, in, out, skb, auth_conf->src_bypasslist_name) > 0) {
				set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
				goto out;
			}

			if (iph->protocol == IPPROTO_UDP) {
				if (UDPH(l4)->dest == __constant_htons(53) || UDPH(l4)->dest == __constant_htons(67)) {
					set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
					goto out;
				}
			}

			if (iph->protocol != IPPROTO_TCP) {
				set_bit(IPS_NATFLOW_USER_DROP_BIT, &ct->status);
				goto out;
			}

			data = skb->data + (iph->ihl << 2) + (TCPH(l4)->doff << 2);
			data_len = ntohs(iph->tot_len) - ((iph->ihl << 2) + (TCPH(l4)->doff << 2));
			if ((data_len > 4 && strncasecmp(data, "GET ", 4) == 0) || (data_len > 5 && strncasecmp(data, "POST ", 5) == 0)) {
				NATFLOW_INFO(DEBUG_TCP_FMT ": sending HTTP 302 redirect dev=%s\n", DEBUG_TCP_ARG(iph,l4), in->name);
				natflow_auth_http_302(in, skb, user, bridge);
				set_bit(IPS_NATFLOW_USER_DROP_BIT, &ct->status);
				ret = NF_DROP;
				goto out;
			} else if (data_len > 0) {
				set_bit(IPS_NATFLOW_USER_DROP_BIT, &ct->status);
				ret = NF_DROP;
				goto out;
			} else if (TCPH(l4)->ack && !TCPH(l4)->syn) {
				natflow_auth_convert_tcprst(skb);
				goto out;
			}
		} else if (fud->auth_type == AUTH_TYPE_AUTO) {
			fud->auth_status = AUTH_OK;
			//TODO notify user
		}
		break;
	case AUTH_OK:
		if (fud->auth_type == AUTH_TYPE_WEB) {
			int data_len;
			unsigned char *data;
			struct iphdr *iph = ip_hdr(skb);
			void *l4 = (void *)iph + iph->ihl * 4;

			if (iph->protocol == IPPROTO_TCP && auth_open_weixin_reply != 0) {
				data = skb->data + (iph->ihl << 2) + (TCPH(l4)->doff << 2);
				data_len = ntohs(iph->tot_len) - ((iph->ihl << 2) + (TCPH(l4)->doff << 2));
				if (data_len > 0) {
					if (TCPH(l4)->dest == __constant_htons(80)) {
						int i = 0;
						if (strncasecmp(data, "GET /auto-portal-subscribe.html", 31) == 0) {
							i += 31;
							while (i < data_len) {
								while (i < data_len && data[i] != '\n') i++;
								i++;
								if (i + 24 < data_len && strncasecmp(data + i, "Host: open.weixin.qq.com", 24) == 0) {
									natflow_auth_open_weixin_reply(in, skb, bridge);
									natflow_auth_convert_tcprst(skb);
									set_bit(IPS_NATFLOW_USER_DROP_BIT, &ct->status);
									goto out;
								}
							}
						}
					}
				}
			}
		}
		set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
		break;
	case AUTH_VIP:
	case AUTH_BYPASS:
		set_bit(IPS_NATFLOW_USER_BYPASS_BIT, &ct->status);
		break;
	case AUTH_BLOCK:
		/* temporary block user */
		set_bit(IPS_NATFLOW_USER_DROP_BIT, &ct->status);
		ret = NF_DROP;
		goto out;
	}

out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	if (ct && (ct->status & IPS_NATFLOW_USER_BYPASS)) {
		if (nf && (nf->status & NF_FF_USER_USE)) {
			/* tell FF -user- has finished it's job */
			simple_clear_bit(NF_FF_USER_USE_BIT, &nf->status);
		}
	}

	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_user_post_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_user_post_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_user_post_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natflow_user_post_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	const struct net_device *br_out = NULL;
#endif
	struct nf_conn_acct *acct;
	natflow_fakeuser_t *user;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	int bridge = 0;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
	        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
		skb_pull(skb, PPPOE_SES_HLEN);
		skb->protocol = __constant_htons(ETH_P_IP);
		skb->network_header += PPPOE_SES_HLEN;
		bridge = 1;
	} else if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	if (out == NULL)
		out = skb->dev;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	br_out = nf_bridge_get_physoutdev(skb);
#endif

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}

	user = natflow_user_get(ct);
	if (NULL == user) {
		/* XXX: no user found, maybe connection from wan to lan */
		if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL ||
		        ipv4_is_zeronet(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip) ||
		        ipv4_is_loopback(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip) ||
		        ipv4_is_multicast(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip) ||
		        ipv4_is_lbcast(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip)) {
			goto out;
		}
		if (!natflow_is_lan_zone(out)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		        && (br_out == NULL || !natflow_is_lan_zone(br_out))
#endif
		   ) {
			goto out;
		}

		user = natflow_user_in(ct, IP_CT_DIR_REPLY);
		if (NULL == user) {
			goto out;
		}
	}

	if (pf != NFPROTO_BRIDGE && !(ct->status & IPS_NATFLOW_SKIP_BRIDGE)) {
		set_bit(IPS_NATFLOW_SKIP_BRIDGE_BIT, &ct->status);
	} else if (pf == NFPROTO_BRIDGE && (ct->status & IPS_NATFLOW_SKIP_BRIDGE)) {
		goto out;
	}

	acct = nf_conn_acct_find(user);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		struct fakeuser_data_t *fud = natflow_fakeuser_data(user);
		natflow_t *nf = natflow_session_get(ct);
		if (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[CTINFO2DIR(ctinfo)].tuple.src.u3.ip) {
			if (nf && (nf->status & NF_FF_TOKEN_CTRL) && rx_token_ctrl(skb, fud, nf) < 0) {
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
				atomic64_inc(&counter[0].packets);
				atomic64_add(skb->len, &counter[0].bytes);
			}
		} else {
			if (nf && (nf->status & NF_FF_TOKEN_CTRL) && tx_token_ctrl(skb, fud, nf) < 0) {
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
				atomic64_inc(&counter[1].packets);
				atomic64_add(skb->len, &counter[1].bytes);
			}
		}
	}
out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	return NF_ACCEPT;
};


static struct nf_hook_ops user_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_pre_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 10 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_forward_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_post_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_pre_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 10 + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_forward_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_post_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC + 10,
	},
};

static inline void auth_conf_cleanup(void)
{
	int i;

	//auth_conf cannot be NULL, otherwise kmod not load.
	auth_conf->dst_bypasslist_name[0] = 0;
	auth_conf->src_bypasslist_name[0] = 0;

	while (auth_conf->num != 0) {
		i = --auth_conf->num;
		auth_conf->auth[i].src_ipgrp_name[0] = 0;
		auth_conf->auth[i].src_whitelist_name[0] = 0;
		auth_conf->auth[i].mac_whitelist_name[0] = 0;
	}
}

static inline void auth_conf_exit(void)
{
	if (auth_conf != NULL) {
		auth_conf_cleanup();
		kfree(auth_conf);
		auth_conf = NULL;
	}
}

static inline int auth_conf_init(void)
{
	auth_conf_update_magic(1);

	auth_conf = kzalloc(sizeof(struct auth_conf), GFP_KERNEL);
	if (auth_conf == NULL) {
		return -ENOMEM;
	}

	return 0;
}

//must lock by caller
static inline struct auth_rule_t *natflow_auth_rule_get(int idx)
{
	if (idx < auth_conf->num) {
		return &(auth_conf->auth[idx]);
	}

	return NULL;
}

static int natflow_user_ctl_buffer_use = 0;
static char *natflow_user_ctl_buffer = NULL;
static void *natflow_user_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(natflow_user_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Usage:\n"
		             "#    clean -- clear all existing auth rule(s)\n"
		             "#    update_magic -- update auth rule magic\n"
		             "#    auth id=<id>,szone=<idx>,type=web/auto,sipgrp=<name>[,ipwhite=<name>][,macwhite=<name>] -- set one auth\n"
		             "#\n"
		             "# Info:\n"
		             "#    disabled=%u\n"
		             "#    auth_conf_magic=%u\n"
		             "#    redirect_ip=%pI4\n"
		             "#    no_flow_timeout=%u\n"
		             "#    auth_open_weixin_reply=%u\n"
		             "#    https_redirect_en=%u\n"
		             "#    https_redirect_port=%u\n"
		             "#    rule(s) num=%u\n"
		             "#    dst_bypasslist_name=%s\n"
		             "#    src_bypasslist_name=%s\n"
		             "#\n"
		             "# Reload cmd:\n"
		             "\n"
		             "clean\n"
		             "\n",
		             disabled,
		             auth_conf_magic,
		             &redirect_ip,
		             natflow_user_timeout,
		             auth_open_weixin_reply,
		             https_redirect_en,
		             ntohs(https_redirect_port),
		             auth_conf->num, auth_conf->dst_bypasslist_name, auth_conf->src_bypasslist_name
		            );
		natflow_user_ctl_buffer[n] = 0;
		return natflow_user_ctl_buffer;
	} else if ((*pos) > 0) {
		struct auth_rule_t *rule = natflow_auth_rule_get((*pos) - 1);

		if (rule) {
			natflow_user_ctl_buffer[0] = 0;
			n = snprintf(natflow_user_ctl_buffer,
			             PAGE_SIZE - 1,
			             "auth id=%u,szone=%u,type=%s,sipgrp=%s,ipwhite=%s,macwhite=%s\n",
			             rule->id, rule->src_zone_id, rule->auth_type == AUTH_TYPE_AUTO ? "auto" : "web",
			             rule->src_ipgrp_name, rule->src_whitelist_name, rule->mac_whitelist_name
			            );
			natflow_user_ctl_buffer[n] = 0;
			return natflow_user_ctl_buffer;
		}
	}

	return NULL;
}

static void *natflow_user_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return natflow_user_start(m, pos);
	}
	return NULL;
}

static void natflow_user_stop(struct seq_file *m, void *v)
{
}

static int natflow_user_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations natflow_user_seq_ops = {
	.start = natflow_user_start,
	.next = natflow_user_next,
	.stop = natflow_user_stop,
	.show = natflow_user_show,
};

static ssize_t natflow_user_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t natflow_user_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
	struct auth_rule_t *rule;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <= MAX_IOCTL_LEN
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "clean", 10) == 0) {
		auth_conf_cleanup();
		goto done;
	} else if (strncmp(data, "disabled=", 9) == 0) {
		unsigned int a;
		n = sscanf(data, "disabled=%u", &a);
		if (n == 1) {
			natflow_user_disabled_set(!!(a));
			goto done;
		}
	} else if (strncmp(data, "update_magic", 10) == 0) {
		auth_conf_update_magic(0);
		goto done;
	} else if (strncmp(data, "dst_bypasslist_name=", 20) == 0) {
		char buf[IPSET_MAXNAMELEN];
		buf[0] = 0;
		n = sscanf(data, "dst_bypasslist_name=%s\n", buf);
		if (n == 1) {
			memcpy(auth_conf->dst_bypasslist_name, buf, sizeof(auth_conf->dst_bypasslist_name));
		} else {
			auth_conf->dst_bypasslist_name[0] = 0;
		}
		goto done;
	} else if (strncmp(data, "src_bypasslist_name=", 20) == 0) {
		char buf[IPSET_MAXNAMELEN];
		buf[0] = 0;
		n = sscanf(data, "src_bypasslist_name=%s\n", buf);
		buf[IPSET_MAXNAMELEN - 1] = 0;
		if (n == 1) {
			memcpy(auth_conf->src_bypasslist_name, buf, sizeof(auth_conf->src_bypasslist_name));
		} else {
			auth_conf->src_bypasslist_name[0] = 0;
		}
		goto done;
	} else if (strncmp(data, "auth id=", 8) == 0) {
		rule = kzalloc(sizeof(struct auth_rule_t), GFP_KERNEL);
		if (rule) {
			n = sscanf(data, "auth id=%u,szone=%u", &rule->id, &rule->src_zone_id);
			if (n == 2) {
				do {
					char *p;
					p = strstr(data, ",type=");
					if (p) {
						p = p + 6;
						if (strncmp(p, "web", 3) == 0) {
							rule->auth_type = AUTH_TYPE_WEB;
						} else if (strncmp(p, "auto", 4) == 0) {
							rule->auth_type = AUTH_TYPE_AUTO;
						} else {
							err = -EINVAL;
							break;
						}
					}

					p = strstr(data, ",sipgrp=");
					if (p) {
						int k = 0;
						p = p + 8;
						while (p[k] && p[k] != ',') {
							rule->src_ipgrp_name[k] = p[k];
							k++;
						}
						rule->src_ipgrp_name[k] = 0;
					} else {
						err = -EINVAL;
						break;
					}

					p = strstr(data, ",ipwhite=");
					if (p) {
						int k = 0;
						p = p + 9;
						while (p[k] && p[k] != ',') {
							rule->src_whitelist_name[k] = p[k];
							k++;
						}
						rule->src_whitelist_name[k] = 0;
					}

					p = strstr(data, ",macwhite=");
					if (p) {
						int k = 0;
						p = p + 10;
						while (p[k] && p[k] != ',') {
							rule->mac_whitelist_name[k] = p[k];
							k++;
						}
						rule->mac_whitelist_name[k] = 0;
					}
				} while (0);
				if (err == 0) {
					if ((err = auth_rule_add_one(rule)) == 0) {
						kfree(rule);
						goto done;
					}
				}
				NATFLOW_println("auth rule set fail err=%d", err);
			}
			kfree(rule);
		}
	} else if (strncmp(data, "redirect_ip=", 12) == 0) {
		unsigned int a, b, c,d;
		n = sscanf(data, "redirect_ip=%u.%u.%u.%u", &a, &b, &c, &d);
		if ( n == 4 &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) ) {
			redirect_ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));
			goto done;
		}
	} else if (strncmp(data, "no_flow_timeout=", 16) == 0) {
		unsigned int a;
		n = sscanf(data, "no_flow_timeout=%u", &a);
		if (n == 1) {
			natflow_user_timeout = a;
			goto done;
		}
	} else if (strncmp(data, "https_redirect_en=", 16) == 0) {
		unsigned int a;
		n = sscanf(data, "https_redirect_en=%u", &a);
		if (n == 1) {
			https_redirect_en = !!a;
			goto done;
		}
	} else if (strncmp(data, "auth_open_weixin_reply=", 23) == 0) {
		unsigned int a;
		n = sscanf(data, "auth_open_weixin_reply=%u", &a);
		if (n == 1) {
			auth_open_weixin_reply = !!a;
			goto done;
		}
	} else if (strncmp(data, "https_redirect_port=", 18) == 0) {
		unsigned int a;
		n = sscanf(data, "https_redirect_port=%u", &a);
		if (n == 1) {
			https_redirect_port = htons(a);
			goto done;
		}
	}

	NATFLOW_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int natflow_user_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	if (natflow_user_ctl_buffer_use++ == 0) {
		natflow_user_ctl_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (natflow_user_ctl_buffer == NULL) {
			natflow_user_ctl_buffer_use--;
			return -ENOMEM;
		}
	}

	ret = seq_open(file, &natflow_user_seq_ops);
	if (ret)
		return ret;
	return 0;
}

static int natflow_user_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);

	if (--natflow_user_ctl_buffer_use == 0) {
		kfree(natflow_user_ctl_buffer);
		natflow_user_ctl_buffer = NULL;
	}

	return ret;
}

static struct file_operations natflow_user_fops = {
	.owner = THIS_MODULE,
	.open = natflow_user_open,
	.release = natflow_user_release,
	.read = natflow_user_read,
	.write = natflow_user_write,
	.llseek  = seq_lseek,
};

struct userinfo_user {
	struct mutex lock;
	struct list_head head;
	unsigned int next_bucket;
	unsigned int count;
	unsigned int status;
	unsigned char data[0];
};
#define USERINFO_MEMSIZE ALIGN(sizeof(struct userinfo_user), 2048)
#define USERINFO_DATALEN (USERINFO_MEMSIZE - sizeof(struct userinfo_user))

static ssize_t userinfo_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	unsigned long end_time = jiffies + msecs_to_jiffies(100);
	struct userinfo_user *user = file->private_data;
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <= MAX_IOCTL_LEN
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "kickall", 7) == 0) {
		err = mutex_lock_interruptible(&user->lock);
		if (err != 0)
			return -EAGAIN;
		if (user->status == 0) {
			unsigned int i, hashsz;
			struct nf_conntrack_tuple_hash *h;
			struct hlist_nulls_head *ct_hash;
			struct hlist_nulls_node *n;
			struct nf_conn *ct;
			struct nf_conn_acct *acct;
			struct fakeuser_data_t *fud;

			user->status = 1;
			rcu_read_lock();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
			ct_hash = init_net.ct.hash;
			hashsz = init_net.ct.htable_size;
#else
			ct_hash = nf_conntrack_hash;
			hashsz = nf_conntrack_htable_size;
#endif
			for (i = user->next_bucket; i < hashsz; i++) {
				hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[i], hnnode) {
					ct = nf_ct_tuplehash_to_ctrack(h);
					if (unlikely(!REFCOUNT_inc_not_zero(&ct->ct_general.use)))
						continue;

					/* we only want to print DIR_ORIGINAL */
					if (NF_CT_DIRECTION(h)) {
						nf_ct_put(ct);
						continue;
					}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
					if (nf_ct_is_expired(ct)) {
						nf_ct_put(ct);
						continue;
					}
#endif
					if (!(IPS_NATFLOW_USER & ct->status)) {
						nf_ct_put(ct);
						continue;
					}
					fud = natflow_fakeuser_data(ct);
					fud->timestamp = 0;
					fud->auth_type = AUTH_TYPE_UNKNOWN;
					fud->auth_status = AUTH_NONE;
					fud->auth_rule_id = INVALID_AUTH_RULE_ID;
					acct = nf_conn_acct_find(ct);
					if (acct) {
						atomic64_set(&acct->counter[0].packets, 0);
						atomic64_set(&acct->counter[0].bytes, 0);
						atomic64_set(&acct->counter[1].packets, 0);
						atomic64_set(&acct->counter[1].bytes, 0);
					}

					nf_ct_put(ct);
				}

				if (time_after(jiffies, end_time) && i < hashsz) {
					user->next_bucket = i + 1;
					user->status = 0;
					rcu_read_unlock();
					mutex_unlock(&user->lock);
					goto again;
				}
			}
			rcu_read_unlock();
		}
		mutex_unlock(&user->lock);
		goto done;
	} else if (strncmp(data, "kick ", 5) == 0) {
		struct nf_conn_acct *acct;
		struct fakeuser_data_t *fud;
		natflow_fakeuser_t *user = NULL;
		__be32 ip;
		unsigned int a, b, c, d;
		n = sscanf(data, "kick %u.%u.%u.%u", &a, &b, &c, &d);
		if ( !(n == 4 &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) )) {
			return -EINVAL;
		}
		ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));

		user = natflow_user_find_get(ip);
		if (!user)
			return -EINVAL;

		fud = natflow_fakeuser_data(user);
		fud->timestamp = 0;
		fud->auth_type = AUTH_TYPE_UNKNOWN;
		fud->auth_status = AUTH_NONE;
		fud->auth_rule_id = INVALID_AUTH_RULE_ID;
		acct = nf_conn_acct_find(user);
		if (acct) {
			atomic64_set(&acct->counter[0].packets, 0);
			atomic64_set(&acct->counter[0].bytes, 0);
			atomic64_set(&acct->counter[1].packets, 0);
			atomic64_set(&acct->counter[1].bytes, 0);
		}

		natflow_user_put(user);
		goto done;
	} else if (strncmp(data, "set-status ", 11) == 0) {
		struct fakeuser_data_t *fud;
		natflow_fakeuser_t *user = NULL;
		__be32 ip;
		unsigned int a, b, c, d, e;
		n = sscanf(data, "set-status %u.%u.%u.%u %u", &a, &b, &c, &d, &e);
		if ( !(n == 5 &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) )) {
			return -EINVAL;
		}
		ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));

		user = natflow_user_find_get(ip);
		if (!user)
			return -EINVAL;

		fud = natflow_fakeuser_data(user);
		fud->auth_status = e;

		natflow_user_put(user);
		goto done;
	} else if (strncmp(data, "set-token-ctrl ", 15) == 0) {
		struct fakeuser_data_t *fud;
		natflow_fakeuser_t *user = NULL;
		__be32 ip;
		unsigned int a, b, c, d, rx, tx;
		n = sscanf(data, "set-token-ctrl %u.%u.%u.%u %u %u", &a, &b, &c, &d, &rx, &tx);
		if ( !(n == 6 &&
		        (((a & 0xff) == a) &&
		         ((b & 0xff) == b) &&
		         ((c & 0xff) == c) &&
		         ((d & 0xff) == d)) )) {
			return -EINVAL;
		}
		ip = htonl((a<<24)|(b<<16)|(c<<8)|(d<<0));

		user = natflow_user_find_get(ip);
		if (!user)
			return -EINVAL;

		fud = natflow_fakeuser_data(user);
		fud->tc.rx.tokens_per_jiffy = rx / HZ;
		fud->tc.tx.tokens_per_jiffy = tx / HZ;
		if (tx || rx) {
			set_bit(IPS_NATFLOW_USER_TOKEN_CTRL_BIT, &user->status);
		} else {
			clear_bit(IPS_NATFLOW_USER_TOKEN_CTRL_BIT, &user->status);
		}

		natflow_user_put(user);
		goto done;
	}

	NATFLOW_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
again:
	return -EAGAIN;
}

/* read one and clear one */
static ssize_t userinfo_read(struct file *file, char __user *buf,
                             size_t count, loff_t *ppos)
{
	unsigned long end_time = jiffies + msecs_to_jiffies(100);
	size_t len;
	ssize_t ret;
	struct userinfo *user_i;
	struct userinfo_user *user = file->private_data;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret != 0)
		return -EAGAIN;
	if (user->status == 0 && list_empty(&user->head)) {
		unsigned int i, hashsz;
		struct nf_conntrack_tuple_hash *h;
		struct hlist_nulls_head *ct_hash;
		struct hlist_nulls_node *n;
		struct nf_conn *ct;
		struct nf_conn_acct *acct;
		struct fakeuser_data_t *fud;

		user->status = 1;
		rcu_read_lock();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		ct_hash = init_net.ct.hash;
		hashsz = init_net.ct.htable_size;
#else
		ct_hash = nf_conntrack_hash;
		hashsz = nf_conntrack_htable_size;
#endif
		for (i = user->next_bucket; i < hashsz; i++) {
			hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[i], hnnode) {
				ct = nf_ct_tuplehash_to_ctrack(h);
				if (unlikely(!REFCOUNT_inc_not_zero(&ct->ct_general.use)))
					continue;

				/* we only want to print DIR_ORIGINAL */
				if (NF_CT_DIRECTION(h)) {
					nf_ct_put(ct);
					continue;
				}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
				if (nf_ct_is_expired(ct)) {
					nf_ct_put(ct);
					continue;
				}
#endif
				if (!(IPS_NATFLOW_USER & ct->status)) {
					nf_ct_put(ct);
					continue;
				}
				fud = natflow_fakeuser_data(ct);
				acct = nf_conn_acct_find(ct);
				if (acct) {
					user_i = kmalloc(sizeof(struct userinfo), GFP_ATOMIC);
					if (!user_i) {
						nf_ct_put(ct);
						ret = -ENOMEM;
						goto out;
					}
					INIT_LIST_HEAD(&user_i->list);
					user_i->timeout = nf_ct_expires(ct)  / HZ;
					user_i->ip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
					memcpy(user_i->macaddr, fud->macaddr, ETH_ALEN);
					user_i->auth_type = fud->auth_type;
					user_i->auth_status = fud->auth_status;
					user_i->auth_rule_id = fud->auth_rule_id;
					user_i->rx_packets = atomic64_read(&acct->counter[0].packets);
					user_i->rx_bytes = atomic64_read(&acct->counter[0].bytes);
					user_i->tx_packets = atomic64_read(&acct->counter[1].packets);
					user_i->tx_bytes = atomic64_read(&acct->counter[1].bytes);

					do {
						unsigned int rx_speed_jiffies = atomic_read(&fud->rx_speed_jiffies);
						unsigned int tx_speed_jiffies = atomic_read(&fud->tx_speed_jiffies);
						int x = (jiffies/HZ/2) % 4;
						unsigned int diff = uintmindiff(jiffies, rx_speed_jiffies);
						if (diff > HZ * 2 * 4) {
							user_i->rx_speed_packets = 0;
							user_i->rx_speed_bytes = 0;
						} else {
							int rx_p2;
							int rx_b2;
							x = (x + 2) % 4;
							rx_p2 = atomic_read(&fud->rx_speed_packets[x]) + 1;
							rx_b2 = atomic_read(&fud->rx_speed_bytes[x]) + 1;
							user_i->rx_speed_packets = rx_p2 / 2;
							user_i->rx_speed_bytes = rx_b2 / 2;
						}

						x = (jiffies/HZ/2) % 4;
						diff = uintmindiff(jiffies, tx_speed_jiffies);
						if (diff > HZ * 2 * 4) {
							user_i->tx_speed_packets = 0;
							user_i->tx_speed_bytes = 0;
						} else {
							int tx_p2;
							int tx_b2;
							x = (x + 2) % 4;
							tx_p2 = atomic_read(&fud->tx_speed_packets[x]) + 1;
							tx_b2 = atomic_read(&fud->tx_speed_bytes[x]) + 1;
							user_i->tx_speed_packets = tx_p2 / 2;
							user_i->tx_speed_bytes = tx_b2 / 2;
						}
					} while (0);
					list_add_tail(&user_i->list, &user->head);
					user->count++;
				}

				nf_ct_put(ct);
			}

			if ((time_after(jiffies, end_time) || user->count >= 4096) && i < hashsz) {
				user->next_bucket = i + 1;
				user->status = 0;
				break;
			}
		}

		rcu_read_unlock();
	}

	user_i = list_first_entry_or_null(&user->head, struct userinfo, list);
	if (user_i) {
		len = sprintf(user->data, "%pI4,%02x:%02x:%02x:%02x:%02x:%02x,0x%x,0x%x,%u,%u,%llu:%llu,%llu:%llu,%u:%u,%u:%u\n",
		              &user_i->ip, user_i->macaddr[0], user_i->macaddr[1], user_i->macaddr[2], user_i->macaddr[3], user_i->macaddr[4], user_i->macaddr[5],
		              user_i->auth_type, user_i->auth_status, user_i->auth_rule_id, user_i->timeout,
		              user_i->rx_packets, user_i->rx_bytes, user_i->tx_packets, user_i->tx_bytes,
		              user_i->rx_speed_packets, user_i->rx_speed_bytes, user_i->tx_speed_packets, user_i->tx_speed_bytes);
		if (len > count) {
			ret = -EINVAL;
			goto out;
		}
		if (copy_to_user(buf, user->data, len)) {
			ret = -EFAULT;
			goto out;
		}
		ret = len;
		list_del(&user_i->list);
		kfree(user_i);
		user->count--;
	} else if (user->status == 0) {
		ret = -EAGAIN;
	} else {
		user->status = 0;
		ret = 0;
	}

out:
	mutex_unlock(&user->lock);
	return ret;
}

static int userinfo_open(struct inode *inode, struct file *file)
{
	struct userinfo_user *user;

	user = kmalloc(USERINFO_MEMSIZE, GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	mutex_init(&user->lock);
	user->next_bucket = 0;
	user->count = 0;
	user->status = 0;
	INIT_LIST_HEAD(&user->head);

	file->private_data = user;
	return 0;
}

static int userinfo_release(struct inode *inode, struct file *file)
{
	struct userinfo *user_i;
	struct userinfo_user *user = file->private_data;

	if (!user)
		return 0;

	while ((user_i = list_first_entry_or_null(&user->head, struct userinfo, list))) {
		list_del(&user_i->list);
		kfree(user_i);
	}

	mutex_destroy(&user->lock);
	kfree(user);
	return 0;
}

const struct file_operations userinfo_fops = {
	.open = userinfo_open,
	.read = userinfo_read,
	.write = userinfo_write,
	.release = userinfo_release,
};

static int userinfo_major = 0;
static int userinfo_minor = 0;
static struct cdev userinfo_cdev;
const char *userinfo_dev_name = "userinfo_ctl";
static struct class *userinfo_class;
static struct device *userinfo_dev;

static int userinfo_init(void)
{
	int retval = 0;
	dev_t devno;

	if (userinfo_major > 0) {
		devno = MKDEV(userinfo_major, userinfo_minor);
		retval = register_chrdev_region(devno, 1, userinfo_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, userinfo_minor, 1, userinfo_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	userinfo_major = MAJOR(devno);
	userinfo_minor = MINOR(devno);
	NATFLOW_println("userinfo_major=%d, userinfo_minor=%d", userinfo_major, userinfo_minor);

	cdev_init(&userinfo_cdev, &userinfo_fops);
	userinfo_cdev.owner = THIS_MODULE;
	userinfo_cdev.ops = &userinfo_fops;

	retval = cdev_add(&userinfo_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	userinfo_class = class_create(THIS_MODULE, "userinfo_class");
#else
	userinfo_class = class_create("userinfo_class");
#endif
	if (IS_ERR(userinfo_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	userinfo_dev = device_create(userinfo_class, NULL, devno, NULL, userinfo_dev_name);
	if (!userinfo_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	return 0;

	//device_destroy(userinfo_class, devno);
device_create_failed:
	class_destroy(userinfo_class);
class_create_failed:
	cdev_del(&userinfo_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
chrdev_region_failed:
	return retval;
}

static void userinfo_exit(void)
{
	dev_t devno;

	devno = MKDEV(userinfo_major, userinfo_minor);
	device_destroy(userinfo_class, devno);
	class_destroy(userinfo_class);
	cdev_del(&userinfo_cdev);
	unregister_chrdev_region(devno, 1);
}


static ssize_t userinfo_event_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	return -ENOSYS;
}
static ssize_t userinfo_event_read(struct file *file, char __user *buf,
                                   size_t count, loff_t *ppos)
{
	size_t len;
	ssize_t ret = 0;
	struct userinfo *user_i;
	struct userinfo_user *user = file->private_data;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret != 0)
		return -EAGAIN;
	if (list_empty(&user->head)) {
		struct userinfo *n;

		if (userinfo_event_store.stage != USERINFO_EVENT_RUNNING) {
			userinfo_event_store.stage = USERINFO_EVENT_RUNNING;
		}
		if (list_empty(&userinfo_event_store.head)) {
			//wait
			ret = wait_event_interruptible(userinfo_event_store.wait, !list_empty(&userinfo_event_store.head));
			if (ret != 0) {
				userinfo_event_store.stage = USERINFO_EVENT_STOPPED;
			}
		}
		spin_lock_bh(&userinfo_event_store.lock);
		list_for_each_entry_safe(user_i, n, &userinfo_event_store.head, list) {
			list_del(&user_i->list);
			list_add_tail(&user_i->list, &user->head);
		}
		spin_unlock_bh(&userinfo_event_store.lock);
	}

	user_i = list_first_entry_or_null(&user->head, struct userinfo, list);
	if (user_i) {
		len = sprintf(user->data, "%pI4,%02x:%02x:%02x:%02x:%02x:%02x,0x%x,0x%x,%u,%u,%llu:%llu,%llu:%llu,%u:%u,%u:%u\n",
		              &user_i->ip, user_i->macaddr[0], user_i->macaddr[1], user_i->macaddr[2], user_i->macaddr[3], user_i->macaddr[4], user_i->macaddr[5],
		              user_i->auth_type, user_i->auth_status, user_i->auth_rule_id, user_i->timeout,
		              user_i->rx_packets, user_i->rx_bytes, user_i->tx_packets, user_i->tx_bytes,
		              user_i->rx_speed_packets, user_i->rx_speed_bytes, user_i->tx_speed_packets, user_i->tx_speed_bytes);
		if (len > count) {
			ret = -EINVAL;
			goto out;
		}
		if (copy_to_user(buf, user->data, len)) {
			ret = -EFAULT;
			goto out;
		}
		ret = len;
		list_del(&user_i->list);
		kfree(user_i);
		user->count--;
	} else {
		ret = -EAGAIN;
	}

out:
	mutex_unlock(&user->lock);
	return ret;
}

static int userinfo_event_open(struct inode *inode, struct file *file)
{
	struct userinfo_user *user;

	/* just allow one user to read */
	if (userinfo_event_store.stage == USERINFO_EVENT_RUNNING)
		return -EBUSY;

	user = kmalloc(USERINFO_MEMSIZE, GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	mutex_init(&user->lock);
	user->next_bucket = 0;
	user->count = 0;
	user->status = 0;
	INIT_LIST_HEAD(&user->head);

	file->private_data = user;
	return 0;
}

static int userinfo_event_release(struct inode *inode, struct file *file)
{
	struct userinfo *user_i;
	struct userinfo_user *user = file->private_data;

	if (!user)
		return 0;

	while ((user_i = list_first_entry_or_null(&user->head, struct userinfo, list))) {
		list_del(&user_i->list);
		kfree(user_i);
	}

	mutex_destroy(&user->lock);
	kfree(user);

	userinfo_event_store.stage = USERINFO_EVENT_STOPPED;
	return 0;
}

const struct file_operations userinfo_event_fops = {
	.open = userinfo_event_open,
	.read = userinfo_event_read,
	.write = userinfo_event_write,
	.release = userinfo_event_release,
};

static int userinfo_event_major = 0;
static int userinfo_event_minor = 0;
static struct cdev userinfo_event_cdev;
const char *userinfo_event_dev_name = "userinfo_event_ctl";
static struct class *userinfo_event_class;
static struct device *userinfo_event_dev;

static int userinfo_event_init(void)
{
	int retval = 0;
	dev_t devno;

	if (userinfo_event_major > 0) {
		devno = MKDEV(userinfo_event_major, userinfo_event_minor);
		retval = register_chrdev_region(devno, 1, userinfo_event_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, userinfo_event_minor, 1, userinfo_event_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	userinfo_event_major = MAJOR(devno);
	userinfo_event_minor = MINOR(devno);
	NATFLOW_println("userinfo_event_major=%d, userinfo_event_minor=%d", userinfo_event_major, userinfo_event_minor);

	cdev_init(&userinfo_event_cdev, &userinfo_event_fops);
	userinfo_event_cdev.owner = THIS_MODULE;
	userinfo_event_cdev.ops = &userinfo_event_fops;

	retval = cdev_add(&userinfo_event_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	userinfo_event_class = class_create(THIS_MODULE, "userinfo_event_class");
#else
	userinfo_event_class = class_create("userinfo_event_class");
#endif
	if (IS_ERR(userinfo_event_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	userinfo_event_dev = device_create(userinfo_event_class, NULL, devno, NULL, userinfo_event_dev_name);
	if (!userinfo_event_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	return 0;

	//device_destroy(userinfo_event_class, devno);
device_create_failed:
	class_destroy(userinfo_event_class);
class_create_failed:
	cdev_del(&userinfo_event_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
chrdev_region_failed:
	return retval;
}

static void userinfo_event_exit(void)
{
	dev_t devno;

	userinfo_event_store_exit();

	devno = MKDEV(userinfo_event_major, userinfo_event_minor);
	device_destroy(userinfo_event_class, devno);
	class_destroy(userinfo_event_class);
	cdev_del(&userinfo_event_cdev);
	unregister_chrdev_region(devno, 1);
}

//must lock by caller
static inline struct qos_rule *qos_rule_get(int idx)
{
	if (idx < qos_token_ctrl_num) {
		return &(qos_token_ctrl_rule[idx]);
	}

	return NULL;
}

static int qos_ctl_buffer_use = 0;
static char *qos_ctl_buffer = NULL;
static void *qos_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(qos_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Usage:\n"
		             "#    clear -- clear all existing auth rule(s)\n"
		             "#    add user=<ipset/ip/ipcidr>,user_port=<portset/port>,remote=<ipset/ip/ipcidr>,remote_port=<portset/port>,proto=<tcp/udp>,rxbytes=Bytes,txbytes=Bytes --add one rule\n"
		             "#\n"
		             "# tc_classid_mode=%u\n"
		             "#\n"
		             "# Reload cmd:\n"
		             "\n"
		             "clear\n"
		             "\n", tc_classid_mode
		            );
		qos_ctl_buffer[n] = 0;
		return qos_ctl_buffer;
	} else if ((*pos) > 0) {
		struct qos_rule *qr = qos_rule_get((*pos) - 1);

		if (qr) {
			qos_ctl_buffer[0] = 0;
			if ((qr->flag & USER_TYPE_IP))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "add user=%pI4,", &qr->user.ip);
			else if ((qr->flag & USER_TYPE_IPCIDR))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "add user=%pI4/%u,", &qr->user.ipcidr.ip, hweight32(ntohl(qr->user.ipcidr.mask)));
			else
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "add user=%s,", qr->user.name);

			if ((qr->flag & USER_PORT_TYPE_PORT))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "user_port=%u,", ntohs(qr->user_port.port));
			else
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "user_port=%s,", qr->user_port.name);

			if ((qr->flag & REMOTE_TYPE_IP))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "remote=%pI4,", &qr->remote.ip);
			else if ((qr->flag & REMOTE_TYPE_IPCIDR))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "remote=%pI4/%u,", &qr->remote.ipcidr.ip, hweight32(ntohl(qr->remote.ipcidr.mask)));
			else
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "remote=%s,", qr->remote.name);

			if ((qr->flag & REMOTE_PORT_TYPE_PORT))
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "remote_port=%u,", ntohs(qr->remote_port.port));
			else
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "remote_port=%s,", qr->remote_port.name);

			if (qr->proto == IPPROTO_TCP)
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "proto=tcp,");
			else if (qr->proto == IPPROTO_UDP)
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "proto=udp,");
			else
				n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "proto=,");

			n += snprintf(qos_ctl_buffer + n, PAGE_SIZE - n - 1, "rxbytes=%u,txbytes=%u\n", qr->rxbytes, qr->txbytes);

			qos_ctl_buffer[n] = 0;
			return qos_ctl_buffer;
		}
	}

	return NULL;
}

static void *qos_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return qos_start(m, pos);
	}
	return NULL;
}

static void qos_stop(struct seq_file *m, void *v)
{
}

static int qos_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations qos_seq_ops = {
	.start = qos_start,
	.next = qos_next,
	.stop = qos_stop,
	.show = qos_show,
};

static ssize_t qos_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t qos_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <= MAX_IOCTL_LEN
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "clear", 5) == 0) {
		qos_token_ctrl_num = 0;
		goto done;
	} else if (strncmp(data, "tc_classid_mode=", 16) == 0) {
		unsigned int a;
		n = sscanf(data, "tc_classid_mode=%u", &a);
		if (n == 1) {
			tc_classid_mode = !!a;
			goto done;
		}
	} else if (strncmp(data, "add user=", 9) == 0) {
		struct qos_rule *qr = kmalloc(sizeof(struct qos_rule), GFP_KERNEL);
		if (qr) {
			qr->flag = 0;
			qr->rxbytes = 0;
			qr->txbytes = 0;
			qr->proto = 0;
			do {
				int i;
				char *p;
				p = strstr(data, "add user=");
				if (p) {
					int a, b, c, d, e;
					p = p + 9;
					n = sscanf(p, "%d.%d.%d.%d/%d,", &a, &b, &c, &d, &e);
					if (n == 5) {
						for (i = 7; i < 19 && p[i] != ','; i++)
							if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.' || p[i] == '/'))
								break;
						if (p[i] == ',' &&
						        (a&0xff) == a &&
						        (b&0xff) == b &&
						        (c&0xff) == c &&
						        (d&0xff) == d &&
						        e >= 0 && e <= 32) {
							qr->user.ipcidr.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
							if (e == 0) {
								qr->user.ipcidr.ip = 0;
								qr->user.ipcidr.mask = 0;
								qr->flag |= USER_TYPE_IPCIDR;
							} else {
								qr->user.ipcidr.mask = htonl(GENMASK(31, 32-e));
								qr->flag |= USER_TYPE_IPCIDR;
								if (qr->user.ipcidr.ip != (qr->user.ipcidr.ip & qr->user.ipcidr.mask)) {
									err = -EINVAL;
									NATFLOW_println("user=<ip> error ipcidr format");
									break;
								}
							}
						} else {
							err = -EINVAL;
							NATFLOW_println("user=<ip> error ipcidr format");
							break;
						}
					} else {
						n = sscanf(p, "%d.%d.%d.%d,", &a, &b, &c, &d);
						if (n == 4) {
							for (i = 7; i < 16 && p[i] != ','; i++)
								if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.'))
									break;
							if (p[i] == ',' &&
							        (a&0xff) == a &&
							        (b&0xff) == b &&
							        (c&0xff) == c &&
							        (d&0xff) == d) {
								qr->user.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
								qr->flag |= USER_TYPE_IP;
							} else {
								err = -EINVAL;
								NATFLOW_println("user=<ip> error ip format");
								break;
							}
						} else {
							int k = 0;
							while (p[k] && p[k] != ',' && k < sizeof(qr->user.name) - 1) {
								qr->user.name[k] = p[k];
								k++;
							}
							if (k >= sizeof(qr->user.name) - 1) {
								err = -EINVAL;
								NATFLOW_println("user=<name> too long");
								break;
							}
							qr->user.name[k] = 0;
							if (k != 0) {
								qr->flag |= USER_TYPE_SET;
							}
							//else empty user
						}
					}
				}

				p = strstr(data, ",user_port=");
				if (p) {
					int a;
					p = p + 11;
					n = sscanf(p, "%d,", &a);
					if (n == 1) {
						if ((a&0xffff) == a) {
							qr->user_port.port = htons(a);
							qr->flag |= USER_PORT_TYPE_PORT;
						} else {
							err = -EINVAL;
							NATFLOW_println("user_port=<port> error port format");
							break;
						}
					} else {
						int k = 0;
						while (p[k] && p[k] != ',' && k < sizeof(qr->user_port.name) - 1) {
							qr->user_port.name[k] = p[k];
							k++;
						}
						if (k >= sizeof(qr->user_port.name) - 1) {
							err = -EINVAL;
							NATFLOW_println("user_port=<name> too long");
							break;
						}
						qr->user_port.name[k] = 0;
						if (k != 0) {
							qr->flag |= USER_PORT_TYPE_SET;
						}
					}
				}

				p = strstr(data, ",remote=");
				if (p) {
					int a, b, c, d, e;
					p = p + 8;
					n = sscanf(p, "%d.%d.%d.%d/%d,", &a, &b, &c, &d, &e);
					if (n == 5) {
						for (i = 7; i < 19 && p[i] != ','; i++)
							if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.' || p[i] == '/'))
								break;
						if (p[i] == ',' &&
						        (a&0xff) == a &&
						        (b&0xff) == b &&
						        (c&0xff) == c &&
						        (d&0xff) == d &&
						        e >= 0 && e <= 32) {
							qr->remote.ipcidr.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
							if (e == 0) {
								qr->remote.ipcidr.ip = 0;
								qr->remote.ipcidr.mask = 0;
								qr->flag |= REMOTE_TYPE_IPCIDR;
							} else {
								qr->remote.ipcidr.mask = htonl(GENMASK(31, 32-e));
								qr->flag |= REMOTE_TYPE_IPCIDR;
								if (qr->remote.ipcidr.ip != (qr->remote.ipcidr.ip & qr->remote.ipcidr.mask)) {
									err = -EINVAL;
									NATFLOW_println("remote=<ip> error ipcidr format");
									break;
								}
							}
						} else {
							err = -EINVAL;
							NATFLOW_println("remote=<ip> error ipcidr format");
							break;
						}
					} else {
						n = sscanf(p, "%d.%d.%d.%d,", &a, &b, &c, &d);
						if (n == 4) {
							for (i = 7; i < 16 && p[i] != ','; i++)
								if (!((p[i] >= '0' && p[i] <= '9') || p[i] == '.'))
									break;
							if (p[i] == ',' &&
							        (a&0xff) == a &&
							        (b&0xff) == b &&
							        (c&0xff) == c &&
							        (d&0xff) == d) {
								qr->remote.ip = htonl((a << 24) | (b << 16) | (c << 8) | d);
								qr->flag |= REMOTE_TYPE_IP;
							} else {
								err = -EINVAL;
								NATFLOW_println("remote=<ip> error ip format");
								break;
							}
						} else {
							int k = 0;
							while (p[k] && p[k] != ',' && k < sizeof(qr->remote.name) - 1) {
								qr->remote.name[k] = p[k];
								k++;
							}
							if (k >= sizeof(qr->remote.name) - 1) {
								err = -EINVAL;
								NATFLOW_println("remote=<name> too long");
								break;
							}
							qr->remote.name[k] = 0;
							if (k != 0) {
								qr->flag |= REMOTE_TYPE_SET;
							}
							//else empty remote
						}
					}
				}

				p = strstr(data, ",remote_port=");
				if (p) {
					int a;
					p = p + 13;
					n = sscanf(p, "%d,", &a);
					if (n == 1) {
						if ((a&0xffff) == a) {
							qr->remote_port.port = htons(a);
							qr->flag |= REMOTE_PORT_TYPE_PORT;
						} else {
							err = -EINVAL;
							NATFLOW_println("remote_port=<port> error port format");
							break;
						}
					} else {
						int k = 0;
						while (p[k] && p[k] != ',' && k < sizeof(qr->remote_port.name) - 1) {
							qr->remote_port.name[k] = p[k];
							k++;
						}
						if (k >= sizeof(qr->remote_port.name) - 1) {
							err = -EINVAL;
							NATFLOW_println("remote_port=<name> too long");
							break;
						}
						qr->remote_port.name[k] = 0;
						if (k != 0) {
							qr->flag |= REMOTE_PORT_TYPE_SET;
						}
					}
				}

				p = strstr(data, ",proto=");
				if (p) {
					p = p + 7;
					if (strncmp(p, "tcp,", 4) == 0) {
						qr->proto = IPPROTO_TCP;
					} else if (strncmp(p, "udp,", 4) == 0) {
						qr->proto = IPPROTO_UDP;
					} else if (strncmp(p, ",", 1) == 0) {
						qr->proto = 0;
					} else {
						err = -EINVAL;
						NATFLOW_println("invalid proto=");
						break;
					}
				}

				p = strstr(data, ",rxbytes=");
				if (p) {
					unsigned int rxbytes, txbytes;
					p = p + 9;
					n = sscanf(p, "%u,txbytes=%u", &rxbytes, &txbytes);
					if (n == 2) {
						qr->rxbytes = rxbytes;
						qr->txbytes = txbytes;
					} else {
						err = -EINVAL;
						NATFLOW_println("invalid rxbytes txbytes");
						break;
					}
				}
			} while (0);
			if (err == 0) {
				if (qos_token_ctrl_num < QOS_TOKEN_CTRL_GROUP_MAX) {
					memcpy(&qos_token_ctrl_rule[qos_token_ctrl_num], qr, sizeof(struct qos_rule));
					qos_token_ctrl[qos_token_ctrl_num].rx.tokens_per_jiffy = qr->rxbytes / HZ;
					qos_token_ctrl[qos_token_ctrl_num].tx.tokens_per_jiffy = qr->txbytes / HZ;
					qos_token_ctrl_num++;
				}
				kfree(qr);
				goto done;
			}
			NATFLOW_println("qos add rule fail err=%d", err);
			kfree(qr);
		}
	}

	NATFLOW_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int qos_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	if (qos_ctl_buffer_use++ == 0) {
		qos_ctl_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (qos_ctl_buffer == NULL) {
			qos_ctl_buffer_use--;
			return -ENOMEM;
		}
	}

	ret = seq_open(file, &qos_seq_ops);
	if (ret)
		return ret;
	return 0;
}

static int qos_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);

	if (--qos_ctl_buffer_use == 0) {
		kfree(qos_ctl_buffer);
		qos_ctl_buffer = NULL;
	}

	return ret;
}

static struct file_operations qos_fops = {
	.owner = THIS_MODULE,
	.open = qos_open,
	.release = qos_release,
	.read = qos_read,
	.write = qos_write,
	.llseek  = seq_lseek,
};

static int qos_init(void)
{
	int retval = 0;
	dev_t devno;

	qos_token_ctrl_init();

	if (qos_major > 0) {
		devno = MKDEV(qos_major, qos_minor);
		retval = register_chrdev_region(devno, 1, qos_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, qos_minor, 1, qos_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	qos_major = MAJOR(devno);
	qos_minor = MINOR(devno);
	NATFLOW_println("qos_major=%d, qos_minor=%d", qos_major, qos_minor);

	cdev_init(&qos_cdev, &qos_fops);
	qos_cdev.owner = THIS_MODULE;
	qos_cdev.ops = &qos_fops;

	retval = cdev_add(&qos_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	qos_class = class_create(THIS_MODULE, "qos_class");
#else
	qos_class = class_create("qos_class");
#endif
	if (IS_ERR(qos_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	qos_dev = device_create(qos_class, NULL, devno, NULL, qos_dev_name);
	if (!qos_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	class_destroy(qos_class);
class_create_failed:
	cdev_del(&qos_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
chrdev_region_failed:
	return retval;
}

static void qos_exit(void)
{
	dev_t devno;

	devno = MKDEV(qos_major, qos_minor);
	device_destroy(qos_class, devno);
	class_destroy(qos_class);
	cdev_del(&qos_cdev);
	unregister_chrdev_region(devno, 1);
}

int natflow_user_init(void)
{
	int i;
	int retval = 0;
	dev_t devno;

	for (i = 0; i < NR_CPUS; i++) {
		natflow_user_uskbs[i] = NULL;
	}

	retval = nf_register_hooks(user_hooks, ARRAY_SIZE(user_hooks));
	if (retval != 0)
		goto nf_register_hooks_failed;

	retval = auth_conf_init();
	if (retval != 0)
		goto auth_conf_init_failed;

	natflow_user_disabled_set(1);

	if (natflow_user_major > 0) {
		devno = MKDEV(natflow_user_major, natflow_user_minor);
		retval = register_chrdev_region(devno, 1, natflow_user_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, natflow_user_minor, 1, natflow_user_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	natflow_user_major = MAJOR(devno);
	natflow_user_minor = MINOR(devno);
	NATFLOW_println("natflow_user_major=%d, natflow_user_minor=%d", natflow_user_major, natflow_user_minor);

	cdev_init(&natflow_user_cdev, &natflow_user_fops);
	natflow_user_cdev.owner = THIS_MODULE;
	natflow_user_cdev.ops = &natflow_user_fops;

	retval = cdev_add(&natflow_user_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	natflow_user_class = class_create(THIS_MODULE, "natflow_user_class");
#else
	natflow_user_class = class_create("natflow_user_class");
#endif
	if (IS_ERR(natflow_user_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	natflow_user_dev = device_create(natflow_user_class, NULL, devno, NULL, natflow_user_dev_name);
	if (!natflow_user_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	retval = userinfo_init();
	if (retval) {
		goto userinfo_init_failed;
	}

	retval = userinfo_event_init();
	if (retval) {
		goto userinfo_event_init_failed;
	}

	userinfo_event_store_init();

	retval = qos_init();
	if (retval) {
		goto qos_init_failed;
	}

	return 0;

	//qos_exit();
qos_init_failed:
	userinfo_event_exit();
userinfo_event_init_failed:
	userinfo_exit();
userinfo_init_failed:
	device_destroy(natflow_user_class, devno);
device_create_failed:
	class_destroy(natflow_user_class);
class_create_failed:
	cdev_del(&natflow_user_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
chrdev_region_failed:
	auth_conf_exit();
auth_conf_init_failed:
	nf_unregister_hooks(user_hooks, ARRAY_SIZE(user_hooks));
nf_register_hooks_failed:
	return retval;
}

void natflow_user_exit(void)
{
	int i;
	dev_t devno;

	qos_exit();
	userinfo_event_exit();
	userinfo_exit();

	devno = MKDEV(natflow_user_major, natflow_user_minor);
	device_destroy(natflow_user_class, devno);
	class_destroy(natflow_user_class);
	cdev_del(&natflow_user_cdev);
	unregister_chrdev_region(devno, 1);

	natflow_user_disabled_set(1);
	synchronize_rcu();

	auth_conf_exit();

	nf_unregister_hooks(user_hooks, ARRAY_SIZE(user_hooks));

	for (i = 0; i < NR_CPUS; i++) {
		if (natflow_user_uskbs[i]) {
			kfree(natflow_user_uskbs[i]);
			natflow_user_uskbs[i] = NULL;
		}
	}
}
