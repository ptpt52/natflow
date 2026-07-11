/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Tue, 22 Jun 2021 22:50:41 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/ip6_checksum.h>
#include "natflow_common.h"
#include "natflow_dpi.h"
#include "natflow_l7.h"
#include "natflow_urllogger.h"
#include "natflow_user.h"
#include "natflow_path.h"

static int urllogger_major = 0;
static int urllogger_minor = 0;
static struct cdev urllogger_cdev;
static const char * const urllogger_dev_name = "urllogger_queue";
static struct class *urllogger_class;
static struct device *urllogger_dev;

#define URLINFO_HOST_MAX_LEN NATFLOW_L7_HOST_MAX_LEN
#define URLINFO_HOST_ALLOW_PORT NATFLOW_L7_HOST_ALLOW_PORT

static inline ssize_t urlinfo_copy_host_tolower(unsigned char *dst, const unsigned char *src, ssize_t n, unsigned int flags)
{
	return natflow_l7_copy_host_tolower(dst, src, n, flags);
}

static inline int urlinfo_uri_validate(const unsigned char *uri, int uri_len)
{
	return natflow_l7_uri_validate(uri, uri_len);
}

struct urlinfo {
	struct list_head list;
#define URLINFO_NOW ((jiffies - INITIAL_JIFFIES) / HZ)
#define TIMESTAMP_FREQ 10
	unsigned int timestamp;
	union {
		__be32 sip;
		union nf_inet_addr sipv6;
	};
	union {
		__be32 dip;
		union nf_inet_addr dipv6;
	};
	__be16 sport;
	__be16 dport;
	unsigned char mac[ETH_ALEN];
#define URLINFO_SOURCE_MASK 0x03
#define URLINFO_SOURCE_HTTP 0x00
#define URLINFO_SOURCE_HTTPS 0x01
#define URLINFO_SOURCE_QUIC 0x02
#define URLINFO_HTTPS URLINFO_SOURCE_HTTPS
#define URLINFO_QUIC URLINFO_SOURCE_QUIC
#define URLINFO_IPV6 0x80
	unsigned char flags;
#define NATFLOW_HTTP_NONE 0
#define NATFLOW_HTTP_GET 1
#define NATFLOW_HTTP_POST 2
#define NATFLOW_HTTP_HEAD 3
	unsigned char http_method;
	unsigned short hits;
	unsigned short data_len;
	unsigned short host_len;
	unsigned char acl_idx;
#define URLINFO_ACL_ACTION_RECORD 0
#define URLINFO_ACL_ACTION_DROP 1
#define URLINFO_ACL_ACTION_RESET 2
#define URLINFO_ACL_ACTION_REDIRECT 3
	unsigned char acl_action;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
	unsigned char data[];
#else
	unsigned char data[0];
#endif
};

#define __URLINFO_ALIGN 64

static struct urlinfo *urlinfo_alloc_record(const unsigned char *host, int host_len,
        unsigned int host_flags,
        const unsigned char *uri, int uri_len);

static const char * const natflow_http_method_names[] = {
	[NATFLOW_HTTP_NONE] = "NONE",
	[NATFLOW_HTTP_GET] = "GET",
	[NATFLOW_HTTP_POST] = "POST",
	[NATFLOW_HTTP_HEAD] = "HEAD",
};

static inline const char *urlinfo_source_name(const struct urlinfo *url)
{
	switch (url->flags & URLINFO_SOURCE_MASK) {
	case URLINFO_SOURCE_HTTPS:
		return "HTTPS";
	case URLINFO_SOURCE_QUIC:
		return "QUIC";
	case URLINFO_SOURCE_HTTP:
	default:
		return "HTTP";
	}
}

static inline void urlinfo_release(struct urlinfo *url)
{
	kfree(url);
}

/*
tuple_type:
0: dir0-src dir0-dst
1: dir0-src dir1-src
2: dir1-dst dir1-src
 */
static unsigned int urllogger_store_tuple_type = 0;
static unsigned int urllogger_store_timestamp_freq = TIMESTAMP_FREQ;
static unsigned int urllogger_store_enable = 0;
static unsigned int urllogger_store_memsize_limit = 1024 * 1024 * 10;
static unsigned int urllogger_store_count_limit = 10000;
static unsigned int urllogger_store_memsize = 0;
static unsigned int urllogger_store_count = 0;
static LIST_HEAD(urllogger_store_list);
static DEFINE_SPINLOCK(urllogger_store_lock);

static inline int urllogger_store_addr_equal(const struct urlinfo *a, const struct urlinfo *b)
{
	if ((a->flags & URLINFO_IPV6) != (b->flags & URLINFO_IPV6))
		return 0;

	if ((a->flags & URLINFO_IPV6)) {
		return memcmp(&a->sipv6, &b->sipv6, sizeof(a->sipv6)) == 0 &&
		       memcmp(&a->dipv6, &b->dipv6, sizeof(a->dipv6)) == 0;
	}

	return a->sip == b->sip && a->dip == b->dip;
}

static void urllogger_store_record(struct urlinfo *url)
{
	struct urlinfo *url_i;
	struct list_head *pos;
	spin_lock(&urllogger_store_lock);
	list_for_each_prev(pos, &urllogger_store_list) {
		url_i = list_entry(pos, struct urlinfo, list);
		/* merge the duplicate url request in 10s */
		if (uintmindiff(url_i->timestamp, url->timestamp) > urllogger_store_timestamp_freq)
			break;
		if (urllogger_store_addr_equal(url_i, url) && url_i->dport == url->dport &&
		        url_i->data_len == url->data_len && memcmp(url_i->data, url->data, url_i->data_len) == 0 &&
		        url_i->flags == url->flags &&
		        url_i->http_method == url->http_method) {
			url_i->hits++;
			spin_unlock(&urllogger_store_lock);
			urlinfo_release(url);
			return;
		}
	}
	urllogger_store_memsize += ALIGN(sizeof(struct urlinfo) + url->data_len, __URLINFO_ALIGN);
	urllogger_store_count++;
	list_add_tail(&url->list, &urllogger_store_list);
	while (urllogger_store_count > urllogger_store_count_limit || urllogger_store_memsize > urllogger_store_memsize_limit) {
		pos = urllogger_store_list.next;
		url_i = list_entry(pos, struct urlinfo, list);
		urllogger_store_memsize -= ALIGN(sizeof(struct urlinfo) + url_i->data_len, __URLINFO_ALIGN);
		urllogger_store_count--;
		list_del(pos);
		urlinfo_release(url_i);
	}
	spin_unlock(&urllogger_store_lock);
}

static void urllogger_store_clear(void)
{
	struct urlinfo *url;
	struct list_head *pos, *n;
	spin_lock_bh(&urllogger_store_lock);
	list_for_each_safe(pos, n, &urllogger_store_list) {
		url = list_entry(pos, struct urlinfo, list);
		urllogger_store_memsize -= ALIGN(sizeof(struct urlinfo) + url->data_len, __URLINFO_ALIGN);
		urllogger_store_count--;
		list_del(pos);
		urlinfo_release(url);
	}
	spin_unlock_bh(&urllogger_store_lock);
}

static int hostacl_major = 0;
static int hostacl_minor = 0;
static struct cdev hostacl_cdev;
static const char * const hostacl_dev_name = "hostacl_ctl";
static struct class *hostacl_class;
static struct device *hostacl_dev;

struct acl_rule {
	unsigned char *acl_buffer;
	ssize_t acl_buffer_size;
	ssize_t acl_buffer_len;
};

/* 0: accept/record, 1: drop, 2: reset, 3: redirect */
static int acl_action_default = URLINFO_ACL_ACTION_RECORD;
static const char * const acl_action_names[] = {"accept", "drop", "reset", "redirect"};
struct urllogger_acl_lookup {
	unsigned short host_len;
	unsigned char acl_idx;
	unsigned char acl_action;
	unsigned char data[URLINFO_HOST_MAX_LEN + 1];
};

static int urllogger_acl_lookup_init(struct urllogger_acl_lookup *lookup,
        const unsigned char *host, int host_len, unsigned int host_flags)
{
	ssize_t copied_host_len;

	copied_host_len = urlinfo_copy_host_tolower(lookup->data, host, host_len, host_flags);
	if (copied_host_len < 0)
		return -EINVAL;

	lookup->host_len = copied_host_len;
	lookup->data[copied_host_len] = 0;
	lookup->acl_idx = 64;
	lookup->acl_action = acl_action_default;

	return 0;
}

static inline void urllogger_dpi_classify_url(struct nf_conn *ct,
        const struct urlinfo *url, unsigned int source)
{
	natflow_dpi_classify_host(ct, url->data, url->host_len, source);
}

static inline void urllogger_dpi_classify_lookup(struct nf_conn *ct,
        const struct urllogger_acl_lookup *lookup, unsigned int source)
{
	natflow_dpi_classify_host(ct, lookup->data, lookup->host_len, source);
}

static inline void urllogger_dpi_classify_raw_host(struct nf_conn *ct,
        const unsigned char *host, int host_len, unsigned int source)
{
	if (host_len <= 0 || host_len > URLINFO_HOST_MAX_LEN)
		return;

	natflow_dpi_classify_host(ct, host, host_len, source);
}

struct acl_redirect_config {
	char url[256];
	char payload[512];
	int payload_len;
};
static struct acl_redirect_config acl_redirect_default = {
	.url = "http://1.1.1.1/blocked.html",
	.payload =
	"HTTP/1.1 302 Moved Temporarily\r\n"
	"Connection: close\r\n"
	"Cache-Control: no-cache\r\n"
	"Content-Type: text/html; charset=UTF-8\r\n"
	"Location: http://1.1.1.1/blocked.html\r\n"
	"Content-Length: 0\r\n"
	"\r\n",
	.payload_len = sizeof(
	    "HTTP/1.1 302 Moved Temporarily\r\n"
	    "Connection: close\r\n"
	    "Cache-Control: no-cache\r\n"
	    "Content-Type: text/html; charset=UTF-8\r\n"
	    "Location: http://1.1.1.1/blocked.html\r\n"
	    "Content-Length: 0\r\n"
	    "\r\n") - 1,
};
static struct acl_redirect_config *acl_redirect_config = &acl_redirect_default;

#define ACL_RULE_ALLOC_SIZE 256
#define ACL_RULE_MAX 32
static int acl_rule_max = 0;
static struct acl_rule acl_rule_node[ACL_RULE_MAX];
static DEFINE_MUTEX(acl_rule_lock);

static void acl_rule_init(void)
{
	int rule_id;
	for (rule_id = 0; rule_id < ACL_RULE_MAX; rule_id++) {
		acl_rule_node[rule_id].acl_buffer = NULL;
	}
}
static void acl_rule_clear(void)
{
	void *tmp;
	int rule_id;

	mutex_lock(&acl_rule_lock);
	for (rule_id = 0; rule_id < ACL_RULE_MAX; rule_id++) {
		tmp = acl_rule_node[rule_id].acl_buffer;
		if (tmp != NULL) {
			rcu_assign_pointer(acl_rule_node[rule_id].acl_buffer, NULL);
			synchronize_rcu();
			kfree(tmp);
		}
	}
	acl_rule_max = 0;
	mutex_unlock(&acl_rule_lock);
}

static int acl_redirect_config_update(const char *url)
{
	static const char http_fmt[] =
	    "HTTP/1.1 302 Moved Temporarily\r\n"
	    "Connection: close\r\n"
	    "Cache-Control: no-cache\r\n"
	    "Content-Type: text/html; charset=UTF-8\r\n"
	    "Location: %s\r\n"
	    "Content-Length: 0\r\n"
	    "\r\n";
	struct acl_redirect_config *new_config;
	struct acl_redirect_config *old_config;

	new_config = kmalloc(sizeof(*new_config), GFP_KERNEL);
	if (!new_config)
		return -ENOMEM;

	snprintf(new_config->url, sizeof(new_config->url), "%s", url);
	snprintf(new_config->payload, sizeof(new_config->payload), http_fmt, new_config->url);
	new_config->payload_len = strnlen(new_config->payload, sizeof(new_config->payload));

	mutex_lock(&acl_rule_lock);
	old_config = acl_redirect_config;
	rcu_assign_pointer(acl_redirect_config, new_config);
	mutex_unlock(&acl_rule_lock);

	if (old_config != &acl_redirect_default) {
		synchronize_rcu();
		kfree(old_config);
	}

	return 0;
}

static void acl_redirect_config_reset(void)
{
	struct acl_redirect_config *old_config;

	mutex_lock(&acl_rule_lock);
	old_config = acl_redirect_config;
	rcu_assign_pointer(acl_redirect_config, &acl_redirect_default);
	mutex_unlock(&acl_rule_lock);

	if (old_config != &acl_redirect_default) {
		synchronize_rcu();
		kfree(old_config);
	}
}

static int acl_rule_add(unsigned int idx, unsigned int act, const char *host, ssize_t host_len)
{
	unsigned char *old_buffer;
	unsigned char *new_buffer;
	ssize_t old_len;
	ssize_t new_len;
	ssize_t new_size;
	int ret = 0;

	mutex_lock(&acl_rule_lock);
	old_buffer = acl_rule_node[idx].acl_buffer;
	old_len = old_buffer ? acl_rule_node[idx].acl_buffer_len : 1;
	new_len = old_len + host_len + 1;
	new_size = old_buffer ? acl_rule_node[idx].acl_buffer_size : ACL_RULE_ALLOC_SIZE;
	while (new_size < new_len)
		new_size += ACL_RULE_ALLOC_SIZE;

	new_buffer = kmalloc(new_size, GFP_KERNEL);
	if (new_buffer == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	if (old_buffer)
		memcpy(new_buffer, old_buffer, old_len);
	else
		new_buffer[0] = 0;

	new_buffer[old_len + host_len] = 0;
	new_buffer[old_len - 1] = (unsigned char)(0x80|act|idx);
	memcpy(new_buffer + old_len, host, host_len);

	rcu_assign_pointer(acl_rule_node[idx].acl_buffer, new_buffer);
	acl_rule_node[idx].acl_buffer_size = new_size;
	acl_rule_node[idx].acl_buffer_len = new_len;
	if (old_buffer) {
		synchronize_rcu();
		kfree(old_buffer);
	}
	if (idx >= acl_rule_max) {
		acl_rule_max = idx + 1;
	}

out:
	mutex_unlock(&acl_rule_lock);
	return ret;
}

/* return: 0 = no matched, 1 = matched */
static int urllogger_acl(struct urlinfo *url, int rule_id)
{
	int ret = 0;
	unsigned char backup_c;
	unsigned char *acl_buffer;

	backup_c = url->data[url->host_len];
	url->data[url->host_len] = 0;

	rcu_read_lock();
	acl_buffer = rcu_dereference(acl_rule_node[rule_id].acl_buffer);

	if (url->host_len >= 1 && acl_buffer != NULL) { /* at least a.b pattern */
		int i = 0;
		unsigned char b;
		unsigned char *ptr = NULL;

		while (ptr == NULL) {
			ptr = strstr(acl_buffer, url->data + i);
			while (ptr != NULL) {
				b = *(ptr - 1);
				if (((ptr[url->host_len - i] & 0x80) != 0 || ptr[url->host_len - i] == 0) && (b & 0x80) != 0) {
					/* found */
					url->acl_idx = (b & 0x1f);
					ret = ((b & 0x60) >> 5);
					url->acl_action = ret;
					ret = 1;
					goto __done;
				}
				if (ptr[url->host_len - i] == 0) {
					ptr = NULL;
					break;
				}
				ptr = strstr(ptr + url->host_len - i, url->data + i);
			}
			while (url->host_len >= i + 1 && url->data[i] != '.') {
				i++;
			}
			if (url->data[i] != '.') {
				break;
			}
			i++;
			if (url->host_len < i + 1) {
				break;
			}
		}
	}
__done:
	rcu_read_unlock();
	url->data[url->host_len] = backup_c;
	return ret;
}

static int urllogger_acl_lookup_rule(struct urllogger_acl_lookup *lookup, int rule_id)
{
	int ret = 0;
	unsigned char backup_c;
	unsigned char *acl_buffer;

	backup_c = lookup->data[lookup->host_len];
	lookup->data[lookup->host_len] = 0;

	rcu_read_lock();
	acl_buffer = rcu_dereference(acl_rule_node[rule_id].acl_buffer);

	if (lookup->host_len >= 1 && acl_buffer != NULL) {
		int i = 0;
		unsigned char b;
		unsigned char *ptr = NULL;

		while (ptr == NULL) {
			ptr = strstr(acl_buffer, lookup->data + i);
			while (ptr != NULL) {
				b = *(ptr - 1);
				if (((ptr[lookup->host_len - i] & 0x80) != 0 || ptr[lookup->host_len - i] == 0) && (b & 0x80) != 0) {
					lookup->acl_idx = (b & 0x1f);
					ret = ((b & 0x60) >> 5);
					lookup->acl_action = ret;
					ret = 1;
					goto __done;
				}
				if (ptr[lookup->host_len - i] == 0) {
					ptr = NULL;
					break;
				}
				ptr = strstr(ptr + lookup->host_len - i, lookup->data + i);
			}
			while (lookup->host_len >= i + 1 && lookup->data[i] != '.') {
				i++;
			}
			if (lookup->data[i] != '.') {
				break;
			}
			i++;
			if (lookup->host_len < i + 1) {
				break;
			}
		}
	}
__done:
	rcu_read_unlock();
	lookup->data[lookup->host_len] = backup_c;
	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
#define URLLOGGER_HOOK_CTX_ARGS const struct nf_hook_state *state
#define URLLOGGER_HOOK_CTX_PASS state
#else
#define URLLOGGER_HOOK_CTX_ARGS const struct net_device *in, const struct net_device *out
#define URLLOGGER_HOOK_CTX_PASS in, out
#endif

static noinline void urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_ARGS,
        struct sk_buff *skb, struct urlinfo *url, int l3num)
{
	const char *ipset_family = l3num == AF_INET6 ? "ipv6" : "ipv4";
	int rule_id = 0;
	char ipset_name[IPSET_MAXNAMELEN];

	do {
		int ret_ip;
		int ret_mac;

		for (; rule_id < acl_rule_max; ) {
			snprintf(ipset_name, sizeof(ipset_name), "host_acl_rule%u_%s", rule_id, ipset_family);
#if NATFLOW_HAVE_IP_SET_STATE_API
			ret_ip = IP_SET_test_src_ip(state, NULL, NULL, skb, ipset_name);
#else
			ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
#endif
			if (ret_ip > 0)
				break;

			snprintf(ipset_name, sizeof(ipset_name), "host_acl_rule%u_mac", rule_id);
#if NATFLOW_HAVE_IP_SET_STATE_API
			ret_mac = IP_SET_test_src_mac(state, NULL, NULL, skb, ipset_name);
#else
			ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
#endif
			if (ret_mac > 0)
				break;

			if (ret_ip == -EINVAL && ret_mac == -EINVAL)
				break;

			rule_id++;
		}
		if (rule_id < acl_rule_max) {
			if (urllogger_acl(url, rule_id) == 1)
				break;
		} else {
			break;
		}

		rule_id++;
	} while (1);
}

static noinline void urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_ARGS,
        struct sk_buff *skb, struct urllogger_acl_lookup *lookup, int l3num)
{
	const char *ipset_family = l3num == AF_INET6 ? "ipv6" : "ipv4";
	int rule_id = 0;
	char ipset_name[IPSET_MAXNAMELEN];

	do {
		int ret_ip;
		int ret_mac;

		for (; rule_id < acl_rule_max; ) {
			snprintf(ipset_name, sizeof(ipset_name), "host_acl_rule%u_%s", rule_id, ipset_family);
#if NATFLOW_HAVE_IP_SET_STATE_API
			ret_ip = IP_SET_test_src_ip(state, NULL, NULL, skb, ipset_name);
#else
			ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
#endif
			if (ret_ip > 0)
				break;

			snprintf(ipset_name, sizeof(ipset_name), "host_acl_rule%u_mac", rule_id);
#if NATFLOW_HAVE_IP_SET_STATE_API
			ret_mac = IP_SET_test_src_mac(state, NULL, NULL, skb, ipset_name);
#else
			ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
#endif
			if (ret_mac > 0)
				break;

			if (ret_ip == -EINVAL && ret_mac == -EINVAL)
				break;

			rule_id++;
		}
		if (rule_id < acl_rule_max) {
			if (urllogger_acl_lookup_rule(lookup, rule_id) == 1)
				break;
		} else {
			break;
		}

		rule_id++;
	} while (1);
}

static inline void natflow_urllogger_tcp_reply_rstack(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int pppoe_hdr)
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
		NATFLOW_ERROR("failed to allocate skb\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("failed to trim pskb: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	/* Set up MAC header. */
	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		/* neth->h_proto = htons(ETH_P_IP); */
	}
	/* Set up IP header. */
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
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
	/* Set up TCP header. */
	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->rst = 1;
	ntcph->psh = 0;
	ntcph->fin = 0;
	ntcph->window = 0;
	/* Checksum. */
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	/* Ready to send out. */
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

static inline void natflow_urllogger_tcp_reply_rstack6(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int pppoe_hdr)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct ipv6hdr *niph, *oiph;
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
	oiph = ipv6_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + sizeof(struct ipv6hdr));

	offset = pppoe_len + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATFLOW_ERROR("failed to allocate skb\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("failed to trim pskb: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	/* Set up MAC header. */
	neth = eth_hdr(nskb);
	niph = ipv6_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		/* neth->h_proto = htons(ETH_P_IPV6); */
	}
	/* Set up IP header. */
	memset(niph, 0, sizeof(struct ipv6hdr));
	niph->version = oiph->version;
	niph->priority = oiph->priority;
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.in6;
	niph->daddr = oiph->saddr;
	niph->flow_lbl[2] = niph->flow_lbl[1] = niph->flow_lbl[0] = 0;
	niph->payload_len = htons(sizeof(struct tcphdr));
	niph->nexthdr = IPPROTO_TCP;
	niph->hop_limit = 255;
	/* Set up TCP header. */
	ntcph = (struct tcphdr *)((char *)niph + sizeof(struct ipv6hdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->payload_len) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->rst = 1;
	ntcph->psh = 0;
	ntcph->fin = 0;
	ntcph->window = 0;
	/* Checksum. */
	len = ntohs(niph->payload_len);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v6_check(len, &niph->saddr, &niph->daddr, csum);
	/* Ready to send out. */
	skb_push(nskb, (char *)niph - (char *)neth - pppoe_len);
	if (pppoe_hdr) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(nskb) + ETH_HLEN);
		ph->length = htons(ntohs(ipv6_hdr(nskb)->payload_len) + sizeof(struct ipv6hdr) + 2);
	}
	nskb->dev = (struct net_device *)dev;
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	dev_queue_xmit(nskb);
out:
	if (pppoe_hdr) {
		oskb->protocol = __constant_htons(ETH_P_IPV6);
		skb_pull(oskb, PPPOE_SES_HLEN);
	}
}
static inline void natflow_urllogger_tcp_reply_302(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int pppoe_hdr)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct iphdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum;
	int offset, header_len;
	int pppoe_len = 0;
	struct acl_redirect_config *redirect;
	int redirect_payload_len;

	rcu_read_lock();
	redirect = rcu_dereference(acl_redirect_config);
	if (redirect->url[0] == 0) {
		rcu_read_unlock();
		natflow_urllogger_tcp_reply_rstack(dev, oskb, ct, pppoe_hdr);
		return;
	}
	redirect_payload_len = redirect->payload_len;

	if (pppoe_hdr) {
		pppoe_len = PPPOE_SES_HLEN;
		skb_push(oskb, PPPOE_SES_HLEN);
		oskb->protocol = __constant_htons(ETH_P_PPP_SES);
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ip_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + oiph->ihl*4);

	offset = pppoe_len + sizeof(struct iphdr) + sizeof(struct tcphdr) + redirect_payload_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATFLOW_ERROR("failed to allocate skb\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("failed to trim pskb: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	/* Set up MAC header. */
	neth = eth_hdr(nskb);
	niph = ip_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	}
	/* Set up IP header. */
	memset(niph, 0, sizeof(struct iphdr));
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
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
	/* Set up TCP header. */
	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct iphdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->tot_len) - (oiph->ihl<<2) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->rst = 0;
	ntcph->psh = 1;
	ntcph->fin = 1;
	ntcph->window = __constant_htons(14600);
	/* Payload */
	memcpy((char *)ntcph + sizeof(struct tcphdr), redirect->payload, redirect_payload_len);
	/* Checksum. */
	len = ntohs(niph->tot_len) - (niph->ihl<<2);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v4_check(len, niph->saddr, niph->daddr, csum);
	/* Ready to send out. */
	skb_push(nskb, (char *)niph - (char *)neth - pppoe_len);
	if (pppoe_hdr) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(nskb) + ETH_HLEN);
		ph->length = htons(ntohs(ip_hdr(nskb)->tot_len) + 2);
	}
	nskb->dev = (struct net_device *)dev;
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	dev_queue_xmit(nskb);
out:
	rcu_read_unlock();
	if (pppoe_hdr) {
		oskb->protocol = __constant_htons(ETH_P_IP);
		skb_pull(oskb, PPPOE_SES_HLEN);
	}
}
static inline void natflow_urllogger_tcp_reply_302_v6(const struct net_device *dev, struct sk_buff *oskb, struct nf_conn *ct, int pppoe_hdr)
{
	struct sk_buff *nskb;
	struct ethhdr *neth, *oeth;
	struct ipv6hdr *niph, *oiph;
	struct tcphdr *otcph, *ntcph;
	int len;
	unsigned int csum;
	int offset, header_len;
	int pppoe_len = 0;
	struct acl_redirect_config *redirect;
	int redirect_payload_len;

	rcu_read_lock();
	redirect = rcu_dereference(acl_redirect_config);
	if (redirect->url[0] == 0) {
		rcu_read_unlock();
		natflow_urllogger_tcp_reply_rstack6(dev, oskb, ct, pppoe_hdr);
		return;
	}
	redirect_payload_len = redirect->payload_len;

	if (pppoe_hdr) {
		pppoe_len = PPPOE_SES_HLEN;
		skb_push(oskb, PPPOE_SES_HLEN);
		oskb->protocol = __constant_htons(ETH_P_PPP_SES);
	}

	oeth = (struct ethhdr *)skb_mac_header(oskb);
	oiph = ipv6_hdr(oskb);
	otcph = (struct tcphdr *)((void *)oiph + sizeof(struct ipv6hdr));

	offset = pppoe_len + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + redirect_payload_len - oskb->len;
	header_len = offset < 0 ? 0 : offset;
	nskb = skb_copy_expand(oskb, skb_headroom(oskb), header_len, GFP_ATOMIC);
	if (!nskb) {
		NATFLOW_ERROR("failed to allocate skb\n");
		goto out;
	}
	if (offset <= 0) {
		if (pskb_trim(nskb, nskb->len + offset)) {
			NATFLOW_ERROR("failed to trim pskb: len=%d, offset=%d\n", nskb->len, offset);
			consume_skb(nskb);
			goto out;
		}
	} else {
		nskb->len += offset;
		nskb->tail += offset;
	}

	/* Set up MAC header. */
	neth = eth_hdr(nskb);
	niph = ipv6_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
	}
	/* Set up IPv6 header. */
	memset(niph, 0, sizeof(struct ipv6hdr));
	niph->version = oiph->version;
	niph->priority = oiph->priority;
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.in6;
	niph->daddr = oiph->saddr;
	niph->flow_lbl[2] = niph->flow_lbl[1] = niph->flow_lbl[0] = 0;
	niph->payload_len = htons(sizeof(struct tcphdr) + redirect_payload_len);
	niph->nexthdr = IPPROTO_TCP;
	niph->hop_limit = 255;
	/* Set up TCP header. */
	ntcph = (struct tcphdr *)((char *)niph + sizeof(struct ipv6hdr));
	memset(ntcph, 0, sizeof(struct tcphdr));
	ntcph->source = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
	ntcph->dest = otcph->source;
	ntcph->seq = otcph->ack_seq;
	ntcph->ack_seq = htonl(ntohl(otcph->seq) + ntohs(oiph->payload_len) - (otcph->doff<<2));
	ntcph->doff = 5;
	ntcph->ack = 1;
	ntcph->rst = 0;
	ntcph->psh = 1;
	ntcph->fin = 1;
	ntcph->window = __constant_htons(14600);
	/* Payload */
	memcpy((char *)ntcph + sizeof(struct tcphdr), redirect->payload, redirect_payload_len);
	/* Checksum. */
	len = ntohs(niph->payload_len);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v6_check(len, &niph->saddr, &niph->daddr, csum);
	/* Ready to send out. */
	skb_push(nskb, (char *)niph - (char *)neth - pppoe_len);
	if (pppoe_hdr) {
		struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(nskb) + ETH_HLEN);
		ph->length = htons(ntohs(ipv6_hdr(nskb)->payload_len) + sizeof(struct ipv6hdr) + 2);
	}
	nskb->dev = (struct net_device *)dev;
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	dev_queue_xmit(nskb);
out:
	rcu_read_unlock();
	if (pppoe_hdr) {
		oskb->protocol = __constant_htons(ETH_P_IPV6);
		skb_pull(oskb, PPPOE_SES_HLEN);
	}
}


struct urllogger_sni_cache_node {
	unsigned long active_jiffies;
	union {
		__be32 src_ip;
		struct in6_addr src_ipv6;
	};
	union {
		__be32 dst_ip;
		struct in6_addr dst_ipv6;
	};
	__be16 src_port;
	__be16 dst_port;
	__u32 seq;
	unsigned int data_len;
	unsigned char *data;
};

#define URLLOGGER_CACHE_TIMEOUT 4
#define MAX_URLLOGGER_SNI_CACHE_NODE 64
#define URLLOGGER_SNI_CACHE_DATA_LIMIT (32 * 1024)
static struct urllogger_sni_cache_node (*urllogger_sni_cache)[MAX_URLLOGGER_SNI_CACHE_NODE];
static unsigned int urllogger_sni_cache_cpu_num;

static inline int urllogger_sni_cache_init(void)
{
	urllogger_sni_cache_cpu_num = nr_cpu_ids;
	urllogger_sni_cache = kcalloc(urllogger_sni_cache_cpu_num, sizeof(*urllogger_sni_cache), GFP_KERNEL);
	if (urllogger_sni_cache == NULL)
		return -ENOMEM;

	return 0;
}

static inline void urllogger_sni_cache_cleanup(void)
{
	int i, j;
	if (urllogger_sni_cache == NULL)
		return;

	for (i = 0; i < urllogger_sni_cache_cpu_num; i++) {
		for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
			if (urllogger_sni_cache[i][j].data != NULL) {
				kfree(urllogger_sni_cache[i][j].data);
				urllogger_sni_cache[i][j].data = NULL;
			}
		}
	}

	kfree(urllogger_sni_cache);
	urllogger_sni_cache = NULL;
	urllogger_sni_cache_cpu_num = 0;
}

static inline int urllogger_sni_cache_attach(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u32 seq, unsigned char *data, unsigned int data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;
	if (urllogger_sni_cache == NULL || i >= urllogger_sni_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].data != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				kfree(urllogger_sni_cache[i][j].data);
				urllogger_sni_cache[i][j].data = NULL;
			} else if (urllogger_sni_cache[i][j].src_ip == src_ip &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           urllogger_sni_cache[i][j].dst_ip == dst_ip &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				return -EEXIST;
			}
		}

		if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_sni_cache[i][j].data == NULL) {
			next_to_use = j;
		}
	}
	if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE) {
		return -ENOMEM;
	}

	urllogger_sni_cache[i][next_to_use].src_ip = src_ip;
	urllogger_sni_cache[i][next_to_use].src_port = src_port;
	urllogger_sni_cache[i][next_to_use].dst_ip = dst_ip;
	urllogger_sni_cache[i][next_to_use].dst_port = dst_port;
	urllogger_sni_cache[i][next_to_use].seq = seq;
	urllogger_sni_cache[i][next_to_use].data_len = data_len;
	urllogger_sni_cache[i][next_to_use].data = data;
	urllogger_sni_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

static inline int urllogger_sni_cache_attach6(struct in6_addr *src_ip, __be16 src_port, struct in6_addr *dst_ip, __be16 dst_port, __u32 seq, unsigned char *data, unsigned int data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;
	if (urllogger_sni_cache == NULL || i >= urllogger_sni_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].data != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				kfree(urllogger_sni_cache[i][j].data);
				urllogger_sni_cache[i][j].data = NULL;
			} else if (memcmp(&urllogger_sni_cache[i][j].src_ipv6, src_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           memcmp(&urllogger_sni_cache[i][j].dst_ipv6, dst_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				return -EEXIST;
			}
		}

		if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_sni_cache[i][j].data == NULL) {
			next_to_use = j;
		}
	}
	if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE) {
		return -ENOMEM;
	}

	memcpy(&urllogger_sni_cache[i][next_to_use].src_ipv6, src_ip, 16);
	urllogger_sni_cache[i][next_to_use].src_port = src_port;
	memcpy(&urllogger_sni_cache[i][next_to_use].dst_ipv6, dst_ip, 16);
	urllogger_sni_cache[i][next_to_use].dst_port = dst_port;
	urllogger_sni_cache[i][next_to_use].seq = seq;
	urllogger_sni_cache[i][next_to_use].data_len = data_len;
	urllogger_sni_cache[i][next_to_use].data = data;
	urllogger_sni_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

static inline unsigned char *urllogger_sni_cache_detach(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, __u32 *seq, unsigned int *data_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *data = NULL;

	if (urllogger_sni_cache == NULL || i >= urllogger_sni_cache_cpu_num)
		return NULL;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].data != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				kfree(urllogger_sni_cache[i][j].data);
				urllogger_sni_cache[i][j].data = NULL;
			} else if (urllogger_sni_cache[i][j].src_ip == src_ip &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           urllogger_sni_cache[i][j].dst_ip == dst_ip &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				/* XXX: actually dst_ip and dst_port could be not matching on reply-path */
				/* but we are only support origin-path right now, so check dst match also */
				data = urllogger_sni_cache[i][j].data;
				*seq = urllogger_sni_cache[i][j].seq;
				*data_len = urllogger_sni_cache[i][j].data_len;
				urllogger_sni_cache[i][j].data = NULL;
			}
		}
	}

	return data;
}

static inline unsigned char *urllogger_sni_cache_detach6(struct in6_addr *src_ip, __be16 src_port, struct in6_addr *dst_ip, __be16 dst_port, __u32 *seq, unsigned int *data_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *data = NULL;

	if (urllogger_sni_cache == NULL || i >= urllogger_sni_cache_cpu_num)
		return NULL;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].data != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				kfree(urllogger_sni_cache[i][j].data);
				urllogger_sni_cache[i][j].data = NULL;
			} else if (memcmp(&urllogger_sni_cache[i][j].src_ipv6, src_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           memcmp(&urllogger_sni_cache[i][j].dst_ipv6, dst_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				/* XXX: actually dst_ipv6 and dst_port could be not matching on reply-path */
				/* but we are only support origin-path right now, so check dst match also */
				data = urllogger_sni_cache[i][j].data;
				*seq = urllogger_sni_cache[i][j].seq;
				*data_len = urllogger_sni_cache[i][j].data_len;
				urllogger_sni_cache[i][j].data = NULL;
			}
		}
	}

	return data;
}

#define QUIC_MAX_CID_LEN NATFLOW_L7_QUIC_MAX_CID_LEN
#define QUIC_INITIAL_SECRET_LEN 32
#define QUIC_INITIAL_KEY_LEN 16
#define QUIC_INITIAL_IV_LEN 12
#define QUIC_INITIAL_TAG_LEN 16
#define QUIC_HP_SAMPLE_LEN 16
#define QUIC_MAX_PACKET_NUMBER_LEN 4
#define QUIC_INITIAL_SCRATCH_PACKET_LEN 2048

static const unsigned char quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

struct urllogger_quic_crypto_ctx {
	struct crypto_shash *hmac;
	struct crypto_skcipher *hp;
	struct skcipher_request *hp_req;
	struct crypto_aead *aead;
	struct aead_request *aead_req;
	unsigned char key[QUIC_INITIAL_KEY_LEN];
	unsigned char iv[QUIC_INITIAL_IV_LEN];
	unsigned char hp_key[QUIC_INITIAL_KEY_LEN];
	unsigned char mask[QUIC_HP_SAMPLE_LEN];
	unsigned char nonce[QUIC_INITIAL_IV_LEN];
	unsigned char hkdf_input[128];
	unsigned char hkdf_digest[QUIC_INITIAL_SECRET_LEN];
	unsigned char hkdf_info[80];
	unsigned char initial_secret[QUIC_INITIAL_SECRET_LEN];
	unsigned char client_secret[QUIC_INITIAL_SECRET_LEN];
	unsigned char scratch_packet[QUIC_INITIAL_SCRATCH_PACKET_LEN];
	char desc_buf[sizeof(struct shash_desc) + HASH_MAX_DESCSIZE] __aligned(__alignof__(struct shash_desc));
};

struct urllogger_quic_cache_node {
	unsigned long active_jiffies;
	union {
		__be32 src_ip;
		struct in6_addr src_ipv6;
	};
	union {
		__be32 dst_ip;
		struct in6_addr dst_ipv6;
	};
	__be16 src_port;
	__be16 dst_port;
	unsigned int version;
	unsigned int dcid_len;
	unsigned char dcid[QUIC_MAX_CID_LEN];
	unsigned int crypto_len;
	unsigned char *crypto_data;
};

static struct urllogger_quic_crypto_ctx *urllogger_quic_crypto_ctx;
static unsigned int urllogger_quic_crypto_cpu_num;
static int urllogger_quic_crypto_ready;
static struct urllogger_quic_cache_node (*urllogger_quic_cache)[MAX_URLLOGGER_SNI_CACHE_NODE];
static unsigned int urllogger_quic_cache_cpu_num;

static int quic_hmac_sha256(struct urllogger_quic_crypto_ctx *ctx,
                            const unsigned char *key, unsigned int key_len,
                            const unsigned char *data, unsigned int data_len,
                            unsigned char *out)
{
	struct shash_desc *desc = (struct shash_desc *)ctx->desc_buf;
	int ret;

	ret = crypto_shash_setkey(ctx->hmac, key, key_len);
	if (ret != 0)
		return ret;

	desc->tfm = ctx->hmac;
	ret = crypto_shash_digest(desc, data, data_len, out);

	shash_desc_zero(desc);
	return ret;
}

static int quic_hkdf_expand(struct urllogger_quic_crypto_ctx *ctx,
                            const unsigned char *secret, unsigned int secret_len,
                            const unsigned char *info, unsigned int info_len,
                            unsigned char *out, unsigned int out_len)
{
	unsigned char *input = ctx->hkdf_input;
	unsigned char *digest = ctx->hkdf_digest;
	int ret;

	if (out_len > QUIC_INITIAL_SECRET_LEN || info_len + 1 > sizeof(ctx->hkdf_input))
		return -EINVAL;

	memcpy(input, info, info_len);
	input[info_len] = 1;
	ret = quic_hmac_sha256(ctx, secret, secret_len, input, info_len + 1, digest);
	if (ret == 0)
		memcpy(out, digest, out_len);

	memzero_explicit(input, sizeof(ctx->hkdf_input));
	memzero_explicit(digest, sizeof(ctx->hkdf_digest));
	return ret;
}

static int quic_hkdf_expand_label(struct urllogger_quic_crypto_ctx *ctx,
                                  const unsigned char *secret, unsigned int secret_len,
                                  const char *label,
                                  unsigned char *out, unsigned int out_len)
{
	unsigned char *info = ctx->hkdf_info;
	unsigned int label_len = strlen(label);
	unsigned int full_label_len = strlen("tls13 ") + label_len;
	int ret;

	if (full_label_len > 255 || 4 + full_label_len > sizeof(ctx->hkdf_info))
		return -EINVAL;

	info[0] = (out_len >> 8) & 0xff;
	info[1] = out_len & 0xff;
	info[2] = full_label_len;
	memcpy(info + 3, "tls13 ", strlen("tls13 "));
	memcpy(info + 3 + strlen("tls13 "), label, label_len);
	info[3 + full_label_len] = 0;

	ret = quic_hkdf_expand(ctx, secret, secret_len, info, 4 + full_label_len, out, out_len);
	memzero_explicit(info, sizeof(ctx->hkdf_info));
	return ret;
}

static int quic_initial_keys(struct urllogger_quic_crypto_ctx *ctx,
                             const unsigned char *dcid, unsigned int dcid_len,
                             unsigned char *key, unsigned char *iv, unsigned char *hp)
{
	unsigned char *initial_secret = ctx->initial_secret;
	unsigned char *client_secret = ctx->client_secret;
	int ret;

	ret = quic_hmac_sha256(ctx, quic_v1_initial_salt, sizeof(quic_v1_initial_salt),
	                       dcid, dcid_len, initial_secret);
	if (ret != 0)
		goto out;

	ret = quic_hkdf_expand_label(ctx, initial_secret, QUIC_INITIAL_SECRET_LEN,
	                             "client in", client_secret, QUIC_INITIAL_SECRET_LEN);
	if (ret != 0)
		goto out;

	ret = quic_hkdf_expand_label(ctx, client_secret, QUIC_INITIAL_SECRET_LEN,
	                             "quic key", key, QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		goto out;

	ret = quic_hkdf_expand_label(ctx, client_secret, QUIC_INITIAL_SECRET_LEN,
	                             "quic iv", iv, QUIC_INITIAL_IV_LEN);
	if (ret != 0)
		goto out;

	ret = quic_hkdf_expand_label(ctx, client_secret, QUIC_INITIAL_SECRET_LEN,
	                             "quic hp", hp, QUIC_INITIAL_KEY_LEN);

out:
	memzero_explicit(initial_secret, sizeof(ctx->initial_secret));
	memzero_explicit(client_secret, sizeof(ctx->client_secret));
	return ret;
}

static int quic_header_protection_mask(struct urllogger_quic_crypto_ctx *ctx,
                                       const unsigned char *hp_key,
                                       const unsigned char *sample,
                                       unsigned char *mask)
{
	struct skcipher_request *req = ctx->hp_req;
	struct scatterlist src;
	struct scatterlist dst;
	int ret;

	ret = crypto_skcipher_setkey(ctx->hp, hp_key, QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		return ret;

	sg_init_one(&src, sample, QUIC_HP_SAMPLE_LEN);
	sg_init_one(&dst, mask, QUIC_HP_SAMPLE_LEN);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, &src, &dst, QUIC_HP_SAMPLE_LEN, NULL);
	ret = crypto_skcipher_encrypt(req);
	return ret;
}

static int quic_initial_decrypt(struct urllogger_quic_crypto_ctx *ctx,
                                const unsigned char *key,
                                const unsigned char *iv,
                                unsigned char *packet,
                                unsigned int packet_len,
                                unsigned int header_len,
                                u64 packet_number,
                                unsigned char **payload,
                                unsigned int *payload_len)
{
	struct aead_request *req = ctx->aead_req;
	struct scatterlist sg;
	unsigned int crypt_len;
	int i;
	int ret;

	if (header_len >= packet_len)
		return -EINVAL;

	crypt_len = packet_len - header_len;
	if (crypt_len < QUIC_INITIAL_TAG_LEN)
		return -EINVAL;

	memcpy(ctx->nonce, iv, sizeof(ctx->nonce));
	for (i = 0; i < 8; i++)
		ctx->nonce[sizeof(ctx->nonce) - 1 - i] ^= (packet_number >> (i * 8)) & 0xff;

	ret = crypto_aead_setauthsize(ctx->aead, QUIC_INITIAL_TAG_LEN);
	if (ret != 0)
		goto out;
	ret = crypto_aead_setkey(ctx->aead, key, QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		goto out;

	sg_init_one(&sg, packet, packet_len);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, header_len);
	aead_request_set_crypt(req, &sg, &sg, crypt_len, ctx->nonce);
	ret = crypto_aead_decrypt(req);
	if (ret == 0) {
		*payload = packet + header_len;
		*payload_len = crypt_len - QUIC_INITIAL_TAG_LEN;
	}

out:
	return ret;
}

static enum natflow_l7_tls_search_result quic_initial_sni_search(const unsigned char *data,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len)
{
	struct urllogger_quic_crypto_ctx *ctx;
	unsigned char *packet;
	unsigned char *payload = NULL;
	unsigned int payload_len = 0;
	unsigned int pn_len;
	unsigned int header_len;
	u64 packet_number = 0;
	int cpu = smp_processor_id();
	int i;
	int ret;

	*host = NULL;

	if (!urllogger_quic_crypto_ready ||
	        urllogger_quic_crypto_ctx == NULL ||
	        cpu >= urllogger_quic_crypto_cpu_num)
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;

	ctx = &urllogger_quic_crypto_ctx[cpu];

	/* Fits regular MTU-sized skb UDP payloads; larger Initial packets are not parsed. */
	if (info->packet_len > sizeof(ctx->scratch_packet)) {
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	}

	packet = ctx->scratch_packet;
	memcpy(packet, data, info->packet_len);

	ret = quic_initial_keys(ctx, info->dcid, info->dcid_len, ctx->key, ctx->iv, ctx->hp_key);
	if (ret != 0)
		goto malformed;

	ret = quic_header_protection_mask(ctx, ctx->hp_key, packet + info->pn_offset + QUIC_MAX_PACKET_NUMBER_LEN, ctx->mask);
	if (ret != 0)
		goto malformed;

	packet[0] ^= ctx->mask[0] & 0x0f;
	pn_len = (packet[0] & 0x03) + 1;
	if (!natflow_l7_quic_has_bytes(info->pn_offset, pn_len, info->packet_len))
		goto malformed;

	for (i = 0; i < pn_len; i++) {
		packet[info->pn_offset + i] ^= ctx->mask[i + 1];
		packet_number = (packet_number << 8) | packet[info->pn_offset + i];
	}

	header_len = info->pn_offset + pn_len;
	ret = quic_initial_decrypt(ctx, ctx->key, ctx->iv, packet, info->packet_len,
	                           header_len, packet_number, &payload, &payload_len);
	if (ret != 0)
		goto malformed;

	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	memzero_explicit(ctx->hp_key, sizeof(ctx->hp_key));
	memzero_explicit(ctx->mask, sizeof(ctx->mask));
	memzero_explicit(ctx->nonce, sizeof(ctx->nonce));

	ret = natflow_l7_quic_crypto_frames_search(payload, payload_len, crypto_data, crypto_len, host, host_len);
	return ret;

malformed:
	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	memzero_explicit(ctx->hp_key, sizeof(ctx->hp_key));
	memzero_explicit(ctx->mask, sizeof(ctx->mask));
	memzero_explicit(ctx->nonce, sizeof(ctx->nonce));
	return NATFLOW_L7_TLS_SEARCH_MALFORMED;
}

static inline int urllogger_quic_cache_init(void)
{
	urllogger_quic_cache_cpu_num = nr_cpu_ids;
	urllogger_quic_cache = kcalloc(urllogger_quic_cache_cpu_num, sizeof(*urllogger_quic_cache), GFP_KERNEL);
	if (urllogger_quic_cache == NULL)
		return -ENOMEM;

	return 0;
}

static inline void urllogger_quic_cache_cleanup(void)
{
	int i, j;

	if (urllogger_quic_cache == NULL)
		return;

	for (i = 0; i < urllogger_quic_cache_cpu_num; i++) {
		for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
			kfree(urllogger_quic_cache[i][j].crypto_data);
			urllogger_quic_cache[i][j].crypto_data = NULL;
		}
	}

	kfree(urllogger_quic_cache);
	urllogger_quic_cache = NULL;
	urllogger_quic_cache_cpu_num = 0;
}

static inline int urllogger_quic_cache_match(const struct urllogger_quic_cache_node *node,
        __be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info)
{
	return node->crypto_data != NULL &&
	       node->src_ip == src_ip &&
	       node->src_port == src_port &&
	       node->dst_ip == dst_ip &&
	       node->dst_port == dst_port &&
	       node->version == info->version &&
	       node->dcid_len == info->dcid_len &&
	       memcmp(node->dcid, info->dcid, info->dcid_len) == 0;
}

static inline int urllogger_quic_cache_match6(const struct urllogger_quic_cache_node *node,
        const struct in6_addr *src_ip, __be16 src_port,
        const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info)
{
	return node->crypto_data != NULL &&
	       memcmp(&node->src_ipv6, src_ip, 16) == 0 &&
	       node->src_port == src_port &&
	       memcmp(&node->dst_ipv6, dst_ip, 16) == 0 &&
	       node->dst_port == dst_port &&
	       node->version == info->version &&
	       node->dcid_len == info->dcid_len &&
	       memcmp(node->dcid, info->dcid, info->dcid_len) == 0;
}

static inline int urllogger_quic_cache_attach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char *crypto_data,
        unsigned int crypto_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;

	if (crypto_data == NULL || crypto_len == 0)
		return -EINVAL;
	if (urllogger_quic_cache == NULL || i >= urllogger_quic_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies, urllogger_quic_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
			kfree(urllogger_quic_cache[i][j].crypto_data);
			urllogger_quic_cache[i][j].crypto_data = NULL;
		}
		if (urllogger_quic_cache_match(&urllogger_quic_cache[i][j], src_ip, src_port, dst_ip, dst_port, info))
			return -EEXIST;
		if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_quic_cache[i][j].crypto_data == NULL)
			next_to_use = j;
	}
	if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE)
		return -ENOMEM;

	urllogger_quic_cache[i][next_to_use].src_ip = src_ip;
	urllogger_quic_cache[i][next_to_use].src_port = src_port;
	urllogger_quic_cache[i][next_to_use].dst_ip = dst_ip;
	urllogger_quic_cache[i][next_to_use].dst_port = dst_port;
	urllogger_quic_cache[i][next_to_use].version = info->version;
	urllogger_quic_cache[i][next_to_use].dcid_len = info->dcid_len;
	memcpy(urllogger_quic_cache[i][next_to_use].dcid, info->dcid, info->dcid_len);
	urllogger_quic_cache[i][next_to_use].crypto_len = crypto_len;
	urllogger_quic_cache[i][next_to_use].crypto_data = crypto_data;
	urllogger_quic_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;
	return 0;
}

static inline int urllogger_quic_cache_attach6(const struct in6_addr *src_ip, __be16 src_port,
        const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char *crypto_data,
        unsigned int crypto_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;

	if (crypto_data == NULL || crypto_len == 0)
		return -EINVAL;
	if (urllogger_quic_cache == NULL || i >= urllogger_quic_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies, urllogger_quic_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
			kfree(urllogger_quic_cache[i][j].crypto_data);
			urllogger_quic_cache[i][j].crypto_data = NULL;
		}
		if (urllogger_quic_cache_match6(&urllogger_quic_cache[i][j], src_ip, src_port, dst_ip, dst_port, info))
			return -EEXIST;
		if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_quic_cache[i][j].crypto_data == NULL)
			next_to_use = j;
	}
	if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE)
		return -ENOMEM;

	memcpy(&urllogger_quic_cache[i][next_to_use].src_ipv6, src_ip, 16);
	urllogger_quic_cache[i][next_to_use].src_port = src_port;
	memcpy(&urllogger_quic_cache[i][next_to_use].dst_ipv6, dst_ip, 16);
	urllogger_quic_cache[i][next_to_use].dst_port = dst_port;
	urllogger_quic_cache[i][next_to_use].version = info->version;
	urllogger_quic_cache[i][next_to_use].dcid_len = info->dcid_len;
	memcpy(urllogger_quic_cache[i][next_to_use].dcid, info->dcid, info->dcid_len);
	urllogger_quic_cache[i][next_to_use].crypto_len = crypto_len;
	urllogger_quic_cache[i][next_to_use].crypto_data = crypto_data;
	urllogger_quic_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;
	return 0;
}

static inline unsigned char *urllogger_quic_cache_detach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *crypto_data = NULL;

	if (urllogger_quic_cache == NULL || i >= urllogger_quic_cache_cpu_num)
		return NULL;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies, urllogger_quic_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
			kfree(urllogger_quic_cache[i][j].crypto_data);
			urllogger_quic_cache[i][j].crypto_data = NULL;
		} else if (urllogger_quic_cache_match(&urllogger_quic_cache[i][j], src_ip, src_port, dst_ip, dst_port, info)) {
			crypto_data = urllogger_quic_cache[i][j].crypto_data;
			*crypto_len = urllogger_quic_cache[i][j].crypto_len;
			urllogger_quic_cache[i][j].crypto_data = NULL;
			break;
		}
	}

	return crypto_data;
}

static inline unsigned char *urllogger_quic_cache_detach6(const struct in6_addr *src_ip, __be16 src_port,
        const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *crypto_data = NULL;

	if (urllogger_quic_cache == NULL || i >= urllogger_quic_cache_cpu_num)
		return NULL;

	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies, urllogger_quic_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
			kfree(urllogger_quic_cache[i][j].crypto_data);
			urllogger_quic_cache[i][j].crypto_data = NULL;
		} else if (urllogger_quic_cache_match6(&urllogger_quic_cache[i][j], src_ip, src_port, dst_ip, dst_port, info)) {
			crypto_data = urllogger_quic_cache[i][j].crypto_data;
			*crypto_len = urllogger_quic_cache[i][j].crypto_len;
			urllogger_quic_cache[i][j].crypto_data = NULL;
			break;
		}
	}

	return crypto_data;
}

static noinline unsigned int urllogger_quic4(URLLOGGER_HOOK_CTX_ARGS,
        struct sk_buff *skb, struct nf_conn *ct, unsigned int consumer_mask)
{
	struct natflow_l7_quic_initial_info quic_info;
	enum natflow_l7_tls_search_result sni_result;
	unsigned char *host = NULL;
	unsigned char *crypto_data = NULL;
	natflow_t *nf = NULL;
	struct iphdr *iph;
	void *l4;
	unsigned int crypto_len = 0;
	unsigned int udp_len;
	int host_len = 0;
	int data_len;
	int quic_ret;
	unsigned char *data;
	int url_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_URL) != 0;
	int dpi_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_DPI) != 0;
	unsigned int ret = NF_ACCEPT;

	if (skb_try_make_writable(skb, ip_hdr(skb)->ihl * 4 + sizeof(struct udphdr)))
		return ret;
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	if (UDPH(l4)->dest != __constant_htons(443))
		return ret;

	udp_len = ntohs(UDPH(l4)->len);
	if (udp_len <= sizeof(struct udphdr))
		goto skip;

	data_len = udp_len - sizeof(struct udphdr);
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + data_len))
		return ret;

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	data = skb->data + iph->ihl * 4 + sizeof(struct udphdr);

	quic_ret = natflow_l7_quic_initial_parse_info(data, data_len, &quic_info);
	if (quic_ret != 0)
		goto skip;

	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	crypto_data = urllogger_quic_cache_detach(iph->saddr, UDPH(l4)->source,
	              iph->daddr, UDPH(l4)->dest, &quic_info, &crypto_len);
	sni_result = quic_initial_sni_search(data, &quic_info,
	                                     &crypto_data, &crypto_len,
	                                     &host, &host_len);
	if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
		if (crypto_data != NULL && crypto_len > 0 &&
		        urllogger_quic_cache_attach(iph->saddr, UDPH(l4)->source,
		                                    iph->daddr, UDPH(l4)->dest,
		                                    &quic_info, crypto_data, crypto_len) == 0) {
			crypto_data = NULL;
			goto done;
		}
		kfree(crypto_data);
		crypto_data = NULL;
	}

skip:
	set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
	if (nf && (nf->status & NF_FF_L7_USE))
		simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

	if (host) {
		struct urlinfo *url;

		if (!url_consumer) {
			if (dpi_consumer)
				urllogger_dpi_classify_raw_host(ct, host, host_len,
				                                NATFLOW_DPI_EVENT_SOURCE_QUIC);
			goto done;
		}

		url = urlinfo_alloc_record(host, host_len, 0, NULL, 0);
		if (!url) {
			struct urllogger_acl_lookup acl;

			if (urllogger_acl_lookup_init(&acl, host, host_len, 0) == 0) {
				if (dpi_consumer)
					urllogger_dpi_classify_lookup(ct, &acl,
					                              NATFLOW_DPI_EVENT_SOURCE_QUIC);
				urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET);
				if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
					set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
					ret = NF_DROP;
					if (nf && !(nf->status & NF_FF_USER_USE))
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
				}
			}
			goto done;
		}

		if (urllogger_store_tuple_type == 0) {
			url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			url->dip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
			url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
		} else if (urllogger_store_tuple_type == 1) {
			url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
			url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
			url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
		} else {
			url->sip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
			url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
			url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
		}
		url->timestamp = URLINFO_NOW;
		url->flags = URLINFO_QUIC;
		url->http_method = 0;
		url->hits = 1;
		memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

		url->acl_idx = 64;
		url->acl_action = acl_action_default;
		if (dpi_consumer)
			urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_QUIC);
		urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET);
		if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
			set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
			ret = NF_DROP;
			if (nf && !(nf->status & NF_FF_USER_USE))
				simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
		}

		urllogger_store_record(url);
	}

done:
	kfree(crypto_data);
	return ret;
}

static noinline unsigned int urllogger_quic6(URLLOGGER_HOOK_CTX_ARGS,
        struct sk_buff *skb, struct nf_conn *ct, unsigned int consumer_mask)
{
	struct natflow_l7_quic_initial_info quic_info;
	enum natflow_l7_tls_search_result sni_result;
	unsigned char *host = NULL;
	unsigned char *crypto_data = NULL;
	natflow_t *nf = NULL;
	struct ipv6hdr *ip6h;
	void *l4;
	unsigned int crypto_len = 0;
	unsigned int udp_len;
	int host_len = 0;
	int data_len;
	int quic_ret;
	unsigned char *data;
	int url_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_URL) != 0;
	int dpi_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_DPI) != 0;
	unsigned int ret = NF_ACCEPT;

	if (skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
		return ret;
	ip6h = ipv6_hdr(skb);
	l4 = (void *)ip6h + sizeof(struct ipv6hdr);
	if (UDPH(l4)->dest != __constant_htons(443))
		return ret;

	udp_len = ntohs(UDPH(l4)->len);
	if (udp_len <= sizeof(struct udphdr))
		goto skip;

	data_len = udp_len - sizeof(struct udphdr);
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr) + data_len))
		return ret;

	ip6h = ipv6_hdr(skb);
	l4 = (void *)ip6h + sizeof(struct ipv6hdr);
	data = skb->data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);

	quic_ret = natflow_l7_quic_initial_parse_info(data, data_len, &quic_info);
	if (quic_ret != 0)
		goto skip;

	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	crypto_data = urllogger_quic_cache_detach6(&ip6h->saddr, UDPH(l4)->source,
	              &ip6h->daddr, UDPH(l4)->dest, &quic_info, &crypto_len);
	sni_result = quic_initial_sni_search(data, &quic_info,
	                                     &crypto_data, &crypto_len,
	                                     &host, &host_len);
	if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
		if (crypto_data != NULL && crypto_len > 0 &&
		        urllogger_quic_cache_attach6(&ip6h->saddr, UDPH(l4)->source,
		                                     &ip6h->daddr, UDPH(l4)->dest,
		                                     &quic_info, crypto_data, crypto_len) == 0) {
			crypto_data = NULL;
			goto done;
		}
		kfree(crypto_data);
		crypto_data = NULL;
	}

skip:
	set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
	if (nf && (nf->status & NF_FF_L7_USE))
		simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

	if (host) {
		struct urlinfo *url;

		if (!url_consumer) {
			if (dpi_consumer)
				urllogger_dpi_classify_raw_host(ct, host, host_len,
				                                NATFLOW_DPI_EVENT_SOURCE_QUIC);
			goto done;
		}

		url = urlinfo_alloc_record(host, host_len, 0, NULL, 0);
		if (!url) {
			struct urllogger_acl_lookup acl;

			if (urllogger_acl_lookup_init(&acl, host, host_len, 0) == 0) {
				if (dpi_consumer)
					urllogger_dpi_classify_lookup(ct, &acl,
					                              NATFLOW_DPI_EVENT_SOURCE_QUIC);
				urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET6);
				if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
					set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
					ret = NF_DROP;
					if (nf && !(nf->status & NF_FF_USER_USE))
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
				}
			}
			goto done;
		}

		if (urllogger_store_tuple_type == 0) {
			url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
			url->dipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
			url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
		} else if (urllogger_store_tuple_type == 1) {
			url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
			url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
			url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
		} else {
			url->sipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3;
			url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
			url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
			url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
		}
		url->timestamp = URLINFO_NOW;
		url->flags = URLINFO_QUIC;
		url->flags |= URLINFO_IPV6;
		url->http_method = 0;
		url->hits = 1;
		memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

		url->acl_idx = 64;
		url->acl_action = acl_action_default;
		if (dpi_consumer)
			urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_QUIC);
		urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET6);
		if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
			set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
			ret = NF_DROP;
			if (nf && !(nf->status & NF_FF_USER_USE))
				simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
		}

		urllogger_store_record(url);
	}

done:
	kfree(crypto_data);
	return ret;
}

static int urllogger_quic_crypto_init(void)
{
	int i;
	int ret = 0;

	urllogger_quic_crypto_cpu_num = nr_cpu_ids;
	urllogger_quic_crypto_ctx = kcalloc(urllogger_quic_crypto_cpu_num, sizeof(*urllogger_quic_crypto_ctx), GFP_KERNEL);
	if (urllogger_quic_crypto_ctx == NULL)
		return -ENOMEM;

	for (i = 0; i < urllogger_quic_crypto_cpu_num; i++) {
		urllogger_quic_crypto_ctx[i].hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
		if (IS_ERR(urllogger_quic_crypto_ctx[i].hmac)) {
			ret = PTR_ERR(urllogger_quic_crypto_ctx[i].hmac);
			urllogger_quic_crypto_ctx[i].hmac = NULL;
			goto failed;
		}

		urllogger_quic_crypto_ctx[i].hp = crypto_alloc_skcipher("ecb(aes)", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(urllogger_quic_crypto_ctx[i].hp)) {
			ret = PTR_ERR(urllogger_quic_crypto_ctx[i].hp);
			urllogger_quic_crypto_ctx[i].hp = NULL;
			goto failed;
		}

		urllogger_quic_crypto_ctx[i].hp_req = skcipher_request_alloc(urllogger_quic_crypto_ctx[i].hp, GFP_KERNEL);
		if (urllogger_quic_crypto_ctx[i].hp_req == NULL) {
			ret = -ENOMEM;
			goto failed;
		}

		urllogger_quic_crypto_ctx[i].aead = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(urllogger_quic_crypto_ctx[i].aead)) {
			ret = PTR_ERR(urllogger_quic_crypto_ctx[i].aead);
			urllogger_quic_crypto_ctx[i].aead = NULL;
			goto failed;
		}

		urllogger_quic_crypto_ctx[i].aead_req = aead_request_alloc(urllogger_quic_crypto_ctx[i].aead, GFP_KERNEL);
		if (urllogger_quic_crypto_ctx[i].aead_req == NULL) {
			ret = -ENOMEM;
			goto failed;
		}
	}

	urllogger_quic_crypto_ready = 1;
	return 0;

failed:
	urllogger_quic_crypto_ready = 0;
	for (i = 0; i < urllogger_quic_crypto_cpu_num; i++) {
		if (urllogger_quic_crypto_ctx[i].aead_req != NULL)
			aead_request_free(urllogger_quic_crypto_ctx[i].aead_req);
		if (urllogger_quic_crypto_ctx[i].aead != NULL)
			crypto_free_aead(urllogger_quic_crypto_ctx[i].aead);
		if (urllogger_quic_crypto_ctx[i].hp_req != NULL)
			skcipher_request_free(urllogger_quic_crypto_ctx[i].hp_req);
		if (urllogger_quic_crypto_ctx[i].hp != NULL)
			crypto_free_skcipher(urllogger_quic_crypto_ctx[i].hp);
		if (urllogger_quic_crypto_ctx[i].hmac != NULL)
			crypto_free_shash(urllogger_quic_crypto_ctx[i].hmac);
	}
	kfree(urllogger_quic_crypto_ctx);
	urllogger_quic_crypto_ctx = NULL;
	urllogger_quic_crypto_cpu_num = 0;
	return ret;
}

static void urllogger_quic_crypto_cleanup(void)
{
	int i;

	urllogger_quic_crypto_ready = 0;
	if (urllogger_quic_crypto_ctx == NULL)
		return;

	for (i = 0; i < urllogger_quic_crypto_cpu_num; i++) {
		if (urllogger_quic_crypto_ctx[i].aead_req != NULL)
			aead_request_free(urllogger_quic_crypto_ctx[i].aead_req);
		if (urllogger_quic_crypto_ctx[i].aead != NULL)
			crypto_free_aead(urllogger_quic_crypto_ctx[i].aead);
		if (urllogger_quic_crypto_ctx[i].hp_req != NULL)
			skcipher_request_free(urllogger_quic_crypto_ctx[i].hp_req);
		if (urllogger_quic_crypto_ctx[i].hp != NULL)
			crypto_free_skcipher(urllogger_quic_crypto_ctx[i].hp);
		if (urllogger_quic_crypto_ctx[i].hmac != NULL)
			crypto_free_shash(urllogger_quic_crypto_ctx[i].hmac);
	}

	kfree(urllogger_quic_crypto_ctx);
	urllogger_quic_crypto_ctx = NULL;
	urllogger_quic_crypto_cpu_num = 0;
}

int natflow_urllogger_url_enabled(void)
{
	return READ_ONCE(urllogger_store_enable) != 0;
}

unsigned int natflow_urllogger_consume_url_view(unsigned int hooknum,
        URLLOGGER_HOOK_CTX_ARGS,
        const struct natflow_l7_packet_view *view)
{
#if NATFLOW_HAVE_IP_SET_STATE_API
	const struct net_device *in = state->in;
#endif
	int ret = NF_ACCEPT;
	int data_len;
	unsigned char *data;
	natflow_t *nf = NULL;
	struct sk_buff *skb;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	unsigned int consumer_mask;
	int url_consumer;
	int dpi_consumer;
	int bridge;

	if (!view || !view->skb || !view->ct)
		return NF_ACCEPT;
	skb = view->skb;
	ct = view->ct;
	consumer_mask = view->consumer_mask;
	url_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_URL) != 0;
	dpi_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_DPI) != 0;
	if (!url_consumer && !dpi_consumer)
		return NF_ACCEPT;
	bridge = (view->flags & NATFLOW_L7_PACKET_F_PPPOE) != 0;

	if (view->l3num == AF_INET6)
		goto urllogger_hook_ipv6_main;

	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		goto out;
	}
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_UDP) {
		ret = urllogger_quic4(URLLOGGER_HOOK_CTX_PASS, skb, ct,
		                       consumer_mask);
		goto out;
	}
	if (iph->protocol != IPPROTO_TCP) {
		goto out;
	}

	if (skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
		goto out;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	/* pause fastnat path */
	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE)) {
		/* tell FF shared L7 still needs this conn */
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);
	}

	data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
	if (data_len > 0) {
		unsigned char *prev_data = NULL;
		__u32 prev_seq = 0;
		unsigned int prev_data_len = 0;
		unsigned char *host = NULL;
		int host_len;
		enum natflow_l7_tls_search_result sni_result;

		if (skb_try_make_writable(skb, skb->len)) {
			goto out;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;

		prev_data = urllogger_sni_cache_detach(iph->saddr, TCPH(l4)->source, iph->daddr, TCPH(l4)->dest, &prev_seq, &prev_data_len);
		if (prev_data) {
			unsigned int append_len = data_len;
			unsigned int next_data_len;

			if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq) + prev_data_len) {
				unsigned char *new_data;

				if (prev_data_len >= URLLOGGER_SNI_CACHE_DATA_LIMIT ||
				        append_len > URLLOGGER_SNI_CACHE_DATA_LIMIT - prev_data_len) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": sni cache data too large, prev_data_len=%u, data_len=%u\n", DEBUG_TCP_ARG(iph,l4), prev_data_len, append_len);
					goto __urllogger_ip_skip;
				}
				next_data_len = prev_data_len + append_len;

				new_data = krealloc(prev_data, next_data_len, GFP_ATOMIC);
				if (!new_data) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to krealloc data\n", DEBUG_TCP_ARG(iph,l4));
					kfree(prev_data);
					ret = NF_ACCEPT;
					goto out;
				}
				prev_data = new_data;

				memcpy(prev_data + prev_data_len, data, data_len);
				prev_data_len = next_data_len;

				host_len = prev_data_len;
				sni_result = natflow_l7_tls_sni_search(prev_data, &host_len, &host);
				if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
					if (prev_data_len >= URLLOGGER_SNI_CACHE_DATA_LIMIT ||
					        urllogger_sni_cache_attach(iph->saddr, TCPH(l4)->source,
					                                   iph->daddr, TCPH(l4)->dest, prev_seq, prev_data, prev_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach urllogger sni cache, prev_data_len=%u\n", DEBUG_TCP_ARG(iph,l4), prev_data_len);
						goto __urllogger_ip_skip;
					}
					ret = NF_ACCEPT;
					goto out;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq)) {
				if (urllogger_sni_cache_attach(iph->saddr, TCPH(l4)->source,
				                               iph->daddr, TCPH(l4)->dest, prev_seq, prev_data, prev_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach urllogger sni cache\n", DEBUG_TCP_ARG(iph,l4));
					goto __urllogger_ip_skip;
				}
				ret = NF_ACCEPT;
				goto out;
			} else {
				goto __urllogger_ip_skip;
			}
		} else {
			host_len = data_len;
			sni_result = natflow_l7_tls_sni_search(data, &host_len, &host);
			if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
				prev_data = kmemdup(data, data_len, GFP_ATOMIC);
				if (prev_data) {
					if (urllogger_sni_cache_attach(iph->saddr, TCPH(l4)->source, iph->daddr, TCPH(l4)->dest, TCPH(l4)->seq, prev_data, data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach urllogger sni cache\n", DEBUG_TCP_ARG(iph,l4));
						goto __urllogger_ip_skip;
					}
				}
				ret = NF_ACCEPT;
				goto out;
			}
		}

__urllogger_ip_skip:
		/* check one packet only */
		set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_L7_USE)) {
			/* tell FF shared L7 has finished its job */
			simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);
		}

		if (host) {
			struct urlinfo *url;

			if (!url_consumer) {
				if (dpi_consumer)
					urllogger_dpi_classify_raw_host(ct, host, host_len,
					                                NATFLOW_DPI_EVENT_SOURCE_TLS);
				if (prev_data) kfree(prev_data);
				goto out;
			}

			url = urlinfo_alloc_record(host, host_len, 0, NULL, 0);
			if (!url) {
				struct urllogger_acl_lookup acl;

				if (urllogger_acl_lookup_init(&acl, host, host_len, 0) == 0) {
					if (dpi_consumer)
						urllogger_dpi_classify_lookup(ct, &acl,
						                              NATFLOW_DPI_EVENT_SOURCE_TLS);
					urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET);
					if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
						set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
						ret = NF_DROP;
						/* tell FF do not emit pkts */
						if (nf && !(nf->status & NF_FF_USER_USE)) {
							/* tell FF -user- need to use this conn */
							simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
						}
						if (acl.acl_action == URLINFO_ACL_ACTION_RESET) {
							natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
							natflow_auth_convert_tcprst(skb);
							ret = NF_ACCEPT;
						} else if (acl.acl_action == URLINFO_ACL_ACTION_REDIRECT) {
							natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
							natflow_auth_convert_tcprst(skb);
							ret = NF_ACCEPT;
						}
					}
				}
				if (prev_data) kfree(prev_data);
				goto out;
			}
			if (prev_data) kfree(prev_data);
			if (urllogger_store_tuple_type == 0) {
				/* 0: dir0-src dir0-dst */
				url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				url->dip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
				url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
			} else if (urllogger_store_tuple_type == 1) {
				/* 1: dir0-src dir1-src */
				url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
				url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
				url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
			} else {
				/* 2: dir1-dst dir1-src */
				url->sip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
				url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
				url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
			}
			url->timestamp = URLINFO_NOW;
			url->flags = URLINFO_HTTPS;
			url->http_method = 0;
			url->hits = 1;
			memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

			url->acl_idx = 64; /* 64 = before acl matching */
			url->acl_action = acl_action_default;
			if (dpi_consumer)
				urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_TLS);
			urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET);
			if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
				set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
				ret = NF_DROP;
				/* tell FF do not emit pkts */
				if (nf && !(nf->status & NF_FF_USER_USE)) {
					/* tell FF -user- need to use this conn */
					simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
				}
				if (url->acl_action == URLINFO_ACL_ACTION_RESET) {
					natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
					natflow_auth_convert_tcprst(skb);
					ret = NF_ACCEPT;
				} else if (url->acl_action == URLINFO_ACL_ACTION_REDIRECT) {
					if (url->http_method == NATFLOW_HTTP_GET || url->http_method == NATFLOW_HTTP_POST) {
						natflow_urllogger_tcp_reply_302(in, skb, ct, bridge);
					} else {
						natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
					}
					natflow_auth_convert_tcprst(skb);
					ret = NF_ACCEPT;
				}
			}

			urllogger_store_record(url);
		} else {
			struct natflow_l7_feature feature;

			if (prev_data) {
				kfree(prev_data);
				prev_data = NULL;
			}
			data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
			if (natflow_l7_http_parse(data, data_len, &feature) > 0) {
				struct urlinfo *url;

				if (!url_consumer) {
					if (dpi_consumer)
						urllogger_dpi_classify_raw_host(ct, feature.host,
						                                feature.host_len,
						                                NATFLOW_DPI_EVENT_SOURCE_HTTP);
					goto out;
				}

				url = urlinfo_alloc_record(feature.host, feature.host_len, 0,
				                           feature.raw_uri.data, feature.raw_uri.len);
				if (!url) {
					struct urllogger_acl_lookup acl;

					if (urllogger_acl_lookup_init(&acl, feature.host, feature.host_len, 0) == 0) {
						if (dpi_consumer)
							urllogger_dpi_classify_lookup(ct, &acl,
							                              NATFLOW_DPI_EVENT_SOURCE_HTTP);
						urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET);
						if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
							set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
							ret = NF_DROP;
							/* tell FF do not emit pkts */
							if (nf && !(nf->status & NF_FF_USER_USE)) {
								/* tell FF -user- need to use this conn */
								simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
							}
							if (acl.acl_action == URLINFO_ACL_ACTION_RESET) {
								natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
								natflow_auth_convert_tcprst(skb);
								ret = NF_ACCEPT;
							} else if (acl.acl_action == URLINFO_ACL_ACTION_REDIRECT) {
								if (feature.http_method == NATFLOW_L7_HTTP_GET ||
								        feature.http_method == NATFLOW_L7_HTTP_POST) {
									natflow_urllogger_tcp_reply_302(in, skb, ct, bridge);
								} else {
									natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
								}
								natflow_auth_convert_tcprst(skb);
								ret = NF_ACCEPT;
							}
						}
					}
					goto out;
				}
				if (urllogger_store_tuple_type == 0) {
					/* 0: dir0-src dir0-dst */
					url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
					url->dip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
					url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				} else if (urllogger_store_tuple_type == 1) {
					/* 1: dir0-src dir1-src */
					url->sip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
					url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
					url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
				} else {
					/* 2: dir1-dst dir1-src */
					url->sip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip;
					url->dip = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip;
					url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
				}
				url->timestamp = URLINFO_NOW;
				url->flags = 0;
				url->http_method = feature.http_method;
				url->hits = 1;
				memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

				url->acl_idx = 64; /* 64 = before acl matching */
				url->acl_action = acl_action_default;
				if (dpi_consumer)
					urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_HTTP);
				urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET);
				if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
					set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
					ret = NF_DROP;
					/* tell FF do not emit pkts */
					if (nf && !(nf->status & NF_FF_USER_USE)) {
						/* tell FF -user- need to use this conn */
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
					}
					if (url->acl_action == URLINFO_ACL_ACTION_RESET) {
						natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
						natflow_auth_convert_tcprst(skb);
						ret = NF_ACCEPT;
					} else if (url->acl_action == URLINFO_ACL_ACTION_REDIRECT) {
						if (url->http_method == NATFLOW_HTTP_GET || url->http_method == NATFLOW_HTTP_POST) {
							natflow_urllogger_tcp_reply_302(in, skb, ct, bridge);
						} else {
							natflow_urllogger_tcp_reply_rstack(in, skb, ct, bridge);
						}
						natflow_auth_convert_tcprst(skb);
						ret = NF_ACCEPT;
					}
				}

				urllogger_store_record(url);
			}
		}
	}
	goto out;

urllogger_hook_ipv6_main:
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr))) {
		goto out;
	}
	iph = (void *)ipv6_hdr(skb);
	if (IPV6H->version != 6) {
		goto out;
	}
	if (IPV6H->nexthdr == IPPROTO_UDP) {
		ret = urllogger_quic6(URLLOGGER_HOOK_CTX_PASS, skb, ct,
		                       consumer_mask);
		goto out;
	}
	if (IPV6H->nexthdr != IPPROTO_TCP) {
		goto out;
	}

	if (skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr))) {
		goto out;
	}
	iph = (void *)ipv6_hdr(skb);
	l4 = (void *)iph + sizeof(struct ipv6hdr);

	/* pause fastnat path */
	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE)) {
		/* tell FF shared L7 still needs this conn */
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);
	}

	data_len = ntohs(IPV6H->payload_len) - TCPH(l4)->doff * 4;
	if (data_len > 0) {
		unsigned char *prev_data = NULL;
		__u32 prev_seq = 0;
		unsigned int prev_data_len = 0;
		unsigned char *host = NULL;
		int host_len;
		enum natflow_l7_tls_search_result sni_result;

		if (skb_try_make_writable(skb, skb->len)) {
			goto out;
		}
		iph = (void *)ipv6_hdr(skb);
		l4 = (void *)iph + sizeof(struct ipv6hdr);
		data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;

		prev_data = urllogger_sni_cache_detach6(&IPV6H->saddr, TCPH(l4)->source, &IPV6H->daddr, TCPH(l4)->dest, &prev_seq, &prev_data_len);
		if (prev_data) {
			unsigned int append_len = data_len;
			unsigned int next_data_len;

			if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq) + prev_data_len) {
				unsigned char *new_data;

				if (prev_data_len >= URLLOGGER_SNI_CACHE_DATA_LIMIT ||
				        append_len > URLLOGGER_SNI_CACHE_DATA_LIMIT - prev_data_len) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": sni cache data too large, prev_data_len=%u, data_len=%u\n", DEBUG_TCP_ARG6(iph,l4), prev_data_len, append_len);
					goto __urllogger_ipv6_skip;
				}
				next_data_len = prev_data_len + append_len;

				new_data = krealloc(prev_data, next_data_len, GFP_ATOMIC);
				if (!new_data) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to krealloc data\n", DEBUG_TCP_ARG6(iph,l4));
					kfree(prev_data);
					ret = NF_ACCEPT;
					goto out;
				}
				prev_data = new_data;

				memcpy(prev_data + prev_data_len, data, data_len);
				prev_data_len = next_data_len;

				host_len = prev_data_len;
				sni_result = natflow_l7_tls_sni_search(prev_data, &host_len, &host);
				if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
					if (prev_data_len >= URLLOGGER_SNI_CACHE_DATA_LIMIT ||
					        urllogger_sni_cache_attach6(&IPV6H->saddr, TCPH(l4)->source,
					                                    &IPV6H->daddr, TCPH(l4)->dest, prev_seq, prev_data, prev_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach urllogger sni cache6, prev_data_len=%u\n", DEBUG_TCP_ARG6(iph,l4), prev_data_len);
						goto __urllogger_ipv6_skip;
					}
					ret = NF_ACCEPT;
					goto out;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq)) {
				if (urllogger_sni_cache_attach6(&IPV6H->saddr, TCPH(l4)->source,
				                                &IPV6H->daddr, TCPH(l4)->dest, prev_seq, prev_data, prev_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach urllogger sni cache6\n", DEBUG_TCP_ARG6(iph,l4));
					goto __urllogger_ipv6_skip;
				}
				ret = NF_ACCEPT;
				goto out;
			} else {
				goto __urllogger_ipv6_skip;
			}
		} else {
			host_len = data_len;
			sni_result = natflow_l7_tls_sni_search(data, &host_len, &host);
			if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
				prev_data = kmemdup(data, data_len, GFP_ATOMIC);
				if (prev_data) {
					if (urllogger_sni_cache_attach6(&IPV6H->saddr, TCPH(l4)->source, &IPV6H->daddr, TCPH(l4)->dest, TCPH(l4)->seq, prev_data, data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach urllogger sni cache6\n", DEBUG_TCP_ARG6(iph,l4));
						goto __urllogger_ipv6_skip;
					}
				}
				ret = NF_ACCEPT;
				goto out;
			}
		}

__urllogger_ipv6_skip:
		/* check one packet only */
		set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_L7_USE)) {
			/* tell FF shared L7 has finished its job */
			simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);
		}

		if (host) {
			struct urlinfo *url;

			if (!url_consumer) {
				if (dpi_consumer)
					urllogger_dpi_classify_raw_host(ct, host, host_len,
					                                NATFLOW_DPI_EVENT_SOURCE_TLS);
				if (prev_data) kfree(prev_data);
				goto out;
			}

			url = urlinfo_alloc_record(host, host_len, 0, NULL, 0);
			if (!url) {
				struct urllogger_acl_lookup acl;

				if (urllogger_acl_lookup_init(&acl, host, host_len, 0) == 0) {
					if (dpi_consumer)
						urllogger_dpi_classify_lookup(ct, &acl,
						                              NATFLOW_DPI_EVENT_SOURCE_TLS);
					urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET6);
					if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
						set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
						ret = NF_DROP;
						/* tell FF do not emit pkts */
						if (nf && !(nf->status & NF_FF_USER_USE)) {
							/* tell FF -user- need to use this conn */
							simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
						}
						if (acl.acl_action == URLINFO_ACL_ACTION_RESET) {
							natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
							natflow_auth_convert_tcprst6(skb);
							ret = NF_ACCEPT;
						}
					}
				}
				if (prev_data) kfree(prev_data);
				goto out;
			}
			if (prev_data) kfree(prev_data);
			if (urllogger_store_tuple_type == 0) {
				/* 0: dir0-src dir0-dst */
				url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
				url->dipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
				url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
			} else if (urllogger_store_tuple_type == 1) {
				/* 1: dir0-src dir1-src */
				url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
				url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
				url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
			} else {
				/* 2: dir1-dst dir1-src */
				url->sipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3;
				url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
				url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
				url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
			}
			url->timestamp = URLINFO_NOW;
			url->flags = URLINFO_HTTPS;
			url->flags |= URLINFO_IPV6;
			url->http_method = 0;
			url->hits = 1;
			memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

			url->acl_idx = 64; /* 64 = before acl matching */
			url->acl_action = acl_action_default;
			if (dpi_consumer)
				urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_TLS);
			urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET6);
			if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
				set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
				ret = NF_DROP;
				/* tell FF do not emit pkts */
				if (nf && !(nf->status & NF_FF_USER_USE)) {
					/* tell FF -user- need to use this conn */
					simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
				}
				if (url->acl_action == URLINFO_ACL_ACTION_RESET) {
					natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
					natflow_auth_convert_tcprst6(skb);
					ret = NF_ACCEPT;
				}
			}

			urllogger_store_record(url);
		} else {
			struct natflow_l7_feature feature;

			if (prev_data) {
				kfree(prev_data);
				prev_data = NULL;
			}
			data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;
			if (natflow_l7_http_parse(data, data_len, &feature) > 0) {
				struct urlinfo *url;

				if (!url_consumer) {
					if (dpi_consumer)
						urllogger_dpi_classify_raw_host(ct, feature.host,
						                                feature.host_len,
						                                NATFLOW_DPI_EVENT_SOURCE_HTTP);
					goto out;
				}

				url = urlinfo_alloc_record(feature.host, feature.host_len, 0,
				                           feature.raw_uri.data, feature.raw_uri.len);
				if (!url) {
					struct urllogger_acl_lookup acl;

					if (urllogger_acl_lookup_init(&acl, feature.host, feature.host_len, 0) == 0) {
						if (dpi_consumer)
							urllogger_dpi_classify_lookup(ct, &acl,
							                              NATFLOW_DPI_EVENT_SOURCE_HTTP);
						urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl, AF_INET6);
						if (acl.acl_action != URLINFO_ACL_ACTION_RECORD) {
							set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
							ret = NF_DROP;
							/* tell FF do not emit pkts */
							if (nf && !(nf->status & NF_FF_USER_USE)) {
								/* tell FF -user- need to use this conn */
								simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
							}
							if (acl.acl_action == URLINFO_ACL_ACTION_RESET) {
								natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
								natflow_auth_convert_tcprst6(skb);
								ret = NF_ACCEPT;
							} else if (acl.acl_action == URLINFO_ACL_ACTION_REDIRECT) {
								if (feature.http_method == NATFLOW_L7_HTTP_GET ||
								        feature.http_method == NATFLOW_L7_HTTP_POST) {
									natflow_urllogger_tcp_reply_302_v6(in, skb, ct, bridge);
								} else {
									natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
								}
								natflow_auth_convert_tcprst6(skb);
								ret = NF_ACCEPT;
							}
						}
					}
					goto out;
				}
				if (urllogger_store_tuple_type == 0) {
					/* 0: dir0-src dir0-dst */
					url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
					url->dipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3;
					url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;
				} else if (urllogger_store_tuple_type == 1) {
					/* 1: dir0-src dir1-src */
					url->sipv6 = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
					url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
					url->sport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
				} else {
					/* 2: dir1-dst dir1-src */
					url->sipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3;
					url->dipv6 = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3;
					url->sport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all;
					url->dport = ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all;
				}
				url->timestamp = URLINFO_NOW;
				url->flags = 0;
				url->flags |= URLINFO_IPV6;
				url->http_method = feature.http_method;
				url->hits = 1;
				memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

				url->acl_idx = 64; /* 64 = before acl matching */
				url->acl_action = acl_action_default;
				if (dpi_consumer)
					urllogger_dpi_classify_url(ct, url, NATFLOW_DPI_EVENT_SOURCE_HTTP);
				urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, AF_INET6);
				if (url->acl_action != URLINFO_ACL_ACTION_RECORD) {
					set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
					ret = NF_DROP;
					/* tell FF do not emit pkts */
					if (nf && !(nf->status & NF_FF_USER_USE)) {
						/* tell FF -user- need to use this conn */
						simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);
					}
					if (url->acl_action == URLINFO_ACL_ACTION_RESET) {
						natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
						natflow_auth_convert_tcprst6(skb);
						ret = NF_ACCEPT;
					} else if (url->acl_action == URLINFO_ACL_ACTION_REDIRECT) {
						if (url->http_method == NATFLOW_HTTP_GET || url->http_method == NATFLOW_HTTP_POST) {
							natflow_urllogger_tcp_reply_302_v6(in, skb, ct, bridge);
						} else {
							natflow_urllogger_tcp_reply_rstack6(in, skb, ct, bridge);
						}
						natflow_auth_convert_tcprst6(skb);
						ret = NF_ACCEPT;
					}
				}

				urllogger_store_record(url);
			}
		}
	}

out:
	return ret;
}

struct urllogger_user {
	struct mutex lock;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
	unsigned char data[];
#else
	unsigned char data[0];
#endif
};
#define URLLOGGER_MEMSIZE ALIGN(sizeof(struct urllogger_user), 2048)
#define URLLOGGER_DATALEN (URLLOGGER_MEMSIZE - sizeof(struct urllogger_user))

static struct urlinfo *urlinfo_alloc_record(const unsigned char *host, int host_len,
        unsigned int host_flags,
        const unsigned char *uri, int uri_len)
{
	ssize_t copied_host_len;
	unsigned int copied_len;
	unsigned int data_len;
	struct urlinfo *url;

	if (!host || host_len <= 0 || uri_len < 0)
		return NULL;
	if (!uri && uri_len != 0)
		return NULL;
	if (uri && urlinfo_uri_validate(uri, uri_len) < 0)
		return NULL;

	copied_host_len = urlinfo_copy_host_tolower(NULL, host, host_len, host_flags);
	if (copied_host_len < 0)
		return NULL;
	copied_len = copied_host_len;

	if ((unsigned int)uri_len > URLLOGGER_DATALEN - 1 ||
	        copied_len > URLLOGGER_DATALEN - (unsigned int)uri_len - 1)
		return NULL;
	data_len = copied_len + (unsigned int)uri_len + 1;

	url = kmalloc(ALIGN(sizeof(*url) + data_len, __URLINFO_ALIGN), GFP_ATOMIC);
	if (!url)
		return NULL;

	INIT_LIST_HEAD(&url->list);
	url->host_len = copied_len;
	if (urlinfo_copy_host_tolower(url->data, host, host_len, host_flags) != copied_host_len) {
		kfree(url);
		return NULL;
	}
	if (uri_len > 0)
		memcpy(url->data + copied_len, uri, uri_len);
	url->data[data_len - 1] = 0;
	url->data_len = data_len;

	return url;
}

static size_t urllogger_csv_field_len(const unsigned char *data, unsigned short data_len)
{
	unsigned int field_len = data_len > 0 ? data_len - 1 : 0;
	size_t len = field_len;
	unsigned int i;
	int quoted = 0;

	for (i = 0; i < field_len; i++) {
		if (data[i] == '"') {
			len++;
			quoted = 1;
		} else if (data[i] == ',' || data[i] == '\r' || data[i] == '\n') {
			quoted = 1;
		}
	}

	return quoted ? len + 2 : len;
}

static size_t urllogger_csv_field_write(char *dst, const unsigned char *data, unsigned short data_len)
{
	unsigned int field_len = data_len > 0 ? data_len - 1 : 0;
	unsigned int i;
	size_t len = 0;
	int quoted = 0;

	for (i = 0; i < field_len; i++) {
		if (data[i] == '"' || data[i] == ',' || data[i] == '\r' || data[i] == '\n') {
			quoted = 1;
			break;
		}
	}

	if (quoted)
		dst[len++] = '"';
	for (i = 0; i < field_len; i++) {
		if (data[i] == '"')
			dst[len++] = '"';
		dst[len++] = data[i];
	}
	if (quoted)
		dst[len++] = '"';

	return len;
}

static ssize_t urllogger_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
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
	while (n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	/* Make sure the line ends with '\n' and is no longer than MAX_IOCTL_LEN. */
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("error: line too long");
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
		urllogger_store_clear();
		goto done;
	}

	NATFLOW_println("ignoring line: [%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

/* read one and clear one */
static ssize_t urllogger_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
	size_t len = 0;
	ssize_t ret;
	struct urlinfo *url;
	struct urllogger_user *user = file->private_data;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret)
		return ret;

	spin_lock_bh(&urllogger_store_lock);
	url = list_first_entry_or_null(&urllogger_store_list, struct urlinfo, list);
	if (url && uintmindiff(URLINFO_NOW, url->timestamp) > urllogger_store_timestamp_freq) {
		urllogger_store_memsize -= ALIGN(sizeof(struct urlinfo) + url->data_len, __URLINFO_ALIGN);
		urllogger_store_count--;
		list_del(&url->list);
	} else {
		url = NULL;
	}
	spin_unlock_bh(&urllogger_store_lock);

	if (url) {
		size_t data_csv_len = urllogger_csv_field_len(url->data, url->data_len);
		int prefix_len;

		/* timestamp, mac,              sip,            sport,dip,            dport,hits, meth,type,acl_idx,acl_action, url\n
		   4294967295,FF:AA:BB:CC:DD:EE,123.123.123.123,65535,111.111.111.111,65535,65535,POST,HTTP,64,1,url\n
		   ------------------------------------------------------------------------------------------------96bytes + 48bytes(if ipv6)
		 */
		if (data_csv_len + 2 /* \n + NUL */ <= URLLOGGER_DATALEN) {
			if ((url->flags & URLINFO_IPV6)) {
				prefix_len = snprintf(user->data, URLLOGGER_DATALEN,
				                      "%u,%02X:%02X:%02X:%02X:%02X:%02X,%pI6,%u,%pI6,%u,%u,%s,%s,%u,%u,",
				                      url->timestamp, url->mac[0], url->mac[1], url->mac[2], url->mac[3], url->mac[4], url->mac[5],
				                      &url->sipv6, ntohs(url->sport), &url->dipv6, ntohs(url->dport), url->hits,
				                      natflow_http_method_names[url->http_method], urlinfo_source_name(url), url->acl_idx, url->acl_action);
			} else {
				prefix_len = snprintf(user->data, URLLOGGER_DATALEN,
				                      "%u,%02X:%02X:%02X:%02X:%02X:%02X,%pI4,%u,%pI4,%u,%u,%s,%s,%u,%u,",
				                      url->timestamp, url->mac[0], url->mac[1], url->mac[2], url->mac[3], url->mac[4], url->mac[5],
				                      &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->hits,
				                      natflow_http_method_names[url->http_method], urlinfo_source_name(url), url->acl_idx, url->acl_action);
			}
			if (prefix_len >= 0 && prefix_len < URLLOGGER_DATALEN &&
			        (size_t)prefix_len + data_csv_len + 2 <= URLLOGGER_DATALEN) {
				len = prefix_len;
				len += urllogger_csv_field_write(user->data + len, url->data, url->data_len);
				user->data[len++] = '\n';
				user->data[len] = 0;
			} else {
				len = 0;
			}
			/*
			 * FIXME: Returning -EINVAL when len > count breaks single-byte reads
			 * (e.g. `while read` in shell scripts). It should be refactored to
			 * handle partial reads like conntrackinfo_read() or use seq_file.
			 */
			if (len > count) {
				ret = -EINVAL;
				goto out;
			}
			if (copy_to_user(buf, user->data, len)) {
				ret = -EFAULT;
				goto out;
			}
			ret = len;
		}
	}

out:
	if (url)
		urlinfo_release(url);
	mutex_unlock(&user->lock);
	return ret;
}

static int urllogger_open(struct inode *inode, struct file *file)
{
	struct urllogger_user *user;

	user = kmalloc(URLLOGGER_MEMSIZE, GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	/* Set nonseekable. */
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	mutex_init(&user->lock);

	file->private_data = user;
	return 0;
}

static int urllogger_release(struct inode *inode, struct file *file)
{
	struct urllogger_user *user = file->private_data;

	if (!user)
		return 0;

	mutex_destroy(&user->lock);
	kfree(user);
	return 0;
}

static const struct file_operations urllogger_fops = {
	.open = urllogger_open,
	.read = urllogger_read,
	.write = urllogger_write,
	.release = urllogger_release,
};

static struct ctl_table urllogger_table[] = {
	{
		.procname       = "memsize_limit",
		.data           = &urllogger_store_memsize_limit,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO|S_IWUSR,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "memsize",
		.data           = &urllogger_store_memsize,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "count_limit",
		.data           = &urllogger_store_count_limit,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO|S_IWUSR,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "count",
		.data           = &urllogger_store_count,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "enable",
		.data           = &urllogger_store_enable,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO|S_IWUSR,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "timestamp_freq",
		.data           = &urllogger_store_timestamp_freq,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO|S_IWUSR,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "tuple_type",
		.data           = &urllogger_store_tuple_type,
		.maxlen         = sizeof(unsigned int),
		.mode           = S_IRUGO|S_IWUSR,
		.proc_handler   = proc_douintvec,
	},
#if NATFLOW_HAVE_REGISTER_SYSCTL_SENTINEL
	{ }
#endif
};

#if NATFLOW_HAVE_REGISTER_SYSCTL_SENTINEL
static struct ctl_table urllogger_root_table[] = {
	{
		.procname       = "urllogger_store",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = urllogger_table,
	},
	{ }
};
#endif

static struct ctl_table_header *urllogger_table_header = NULL;

static void *hostacl_seq_entry(struct seq_file *m, loff_t *pos)
{
	int n = 0;
	char *hostacl_ctl_buffer = m->private;

	if ((*pos) == 0) {
		struct acl_redirect_config *redirect;
		rcu_read_lock();
		redirect = rcu_dereference(acl_redirect_config);
		n = snprintf(hostacl_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Usage:\n"
		             "#    clear -- clear all existing acl rule(s)\n"
		             "#    acl_action_default=accept/drop/reset/redirect\n"
		             "#    redirect_url=<http_url>\n"
		             "#    add acl=<id>,<act>,<host> --add one rule\n"
		             "#    IPSET format: host_acl_rule<id>_<fml>\n"
		             "#    <fml>=ipv4/ipv6/mac\n"
		             "#\n"
		             "acl_action_default=%s\n"
		             "redirect_url=%s\n"
		             "\n",
		             acl_action_names[acl_action_default],
		             redirect->url);
		rcu_read_unlock();
		hostacl_ctl_buffer[n] = 0;
		return hostacl_ctl_buffer;
	} else if ((*pos) % 2 == 1) {
		if ( ((*pos) - 1) / 2 < ACL_RULE_MAX ) {
			snprintf(hostacl_ctl_buffer, PAGE_SIZE, "\nACL%u=", (unsigned int)((*pos) - 1) / 2);
			return hostacl_ctl_buffer;
		} else if ( ((*pos) - 1) / 2 == ACL_RULE_MAX ) {
			strcpy(hostacl_ctl_buffer, "\n");
			return hostacl_ctl_buffer;
		} else {
			return NULL;
		}
	} else if ((*pos) % 2 == 0) {
		if ( ((*pos) - 1) / 2 < ACL_RULE_MAX ) {
			if (acl_rule_node[((*pos) - 1) / 2].acl_buffer != NULL) {
				return acl_rule_node[((*pos) - 1) / 2].acl_buffer;
			} else {
				strcpy(hostacl_ctl_buffer, "");
				return hostacl_ctl_buffer;
			}
		} else {
			return NULL;
		}
	}

	return NULL;
}

static void *hostacl_start(struct seq_file *m, loff_t *pos)
{
	mutex_lock(&acl_rule_lock);
	return hostacl_seq_entry(m, pos);
}

static void *hostacl_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return hostacl_seq_entry(m, pos);
	}
	return NULL;
}

static void hostacl_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&acl_rule_lock);
}

static int hostacl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

static const struct seq_operations hostacl_seq_ops = {
	.start = hostacl_start,
	.next = hostacl_next,
	.stop = hostacl_stop,
	.show = hostacl_show,
};

static ssize_t hostacl_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
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
	while (n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	/* Make sure the line ends with '\n' and is no longer than MAX_IOCTL_LEN. */
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("error: line too long");
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
		acl_rule_clear();
		goto done;
	} else if (strncmp(data, "acl_action_default=", 19) == 0) {
		mutex_lock(&acl_rule_lock);
		if (strncmp(data + 19, "accept", 6) == 0) {
			acl_action_default = URLINFO_ACL_ACTION_RECORD;
		} else if (strncmp(data + 19, "drop", 4) == 0) {
			acl_action_default = URLINFO_ACL_ACTION_DROP;
		} else if (strncmp(data + 19, "reset", 5) == 0) {
			acl_action_default = URLINFO_ACL_ACTION_RESET;
		} else if (strncmp(data + 19, "redirect", 8) == 0) {
			acl_action_default = URLINFO_ACL_ACTION_REDIRECT;
		} else {
			err = -EINVAL;
		}
		mutex_unlock(&acl_rule_lock);
		if (err == 0) {
			goto done;
		}
	} else if (strncmp(data, "redirect_url=", 13) == 0) {
		err = acl_redirect_config_update(data + 13);
		if (err == 0)
			goto done;
	} else if (strncmp(data, "add acl=", 8) == 0) {
		unsigned int idx = 64;
		unsigned int act;
		n = sscanf(data, "add acl=%u,%u,", &idx, &act);
		if (n == 2 && act >= 0 && act < 4) {
			act = (0x60 & (act << 5));

			if (idx >= 0 && idx < ACL_RULE_MAX) {
				int i = 8;
				while (data[i] != ',' && data[i] != 0) {
					i++;
				}
				if (data[i] == ',') {
					i++;
					while (data[i] != ',' && data[i] != 0) {
						i++;
					}
					if (data[i] == ',') {
						i++;
						n = 0;
						while (data[i + n] != 0) {
							n++;
						}
						if (data[i + n] == 0 && n >= 1) {
							err = acl_rule_add(idx, act, data + i, n);
							if (err == 0)
								goto done;
							return err;
						}
					}
				}
			}
		}
	}

	NATFLOW_println("ignoring line: [%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static ssize_t hostacl_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static int hostacl_open(struct inode *inode, struct file *file)
{
	int ret;
	/* Set nonseekable. */
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	ret = seq_open_private(file, &hostacl_seq_ops, PAGE_SIZE);
	if (ret)
		return ret;
	return 0;
}

static int hostacl_release(struct inode *inode, struct file *file)
{
	int ret = seq_release_private(inode, file);
	return ret;
}

static const struct file_operations hostacl_fops = {
	.owner = THIS_MODULE,
	.open = hostacl_open,
	.release = hostacl_release,
	.read = hostacl_read,
	.write = hostacl_write,
	.llseek  = seq_lseek,
};

static int natflow_hostacl_init(void)
{
	int ret = 0;
	dev_t devno;

	acl_rule_init();

	if (hostacl_major > 0) {
		devno = MKDEV(hostacl_major, hostacl_minor);
		ret = register_chrdev_region(devno, 1, hostacl_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, hostacl_minor, 1, hostacl_dev_name);
	}
	if (ret < 0) {
		NATFLOW_println("failed to allocate chrdev region");
		return ret;
	}
	hostacl_major = MAJOR(devno);
	hostacl_minor = MINOR(devno);
	NATFLOW_println("hostacl_major=%d, hostacl_minor=%d", hostacl_major, hostacl_minor);

	cdev_init(&hostacl_cdev, &hostacl_fops);
	hostacl_cdev.owner = THIS_MODULE;
	hostacl_cdev.ops = &hostacl_fops;

	ret = cdev_add(&hostacl_cdev, devno, 1);
	if (ret) {
		NATFLOW_println("failed to add cdev, error=%d", ret);
		goto cdev_add_failed;
	}

	hostacl_class = natflow_class_create("hostacl_class");
	if (IS_ERR(hostacl_class)) {
		NATFLOW_println("failed to create class");
		ret = -EINVAL;
		goto class_create_failed;
	}

	hostacl_dev = device_create(hostacl_class, NULL, devno, NULL, hostacl_dev_name);
	if (IS_ERR(hostacl_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	return 0;

	/* device_create() failed before creating a device node. */
device_create_failed:
	class_destroy(hostacl_class);
class_create_failed:
	cdev_del(&hostacl_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void natflow_hostacl_exit(void)
{
	dev_t devno;

	devno = MKDEV(hostacl_major, hostacl_minor);

	device_destroy(hostacl_class, devno);
	class_destroy(hostacl_class);
	cdev_del(&hostacl_cdev);
	unregister_chrdev_region(devno, 1);

	acl_rule_clear();
	acl_redirect_config_reset();
}

int natflow_urllogger_init(void)
{
	int ret = 0;
	dev_t devno;

	ret = urllogger_sni_cache_init();
	if (ret != 0)
		return ret;

	ret = urllogger_quic_cache_init();
	if (ret != 0) {
		urllogger_sni_cache_cleanup();
		return ret;
	}

	ret = urllogger_quic_crypto_init();
	if (ret != 0)
		NATFLOW_WARN("QUIC hostname parser disabled, crypto init error=%d\n", ret);

	if (urllogger_major > 0) {
		devno = MKDEV(urllogger_major, urllogger_minor);
		ret = register_chrdev_region(devno, 1, urllogger_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, urllogger_minor, 1, urllogger_dev_name);
	}
	if (ret < 0) {
		NATFLOW_println("failed to allocate chrdev region");
		urllogger_quic_crypto_cleanup();
		urllogger_quic_cache_cleanup();
		urllogger_sni_cache_cleanup();
		return ret;
	}
	urllogger_major = MAJOR(devno);
	urllogger_minor = MINOR(devno);
	NATFLOW_println("urllogger_major=%d, urllogger_minor=%d", urllogger_major, urllogger_minor);

	cdev_init(&urllogger_cdev, &urllogger_fops);
	urllogger_cdev.owner = THIS_MODULE;
	urllogger_cdev.ops = &urllogger_fops;

	ret = cdev_add(&urllogger_cdev, devno, 1);
	if (ret) {
		NATFLOW_println("failed to add cdev, error=%d", ret);
		goto cdev_add_failed;
	}

	urllogger_class = natflow_class_create("urllogger_class");
	if (IS_ERR(urllogger_class)) {
		NATFLOW_println("failed to create class");
		ret = -EINVAL;
		goto class_create_failed;
	}

	urllogger_dev = device_create(urllogger_class, NULL, devno, NULL, urllogger_dev_name);
	if (IS_ERR(urllogger_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	ret = natflow_hostacl_init();
	if (ret != 0)
		goto natflow_hostacl_init_failed;

	urllogger_table_header = natflow_register_sysctl("urllogger_store", urllogger_root_table, urllogger_table);
	if (urllogger_table_header == NULL) {
		ret = -ENOMEM;
		goto register_sysctl_failed;
	}

	return 0;

register_sysctl_failed:
	natflow_hostacl_exit();
natflow_hostacl_init_failed:
	device_destroy(urllogger_class, devno);
device_create_failed:
	class_destroy(urllogger_class);
class_create_failed:
	cdev_del(&urllogger_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	urllogger_quic_crypto_cleanup();
	urllogger_quic_cache_cleanup();
	urllogger_sni_cache_cleanup();
	return ret;
}

void natflow_urllogger_exit(void)
{
	dev_t devno;

	natflow_hostacl_exit();

	devno = MKDEV(urllogger_major, urllogger_minor);

	device_destroy(urllogger_class, devno);
	class_destroy(urllogger_class);
	cdev_del(&urllogger_cdev);
	unregister_chrdev_region(devno, 1);

	urllogger_store_clear();

	if (urllogger_table_header) {
		unregister_sysctl_table(urllogger_table_header);
		urllogger_table_header = NULL;
	}

	urllogger_quic_crypto_cleanup();
	urllogger_quic_cache_cleanup();
	urllogger_sni_cache_cleanup();
}
