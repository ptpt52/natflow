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
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/wait.h>
#include <linux/highmem.h>
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
static const char * const urllogger_dev_name = "natflow_urllogger_queue";
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
#define NATFLOW_HTTP_NONE NATFLOW_URLLOGGER_METHOD_NONE
#define NATFLOW_HTTP_GET NATFLOW_URLLOGGER_METHOD_GET
#define NATFLOW_HTTP_POST NATFLOW_URLLOGGER_METHOD_POST
#define NATFLOW_HTTP_HEAD NATFLOW_URLLOGGER_METHOD_HEAD
	unsigned char http_method;
	unsigned short hits;
	unsigned short data_len;
	unsigned short host_len;
	unsigned char acl_idx;
#define URLINFO_ACL_ACTION_RECORD NATFLOW_URLLOGGER_ACL_ACTION_RECORD
#define URLINFO_ACL_ACTION_DROP NATFLOW_URLLOGGER_ACL_ACTION_DROP
#define URLINFO_ACL_ACTION_RESET NATFLOW_URLLOGGER_ACL_ACTION_RESET
#define URLINFO_ACL_ACTION_REDIRECT NATFLOW_URLLOGGER_ACL_ACTION_REDIRECT
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

static inline unsigned char urlinfo_event_source(const struct urlinfo *url)
{
	switch (url->flags & URLINFO_SOURCE_MASK) {
	case URLINFO_SOURCE_HTTPS:
		return NATFLOW_URLLOGGER_EVENT_SOURCE_TLS;
	case URLINFO_SOURCE_QUIC:
		return NATFLOW_URLLOGGER_EVENT_SOURCE_QUIC;
	case URLINFO_SOURCE_HTTP:
	default:
		return NATFLOW_URLLOGGER_EVENT_SOURCE_HTTP;
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
static unsigned int urllogger_store_count = 0;
static LIST_HEAD(urllogger_store_list);
static DEFINE_SPINLOCK(urllogger_store_lock);
static wait_queue_head_t urllogger_wait;
static unsigned int urllogger_store_readers;
static unsigned int urllogger_store_cache_limit;
static struct natflow_queue_cache_write_state urllogger_write_state;

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

static inline int urllogger_store_ready_locked(void)
{
	struct urlinfo *url;

	url = list_first_entry_or_null(&urllogger_store_list, struct urlinfo, list);
	return url && uintmindiff(URLINFO_NOW, url->timestamp) > urllogger_store_timestamp_freq;
}

static void urllogger_store_purge_locked(struct list_head *free_list)
{
	list_splice_init(&urllogger_store_list, free_list);
	urllogger_store_count = 0;
}

static void urllogger_store_free_list(struct list_head *free_list)
{
	struct urlinfo *url;
	struct urlinfo *tmp;

	list_for_each_entry_safe(url, tmp, free_list, list) {
		list_del(&url->list);
		urlinfo_release(url);
	}
}

static void urllogger_store_record(struct urlinfo *url)
{
	struct urlinfo *url_i;
	struct list_head *pos;
	LIST_HEAD(free_list);
	int ready;

	if (READ_ONCE(urllogger_store_readers) == 0 ||
	        READ_ONCE(urllogger_store_cache_limit) == 0) {
		urlinfo_release(url);
		return;
	}

	spin_lock(&urllogger_store_lock);
	if (urllogger_store_readers == 0 || urllogger_store_cache_limit == 0) {
		spin_unlock(&urllogger_store_lock);
		urlinfo_release(url);
		return;
	}
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
			ready = urllogger_store_ready_locked();
			spin_unlock(&urllogger_store_lock);
			urlinfo_release(url);
			if (ready)
				wake_up_interruptible(&urllogger_wait);
			return;
		}
	}
	if (urllogger_store_count >= urllogger_store_cache_limit) {
		spin_unlock(&urllogger_store_lock);
		urlinfo_release(url);
		return;
	}
	urllogger_store_count++;
	list_add_tail(&url->list, &urllogger_store_list);
	while (urllogger_store_count > urllogger_store_cache_limit) {
		pos = urllogger_store_list.next;
		url_i = list_entry(pos, struct urlinfo, list);
		urllogger_store_count--;
		list_del(pos);
		list_add_tail(&url_i->list, &free_list);
	}
	ready = urllogger_store_ready_locked();
	spin_unlock(&urllogger_store_lock);

	urllogger_store_free_list(&free_list);
	if (ready)
		wake_up_interruptible(&urllogger_wait);
}

static void urllogger_store_clear(void)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&urllogger_store_lock);
	urllogger_store_purge_locked(&free_list);
	spin_unlock_bh(&urllogger_store_lock);

	urllogger_store_free_list(&free_list);
}

static void urllogger_store_cache_set(unsigned int cache_limit)
{
	LIST_HEAD(free_list);
	struct list_head *pos;
	struct urlinfo *url_i;

	WRITE_ONCE(urllogger_store_cache_limit, cache_limit);
	if (cache_limit == 0) {
		urllogger_store_clear();
		wake_up_interruptible(&urllogger_wait);
		return;
	}

	spin_lock_bh(&urllogger_store_lock);
	while (urllogger_store_count > cache_limit) {
		pos = urllogger_store_list.next;
		url_i = list_entry(pos, struct urlinfo, list);
		urllogger_store_count--;
		list_del(pos);
		list_add_tail(&url_i->list, &free_list);
	}
	spin_unlock_bh(&urllogger_store_lock);

	urllogger_store_free_list(&free_list);
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
	natflow_dpi_classify_host_normalized(ct, url->data, url->host_len,
	                                     source);
}

static inline void urllogger_dpi_classify_lookup(struct nf_conn *ct,
        const struct urllogger_acl_lookup *lookup, unsigned int source)
{
	natflow_dpi_classify_host_normalized(ct, lookup->data,
	                                     lookup->host_len, source);
}

static inline void urllogger_dpi_classify_raw_host(struct nf_conn *ct,
        const unsigned char *host, int host_len, unsigned int source,
        unsigned int host_flags)
{
	if (host_len <= 0)
		return;
	if (host_len > URLINFO_HOST_MAX_LEN &&
	        !(host_flags & URLINFO_HOST_ALLOW_PORT))
		return;

	natflow_dpi_classify_host_flags(ct, host, host_len, source, host_flags);
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

enum urllogger_redirect_reply {
	URLLOGGER_REDIRECT_DROP = 0,
	URLLOGGER_REDIRECT_RST,
	URLLOGGER_REDIRECT_HTTP,
};

static inline void urllogger_fill_url_tuple(struct urlinfo *url,
        struct nf_conn *ct, int l3num)
{
	if (l3num == AF_INET6) {
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
		return;
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
}

static inline unsigned int urllogger_reply_acl_action(URLLOGGER_HOOK_CTX_ARGS,
        const struct net_device *reply_dev, struct sk_buff *skb,
        struct nf_conn *ct, natflow_t *nf, int l3num, int bridge,
        unsigned char acl_action, unsigned char http_method, int reset_reply,
        enum urllogger_redirect_reply redirect_reply)
{
	unsigned int ret = NF_DROP;

	set_bit(IPS_NATFLOW_CT_DROP_BIT, &ct->status);
	if (nf && !(nf->status & NF_FF_USER_USE))
		simple_set_bit(NF_FF_USER_USE_BIT, &nf->status);

	if (acl_action == URLINFO_ACL_ACTION_RESET && reset_reply) {
		if (l3num == AF_INET6) {
			natflow_urllogger_tcp_reply_rstack6(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst6(skb);
		} else {
			natflow_urllogger_tcp_reply_rstack(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst(skb);
		}
		return NF_ACCEPT;
	}

	if (acl_action != URLINFO_ACL_ACTION_REDIRECT)
		return ret;

	if (redirect_reply == URLLOGGER_REDIRECT_RST) {
		if (l3num == AF_INET6) {
			natflow_urllogger_tcp_reply_rstack6(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst6(skb);
		} else {
			natflow_urllogger_tcp_reply_rstack(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst(skb);
		}
		return NF_ACCEPT;
	}

	if (redirect_reply == URLLOGGER_REDIRECT_HTTP) {
		if (l3num == AF_INET6) {
			if (http_method == NATFLOW_HTTP_GET ||
			        http_method == NATFLOW_HTTP_POST)
				natflow_urllogger_tcp_reply_302_v6(reply_dev, skb, ct, bridge);
			else
				natflow_urllogger_tcp_reply_rstack6(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst6(skb);
		} else {
			if (http_method == NATFLOW_HTTP_GET ||
			        http_method == NATFLOW_HTTP_POST)
				natflow_urllogger_tcp_reply_302(reply_dev, skb, ct, bridge);
			else
				natflow_urllogger_tcp_reply_rstack(reply_dev, skb, ct, bridge);
			natflow_auth_convert_tcprst(skb);
		}
		return NF_ACCEPT;
	}

	return ret;
}

static inline int urllogger_source_to_url_flags(enum natflow_l7_feature_source source,
        int l3num, unsigned int *url_flags)
{
	unsigned int flags;

	switch (source) {
	case NATFLOW_L7_SOURCE_HTTP:
		flags = 0;
		break;
	case NATFLOW_L7_SOURCE_TLS:
		flags = URLINFO_HTTPS;
		break;
	case NATFLOW_L7_SOURCE_QUIC:
		flags = URLINFO_QUIC;
		break;
	default:
		return -EINVAL;
	}

	if (l3num == AF_INET6)
		flags |= URLINFO_IPV6;

	*url_flags = flags;
	return 0;
}

static inline int urllogger_source_to_dpi_source(enum natflow_l7_feature_source source,
        unsigned int *dpi_source)
{
	switch (source) {
	case NATFLOW_L7_SOURCE_HTTP:
		*dpi_source = NATFLOW_DPI_EVENT_SOURCE_HTTP;
		return 0;
	case NATFLOW_L7_SOURCE_TLS:
		*dpi_source = NATFLOW_DPI_EVENT_SOURCE_TLS;
		return 0;
	case NATFLOW_L7_SOURCE_QUIC:
		*dpi_source = NATFLOW_DPI_EVENT_SOURCE_QUIC;
		return 0;
	default:
		return -EINVAL;
	}
}

static inline void urllogger_source_acl_reply(enum natflow_l7_feature_source source,
        int l3num, int *reset_reply,
        enum urllogger_redirect_reply *redirect_reply)
{
	*reset_reply = 0;
	*redirect_reply = URLLOGGER_REDIRECT_DROP;

	switch (source) {
	case NATFLOW_L7_SOURCE_HTTP:
		*reset_reply = 1;
		*redirect_reply = URLLOGGER_REDIRECT_HTTP;
		break;
	case NATFLOW_L7_SOURCE_TLS:
		*reset_reply = 1;
		if (l3num == AF_INET)
			*redirect_reply = URLLOGGER_REDIRECT_RST;
		break;
	default:
		break;
	}
}

static noinline unsigned int urllogger_consume_host_view_fallback(URLLOGGER_HOOK_CTX_ARGS,
        const struct net_device *reply_dev, struct sk_buff *skb,
        struct nf_conn *ct, natflow_t *nf,
        const struct natflow_l7_host_view *host_view, unsigned int dpi_source,
        int l3num, int bridge, int dpi_consumer, int reset_reply,
        enum urllogger_redirect_reply redirect_reply)
{
	struct urllogger_acl_lookup acl;
	unsigned int ret = NF_ACCEPT;

	if (urllogger_acl_lookup_init(&acl, host_view->host.data,
	                              host_view->host.len,
	                              host_view->host_flags) != 0)
		return ret;

	if (dpi_consumer)
		urllogger_dpi_classify_lookup(ct, &acl, dpi_source);
	urllogger_apply_host_acl_lookup(URLLOGGER_HOOK_CTX_PASS, skb, &acl,
	                                l3num);
	if (acl.acl_action != URLINFO_ACL_ACTION_RECORD)
		ret = urllogger_reply_acl_action(URLLOGGER_HOOK_CTX_PASS,
		                                 reply_dev, skb, ct, nf,
		                                 l3num, bridge, acl.acl_action,
		                                 host_view->http_method,
		                                 reset_reply, redirect_reply);

	return ret;
}

static unsigned int urllogger_consume_host_view_internal(URLLOGGER_HOOK_CTX_ARGS,
        const struct net_device *reply_dev, struct sk_buff *skb,
        struct nf_conn *ct, natflow_t *nf,
        const struct natflow_l7_host_view *host_view, int l3num, int bridge,
        int url_consumer, int dpi_consumer)
{
	const unsigned char *host;
	const unsigned char *uri;
	struct urlinfo *url;
	unsigned int ret = NF_ACCEPT;
	unsigned int url_flags;
	unsigned int dpi_source;
	unsigned char http_method;
	int reset_reply;
	enum urllogger_redirect_reply redirect_reply;

	if (!host_view ||
	        urllogger_source_to_url_flags(host_view->source, l3num,
	                                      &url_flags) != 0 ||
	        urllogger_source_to_dpi_source(host_view->source,
	                                       &dpi_source) != 0)
		return ret;

	host = host_view->host.data;
	uri = host_view->uri.data;
	http_method = host_view->http_method;
	urllogger_source_acl_reply(host_view->source, l3num, &reset_reply,
	                           &redirect_reply);

	if (!url_consumer) {
		if (dpi_consumer)
			urllogger_dpi_classify_raw_host(ct, host, host_view->host.len,
			                                dpi_source,
			                                host_view->host_flags);
		return ret;
	}

	url = urlinfo_alloc_record(host, host_view->host.len,
	                           host_view->host_flags, uri,
	                           host_view->uri.len);
	if (!url)
		return urllogger_consume_host_view_fallback(URLLOGGER_HOOK_CTX_PASS,
		        reply_dev, skb, ct, nf, host_view, dpi_source, l3num, bridge,
		        dpi_consumer, reset_reply, redirect_reply);

	urllogger_fill_url_tuple(url, ct, l3num);
	url->timestamp = URLINFO_NOW;
	url->flags = url_flags;
	url->http_method = http_method;
	url->hits = 1;
	memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

	url->acl_idx = 64; /* 64 = before acl matching */
	url->acl_action = acl_action_default;
	if (dpi_consumer)
		urllogger_dpi_classify_url(ct, url, dpi_source);
	urllogger_apply_host_acl(URLLOGGER_HOOK_CTX_PASS, skb, url, l3num);
	if (url->acl_action != URLINFO_ACL_ACTION_RECORD)
		ret = urllogger_reply_acl_action(URLLOGGER_HOOK_CTX_PASS,
		                                 reply_dev, skb, ct, nf, l3num,
		                                 bridge, url->acl_action,
		                                 url->http_method, reset_reply,
		                                 redirect_reply);

	urllogger_store_record(url);
	return ret;
}

unsigned int natflow_urllogger_consume_host_view(unsigned int hooknum,
        URLLOGGER_HOOK_CTX_ARGS,
        const struct natflow_l7_packet_view *view,
        unsigned int consumer_mask,
        const struct natflow_l7_host_view *host_view,
        const struct net_device *reply_dev,
        int bridge)
{
	natflow_t *nf;
	int url_consumer;
	int dpi_consumer;

	if (!view || !view->skb || !view->ct || !host_view)
		return NF_ACCEPT;

	consumer_mask &= view->consumer_mask;
	url_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_URL) != 0;
	dpi_consumer = (consumer_mask & NATFLOW_L7_CONSUMER_DPI_DOMAIN) != 0;
	if (!url_consumer && !dpi_consumer)
		return NF_ACCEPT;

	nf = natflow_session_get(view->ct);
	return urllogger_consume_host_view_internal(URLLOGGER_HOOK_CTX_PASS,
	        reply_dev, view->skb,
	        view->ct, nf, host_view,
	        view->l3num, bridge,
	        url_consumer, dpi_consumer);
}

int natflow_urllogger_url_enabled(void)
{
	return READ_ONCE(urllogger_store_enable) != 0;
}

#define URLLOGGER_DATALEN 2048

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

static ssize_t urllogger_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	return natflow_queue_cache_write(&urllogger_write_state, buf, buf_len,
	                                 offset, urllogger_store_cache_set);
}

static ssize_t urllogger_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
	struct natflow_urllogger_event_hdr hdr;
	size_t payload_len;
	size_t record_len;
	size_t copied = 0;
	struct urlinfo *url;

	if (count < sizeof(struct natflow_urllogger_event_hdr))
		return -EINVAL;

	while (count - copied >= sizeof(struct natflow_urllogger_event_hdr)) {
		spin_lock_bh(&urllogger_store_lock);
		url = list_first_entry_or_null(&urllogger_store_list,
		                               struct urlinfo, list);
		if (!url || !urllogger_store_ready_locked()) {
			spin_unlock_bh(&urllogger_store_lock);
			break;
		}

		payload_len = url->data_len > 0 ? url->data_len - 1 : 0;
		record_len = sizeof(hdr) + payload_len;
		if (count - copied < record_len) {
			spin_unlock_bh(&urllogger_store_lock);
			return copied > 0 ? (ssize_t)copied : -EINVAL;
		}
		urllogger_store_count--;
		list_del(&url->list);
		spin_unlock_bh(&urllogger_store_lock);

		memset(&hdr, 0, sizeof(hdr));
		hdr.version = NATFLOW_URLLOGGER_EVENT_VERSION;
		hdr.header_len = (__u16)sizeof(hdr);
		hdr.record_len = (__u16)record_len;
		hdr.family = (url->flags & URLINFO_IPV6) ? AF_INET6 : AF_INET;
		hdr.timestamp = url->timestamp;
		hdr.sport = ntohs(url->sport);
		hdr.dport = ntohs(url->dport);
		hdr.hits = url->hits;
		hdr.host_len = url->host_len;
		hdr.method = url->http_method;
		hdr.source = urlinfo_event_source(url);
		hdr.acl_idx = url->acl_idx;
		hdr.acl_action = url->acl_action;
		memcpy(hdr.mac, url->mac, sizeof(hdr.mac));
		if ((url->flags & URLINFO_IPV6)) {
			memcpy(hdr.sip, &url->sipv6, sizeof(hdr.sip));
			memcpy(hdr.dip, &url->dipv6, sizeof(hdr.dip));
		} else {
			memcpy(hdr.sip, &url->sip, sizeof(url->sip));
			memcpy(hdr.dip, &url->dip, sizeof(url->dip));
		}

		if (copy_to_user(buf + copied, &hdr, sizeof(hdr)) != 0) {
			urlinfo_release(url);
			return copied > 0 ? (ssize_t)copied : -EFAULT;
		}
		if (payload_len > 0 &&
		        copy_to_user(buf + copied + sizeof(hdr), url->data, payload_len) != 0) {
			urlinfo_release(url);
			return copied > 0 ? (ssize_t)copied : -EFAULT;
		}
		copied += record_len;
		urlinfo_release(url);
	}
	return copied;
}

static int urllogger_open(struct inode *inode, struct file *file)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&urllogger_store_lock);
	if (urllogger_store_readers != 0) {
		spin_unlock_bh(&urllogger_store_lock);
		return -EBUSY;
	}
	WRITE_ONCE(urllogger_store_readers, 1);
	WRITE_ONCE(urllogger_store_cache_limit, 0);
	urllogger_write_state.data_left = 0;
	urllogger_store_purge_locked(&free_list);
	spin_unlock_bh(&urllogger_store_lock);

	urllogger_store_free_list(&free_list);

	/* Set nonseekable. */
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
}

static int urllogger_release(struct inode *inode, struct file *file)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&urllogger_store_lock);
	WRITE_ONCE(urllogger_store_readers, 0);
	WRITE_ONCE(urllogger_store_cache_limit, 0);
	urllogger_write_state.data_left = 0;
	urllogger_store_purge_locked(&free_list);
	spin_unlock_bh(&urllogger_store_lock);

	urllogger_store_free_list(&free_list);
	wake_up_interruptible(&urllogger_wait);
	return 0;
}

static unsigned int urllogger_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &urllogger_wait, wait);
	spin_lock_bh(&urllogger_store_lock);
	if (urllogger_store_ready_locked())
		mask = POLLIN | POLLRDNORM;
	spin_unlock_bh(&urllogger_store_lock);
	return mask;
}

static const struct file_operations urllogger_fops = {
	.open = urllogger_open,
	.read = urllogger_read,
	.write = urllogger_write,
	.poll = urllogger_poll,
	.release = urllogger_release,
};

static struct ctl_table urllogger_table[] = {
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

	init_waitqueue_head(&urllogger_wait);
	WRITE_ONCE(urllogger_store_readers, 0);
	WRITE_ONCE(urllogger_store_cache_limit, 0);

	if (urllogger_major > 0) {
		devno = MKDEV(urllogger_major, urllogger_minor);
		ret = register_chrdev_region(devno, 1, urllogger_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, urllogger_minor, 1, urllogger_dev_name);
	}
	if (ret < 0) {
		NATFLOW_println("failed to allocate chrdev region");
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
	return ret;
}

void natflow_urllogger_exit(void)
{
	dev_t devno;

	WRITE_ONCE(urllogger_store_readers, 0);
	WRITE_ONCE(urllogger_store_cache_limit, 0);
	wake_up_interruptible(&urllogger_wait);

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
}
