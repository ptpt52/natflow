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
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/ip6_checksum.h>
#include "natflow_common.h"
#include "natflow_urllogger.h"

static int urllogger_major = 0;
static int urllogger_minor = 0;
static struct cdev urllogger_cdev;
const char *urllogger_dev_name = "urllogger_queue";
static struct class *urllogger_class;
static struct device *urllogger_dev;

static inline ssize_t urlinfo_copy_host_tolower(unsigned char *dst, unsigned char *src, ssize_t n)
{
	ssize_t i = 0;
	for (; i < n; i++) {
		if (src[i] == '/')
			break;
		if (src[i] >= 'A' && src[i] <= 'Z')
			dst[i] = src[i] - 'A' + 'a';
		else
			dst[i] = src[i];
	}
	memcpy(dst + i, src + i, n - i);

	return i;
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
#define URLINFO_HTTPS 0x01
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
	unsigned char data[0];
};

#define __URLINFO_ALIGN 64

static const char *NATFLOW_http_method[] = {
	[NATFLOW_HTTP_NONE] = "NONE",
	[NATFLOW_HTTP_GET] = "GET",
	[NATFLOW_HTTP_POST] = "POST",
	[NATFLOW_HTTP_HEAD] = "HEAD",
};

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
		if (url_i->sip == url->sip && url_i->dip == url->dip && url_i->dport == url->dport &&
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
const char *hostacl_dev_name = "hostacl_ctl";
static struct class *hostacl_class;
static struct device *hostacl_dev;

struct acl_rule {
	unsigned char *acl_buffer;
	ssize_t acl_buffer_size;
	ssize_t acl_buffer_len;
};

#define ACL_RULE_ALLOC_SIZE 256
#define ACL_RULE_MAX 32
static int acl_rule_max = 0;
static struct acl_rule acl_rule_node[ACL_RULE_MAX];

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
	for (rule_id = 0; rule_id < ACL_RULE_MAX; rule_id++) {
		tmp = acl_rule_node[rule_id].acl_buffer;
		if (tmp != NULL) {
			acl_rule_node[rule_id].acl_buffer = NULL;
			synchronize_rcu();
			kfree(tmp);
		}
	}
	acl_rule_max = 0;
}

/* return: 0 = no matched, 1 = matched */
static int urllogger_acl(struct urlinfo *url, int rule_id)
{
	int ret = 0;
	unsigned char backup_c;
	unsigned char *acl_buffer;

	acl_buffer = acl_rule_node[rule_id].acl_buffer;

	backup_c = url->data[url->host_len];
	url->data[url->host_len] = 0;

	if (url->host_len >= 1 && acl_buffer != NULL) { /* at least a.b pattern */
		int i = 0;
		unsigned char b;
		unsigned char *ptr = NULL;

		while (ptr == NULL) {
			ptr = strstr(acl_buffer, url->data + i);
			while (ptr != NULL) {
				b = *(ptr - 1);
				if (((ptr[url->host_len - i] & 0x80) != 0 || ptr[url->host_len - i] == 0) && (b & 0x80) != 0) {
					//found
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
	url->data[url->host_len] = backup_c;
	return ret;
}

static unsigned char *tls_sni_search(unsigned char *data, int *data_len, int *needmore)
{
	unsigned char *p = data;
	int p_len = *data_len;
	int i_data_len = p_len;
	unsigned int i = 0;
	unsigned short len;

	if (p[i + 0] != 0x16) {//Content Type NOT HandShake
		return NULL;
	}
	i += 1 + 2;
	if (i >= p_len) return NULL;
	len = ntohs(get_byte2(p + i + 0)); //content_len
	i += 2;
	if (i >= p_len) return NULL;
	if (i + len > p_len) {
		if (needmore && p[i] == 0x01) //HanShake Type is Client Hello
			*needmore = 1;
	}

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	if (p[i + 0] != 0x01) { //HanShake Type NOT Client Hello
		return NULL;
	}
	i += 1;
	if (i >= p_len || i >= i_data_len) return NULL;
	len = (p[i + 0] << 8) + ntohs(get_byte2(p + i + 0 + 1)); //hanshake_len
	i += 1 + 2;
	if (i >= p_len || i >= i_data_len) return NULL;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	i += 2 + 32;
	if (i >= p_len || i >= i_data_len) return NULL; //tls_v, random
	i += 1 + p[i + 0];
	if (i >= p_len || i >= i_data_len) return NULL; //session id
	i += 2 + ntohs(get_byte2(p + i + 0));
	if (i >= p_len || i >= i_data_len) return NULL; //Cipher Suites
	i += 1 + p[i + 0];
	if (i >= p_len || i >= i_data_len) return NULL; //Compression Methods

	len = ntohs(get_byte2(p + i + 0)); //ext_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (get_byte2(p + i + 0) != __constant_htons(0)) {
			i += 2 + 2 + ntohs(get_byte2(p + i + 0 + 2));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 2)); //sn_len
		i = i + 2 + 2;
		if (i + len > p_len || i + len > i_data_len) return NULL;

		p = p + i;
		p_len = len;
		i_data_len -= i;
		i = 0;
		break;
	}
	if (i >= p_len || i >= i_data_len) return NULL;

	len = ntohs(get_byte2(p + i + 0)); //snl_len
	i += 2;
	if (i + len > p_len || i + len > i_data_len) return NULL;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (p[i + 0] != 0) {
			i += 1 + 2 + ntohs(get_byte2(p + i + 0 + 1));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 1 + 2;
		if (i + len > p_len || i + len > i_data_len) return NULL;

		*data_len = len;
		return (p + i);
	}

	return NULL;
}

/* to do it simple:
   just assume
   1. data begin with 'GET ' or 'POST ' or 'HEAD '
 */
static int http_url_search(unsigned char *data,
                           int *data_len /*IN: data_len, OUT: host_len */, unsigned char **host,
                           int *uri_len, unsigned char **uri, int *http_method)
{
	unsigned char *p = data;
	int p_len = *data_len;
	unsigned int i = 0;

	if (i + 5 > p_len) return -1;
	if ((p[i] == 'G' || p[i] == 'g') &&
	        (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	        (p[i + 2] == 'T' || p[i + 2] == 't') &&
	        (p[i + 3] == ' ' || p[i + 3] == ' ')) {
		i += 4;
		*http_method = NATFLOW_HTTP_GET;
	} else if ((p[i] == 'P' || p[i] == 'p') &&
	           (p[i + 1] == 'O' || p[i + 1] == 'o') &&
	           (p[i + 2] == 'S' || p[i + 2] == 's') &&
	           (p[i + 3] == 'T' || p[i + 3] == 't') &&
	           (p[i + 4] == ' ' || p[i + 4] == ' ')) {
		i += 5;
		*http_method = NATFLOW_HTTP_POST;
	} else if ((p[i] == 'H' || p[i] == 'h') &&
	           (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	           (p[i + 2] == 'A' || p[i + 2] == 'a') &&
	           (p[i + 3] == 'D' || p[i + 3] == 'd') &&
	           (p[i + 4] == ' ' || p[i + 4] == ' ')) {
		i += 5;
		*http_method = NATFLOW_HTTP_HEAD;
	} else {
		return 0;
	}

	while (i < p_len && p[i] == ' ') i++;
	if (i >= p_len) return -1;
	if (p[i] != '/') return -1;
	*uri = p + i;

	i++;
	while (i < p_len && p[i] != ' ') i++;
	if (i >= p_len) return -1;
	if (p[i] != ' ') return -1;
	*uri_len = p + i - *uri;
	i++;

	while (i < p_len && p[i] != '\n') i++;
	if (i >= p_len) return -1;
	i++;

	do {
		if (i + 5 > p_len) return -1;
		if ((p[i] == 'H' || p[i] == 'h') &&
		        (p[i + 1] == 'o' || p[i + 1] == 'O') &&
		        (p[i + 2] == 's' || p[i + 2] == 'S') &&
		        (p[i + 3] == 't' || p[i + 3] == 'T') &&
		        p[i + 4] == ':') {
			i += 5;
			while (i < p_len && p[i] == ' ') i++;
			if (i >= p_len) return -1;
			*host = p + i;

			i++;
			while (i < p_len && p[i] != ' ' && p[i] != '\r' && p[i] != '\n') i++;
			if (i >= p_len) return -1;
			if (p[i] != ' ' && p[i] != '\r' && p[i] != '\n') return -1;
			*data_len = p + i - *host;

			return *data_len + *uri_len;
		}
		while (i < p_len && p[i] != '\n') i++;
		i++;
	} while (1);

	return 0; /* not found */
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
	//setup tcp header
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
	niph = ipv6_hdr(nskb);
	if ((char *)niph - (char *)neth >= ETH_HLEN) {
		memcpy(neth->h_dest, oeth->h_source, ETH_ALEN);
		memcpy(neth->h_source, oeth->h_dest, ETH_ALEN);
		//neth->h_proto = htons(ETH_P_IP);
	}
	//setup ip header
	memset(niph, 0, sizeof(struct iphdr));
	niph->version = oiph->version;
	niph->priority = oiph->priority;
	niph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.in6;
	niph->daddr = oiph->saddr;
	niph->flow_lbl[2] = niph->flow_lbl[1] = niph->flow_lbl[0] = 0;
	niph->payload_len = htons(sizeof(struct tcphdr));
	niph->nexthdr = IPPROTO_TCP;
	niph->hop_limit = 255;
	//setup tcp header
	ntcph = (struct tcphdr *)((char *)ip_hdr(nskb) + sizeof(struct ipv6hdr));
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
	//sum check
	len = ntohs(niph->payload_len);
	csum = csum_partial((char*)ntcph, len, 0);
	ntcph->check = tcp_v6_check(len, &niph->saddr, &niph->daddr, csum);
	//ready to send out
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
		oskb->protocol = __constant_htons(ETH_P_IP);
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
	unsigned short add_data_len;
	struct sk_buff *skb;
};

#define URLLOGGER_CACHE_TIMEOUT 4
#define MAX_URLLOGGER_SNI_CACHE_NODE 64
static struct urllogger_sni_cache_node urllogger_sni_cache[NR_CPUS][MAX_URLLOGGER_SNI_CACHE_NODE];

static inline void urllogger_sni_cache_init(void)
{
	int i, j;
	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
			urllogger_sni_cache[i][j].skb = NULL;
		}
	}
}

static inline void urllogger_sni_cache_cleanup(void)
{
	int i, j;
	for (i = 0; i < NR_CPUS; i++) {
		for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
			if (urllogger_sni_cache[i][j].skb != NULL) {
				consume_skb(urllogger_sni_cache[i][j].skb);
				urllogger_sni_cache[i][j].skb = NULL;
			}
		}
	}
}

static inline int urllogger_sni_cache_attach(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, struct sk_buff *skb, unsigned short add_data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;
	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL &&
		        urllogger_sni_cache[i][j].src_ip == src_ip &&
		        urllogger_sni_cache[i][j].src_port == src_port &&
		        urllogger_sni_cache[i][j].dst_ip == dst_ip &&
		        urllogger_sni_cache[i][j].dst_port == dst_port) {
			return -EEXIST;
		} else if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_sni_cache[i][j].skb == NULL) {
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
	urllogger_sni_cache[i][next_to_use].add_data_len = add_data_len;
	urllogger_sni_cache[i][next_to_use].skb = skb;
	urllogger_sni_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

static inline int urllogger_sni_cache_attach6(struct in6_addr *src_ip, __be16 src_port, struct in6_addr *dst_ip, __be16 dst_port, struct sk_buff *skb, unsigned short add_data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = MAX_URLLOGGER_SNI_CACHE_NODE;
	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL &&
		        memcmp(&urllogger_sni_cache[i][j].src_ipv6, src_ip, 16) == 0 &&
		        urllogger_sni_cache[i][j].src_port == src_port &&
		        memcmp(&urllogger_sni_cache[i][j].dst_ipv6, dst_ip, 16) == 0 &&
		        urllogger_sni_cache[i][j].dst_port == dst_port) {
			return -EEXIST;
		} else if (next_to_use == MAX_URLLOGGER_SNI_CACHE_NODE && urllogger_sni_cache[i][j].skb == NULL) {
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
	urllogger_sni_cache[i][next_to_use].add_data_len = add_data_len;
	urllogger_sni_cache[i][next_to_use].skb = skb;
	urllogger_sni_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

static inline struct sk_buff *urllogger_sni_cache_detach(__be32 src_ip, __be16 src_port, __be32 dst_ip, __be16 dst_port, unsigned short *add_data_len)
{
	int i = smp_processor_id();
	int j = 0;
	struct sk_buff *skb = NULL;
	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				consume_skb(urllogger_sni_cache[i][j].skb);
				urllogger_sni_cache[i][j].skb = NULL;
			} else if (urllogger_sni_cache[i][j].src_ip == src_ip &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           urllogger_sni_cache[i][j].dst_ip == dst_ip &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				skb = urllogger_sni_cache[i][j].skb;
				*add_data_len = urllogger_sni_cache[i][j].add_data_len;
				urllogger_sni_cache[i][j].skb = NULL;
				break;
			}
		}
	}
	for (; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				consume_skb(urllogger_sni_cache[i][j].skb);
				urllogger_sni_cache[i][j].skb = NULL;
			}
		}
	}

	return skb;
}

static inline struct sk_buff *urllogger_sni_cache_detach6(struct in6_addr *src_ip, __be16 src_port, struct in6_addr *dst_ip, __be16 dst_port, unsigned short *add_data_len)
{
	int i = smp_processor_id();
	int j = 0;
	struct sk_buff *skb = NULL;
	for (j = 0; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				consume_skb(urllogger_sni_cache[i][j].skb);
				urllogger_sni_cache[i][j].skb = NULL;
			} else if (memcmp(&urllogger_sni_cache[i][j].src_ipv6, src_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].src_port == src_port &&
			           memcmp(&urllogger_sni_cache[i][j].dst_ipv6, dst_ip, 16) == 0 &&
			           urllogger_sni_cache[i][j].dst_port == dst_port) {
				skb = urllogger_sni_cache[i][j].skb;
				*add_data_len = urllogger_sni_cache[i][j].add_data_len;
				urllogger_sni_cache[i][j].skb = NULL;
				break;
			}
		}
	}
	for (; j < MAX_URLLOGGER_SNI_CACHE_NODE; j++) {
		if (urllogger_sni_cache[i][j].skb != NULL) {
			if (time_after(jiffies, urllogger_sni_cache[i][j].active_jiffies + URLLOGGER_CACHE_TIMEOUT * HZ)) {
				consume_skb(urllogger_sni_cache[i][j].skb);
				urllogger_sni_cache[i][j].skb = NULL;
			}
		}
	}

	return skb;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_urllogger_hook_v1(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_urllogger_hook_v1(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_urllogger_hook_v1(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#else
static unsigned int natflow_urllogger_hook_v1(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	const struct net_device *out = state->out;
#endif
#endif
	int ret = NF_ACCEPT;
	enum ip_conntrack_info ctinfo;
	int data_len;
	unsigned char *data;
	natflow_t *nf;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	int bridge = 0;

	if (!urllogger_store_enable)
		return NF_ACCEPT;

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
	if (NULL == ct)
		goto out;

	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		goto out;

	if ((ct->status & IPS_NATFLOW_URLLOGGER_HANDLED))
		goto out;

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == AF_INET6)
		goto urllogger_hook_ipv6_main;

	iph = ip_hdr(skb);
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
	if (nf && !(nf->status & NF_FF_URLLOGGER_USE)) {
		/* tell FF -urllogger- need this conn */
		simple_set_bit(NF_FF_URLLOGGER_USE_BIT, &nf->status);
	}

	data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
	if (data_len > 0) {
		struct sk_buff *prev_skb = NULL;
		unsigned char *host = NULL;
		int host_len;
		unsigned short add_data_len = 0;

		if (skb_try_make_writable(skb, skb->len)) {
			goto out;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		prev_skb = urllogger_sni_cache_detach(iph->saddr, TCPH(l4)->source, iph->daddr, TCPH(l4)->dest, &add_data_len);
		if (prev_skb) {
			struct iphdr *prev_iph = ip_hdr(prev_skb);
			void *prev_l4 = (void *)prev_iph + prev_iph->ihl * 4;
			int prev_data_len = ntohs(prev_iph->tot_len) - (prev_iph->ihl * 4 + TCPH(prev_l4)->doff * 4);

			data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;

			if (ntohl(TCPH(l4)->seq) == ntohl(TCPH(prev_l4)->seq) + prev_data_len + add_data_len) {
				int needmore = 0;
				if (skb_tailroom(prev_skb) < add_data_len + data_len &&
				        pskb_expand_head(prev_skb, 0, add_data_len + data_len, GFP_ATOMIC)) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": pskb_expand_head failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(prev_skb);
					return NF_ACCEPT;
				}
				prev_iph = ip_hdr(prev_skb);
				prev_l4 = (void *)prev_iph + prev_iph->ihl * 4;

				memcpy(prev_skb->data + prev_skb->len + add_data_len, data, data_len);
				add_data_len += data_len;

				data = prev_skb->data + prev_iph->ihl * 4 + TCPH(prev_l4)->doff * 4;
				host_len = prev_data_len + add_data_len;
				host = tls_sni_search(data, &host_len, &needmore);
				if (!host && needmore == 1) {
					if (add_data_len >= 32 * 1024 ||
					        urllogger_sni_cache_attach(prev_iph->saddr, TCPH(prev_l4)->source,
					                                   prev_iph->daddr, TCPH(prev_l4)->dest, prev_skb, add_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": urllogger_sni_cache_attach failed with add_data_len=%u\n", DEBUG_TCP_ARG(iph,l4), add_data_len);
						consume_skb(prev_skb);
						goto __urllogger_ip_skip;
					}
					return NF_ACCEPT;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(TCPH(prev_l4)->seq)) {
				if (urllogger_sni_cache_attach(prev_iph->saddr, TCPH(prev_l4)->source,
				                               prev_iph->daddr, TCPH(prev_l4)->dest, prev_skb, add_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": urllogger_sni_cache_attach failed\n", DEBUG_TCP_ARG(iph,l4));
					consume_skb(prev_skb);
					goto __urllogger_ip_skip;
				}
				return NF_ACCEPT;
			} else {
				consume_skb(prev_skb);
				goto __urllogger_ip_skip;
			}
		} else {
			int needmore = 0;
			data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
			host_len = data_len;
			host = tls_sni_search(data, &host_len, &needmore);
			if (!host && needmore == 1) {
				prev_skb = skb_copy(skb, GFP_ATOMIC);
				if (prev_skb) {
					if (urllogger_sni_cache_attach(iph->saddr, TCPH(l4)->source, iph->daddr, TCPH(l4)->dest, prev_skb, 0) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": urllogger_sni_cache_attach failed\n", DEBUG_TCP_ARG(iph,l4));
						consume_skb(prev_skb);
						goto __urllogger_ip_skip;
					}
				}
				return NF_ACCEPT;
			}
		}

		data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
__urllogger_ip_skip:
		/* check one packet only */
		set_bit(IPS_NATFLOW_URLLOGGER_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_URLLOGGER_USE)) {
			/* tell FF -urllogger- has finished it's job */
			simple_clear_bit(NF_FF_URLLOGGER_USE_BIT, &nf->status);
		}

		if (host) {
			int rule_id = 0;
			struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
			if (!url)
				goto out;
			INIT_LIST_HEAD(&url->list);
			url->host_len = urlinfo_copy_host_tolower(url->data, host, host_len);
			url->data[host_len] = 0;
			url->data_len = host_len + 1;
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
			url->acl_action = URLINFO_ACL_ACTION_RECORD;
			do {
				int ret_ip;
				int ret_mac;
				for (; rule_id < acl_rule_max; ) {
					char ipset_name[32];

					snprintf(ipset_name, 32, "host_acl_rule%u_ipv4", rule_id);
					ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
					if (ret_ip > 0) {
						break;
					}

					snprintf(ipset_name, 32, "host_acl_rule%u_mac", rule_id);
					ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
					if (ret_mac > 0) {
						break;
					}

					if (ret_ip == -EINVAL && ret_mac == -EINVAL) {
						break;
					}

					rule_id++;
				}
				if (rule_id < acl_rule_max) {
					if (urllogger_acl(url, rule_id) == 1) {
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
							}
							break;
						}
					}
				} else {
					break;
				}

				rule_id++;
			} while (1);

			urllogger_store_record(url);
		} else {
			unsigned char *uri = NULL;
			int rule_id = 0;
			int uri_len = 0;
			int http_method = 0;

			host_len = data_len;
			if (http_url_search(data, &host_len, &host, &uri_len, &uri, &http_method) > 0) {
				struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + uri_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
				if (!url)
					goto out;
				INIT_LIST_HEAD(&url->list);
				url->host_len = urlinfo_copy_host_tolower(url->data, host, host_len);
				memcpy(url->data + host_len, uri, uri_len);
				url->data[host_len + uri_len] = 0;
				url->data_len = host_len + uri_len + 1;
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
				url->http_method = http_method;
				url->hits = 1;
				memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

				url->acl_idx = 64; /* 64 = before acl matching */
				url->acl_action = URLINFO_ACL_ACTION_RECORD;
				do {
					int ret_ip;
					int ret_mac;
					for (; rule_id < acl_rule_max; ) {
						char ipset_name[32];

						snprintf(ipset_name, 32, "host_acl_rule%u_ipv4", rule_id);
						ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
						if (ret_ip > 0) {
							break;
						}

						snprintf(ipset_name, 32, "host_acl_rule%u_mac", rule_id);
						ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
						if (ret_mac > 0) {
							break;
						}

						if (ret_ip == -EINVAL && ret_mac == -EINVAL) {
							break;
						}

						rule_id++;
					}
					if (rule_id < acl_rule_max) {
						if (urllogger_acl(url, rule_id) == 1) {
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
								}
								break;
							}
						}
					} else {
						break;
					}

					rule_id++;
				} while (1);

				urllogger_store_record(url);
			}
		}
	}
	goto out;

urllogger_hook_ipv6_main:
	iph = (void *)ipv6_hdr(skb);
	if (IPV6H->version != 6 || IPV6H->nexthdr != IPPROTO_TCP) {
		goto out;
	}

	if (skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr))) {
		goto out;
	}
	iph = (void *)ipv6_hdr(skb);
	l4 = (void *)iph + sizeof(struct ipv6hdr);

	/* pause fastnat path */
	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_URLLOGGER_USE)) {
		/* tell FF -urllogger- need this conn */
		simple_set_bit(NF_FF_URLLOGGER_USE_BIT, &nf->status);
	}

	data_len = ntohs(IPV6H->payload_len) - TCPH(l4)->doff * 4;
	if (data_len > 0) {
		struct sk_buff *prev_skb = NULL;
		unsigned char *host = NULL;
		int host_len;
		unsigned short add_data_len = 0;

		if (skb_try_make_writable(skb, skb->len)) {
			goto out;
		}
		iph = (void *)ipv6_hdr(skb);
		l4 = (void *)iph + sizeof(struct ipv6hdr);

		prev_skb = urllogger_sni_cache_detach6(&IPV6H->saddr, TCPH(l4)->source, &IPV6H->daddr, TCPH(l4)->dest, &add_data_len);
		if (prev_skb) {
			struct ipv6hdr *prev_iph = ipv6_hdr(prev_skb);
			void *prev_l4 = (void *)prev_iph + sizeof(struct ipv6hdr);
			int prev_data_len = ntohs(prev_iph->payload_len) - TCPH(prev_l4)->doff * 4;

			data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;

			if (ntohl(TCPH(l4)->seq) == ntohl(TCPH(prev_l4)->seq) + prev_data_len + add_data_len) {
				int needmore = 0;
				if (skb_tailroom(prev_skb) < add_data_len + data_len &&
				        pskb_expand_head(prev_skb, 0, add_data_len + data_len, GFP_ATOMIC)) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": pskb_expand_head failed\n", DEBUG_TCP_ARG6(iph,l4));
					consume_skb(prev_skb);
					return NF_ACCEPT;
				}
				prev_iph = ipv6_hdr(prev_skb);
				prev_l4 = (void *)prev_iph + sizeof(struct ipv6hdr);

				memcpy(prev_skb->data + prev_skb->len + add_data_len, data, data_len);
				add_data_len += data_len;

				data = prev_skb->data + sizeof(struct ipv6hdr) + TCPH(prev_l4)->doff * 4;
				host_len = prev_data_len + add_data_len;
				host = tls_sni_search(data, &host_len, &needmore);
				if (!host && needmore == 1) {
					if (add_data_len >= 32 * 1024 ||
					        urllogger_sni_cache_attach6(&prev_iph->saddr, TCPH(prev_l4)->source,
					                                    &prev_iph->daddr, TCPH(prev_l4)->dest, prev_skb, add_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": urllogger_sni_cache_attach6 failed with add_data_len=%u\n", DEBUG_TCP_ARG6(iph,l4), add_data_len);
						consume_skb(prev_skb);
						goto __urllogger_ipv6_skip;
					}
					return NF_ACCEPT;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(TCPH(prev_l4)->seq)) {
				if (urllogger_sni_cache_attach6(&prev_iph->saddr, TCPH(prev_l4)->source,
				                                &prev_iph->daddr, TCPH(prev_l4)->dest, prev_skb, add_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": urllogger_sni_cache_attach6 failed\n", DEBUG_TCP_ARG6(iph,l4));
					consume_skb(prev_skb);
					goto __urllogger_ipv6_skip;
				}
				return NF_ACCEPT;
			} else {
				consume_skb(prev_skb);
				goto __urllogger_ipv6_skip;
			}
		} else {
			int needmore = 0;
			data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;
			host_len = data_len;
			host = tls_sni_search(data, &host_len, &needmore);
			if (!host && needmore == 1) {
				prev_skb = skb_copy(skb, GFP_ATOMIC);
				if (prev_skb) {
					if (urllogger_sni_cache_attach6(&IPV6H->saddr, TCPH(l4)->source, &IPV6H->daddr, TCPH(l4)->dest, prev_skb, 0) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": urllogger_sni_cache_attach6 failed\n", DEBUG_TCP_ARG6(iph,l4));
						consume_skb(prev_skb);
						goto __urllogger_ipv6_skip;
					}
				}
				return NF_ACCEPT;
			}
		}

		data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;
__urllogger_ipv6_skip:
		/* check one packet only */
		set_bit(IPS_NATFLOW_URLLOGGER_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_URLLOGGER_USE)) {
			/* tell FF -urllogger- has finished it's job */
			simple_clear_bit(NF_FF_URLLOGGER_USE_BIT, &nf->status);
		}

		if (host) {
			int rule_id = 0;
			struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
			if (!url)
				goto out;
			INIT_LIST_HEAD(&url->list);
			url->host_len = urlinfo_copy_host_tolower(url->data, host, host_len);
			url->data[host_len] = 0;
			url->data_len = host_len + 1;
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
			url->acl_action = URLINFO_ACL_ACTION_RECORD;
			do {
				int ret_ip;
				int ret_mac;
				for (; rule_id < acl_rule_max; ) {
					char ipset_name[32];

					snprintf(ipset_name, 32, "host_acl_rule%u_ipv6", rule_id);
					ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
					if (ret_ip > 0) {
						break;
					}

					snprintf(ipset_name, 32, "host_acl_rule%u_mac", rule_id);
					ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
					if (ret_mac > 0) {
						break;
					}

					if (ret_ip == -EINVAL && ret_mac == -EINVAL) {
						break;
					}

					rule_id++;
				}
				if (rule_id < acl_rule_max) {
					if (urllogger_acl(url, rule_id) == 1) {
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
							}
							break;
						}
					}
				} else {
					break;
				}

				rule_id++;
			} while (1);

			urllogger_store_record(url);
		} else {
			unsigned char *uri = NULL;
			int rule_id = 0;
			int uri_len = 0;
			int http_method = 0;

			host_len = data_len;
			if (http_url_search(data, &host_len, &host, &uri_len, &uri, &http_method) > 0) {
				struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + uri_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
				if (!url)
					goto out;
				INIT_LIST_HEAD(&url->list);
				url->host_len = urlinfo_copy_host_tolower(url->data, host, host_len);
				memcpy(url->data + host_len, uri, uri_len);
				url->data[host_len + uri_len] = 0;
				url->data_len = host_len + uri_len + 1;
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
				url->http_method = http_method;
				url->hits = 1;
				memcpy(url->mac, eth_hdr(skb)->h_source, ETH_ALEN);

				url->acl_idx = 64; /* 64 = before acl matching */
				url->acl_action = URLINFO_ACL_ACTION_RECORD;
				do {
					int ret_ip;
					int ret_mac;
					for (; rule_id < acl_rule_max; ) {
						char ipset_name[32];

						snprintf(ipset_name, 32, "host_acl_rule%u_ipv6", rule_id);
						ret_ip = IP_SET_test_src_ip(state, in, out, skb, ipset_name);
						if (ret_ip > 0) {
							break;
						}

						snprintf(ipset_name, 32, "host_acl_rule%u_mac", rule_id);
						ret_mac = IP_SET_test_src_mac(state, in, out, skb, ipset_name);
						if (ret_mac > 0) {
							break;
						}

						if (ret_ip == -EINVAL && ret_mac == -EINVAL) {
							break;
						}

						rule_id++;
					}
					if (rule_id < acl_rule_max) {
						if (urllogger_acl(url, rule_id) == 1) {
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
								}
								break;
							}
						}
					} else {
						break;
					}

					rule_id++;
				} while (1);

				urllogger_store_record(url);
			}
		}
	}

out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	return ret;
}

static struct nf_hook_ops urllogger_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_urllogger_hook_v1,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_urllogger_hook_v1,
		.pf = AF_INET6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER - 10,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_urllogger_hook_v1,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER - 10,
	},
};

struct urllogger_user {
	struct mutex lock;
	unsigned char data[0];
};
#define URLLOGGER_MEMSIZE ALIGN(sizeof(struct urllogger_user), 2048)
#define URLLOGGER_DATALEN (URLLOGGER_MEMSIZE - sizeof(struct urllogger_user))

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
		urllogger_store_clear();
		goto done;
	}

	NATFLOW_println("ignoring line[%s]", data);
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
		/* timestamp, mac,              sip,            sport,dip,            dport,hits, meth,type,acl_idx,acl_action, url\n
		   4294967295,FF:AA:BB:CC:DD:EE,123.123.123.123,65535,111.111.111.111,65535,65535,POST,HTTP,64,1,url\n
		   ----------------------------------------------------------------------------------------------94bytes + 48bytes(if ipv6)
		 */
		if (94 + 48 + url->data_len + 1 /* \n */ <= URLLOGGER_DATALEN) {
			if ((url->flags & URLINFO_IPV6)) {
				len = sprintf(user->data, "%u,%02X:%02X:%02X:%02X:%02X:%02X,%pI6,%u,%pI6,%u,%u,%s,%s,%u,%u,%s\n",
				              url->timestamp, url->mac[0], url->mac[1], url->mac[2], url->mac[3], url->mac[4], url->mac[5],
				              &url->sipv6, ntohs(url->sport), &url->dipv6, ntohs(url->dport), url->hits,
				              NATFLOW_http_method[url->http_method], (url->flags & URLINFO_HTTPS) ? "SSL" : "HTTP", url->acl_idx, url->acl_action, url->data);
			} else {
				len = sprintf(user->data, "%u,%02X:%02X:%02X:%02X:%02X:%02X,%pI4,%u,%pI4,%u,%u,%s,%s,%u,%u,%s\n",
				              url->timestamp, url->mac[0], url->mac[1], url->mac[2], url->mac[3], url->mac[4], url->mac[5],
				              &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->hits,
				              NATFLOW_http_method[url->http_method], (url->flags & URLINFO_HTTPS) ? "SSL" : "HTTP", url->acl_idx, url->acl_action, url->data);
			}
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

	//set nonseekable
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

const struct file_operations urllogger_fops = {
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
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
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

static void *hostacl_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;
	char *hostacl_ctl_buffer = m->private;

	if ((*pos) == 0) {
		n = snprintf(hostacl_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Usage:\n"
		             "#    clear -- clear all existing acl rule(s)\n"
		             "#    add acl=<id>,<act>,<host> --add one rule\n"
		             "#    IPSET format: host_acl_rule<id>_<fml>\n"
		             "#    <fml>=ipv4/ipv6/mac\n"
		             "#\n"
		             "\n");
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

static void *hostacl_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return hostacl_start(m, pos);
	}
	return NULL;
}

static void hostacl_stop(struct seq_file *m, void *v)
{
}

static int hostacl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations hostacl_seq_ops = {
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
		acl_rule_clear();
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
							unsigned char *new_buffer;
							ssize_t add_size = 0;
							if (acl_rule_node[idx].acl_buffer == NULL) {
								new_buffer = kmalloc(ACL_RULE_ALLOC_SIZE, GFP_KERNEL);
								if (new_buffer == NULL) {
									return -ENOMEM;
								}
								new_buffer[0] = 0;
								acl_rule_node[idx].acl_buffer_size = ACL_RULE_ALLOC_SIZE;
								acl_rule_node[idx].acl_buffer_len = 1;
								acl_rule_node[idx].acl_buffer = new_buffer;
							}
							while (acl_rule_node[idx].acl_buffer_size + add_size < acl_rule_node[idx].acl_buffer_len + n + 1) {
								add_size += ACL_RULE_ALLOC_SIZE;
							}
							new_buffer = acl_rule_node[idx].acl_buffer;
							if (add_size > 0) {
								unsigned char *old_buffer = acl_rule_node[idx].acl_buffer;
								new_buffer = kmalloc(acl_rule_node[idx].acl_buffer_size + add_size, GFP_KERNEL);
								if (new_buffer == NULL) {
									return -ENOMEM;
								}
								memcpy(new_buffer, acl_rule_node[idx].acl_buffer, acl_rule_node[idx].acl_buffer_len);
								acl_rule_node[idx].acl_buffer = new_buffer;
								synchronize_rcu();
								kfree(old_buffer);
							}
							new_buffer[acl_rule_node[idx].acl_buffer_len + n] = 0;
							new_buffer[acl_rule_node[idx].acl_buffer_len - 1] = (unsigned char)(0x80|act|idx);
							memcpy(new_buffer + acl_rule_node[idx].acl_buffer_len, data + i, n);
							acl_rule_node[idx].acl_buffer_len += n + 1;
							if (idx >= acl_rule_max) {
								acl_rule_max =  idx + 1;
							}
							goto done;
						}
					}
				}
			}
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

static ssize_t hostacl_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static int hostacl_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
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

static struct file_operations hostacl_fops = {
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
		NATFLOW_println("alloc_chrdev_region failed!");
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
		NATFLOW_println("adding chardev, error=%d", ret);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	hostacl_class = class_create(THIS_MODULE, "hostacl_class");
#else
	hostacl_class = class_create("hostacl_class");
#endif
	if (IS_ERR(hostacl_class)) {
		NATFLOW_println("failed in creating class");
		ret = -EINVAL;
		goto class_create_failed;
	}

	hostacl_dev = device_create(hostacl_class, NULL, devno, NULL, hostacl_dev_name);
	if (IS_ERR(hostacl_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	return 0;

	//device_destroy(hostacl_class, devno);
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
}

int natflow_urllogger_init(void)
{
	int ret = 0;
	dev_t devno;

	urllogger_sni_cache_init();

	if (urllogger_major > 0) {
		devno = MKDEV(urllogger_major, urllogger_minor);
		ret = register_chrdev_region(devno, 1, urllogger_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, urllogger_minor, 1, urllogger_dev_name);
	}
	if (ret < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
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
		NATFLOW_println("adding chardev, error=%d", ret);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	urllogger_class = class_create(THIS_MODULE, "urllogger_class");
#else
	urllogger_class = class_create("urllogger_class");
#endif
	if (IS_ERR(urllogger_class)) {
		NATFLOW_println("failed in creating class");
		ret = -EINVAL;
		goto class_create_failed;
	}

	urllogger_dev = device_create(urllogger_class, NULL, devno, NULL, urllogger_dev_name);
	if (IS_ERR(urllogger_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	ret = nf_register_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	ret = natflow_hostacl_init();
	if (ret != 0)
		goto natflow_hostacl_init_failed;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
	urllogger_table_header = register_sysctl_table(urllogger_root_table);
#else
	urllogger_table_header = register_sysctl("urllogger_store", urllogger_table);
#endif

	return 0;

	//natflow_hostacl_exit();
natflow_hostacl_init_failed:
	nf_unregister_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
nf_register_hooks_failed:
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

	natflow_hostacl_exit();

	devno = MKDEV(urllogger_major, urllogger_minor);

	device_destroy(urllogger_class, devno);
	class_destroy(urllogger_class);
	cdev_del(&urllogger_cdev);
	unregister_chrdev_region(devno, 1);

	nf_unregister_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
	urllogger_store_clear();

	unregister_sysctl_table(urllogger_table_header);

	urllogger_sni_cache_cleanup();
}
