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
#include "natflow_common.h"
#include "natflow_urllogger.h"

static int urllogger_major = 0;
static int urllogger_minor = 0;
static int number_of_devices = 1;
static struct cdev urllogger_cdev;
const char *urllogger_dev_name = "urllogger_queue";
static struct class *urllogger_class;
static struct device *urllogger_dev;

struct urlinfo {
	struct list_head list;
#define URLINFO_NOW ((jiffies - INITIAL_JIFFIES) / HZ)
#define TIMESTAMP_FREQ 10
	unsigned int timestamp;
	__be32 sip;
	__be32 dip;
	__be16 sport;
	__be16 dport;
	unsigned char mac[ETH_ALEN];
#define URLINFO_HTTPS 0x01
	unsigned char flags;
#define NATFLOW_HTTP_NONE 0
#define NATFLOW_HTTP_GET 1
#define NATFLOW_HTTP_POST 2
#define NATFLOW_HTTP_HEAD 3
	unsigned char http_method;
	unsigned short hits;
	unsigned short data_len;
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
		        (url_i->flags & URLINFO_HTTPS) == (url->flags & URLINFO_HTTPS) &&
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

static unsigned char *tls_sni_search(unsigned char *data, int *data_len)
{
	unsigned char *p = data;
	int p_len = *data_len;
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
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	if (p[i + 0] != 0x01) { //HanShake Type NOT Client Hello
		return NULL;
	}
	i += 1;
	if (i >= p_len) return NULL;
	len = (p[i + 0] << 8) + ntohs(get_byte2(p + i + 0 + 1)); //hanshake_len
	i += 1 + 2;
	if (i >= p_len) return NULL;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	i += 2 + 32;
	if (i >= p_len) return NULL; //tls_v, random
	i += 1 + p[i + 0];
	if (i >= p_len) return NULL; //session id
	i += 2 + ntohs(get_byte2(p + i + 0));
	if (i >= p_len) return NULL; //Cipher Suites
	i += 1 + p[i + 0];
	if (i >= p_len) return NULL; //Compression Methods

	len = ntohs(get_byte2(p + i + 0)); //ext_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	while (i < p_len) {
		if (get_byte2(p + i + 0) != __constant_htons(0)) {
			i += 2 + 2 + ntohs(get_byte2(p + i + 0 + 2));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 2)); //sn_len
		i = i + 2 + 2;
		if (i + len > p_len) return NULL;

		p = p + i;
		p_len = len;
		i = 0;
		break;
	}
	if (i >= p_len) return NULL;

	len = ntohs(get_byte2(p + i + 0)); //snl_len
	i += 2;
	if (i + len > p_len) return NULL;

	p = p + i;
	p_len = len;
	i = 0;

	while (i < p_len) {
		if (p[i + 0] != 0) {
			i += 1 + 2 + ntohs(get_byte2(p + i + 0 + 1));
			continue;
		}
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 1 + 2;
		if (i + len > p_len) return NULL;

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
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_urllogger_hook_v1(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *out = state->out;
#endif
#endif
	int dir = 0;
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
	} else if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct)
		goto out;

	dir = CTINFO2DIR(ctinfo);
	if (dir != IP_CT_DIR_ORIGINAL)
		goto out;

	if ((ct->status & IPS_NATFLOW_URLLOGGER_HANDLED))
		goto out;

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
		unsigned char *host = NULL;
		int host_len = data_len;

		if (skb_try_make_writable(skb, skb->len)) {
			goto out;
		}
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;

		data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;

		/* check one packet only */
		set_bit(IPS_NATFLOW_URLLOGGER_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_URLLOGGER_USE)) {
			/* tell FF -urllogger- has finished it's job */
			simple_clear_bit(NF_FF_URLLOGGER_USE_BIT, &nf->status);
		}

		/* try to get HTTPS/TLS SNI HOST */
		host = tls_sni_search(data, &host_len);
		if (host) {
			struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
			if (!url)
				goto out;
			INIT_LIST_HEAD(&url->list);
			memcpy(url->data, host, host_len);
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

			//printk("%pI4:%u->%pI4:%u, url=%s, https, t=%u\n", &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->data, url->timestamp);

			urllogger_store_record(url);
		} else {
			unsigned char *uri = NULL;
			int uri_len = 0;
			int http_method = 0;
			if (http_url_search(data, &host_len, &host, &uri_len, &uri, &http_method) > 0) {
				struct urlinfo *url = kmalloc(ALIGN(sizeof(struct urlinfo) + host_len + uri_len + 1, __URLINFO_ALIGN), GFP_ATOMIC);
				if (!url)
					goto out;
				INIT_LIST_HEAD(&url->list);
				memcpy(url->data, host, host_len);
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

				//printk("%pI4:%u->%pI4:%u, url=%s, http, t=%u\n", &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->data, url->timestamp);

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

	return NF_ACCEPT;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
static ssize_t urllogger_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	char *buf;
	struct file *file = iocb->ki_filp;
	struct devkmsg_user *user = file->private_data;
	size_t len = iov_iter_count(from);
	ssize_t ret = len;

	if (!user || len > 1024)
		return -EINVAL;

	buf = kmalloc(len + 1, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	buf[len] = '\0';
	if (!copy_from_iter_full(buf, len, from)) {
		kfree(buf);
		return -EFAULT;
	}

	if (memcmp(buf, "clear", 5) == 0) {
		urllogger_store_clear();
	} else {
		NATFLOW_println("unkown command: %s", buf);
		ret = -EINVAL;
	}

	kfree(buf);
	return ret;
}

#else

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
#endif

/* read one and clear one */
static ssize_t urllogger_read(struct file *file, char __user *buf,
                              size_t count, loff_t *ppos)
{
	size_t len;
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
		/* timestamp, mac,              sip,            sport,dip,            dport,hits, meth,type, url\n
		   4294967295,FF:AA:BB:CC:DD:EE,123.123.123.123,65535,111.111.111.111,65535,65535,POST,HTTP,url\n
		   -----------------------------------------------------------------------------------------89bytes
		 */
		if (89 + url->data_len + 1 /* \n */ <= URLLOGGER_DATALEN) {
			len = sprintf(user->data, "%u,%02X:%02X:%02X:%02X:%02X:%02X,%pI4,%u,%pI4,%u,%u,%s,%s,%s\n",
			              url->timestamp, url->mac[0], url->mac[1], url->mac[2], url->mac[3], url->mac[4], url->mac[5],
			              &url->sip, ntohs(url->sport), &url->dip, ntohs(url->dport), url->hits,
			              NATFLOW_http_method[url->http_method], (url->flags & URLINFO_HTTPS) ? "SSL" : "HTTP", url->data);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	.write_iter = urllogger_write_iter,
#else
	.write = urllogger_write,
#endif
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
	{ }
};

static struct ctl_table urllogger_root_table[] = {
	{
		.procname       = "urllogger_store",
		.maxlen         = 0,
		.mode           = 0555,
		.child          = urllogger_table,
	},
	{ }
};

static struct ctl_table_header *urllogger_table_header;

int natflow_urllogger_init(void)
{
	int ret = 0;
	dev_t devno;

	if (urllogger_major > 0) {
		devno = MKDEV(urllogger_major, urllogger_minor);
		ret = register_chrdev_region(devno, number_of_devices, urllogger_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, urllogger_minor, number_of_devices, urllogger_dev_name);
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
	if (!urllogger_dev) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	ret = nf_register_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	urllogger_table_header = register_sysctl_table(urllogger_root_table);

	return 0;

	//nf_unregister_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
nf_register_hooks_failed:
	device_destroy(urllogger_class, devno);
device_create_failed:
	class_destroy(urllogger_class);
class_create_failed:
	cdev_del(&urllogger_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);
	return ret;
}

void natflow_urllogger_exit(void)
{
	dev_t devno;

	devno = MKDEV(urllogger_major, urllogger_minor);

	device_destroy(urllogger_class, devno);
	class_destroy(urllogger_class);
	cdev_del(&urllogger_cdev);
	unregister_chrdev_region(devno, number_of_devices);

	nf_unregister_hooks(urllogger_hooks, ARRAY_SIZE(urllogger_hooks));
	urllogger_store_clear();

	unregister_sysctl_table(urllogger_table_header);
}
