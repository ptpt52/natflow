/*
 * Shared L7 hook lifecycle.
 *
 * L7 owns the shared hook entry and dispatches active consumers. Legacy URL
 * parsing and Host ACL handling still live in natflow_urllogger.c.
 */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "natflow_common.h"
#include "natflow_l7.h"
#if defined(CONFIG_NATFLOW_DPI) && defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_dpi.h"
#endif
#if defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_urllogger.h"
#endif

static int natflow_l7_started;

static unsigned int natflow_l7_active_consumer_mask(void)
{
	unsigned int mask = 0;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	if (natflow_urllogger_url_enabled())
		mask |= NATFLOW_L7_CONSUMER_URL;
#endif
#if defined(CONFIG_NATFLOW_DPI) && defined(CONFIG_NATFLOW_URLLOGGER)
	if (natflow_dpi_host_consumer_enabled())
		mask |= NATFLOW_L7_CONSUMER_DPI;
#endif

	return mask;
}

unsigned int natflow_l7_consumer_mask(void)
{
	return natflow_l7_active_consumer_mask();
}

int natflow_l7_consumer_active(unsigned int consumer)
{
	return (natflow_l7_active_consumer_mask() & consumer) != 0;
}

#if defined(CONFIG_NATFLOW_URLLOGGER)
#if NATFLOW_HAVE_IP_SET_STATE_API
#define NATFLOW_L7_URL_CONSUMER_ARGS \
	unsigned int hooknum, const struct nf_hook_state *state, struct sk_buff *skb
#define NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, state, in, out) \
	natflow_l7_url_consume_common(hooknum, state, skb)
#define NATFLOW_L7_DISPATCH_URL_VIEW(view, consumer_mask) \
	natflow_l7_dispatch_url_view(hooknum, state, view, consumer_mask)
#else
#define NATFLOW_L7_URL_CONSUMER_ARGS \
	unsigned int hooknum, const struct net_device *in, \
	const struct net_device *out, struct sk_buff *skb
#define NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, state, in, out) \
	natflow_l7_url_consume_common(hooknum, in, out, skb)
#define NATFLOW_L7_DISPATCH_URL_VIEW(view, consumer_mask) \
	natflow_l7_dispatch_url_view(hooknum, in, out, view, consumer_mask)
#endif

#if NATFLOW_HAVE_IP_SET_STATE_API
static unsigned int natflow_l7_dispatch_url_view(unsigned int hooknum,
        const struct nf_hook_state *state,
        const struct natflow_l7_packet_view *view,
        unsigned int consumer_mask)
#else
static unsigned int natflow_l7_dispatch_url_view(unsigned int hooknum,
        const struct net_device *in,
        const struct net_device *out,
        const struct natflow_l7_packet_view *view,
        unsigned int consumer_mask)
#endif
{
	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

#if NATFLOW_HAVE_IP_SET_STATE_API
	return natflow_urllogger_consume_url_view(hooknum, state, view);
#else
	return natflow_urllogger_consume_url_view(hooknum, in, out, view);
#endif
}

static unsigned int natflow_l7_url_consume_common(NATFLOW_L7_URL_CONSUMER_ARGS)
{
	struct natflow_l7_packet_view view;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	unsigned int consumer_mask;
	unsigned int ret = NF_ACCEPT;

	consumer_mask = natflow_l7_active_consumer_mask();
	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

	memset(&view, 0, sizeof(view));
	view.skb = skb;

	if (skb->protocol == __constant_htons(ETH_P_PPP_SES)) {
		if (!pskb_may_pull(skb, PPPOE_SES_HLEN))
			return NF_DROP;

		if (pppoe_proto(skb) == __constant_htons(PPP_IP)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IP);
			skb->network_header += PPPOE_SES_HLEN;
			view.flags |= NATFLOW_L7_PACKET_F_PPPOE;
		} else if (pppoe_proto(skb) == __constant_htons(PPP_IPV6)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IPV6);
			skb->network_header += PPPOE_SES_HLEN;
			view.flags |= NATFLOW_L7_PACKET_F_PPPOE;
		} else {
			return NF_ACCEPT;
		}
	} else if (skb->protocol != __constant_htons(ETH_P_IP) &&
	           skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out;
	if ((ct->status & IPS_NATFLOW_CT_DROP)) {
		ret = NF_DROP;
		goto out;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		goto out;
	if ((ct->status & IPS_NATFLOW_L7_HANDLED))
		goto out;

	view.ct = ct;
	view.consumer_mask = consumer_mask;
	view.l3num = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
	if (view.l3num == AF_INET6)
		view.l3 = ipv6_hdr(skb);
	else
		view.l3 = ip_hdr(skb);

	ret = NATFLOW_L7_DISPATCH_URL_VIEW(&view, consumer_mask);

out:
	if (view.flags & NATFLOW_L7_PACKET_F_PPPOE) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	return ret;
}

#if !defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG
static unsigned int natflow_l7_url_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	return NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, NULL, in, out);
}
#elif NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
static unsigned int natflow_l7_url_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	return NATFLOW_L7_URL_CONSUMER_CALL(ops->hooknum, skb, NULL, in, out);
}
#elif NATFLOW_NF_HOOK_OPS_HAVE_STATE_ARG
static unsigned int natflow_l7_url_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in,
	                                    state->out);
}
#else
static unsigned int natflow_l7_url_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if NATFLOW_NF_HOOK_STATE_HAS_OUTDEV
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in,
	                                    state->out);
#else
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in, NULL);
#endif
}
#endif
#endif /* !CONFIG_NATFLOW_URLLOGGER_LOCAL_IN */

#if defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG
static unsigned int natflow_l7_url_local_in(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
static unsigned int natflow_l7_url_local_in(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif NATFLOW_NF_HOOK_OPS_HAVE_STATE_ARG
static unsigned int natflow_l7_url_local_in(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if !NATFLOW_HAVE_IP_SET_STATE_API
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#else
static unsigned int natflow_l7_url_local_in(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if !NATFLOW_HAVE_IP_SET_STATE_API
	const struct net_device *in = state->in;
#if NATFLOW_NF_HOOK_STATE_HAS_OUTDEV
	const struct net_device *out = state->out;
#else
	const struct net_device *out = NULL;
#endif
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	unsigned int consumer_mask;

	consumer_mask = natflow_l7_active_consumer_mask();
	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num != AF_INET)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG || NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
	return NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, NULL, in, out);
#else
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, in, out);
#endif
}
#endif /* CONFIG_NATFLOW_URLLOGGER_LOCAL_IN */

static struct nf_hook_ops natflow_l7_url_hooks[] = {
#if defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_local_in,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER + 5,
	},
#else
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = AF_INET6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
#endif
};

static int natflow_l7_url_hooks_register(void)
{
	return nf_register_hooks(natflow_l7_url_hooks,
	                         ARRAY_SIZE(natflow_l7_url_hooks));
}

static void natflow_l7_url_hooks_unregister(void)
{
	nf_unregister_hooks(natflow_l7_url_hooks,
	                    ARRAY_SIZE(natflow_l7_url_hooks));
}
#endif /* CONFIG_NATFLOW_URLLOGGER */

static inline int natflow_l7_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return offset <= len && bytes <= len - offset;
}

static inline int natflow_l7_is_digit(unsigned char c)
{
	return c >= '0' && c <= '9';
}

static inline int natflow_l7_host_char_valid(unsigned char c)
{
	return (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') ||
	       c == '-' ||
	       c == '.';
}

ssize_t natflow_l7_copy_host_tolower(unsigned char *dst,
        const unsigned char *src, ssize_t n, unsigned int flags)
{
	ssize_t i = 0;
	ssize_t end = n;
	ssize_t out = 0;
	ssize_t label_len = 0;
	unsigned char last = 0;

	if (n <= 0)
		return -EINVAL;

	if ((flags & NATFLOW_L7_HOST_ALLOW_PORT)) {
		ssize_t colon = -1;
		unsigned int port = 0;

		for (i = 0; i < end; i++) {
			if (src[i] != ':')
				continue;
			if (colon >= 0)
				return -EINVAL;
			colon = i;
		}

		if (colon >= 0) {
			if (colon == 0 || colon + 1 >= end)
				return -EINVAL;
			for (i = colon + 1; i < end; i++) {
				unsigned int digit;

				if (!natflow_l7_is_digit(src[i]))
					return -EINVAL;
				digit = src[i] - '0';
				if (port > 6553 || (port == 6553 && digit > 5))
					return -EINVAL;
				port = port * 10 + digit;
			}
			end = colon;
		}
	}

	if (end > 0 && src[end - 1] == '.')
		end--;
	if (end <= 0 || end > NATFLOW_L7_HOST_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < end; i++) {
		unsigned char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = c - 'A' + 'a';
		if (!natflow_l7_host_char_valid(c))
			return -EINVAL;

		if (c == '.') {
			if (label_len == 0 || label_len > 63 || (out > 0 && last == '-'))
				return -EINVAL;
			if (dst)
				dst[out] = c;
			out++;
			last = c;
			label_len = 0;
			continue;
		}

		if (label_len == 0 && c == '-')
			return -EINVAL;
		label_len++;
		if (label_len > 63)
			return -EINVAL;
		if (dst)
			dst[out] = c;
		out++;
		last = c;
	}

	if (label_len == 0 || (out > 0 && last == '-'))
		return -EINVAL;

	return out;
}

int natflow_l7_uri_validate(const unsigned char *uri, int uri_len)
{
	int i;

	if (uri_len <= 0)
		return -EINVAL;

	for (i = 0; i < uri_len; i++) {
		if (uri[i] < 0x20 || uri[i] == 0x7f)
			return -EINVAL;
	}

	return 0;
}

void natflow_l7_feature_init(struct natflow_l7_feature *feature,
        enum natflow_l7_feature_source source)
{
	memset(feature, 0, sizeof(*feature));
	feature->source = source;
	feature->http_method = NATFLOW_L7_HTTP_NONE;
}

int natflow_l7_feature_set_host(struct natflow_l7_feature *feature,
        const unsigned char *host, int host_len, unsigned int host_flags)
{
	ssize_t copied_host_len;

	if (!feature || !host || host_len <= 0)
		return -EINVAL;

	copied_host_len = natflow_l7_copy_host_tolower(feature->host, host,
	                  host_len, host_flags);
	if (copied_host_len < 0)
		return -EINVAL;

	feature->host_len = copied_host_len;
	feature->host[copied_host_len] = 0;
	feature->host_flags = host_flags;
	feature->raw_host.data = host;
	feature->raw_host.len = host_len;
	feature->flags |= NATFLOW_L7_FEATURE_HOST;

	return 0;
}

int natflow_l7_feature_set_uri(struct natflow_l7_feature *feature,
        const unsigned char *uri, int uri_len)
{
	if (!feature || !uri || natflow_l7_uri_validate(uri, uri_len) < 0)
		return -EINVAL;

	feature->raw_uri.data = uri;
	feature->raw_uri.len = uri_len;
	feature->uri_len = uri_len;
	feature->flags |= NATFLOW_L7_FEATURE_URI;

	return 0;
}

int natflow_l7_host_view_init(struct natflow_l7_host_view *view,
        enum natflow_l7_feature_source source, const unsigned char *host,
        int host_len, unsigned int host_flags)
{
	if (!view || !host || host_len <= 0)
		return -EINVAL;

	memset(view, 0, sizeof(*view));
	view->source = source;
	view->http_method = NATFLOW_L7_HTTP_NONE;
	view->host.data = host;
	view->host.len = host_len;
	view->host_flags = host_flags;

	return 0;
}

int natflow_l7_host_view_from_feature(struct natflow_l7_host_view *view,
        const struct natflow_l7_feature *feature)
{
	int ret;

	if (!feature || !(feature->flags & NATFLOW_L7_FEATURE_HOST))
		return -EINVAL;

	ret = natflow_l7_host_view_init(view, feature->source, feature->host,
	                                feature->host_len, 0);
	if (ret != 0)
		return ret;

	view->http_method = feature->http_method;
	if (feature->flags & NATFLOW_L7_FEATURE_URI)
		view->uri = feature->raw_uri;

	return 0;
}

/* Simple request-line + Host header parser matching legacy URL logger behavior. */
int natflow_l7_http_parse(unsigned char *data, int data_len,
        struct natflow_l7_feature *feature)
{
	unsigned char *host = NULL;
	unsigned char *uri = NULL;
	unsigned char *p = data;
	int host_len;
	int uri_len;
	int p_len = data_len;
	unsigned int i = 0;
	enum natflow_l7_http_method http_method;

	if (!data || !feature)
		return -1;

	natflow_l7_feature_init(feature, NATFLOW_L7_SOURCE_HTTP);

	if (i + 5 > p_len)
		return -1;
	if ((p[i] == 'G' || p[i] == 'g') &&
	        (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	        (p[i + 2] == 'T' || p[i + 2] == 't') &&
	        p[i + 3] == ' ') {
		i += 4;
		http_method = NATFLOW_L7_HTTP_GET;
	} else if ((p[i] == 'P' || p[i] == 'p') &&
	           (p[i + 1] == 'O' || p[i + 1] == 'o') &&
	           (p[i + 2] == 'S' || p[i + 2] == 's') &&
	           (p[i + 3] == 'T' || p[i + 3] == 't') &&
	           p[i + 4] == ' ') {
		i += 5;
		http_method = NATFLOW_L7_HTTP_POST;
	} else if ((p[i] == 'H' || p[i] == 'h') &&
	           (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	           (p[i + 2] == 'A' || p[i + 2] == 'a') &&
	           (p[i + 3] == 'D' || p[i + 3] == 'd') &&
	           p[i + 4] == ' ') {
		i += 5;
		http_method = NATFLOW_L7_HTTP_HEAD;
	} else {
		return 0;
	}

	while (i < p_len && p[i] == ' ')
		i++;
	if (i >= p_len)
		return -1;
	if (p[i] != '/')
		return -1;
	uri = p + i;

	i++;
	while (i < p_len && p[i] != ' ')
		i++;
	if (i >= p_len)
		return -1;
	if (p[i] != ' ')
		return -1;
	uri_len = p + i - uri;
	i++;

	while (i < p_len && p[i] != '\n')
		i++;
	if (i >= p_len)
		return -1;
	i++;

	do {
		if (i + 5 > p_len)
			return -1;
		if ((p[i] == 'H' || p[i] == 'h') &&
		        (p[i + 1] == 'o' || p[i + 1] == 'O') &&
		        (p[i + 2] == 's' || p[i + 2] == 'S') &&
		        (p[i + 3] == 't' || p[i + 3] == 'T') &&
		        p[i + 4] == ':') {
			i += 5;
			while (i < p_len && p[i] == ' ')
				i++;
			if (i >= p_len)
				return -1;
			host = p + i;

			i++;
			while (i < p_len && p[i] != ' ' && p[i] != '\r' && p[i] != '\n')
				i++;
			if (i >= p_len)
				return -1;
			if (p[i] != ' ' && p[i] != '\r' && p[i] != '\n')
				return -1;
			host_len = p + i - host;

			if (natflow_l7_feature_set_host(feature, host, host_len,
			                                NATFLOW_L7_HOST_ALLOW_PORT) < 0)
				return -1;
			feature->raw_uri.data = uri;
			feature->raw_uri.len = uri_len;
			feature->uri_len = uri_len;
			feature->flags |= NATFLOW_L7_FEATURE_URI;
			feature->http_method = http_method;

			return host_len + uri_len;
		}
		while (i < p_len && p[i] != '\n')
			i++;
		i++;
	} while (1);

	return 0;
}

static inline int natflow_l7_tls_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return offset <= len && bytes <= len - offset;
}

enum natflow_l7_tls_search_result natflow_l7_tls_client_hello_search(unsigned char *data,
        int *data_len, unsigned char **host)
{
	unsigned char *p = data;
	unsigned int p_len;
	unsigned int i_data_len;
	unsigned int i = 0;
	unsigned int len;

	*host = NULL;

	if (*data_len <= 0)
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;

	p_len = *data_len;
	i_data_len = p_len;

	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	if (p[i + 0] != 0x01) {
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
		goto need_more;
	len = ((unsigned int)p[i + 0] << 16) |
	      ((unsigned int)p[i + 1] << 8) |
	      ((unsigned int)p[i + 2]);
	i += 1 + 2;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	if (!natflow_l7_tls_has_bytes(i, 2 + 32, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2 + 32, i_data_len))
		goto need_more;
	i += 2 + 32;

	if (!natflow_l7_tls_has_bytes(i, 1, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		goto need_more;
	len = p[i + 0];
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 1, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		goto need_more;
	len = p[i + 0];
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_NO_SNI;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (!natflow_l7_tls_has_bytes(i, 4, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 4, i_data_len))
			goto need_more;
		len = ntohs(get_byte2(p + i + 0 + 2));
		if (ntohs(get_byte2(p + i + 0)) != 0) {
			if (!natflow_l7_tls_has_bytes(i + 4, len, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i + 4, len, i_data_len))
				goto need_more;
			i += 4 + len;
			continue;
		}
		i += 4;
		if (!natflow_l7_tls_has_bytes(i, len, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;

		p = p + i;
		p_len = len;
		i_data_len -= i;
		i = 0;
		break;
	}
	if (i >= i_data_len && i < p_len)
		goto need_more;
	if (i >= p_len)
		return NATFLOW_L7_TLS_SEARCH_NO_SNI;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (!natflow_l7_tls_has_bytes(i, 1, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
			goto need_more;
		if (p[i + 0] != 0) {
			if (!natflow_l7_tls_has_bytes(i, 3, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
				goto need_more;
			len = ntohs(get_byte2(p + i + 0 + 1));
			if (!natflow_l7_tls_has_bytes(i + 3, len, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i + 3, len, i_data_len))
				goto need_more;
			i += 3 + len;
			continue;
		}
		if (!natflow_l7_tls_has_bytes(i, 3, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
			goto need_more;
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 3;
		if (!natflow_l7_tls_has_bytes(i, len, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
			goto need_more;

		*data_len = len;
		*host = p + i;
		return NATFLOW_L7_TLS_SEARCH_FOUND;
	}
	if (i >= i_data_len && i < p_len)
		goto need_more;

	return NATFLOW_L7_TLS_SEARCH_NO_SNI;

need_more:
	return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
}

enum natflow_l7_tls_search_result natflow_l7_tls_sni_search(unsigned char *data,
        int *data_len, unsigned char **host)
{
	unsigned char *p = data;
	unsigned int p_len;
	unsigned int i_data_len;
	unsigned int actual_len;
	unsigned int i = 0;
	unsigned int len;

	*host = NULL;

	if (*data_len <= 0)
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p_len = *data_len;
	i_data_len = p_len;

	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	if (p[i + 0] != 0x16) {
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}
	i += 1 + 2;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len)) {
		if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
			goto need_more;
		if (p[i] != 0x01)
			return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}

	actual_len = min_t(unsigned int, len, i_data_len - i);
	if (actual_len == len && !natflow_l7_tls_has_bytes(0, 4, actual_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (natflow_l7_tls_has_bytes(0, 4, actual_len)) {
		unsigned int handshake_len = ((unsigned int)p[i + 1] << 16) |
		                             ((unsigned int)p[i + 2] << 8) |
		                             ((unsigned int)p[i + 3]);

		if (!natflow_l7_tls_has_bytes(4, handshake_len, len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	}

	*data_len = actual_len;
	return natflow_l7_tls_client_hello_search(p + i, data_len, host);

need_more:
	return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
}

#define NATFLOW_L7_QUIC_V1_VERSION 0x00000001u
#define NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN 4
#define NATFLOW_L7_QUIC_INITIAL_TAG_LEN 16
#define NATFLOW_L7_QUIC_HP_SAMPLE_LEN 16
#define NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT (32 * 1024)

int natflow_l7_quic_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return natflow_l7_has_bytes(offset, bytes, len);
}

static int natflow_l7_quic_read_varint(const unsigned char *data,
        unsigned int data_len, unsigned int *offset, u64 *value)
{
	unsigned int pos = *offset;
	unsigned int len;
	unsigned int i;

	if (!natflow_l7_quic_has_bytes(pos, 1, data_len))
		return -EINVAL;

	len = 1u << (data[pos] >> 6);
	if (!natflow_l7_quic_has_bytes(pos, len, data_len))
		return -EINVAL;

	*value = data[pos] & 0x3f;
	for (i = 1; i < len; i++)
		*value = (*value << 8) | data[pos + i];

	*offset = pos + len;
	return 0;
}

int natflow_l7_quic_initial_parse_info(const unsigned char *data,
        unsigned int data_len, struct natflow_l7_quic_initial_info *info)
{
	unsigned int offset = 0;
	unsigned int scid_len;
	u64 token_len;
	u64 packet_len;

	if (!info || !natflow_l7_quic_has_bytes(offset, 1 + 4 + 1, data_len))
		return -EINVAL;

	if ((data[offset] & 0x80) == 0 || (data[offset] & 0x40) == 0)
		return -ENOENT;
	if ((data[offset] & 0x30) != 0)
		return -ENOENT;
	offset++;

	info->version = ntohl(get_byte4(data + offset));
	offset += 4;
	if (info->version != NATFLOW_L7_QUIC_V1_VERSION)
		return -ENOENT;

	info->dcid_len = data[offset++];
	if (info->dcid_len == 0 || info->dcid_len > NATFLOW_L7_QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (!natflow_l7_quic_has_bytes(offset, info->dcid_len + 1, data_len))
		return -EINVAL;
	memcpy(info->dcid, data + offset, info->dcid_len);
	offset += info->dcid_len;

	scid_len = data[offset++];
	if (scid_len > NATFLOW_L7_QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (!natflow_l7_quic_has_bytes(offset, scid_len, data_len))
		return -EINVAL;
	offset += scid_len;

	if (natflow_l7_quic_read_varint(data, data_len, &offset, &token_len) != 0)
		return -EINVAL;
	if (token_len > UINT_MAX ||
	        !natflow_l7_quic_has_bytes(offset, (unsigned int)token_len, data_len))
		return -EINVAL;
	offset += (unsigned int)token_len;

	if (natflow_l7_quic_read_varint(data, data_len, &offset, &packet_len) != 0)
		return -EINVAL;
	if (packet_len > UINT_MAX ||
	        !natflow_l7_quic_has_bytes(offset, (unsigned int)packet_len, data_len))
		return -EINVAL;
	if (packet_len < NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN + NATFLOW_L7_QUIC_INITIAL_TAG_LEN)
		return -EINVAL;

	info->pn_offset = offset;
	info->packet_len = offset + (unsigned int)packet_len;
	if (!natflow_l7_quic_has_bytes(info->pn_offset + NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN,
	                               NATFLOW_L7_QUIC_HP_SAMPLE_LEN,
	                               info->packet_len))
		return -EINVAL;

	return 0;
}

static int natflow_l7_quic_crypto_data_merge(unsigned char **crypto_data,
        unsigned int *crypto_len, u64 offset,
        const unsigned char *data, unsigned int data_len)
{
	unsigned char *new_data;
	unsigned int new_len;
	unsigned int copy_offset;

	if (offset > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT ||
	        data_len > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT ||
	        offset + data_len > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT)
		return -ENOSPC;

	if (offset > *crypto_len)
		return -EAGAIN;

	new_len = (unsigned int)offset + data_len;
	if (new_len <= *crypto_len)
		return 0;

	new_data = kmalloc(new_len, GFP_ATOMIC);
	if (new_data == NULL)
		return -ENOMEM;

	if (*crypto_data != NULL && *crypto_len > 0)
		memcpy(new_data, *crypto_data, *crypto_len);

	copy_offset = *crypto_len - (unsigned int)offset;
	memcpy(new_data + *crypto_len, data + copy_offset, data_len - copy_offset);

	kfree(*crypto_data);
	*crypto_data = new_data;
	*crypto_len = new_len;
	return 0;
}

static int natflow_l7_quic_skip_ack_frame(const unsigned char *data,
        unsigned int data_len, unsigned int *offset, unsigned char frame_type)
{
	u64 ack_range_count;
	u64 value;
	u64 i;

	if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &ack_range_count) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
		return -EINVAL;
	}

	for (i = 0; i < ack_range_count; i++) {
		if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
			return -EINVAL;
		}
	}

	if (frame_type == 0x03) {
		if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
			return -EINVAL;
		}
	}

	return 0;
}

enum natflow_l7_tls_search_result natflow_l7_quic_crypto_frames_search(const unsigned char *data,
        unsigned int data_len,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len)
{
	enum natflow_l7_tls_search_result sni_result = NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	unsigned int offset = 0;
	int has_crypto = 0;

	while (offset < data_len) {
		unsigned char frame_type = data[offset++];

		switch (frame_type) {
		case 0x00:
		case 0x01:
			break;
		case 0x02:
		case 0x03:
			if (natflow_l7_quic_skip_ack_frame(data, data_len, &offset, frame_type) != 0)
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			break;
		case 0x06: {
			u64 crypto_offset;
			u64 crypto_frame_len;
			int merge_ret;

			if (natflow_l7_quic_read_varint(data, data_len, &offset, &crypto_offset) != 0 ||
			        natflow_l7_quic_read_varint(data, data_len, &offset, &crypto_frame_len) != 0) {
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			}
			if (crypto_frame_len > UINT_MAX ||
			        !natflow_l7_quic_has_bytes(offset, (unsigned int)crypto_frame_len, data_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;

			merge_ret = natflow_l7_quic_crypto_data_merge(crypto_data, crypto_len, crypto_offset,
			            data + offset, (unsigned int)crypto_frame_len);
			offset += (unsigned int)crypto_frame_len;
			if (merge_ret == -EAGAIN) {
				has_crypto = 1;
				continue;
			}
			if (merge_ret != 0)
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;

			has_crypto = 1;
			*host_len = *crypto_len;
			sni_result = natflow_l7_tls_client_hello_search(*crypto_data, host_len, host);
			if (sni_result != NATFLOW_L7_TLS_SEARCH_NEED_MORE)
				return sni_result;
			break;
		}
		default:
			return has_crypto ? sni_result : NATFLOW_L7_TLS_SEARCH_NO_SNI;
		}
	}

	if (*crypto_data != NULL && *crypto_len > 0) {
		*host_len = *crypto_len;
		sni_result = natflow_l7_tls_client_hello_search(*crypto_data, host_len, host);
	}

	return has_crypto ? sni_result : NATFLOW_L7_TLS_SEARCH_NO_SNI;
}

int natflow_l7_dns_parse(const unsigned char *data, unsigned int data_len,
        unsigned char l4proto, struct natflow_l7_feature *feature)
{
	unsigned char host[NATFLOW_L7_HOST_MAX_LEN + 1];
	unsigned int offset;
	unsigned int qdcount;
	unsigned int host_len = 0;
	unsigned int flags;
	unsigned int msg_len;

	if (!data || !feature)
		return -EINVAL;

	natflow_l7_feature_init(feature, NATFLOW_L7_SOURCE_DNS);

	if (l4proto == IPPROTO_TCP) {
		unsigned int available;

		if (data_len < 2)
			return -EINVAL;
		msg_len = ntohs(get_byte2(data));
		if (msg_len < 12)
			return -EINVAL;
		available = data_len - 2;
		data += 2;
		data_len = msg_len < available ? msg_len : available;
	} else if (l4proto != IPPROTO_UDP) {
		return -EINVAL;
	}

	if (data_len < 12)
		return -EINVAL;

	flags = ntohs(get_byte2(data + 2));
	if (flags & 0x8000)
		return 0;
	if ((flags & 0x7800) != 0)
		return 0;
	qdcount = ntohs(get_byte2(data + 4));
	if (qdcount == 0)
		return 0;

	offset = 12;
	do {
		unsigned int label_len;

		if (!natflow_l7_has_bytes(offset, 1, data_len))
			return -EINVAL;
		label_len = data[offset++];
		if (label_len == 0)
			break;
		if ((label_len & 0xc0) != 0 || label_len > 63)
			return -EINVAL;
		if (!natflow_l7_has_bytes(offset, label_len, data_len))
			return -EINVAL;
		if (host_len != 0) {
			if (host_len >= NATFLOW_L7_HOST_MAX_LEN)
				return -EINVAL;
			host[host_len++] = '.';
		}
		if (label_len > NATFLOW_L7_HOST_MAX_LEN - host_len)
			return -EINVAL;
		memcpy(host + host_len, data + offset, label_len);
		host_len += label_len;
		offset += label_len;
	} while (offset < data_len);

	if (host_len == 0)
		return 0;
	if (!natflow_l7_has_bytes(offset, 4, data_len))
		return -EINVAL;

	if (natflow_l7_feature_set_host(feature, host, host_len, 0) < 0)
		return -EINVAL;
	feature->raw_host.data = feature->host;
	feature->raw_host.len = feature->host_len;

	return 1;
}

int natflow_l7_init(void)
{
	int ret;

	ret = natflow_ct_ext_layout_validate();
	if (ret != 0)
		return ret;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	ret = natflow_l7_url_hooks_register();
	if (ret != 0)
		return ret;
#endif

	natflow_l7_started = 1;
	return 0;
}

void natflow_l7_exit(void)
{
	if (!natflow_l7_started)
		return;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	natflow_l7_url_hooks_unregister();
#endif
	natflow_l7_started = 0;
}
