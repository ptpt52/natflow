/*
 * Shared L7 hook lifecycle.
 *
 * The first implementation step only centralizes hook ownership. Legacy URL
 * parsing and Host ACL handling still live in natflow_urllogger.c.
 */
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/string.h>
#include "natflow_common.h"
#include "natflow_l7.h"
#if defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_urllogger.h"
#endif

static int natflow_l7_started;

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

int natflow_l7_init(void)
{
	int ret;

	ret = natflow_ct_ext_layout_validate();
	if (ret != 0)
		return ret;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	ret = natflow_urllogger_hooks_register();
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
	natflow_urllogger_hooks_unregister();
#endif
	natflow_l7_started = 0;
}
