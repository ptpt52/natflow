/*
 * Shared L7 hook lifecycle.
 */
#ifndef _NATFLOW_L7_H_
#define _NATFLOW_L7_H_

#include <linux/types.h>

struct nf_conn;
struct sk_buff;

#define NATFLOW_L7_HOST_MAX_LEN 253
#define NATFLOW_L7_HOST_ALLOW_PORT 0x01

enum natflow_l7_feature_source {
	NATFLOW_L7_SOURCE_NONE = 0,
	NATFLOW_L7_SOURCE_HTTP,
	NATFLOW_L7_SOURCE_TLS,
	NATFLOW_L7_SOURCE_QUIC,
	NATFLOW_L7_SOURCE_DNS,
};

enum natflow_l7_http_method {
	NATFLOW_L7_HTTP_NONE = 0,
	NATFLOW_L7_HTTP_GET = 1,
	NATFLOW_L7_HTTP_POST = 2,
	NATFLOW_L7_HTTP_HEAD = 3,
};

enum natflow_l7_tls_search_result {
	NATFLOW_L7_TLS_SEARCH_FOUND,
	NATFLOW_L7_TLS_SEARCH_NEED_MORE,
	NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO,
	NATFLOW_L7_TLS_SEARCH_NO_SNI,
	NATFLOW_L7_TLS_SEARCH_MALFORMED,
};

struct natflow_l7_data_view {
	const unsigned char *data;
	int len;
};

struct natflow_l7_packet_view {
	struct sk_buff *skb;
	struct nf_conn *ct;
	int l3num;
	unsigned char l4proto;
	void *l3;
	void *l4;
	unsigned char *payload;
	unsigned int payload_len;
};

struct natflow_l7_feature {
	enum natflow_l7_feature_source source;
	unsigned int flags;
#define NATFLOW_L7_FEATURE_HOST 0x01
#define NATFLOW_L7_FEATURE_URI 0x02
	unsigned int host_flags;
	unsigned short host_len;
	unsigned short uri_len;
	enum natflow_l7_http_method http_method;
	struct natflow_l7_data_view raw_host;
	struct natflow_l7_data_view raw_uri;
	unsigned char host[NATFLOW_L7_HOST_MAX_LEN + 1];
};

extern ssize_t natflow_l7_copy_host_tolower(unsigned char *dst,
                                            const unsigned char *src,
                                            ssize_t n,
                                            unsigned int flags);
extern int natflow_l7_uri_validate(const unsigned char *uri, int uri_len);
extern void natflow_l7_feature_init(struct natflow_l7_feature *feature,
                                    enum natflow_l7_feature_source source);
extern int natflow_l7_feature_set_host(struct natflow_l7_feature *feature,
                                       const unsigned char *host,
                                       int host_len,
                                       unsigned int host_flags);
extern int natflow_l7_feature_set_uri(struct natflow_l7_feature *feature,
                                      const unsigned char *uri,
                                      int uri_len);
extern int natflow_l7_http_parse(unsigned char *data, int data_len,
                                 struct natflow_l7_feature *feature);
extern enum natflow_l7_tls_search_result natflow_l7_tls_client_hello_search(unsigned char *data,
        int *data_len, unsigned char **host);
extern enum natflow_l7_tls_search_result natflow_l7_tls_sni_search(unsigned char *data,
        int *data_len, unsigned char **host);
extern int natflow_l7_init(void);
extern void natflow_l7_exit(void);

#endif /* _NATFLOW_L7_H_ */
