/*
 * Shared L7 hook lifecycle.
 */
#ifndef _NATFLOW_L7_H_
#define _NATFLOW_L7_H_

#include <linux/types.h>

struct nf_conn;
struct in6_addr;
struct sk_buff;

#define NATFLOW_L7_HOST_MAX_LEN 253
#define NATFLOW_L7_DNS_QNAME_WIRE_MAX 255
#define NATFLOW_L7_HOST_ALLOW_PORT 0x01
#define NATFLOW_L7_QUIC_MAX_CID_LEN 20
#define NATFLOW_L7_TLS_CACHE_DATA_LIMIT (32 * 1024)

enum natflow_l7_feature_source {
	NATFLOW_L7_SOURCE_NONE = 0,
	NATFLOW_L7_SOURCE_HTTP,
	NATFLOW_L7_SOURCE_TLS,
	NATFLOW_L7_SOURCE_QUIC,
	NATFLOW_L7_SOURCE_DNS,
};

enum natflow_l7_consumer {
	NATFLOW_L7_CONSUMER_URL = 0x01,
	NATFLOW_L7_CONSUMER_DPI_DOMAIN = 0x02,
	NATFLOW_L7_CONSUMER_DPI_PACKET = 0x04,
	NATFLOW_L7_CONSUMER_DPI = NATFLOW_L7_CONSUMER_DPI_DOMAIN |
	                          NATFLOW_L7_CONSUMER_DPI_PACKET,
};

enum natflow_l7_direction {
	NATFLOW_L7_DIR_UNSPEC = 0,
	NATFLOW_L7_DIR_ORIGINAL = 1,
	NATFLOW_L7_DIR_REPLY = 2,
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
	unsigned int flags;
#define NATFLOW_L7_PACKET_F_PPPOE 0x01
	unsigned int consumer_mask;
	int l3num;
	unsigned char l4proto;
	unsigned char direction;
	__be16 sport;
	__be16 dport;
	void *l3;
	void *l4;
	unsigned char *payload;
	unsigned int payload_len;
	unsigned int payload_linear_len;
};

static inline __be16 natflow_l7_packet_client_port(
    const struct natflow_l7_packet_view *view)
{
	if (!view)
		return 0;
	if (view->direction == NATFLOW_L7_DIR_ORIGINAL)
		return view->sport;
	if (view->direction == NATFLOW_L7_DIR_REPLY)
		return view->dport;
	return 0;
}

static inline __be16 natflow_l7_packet_server_port(
    const struct natflow_l7_packet_view *view)
{
	if (!view)
		return 0;
	if (view->direction == NATFLOW_L7_DIR_ORIGINAL)
		return view->dport;
	if (view->direction == NATFLOW_L7_DIR_REPLY)
		return view->sport;
	return 0;
}

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

struct natflow_l7_host_view {
	enum natflow_l7_feature_source source;
	enum natflow_l7_http_method http_method;
	unsigned int host_flags;
	struct natflow_l7_data_view host;
	struct natflow_l7_data_view uri;
};

struct natflow_l7_quic_initial_info {
	unsigned int version;
	unsigned int packet_len;
	unsigned int pn_offset;
	unsigned char dcid_len;
	unsigned char dcid[NATFLOW_L7_QUIC_MAX_CID_LEN];
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
extern int natflow_l7_host_view_init(struct natflow_l7_host_view *view,
                                     enum natflow_l7_feature_source source,
                                     const unsigned char *host,
                                     int host_len,
                                     unsigned int host_flags);
extern int natflow_l7_host_view_from_feature(struct natflow_l7_host_view *view,
        const struct natflow_l7_feature *feature);
extern int natflow_l7_http_parse(unsigned char *data, int data_len,
                                 struct natflow_l7_feature *feature);
extern enum natflow_l7_tls_search_result natflow_l7_tls_client_hello_search(unsigned char *data,
        int *data_len, unsigned char **host);
extern enum natflow_l7_tls_search_result natflow_l7_tls_sni_search(unsigned char *data,
        int *data_len, unsigned char **host);
extern int natflow_l7_tls_cache_attach(__be32 src_ip,
                                       __be16 src_port,
                                       __be32 dst_ip,
                                       __be16 dst_port,
                                       __u32 seq,
                                       unsigned char *data,
                                       unsigned int data_len);
extern int natflow_l7_tls_cache_attach6(const struct in6_addr *src_ip,
                                        __be16 src_port,
                                        const struct in6_addr *dst_ip,
                                        __be16 dst_port,
                                        __u32 seq,
                                        unsigned char *data,
                                        unsigned int data_len);
extern unsigned char *natflow_l7_tls_cache_detach(__be32 src_ip,
        __be16 src_port,
        __be32 dst_ip,
        __be16 dst_port,
        __u32 *seq,
        unsigned int *data_len);
extern unsigned char *natflow_l7_tls_cache_detach6(const struct in6_addr *src_ip,
        __be16 src_port,
        const struct in6_addr *dst_ip,
        __be16 dst_port,
        __u32 *seq,
        unsigned int *data_len);
extern int natflow_l7_quic_has_bytes(unsigned int offset,
                                     unsigned int bytes,
                                     unsigned int len);
extern int natflow_l7_quic_initial_parse_info(const unsigned char *data,
        unsigned int data_len,
        struct natflow_l7_quic_initial_info *info);
extern enum natflow_l7_tls_search_result natflow_l7_quic_initial_sni_search(const unsigned char *data,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len);
extern enum natflow_l7_tls_search_result natflow_l7_quic_crypto_frames_search(const unsigned char *data,
        unsigned int data_len,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len);
extern int natflow_l7_quic_cache_attach(__be32 src_ip,
                                        __be16 src_port,
                                        __be32 dst_ip,
                                        __be16 dst_port,
                                        const struct natflow_l7_quic_initial_info *info,
                                        unsigned char *crypto_data,
                                        unsigned int crypto_len);
extern int natflow_l7_quic_cache_attach6(const struct in6_addr *src_ip,
        __be16 src_port,
        const struct in6_addr *dst_ip,
        __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char *crypto_data,
        unsigned int crypto_len);
extern unsigned char *natflow_l7_quic_cache_detach(__be32 src_ip,
        __be16 src_port,
        __be32 dst_ip,
        __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len);
extern unsigned char *natflow_l7_quic_cache_detach6(const struct in6_addr *src_ip,
        __be16 src_port,
        const struct in6_addr *dst_ip,
        __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len);
extern int natflow_l7_dns_parse(const unsigned char *data,
                                unsigned int data_len,
                                unsigned char l4proto,
                                struct natflow_l7_feature *feature);
extern int natflow_l7_dns_response_parse(const unsigned char *data,
        unsigned int data_len, unsigned char l4proto);
extern unsigned int natflow_l7_consumer_mask(void);
extern int natflow_l7_consumer_active(unsigned int consumer);
extern int natflow_l7_init(void);
extern void natflow_l7_exit(void);

#endif /* _NATFLOW_L7_H_ */
