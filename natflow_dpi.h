/*
 * Natflow DPI control and event skeleton.
 */
#ifndef _NATFLOW_DPI_H_
#define _NATFLOW_DPI_H_

#include <linux/types.h>

struct nf_conn;
struct natflow_l7_packet_view;

#define NATFLOW_DPI_CTL_MAX_LINE 512
#define NATFLOW_DPI_EVENT_VERSION 2
#define NATFLOW_DPI_HOST_MAX_LEN 253

enum natflow_dpi_event_reason {
	NATFLOW_DPI_REASON_NONE = 0,
	NATFLOW_DPI_REASON_DISABLED = 1,
	NATFLOW_DPI_REASON_NO_DETECTOR = 2,
	NATFLOW_DPI_REASON_CACHE_FULL = 3,
	NATFLOW_DPI_REASON_NOT_ELIGIBLE = 4,
	NATFLOW_DPI_REASON_MODULE_EXIT = 5,
	NATFLOW_DPI_REASON_MATCHED = 6,
};

enum natflow_dpi_event_source {
	NATFLOW_DPI_EVENT_SOURCE_HTTP = 1,
	NATFLOW_DPI_EVENT_SOURCE_TLS = 2,
	NATFLOW_DPI_EVENT_SOURCE_QUIC = 3,
	NATFLOW_DPI_EVENT_SOURCE_DNS = 4,
	NATFLOW_DPI_EVENT_SOURCE_SSH = 5,
	NATFLOW_DPI_EVENT_SOURCE_WIREGUARD = 6,
	NATFLOW_DPI_EVENT_SOURCE_STUN = 7,
	NATFLOW_DPI_EVENT_SOURCE_TURN = 8,
	NATFLOW_DPI_EVENT_SOURCE_BITTORRENT = 9,
};

struct natflow_dpi_event_hdr {
	__u16 version;
	__u16 header_len;
	__u16 record_len;
	__u16 family;
	__u64 timestamp;
	__u8 l4proto;
	__u8 tuple_dir;
	__u16 reason;
	__u16 sport;
	__u16 dport;
	__u8 sip[16];
	__u8 dip[16];
	__u32 generation;
	__u32 app_id;
	__u32 category_id;
	__u32 rule_id;
	__u32 flags;
} __packed;

extern int natflow_dpi_init(void);
extern void natflow_dpi_exit(void);
extern int natflow_dpi_consumer_enabled(void);
extern int natflow_dpi_host_consumer_enabled(void);
extern int natflow_dpi_packet_consumer_enabled(void);
extern unsigned int natflow_dpi_packet_view_pull_len(unsigned char l4proto,
        __be16 dport, unsigned int payload_len);
extern unsigned int natflow_dpi_consume_packet_view(
        const struct natflow_l7_packet_view *view);
extern void natflow_dpi_classify_host(struct nf_conn *ct,
                                      const unsigned char *host,
                                      unsigned short host_len,
                                      unsigned int source);
extern void natflow_dpi_classify_host_flags(struct nf_conn *ct,
        const unsigned char *host, unsigned short host_len,
        unsigned int source, unsigned int host_flags);
extern void natflow_dpi_classify_host_normalized(struct nf_conn *ct,
        const unsigned char *host, unsigned short host_len,
        unsigned int source);

#endif /* _NATFLOW_DPI_H_ */
