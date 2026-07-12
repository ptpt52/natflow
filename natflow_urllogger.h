/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Tue, 22 Jun 2021 22:50:41 +0800
 */
#ifndef _NATFLOW_URLLOGGER_H_
#define _NATFLOW_URLLOGGER_H_

#include <linux/types.h>

struct net_device;
struct natflow_l7_host_view;
struct natflow_l7_packet_view;
struct nf_hook_state;

#define NATFLOW_URLLOGGER_EVENT_VERSION 2

enum natflow_urllogger_event_source {
	NATFLOW_URLLOGGER_EVENT_SOURCE_HTTP = 1,
	NATFLOW_URLLOGGER_EVENT_SOURCE_TLS = 2,
	NATFLOW_URLLOGGER_EVENT_SOURCE_HTTPS = NATFLOW_URLLOGGER_EVENT_SOURCE_TLS,
	NATFLOW_URLLOGGER_EVENT_SOURCE_QUIC = 3,
};

enum natflow_urllogger_method {
	NATFLOW_URLLOGGER_METHOD_NONE = 0,
	NATFLOW_URLLOGGER_METHOD_GET = 1,
	NATFLOW_URLLOGGER_METHOD_POST = 2,
	NATFLOW_URLLOGGER_METHOD_HEAD = 3,
};

enum natflow_urllogger_acl_action {
	NATFLOW_URLLOGGER_ACL_ACTION_RECORD = 0,
	NATFLOW_URLLOGGER_ACL_ACTION_DROP = 1,
	NATFLOW_URLLOGGER_ACL_ACTION_RESET = 2,
	NATFLOW_URLLOGGER_ACL_ACTION_REDIRECT = 3,
};

struct natflow_urllogger_event_hdr {
	__u16 version;
	__u16 header_len;
	__u16 record_len;
	__u16 family;
	__u32 timestamp;
	__u16 sport;
	__u16 dport;
	__u8 sip[16];
	__u8 dip[16];
	__u8 mac[6];
	__u16 hits;
	__u16 host_len;
	__u8 method;
	__u8 source;
	__u8 acl_idx;
	__u8 acl_action;
} __packed;

extern int natflow_urllogger_init(void);
extern void natflow_urllogger_exit(void);
extern int natflow_urllogger_url_enabled(void);
#if NATFLOW_HAVE_IP_SET_STATE_API
extern unsigned int natflow_urllogger_consume_host_view(unsigned int hooknum,
        const struct nf_hook_state *state,
        const struct natflow_l7_packet_view *view,
        const struct natflow_l7_host_view *host_view,
        const struct net_device *reply_dev,
        int bridge);
#else
extern unsigned int natflow_urllogger_consume_host_view(unsigned int hooknum,
        const struct net_device *in,
        const struct net_device *out,
        const struct natflow_l7_packet_view *view,
        const struct natflow_l7_host_view *host_view,
        const struct net_device *reply_dev,
        int bridge);
#endif

#endif /* _NATFLOW_URLLOGGER_H_ */
