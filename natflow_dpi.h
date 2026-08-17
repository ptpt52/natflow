/*
 * Natflow DPI control and event skeleton.
 */
#ifndef _NATFLOW_DPI_H_
#define _NATFLOW_DPI_H_

#include <linux/types.h>

struct nf_conn;
struct natflow_l7_packet_view;

#define NATFLOW_DPI_CTL_MAX_LINE 512
#define NATFLOW_DPI_EVENT_VERSION 3
#define NATFLOW_DPI_EVENT_HEADER_LEN 78
#define NATFLOW_DPI_HOST_MAX_LEN 253
#define NATFLOW_DPI_CATALOG_REVISION 3

/*
 * Fixed application IDs are stable DPI UAPI.  Published values must never be
 * renumbered or reused.  app_id 0 always means unknown or pending.
 */
enum natflow_dpi_app_id {
	NATFLOW_DPI_APP_UNKNOWN = 0,
	NATFLOW_DPI_APP_DNS = 0x00000001,
	NATFLOW_DPI_APP_SSH = 0x00000002,
	NATFLOW_DPI_APP_WIREGUARD = 0x00000003,
	NATFLOW_DPI_APP_STUN = 0x00000004,
	NATFLOW_DPI_APP_TURN = 0x00000005,
	NATFLOW_DPI_APP_BITTORRENT = 0x00000006,
	NATFLOW_DPI_APP_FTP = 0x00000007,
	NATFLOW_DPI_APP_SMTP = 0x00000008,
	NATFLOW_DPI_APP_POP3 = 0x00000009,
	NATFLOW_DPI_APP_IMAP = 0x0000000a,
	NATFLOW_DPI_APP_SIP = 0x0000000b,
	NATFLOW_DPI_APP_RTSP = 0x0000000c,
	NATFLOW_DPI_APP_MQTT = 0x0000000d,
	NATFLOW_DPI_APP_RESP = 0x0000000e,
	NATFLOW_DPI_APP_MYSQL = 0x0000000f,
	NATFLOW_DPI_APP_POSTGRESQL = 0x00000010,
	NATFLOW_DPI_APP_RDP = 0x00000011,
	NATFLOW_DPI_APP_SMB = 0x00000012,
	NATFLOW_DPI_APP_NTP = 0x00000013,
	NATFLOW_DPI_APP_SNMP = 0x00000014,
	NATFLOW_DPI_APP_RADIUS = 0x00000015,
	NATFLOW_DPI_APP_TFTP = 0x00000016,
	NATFLOW_DPI_APP_LDAP = 0x00000017,
	NATFLOW_DPI_APP_NFS = 0x00000018,
	NATFLOW_DPI_APP_SOCKS = 0x00000019,
	NATFLOW_DPI_APP_COAP = 0x0000001a,
	NATFLOW_DPI_APP_YOUTUBE = 0x00001001,
	NATFLOW_DPI_APP_NETFLIX = 0x00001002,
	NATFLOW_DPI_APP_IQIYI = 0x00001003,
	NATFLOW_DPI_APP_TENCENT_VIDEO = 0x00001004,
	NATFLOW_DPI_APP_SPOTIFY = 0x00001005,
	NATFLOW_DPI_APP_TELEGRAM = 0x00002001,
	NATFLOW_DPI_APP_WECHAT = 0x00002002,
	NATFLOW_DPI_APP_QQ = 0x00002003,
	NATFLOW_DPI_APP_DINGTALK = 0x00002004,
	NATFLOW_DPI_APP_WHATSAPP = 0x00002005,
	NATFLOW_DPI_APP_MESSENGER = 0x00002006,
	NATFLOW_DPI_APP_DISCORD = 0x00002007,
	NATFLOW_DPI_APP_ZOOM = 0x00002008,
	NATFLOW_DPI_APP_TAOBAO = 0x00004001,
	NATFLOW_DPI_APP_TIKTOK = 0x00005001,
	NATFLOW_DPI_APP_FACEBOOK = 0x00005002,
	NATFLOW_DPI_APP_INSTAGRAM = 0x00005003,
	NATFLOW_DPI_APP_TWITTER = 0x00005004,
	NATFLOW_DPI_APP_WEIBO = 0x00005005,
};

enum natflow_dpi_category_id {
	NATFLOW_DPI_CATEGORY_UNKNOWN = 0,
	NATFLOW_DPI_CATEGORY_INFRASTRUCTURE = 1,
	NATFLOW_DPI_CATEGORY_REMOTE_ACCESS = 2,
	NATFLOW_DPI_CATEGORY_VPN_TUNNEL = 3,
	NATFLOW_DPI_CATEGORY_REALTIME = 4,
	NATFLOW_DPI_CATEGORY_FILE_SHARING = 5,
	NATFLOW_DPI_CATEGORY_FILE_TRANSFER = 6,
	NATFLOW_DPI_CATEGORY_EMAIL = 7,
	NATFLOW_DPI_CATEGORY_VOIP = 8,
	NATFLOW_DPI_CATEGORY_IOT = 9,
	NATFLOW_DPI_CATEGORY_DATABASE = 10,
	NATFLOW_DPI_CATEGORY_STREAMING = 11,
	NATFLOW_DPI_CATEGORY_COMMUNICATION = 12,
	NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK = 13,
	NATFLOW_DPI_CATEGORY_SHOPPING = 14,
};

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
	NATFLOW_DPI_EVENT_SOURCE_FTP = 10,
	NATFLOW_DPI_EVENT_SOURCE_SMTP = 11,
	NATFLOW_DPI_EVENT_SOURCE_POP3 = 12,
	NATFLOW_DPI_EVENT_SOURCE_IMAP = 13,
	NATFLOW_DPI_EVENT_SOURCE_SIP = 14,
	NATFLOW_DPI_EVENT_SOURCE_RTSP = 15,
	NATFLOW_DPI_EVENT_SOURCE_MQTT = 16,
	NATFLOW_DPI_EVENT_SOURCE_RESP = 17,
	NATFLOW_DPI_EVENT_SOURCE_MYSQL = 18,
	NATFLOW_DPI_EVENT_SOURCE_POSTGRESQL = 19,
	NATFLOW_DPI_EVENT_SOURCE_RDP = 20,
	NATFLOW_DPI_EVENT_SOURCE_SMB = 21,
	NATFLOW_DPI_EVENT_SOURCE_DINGTALK = 22,
	NATFLOW_DPI_EVENT_SOURCE_QQ = 23,
	NATFLOW_DPI_EVENT_SOURCE_IQIYI = 24,
	NATFLOW_DPI_EVENT_SOURCE_NTP = 25,
	NATFLOW_DPI_EVENT_SOURCE_SNMP = 26,
	NATFLOW_DPI_EVENT_SOURCE_RADIUS = 27,
	NATFLOW_DPI_EVENT_SOURCE_TFTP = 28,
	NATFLOW_DPI_EVENT_SOURCE_LDAP = 29,
	NATFLOW_DPI_EVENT_SOURCE_NFS = 30,
	NATFLOW_DPI_EVENT_SOURCE_SOCKS = 31,
	NATFLOW_DPI_EVENT_SOURCE_COAP = 32,
	NATFLOW_DPI_EVENT_SOURCE_WHATSAPP = 33,
	NATFLOW_DPI_EVENT_SOURCE_DISCORD = 34,
	NATFLOW_DPI_EVENT_SOURCE_SPOTIFY = 35,
	NATFLOW_DPI_EVENT_SOURCE_ZOOM = 36,
};

struct natflow_dpi_event_hdr {
	__u16 version;
	__u16 header_len;
	__u16 record_len;
	__u16 family;
	__u64 timestamp;
	__u8 l4proto;
	__u8 tuple_dir;
	__u8 evidence_dir;
	__u8 reserved;
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
extern unsigned int natflow_dpi_packet_view_pull_len(unsigned int consumer_mask,
        unsigned char l4proto, unsigned char direction, __be16 server_port,
        unsigned int payload_len);
extern unsigned int natflow_dpi_consume_packet_view(
    const struct natflow_l7_packet_view *view, unsigned int consumer_mask);
extern unsigned int natflow_dpi_consume_local_dns_query(
    const struct natflow_l7_packet_view *view);
extern void natflow_dpi_packet_context_abort(struct nf_conn *ct);
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
