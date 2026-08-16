/*
 * Natflow DPI control, fixed classifiers, and event queue.
 */
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "natflow_common.h"
#include "natflow_dpi.h"
#include "natflow_l7.h"

enum natflow_dpi_state {
	NATFLOW_DPI_STATE_DISABLED = 0,
	NATFLOW_DPI_STATE_ENABLED = 1,
};

#define NATFLOW_DPI_EVENT_TIMESTAMP_NOW ((u64)((jiffies - INITIAL_JIFFIES) / HZ))

enum natflow_dpi_domain_kind {
	NATFLOW_DPI_DOMAIN_EXACT = 0,
	NATFLOW_DPI_DOMAIN_SUFFIX = 1,
};

enum natflow_dpi_app_machine_status {
	NATFLOW_DPI_APP_MACHINE_EXCLUDED,
	NATFLOW_DPI_APP_MACHINE_TERMINAL,
	NATFLOW_DPI_APP_MACHINE_INTENT,
};

enum natflow_dpi_proto {
	NATFLOW_DPI_PROTO_DNS = 1,
	NATFLOW_DPI_PROTO_SSH = 2,
	NATFLOW_DPI_PROTO_WIREGUARD = 3,
	NATFLOW_DPI_PROTO_STUN = 4,
	NATFLOW_DPI_PROTO_TURN = 5,
	NATFLOW_DPI_PROTO_BITTORRENT = 6,
	NATFLOW_DPI_PROTO_FTP = 7,
	NATFLOW_DPI_PROTO_SMTP = 8,
	NATFLOW_DPI_PROTO_POP3 = 9,
	NATFLOW_DPI_PROTO_IMAP = 10,
	NATFLOW_DPI_PROTO_SIP = 11,
	NATFLOW_DPI_PROTO_RTSP = 12,
	NATFLOW_DPI_PROTO_MQTT = 13,
	NATFLOW_DPI_PROTO_RESP = 14,
	NATFLOW_DPI_PROTO_MYSQL = 15,
	NATFLOW_DPI_PROTO_POSTGRESQL = 16,
	NATFLOW_DPI_PROTO_RDP = 17,
	NATFLOW_DPI_PROTO_SMB = 18,
	NATFLOW_DPI_PROTO_NTP = 19,
	NATFLOW_DPI_PROTO_SNMP = 20,
	NATFLOW_DPI_PROTO_RADIUS = 21,
	NATFLOW_DPI_PROTO_TFTP = 22,
	NATFLOW_DPI_PROTO_LDAP = 23,
	NATFLOW_DPI_PROTO_NFS = 24,
	NATFLOW_DPI_PROTO_SOCKS = 25,
	NATFLOW_DPI_PROTO_COAP = 26,
};

#define NATFLOW_DPI_PROTO_BIT(proto) (1U << ((proto) - 1))
#define NATFLOW_DPI_PROTO_ALL_MASK \
	((1U << NATFLOW_DPI_PROTO_COAP) - 1)

enum natflow_dpi_context_result {
	NATFLOW_DPI_CONTEXT_WAIT,
	NATFLOW_DPI_CONTEXT_EXHAUSTED,
	NATFLOW_DPI_CONTEXT_EMPTY,
};

/* These bits only compact discovery state; dispatch is explicit below. */
enum natflow_dpi_machine_class_id {
	NATFLOW_DPI_MACHINE_CLASS_DNS,
	NATFLOW_DPI_MACHINE_CLASS_STUN_TURN,
	NATFLOW_DPI_MACHINE_CLASS_SSH,
	NATFLOW_DPI_MACHINE_CLASS_WIREGUARD,
	NATFLOW_DPI_MACHINE_CLASS_BITTORRENT,
	NATFLOW_DPI_MACHINE_CLASS_TEXT,
	NATFLOW_DPI_MACHINE_CLASS_DATABASE,
	NATFLOW_DPI_MACHINE_CLASS_BINARY,
	NATFLOW_DPI_MACHINE_CLASS_MAX,
};

#define NATFLOW_DPI_MACHINE_CLASS_BIT(id) (1U << (id))
#define NATFLOW_DPI_DIRECTION_PACKET_BUDGET 4
#define NATFLOW_DPI_CONNTRACK_PACKET_LIMIT 256U
#define NATFLOW_DPI_HTTP_APP_INSPECT_MAX 512
#define NATFLOW_DPI_IQIYI_PAYLOAD_MIN 121
#define NATFLOW_DPI_IQIYI_PAYLOAD_MAX 299

#define NATFLOW_DPI_EVENT_SOURCE_MAX NATFLOW_DPI_EVENT_SOURCE_ZOOM
#define NATFLOW_DPI_AUTOMATON_DISCOVERY_MASK 0x00ffu
#define NATFLOW_DPI_AUTOMATON_CLAIMED 0x8000u
#define NATFLOW_DPI_AUTOMATON_MACHINE_MASK 0x7f00u
#define NATFLOW_DPI_AUTOMATON_MACHINE_SHIFT 8
#define NATFLOW_DPI_AUTOMATON_STATE_MASK 0x00ffu

enum natflow_dpi_automaton_machine {
	NATFLOW_DPI_AUTOMATON_MACHINE_NONE,
	NATFLOW_DPI_AUTOMATON_MACHINE_RDP,
	NATFLOW_DPI_AUTOMATON_MACHINE_SOCKS,
	NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP,
};

enum natflow_dpi_rdp_state {
	NATFLOW_DPI_RDP_HAVE_REQUEST = 0x01,
	NATFLOW_DPI_RDP_HAVE_CONFIRM = 0x02,
	NATFLOW_DPI_RDP_COMPLETE = NATFLOW_DPI_RDP_HAVE_REQUEST |
	                           NATFLOW_DPI_RDP_HAVE_CONFIRM,
};

enum natflow_dpi_socks_state {
	NATFLOW_DPI_SOCKS_VERSION_4 = 0x04,
	NATFLOW_DPI_SOCKS_VERSION_5 = 0x05,
};

#define NATFLOW_DPI_WHATSAPP_MATCHED_MASK 0x0fu
#define NATFLOW_DPI_WHATSAPP_REPLY_STATE 0x10u

static bool natflow_dpi_automaton_claimed(unsigned short automaton);
static unsigned int natflow_dpi_automaton_machine(unsigned short automaton);
static unsigned short natflow_dpi_automaton_word(unsigned int machine,
        unsigned int state);

struct natflow_dpi_app_meta {
	unsigned int app_id;
	unsigned int category_id;
	unsigned int proto;
	const char *name;
};

struct natflow_dpi_app_machine_result {
	const struct natflow_dpi_app_meta *app;
	unsigned char status;
};

struct natflow_dpi_payload_app_result {
	const struct natflow_dpi_app_meta *app;
	unsigned int source;
	bool excluded;
};

struct natflow_dpi_http_message_view {
	struct natflow_l7_data_view start_line;
	struct natflow_l7_data_view headers;
	struct natflow_l7_data_view host;
	struct natflow_l7_data_view user_agent;
	struct natflow_l7_data_view content_type;
	struct natflow_l7_data_view body;
	bool request;
	bool response;
};

enum natflow_dpi_native_machine_status {
	NATFLOW_DPI_NATIVE_MACHINE_PENDING,
	NATFLOW_DPI_NATIVE_MACHINE_TERMINAL,
	NATFLOW_DPI_NATIVE_MACHINE_EXCLUDED,
};

struct natflow_dpi_native_machine_result {
	unsigned int proto;
	unsigned char status;
};

struct natflow_dpi_static_domain {
	const char *host;
	unsigned short host_len;
	unsigned char kind;
	unsigned int app_id;
};

#define NATFLOW_DPI_STATIC_DOMAIN(_host, _kind, _app_id) \
	{ (_host), sizeof(_host) - 1, (_kind), (_app_id) }

static int natflow_dpi_host_normalize(unsigned char *dst,
                                      const unsigned char *src, unsigned int len);

static const struct natflow_dpi_app_meta natflow_dpi_app_catalog[] = {
	{	NATFLOW_DPI_APP_DNS, NATFLOW_DPI_CATEGORY_INFRASTRUCTURE,
		NATFLOW_DPI_PROTO_DNS, "dns"
	},
	{	NATFLOW_DPI_APP_SSH, NATFLOW_DPI_CATEGORY_REMOTE_ACCESS,
		NATFLOW_DPI_PROTO_SSH, "ssh"
	},
	{	NATFLOW_DPI_APP_WIREGUARD, NATFLOW_DPI_CATEGORY_VPN_TUNNEL,
		NATFLOW_DPI_PROTO_WIREGUARD, "wireguard"
	},
	{	NATFLOW_DPI_APP_STUN, NATFLOW_DPI_CATEGORY_REALTIME,
		NATFLOW_DPI_PROTO_STUN, "stun"
	},
	{	NATFLOW_DPI_APP_TURN, NATFLOW_DPI_CATEGORY_REALTIME,
		NATFLOW_DPI_PROTO_TURN, "turn"
	},
	{	NATFLOW_DPI_APP_BITTORRENT, NATFLOW_DPI_CATEGORY_FILE_SHARING,
		NATFLOW_DPI_PROTO_BITTORRENT, "bittorrent"
	},
	{	NATFLOW_DPI_APP_FTP, NATFLOW_DPI_CATEGORY_FILE_TRANSFER,
		NATFLOW_DPI_PROTO_FTP, "ftp"
	},
	{	NATFLOW_DPI_APP_SMTP, NATFLOW_DPI_CATEGORY_EMAIL,
		NATFLOW_DPI_PROTO_SMTP, "smtp"
	},
	{	NATFLOW_DPI_APP_POP3, NATFLOW_DPI_CATEGORY_EMAIL,
		NATFLOW_DPI_PROTO_POP3, "pop3"
	},
	{	NATFLOW_DPI_APP_IMAP, NATFLOW_DPI_CATEGORY_EMAIL,
		NATFLOW_DPI_PROTO_IMAP, "imap"
	},
	{	NATFLOW_DPI_APP_SIP, NATFLOW_DPI_CATEGORY_VOIP,
		NATFLOW_DPI_PROTO_SIP, "sip"
	},
	{	NATFLOW_DPI_APP_RTSP, NATFLOW_DPI_CATEGORY_REALTIME,
		NATFLOW_DPI_PROTO_RTSP, "rtsp"
	},
	{	NATFLOW_DPI_APP_MQTT, NATFLOW_DPI_CATEGORY_IOT,
		NATFLOW_DPI_PROTO_MQTT, "mqtt"
	},
	{	NATFLOW_DPI_APP_RESP, NATFLOW_DPI_CATEGORY_DATABASE,
		NATFLOW_DPI_PROTO_RESP, "resp"
	},
	{	NATFLOW_DPI_APP_MYSQL, NATFLOW_DPI_CATEGORY_DATABASE,
		NATFLOW_DPI_PROTO_MYSQL, "mysql"
	},
	{	NATFLOW_DPI_APP_POSTGRESQL, NATFLOW_DPI_CATEGORY_DATABASE,
		NATFLOW_DPI_PROTO_POSTGRESQL, "postgresql"
	},
	{	NATFLOW_DPI_APP_RDP, NATFLOW_DPI_CATEGORY_REMOTE_ACCESS,
		NATFLOW_DPI_PROTO_RDP, "rdp"
	},
	{	NATFLOW_DPI_APP_SMB, NATFLOW_DPI_CATEGORY_FILE_SHARING,
		NATFLOW_DPI_PROTO_SMB, "smb"
	},
	{	NATFLOW_DPI_APP_NTP, NATFLOW_DPI_CATEGORY_INFRASTRUCTURE,
		NATFLOW_DPI_PROTO_NTP, "ntp"
	},
	{	NATFLOW_DPI_APP_SNMP, NATFLOW_DPI_CATEGORY_INFRASTRUCTURE,
		NATFLOW_DPI_PROTO_SNMP, "snmp"
	},
	{	NATFLOW_DPI_APP_RADIUS, NATFLOW_DPI_CATEGORY_INFRASTRUCTURE,
		NATFLOW_DPI_PROTO_RADIUS, "radius"
	},
	{	NATFLOW_DPI_APP_TFTP, NATFLOW_DPI_CATEGORY_FILE_TRANSFER,
		NATFLOW_DPI_PROTO_TFTP, "tftp"
	},
	{	NATFLOW_DPI_APP_LDAP, NATFLOW_DPI_CATEGORY_INFRASTRUCTURE,
		NATFLOW_DPI_PROTO_LDAP, "ldap"
	},
	{	NATFLOW_DPI_APP_NFS, NATFLOW_DPI_CATEGORY_FILE_SHARING,
		NATFLOW_DPI_PROTO_NFS, "nfs"
	},
	{	NATFLOW_DPI_APP_SOCKS, NATFLOW_DPI_CATEGORY_VPN_TUNNEL,
		NATFLOW_DPI_PROTO_SOCKS, "socks"
	},
	{	NATFLOW_DPI_APP_COAP, NATFLOW_DPI_CATEGORY_IOT,
		NATFLOW_DPI_PROTO_COAP, "coap"
	},
	{	NATFLOW_DPI_APP_YOUTUBE, NATFLOW_DPI_CATEGORY_STREAMING,
		0, "youtube"
	},
	{	NATFLOW_DPI_APP_NETFLIX, NATFLOW_DPI_CATEGORY_STREAMING,
		0, "netflix"
	},
	{	NATFLOW_DPI_APP_IQIYI, NATFLOW_DPI_CATEGORY_STREAMING,
		0, "iqiyi"
	},
	{	NATFLOW_DPI_APP_TENCENT_VIDEO, NATFLOW_DPI_CATEGORY_STREAMING,
		0, "tencent-video"
	},
	{	NATFLOW_DPI_APP_SPOTIFY, NATFLOW_DPI_CATEGORY_STREAMING,
		0, "spotify"
	},
	{	NATFLOW_DPI_APP_TELEGRAM, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "telegram"
	},
	{	NATFLOW_DPI_APP_WECHAT, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "wechat"
	},
	{	NATFLOW_DPI_APP_QQ, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "qq"
	},
	{	NATFLOW_DPI_APP_DINGTALK, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "dingtalk"
	},
	{	NATFLOW_DPI_APP_WHATSAPP, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "whatsapp"
	},
	{	NATFLOW_DPI_APP_MESSENGER, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "messenger"
	},
	{	NATFLOW_DPI_APP_DISCORD, NATFLOW_DPI_CATEGORY_COMMUNICATION,
		0, "discord"
	},
	{	NATFLOW_DPI_APP_ZOOM, NATFLOW_DPI_CATEGORY_REALTIME,
		0, "zoom"
	},
	{	NATFLOW_DPI_APP_TAOBAO, NATFLOW_DPI_CATEGORY_SHOPPING,
		0, "taobao"
	},
	{	NATFLOW_DPI_APP_TIKTOK, NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK,
		0, "tiktok"
	},
	{	NATFLOW_DPI_APP_FACEBOOK, NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK,
		0, "facebook"
	},
	{	NATFLOW_DPI_APP_INSTAGRAM, NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK,
		0, "instagram"
	},
	{	NATFLOW_DPI_APP_TWITTER, NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK,
		0, "twitter"
	},
	{	NATFLOW_DPI_APP_WEIBO, NATFLOW_DPI_CATEGORY_SOCIAL_NETWORK,
		0, "weibo"
	},
};

/* Exact entries precede suffix entries; suffix entries are longest first. */
static const struct natflow_dpi_static_domain natflow_dpi_static_domains[] = {
	NATFLOW_DPI_STATIC_DOMAIN("youtu.be", NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_YOUTUBE),
	NATFLOW_DPI_STATIC_DOMAIN("p16-tiktokcdn-com.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("p16-va-default.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokcdn.liveplay.myqcloud.com",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("instagram.c10r.facebook.com",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_INSTAGRAM),
	NATFLOW_DPI_STATIC_DOMAIN("fbstatic-a.akamaihd.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("audio4-ak-spotify-com.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("audio-ak-spotify-com.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("heads-ak-spotify-com.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotify-com.akamaized.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotify.com.edgesuite.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotify.map.fastly.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotify.edgekey.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotify.demdex.net",
	                          NATFLOW_DPI_DOMAIN_EXACT,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("chat-e2ee-mini.facebook.com",
	                          NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WHATSAPP),
	NATFLOW_DPI_STATIC_DOMAIN("edge-mqtt.facebook.com",
	                          NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_MESSENGER),
	NATFLOW_DPI_STATIC_DOMAIN("mqtt-mini.facebook.com",
	                          NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_MESSENGER),
	NATFLOW_DPI_STATIC_DOMAIN("youtube-nocookie.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_YOUTUBE),
	NATFLOW_DPI_STATIC_DOMAIN("cdninstagram.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_INSTAGRAM),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokcdn-eu.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokcdn-us.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("byteoversea.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("googlevideo.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_YOUTUBE),
	NATFLOW_DPI_STATIC_DOMAIN("discordapp.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DISCORD),
	NATFLOW_DPI_STATIC_DOMAIN("discordapp.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DISCORD),
	NATFLOW_DPI_STATIC_DOMAIN("spotifycdn.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotifycdn.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("spotilocal.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("tik-tokcdn.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("discord.media", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DISCORD),
	NATFLOW_DPI_STATIC_DOMAIN("instagram.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_INSTAGRAM),
	NATFLOW_DPI_STATIC_DOMAIN("messenger.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_MESSENGER),
	NATFLOW_DPI_STATIC_DOMAIN("mmsns.qpic.cn", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WECHAT),
	NATFLOW_DPI_STATIC_DOMAIN("nflxvideo.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokcdn.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("wechatapp.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WECHAT),
	NATFLOW_DPI_STATIC_DOMAIN("byteicdn.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("dingtalk.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DINGTALK),
	NATFLOW_DPI_STATIC_DOMAIN("facebook.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("facebook.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("ibyteimg.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("iqiyipic.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_IQIYI),
	NATFLOW_DPI_STATIC_DOMAIN("telegram.org", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TELEGRAM),
	NATFLOW_DPI_STATIC_DOMAIN("whatsapp.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WHATSAPP),
	NATFLOW_DPI_STATIC_DOMAIN("whatsapp.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WHATSAPP),
	NATFLOW_DPI_STATIC_DOMAIN("discord.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DISCORD),
	NATFLOW_DPI_STATIC_DOMAIN("musemuse.cn", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("netflix.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("nflxext.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("nflximg.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("nflximg.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("spotify.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("telegram.me", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TELEGRAM),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokv.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("twitter.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TWITTER),
	NATFLOW_DPI_STATIC_DOMAIN("youtube.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_YOUTUBE),
	NATFLOW_DPI_STATIC_DOMAIN("bytecdn.cn", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("discord.gg", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_DISCORD),
	NATFLOW_DPI_STATIC_DOMAIN("muscdn.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("musical.ly", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("nflxso.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_NETFLIX),
	NATFLOW_DPI_STATIC_DOMAIN("taobao.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TAOBAO),
	NATFLOW_DPI_STATIC_DOMAIN("tiktok.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokv.eu", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("tiktokv.us", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("wechat.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WECHAT),
	NATFLOW_DPI_STATIC_DOMAIN("wechat.org", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WECHAT),
	NATFLOW_DPI_STATIC_DOMAIN("byted.org", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TIKTOK),
	NATFLOW_DPI_STATIC_DOMAIN("fbcdn.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("fbsbx.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("gtimg.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_QQ),
	NATFLOW_DPI_STATIC_DOMAIN("iqiyi.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_IQIYI),
	NATFLOW_DPI_STATIC_DOMAIN("tmall.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TAOBAO),
	NATFLOW_DPI_STATIC_DOMAIN("twimg.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TWITTER),
	NATFLOW_DPI_STATIC_DOMAIN("twttr.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TWITTER),
	NATFLOW_DPI_STATIC_DOMAIN("weibo.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WEIBO),
	NATFLOW_DPI_STATIC_DOMAIN("ytimg.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_YOUTUBE),
	NATFLOW_DPI_STATIC_DOMAIN("fbwat.ch", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("pscdn.co", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("v.qq.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TENCENT_VIDEO),
	NATFLOW_DPI_STATIC_DOMAIN("weibo.cn", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WEIBO),
	NATFLOW_DPI_STATIC_DOMAIN("scdn.co", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_SPOTIFY),
	NATFLOW_DPI_STATIC_DOMAIN("we.chat", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_WECHAT),
	NATFLOW_DPI_STATIC_DOMAIN("zoom.us", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_ZOOM),
	NATFLOW_DPI_STATIC_DOMAIN("fb.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("iq.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_IQIYI),
	NATFLOW_DPI_STATIC_DOMAIN("pps.tv", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_IQIYI),
	NATFLOW_DPI_STATIC_DOMAIN("qq.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_QQ),
	NATFLOW_DPI_STATIC_DOMAIN("qy.net", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_IQIYI),
	NATFLOW_DPI_STATIC_DOMAIN("fb.gg", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_FACEBOOK),
	NATFLOW_DPI_STATIC_DOMAIN("x.com", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TWITTER),
	NATFLOW_DPI_STATIC_DOMAIN("m.me", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_MESSENGER),
	NATFLOW_DPI_STATIC_DOMAIN("t.co", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TWITTER),
	NATFLOW_DPI_STATIC_DOMAIN("t.me", NATFLOW_DPI_DOMAIN_SUFFIX,
	                          NATFLOW_DPI_APP_TELEGRAM),
};

static const struct natflow_dpi_app_meta *
natflow_dpi_app_by_id(unsigned int app_id)
{
	switch (app_id) {
	case NATFLOW_DPI_APP_YOUTUBE:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP];
	case NATFLOW_DPI_APP_NETFLIX:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 1];
	case NATFLOW_DPI_APP_IQIYI:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 2];
	case NATFLOW_DPI_APP_TENCENT_VIDEO:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 3];
	case NATFLOW_DPI_APP_SPOTIFY:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 4];
	case NATFLOW_DPI_APP_TELEGRAM:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 5];
	case NATFLOW_DPI_APP_WECHAT:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 6];
	case NATFLOW_DPI_APP_QQ:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 7];
	case NATFLOW_DPI_APP_DINGTALK:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 8];
	case NATFLOW_DPI_APP_WHATSAPP:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 9];
	case NATFLOW_DPI_APP_MESSENGER:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 10];
	case NATFLOW_DPI_APP_DISCORD:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 11];
	case NATFLOW_DPI_APP_ZOOM:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 12];
	case NATFLOW_DPI_APP_TAOBAO:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 13];
	case NATFLOW_DPI_APP_TIKTOK:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 14];
	case NATFLOW_DPI_APP_FACEBOOK:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 15];
	case NATFLOW_DPI_APP_INSTAGRAM:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 16];
	case NATFLOW_DPI_APP_TWITTER:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 17];
	case NATFLOW_DPI_APP_WEIBO:
		return &natflow_dpi_app_catalog[NATFLOW_DPI_PROTO_COAP + 18];
	default:
		return NULL;
	}
}

static int natflow_dpi_app_catalog_validate(void)
{
	unsigned int i;
	unsigned int j;

	for (i = 0; i < ARRAY_SIZE(natflow_dpi_app_catalog); i++) {
		const struct natflow_dpi_app_meta *app =
			    &natflow_dpi_app_catalog[i];

		if (app->app_id == NATFLOW_DPI_APP_UNKNOWN ||
		        app->category_id == NATFLOW_DPI_CATEGORY_UNKNOWN ||
		        (i < NATFLOW_DPI_PROTO_COAP && app->proto != i + 1) ||
		        (i >= NATFLOW_DPI_PROTO_COAP && app->proto != 0) ||
		        !app->name || app->name[0] == 0)
			return -EINVAL;

		for (j = i + 1; j < ARRAY_SIZE(natflow_dpi_app_catalog); j++) {
			if (app->app_id == natflow_dpi_app_catalog[j].app_id ||
			        (app->proto != 0 &&
			         app->proto == natflow_dpi_app_catalog[j].proto))
				return -EINVAL;
		}
	}

	return 0;
}

static bool natflow_dpi_static_domain_matches(
    const struct natflow_dpi_static_domain *domain,
    const unsigned char *host, unsigned int host_len)
{
	unsigned int offset;

	if (host_len < domain->host_len)
		return false;
	offset = host_len - domain->host_len;
	if (memcmp(host + offset, domain->host, domain->host_len) != 0)
		return false;
	if (domain->kind == NATFLOW_DPI_DOMAIN_EXACT)
		return offset == 0;
	return offset == 0 || host[offset - 1] == '.';
}

static int natflow_dpi_static_domain_catalog_validate(void)
{
	unsigned int i;
	unsigned int j;
	bool suffix_seen = false;
	unsigned int previous_suffix_len = ~0U;

	for (i = 0; i < ARRAY_SIZE(natflow_dpi_static_domains); i++) {
		const struct natflow_dpi_static_domain *domain =
			    &natflow_dpi_static_domains[i];

		if (!domain->host || domain->host_len == 0 ||
		        domain->host_len > NATFLOW_DPI_HOST_MAX_LEN ||
		        natflow_dpi_host_normalize(NULL,
		                                   (const unsigned char *)domain->host,
		                                   domain->host_len) != domain->host_len ||
		        !natflow_dpi_app_by_id(domain->app_id))
			return -EINVAL;
		if (domain->kind == NATFLOW_DPI_DOMAIN_SUFFIX) {
			suffix_seen = true;
			if (domain->host_len > previous_suffix_len)
				return -EINVAL;
			previous_suffix_len = domain->host_len;
		} else if (domain->kind != NATFLOW_DPI_DOMAIN_EXACT || suffix_seen) {
			return -EINVAL;
		}
		for (j = i + 1; j < ARRAY_SIZE(natflow_dpi_static_domains); j++) {
			if (domain->host_len == natflow_dpi_static_domains[j].host_len &&
			        memcmp(domain->host, natflow_dpi_static_domains[j].host,
			               domain->host_len) == 0)
				return -EINVAL;
		}
	}
	return 0;
}

static const struct natflow_dpi_app_meta *
natflow_dpi_static_domain_lookup(const unsigned char *host,
                                 unsigned int host_len)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(natflow_dpi_static_domains); i++) {
		if (natflow_dpi_static_domain_matches(&natflow_dpi_static_domains[i],
		                                      host, host_len))
			return natflow_dpi_app_by_id(natflow_dpi_static_domains[i].app_id);
	}
	return NULL;
}

static struct natflow_dpi_app_machine_result
natflow_dpi_domain_app_step(const unsigned char *host, unsigned int host_len,
                            unsigned int source)
{
	struct natflow_dpi_app_machine_result result = {
		.status = NATFLOW_DPI_APP_MACHINE_EXCLUDED,
	};

	switch (source) {
	case NATFLOW_DPI_EVENT_SOURCE_HTTP:
	case NATFLOW_DPI_EVENT_SOURCE_TLS:
	case NATFLOW_DPI_EVENT_SOURCE_QUIC:
		result.app = natflow_dpi_static_domain_lookup(host, host_len);
		if (result.app)
			result.status = NATFLOW_DPI_APP_MACHINE_TERMINAL;
		break;
	case NATFLOW_DPI_EVENT_SOURCE_DNS:
		result.app = natflow_dpi_static_domain_lookup(host, host_len);
		if (result.app)
			result.status = NATFLOW_DPI_APP_MACHINE_INTENT;
		break;
	default:
		break;
	}
	return result;
}

static struct natflow_dpi_payload_app_result
natflow_dpi_payload_app_pending(void)
{
	struct natflow_dpi_payload_app_result result = { };

	return result;
}

static struct natflow_dpi_payload_app_result
natflow_dpi_payload_app_terminal(unsigned int app_id, unsigned int source)
{
	struct natflow_dpi_payload_app_result result = {
		.app = natflow_dpi_app_by_id(app_id),
		.source = source,
	};

	if (!result.app)
		result.source = 0;
	return result;
}

static struct natflow_dpi_payload_app_result
natflow_dpi_payload_app_excluded(void)
{
	struct natflow_dpi_payload_app_result result = {
		.excluded = true,
	};

	return result;
}

static bool natflow_dpi_ascii_equal_nocase(const unsigned char *data,
        unsigned int data_len, const char *literal, unsigned int literal_len)
{
	unsigned int i;

	if (!data || !literal || data_len != literal_len)
		return false;
	for (i = 0; i < data_len; i++) {
		unsigned char a = data[i];
		unsigned char b = literal[i];

		if (a >= 'A' && a <= 'Z')
			a = a - 'A' + 'a';
		if (b >= 'A' && b <= 'Z')
			b = b - 'A' + 'a';
		if (a != b)
			return false;
	}
	return true;
}

static bool natflow_dpi_http_request_line_valid(const unsigned char *data,
        unsigned int len)
{
	unsigned int method_end = 0;
	unsigned int target_end;
	unsigned int i;

	while (method_end < len && data[method_end] != ' ')
		method_end++;
	if (method_end < 3 || method_end > 8 || method_end >= len)
		return false;
	for (i = 0; i < method_end; i++) {
		if (data[i] < 'A' || data[i] > 'Z')
			return false;
	}
	target_end = method_end + 1;
	while (target_end < len && data[target_end] != ' ')
		target_end++;
	if (target_end == method_end + 1 || target_end + 9 != len)
		return false;
	return memcmp(data + target_end + 1, "HTTP/1.", 7) == 0 &&
	       data[target_end + 8] >= '0' && data[target_end + 8] <= '9';
}

static bool natflow_dpi_http_response_line_valid(const unsigned char *data,
        unsigned int len)
{
	return len >= 12 && memcmp(data, "HTTP/1.", 7) == 0 &&
	       data[7] >= '0' && data[7] <= '9' && data[8] == ' ' &&
	       data[9] >= '1' && data[9] <= '5' &&
	       data[10] >= '0' && data[10] <= '9' &&
	       data[11] >= '0' && data[11] <= '9';
}

static bool natflow_dpi_http_message_parse(const unsigned char *data,
        unsigned int len, unsigned char direction,
        struct natflow_dpi_http_message_view *message)
{
	unsigned int header_count = 0;
	unsigned int headers_offset;
	unsigned int line_feed;
	unsigned int line_end;
	unsigned int offset;

	if (!data || !message || len == 0)
		return false;
	memset(message, 0, sizeof(*message));

	for (line_feed = 0; line_feed < len && data[line_feed] != '\n';
	        line_feed++)
		;
	if (line_feed == len)
		return false;
	line_end = line_feed;
	if (line_end > 0 && data[line_end - 1] == '\r')
		line_end--;
	if (line_end == 0)
		return false;

	message->start_line.data = data;
	message->start_line.len = line_end;
	if (direction == NATFLOW_L7_DIR_ORIGINAL)
		message->request = natflow_dpi_http_request_line_valid(data, line_end);
	else if (direction == NATFLOW_L7_DIR_REPLY)
		message->response = natflow_dpi_http_response_line_valid(data, line_end);
	if (!message->request && !message->response)
		return false;

	headers_offset = line_feed + 1;
	offset = headers_offset;
	while (offset < len) {
		unsigned int colon;
		unsigned int name_len;
		unsigned int value_end;
		unsigned int value_offset;

		for (line_feed = offset;
		        line_feed < len && data[line_feed] != '\n'; line_feed++)
			;
		if (line_feed == len)
			return false;
		line_end = line_feed;
		if (line_end > offset && data[line_end - 1] == '\r')
			line_end--;
		if (line_end == offset) {
			message->headers.data = data + headers_offset;
			message->headers.len = offset - headers_offset;
			message->body.data = data + line_feed + 1;
			message->body.len = len - line_feed - 1;
			return true;
		}
		if (header_count++ >= 32)
			return false;
		if (data[offset] == ' ' || data[offset] == '\t')
			return false;

		for (colon = offset; colon < line_end && data[colon] != ':'; colon++)
			;
		if (colon == offset || colon == line_end)
			return false;
		name_len = colon - offset;
		value_offset = colon + 1;
		while (value_offset < line_end &&
		        (data[value_offset] == ' ' || data[value_offset] == '\t'))
			value_offset++;
		value_end = line_end;
		while (value_end > value_offset &&
		        (data[value_end - 1] == ' ' || data[value_end - 1] == '\t'))
			value_end--;

		if (natflow_dpi_ascii_equal_nocase(data + offset, name_len,
		                                   "host", sizeof("host") - 1)) {
			if (message->host.data)
				return false;
			message->host.data = data + value_offset;
			message->host.len = value_end - value_offset;
		} else if (natflow_dpi_ascii_equal_nocase(data + offset, name_len,
		           "user-agent", sizeof("user-agent") - 1)) {
			message->user_agent.data = data + value_offset;
			message->user_agent.len = value_end - value_offset;
		} else if (natflow_dpi_ascii_equal_nocase(data + offset, name_len,
		           "content-type", sizeof("content-type") - 1)) {
			message->content_type.data = data + value_offset;
			message->content_type.len = value_end - value_offset;
		}
		offset = line_feed + 1;
	}
	return false;
}

static noinline struct natflow_dpi_payload_app_result
natflow_dpi_http_app_machine_step(const unsigned char *data,
                                  unsigned int inspect_len, unsigned char direction)
{
	struct natflow_dpi_http_message_view message;
	const struct natflow_dpi_app_meta *app;
	unsigned char normalized[NATFLOW_DPI_HOST_MAX_LEN + 1];
	ssize_t normalized_len;

	if (!natflow_dpi_http_message_parse(data, inspect_len, direction, &message) ||
	        !message.request || !message.host.data || message.host.len <= 0)
		return natflow_dpi_payload_app_pending();

	normalized_len = natflow_l7_copy_host_tolower(normalized,
	                 message.host.data, message.host.len,
	                 NATFLOW_L7_HOST_ALLOW_PORT);
	if (normalized_len <= 0)
		return natflow_dpi_payload_app_pending();
	app = natflow_dpi_static_domain_lookup(normalized, normalized_len);
	if (!app)
		return natflow_dpi_payload_app_pending();
	return natflow_dpi_payload_app_terminal(app->app_id,
	                                        NATFLOW_DPI_EVENT_SOURCE_HTTP);
}

static unsigned int natflow_dpi_read_be16(const unsigned char *data)
{
	return ((unsigned int)data[0] << 8) | data[1];
}

static unsigned int natflow_dpi_read_be32(const unsigned char *data)
{
	return ((unsigned int)data[0] << 24) |
	       ((unsigned int)data[1] << 16) |
	       ((unsigned int)data[2] << 8) | data[3];
}

static bool natflow_dpi_whatsapp_byte_matches(unsigned int offset,
        unsigned char value)
{
	static const unsigned char prefix[] = { 0x45, 0x44, 0x00, 0x01, 0x00, 0x00 };

	if (offset < ARRAY_SIZE(prefix))
		return value == prefix[offset];
	if (offset == 6)
		return value == 0x02 || value == 0x04;
	return offset == 7 && value == 0x08;
}

static struct natflow_dpi_payload_app_result
natflow_dpi_whatsapp_app_machine_step(natflow_t *nf,
                                      const unsigned char *data, unsigned int payload_len,
                                      unsigned int inspect_len, unsigned char direction)
{
	unsigned short automaton;
	unsigned int matched = 0;
	unsigned int state;
	unsigned int limit;
	unsigned int i;
	bool reply;

	if (!nf || !data || inspect_len == 0)
		return natflow_dpi_payload_app_pending();
	automaton = READ_ONCE(nf->dpi_automaton);
	if (natflow_dpi_automaton_claimed(automaton)) {
		if (natflow_dpi_automaton_machine(automaton) !=
		        NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP)
			return natflow_dpi_payload_app_pending();
		state = automaton & NATFLOW_DPI_AUTOMATON_STATE_MASK;
		matched = state & NATFLOW_DPI_WHATSAPP_MATCHED_MASK;
		reply = (state & NATFLOW_DPI_WHATSAPP_REPLY_STATE) != 0;
		if (matched < 2 || matched >= 8)
			return natflow_dpi_payload_app_excluded();
		if (reply != (direction == NATFLOW_L7_DIR_REPLY))
			return natflow_dpi_payload_app_pending();
	} else {
		if (payload_len > 4 && inspect_len >= 4 &&
		        memcmp(data, "\x57\x41\x01\x05", 4) == 0)
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_WHATSAPP,
			           NATFLOW_DPI_EVENT_SOURCE_WHATSAPP);
	}

	limit = payload_len;
	if (limit > 8 - matched)
		limit = 8 - matched;
	if (inspect_len < limit)
		return natflow_dpi_payload_app_pending();
	for (i = 0; i < limit; i++) {
		if (!natflow_dpi_whatsapp_byte_matches(matched + i, data[i]))
			return matched ? natflow_dpi_payload_app_excluded() :
			       natflow_dpi_payload_app_pending();
	}
	matched += limit;
	if (matched == 8)
		return natflow_dpi_payload_app_terminal(
		           NATFLOW_DPI_APP_WHATSAPP,
		           NATFLOW_DPI_EVENT_SOURCE_WHATSAPP);
	if (matched < 2 || payload_len != limit)
		return natflow_dpi_payload_app_pending();

	state = matched;
	if (direction == NATFLOW_L7_DIR_REPLY)
		state |= NATFLOW_DPI_WHATSAPP_REPLY_STATE;
	if (natflow_dpi_automaton_claimed(automaton)) {
		if (cmpxchg(&nf->dpi_automaton, automaton,
		            natflow_dpi_automaton_word(
		                NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP,
		                state)) != automaton)
			return natflow_dpi_payload_app_excluded();
	} else if (cmpxchg(&nf->dpi_automaton, automaton,
	                   natflow_dpi_automaton_word(
	                       NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP,
	                       state)) != automaton) {
		return natflow_dpi_payload_app_pending();
	}
	return natflow_dpi_payload_app_pending();
}

static bool natflow_dpi_discord_payload(const unsigned char *data,
                                        unsigned int payload_len, unsigned int inspect_len)
{
	return payload_len == 8 && inspect_len >= 4 &&
	       natflow_dpi_read_be32(data) == 0x1337cafe;
}

static bool natflow_dpi_spotify_payload(const unsigned char *data,
                                        unsigned int payload_len, unsigned int inspect_len,
                                        unsigned char l4proto, __be16 sport, __be16 dport)
{
	if (l4proto == IPPROTO_UDP)
		return sport == __constant_htons(57621) &&
		       dport == __constant_htons(57621) && payload_len >= 7 &&
		       inspect_len >= 7 && memcmp(data, "SpotUdp", 7) == 0;
	return l4proto == IPPROTO_TCP && payload_len >= 9 && inspect_len >= 9 &&
	       data[0] == 0x00 && data[1] == 0x04 && data[2] == 0x00 &&
	       data[3] == 0x00 && data[6] == 0x52 &&
	       (data[7] == 0x0e || data[7] == 0x0f) && data[8] == 0x50;
}

static bool natflow_dpi_zoom_payload(const unsigned char *data,
                                     unsigned int payload_len, unsigned int inspect_len,
                                     unsigned char l4proto, __be16 sport, __be16 dport)
{
	unsigned int source_port = ntohs(sport);
	unsigned int destination_port = ntohs(dport);

	if (l4proto != IPPROTO_UDP || payload_len <= 8 || inspect_len < 3 ||
	        ((source_port < 8801 || source_port > 8810) &&
	         (destination_port < 8801 || destination_port > 8810)))
		return false;
	return (data[0] == 0x01 || data[0] == 0x02) && data[1] == 0x00 &&
	       (data[2] == 0x02 || data[2] == 0x03);
}

static bool natflow_dpi_payload_contains(const unsigned char *data,
        unsigned int data_len, const char *literal, unsigned int literal_len)
{
	unsigned int i;

	if (!data || !literal || literal_len == 0 || data_len < literal_len)
		return false;
	for (i = 0; i <= data_len - literal_len; i++) {
		if (memcmp(data + i, literal, literal_len) == 0)
			return true;
	}
	return false;
}

static bool natflow_dpi_dingtalk_payload(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	return payload_len > 90 && inspect_len >= 16 && data[0] == 0x10 &&
	       natflow_dpi_read_be32(data + 2) == 0x87800100 &&
	       natflow_dpi_read_be32(data + 6) == 0x01000200 &&
	       natflow_dpi_read_be32(data + 10) == 0x02646b03 &&
	       natflow_dpi_read_be16(data + 14) == 0x0020;
}

static bool natflow_dpi_qq_payload(const unsigned char *data,
                                   unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int prefix;

	if (inspect_len < 4)
		return false;
	prefix = natflow_dpi_read_be32(data);
	if ((payload_len == 72 && prefix == 0x02004800) ||
	        (payload_len == 64 && prefix == 0x02004000) ||
	        (payload_len == 60 && prefix == 0x02004200) ||
	        (payload_len == 84 && prefix == 0x02005a00) ||
	        (payload_len == 56 && prefix == 0x02003800) ||
	        (payload_len >= 39 && prefix == 0x28000000))
		return true;

	if (inspect_len >= 7 && data[0] == 0x02 &&
	        natflow_dpi_read_be16(data + 1) == 0x3b0b) {
		unsigned int command = natflow_dpi_read_be16(data + 3);

		return (command >= 0x0001 && command <= 0x00b5) ||
		       command == 0x03f7;
	}
	return false;
}

static bool natflow_dpi_iqiyi_payload(const unsigned char *data,
                                      unsigned int payload_len, unsigned int inspect_len)
{
	if (payload_len < NATFLOW_DPI_IQIYI_PAYLOAD_MIN ||
	        payload_len > NATFLOW_DPI_IQIYI_PAYLOAD_MAX ||
	        inspect_len < payload_len)
		return false;
	return natflow_dpi_payload_contains(data, payload_len, "PPStream",
	                                    sizeof("PPStream") - 1);
}

static struct natflow_dpi_payload_app_result
natflow_dpi_payload_app_machine_step(natflow_t *nf,
                                     const unsigned char *data,
                                     unsigned int payload_len, unsigned int inspect_len,
                                     unsigned char l4proto, unsigned char direction,
                                     __be16 sport, __be16 dport)
{
	struct natflow_dpi_payload_app_result result;
	unsigned short automaton;

	if (!data || inspect_len == 0)
		return natflow_dpi_payload_app_pending();
	automaton = nf ? READ_ONCE(nf->dpi_automaton) : 0;
	if (natflow_dpi_automaton_claimed(automaton)) {
		if (natflow_dpi_automaton_machine(automaton) ==
		        NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP)
			return natflow_dpi_whatsapp_app_machine_step(nf, data,
			        payload_len, inspect_len, direction);
		return natflow_dpi_payload_app_pending();
	}
	if (l4proto == IPPROTO_TCP) {
		result = natflow_dpi_http_app_machine_step(data, inspect_len,
		         direction);
		if (result.app)
			return result;
		if (natflow_dpi_dingtalk_payload(data, payload_len, inspect_len))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_DINGTALK,
			           NATFLOW_DPI_EVENT_SOURCE_DINGTALK);
		if (natflow_dpi_spotify_payload(data, payload_len, inspect_len,
		                                l4proto, sport, dport))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_SPOTIFY,
			           NATFLOW_DPI_EVENT_SOURCE_SPOTIFY);
		result = natflow_dpi_whatsapp_app_machine_step(nf, data,
		         payload_len, inspect_len, direction);
		if (result.app || result.excluded ||
		        natflow_dpi_automaton_claimed(READ_ONCE(nf->dpi_automaton)))
			return result;
	} else if (l4proto == IPPROTO_UDP) {
		if (natflow_dpi_discord_payload(data, payload_len, inspect_len))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_DISCORD,
			           NATFLOW_DPI_EVENT_SOURCE_DISCORD);
		if (natflow_dpi_spotify_payload(data, payload_len, inspect_len,
		                                l4proto, sport, dport))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_SPOTIFY,
			           NATFLOW_DPI_EVENT_SOURCE_SPOTIFY);
		if (natflow_dpi_zoom_payload(data, payload_len, inspect_len,
		                             l4proto, sport, dport))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_ZOOM,
			           NATFLOW_DPI_EVENT_SOURCE_ZOOM);
		if (natflow_dpi_qq_payload(data, payload_len, inspect_len))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_QQ, NATFLOW_DPI_EVENT_SOURCE_QQ);
		if (natflow_dpi_iqiyi_payload(data, payload_len, inspect_len))
			return natflow_dpi_payload_app_terminal(
			           NATFLOW_DPI_APP_IQIYI,
			           NATFLOW_DPI_EVENT_SOURCE_IQIYI);
	}
	return natflow_dpi_payload_app_pending();
}

static const struct natflow_dpi_app_meta *
natflow_dpi_app_by_proto(unsigned int proto)
{
	const struct natflow_dpi_app_meta *app;

	if (proto == 0 || proto > NATFLOW_DPI_PROTO_COAP)
		return NULL;
	app = &natflow_dpi_app_catalog[proto - 1];
	return app->proto == proto ? app : NULL;
}

struct natflow_dpi_event_node {
	struct list_head list;
	struct natflow_dpi_event_hdr hdr;
};

static int natflow_dpi_ctl_major = 0;
static int natflow_dpi_ctl_minor = 0;
static struct cdev natflow_dpi_ctl_cdev;
static const char * const natflow_dpi_ctl_dev_name = "natflow_dpi_ctl";
static struct class *natflow_dpi_ctl_class;
static struct device *natflow_dpi_ctl_dev;

static int natflow_dpi_queue_major = 0;
static int natflow_dpi_queue_minor = 0;
static struct cdev natflow_dpi_queue_cdev;
static const char * const natflow_dpi_queue_dev_name = "natflow_dpi_queue";
static struct class *natflow_dpi_queue_class;
static struct device *natflow_dpi_queue_dev;

static DEFINE_MUTEX(natflow_dpi_lock);
static DEFINE_MUTEX(natflow_dpi_write_lock);
static wait_queue_head_t natflow_dpi_wait;
static LIST_HEAD(natflow_dpi_event_list);
static DEFINE_SPINLOCK(natflow_dpi_event_lock);
static unsigned int natflow_dpi_event_count;
static unsigned int natflow_dpi_queue_readers;
static unsigned int natflow_dpi_queue_cache_limit;
static struct natflow_queue_cache_write_state natflow_dpi_queue_write_state;
static unsigned int natflow_dpi_state = NATFLOW_DPI_STATE_DISABLED;
static atomic64_t natflow_dpi_matches;
static atomic64_t natflow_dpi_source_matches[NATFLOW_DPI_EVENT_SOURCE_MAX + 1];
static atomic64_t natflow_dpi_events;
static atomic64_t natflow_dpi_events_suppressed;
static atomic64_t natflow_dpi_events_lost;
static atomic64_t natflow_dpi_source_events[NATFLOW_DPI_EVENT_SOURCE_MAX + 1];
static const char * const natflow_dpi_source_names[] = {
	[NATFLOW_DPI_EVENT_SOURCE_HTTP] = "http",
	[NATFLOW_DPI_EVENT_SOURCE_TLS] = "tls",
	[NATFLOW_DPI_EVENT_SOURCE_QUIC] = "quic",
	[NATFLOW_DPI_EVENT_SOURCE_DNS] = "dns",
	[NATFLOW_DPI_EVENT_SOURCE_SSH] = "ssh",
	[NATFLOW_DPI_EVENT_SOURCE_WIREGUARD] = "wireguard",
	[NATFLOW_DPI_EVENT_SOURCE_STUN] = "stun",
	[NATFLOW_DPI_EVENT_SOURCE_TURN] = "turn",
	[NATFLOW_DPI_EVENT_SOURCE_BITTORRENT] = "bittorrent",
	[NATFLOW_DPI_EVENT_SOURCE_FTP] = "ftp",
	[NATFLOW_DPI_EVENT_SOURCE_SMTP] = "smtp",
	[NATFLOW_DPI_EVENT_SOURCE_POP3] = "pop3",
	[NATFLOW_DPI_EVENT_SOURCE_IMAP] = "imap",
	[NATFLOW_DPI_EVENT_SOURCE_SIP] = "sip",
	[NATFLOW_DPI_EVENT_SOURCE_RTSP] = "rtsp",
	[NATFLOW_DPI_EVENT_SOURCE_MQTT] = "mqtt",
	[NATFLOW_DPI_EVENT_SOURCE_RESP] = "resp",
	[NATFLOW_DPI_EVENT_SOURCE_MYSQL] = "mysql",
	[NATFLOW_DPI_EVENT_SOURCE_POSTGRESQL] = "postgresql",
	[NATFLOW_DPI_EVENT_SOURCE_RDP] = "rdp",
	[NATFLOW_DPI_EVENT_SOURCE_SMB] = "smb",
	[NATFLOW_DPI_EVENT_SOURCE_DINGTALK] = "dingtalk",
	[NATFLOW_DPI_EVENT_SOURCE_QQ] = "qq",
	[NATFLOW_DPI_EVENT_SOURCE_IQIYI] = "iqiyi",
	[NATFLOW_DPI_EVENT_SOURCE_NTP] = "ntp",
	[NATFLOW_DPI_EVENT_SOURCE_SNMP] = "snmp",
	[NATFLOW_DPI_EVENT_SOURCE_RADIUS] = "radius",
	[NATFLOW_DPI_EVENT_SOURCE_TFTP] = "tftp",
	[NATFLOW_DPI_EVENT_SOURCE_LDAP] = "ldap",
	[NATFLOW_DPI_EVENT_SOURCE_NFS] = "nfs",
	[NATFLOW_DPI_EVENT_SOURCE_SOCKS] = "socks",
	[NATFLOW_DPI_EVENT_SOURCE_COAP] = "coap",
	[NATFLOW_DPI_EVENT_SOURCE_WHATSAPP] = "whatsapp",
	[NATFLOW_DPI_EVENT_SOURCE_DISCORD] = "discord",
	[NATFLOW_DPI_EVENT_SOURCE_SPOTIFY] = "spotify",
	[NATFLOW_DPI_EVENT_SOURCE_ZOOM] = "zoom",
};
static atomic64_t natflow_dpi_domain_lookups;
static atomic64_t natflow_dpi_domain_matches;
static atomic64_t natflow_dpi_dns_app_intents;
static atomic64_t natflow_dpi_packet_inspections[IP_CT_DIR_MAX];
static atomic64_t natflow_dpi_packet_matches[IP_CT_DIR_MAX];
static atomic64_t natflow_dpi_context_armed;
static atomic64_t natflow_dpi_context_cleared_match;
static atomic64_t natflow_dpi_context_cleared_budget;
static atomic64_t natflow_dpi_context_cleared_transport;
static atomic64_t natflow_dpi_context_cleared_app;
static atomic64_t natflow_dpi_context_cleared_no_candidate;
static atomic64_t natflow_dpi_context_cleared_acct_limit;
static atomic64_t natflow_dpi_context_aborted;
static atomic64_t natflow_dpi_proto_no_session;
static atomic64_t natflow_dpi_proto_app_exists;

static bool natflow_dpi_commit_app(struct nf_conn *ct,
                                   const struct natflow_dpi_app_meta *app,
                                   unsigned int source, unsigned char direction);
static bool natflow_dpi_context_clear_locked(natflow_t *nf);
static bool natflow_dpi_commit_app_locked(natflow_t *nf,
        const struct natflow_dpi_app_meta *app, bool *app_exists,
        bool *context_cleared);

static const char *natflow_dpi_state_name(unsigned int state)
{
	switch (state) {
	case NATFLOW_DPI_STATE_ENABLED:
		return "enabled";
	case NATFLOW_DPI_STATE_DISABLED:
	default:
		return "disabled";
	}
}

static inline int natflow_dpi_host_char_valid(unsigned char c)
{
	return (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') ||
	       c == '-' ||
	       c == '.';
}

static int natflow_dpi_host_normalize(unsigned char *dst,
                                      const unsigned char *src,
                                      unsigned int len)
{
	unsigned int i;
	unsigned int out = 0;
	unsigned int label_len = 0;
	unsigned char last = 0;

	if (!src || len == 0)
		return -EINVAL;
	if (len > NATFLOW_DPI_HOST_MAX_LEN)
		return -EINVAL;

	if (src[len - 1] == '.')
		len--;
	if (len == 0 || len > NATFLOW_DPI_HOST_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		unsigned char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = c - 'A' + 'a';
		if (!natflow_dpi_host_char_valid(c))
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
	if (dst)
		dst[out] = 0;
	return out;
}

static void natflow_dpi_event_fill_tuple(struct natflow_dpi_event_hdr *hdr,
        const struct nf_conn *ct)
{
	const struct nf_conntrack_tuple *tuple;

	if (!ct)
		return;

	tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	hdr->family = tuple->src.l3num;
	hdr->l4proto = tuple->dst.protonum;
	hdr->tuple_dir = IP_CT_DIR_ORIGINAL;

	switch (tuple->src.l3num) {
	case AF_INET:
		memcpy(hdr->sip, &tuple->src.u3.ip, sizeof(tuple->src.u3.ip));
		memcpy(hdr->dip, &tuple->dst.u3.ip, sizeof(tuple->dst.u3.ip));
		break;
	case AF_INET6:
		memcpy(hdr->sip, tuple->src.u3.ip6, sizeof(hdr->sip));
		memcpy(hdr->dip, tuple->dst.u3.ip6, sizeof(hdr->dip));
		break;
	default:
		break;
	}

	switch (tuple->dst.protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		hdr->sport = ntohs(tuple->src.u.all);
		hdr->dport = ntohs(tuple->dst.u.all);
		break;
	default:
		break;
	}
}

static void natflow_dpi_event_queue(const struct nf_conn *ct,
                                    unsigned int reason, unsigned int generation,
                                    unsigned int app_id, unsigned int category_id,
                                    unsigned int rule_id,
                                    unsigned int flags, unsigned char direction)
{
	struct natflow_dpi_event_node *node;

	atomic64_inc(&natflow_dpi_matches);
	if (flags <= NATFLOW_DPI_EVENT_SOURCE_MAX)
		atomic64_inc(&natflow_dpi_source_matches[flags]);

	if (READ_ONCE(natflow_dpi_queue_readers) == 0 ||
	        READ_ONCE(natflow_dpi_queue_cache_limit) == 0) {
		atomic64_inc(&natflow_dpi_events_suppressed);
		return;
	}

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		atomic64_inc(&natflow_dpi_events_lost);
		return;
	}

	node->hdr.version = NATFLOW_DPI_EVENT_VERSION;
	node->hdr.header_len = sizeof(struct natflow_dpi_event_hdr);
	node->hdr.record_len = sizeof(struct natflow_dpi_event_hdr);
	node->hdr.reason = reason;
	node->hdr.generation = generation;
	node->hdr.app_id = app_id;
	node->hdr.category_id = category_id;
	node->hdr.rule_id = rule_id;
	node->hdr.flags = flags;
	node->hdr.evidence_dir = direction == NATFLOW_L7_DIR_REPLY ?
	                         IP_CT_DIR_REPLY : IP_CT_DIR_ORIGINAL;
	node->hdr.timestamp = NATFLOW_DPI_EVENT_TIMESTAMP_NOW;
	natflow_dpi_event_fill_tuple(&node->hdr, ct);

	spin_lock_bh(&natflow_dpi_event_lock);
	if (natflow_dpi_queue_readers == 0 ||
	        natflow_dpi_queue_cache_limit == 0) {
		spin_unlock_bh(&natflow_dpi_event_lock);
		kfree(node);
		atomic64_inc(&natflow_dpi_events_suppressed);
		return;
	}
	if (natflow_dpi_event_count >= natflow_dpi_queue_cache_limit) {
		spin_unlock_bh(&natflow_dpi_event_lock);
		kfree(node);
		atomic64_inc(&natflow_dpi_events_lost);
		return;
	}
	list_add_tail(&node->list, &natflow_dpi_event_list);
	natflow_dpi_event_count++;
	spin_unlock_bh(&natflow_dpi_event_lock);

	atomic64_inc(&natflow_dpi_events);
	if (flags <= NATFLOW_DPI_EVENT_SOURCE_MAX)
		atomic64_inc(&natflow_dpi_source_events[flags]);
	wake_up_interruptible(&natflow_dpi_wait);
}

static void natflow_dpi_event_purge_locked(struct list_head *free_list)
{
	list_splice_init(&natflow_dpi_event_list, free_list);
	natflow_dpi_event_count = 0;
}

static void natflow_dpi_event_free_list(struct list_head *free_list)
{
	struct natflow_dpi_event_node *node;
	struct natflow_dpi_event_node *tmp;

	list_for_each_entry_safe(node, tmp, free_list, list) {
		list_del(&node->list);
		kfree(node);
	}
}

static void natflow_dpi_event_purge(void)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&natflow_dpi_event_lock);
	natflow_dpi_event_purge_locked(&free_list);
	spin_unlock_bh(&natflow_dpi_event_lock);

	natflow_dpi_event_free_list(&free_list);
}

static void natflow_dpi_counters_clear(void)
{
	int i;

	atomic64_set(&natflow_dpi_matches, 0);
	atomic64_set(&natflow_dpi_events, 0);
	atomic64_set(&natflow_dpi_events_suppressed, 0);
	atomic64_set(&natflow_dpi_events_lost, 0);
	atomic64_set(&natflow_dpi_domain_lookups, 0);
	atomic64_set(&natflow_dpi_domain_matches, 0);
	atomic64_set(&natflow_dpi_dns_app_intents, 0);
	atomic64_set(&natflow_dpi_packet_inspections[IP_CT_DIR_ORIGINAL], 0);
	atomic64_set(&natflow_dpi_packet_inspections[IP_CT_DIR_REPLY], 0);
	atomic64_set(&natflow_dpi_packet_matches[IP_CT_DIR_ORIGINAL], 0);
	atomic64_set(&natflow_dpi_packet_matches[IP_CT_DIR_REPLY], 0);
	atomic64_set(&natflow_dpi_context_armed, 0);
	atomic64_set(&natflow_dpi_context_cleared_match, 0);
	atomic64_set(&natflow_dpi_context_cleared_budget, 0);
	atomic64_set(&natflow_dpi_context_cleared_transport, 0);
	atomic64_set(&natflow_dpi_context_cleared_app, 0);
	atomic64_set(&natflow_dpi_context_cleared_no_candidate, 0);
	atomic64_set(&natflow_dpi_context_cleared_acct_limit, 0);
	atomic64_set(&natflow_dpi_context_aborted, 0);
	atomic64_set(&natflow_dpi_proto_no_session, 0);
	atomic64_set(&natflow_dpi_proto_app_exists, 0);
	for (i = 0; i <= NATFLOW_DPI_EVENT_SOURCE_MAX; i++) {
		atomic64_set(&natflow_dpi_source_matches[i], 0);
		atomic64_set(&natflow_dpi_source_events[i], 0);
	}
}

static void natflow_dpi_events_clear(void)
{
	unsigned int state = READ_ONCE(natflow_dpi_state);

	/* Producers run from Netfilter hooks; drain them before resetting counters. */
	WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);
	synchronize_net();
	natflow_dpi_event_purge();
	natflow_dpi_counters_clear();
	WRITE_ONCE(natflow_dpi_state, state);
	wake_up_interruptible(&natflow_dpi_wait);
}

static void natflow_dpi_queue_cache_set(unsigned int cache_limit)
{
	LIST_HEAD(free_list);

	WRITE_ONCE(natflow_dpi_queue_cache_limit, cache_limit);
	if (cache_limit == 0) {
		natflow_dpi_event_purge();
		wake_up_interruptible(&natflow_dpi_wait);
		return;
	}

	spin_lock_bh(&natflow_dpi_event_lock);
	while (natflow_dpi_event_count > cache_limit) {
		struct natflow_dpi_event_node *node;

		node = list_first_entry(&natflow_dpi_event_list,
		                        struct natflow_dpi_event_node, list);
		list_del(&node->list);
		natflow_dpi_event_count--;
		list_add_tail(&node->list, &free_list);
	}
	spin_unlock_bh(&natflow_dpi_event_lock);

	natflow_dpi_event_free_list(&free_list);
}

int natflow_dpi_consumer_enabled(void)
{
	return READ_ONCE(natflow_dpi_state) == NATFLOW_DPI_STATE_ENABLED;
}

int natflow_dpi_host_consumer_enabled(void)
{
	return READ_ONCE(natflow_dpi_state) == NATFLOW_DPI_STATE_ENABLED;
}

int natflow_dpi_packet_consumer_enabled(void)
{
	return READ_ONCE(natflow_dpi_state) == NATFLOW_DPI_STATE_ENABLED;
}

static void natflow_dpi_classify_normalized_host_match(struct nf_conn *ct,
        const unsigned char *normalized, unsigned short normalized_len,
        unsigned int source)
{
	struct natflow_dpi_app_machine_result result;

	atomic64_inc(&natflow_dpi_domain_lookups);
	result = natflow_dpi_domain_app_step(normalized, normalized_len, source);
	if (result.status == NATFLOW_DPI_APP_MACHINE_TERMINAL) {
		atomic64_inc(&natflow_dpi_domain_matches);
		natflow_dpi_commit_app(ct, result.app, source,
		                       NATFLOW_L7_DIR_ORIGINAL);
		return;
	}
	if (source == NATFLOW_DPI_EVENT_SOURCE_DNS) {
		if (result.status == NATFLOW_DPI_APP_MACHINE_INTENT)
			atomic64_inc(&natflow_dpi_dns_app_intents);
	}
}

void natflow_dpi_classify_host_normalized(struct nf_conn *ct,
        const unsigned char *host, unsigned short host_len, unsigned int source)
{
	if (!ct || !host || host_len == 0 || host_len > NATFLOW_DPI_HOST_MAX_LEN)
		return;
	if (READ_ONCE(natflow_dpi_state) != NATFLOW_DPI_STATE_ENABLED)
		return;

	natflow_dpi_classify_normalized_host_match(ct, host, host_len, source);
}

void natflow_dpi_classify_host_flags(struct nf_conn *ct,
                                     const unsigned char *host,
                                     unsigned short host_len,
                                     unsigned int source,
                                     unsigned int host_flags)
{
	unsigned char normalized[NATFLOW_DPI_HOST_MAX_LEN + 1];
	int normalized_len;

	if (!ct || !host || host_len == 0)
		return;
	if (READ_ONCE(natflow_dpi_state) != NATFLOW_DPI_STATE_ENABLED)
		return;

	if (host_flags != 0)
		normalized_len = natflow_l7_copy_host_tolower(normalized, host,
		                 host_len, host_flags);
	else
		normalized_len = natflow_dpi_host_normalize(normalized, host,
		                 host_len);
	if (normalized_len <= 0)
		return;

	natflow_dpi_classify_normalized_host_match(ct, normalized,
	        normalized_len, source);
}

void natflow_dpi_classify_host(struct nf_conn *ct, const unsigned char *host,
                               unsigned short host_len, unsigned int source)
{
	natflow_dpi_classify_host_flags(ct, host, host_len, source, 0);
}

static unsigned int natflow_dpi_proto_event_source(unsigned int proto)
{
	switch (proto) {
	case NATFLOW_DPI_PROTO_DNS:
		return NATFLOW_DPI_EVENT_SOURCE_DNS;
	case NATFLOW_DPI_PROTO_SSH:
		return NATFLOW_DPI_EVENT_SOURCE_SSH;
	case NATFLOW_DPI_PROTO_WIREGUARD:
		return NATFLOW_DPI_EVENT_SOURCE_WIREGUARD;
	case NATFLOW_DPI_PROTO_STUN:
		return NATFLOW_DPI_EVENT_SOURCE_STUN;
	case NATFLOW_DPI_PROTO_TURN:
		return NATFLOW_DPI_EVENT_SOURCE_TURN;
	case NATFLOW_DPI_PROTO_BITTORRENT:
		return NATFLOW_DPI_EVENT_SOURCE_BITTORRENT;
	case NATFLOW_DPI_PROTO_FTP:
		return NATFLOW_DPI_EVENT_SOURCE_FTP;
	case NATFLOW_DPI_PROTO_SMTP:
		return NATFLOW_DPI_EVENT_SOURCE_SMTP;
	case NATFLOW_DPI_PROTO_POP3:
		return NATFLOW_DPI_EVENT_SOURCE_POP3;
	case NATFLOW_DPI_PROTO_IMAP:
		return NATFLOW_DPI_EVENT_SOURCE_IMAP;
	case NATFLOW_DPI_PROTO_SIP:
		return NATFLOW_DPI_EVENT_SOURCE_SIP;
	case NATFLOW_DPI_PROTO_RTSP:
		return NATFLOW_DPI_EVENT_SOURCE_RTSP;
	case NATFLOW_DPI_PROTO_MQTT:
		return NATFLOW_DPI_EVENT_SOURCE_MQTT;
	case NATFLOW_DPI_PROTO_RESP:
		return NATFLOW_DPI_EVENT_SOURCE_RESP;
	case NATFLOW_DPI_PROTO_MYSQL:
		return NATFLOW_DPI_EVENT_SOURCE_MYSQL;
	case NATFLOW_DPI_PROTO_POSTGRESQL:
		return NATFLOW_DPI_EVENT_SOURCE_POSTGRESQL;
	case NATFLOW_DPI_PROTO_RDP:
		return NATFLOW_DPI_EVENT_SOURCE_RDP;
	case NATFLOW_DPI_PROTO_SMB:
		return NATFLOW_DPI_EVENT_SOURCE_SMB;
	case NATFLOW_DPI_PROTO_NTP:
		return NATFLOW_DPI_EVENT_SOURCE_NTP;
	case NATFLOW_DPI_PROTO_SNMP:
		return NATFLOW_DPI_EVENT_SOURCE_SNMP;
	case NATFLOW_DPI_PROTO_RADIUS:
		return NATFLOW_DPI_EVENT_SOURCE_RADIUS;
	case NATFLOW_DPI_PROTO_TFTP:
		return NATFLOW_DPI_EVENT_SOURCE_TFTP;
	case NATFLOW_DPI_PROTO_LDAP:
		return NATFLOW_DPI_EVENT_SOURCE_LDAP;
	case NATFLOW_DPI_PROTO_NFS:
		return NATFLOW_DPI_EVENT_SOURCE_NFS;
	case NATFLOW_DPI_PROTO_SOCKS:
		return NATFLOW_DPI_EVENT_SOURCE_SOCKS;
	case NATFLOW_DPI_PROTO_COAP:
		return NATFLOW_DPI_EVENT_SOURCE_COAP;
	default:
		return 0;
	}
}

static bool natflow_dpi_commit_app(struct nf_conn *ct,
                                   const struct natflow_dpi_app_meta *app,
                                   unsigned int source,
                                   unsigned char direction)
{
	natflow_t *nf;
	bool committed;
	bool app_exists;
	bool context_cleared;

	if (!ct || !app || app->app_id == NATFLOW_DPI_APP_UNKNOWN || source == 0)
		return false;

	nf = natflow_session_get(ct);
	if (!nf) {
		atomic64_inc(&natflow_dpi_proto_no_session);
		return false;
	}

	spin_lock_bh(&ct->lock);
	committed = natflow_dpi_commit_app_locked(nf, app, &app_exists,
	            &context_cleared);
	spin_unlock_bh(&ct->lock);

	if (context_cleared)
		atomic64_inc(&natflow_dpi_context_cleared_app);
	if (app_exists) {
		atomic64_inc(&natflow_dpi_proto_app_exists);
		return false;
	}
	if (!committed)
		return false;

	natflow_dpi_event_queue(ct, NATFLOW_DPI_REASON_MATCHED,
	                        NATFLOW_DPI_CATALOG_REVISION, app->app_id,
	                        app->category_id, 0, source, direction);
	return true;
}

static void *natflow_dpi_ctl_start(struct seq_file *m, loff_t *pos)
{
	char *buffer = m->private;
	unsigned int i;
	int n;

	if (*pos != 0)
		return NULL;

	mutex_lock(&natflow_dpi_lock);
	n = snprintf(buffer, PAGE_SIZE - 1,
	             "# Version: %s\n"
	             "# Usage:\n"
	             "#    enable=0|1\n"
	             "#    events_clear\n"
	             "# Event ABI:\n"
	             "#    version=%u header_len=%u\n"
	             "\n"
	             "state=%s\n"
	             "enable=%u\n"
	             "catalog_revision=%u\n"
	             "catalog_apps=%u\n"
	             "matches=%llu\n"
	             "events=%llu\n"
	             "events_suppressed=%llu\n"
	             "events_lost=%llu\n"
	             "domain_lookups=%llu\n"
	             "domain_matches=%llu\n"
	             "dns_app_intents=%llu\n"
	             "packet_inspect_original=%llu\n"
	             "packet_inspect_reply=%llu\n"
	             "packet_match_original=%llu\n"
	             "packet_match_reply=%llu\n"
	             "context_armed=%llu\n"
	             "context_cleared_match=%llu\n"
	             "context_cleared_budget=%llu\n"
	             "context_cleared_transport=%llu\n"
	             "context_cleared_app=%llu\n"
	             "context_cleared_no_candidate=%llu\n"
	             "context_cleared_acct_limit=%llu\n"
	             "context_aborted=%llu\n"
	             "proto_no_session=%llu\n"
	             "proto_app_exists=%llu\n",
	             NATFLOW_VERSION,
	             NATFLOW_DPI_EVENT_VERSION,
	             (unsigned int)sizeof(struct natflow_dpi_event_hdr),
	             natflow_dpi_state_name(natflow_dpi_state),
	             natflow_dpi_state == NATFLOW_DPI_STATE_ENABLED,
	             NATFLOW_DPI_CATALOG_REVISION,
	             (unsigned int)ARRAY_SIZE(natflow_dpi_app_catalog),
	             (unsigned long long)atomic64_read(&natflow_dpi_matches),
	             (unsigned long long)atomic64_read(&natflow_dpi_events),
	             (unsigned long long)atomic64_read(&natflow_dpi_events_suppressed),
	             (unsigned long long)atomic64_read(&natflow_dpi_events_lost),
	             (unsigned long long)atomic64_read(&natflow_dpi_domain_lookups),
	             (unsigned long long)atomic64_read(&natflow_dpi_domain_matches),
	             (unsigned long long)atomic64_read(&natflow_dpi_dns_app_intents),
	             (unsigned long long)atomic64_read(&natflow_dpi_packet_inspections[IP_CT_DIR_ORIGINAL]),
	             (unsigned long long)atomic64_read(&natflow_dpi_packet_inspections[IP_CT_DIR_REPLY]),
	             (unsigned long long)atomic64_read(&natflow_dpi_packet_matches[IP_CT_DIR_ORIGINAL]),
	             (unsigned long long)atomic64_read(&natflow_dpi_packet_matches[IP_CT_DIR_REPLY]),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_armed),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_match),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_budget),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_transport),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_app),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_no_candidate),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_cleared_acct_limit),
	             (unsigned long long)atomic64_read(&natflow_dpi_context_aborted),
	             (unsigned long long)atomic64_read(&natflow_dpi_proto_no_session),
	             (unsigned long long)atomic64_read(&natflow_dpi_proto_app_exists));
	if (n >= 0 && n < PAGE_SIZE) {
		for (i = NATFLOW_DPI_EVENT_SOURCE_HTTP;
		        i <= NATFLOW_DPI_EVENT_SOURCE_MAX && n < PAGE_SIZE - 1; i++) {
			n += scnprintf(buffer + n, PAGE_SIZE - n,
			               "matches_%s=%llu\nevents_%s=%llu\n",
			               natflow_dpi_source_names[i],
			               (unsigned long long)atomic64_read(
			                   &natflow_dpi_source_matches[i]),
			               natflow_dpi_source_names[i],
			               (unsigned long long)atomic64_read(
			                   &natflow_dpi_source_events[i]));
		}
	}
	mutex_unlock(&natflow_dpi_lock);

	if (n < 0)
		return NULL;
	if (n >= PAGE_SIZE)
		n = PAGE_SIZE - 1;
	buffer[n] = 0;
	return buffer;
}

static void *natflow_dpi_ctl_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void natflow_dpi_ctl_stop(struct seq_file *m, void *v)
{
}

static int natflow_dpi_ctl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

static const struct seq_operations natflow_dpi_ctl_seq_ops = {
	.start = natflow_dpi_ctl_start,
	.next  = natflow_dpi_ctl_next,
	.stop  = natflow_dpi_ctl_stop,
	.show  = natflow_dpi_ctl_show,
};

static int natflow_dpi_ctl_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &natflow_dpi_ctl_seq_ops, PAGE_SIZE);
}

static int natflow_dpi_ctl_release(struct inode *inode, struct file *file)
{
	return seq_release_private(inode, file);
}

static int natflow_dpi_ctl_apply_line(char *data)
{
	int err = 0;

	mutex_lock(&natflow_dpi_lock);
	if (strcmp(data, "enable=1") == 0 || strcmp(data, "enable") == 0) {
		WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_ENABLED);
	} else if (strcmp(data, "enable=0") == 0 || strcmp(data, "disable") == 0) {
		WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);
		wake_up_interruptible(&natflow_dpi_wait);
	} else if (strcmp(data, "events_clear") == 0) {
		natflow_dpi_events_clear();
	} else {
		err = -EINVAL;
	}

	mutex_unlock(&natflow_dpi_lock);
	return err;
}

static ssize_t natflow_dpi_ctl_write(struct file *file, const char __user *buf,
                                     size_t buf_len, loff_t *offset)
{
	ssize_t ret;
	int err;
	int n, l;
	int cnt = NATFLOW_DPI_CTL_MAX_LINE;
	static char data[NATFLOW_DPI_CTL_MAX_LINE];
	static int data_left = 0;
	int old_data_left;

	mutex_lock(&natflow_dpi_write_lock);
	old_data_left = data_left;
	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0) {
		ret = -EACCES;
		goto out_unlock;
	}

	n = 0;
	if (old_data_left == 0) {
		while (n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t'))
			n++;
	}
	if (n) {
		*offset += n;
		data_left = 0;
		ret = n;
		goto out_unlock;
	}

	l = 0;
	while (l < cnt && data[l + data_left] != '\n')
		l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= NATFLOW_DPI_CTL_MAX_LINE) {
			data_left = 0;
			ret = -EINVAL;
			goto out_unlock;
		}
		goto done;
	}

	data[l + data_left] = 0;
	data_left = 0;
	l++;

	err = natflow_dpi_ctl_apply_line(data);
	if (err != 0) {
		ret = err;
		goto out_unlock;
	}

done:
	*offset += l;
	ret = l;
out_unlock:
	mutex_unlock(&natflow_dpi_write_lock);
	return ret;
}

static const struct file_operations natflow_dpi_ctl_fops = {
	.owner = THIS_MODULE,
	.open = natflow_dpi_ctl_open,
	.release = natflow_dpi_ctl_release,
	.read = seq_read,
	.write = natflow_dpi_ctl_write,
	.llseek = seq_lseek,
};

static int natflow_dpi_queue_open(struct inode *inode, struct file *file)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&natflow_dpi_event_lock);
	if (natflow_dpi_queue_readers != 0) {
		spin_unlock_bh(&natflow_dpi_event_lock);
		return -EBUSY;
	}
	WRITE_ONCE(natflow_dpi_queue_readers, 1);
	WRITE_ONCE(natflow_dpi_queue_cache_limit, 0);
	natflow_dpi_queue_write_state.data_left = 0;
	natflow_dpi_event_purge_locked(&free_list);
	spin_unlock_bh(&natflow_dpi_event_lock);

	natflow_dpi_event_free_list(&free_list);
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	return 0;
}

static int natflow_dpi_queue_release(struct inode *inode, struct file *file)
{
	LIST_HEAD(free_list);

	spin_lock_bh(&natflow_dpi_event_lock);
	WRITE_ONCE(natflow_dpi_queue_readers, 0);
	WRITE_ONCE(natflow_dpi_queue_cache_limit, 0);
	natflow_dpi_queue_write_state.data_left = 0;
	natflow_dpi_event_purge_locked(&free_list);
	spin_unlock_bh(&natflow_dpi_event_lock);

	natflow_dpi_event_free_list(&free_list);
	wake_up_interruptible(&natflow_dpi_wait);
	return 0;
}

static ssize_t natflow_dpi_queue_read(struct file *file, char __user *buf,
                                      size_t count, loff_t *ppos)
{
	struct natflow_dpi_event_node *node;
	size_t copied = 0;

	if (count < sizeof(struct natflow_dpi_event_hdr))
		return -EINVAL;

	while (count - copied >= sizeof(struct natflow_dpi_event_hdr)) {
		spin_lock_bh(&natflow_dpi_event_lock);
		if (list_empty(&natflow_dpi_event_list)) {
			spin_unlock_bh(&natflow_dpi_event_lock);
			break;
		}

		node = list_first_entry(&natflow_dpi_event_list,
		                        struct natflow_dpi_event_node, list);
		list_del(&node->list);
		natflow_dpi_event_count--;
		spin_unlock_bh(&natflow_dpi_event_lock);

		if (copy_to_user(buf + copied, &node->hdr, sizeof(node->hdr)) != 0) {
			kfree(node);
			return copied > 0 ? (ssize_t)copied : -EFAULT;
		}
		copied += sizeof(node->hdr);
		kfree(node);
	}
	return copied;
}

static ssize_t natflow_dpi_queue_write(struct file *file, const char __user *buf,
                                       size_t buf_len, loff_t *offset)
{
	return natflow_queue_cache_write(&natflow_dpi_queue_write_state, buf,
	                                 buf_len, offset,
	                                 natflow_dpi_queue_cache_set);
}

static unsigned int natflow_dpi_queue_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &natflow_dpi_wait, wait);
	spin_lock_bh(&natflow_dpi_event_lock);
	if (!list_empty(&natflow_dpi_event_list))
		mask = POLLIN | POLLRDNORM;
	spin_unlock_bh(&natflow_dpi_event_lock);
	return mask;
}

static const struct file_operations natflow_dpi_queue_fops = {
	.owner = THIS_MODULE,
	.open = natflow_dpi_queue_open,
	.release = natflow_dpi_queue_release,
	.read = natflow_dpi_queue_read,
	.write = natflow_dpi_queue_write,
	.poll = natflow_dpi_queue_poll,
	.llseek = natflow_no_llseek,
};

#define NATFLOW_DPI_PAYLOAD_INSPECT_MAX 96
#define NATFLOW_DPI_DNS_INSPECT_MAX (2 + 12 + NATFLOW_L7_DNS_QNAME_WIRE_MAX + 4)
#define NATFLOW_DPI_PAYLOAD_BYTE_BUDGET \
	(NATFLOW_DPI_DIRECTION_PACKET_BUDGET * NATFLOW_DPI_PAYLOAD_INSPECT_MAX)
#define NATFLOW_DPI_DNS_BYTE_BUDGET \
	(NATFLOW_DPI_DIRECTION_PACKET_BUDGET * NATFLOW_DPI_DNS_INSPECT_MAX)
static bool natflow_dpi_automaton_claimed(unsigned short automaton)
{
	return (automaton & NATFLOW_DPI_AUTOMATON_CLAIMED) != 0;
}

static unsigned int natflow_dpi_automaton_machine(unsigned short automaton)
{
	return (automaton & NATFLOW_DPI_AUTOMATON_MACHINE_MASK) >>
	       NATFLOW_DPI_AUTOMATON_MACHINE_SHIFT;
}

static unsigned short natflow_dpi_automaton_word(unsigned int machine,
        unsigned int state)
{
	return NATFLOW_DPI_AUTOMATON_CLAIMED |
	       ((machine << NATFLOW_DPI_AUTOMATON_MACHINE_SHIFT) &
	        NATFLOW_DPI_AUTOMATON_MACHINE_MASK) |
	       (state & NATFLOW_DPI_AUTOMATON_STATE_MASK);
}

static unsigned int natflow_dpi_context_machine_class_mask(const natflow_t *nf)
{
	unsigned short automaton = READ_ONCE(nf->dpi_automaton);

	if (natflow_dpi_automaton_claimed(automaton))
		return 0;
	return automaton & NATFLOW_DPI_AUTOMATON_DISCOVERY_MASK;
}

static bool natflow_dpi_context_set_machine_class_mask(natflow_t *nf,
        unsigned int machine_class_mask)
{
	unsigned short automaton;
	unsigned short next;

	next = machine_class_mask & NATFLOW_DPI_AUTOMATON_DISCOVERY_MASK;
	do {
		automaton = READ_ONCE(nf->dpi_automaton);
		if (natflow_dpi_automaton_claimed(automaton))
			return false;
	} while (cmpxchg(&nf->dpi_automaton, automaton, next) != automaton);
	return true;
}

static unsigned int natflow_dpi_context_intersect_machine_class_mask(
    natflow_t *nf, unsigned int machine_class_mask)
{
	unsigned short automaton;
	unsigned short next;

	do {
		automaton = READ_ONCE(nf->dpi_automaton);
		if (natflow_dpi_automaton_claimed(automaton))
			return 0;
		next = automaton & machine_class_mask &
		       NATFLOW_DPI_AUTOMATON_DISCOVERY_MASK;
	} while (cmpxchg(&nf->dpi_automaton, automaton, next) != automaton);
	return next;
}

static bool natflow_dpi_payload_has_token(const unsigned char *data,
        unsigned int data_len, const char *token, unsigned int token_len)
{
	unsigned int i;

	if (data_len < token_len)
		return false;
	for (i = 0; i <= data_len - token_len; i++) {
		if (memcmp(data + i, token, token_len) == 0)
			return true;
	}
	return false;
}

static bool natflow_dpi_ber_length(const unsigned char *data,
                                   unsigned int data_len, unsigned int *value,
                                   unsigned int *field_len)
{
	unsigned int bytes;
	unsigned int length = 0;
	unsigned int i;

	if (!data || data_len == 0 || !value || !field_len)
		return false;
	if (data[0] < 0x80) {
		*value = data[0];
		*field_len = 1;
		return true;
	}
	bytes = data[0] & 0x7f;
	if (bytes == 0 || bytes > 4 || data_len < bytes + 1 || data[1] == 0)
		return false;
	for (i = 0; i < bytes; i++)
		length = (length << 8) | data[i + 1];
	if (length < 0x80)
		return false;
	*value = length;
	*field_len = bytes + 1;
	return true;
}

static bool natflow_dpi_parse_ntp(const unsigned char *data,
                                  unsigned int payload_len, unsigned int inspect_len,
                                  __be16 sport, __be16 dport)
{
	unsigned int mode;
	unsigned int version;

	if ((sport != __constant_htons(123) &&
	        dport != __constant_htons(123)) || payload_len < 48 ||
	        inspect_len < 2)
		return false;
	version = (data[0] >> 3) & 0x07;
	mode = data[0] & 0x07;
	return version >= 1 && version <= 4 && mode >= 1 && mode <= 7 &&
	       data[1] <= 16;
}

static bool natflow_dpi_parse_snmp(const unsigned char *data,
                                   unsigned int payload_len, unsigned int inspect_len,
                                   __be16 sport, __be16 dport)
{
	unsigned int sequence_len;
	unsigned int sequence_len_len;
	unsigned int version_len;
	unsigned int version_len_len;
	unsigned int offset;

	if ((sport != __constant_htons(161) &&
	        sport != __constant_htons(162) &&
	        dport != __constant_htons(161) &&
	        dport != __constant_htons(162)) || payload_len <= 16 ||
	        inspect_len < 6 || data[0] != 0x30 ||
	        !natflow_dpi_ber_length(data + 1, inspect_len - 1,
	                                &sequence_len, &sequence_len_len) ||
	        sequence_len != payload_len - 1 - sequence_len_len)
		return false;
	offset = 1 + sequence_len_len;
	if (offset + 2 > inspect_len || data[offset] != 0x02 ||
	        !natflow_dpi_ber_length(data + offset + 1,
	                                inspect_len - offset - 1,
	                                &version_len, &version_len_len))
		return false;
	offset += 1 + version_len_len;
	return version_len == 1 && offset < inspect_len &&
	       (data[offset] == 0 || data[offset] == 1 || data[offset] == 3);
}

static bool natflow_dpi_parse_radius(const unsigned char *data,
                                     unsigned int payload_len, unsigned int inspect_len,
                                     __be16 sport, __be16 dport)
{
	if (sport != __constant_htons(1812) &&
	        sport != __constant_htons(1813) &&
	        sport != __constant_htons(18013) &&
	        dport != __constant_htons(1812) &&
	        dport != __constant_htons(1813) &&
	        dport != __constant_htons(18013))
		return false;
	return payload_len >= 20 && payload_len <= 4096 && inspect_len >= 4 &&
	       data[0] >= 1 && data[0] <= 13 &&
	       natflow_dpi_read_be16(data + 2) == payload_len;
}

static bool natflow_dpi_tftp_string(const unsigned char *data,
                                    unsigned int payload_len, unsigned int *offset,
                                    const unsigned char **string, unsigned int *string_len)
{
	unsigned int start;
	unsigned int i;

	if (!data || !offset || *offset >= payload_len)
		return false;
	start = *offset;
	for (i = start; i < payload_len && data[i] != 0; i++) {
		if (data[i] < 0x20 || data[i] > 0x7e)
			return false;
	}
	if (i == start || i == payload_len)
		return false;
	if (string)
		*string = data + start;
	if (string_len)
		*string_len = i - start;
	*offset = i + 1;
	return true;
}

static bool natflow_dpi_tftp_options(const unsigned char *data,
                                     unsigned int payload_len, unsigned int offset)
{
	const unsigned char *name;
	unsigned int name_len;
	unsigned int used = 0;
	unsigned int option;
	bool found = false;

	while (offset < payload_len) {
		if (!natflow_dpi_tftp_string(data, payload_len, &offset,
		                             &name, &name_len))
			return false;
		if (natflow_dpi_ascii_equal_nocase(name, name_len,
		                                   "blksize", 7))
			option = 1;
		else if (natflow_dpi_ascii_equal_nocase(name, name_len,
		                                        "tsize", 5))
			option = 2;
		else
			return false;
		if (used & option)
			return false;
		used |= option;
		if (!natflow_dpi_tftp_string(data, payload_len, &offset, NULL, NULL))
			return false;
		found = true;
	}
	return found;
}

static bool natflow_dpi_parse_tftp(const unsigned char *data,
                                   unsigned int payload_len, unsigned int inspect_len,
                                   unsigned char direction, __be16 sport, __be16 dport)
{
	const unsigned char *mode;
	unsigned int mode_len;
	unsigned int offset = 2;
	unsigned int opcode;

	if (payload_len < 4 || inspect_len < payload_len || data[0] != 0)
		return false;
	opcode = data[1];
	if ((opcode == 1 || opcode == 2) &&
	        direction == NATFLOW_L7_DIR_ORIGINAL &&
	        (sport == __constant_htons(69) ||
	         dport == __constant_htons(69))) {
		if (!natflow_dpi_tftp_string(data, payload_len, &offset, NULL, NULL) ||
		        !natflow_dpi_tftp_string(data, payload_len, &offset,
		                                 &mode, &mode_len))
			return false;
		if (!natflow_dpi_ascii_equal_nocase(mode, mode_len, "netascii", 8) &&
		        !natflow_dpi_ascii_equal_nocase(mode, mode_len, "octet", 5) &&
		        !natflow_dpi_ascii_equal_nocase(mode, mode_len, "mail", 4))
			return false;
		return offset == payload_len ||
		       natflow_dpi_tftp_options(data, payload_len, offset);
	}
	/* OACK commonly starts a related flow from the server's dynamic TID. */
	return opcode == 6 &&
	       natflow_dpi_tftp_options(data, payload_len, offset);
}

static bool natflow_dpi_parse_ldap(const unsigned char *data,
                                   unsigned int payload_len, unsigned int inspect_len,
                                   __be16 sport, __be16 dport)
{
	unsigned int sequence_len;
	unsigned int sequence_len_len;
	unsigned int message_len;
	unsigned int message_len_len;
	unsigned int offset;
	unsigned int op;

	if ((sport != __constant_htons(389) &&
	        dport != __constant_htons(389)) || payload_len < 7 ||
	        inspect_len < 7 || data[0] != 0x30 ||
	        !natflow_dpi_ber_length(data + 1, inspect_len - 1,
	                                &sequence_len, &sequence_len_len) ||
	        sequence_len != payload_len - 1 - sequence_len_len)
		return false;
	offset = 1 + sequence_len_len;
	if (offset + 2 > inspect_len || data[offset] != 0x02 ||
	        !natflow_dpi_ber_length(data + offset + 1,
	                                inspect_len - offset - 1,
	                                &message_len, &message_len_len))
		return false;
	if (message_len == 0 || message_len > 4)
		return false;
	offset += 1 + message_len_len + message_len;
	if (offset >= inspect_len)
		return false;
	op = data[offset];
	return (op & 0xe0) == 0x60 && (op & 0x1f) <= 25;
}

static bool natflow_dpi_parse_coap(const unsigned char *data,
                                   unsigned int payload_len, unsigned int inspect_len,
                                   __be16 sport, __be16 dport)
{
	unsigned int source_port = ntohs(sport);
	unsigned int destination_port = ntohs(dport);
	unsigned int token_len;
	unsigned int code;

	if ((source_port != 5683 &&
	        (source_port < 61616 || source_port > 61631) &&
	        destination_port != 5683 &&
	        (destination_port < 61616 || destination_port > 61631)) ||
	        payload_len < 4 || inspect_len < 4 || (data[0] >> 6) != 1)
		return false;
	token_len = data[0] & 0x0f;
	if (token_len > 8 || payload_len < 4 + token_len)
		return false;
	code = data[1];
	if (code == 0)
		return token_len == 0 && payload_len == 4;
	return code <= 5 || (code >= 65 && code <= 69) ||
	       (code >= 128 && code <= 134) ||
	       (code >= 140 && code <= 143) ||
	       (code >= 160 && code <= 165);
}

static unsigned int natflow_dpi_parse_network_protocol(
    const unsigned char *data, unsigned int payload_len,
    unsigned int inspect_len, unsigned char l4proto,
    unsigned char direction, __be16 sport, __be16 dport)
{
	if (l4proto == IPPROTO_UDP &&
	        natflow_dpi_parse_ntp(data, payload_len, inspect_len, sport, dport))
		return NATFLOW_DPI_PROTO_NTP;
	if (l4proto == IPPROTO_UDP &&
	        natflow_dpi_parse_snmp(data, payload_len, inspect_len, sport, dport))
		return NATFLOW_DPI_PROTO_SNMP;
	if (l4proto == IPPROTO_UDP &&
	        natflow_dpi_parse_radius(data, payload_len, inspect_len, sport, dport))
		return NATFLOW_DPI_PROTO_RADIUS;
	if (l4proto == IPPROTO_UDP &&
	        natflow_dpi_parse_tftp(data, payload_len, inspect_len, direction,
	                               sport, dport))
		return NATFLOW_DPI_PROTO_TFTP;
	if (natflow_dpi_parse_ldap(data, payload_len, inspect_len, sport, dport))
		return NATFLOW_DPI_PROTO_LDAP;
	if (l4proto == IPPROTO_UDP &&
	        natflow_dpi_parse_coap(data, payload_len, inspect_len, sport, dport))
		return NATFLOW_DPI_PROTO_COAP;
	return 0;
}

static bool natflow_dpi_parse_nfs(const unsigned char *data,
                                  unsigned int payload_len, unsigned int inspect_len,
                                  unsigned char l4proto)
{
	unsigned int offset = l4proto == IPPROTO_TCP ? 4 : 0;
	unsigned int program;

	if (payload_len < 40 + offset || inspect_len < 20 + offset)
		return false;
	if (offset && (natflow_dpi_read_be32(data) & 0x80000000u) == 0)
		return false;
	if (offset && (natflow_dpi_read_be32(data) & 0x7fffffffu) !=
	        payload_len - offset)
		return false;
	if (natflow_dpi_read_be32(data + 4 + offset) != 0 ||
	        natflow_dpi_read_be32(data + 8 + offset) != 2)
		return false;
	program = natflow_dpi_read_be32(data + 12 + offset);
	if (program != 0x000186a5 && program != 0x000186a3 &&
	        program != 0x000186a0)
		return false;
	return natflow_dpi_read_be32(data + 16 + offset) <= 4;
}

static unsigned int natflow_dpi_parse_stun_turn(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int msg_type;
	unsigned int msg_len;
	unsigned int method;

	if (payload_len < 20 || inspect_len < 8)
		return 0;
	if (data[0] & 0xc0)
		return 0;
	msg_type = ((unsigned int)data[0] << 8) | data[1];
	msg_len = ((unsigned int)data[2] << 8) | data[3];
	if ((msg_len & 0x3) != 0 || msg_len > payload_len - 20)
		return 0;
	if (data[4] != 0x21 || data[5] != 0x12 || data[6] != 0xa4 || data[7] != 0x42)
		return 0;

	method = (msg_type & 0x000f) |
	         ((msg_type & 0x00e0) >> 1) |
	         ((msg_type & 0x3e00) >> 2);
	switch (method) {
	case 0x003: /* Allocate */
	case 0x004: /* Refresh */
	case 0x006: /* Send */
	case 0x007: /* Data */
	case 0x008: /* CreatePermission */
	case 0x009: /* ChannelBind */
		return NATFLOW_DPI_PROTO_TURN;
	default:
		return NATFLOW_DPI_PROTO_STUN;
	}
}

static unsigned int natflow_dpi_parse_wireguard_udp(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int message_type;

	if (inspect_len < 4)
		return 0;
	if (data[1] != 0 || data[2] != 0 || data[3] != 0)
		return 0;

	message_type = data[0];
	switch (message_type) {
	case 1: /* Handshake Initiation */
		if (payload_len == 148)
			return NATFLOW_DPI_PROTO_WIREGUARD;
		break;
	case 2: /* Handshake Response */
		if (payload_len == 92)
			return NATFLOW_DPI_PROTO_WIREGUARD;
		break;
	case 3: /* Cookie Reply */
		if (payload_len == 64)
			return NATFLOW_DPI_PROTO_WIREGUARD;
		break;
	case 4: /* Transport Data */
		if (payload_len >= 32 && (payload_len & 0x0f) == 0)
			return NATFLOW_DPI_PROTO_WIREGUARD;
		break;
	default:
		break;
	}

	return 0;
}

static unsigned int natflow_dpi_parse_bittorrent_tcp(const unsigned char *data,
        unsigned int inspect_len)
{
	if (inspect_len >= 20 &&
	        data[0] == 19 &&
	        memcmp(data + 1, "BitTorrent protocol", 19) == 0)
		return NATFLOW_DPI_PROTO_BITTORRENT;

	return 0;
}

static unsigned int natflow_dpi_parse_ssh_tcp(const unsigned char *data,
        unsigned int inspect_len)
{
	unsigned int i;
	unsigned int limit;

	if (inspect_len < 8)
		return 0;
	if (memcmp(data, "SSH-", 4) != 0)
		return 0;
	if (data[4] != '1' && data[4] != '2')
		return 0;
	if (data[5] != '.')
		return 0;
	if (data[6] < '0' || data[6] > '9')
		return 0;

	limit = inspect_len < 16 ? inspect_len : 16;
	for (i = 7; i < limit; i++) {
		if (data[i] == '-')
			return NATFLOW_DPI_PROTO_SSH;
		if ((data[i] < '0' || data[i] > '9') && data[i] != '.')
			return 0;
	}
	return 0;
}

static bool natflow_dpi_payload_is_utp(const unsigned char *data,
                                       unsigned int inspect_len)
{
	unsigned char utp_type;
	unsigned char utp_version;
	unsigned char utp_extension;
	unsigned int extension_count = 0;
	unsigned int offset = 20;

	if (inspect_len < 20)
		return false;

	utp_type = data[0] >> 4;
	utp_version = data[0] & 0x0f;
	utp_extension = data[1];

	if (utp_version != 1 || utp_type > 4)
		return false;
	if (utp_extension > 2)
		return false;
	/* A DATA packet with connection ID 0 overlaps WireGuard type 1. */
	if (data[0] == 1 && data[2] == 0 && data[3] == 0)
		return false;

	while (utp_extension != 0) {
		unsigned int extension_len;

		if (++extension_count > 4 || offset > inspect_len ||
		        inspect_len - offset < 2)
			return false;
		utp_extension = data[offset++];
		extension_len = data[offset++];
		if (extension_len == 0 || extension_len > inspect_len - offset)
			return false;
		offset += extension_len;
		if (utp_extension > 2)
			return false;
	}

	return true;
}

static unsigned int natflow_dpi_parse_bittorrent_udp(const unsigned char *data,
        unsigned int inspect_len)
{
	if (natflow_dpi_payload_is_utp(data, inspect_len))
		return NATFLOW_DPI_PROTO_BITTORRENT;
	if (inspect_len >= 8 && data[0] == 'd') {
		if (natflow_dpi_payload_has_token(data, inspect_len, "1:y1:q", 6) ||
		        natflow_dpi_payload_has_token(data, inspect_len, "1:y1:r", 6) ||
		        natflow_dpi_payload_has_token(data, inspect_len, "1:y1:e", 6))
			return NATFLOW_DPI_PROTO_BITTORRENT;
	}

	return 0;
}

static bool natflow_dpi_payload_starts(const unsigned char *data,
                                       unsigned int inspect_len, const char *prefix, unsigned int prefix_len)
{
	return inspect_len >= prefix_len && memcmp(data, prefix, prefix_len) == 0;
}

static unsigned int natflow_dpi_text_line_len(const unsigned char *data,
        unsigned int inspect_len)
{
	unsigned int i;

	for (i = 0; i + 1 < inspect_len; i++) {
		if (data[i] == '\r' && data[i + 1] == '\n')
			return i + 2;
	}
	return 0;
}

static unsigned int natflow_dpi_parse_text_protocol(const unsigned char *data,
        unsigned int inspect_len, unsigned int proto_mask)
{
	unsigned int line_len;
	unsigned int i;

	line_len = natflow_dpi_text_line_len(data, inspect_len);
	if (line_len == 0)
		return 0;
	inspect_len = line_len;

	if (proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SIP)) {
		static const char * const methods[] = {
			"INVITE ", "REGISTER ", "ACK ", "BYE ", "CANCEL ",
			"OPTIONS ", "SUBSCRIBE ", "NOTIFY ", "MESSAGE ",
		};

		if (inspect_len >= 13 &&
		        natflow_dpi_payload_starts(data, inspect_len, "SIP/2.0 ", 8) &&
		        data[8] >= '1' && data[8] <= '6' &&
		        data[9] >= '0' && data[9] <= '9' &&
		        data[10] >= '0' && data[10] <= '9')
			return NATFLOW_DPI_PROTO_SIP;
		for (i = 0; i < ARRAY_SIZE(methods); i++) {
			unsigned int len = strlen(methods[i]);

			if (natflow_dpi_payload_starts(data, inspect_len, methods[i], len) &&
			        natflow_dpi_payload_has_token(data + len,
			                                      inspect_len - len, " SIP/2.0\r\n", 10) &&
			        (natflow_dpi_payload_starts(data + len,
			                                    inspect_len - len, "sip:", 4) ||
			         natflow_dpi_payload_starts(data + len,
			                                    inspect_len - len, "sips:", 5)))
				return NATFLOW_DPI_PROTO_SIP;
		}
	}

	if (proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_RTSP)) {
		static const char * const methods[] = {
			"OPTIONS ", "DESCRIBE ", "ANNOUNCE ", "SETUP ", "PLAY ",
			"PAUSE ", "TEARDOWN ", "GET_PARAMETER ", "SET_PARAMETER ",
		};

		if (inspect_len >= 14 &&
		        (natflow_dpi_payload_starts(data, inspect_len, "RTSP/1.0 ", 9) ||
		         natflow_dpi_payload_starts(data, inspect_len, "RTSP/2.0 ", 9)) &&
		        data[9] >= '1' && data[9] <= '6' &&
		        data[10] >= '0' && data[10] <= '9' &&
		        data[11] >= '0' && data[11] <= '9')
			return NATFLOW_DPI_PROTO_RTSP;
		for (i = 0; i < ARRAY_SIZE(methods); i++) {
			unsigned int len = strlen(methods[i]);

			if (natflow_dpi_payload_starts(data, inspect_len, methods[i], len) &&
			        natflow_dpi_payload_starts(data + len,
			                                   inspect_len - len, "rtsp://", 7) &&
			        (natflow_dpi_payload_has_token(data + len,
			                                       inspect_len - len, " RTSP/1.0\r\n", 11) ||
			         natflow_dpi_payload_has_token(data + len,
			                                       inspect_len - len, " RTSP/2.0\r\n", 11)))
				return NATFLOW_DPI_PROTO_RTSP;
		}
	}

	if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SMTP)) &&
	        (natflow_dpi_payload_starts(data, inspect_len, "EHLO ", 5) ||
	         natflow_dpi_payload_starts(data, inspect_len, "HELO ", 5) ||
	         natflow_dpi_payload_starts(data, inspect_len, "MAIL FROM:<", 11) ||
	         natflow_dpi_payload_starts(data, inspect_len, "RCPT TO:<", 9)))
		return NATFLOW_DPI_PROTO_SMTP;

	if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_FTP)) &&
	        (natflow_dpi_payload_starts(data, inspect_len, "PASV\r\n", 6) ||
	         natflow_dpi_payload_starts(data, inspect_len, "EPSV\r\n", 6) ||
	         (natflow_dpi_payload_starts(data, inspect_len, "EPRT |", 6) &&
	          natflow_dpi_payload_has_token(data + 6, inspect_len - 6, "|", 1)) ||
	         (natflow_dpi_payload_starts(data, inspect_len, "PORT ", 5) &&
	          natflow_dpi_payload_has_token(data + 5, inspect_len - 5, ",", 1))))
		return NATFLOW_DPI_PROTO_FTP;

	if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_POP3)) &&
	        (natflow_dpi_payload_starts(data, inspect_len, "CAPA\r\n", 6) ||
	         natflow_dpi_payload_starts(data, inspect_len, "STLS\r\n", 6) ||
	         natflow_dpi_payload_starts(data, inspect_len, "APOP ", 5)))
		return NATFLOW_DPI_PROTO_POP3;

	if (proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_IMAP)) {
		for (i = 1; i < inspect_len && i <= 16; i++) {
			if (!((data[i - 1] >= 'a' && data[i - 1] <= 'z') ||
			        (data[i - 1] >= 'A' && data[i - 1] <= 'Z') ||
			        (data[i - 1] >= '0' && data[i - 1] <= '9')))
				break;
			if (data[i] != ' ')
				continue;
			if (natflow_dpi_payload_starts(data + i + 1,
			                               inspect_len - i - 1, "CAPABILITY\r\n", 12) ||
			        natflow_dpi_payload_starts(data + i + 1,
			                                   inspect_len - i - 1, "STARTTLS\r\n", 10) ||
			        natflow_dpi_payload_starts(data + i + 1,
			                                   inspect_len - i - 1, "LOGIN ", 6) ||
			        natflow_dpi_payload_starts(data + i + 1,
			                                   inspect_len - i - 1, "SELECT ", 7))
				return NATFLOW_DPI_PROTO_IMAP;
			break;
		}
	}
	return 0;
}

static int natflow_dpi_parse_decimal(const unsigned char *data,
                                     unsigned int len, unsigned int *value, unsigned int *consumed)
{
	unsigned int number = 0;
	unsigned int i;

	if (len == 0 || data[0] < '0' || data[0] > '9')
		return -EINVAL;
	for (i = 0; i < len && i < 6; i++) {
		if (data[i] < '0' || data[i] > '9')
			break;
		number = number * 10 + data[i] - '0';
	}
	if (i == len || i == 6 || data[i] != '\r' || i + 1 >= len ||
	        data[i + 1] != '\n')
		return -EINVAL;
	*value = number;
	*consumed = i + 2;
	return 0;
}

static unsigned int natflow_dpi_parse_resp(const unsigned char *data,
        unsigned int inspect_len)
{
	static const char * const commands[] = {
		"GET", "SET", "DEL", "MGET", "MSET", "AUTH", "HELLO", "PING",
		"INFO", "SELECT", "SUBSCRIBE", "PUBLISH", "HGET", "HSET", "EVAL",
	};
	unsigned int array_count;
	unsigned int command_len;
	unsigned int consumed;
	unsigned int offset;
	unsigned int i;

	if (inspect_len < 10 || data[0] != '*' ||
	        natflow_dpi_parse_decimal(data + 1, inspect_len - 1,
	                                  &array_count, &consumed) ||
	        array_count == 0 || array_count > 1024)
		return 0;
	offset = 1 + consumed;
	if (offset >= inspect_len || data[offset++] != '$' ||
	        natflow_dpi_parse_decimal(data + offset, inspect_len - offset,
	                                  &command_len, &consumed) ||
	        command_len == 0 || command_len > 16)
		return 0;
	offset += consumed;
	if (command_len + 2 > inspect_len - offset ||
	        data[offset + command_len] != '\r' ||
	        data[offset + command_len + 1] != '\n')
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		unsigned int len = strlen(commands[i]);
		unsigned int j;

		if (len != command_len)
			continue;
		for (j = 0; j < len; j++) {
			unsigned char c = data[offset + j];
			if (c >= 'a' && c <= 'z')
				c -= 'a' - 'A';
			if (c != commands[i][j])
				break;
		}
		if (j == len)
			return NATFLOW_DPI_PROTO_RESP;
	}
	return 0;
}

static unsigned int natflow_dpi_parse_postgresql(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int length;
	unsigned int code;

	if (inspect_len < 8)
		return 0;
	length = ((unsigned int)data[0] << 24) | ((unsigned int)data[1] << 16) |
	         ((unsigned int)data[2] << 8) | data[3];
	code = ((unsigned int)data[4] << 24) | ((unsigned int)data[5] << 16) |
	       ((unsigned int)data[6] << 8) | data[7];
	if (length > payload_len || length < 8)
		return 0;
	if ((length == 8 && code == 80877103U) ||
	        (length == 16 && code == 80877102U))
		return NATFLOW_DPI_PROTO_POSTGRESQL;
	if (code == 0x00030000 && length >= 15 && inspect_len >= 13 &&
	        memcmp(data + 8, "user\0", 5) == 0)
		return NATFLOW_DPI_PROTO_POSTGRESQL;
	return 0;
}

static unsigned int natflow_dpi_parse_mysql(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int packet_len;
	unsigned int nul;

	if (inspect_len < 22 || data[3] != 0 || data[4] != 10)
		return 0;
	packet_len = data[0] | ((unsigned int)data[1] << 8) |
	             ((unsigned int)data[2] << 16);
	if (packet_len < 30 || packet_len + 4 > payload_len)
		return 0;
	for (nul = 5; nul < inspect_len && nul < 64; nul++) {
		if (data[nul] == 0)
			break;
		if (data[nul] < 0x20 || data[nul] > 0x7e)
			return 0;
	}
	if (nul < 8 || nul + 16 > inspect_len || data[nul + 13] != 0)
		return 0;
	if (data[nul + 14] == 0 && data[nul + 15] == 0)
		return 0;
	return NATFLOW_DPI_PROTO_MYSQL;
}

static unsigned int natflow_dpi_parse_database_protocol(
    const unsigned char *data,
    unsigned int payload_len, unsigned int inspect_len,
    unsigned char direction, unsigned int proto_mask)
{
	if (direction == NATFLOW_L7_DIR_ORIGINAL) {
		if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_RESP)) &&
		        natflow_dpi_parse_resp(data, inspect_len))
			return NATFLOW_DPI_PROTO_RESP;
		if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_POSTGRESQL)) &&
		        natflow_dpi_parse_postgresql(data, payload_len, inspect_len))
			return NATFLOW_DPI_PROTO_POSTGRESQL;
	} else if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_MYSQL)) &&
	           natflow_dpi_parse_mysql(data, payload_len, inspect_len)) {
		return NATFLOW_DPI_PROTO_MYSQL;
	}
	return 0;
}

static unsigned int natflow_dpi_parse_mqtt(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int multiplier = 1;
	unsigned int remaining = 0;
	unsigned int offset = 1;
	unsigned int encoded;

	if (inspect_len < 12 || data[0] != 0x10)
		return 0;
	do {
		if (offset >= inspect_len || offset > 4)
			return 0;
		encoded = data[offset++];
		remaining += (encoded & 0x7f) * multiplier;
		multiplier *= 128;
	} while (encoded & 0x80);
	if (remaining < 10 || remaining > payload_len - offset ||
	        offset + 9 > inspect_len)
		return 0;
	if (data[offset] != 0 || data[offset + 1] != 4 ||
	        memcmp(data + offset + 2, "MQTT", 4) != 0 ||
	        (data[offset + 6] != 4 && data[offset + 6] != 5) ||
	        (data[offset + 7] & 0x01))
		return 0;
	return NATFLOW_DPI_PROTO_MQTT;
}

static unsigned int natflow_dpi_parse_smb(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len)
{
	unsigned int offset = 0;
	unsigned int nbss_len = 0;
	bool has_nbss = false;

	if (inspect_len >= 8 && data[0] == 0) {
		nbss_len = ((unsigned int)data[1] << 16) |
		           ((unsigned int)data[2] << 8) | data[3];
		if (nbss_len > payload_len - 4)
			return 0;
		offset = 4;
		has_nbss = true;
	}
	if (inspect_len - offset >= 64 && data[offset] == 0xfe &&
	        memcmp(data + offset + 1, "SMB", 3) == 0 &&
	        data[offset + 4] == 64 && data[offset + 5] == 0 &&
	        (!has_nbss || nbss_len >= 64))
		return NATFLOW_DPI_PROTO_SMB;
	if (inspect_len - offset >= 32 && data[offset] == 0xff &&
	        memcmp(data + offset + 1, "SMB", 3) == 0 &&
	        (!has_nbss || nbss_len >= 32))
		return NATFLOW_DPI_PROTO_SMB;
	return 0;
}

static unsigned int natflow_dpi_rdp_evidence(const unsigned char *data,
        unsigned int payload_len, unsigned int inspect_len,
        unsigned char direction)
{
	unsigned int length;

	if (inspect_len < 11 || data[0] != 3 || data[1] != 0)
		return 0;
	length = ((unsigned int)data[2] << 8) | data[3];
	if (length < 11 || length > payload_len || data[4] != length - 5 ||
	        data[10] != 0)
		return 0;
	if (direction == NATFLOW_L7_DIR_ORIGINAL && data[5] == 0xe0)
		return NATFLOW_DPI_RDP_HAVE_REQUEST;
	if (direction == NATFLOW_L7_DIR_REPLY && data[5] == 0xd0)
		return NATFLOW_DPI_RDP_HAVE_CONFIRM;
	return 0;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_native_machine_pending(void)
{
	struct natflow_dpi_native_machine_result result = {
		.proto = 0,
		.status = NATFLOW_DPI_NATIVE_MACHINE_PENDING,
	};

	return result;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_native_machine_terminal(unsigned int proto)
{
	struct natflow_dpi_native_machine_result result = {
		.proto = proto,
		.status = NATFLOW_DPI_NATIVE_MACHINE_TERMINAL,
	};

	return result;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_native_machine_excluded(void)
{
	struct natflow_dpi_native_machine_result result = {
		.proto = 0,
		.status = NATFLOW_DPI_NATIVE_MACHINE_EXCLUDED,
	};

	return result;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_rdp_machine_step(natflow_t *nf, unsigned int evidence)
{
	unsigned short automaton;
	unsigned short next;
	unsigned int state;

	if (!nf)
		return natflow_dpi_native_machine_excluded();
	if (evidence != 0 && evidence != NATFLOW_DPI_RDP_HAVE_REQUEST &&
	        evidence != NATFLOW_DPI_RDP_HAVE_CONFIRM)
		return natflow_dpi_native_machine_excluded();

	for (;;) {
		automaton = READ_ONCE(nf->dpi_automaton);
		if (natflow_dpi_automaton_claimed(automaton)) {
			if (natflow_dpi_automaton_machine(automaton) !=
			        NATFLOW_DPI_AUTOMATON_MACHINE_RDP)
				return natflow_dpi_native_machine_excluded();
			state = automaton & NATFLOW_DPI_AUTOMATON_STATE_MASK;
			if ((state & ~NATFLOW_DPI_RDP_COMPLETE) != 0)
				return natflow_dpi_native_machine_excluded();
			if (state == NATFLOW_DPI_RDP_COMPLETE)
				return natflow_dpi_native_machine_terminal(
				           NATFLOW_DPI_PROTO_RDP);
			if (evidence == 0)
				return natflow_dpi_native_machine_pending();
		} else {
			if (evidence == 0)
				return natflow_dpi_native_machine_pending();
			state = 0;
		}

		state |= evidence;
		next = natflow_dpi_automaton_word(
		           NATFLOW_DPI_AUTOMATON_MACHINE_RDP, state);
		if (cmpxchg(&nf->dpi_automaton, automaton, next) != automaton)
			continue;
		if (state == NATFLOW_DPI_RDP_COMPLETE)
			return natflow_dpi_native_machine_terminal(
			           NATFLOW_DPI_PROTO_RDP);
		return natflow_dpi_native_machine_pending();
	}
}

static unsigned int natflow_dpi_parse_socks_request(
    const unsigned char *data, unsigned int payload_len,
    unsigned int inspect_len)
{
	if (payload_len >= 9 && inspect_len >= payload_len && data[0] == 0x04 &&
	        (data[1] == 0x01 || data[1] == 0x02) &&
	        data[payload_len - 1] == 0x00)
		return NATFLOW_DPI_SOCKS_VERSION_4;
	if (payload_len == 3 && inspect_len >= 3 && data[0] == 0x05 &&
	        data[1] == 0x01 && data[2] == 0x00)
		return NATFLOW_DPI_SOCKS_VERSION_5;
	if (payload_len == 4 && inspect_len >= 4 && data[0] == 0x05 &&
	        data[1] == 0x02 && data[2] == 0x00 && data[3] == 0x01)
		return NATFLOW_DPI_SOCKS_VERSION_5;
	return 0;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_socks_machine_step(natflow_t *nf, const unsigned char *data,
                               unsigned int payload_len, unsigned int inspect_len,
                               unsigned char direction)
{
	unsigned short automaton;
	unsigned int state;

	if (!nf || !data || inspect_len == 0)
		return natflow_dpi_native_machine_pending();
	automaton = READ_ONCE(nf->dpi_automaton);
	if (!natflow_dpi_automaton_claimed(automaton)) {
		if (direction != NATFLOW_L7_DIR_ORIGINAL)
			return natflow_dpi_native_machine_pending();
		state = natflow_dpi_parse_socks_request(data, payload_len,
		                                        inspect_len);
		if (state == 0)
			return natflow_dpi_native_machine_pending();
		if (cmpxchg(&nf->dpi_automaton, automaton,
		            natflow_dpi_automaton_word(
		                NATFLOW_DPI_AUTOMATON_MACHINE_SOCKS,
		                state)) != automaton)
			return natflow_dpi_native_machine_pending();
		return natflow_dpi_native_machine_pending();
	}
	if (natflow_dpi_automaton_machine(automaton) !=
	        NATFLOW_DPI_AUTOMATON_MACHINE_SOCKS)
		return natflow_dpi_native_machine_excluded();
	state = automaton & NATFLOW_DPI_AUTOMATON_STATE_MASK;
	if (state != NATFLOW_DPI_SOCKS_VERSION_4 &&
	        state != NATFLOW_DPI_SOCKS_VERSION_5)
		return natflow_dpi_native_machine_excluded();
	if (direction == NATFLOW_L7_DIR_ORIGINAL)
		return natflow_dpi_native_machine_pending();
	if (state == NATFLOW_DPI_SOCKS_VERSION_4 && payload_len == 8 &&
	        inspect_len >= 8 && data[0] == 0x00 &&
	        data[1] >= 0x5a && data[1] <= 0x5d)
		return natflow_dpi_native_machine_terminal(NATFLOW_DPI_PROTO_SOCKS);
	if (state == NATFLOW_DPI_SOCKS_VERSION_5 && payload_len == 2 &&
	        inspect_len >= 2 && data[0] == 0x05 && data[1] == 0x00)
		return natflow_dpi_native_machine_terminal(NATFLOW_DPI_PROTO_SOCKS);
	return natflow_dpi_native_machine_excluded();
}

static unsigned int natflow_dpi_parse_binary_protocol(
    const unsigned char *data,
    unsigned int payload_len, unsigned int inspect_len,
    unsigned char direction, unsigned int proto_mask)
{
	if ((proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SMB)) &&
	        natflow_dpi_parse_smb(data, payload_len, inspect_len))
		return NATFLOW_DPI_PROTO_SMB;
	if (direction == NATFLOW_L7_DIR_ORIGINAL &&
	        (proto_mask & NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_MQTT)) &&
	        natflow_dpi_parse_mqtt(data, payload_len, inspect_len))
		return NATFLOW_DPI_PROTO_MQTT;
	return 0;
}

static unsigned int natflow_dpi_automaton_machine_class_mask(
    unsigned short automaton)
{
	if (!natflow_dpi_automaton_claimed(automaton))
		return automaton & NATFLOW_DPI_AUTOMATON_DISCOVERY_MASK;

	switch (natflow_dpi_automaton_machine(automaton)) {
	case NATFLOW_DPI_AUTOMATON_MACHINE_RDP:
		return NATFLOW_DPI_MACHINE_CLASS_BIT(
		           NATFLOW_DPI_MACHINE_CLASS_BINARY);
	case NATFLOW_DPI_AUTOMATON_MACHINE_SOCKS:
		return NATFLOW_DPI_MACHINE_CLASS_BIT(
		           NATFLOW_DPI_MACHINE_CLASS_BINARY);
	case NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP:
		return NATFLOW_DPI_MACHINE_CLASS_BIT(
		           NATFLOW_DPI_MACHINE_CLASS_TEXT);
	default:
		return 0;
	}
}

static int natflow_dpi_direction_index(unsigned char direction)
{
	if (direction == NATFLOW_L7_DIR_ORIGINAL)
		return NF_FF_DIR_ORIGINAL;
	if (direction == NATFLOW_L7_DIR_REPLY)
		return NF_FF_DIR_REPLY;
	return -EINVAL;
}

static bool natflow_dpi_context_clear_locked(natflow_t *nf)
{
	bool active;

	if (!nf)
		return false;

	active = (READ_ONCE(nf->status) & NF_FF_DPI_USE) != 0;
	if (active)
		simple_clear_bit(NF_FF_DPI_USE_BIT, &nf->status);
	nf->dpi_byte_count[NF_FF_DIR_ORIGINAL] = 0;
	nf->dpi_byte_count[NF_FF_DIR_REPLY] = 0;
	nf->dpi_packet_count[NF_FF_DIR_ORIGINAL] = 0;
	nf->dpi_packet_count[NF_FF_DIR_REPLY] = 0;
	xchg(&nf->dpi_automaton, 0);
	return active;
}

static bool natflow_dpi_commit_app_locked(natflow_t *nf,
        const struct natflow_dpi_app_meta *app, bool *app_exists,
        bool *context_cleared)
{
	bool committed = false;

	*app_exists = false;
	*context_cleared = false;
	if (!nf || !app || app->app_id == NATFLOW_DPI_APP_UNKNOWN)
		return false;

	if (READ_ONCE(nf->app_id) != NATFLOW_DPI_APP_UNKNOWN) {
		*app_exists = true;
	} else if (cmpxchg(&nf->app_id, NATFLOW_DPI_APP_UNKNOWN, app->app_id) ==
	           NATFLOW_DPI_APP_UNKNOWN) {
		committed = true;
	} else {
		*app_exists = true;
	}
	if (committed || *app_exists) {
		*context_cleared = natflow_dpi_context_clear_locked(nf);
		simple_set_bit(NF_FF_L7_DPI_PACKET_DONE_BIT, &nf->status);
	}
	return committed;
}

void natflow_dpi_packet_context_abort(struct nf_conn *ct)
{
	natflow_t *nf;
	bool active;

	if (!ct)
		return;
	nf = natflow_session_get(ct);
	if (!nf)
		return;

	spin_lock_bh(&ct->lock);
	active = natflow_dpi_context_clear_locked(nf);
	spin_unlock_bh(&ct->lock);
	if (active)
		atomic64_inc(&natflow_dpi_context_aborted);
}

static bool natflow_dpi_packet_direction_valid(unsigned char direction)
{
	return direction == NATFLOW_L7_DIR_ORIGINAL ||
	       direction == NATFLOW_L7_DIR_REPLY;
}

static bool natflow_dpi_l4_supported(unsigned char l4proto)
{
	return l4proto == IPPROTO_TCP || l4proto == IPPROTO_UDP;
}

static unsigned int natflow_dpi_payload_machine_class_mask(
    unsigned char l4proto)
{
	unsigned int mask;

	if (!natflow_dpi_l4_supported(l4proto))
		return 0;

	mask = NATFLOW_DPI_MACHINE_CLASS_BIT(
	           NATFLOW_DPI_MACHINE_CLASS_STUN_TURN) |
	       NATFLOW_DPI_MACHINE_CLASS_BIT(
	           NATFLOW_DPI_MACHINE_CLASS_BITTORRENT) |
	       NATFLOW_DPI_MACHINE_CLASS_BIT(NATFLOW_DPI_MACHINE_CLASS_TEXT);
	if (l4proto == IPPROTO_TCP)
		mask |= NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_SSH) |
		        NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_DATABASE) |
		        NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_BINARY);
	else
		mask |= NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_WIREGUARD) |
		        NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_BINARY);
	return mask;
}

static unsigned int natflow_dpi_candidate_machine_class_mask(
    unsigned char l4proto, __be16 server_port)
{
	unsigned int mask = natflow_dpi_payload_machine_class_mask(l4proto);

	if (mask != 0 && server_port == __constant_htons(53))
		mask |= NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_DNS);
	return mask;
}

static unsigned int natflow_dpi_machine_class_byte_budget(unsigned int mask)
{
	if (mask & ~NATFLOW_DPI_MACHINE_CLASS_BIT(
	            NATFLOW_DPI_MACHINE_CLASS_DNS))
		return NATFLOW_DPI_PAYLOAD_BYTE_BUDGET;
	return NATFLOW_DPI_DNS_BYTE_BUDGET;
}

static bool natflow_dpi_machine_class_direction_exhausted(
    const natflow_t *nf, unsigned int machine_class_mask,
    unsigned int direction)
{
	return nf->dpi_packet_count[direction] >=
	       NATFLOW_DPI_DIRECTION_PACKET_BUDGET ||
	       nf->dpi_byte_count[direction] >=
	       natflow_dpi_machine_class_byte_budget(machine_class_mask);
}

static bool natflow_dpi_context_machine_classes_exhausted(
    const natflow_t *nf, unsigned short automaton)
{
	unsigned int machine_class_mask;

	if (natflow_dpi_automaton_claimed(automaton))
		machine_class_mask =
		    natflow_dpi_automaton_machine_class_mask(automaton);
	else
		machine_class_mask = natflow_dpi_context_machine_class_mask(nf);
	if (machine_class_mask == 0)
		return true;

	return natflow_dpi_machine_class_direction_exhausted(
	           nf, machine_class_mask, NF_FF_DIR_ORIGINAL) &&
	       natflow_dpi_machine_class_direction_exhausted(
	           nf, machine_class_mask, NF_FF_DIR_REPLY);
}

static unsigned int natflow_dpi_context_direction_machine_class_mask(
    const natflow_t *nf, unsigned int machine_class_mask,
    unsigned char direction)
{
	int dir = natflow_dpi_direction_index(direction);

	if (dir < 0)
		return 0;
	if ((READ_ONCE(nf->status) & NF_FF_DPI_USE) &&
	        natflow_dpi_machine_class_direction_exhausted(
	            nf, machine_class_mask, dir))
		return 0;
	return machine_class_mask;
}

static enum natflow_dpi_context_result natflow_dpi_context_observe(
    natflow_t *nf, unsigned char direction, unsigned int machine_class_mask,
    unsigned int observed_machine_class_mask, unsigned int payload_len,
    unsigned int payload_linear_len)
{
	unsigned short automaton;
	unsigned int inspect_len;
	unsigned int byte_count;
	unsigned int context_machine_class_mask;
	int dir;

	if (!nf || machine_class_mask == 0)
		return NATFLOW_DPI_CONTEXT_EMPTY;
	if (READ_ONCE(nf->app_id) != 0 ||
	        (READ_ONCE(nf->status) & NF_FF_L7_DPI_PACKET_DONE))
		return NATFLOW_DPI_CONTEXT_EMPTY;
	dir = natflow_dpi_direction_index(direction);
	if (dir < 0)
		return NATFLOW_DPI_CONTEXT_EMPTY;

	automaton = READ_ONCE(nf->dpi_automaton);
	if (READ_ONCE(nf->status) & NF_FF_DPI_USE) {
		if (natflow_dpi_automaton_claimed(automaton)) {
			context_machine_class_mask =
			    natflow_dpi_automaton_machine_class_mask(automaton);
		} else {
			context_machine_class_mask =
			    natflow_dpi_context_intersect_machine_class_mask(
			        nf, machine_class_mask);
			if (context_machine_class_mask == 0) {
				automaton = READ_ONCE(nf->dpi_automaton);
				context_machine_class_mask =
				    natflow_dpi_automaton_machine_class_mask(automaton);
			}
		}
	} else {
		nf->dpi_byte_count[NF_FF_DIR_ORIGINAL] = 0;
		nf->dpi_byte_count[NF_FF_DIR_REPLY] = 0;
		nf->dpi_packet_count[NF_FF_DIR_ORIGINAL] = 0;
		nf->dpi_packet_count[NF_FF_DIR_REPLY] = 0;
		if (natflow_dpi_automaton_claimed(automaton)) {
			context_machine_class_mask =
			    natflow_dpi_automaton_machine_class_mask(automaton);
		} else {
			context_machine_class_mask = machine_class_mask;
			if (!natflow_dpi_context_set_machine_class_mask(
			            nf, context_machine_class_mask)) {
				automaton = READ_ONCE(nf->dpi_automaton);
				context_machine_class_mask =
				    natflow_dpi_automaton_machine_class_mask(automaton);
			}
		}
	}
	if (context_machine_class_mask == 0)
		return NATFLOW_DPI_CONTEXT_EMPTY;

	if (payload_len > 0 && observed_machine_class_mask != 0) {
		if (nf->dpi_packet_count[dir] != 0xff)
			nf->dpi_packet_count[dir]++;

		inspect_len = payload_linear_len;
		if (inspect_len > payload_len)
			inspect_len = payload_len;
		if (context_machine_class_mask &
		        ~NATFLOW_DPI_MACHINE_CLASS_BIT(
		            NATFLOW_DPI_MACHINE_CLASS_DNS)) {
			if (inspect_len > NATFLOW_DPI_PAYLOAD_INSPECT_MAX)
				inspect_len = NATFLOW_DPI_PAYLOAD_INSPECT_MAX;
		} else if (inspect_len > NATFLOW_DPI_DNS_INSPECT_MAX) {
			inspect_len = NATFLOW_DPI_DNS_INSPECT_MAX;
		}

		byte_count = nf->dpi_byte_count[dir];
		if (inspect_len > 0xffffu - byte_count)
			byte_count = 0xffffu;
		else
			byte_count += inspect_len;
		nf->dpi_byte_count[dir] = byte_count;
	}

	automaton = READ_ONCE(nf->dpi_automaton);
	if (natflow_dpi_context_machine_classes_exhausted(nf, automaton))
		return NATFLOW_DPI_CONTEXT_EXHAUSTED;

	if (!(READ_ONCE(nf->status) & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);
	if (!(READ_ONCE(nf->status) & NF_FF_DPI_USE)) {
		simple_set_bit(NF_FF_DPI_USE_BIT, &nf->status);
		atomic64_inc(&natflow_dpi_context_armed);
	}
	return NATFLOW_DPI_CONTEXT_WAIT;
}

static bool natflow_dpi_packet_is_terminal(
    const struct natflow_l7_packet_view *view)
{
	if (!view || view->l4proto != IPPROTO_TCP || !view->l4)
		return false;
	return TCPH(view->l4)->fin || TCPH(view->l4)->rst;
}

static bool natflow_dpi_conntrack_packet_limit_exceeded(const struct nf_conn *ct)
{
	struct nf_conn_acct *acct;
	struct nf_conn_counter *counter;
	u64 original_packets;
	u64 reply_packets;

	if (!ct)
		return false;
	acct = nf_conn_acct_find(ct);
	if (!acct)
		return false;

	counter = acct->counter;
	original_packets = atomic64_read(
	                       &counter[IP_CT_DIR_ORIGINAL].packets);
	reply_packets = atomic64_read(&counter[IP_CT_DIR_REPLY].packets);
	if (original_packets > NATFLOW_DPI_CONNTRACK_PACKET_LIMIT ||
	        reply_packets > NATFLOW_DPI_CONNTRACK_PACKET_LIMIT)
		return true;
	return original_packets + reply_packets >
	       NATFLOW_DPI_CONNTRACK_PACKET_LIMIT;
}

static struct natflow_dpi_native_machine_result
natflow_dpi_native_machine_step(natflow_t *nf,
                                unsigned int machine_class_mask,
                                const unsigned char *data,
                                unsigned int payload_len,
                                unsigned int inspect_len,
                                unsigned char l4proto,
                                unsigned char direction,
                                __be16 sport, __be16 dport)
{
	struct natflow_dpi_native_machine_result result;
	unsigned short automaton;
	unsigned int proto = 0;
	unsigned int proto_mask;
	unsigned int evidence;

	if (!nf || !data || inspect_len == 0 ||
	        !natflow_dpi_l4_supported(l4proto) ||
	        !natflow_dpi_packet_direction_valid(direction))
		return natflow_dpi_native_machine_pending();

	automaton = READ_ONCE(nf->dpi_automaton);
	if (natflow_dpi_automaton_claimed(automaton)) {
		switch (natflow_dpi_automaton_machine(automaton)) {
		case NATFLOW_DPI_AUTOMATON_MACHINE_RDP:
			evidence = natflow_dpi_rdp_evidence(data, payload_len,
			                                    inspect_len, direction);
			return natflow_dpi_rdp_machine_step(nf, evidence);
		case NATFLOW_DPI_AUTOMATON_MACHINE_SOCKS:
			return natflow_dpi_socks_machine_step(nf, data, payload_len,
			                                      inspect_len, direction);
		case NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP:
			return natflow_dpi_native_machine_pending();
		default:
			return natflow_dpi_native_machine_excluded();
		}
	}

	/* Recognition precedence is part of the fixed native-machine contract. */
	if (l4proto == IPPROTO_TCP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_BINARY))) {
		evidence = natflow_dpi_rdp_evidence(data, payload_len, inspect_len,
		                                    direction);
		result = natflow_dpi_rdp_machine_step(nf, evidence);
		if (result.status != NATFLOW_DPI_NATIVE_MACHINE_PENDING ||
		        natflow_dpi_automaton_claimed(READ_ONCE(nf->dpi_automaton)))
			return result;
	}
	if (l4proto == IPPROTO_TCP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_BINARY))) {
		result = natflow_dpi_socks_machine_step(nf, data, payload_len,
		                                        inspect_len, direction);
		if (result.status != NATFLOW_DPI_NATIVE_MACHINE_PENDING ||
		        natflow_dpi_automaton_claimed(READ_ONCE(nf->dpi_automaton)))
			return result;
	}

	if (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	            NATFLOW_DPI_MACHINE_CLASS_TEXT)) {
		proto = natflow_dpi_parse_network_protocol(data, payload_len,
		        inspect_len, l4proto, direction, sport, dport);
	}
	if (!proto && (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	                   NATFLOW_DPI_MACHINE_CLASS_STUN_TURN))) {
		proto = natflow_dpi_parse_stun_turn(data, payload_len, inspect_len);
	}
	if (!proto && (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	                   NATFLOW_DPI_MACHINE_CLASS_BINARY)) &&
	        natflow_dpi_parse_nfs(data, payload_len, inspect_len, l4proto)) {
		proto = NATFLOW_DPI_PROTO_NFS;
	}
	if (!proto && l4proto == IPPROTO_TCP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_SSH))) {
		proto = natflow_dpi_parse_ssh_tcp(data, inspect_len);
	}
	if (!proto && l4proto == IPPROTO_UDP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_WIREGUARD))) {
		proto = natflow_dpi_parse_wireguard_udp(data, payload_len,
		                                        inspect_len);
	}
	if (!proto && (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	                   NATFLOW_DPI_MACHINE_CLASS_BITTORRENT))) {
		if (l4proto == IPPROTO_TCP)
			proto = natflow_dpi_parse_bittorrent_tcp(data, inspect_len);
		else
			proto = natflow_dpi_parse_bittorrent_udp(data, inspect_len);
	}
	if (!proto && (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	                   NATFLOW_DPI_MACHINE_CLASS_TEXT))) {
		if (l4proto == IPPROTO_UDP) {
			proto_mask = NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SIP);
		} else if (direction == NATFLOW_L7_DIR_ORIGINAL) {
			proto_mask = NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_FTP) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SMTP) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_POP3) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_IMAP) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SIP) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_RTSP);
		} else {
			proto_mask = NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SIP) |
			             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_RTSP);
		}
		proto = natflow_dpi_parse_text_protocol(data, inspect_len,
		                                        proto_mask);
	}
	if (!proto && l4proto == IPPROTO_TCP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_DATABASE))) {
		proto_mask = direction == NATFLOW_L7_DIR_ORIGINAL ?
		             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_RESP) |
		             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_POSTGRESQL) :
		             NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_MYSQL);
		proto = natflow_dpi_parse_database_protocol(data, payload_len,
		        inspect_len, direction, proto_mask);
	}
	if (!proto && l4proto == IPPROTO_TCP &&
	        (machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_BINARY))) {
		proto_mask = NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_SMB);
		if (direction == NATFLOW_L7_DIR_ORIGINAL)
			proto_mask |= NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_MQTT);
		proto = natflow_dpi_parse_binary_protocol(data, payload_len,
		        inspect_len, direction, proto_mask);
	}
	return proto ? natflow_dpi_native_machine_terminal(proto) :
	       natflow_dpi_native_machine_pending();
}

static noinline bool natflow_dpi_classify_dns_query(struct nf_conn *ct,
        const unsigned char *payload, unsigned int payload_len,
        unsigned char l4proto, bool classify_domain)
{
	struct natflow_l7_feature feature;

	if (payload_len == 0)
		return false;
	if (natflow_l7_dns_parse(payload, payload_len, l4proto, &feature) <= 0)
		return false;

	if (classify_domain)
		natflow_dpi_classify_host_normalized(ct, feature.host,
		                                     feature.host_len, NATFLOW_DPI_EVENT_SOURCE_DNS);
	return true;
}

static bool natflow_dpi_dns_candidate(unsigned char l4proto,
                                      unsigned char direction, __be16 server_port)
{
	return natflow_dpi_l4_supported(l4proto) &&
	       natflow_dpi_packet_direction_valid(direction) &&
	       server_port == __constant_htons(53);
}

unsigned int natflow_dpi_packet_view_pull_len(unsigned int consumer_mask,
        unsigned char l4proto, unsigned char direction, __be16 server_port,
        unsigned int payload_len)
{
	unsigned int inspect_max = NATFLOW_DPI_PAYLOAD_INSPECT_MAX;

	if (payload_len == 0)
		return 0;
	if (!natflow_dpi_l4_supported(l4proto) ||
	        !natflow_dpi_packet_direction_valid(direction))
		return 0;

	if (natflow_dpi_dns_candidate(l4proto, direction, server_port) &&
	        (((consumer_mask & NATFLOW_L7_CONSUMER_DPI_DOMAIN) &&
	          direction == NATFLOW_L7_DIR_ORIGINAL) ||
	         (consumer_mask & NATFLOW_L7_CONSUMER_DPI_PACKET)))
		return payload_len > NATFLOW_DPI_DNS_INSPECT_MAX ?
		       NATFLOW_DPI_DNS_INSPECT_MAX : payload_len;

	if (!(consumer_mask & NATFLOW_L7_CONSUMER_DPI_PACKET) ||
	        natflow_dpi_payload_machine_class_mask(l4proto) == 0)
		return 0;

	if (l4proto == IPPROTO_TCP)
		inspect_max = NATFLOW_DPI_HTTP_APP_INSPECT_MAX;
	else if (payload_len >= NATFLOW_DPI_IQIYI_PAYLOAD_MIN &&
	         payload_len <= NATFLOW_DPI_IQIYI_PAYLOAD_MAX)
		inspect_max = NATFLOW_DPI_IQIYI_PAYLOAD_MAX;
	return payload_len > inspect_max ? inspect_max : payload_len;
}

unsigned int natflow_dpi_consume_packet_view(
    const struct natflow_l7_packet_view *view, unsigned int consumer_mask)
{
	const unsigned char *payload;
	const struct natflow_dpi_app_meta *matched_app = NULL;
	struct natflow_dpi_native_machine_result machine_result =
	    natflow_dpi_native_machine_pending();
	struct natflow_dpi_payload_app_result payload_app_result =
	    natflow_dpi_payload_app_pending();
	natflow_t *nf;
	unsigned short automaton;
	unsigned int payload_linear_len;
	unsigned int machine_class_mask;
	unsigned int inspect_machine_class_mask;
	unsigned int app_inspect_len;
	unsigned int dns_inspect_len;
	unsigned int inspect_len;
	unsigned int done_mask = 0;
	unsigned int proto = 0;
	unsigned int matched_source = 0;
	enum natflow_dpi_context_result context_result;
	bool inspected = false;
	bool dns_match = false;
	bool app_committed = false;
	bool app_exists = false;
	bool context_cleared = false;
	int dir;
	__be16 server_port;

	if (!view || !view->ct || !view->l4)
		return 0;
	if (!natflow_dpi_consumer_enabled())
		return 0;

	consumer_mask &= view->consumer_mask & NATFLOW_L7_CONSUMER_DPI;
	if (view->direction != NATFLOW_L7_DIR_ORIGINAL)
		consumer_mask &= ~NATFLOW_L7_CONSUMER_DPI_DOMAIN;
	if (!consumer_mask)
		return 0;
	if (!natflow_dpi_packet_direction_valid(view->direction))
		return 0;
	dir = natflow_dpi_direction_index(view->direction);
	if (dir < 0)
		return 0;

	if (!natflow_dpi_l4_supported(view->l4proto))
		return 0;
	server_port = natflow_l7_packet_server_port(view);
	nf = natflow_session_get(view->ct);

	payload = view->payload;
	payload_linear_len = view->payload_linear_len;
	if (payload_linear_len > view->payload_len)
		payload_linear_len = view->payload_len;

	if (natflow_dpi_dns_candidate(view->l4proto, view->direction,
	                              server_port) &&
	        (consumer_mask & NATFLOW_L7_CONSUMER_DPI)) {
		dns_inspect_len = view->payload_len > NATFLOW_DPI_DNS_INSPECT_MAX ?
		                  NATFLOW_DPI_DNS_INSPECT_MAX : view->payload_len;
		if (dns_inspect_len > payload_linear_len)
			dns_inspect_len = payload_linear_len;
		if (dns_inspect_len > 0 && payload) {
			if (consumer_mask & NATFLOW_L7_CONSUMER_DPI_PACKET)
				inspected = true;
			if (view->direction == NATFLOW_L7_DIR_ORIGINAL &&
			        natflow_dpi_classify_dns_query(view->ct, payload,
			                                       dns_inspect_len, view->l4proto,
			                                       (consumer_mask & NATFLOW_L7_CONSUMER_DPI_DOMAIN) != 0))
				dns_match = true;
			else if (view->direction == NATFLOW_L7_DIR_REPLY &&
			         natflow_l7_dns_response_parse(payload, dns_inspect_len,
			                                       view->l4proto) > 0)
				dns_match = true;
		}
		if (consumer_mask & NATFLOW_L7_CONSUMER_DPI_DOMAIN)
			done_mask |= NATFLOW_L7_CONSUMER_DPI_DOMAIN;
	}

	if (!(consumer_mask & NATFLOW_L7_CONSUMER_DPI_PACKET))
		return done_mask;
	if (!nf) {
		atomic64_inc(&natflow_dpi_proto_no_session);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		return done_mask;
	}

	spin_lock_bh(&view->ct->lock);
	if (READ_ONCE(nf->app_id) != 0) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_app);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}
	if (natflow_dpi_packet_is_terminal(view)) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_transport);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}

	if (natflow_dpi_conntrack_packet_limit_exceeded(view->ct)) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_acct_limit);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}

	machine_class_mask = natflow_dpi_candidate_machine_class_mask(
	                         view->l4proto, server_port);
	if (machine_class_mask == 0) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_no_candidate);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}
	automaton = READ_ONCE(nf->dpi_automaton);
	if (natflow_dpi_automaton_claimed(automaton)) {
		inspect_machine_class_mask =
		    natflow_dpi_context_direction_machine_class_mask(
		        nf, natflow_dpi_automaton_machine_class_mask(automaton),
		        view->direction);
	} else {
		inspect_machine_class_mask =
		    natflow_dpi_context_direction_machine_class_mask(
		        nf, machine_class_mask, view->direction);
	}

	if (dns_match && (inspect_machine_class_mask &
	                  NATFLOW_DPI_MACHINE_CLASS_BIT(NATFLOW_DPI_MACHINE_CLASS_DNS)))
		machine_result = natflow_dpi_native_machine_terminal(
		                     NATFLOW_DPI_PROTO_DNS);

	if (machine_result.status == NATFLOW_DPI_NATIVE_MACHINE_PENDING &&
	        (!natflow_dpi_automaton_claimed(automaton) ||
	         natflow_dpi_automaton_machine(automaton) ==
	         NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP) &&
	        (inspect_machine_class_mask & NATFLOW_DPI_MACHINE_CLASS_BIT(
	             NATFLOW_DPI_MACHINE_CLASS_TEXT))) {
		app_inspect_len = view->payload_len > NATFLOW_DPI_HTTP_APP_INSPECT_MAX ?
		                  NATFLOW_DPI_HTTP_APP_INSPECT_MAX : view->payload_len;
		if (app_inspect_len > payload_linear_len)
			app_inspect_len = payload_linear_len;
		if (app_inspect_len > 0 && payload) {
			inspected = true;
			payload_app_result = natflow_dpi_payload_app_machine_step(
			                         nf, payload, view->payload_len, app_inspect_len,
			                         view->l4proto, view->direction, view->sport,
			                         view->dport);
		}
	}
	if (payload_app_result.excluded) {
		if (inspected)
			atomic64_inc(&natflow_dpi_packet_inspections[dir]);
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_no_candidate);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}
	if (payload_app_result.app) {
		if (inspected)
			atomic64_inc(&natflow_dpi_packet_inspections[dir]);
		atomic64_inc(&natflow_dpi_packet_matches[dir]);
		matched_app = payload_app_result.app;
		matched_source = payload_app_result.source;
		app_committed = natflow_dpi_commit_app_locked(nf, matched_app,
		                &app_exists, &context_cleared);
		if (context_cleared)
			atomic64_inc(&natflow_dpi_context_cleared_match);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}

	if (machine_result.status == NATFLOW_DPI_NATIVE_MACHINE_PENDING &&
	        (inspect_machine_class_mask &
	         ~NATFLOW_DPI_MACHINE_CLASS_BIT(NATFLOW_DPI_MACHINE_CLASS_DNS))) {
		inspect_len = view->payload_len > NATFLOW_DPI_PAYLOAD_INSPECT_MAX ?
		              NATFLOW_DPI_PAYLOAD_INSPECT_MAX : view->payload_len;
		if (inspect_len > payload_linear_len)
			inspect_len = payload_linear_len;
		if (inspect_len > 0 && payload) {
			inspected = true;
			machine_result = natflow_dpi_native_machine_step(
			                     nf, inspect_machine_class_mask, payload,
			                     view->payload_len, inspect_len,
			                     view->l4proto, view->direction,
			                     view->sport, view->dport);
		}
	}
	if (inspected)
		atomic64_inc(&natflow_dpi_packet_inspections[dir]);

	if (machine_result.status == NATFLOW_DPI_NATIVE_MACHINE_TERMINAL) {
		proto = machine_result.proto;
		atomic64_inc(&natflow_dpi_packet_matches[dir]);
		matched_app = natflow_dpi_app_by_proto(proto);
		matched_source = natflow_dpi_proto_event_source(proto);
		app_committed = natflow_dpi_commit_app_locked(nf, matched_app,
		                &app_exists, &context_cleared);
		if (context_cleared)
			atomic64_inc(&natflow_dpi_context_cleared_match);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}
	if (machine_result.status == NATFLOW_DPI_NATIVE_MACHINE_EXCLUDED) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_no_candidate);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}
	if (READ_ONCE(nf->app_id) != 0) {
		if (natflow_dpi_context_clear_locked(nf))
			atomic64_inc(&natflow_dpi_context_cleared_app);
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
		goto out_unlock;
	}

	context_result = natflow_dpi_context_observe(nf, view->direction,
	                 machine_class_mask, inspect_machine_class_mask,
	                 view->payload_len, payload_linear_len);
	if (context_result != NATFLOW_DPI_CONTEXT_WAIT) {
		if (natflow_dpi_context_clear_locked(nf)) {
			if (context_result == NATFLOW_DPI_CONTEXT_EXHAUSTED)
				atomic64_inc(&natflow_dpi_context_cleared_budget);
			else
				atomic64_inc(&natflow_dpi_context_cleared_no_candidate);
		}
		done_mask |= NATFLOW_L7_CONSUMER_DPI_PACKET;
	}

out_unlock:
	if (done_mask & NATFLOW_L7_CONSUMER_DPI_PACKET)
		simple_set_bit(NF_FF_L7_DPI_PACKET_DONE_BIT, &nf->status);
	spin_unlock_bh(&view->ct->lock);
	if (app_exists)
		atomic64_inc(&natflow_dpi_proto_app_exists);
	if (app_committed)
		natflow_dpi_event_queue(view->ct, NATFLOW_DPI_REASON_MATCHED,
		                        NATFLOW_DPI_CATALOG_REVISION,
		                        matched_app->app_id, matched_app->category_id,
		                        0, matched_source, view->direction);
	return done_mask;
}

static int natflow_dpi_ctl_device_init(void)
{
	int ret;
	dev_t devno;

	if (natflow_dpi_ctl_major > 0) {
		devno = MKDEV(natflow_dpi_ctl_major, natflow_dpi_ctl_minor);
		ret = register_chrdev_region(devno, 1, natflow_dpi_ctl_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, natflow_dpi_ctl_minor, 1, natflow_dpi_ctl_dev_name);
	}
	if (ret < 0)
		return ret;

	natflow_dpi_ctl_major = MAJOR(devno);
	natflow_dpi_ctl_minor = MINOR(devno);
	NATFLOW_println("natflow_dpi_ctl_major=%d, natflow_dpi_ctl_minor=%d",
	                natflow_dpi_ctl_major, natflow_dpi_ctl_minor);

	cdev_init(&natflow_dpi_ctl_cdev, &natflow_dpi_ctl_fops);
	natflow_dpi_ctl_cdev.owner = THIS_MODULE;
	ret = cdev_add(&natflow_dpi_ctl_cdev, devno, 1);
	if (ret)
		goto cdev_add_failed;

	natflow_dpi_ctl_class = natflow_class_create("natflow_dpi_ctl_class");
	if (IS_ERR(natflow_dpi_ctl_class)) {
		ret = PTR_ERR(natflow_dpi_ctl_class);
		NATFLOW_println("failed to create DPI ctl class, error=%d", ret);
		goto class_create_failed;
	}

	natflow_dpi_ctl_dev = device_create(natflow_dpi_ctl_class, NULL, devno,
	                                    NULL, natflow_dpi_ctl_dev_name);
	if (IS_ERR(natflow_dpi_ctl_dev)) {
		ret = PTR_ERR(natflow_dpi_ctl_dev);
		NATFLOW_println("failed to create DPI ctl device, error=%d", ret);
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	class_destroy(natflow_dpi_ctl_class);
class_create_failed:
	cdev_del(&natflow_dpi_ctl_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void natflow_dpi_ctl_device_exit(void)
{
	dev_t devno = MKDEV(natflow_dpi_ctl_major, natflow_dpi_ctl_minor);

	device_destroy(natflow_dpi_ctl_class, devno);
	class_destroy(natflow_dpi_ctl_class);
	cdev_del(&natflow_dpi_ctl_cdev);
	unregister_chrdev_region(devno, 1);
}

static int natflow_dpi_queue_device_init(void)
{
	int ret;
	dev_t devno;

	if (natflow_dpi_queue_major > 0) {
		devno = MKDEV(natflow_dpi_queue_major, natflow_dpi_queue_minor);
		ret = register_chrdev_region(devno, 1, natflow_dpi_queue_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, natflow_dpi_queue_minor, 1, natflow_dpi_queue_dev_name);
	}
	if (ret < 0)
		return ret;

	natflow_dpi_queue_major = MAJOR(devno);
	natflow_dpi_queue_minor = MINOR(devno);
	NATFLOW_println("natflow_dpi_queue_major=%d, natflow_dpi_queue_minor=%d",
	                natflow_dpi_queue_major, natflow_dpi_queue_minor);

	cdev_init(&natflow_dpi_queue_cdev, &natflow_dpi_queue_fops);
	natflow_dpi_queue_cdev.owner = THIS_MODULE;
	ret = cdev_add(&natflow_dpi_queue_cdev, devno, 1);
	if (ret)
		goto cdev_add_failed;

	natflow_dpi_queue_class = natflow_class_create("natflow_dpi_queue_class");
	if (IS_ERR(natflow_dpi_queue_class)) {
		ret = PTR_ERR(natflow_dpi_queue_class);
		NATFLOW_println("failed to create DPI queue class, error=%d", ret);
		goto class_create_failed;
	}

	natflow_dpi_queue_dev = device_create(natflow_dpi_queue_class, NULL, devno,
	                                      NULL, natflow_dpi_queue_dev_name);
	if (IS_ERR(natflow_dpi_queue_dev)) {
		ret = PTR_ERR(natflow_dpi_queue_dev);
		NATFLOW_println("failed to create DPI queue device, error=%d", ret);
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	class_destroy(natflow_dpi_queue_class);
class_create_failed:
	cdev_del(&natflow_dpi_queue_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void natflow_dpi_queue_device_exit(void)
{
	dev_t devno = MKDEV(natflow_dpi_queue_major, natflow_dpi_queue_minor);

	device_destroy(natflow_dpi_queue_class, devno);
	class_destroy(natflow_dpi_queue_class);
	cdev_del(&natflow_dpi_queue_cdev);
	unregister_chrdev_region(devno, 1);
}

int natflow_dpi_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct natflow_dpi_event_hdr) !=
	             NATFLOW_DPI_EVENT_HEADER_LEN);
	BUILD_BUG_ON(ARRAY_SIZE(natflow_dpi_source_names) !=
	             NATFLOW_DPI_EVENT_SOURCE_MAX + 1);
	BUILD_BUG_ON(NATFLOW_DPI_MACHINE_CLASS_MAX > 8);
	BUILD_BUG_ON(NATFLOW_DPI_PROTO_COAP > 32);
	BUILD_BUG_ON(NATFLOW_DPI_AUTOMATON_MACHINE_WHATSAPP > 0x7f);
	BUILD_BUG_ON(NATFLOW_DPI_RDP_COMPLETE >
	             NATFLOW_DPI_AUTOMATON_STATE_MASK);
	BUILD_BUG_ON(NATFLOW_DPI_PROTO_ALL_MASK !=
	             (NATFLOW_DPI_PROTO_BIT(NATFLOW_DPI_PROTO_COAP + 1) - 1));
	BUILD_BUG_ON(ARRAY_SIZE(natflow_dpi_app_catalog) != 45);

	ret = natflow_dpi_app_catalog_validate();
	if (ret != 0)
		return ret;
	ret = natflow_dpi_static_domain_catalog_validate();
	if (ret != 0)
		return ret;

	init_waitqueue_head(&natflow_dpi_wait);
	natflow_dpi_counters_clear();
	WRITE_ONCE(natflow_dpi_queue_readers, 0);
	WRITE_ONCE(natflow_dpi_queue_cache_limit, 0);
	WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);

	ret = natflow_dpi_ctl_device_init();
	if (ret != 0)
		return ret;

	ret = natflow_dpi_queue_device_init();
	if (ret != 0)
		goto queue_device_init_failed;

	return 0;

queue_device_init_failed:
	natflow_dpi_ctl_device_exit();
	return ret;
}

void natflow_dpi_exit(void)
{
	mutex_lock(&natflow_dpi_lock);
	WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);
	WRITE_ONCE(natflow_dpi_queue_readers, 0);
	WRITE_ONCE(natflow_dpi_queue_cache_limit, 0);
	mutex_unlock(&natflow_dpi_lock);

	wake_up_interruptible(&natflow_dpi_wait);
	natflow_dpi_queue_device_exit();
	natflow_dpi_ctl_device_exit();
	natflow_dpi_event_purge();
}
