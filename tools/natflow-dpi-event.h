#ifndef NATFLOW_DPI_EVENT_H
#define NATFLOW_DPI_EVENT_H

#include <stdint.h>

#define NATFLOW_DPI_EVENT_VERSION 3U
#define NATFLOW_DPI_EVENT_HEADER_LEN 78U

enum natflow_dpi_event_reason {
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
};

struct natflow_dpi_event_hdr {
	uint16_t version;
	uint16_t header_len;
	uint16_t record_len;
	uint16_t family;
	uint64_t timestamp;
	uint8_t l4proto;
	uint8_t tuple_dir;
	uint8_t evidence_dir;
	uint8_t reserved;
	uint16_t reason;
	uint16_t sport;
	uint16_t dport;
	uint8_t sip[16];
	uint8_t dip[16];
	uint32_t generation;
	uint32_t app_id;
	uint32_t category_id;
	uint32_t rule_id;
	uint32_t flags;
} __attribute__((packed));

_Static_assert(sizeof(struct natflow_dpi_event_hdr) ==
               NATFLOW_DPI_EVENT_HEADER_LEN,
               "unexpected DPI event header size");

#endif /* NATFLOW_DPI_EVENT_H */
