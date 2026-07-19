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
