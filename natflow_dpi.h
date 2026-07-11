/*
 * Natflow DPI control and event skeleton.
 */
#ifndef _NATFLOW_DPI_H_
#define _NATFLOW_DPI_H_

#include <linux/types.h>

#define NATFLOW_DPI_CTL_MAX_LINE 512
#define NATFLOW_DPI_EVENT_VERSION 1

enum natflow_dpi_event_reason {
	NATFLOW_DPI_REASON_NONE = 0,
	NATFLOW_DPI_REASON_DISABLED = 1,
	NATFLOW_DPI_REASON_NO_DETECTOR = 2,
	NATFLOW_DPI_REASON_CACHE_FULL = 3,
	NATFLOW_DPI_REASON_NOT_ELIGIBLE = 4,
	NATFLOW_DPI_REASON_MODULE_EXIT = 5,
};

struct natflow_dpi_event_hdr {
	__u16 version;
	__u16 header_len;
	__u16 record_len;
	__u16 reason;
	__u32 generation;
	__u32 app_id;
	__u32 category_id;
	__u32 rule_id;
	__u32 flags;
	__u64 timestamp;
} __packed;

extern int natflow_dpi_init(void);
extern void natflow_dpi_exit(void);

#endif /* _NATFLOW_DPI_H_ */
