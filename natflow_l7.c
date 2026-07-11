/*
 * Shared L7 hook lifecycle.
 *
 * The first implementation step only centralizes hook ownership. Legacy URL
 * parsing and Host ACL handling still live in natflow_urllogger.c.
 */
#include <linux/module.h>
#include "natflow_common.h"
#include "natflow_l7.h"
#if defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_urllogger.h"
#endif

static int natflow_l7_started;

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
