/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Tue, 22 Jun 2021 22:50:41 +0800
 */
#ifndef _NATFLOW_URLLOGGER_H_
#define _NATFLOW_URLLOGGER_H_

struct net_device;
struct natflow_l7_host_view;
struct natflow_l7_packet_view;
struct nf_hook_state;

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
