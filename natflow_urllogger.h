/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Tue, 22 Jun 2021 22:50:41 +0800
 */
#ifndef _NATFLOW_URLLOGGER_H_
#define _NATFLOW_URLLOGGER_H_

struct net_device;
struct natflow_l7_packet_view;
struct nf_hook_state;
struct sk_buff;

extern int natflow_urllogger_init(void);
extern void natflow_urllogger_exit(void);
extern int natflow_urllogger_is_enabled(void);
#if NATFLOW_HAVE_IP_SET_STATE_API
extern unsigned int natflow_urllogger_consume_skb(unsigned int hooknum,
        const struct nf_hook_state *state,
        const struct natflow_l7_packet_view *view);
#else
extern unsigned int natflow_urllogger_consume_skb(unsigned int hooknum,
        const struct net_device *in,
        const struct net_device *out,
        const struct natflow_l7_packet_view *view);
#endif

#endif /* _NATFLOW_URLLOGGER_H_ */
