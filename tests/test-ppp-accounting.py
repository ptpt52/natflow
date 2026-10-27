#!/usr/bin/env python3
"""Run the production PPP accounting helpers with mocked devices, no root needed."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
header = (repo / "natflow.h").read_text()
types = header[header.index("typedef struct natflow_route_t {"):
               header.index("struct nf_conn;")]
legacy = types[types.index("typedef struct natflow_t {"):]
legacy = legacy[:legacy.index("\t/* Logical PPP statistics endpoints")]
legacy = legacy.replace("struct natflow_t {", "struct legacy_t {") + "} legacy_t;"
path = (repo / "natflow_path.c").read_text()
helpers = path[path.index("static DEFINE_SPINLOCK(natflow_ppp_lock);"):
               path.index("#else\nstatic inline void natflow_ppp_learn")]

pre = r"""
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint16_t __be16;
#define ETH_ALEN 6
#define ETH_HLEN 14
#define PPPOE_SES_HLEN 8
#define ETH_P_PPP_SES 0x8864
#define ARPHRD_PPP 512
struct ethhdr { unsigned char dst[6], src[6]; __be16 h_proto; };
#define ETH(p) ((const struct ethhdr *)(p))
struct net { int id; };
static struct net init_net, other_net = { 1 };
struct pcpu_sw_netstats {
    uint64_t tx_bytes, tx_packets, rx_bytes, rx_packets;
    int syncp;
};
struct net_device {
    int type, ifindex, running, carrier;
    struct net *net;
    struct pcpu_sw_netstats *tstats;
};
#define dev_net(dev) ((dev)->net)
#define net_eq(a, b) ((a) == (b))
#define netif_running(dev) ((dev)->running)
#define netif_carrier_ok(dev) ((dev)->carrier)
#define DEFINE_SPINLOCK(name) int name
static int lock_depth, rcu_depth, path_generation;
#define NATFLOW_PATH_MAGIC_MASK 0xffff
#define natflow_path_magic path_generation
#define atomic_read_acquire(ptr) (*(ptr))
#define READ_ONCE(value) (value)
#define spin_lock_bh(lock) do { (void)(lock); assert(!lock_depth++); } while (0)
#define spin_unlock_bh(lock) do { (void)(lock); assert(lock_depth-- == 1); } while (0)
#define rcu_read_lock() do { ++rcu_depth; } while (0)
#define rcu_read_unlock() do { assert(rcu_depth-- == 1); } while (0)
#define this_cpu_ptr(ptr) (ptr)
#define u64_stats_update_begin(ptr) do { (void)(ptr); assert(lock_depth); } while (0)
#define u64_stats_update_end(ptr) do { (void)(ptr); assert(lock_depth); } while (0)
#define compat_u64_stats_add(ptr, value) (*(ptr) += (value))
static struct net_device *devices[3];
static struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex)
{
    assert(rcu_depth && lock_depth);
    for (unsigned int i = 0; i < 3; i++)
        if (devices[i] && devices[i]->net == net && devices[i]->ifindex == ifindex)
            return devices[i];
    return NULL;
}
static void natflow_update_magic(int init)
{
    assert(!init && lock_depth);
    ++path_generation;
}
"""

tests = r"""
_Static_assert(sizeof(natflow_t) == sizeof(legacy_t) + 16, "extension growth");
_Static_assert(offsetof(natflow_t, app_id) == offsetof(legacy_t, app_id), "app offset");
_Static_assert(offsetof(natflow_t, dpi_automaton) ==
               offsetof(legacy_t, dpi_automaton), "DPI offset");
static void account(natflow_t *nf, int dir, unsigned long bytes, unsigned long packets)
{
    natflow_ppp_account(nf, dir, bytes, packets, path_generation, 0);
}
static void pppoe(natflow_route_t *route)
{
    route->l2_head_len = ETH_HLEN + PPPOE_SES_HLEN;
    struct ethhdr *eth = (void *)route->l2_head;
    eth->h_proto = htons(ETH_P_PPP_SES);
}
int main(void)
{
    struct pcpu_sw_netstats a = {0}, b = {0}, replacement = {0};
    struct net_device wan = {ARPHRD_PPP, 70000, 1, 1, &init_net, &a};
    struct net_device second = {ARPHRD_PPP, 80000, 1, 1, &init_net, &b};
    struct net_device foreign = {ARPHRD_PPP, 70000, 1, 1, &other_net, &replacement};
    struct net_device reused = {ARPHRD_PPP, 70000, 1, 1, &init_net, &replacement};
    natflow_t nf = {.status = NF_FF_ROUTE};
    devices[0] = &wan;
    devices[1] = &second;

    assert(natflow_ppp_ready(&nf));
    pppoe(&nf.rroute[0]);
    assert(!natflow_ppp_ready(&nf));
    natflow_ppp_learn(&nf, 0, &foreign);
    assert(!natflow_ppp_ready(&nf));
    wan.carrier = 0;
    natflow_ppp_learn(&nf, 0, &wan);
    assert(!natflow_ppp_ready(&nf));
    wan.carrier = 1;
    natflow_ppp_learn(&nf, 0, &wan);
    assert(natflow_ppp_ready(&nf));

    /* Traffic direction is independent of client/server and IP version. */
    account(&nf, 0, 3000, 2);
    account(&nf, 1, 1000, 1);
    assert(a.tx_bytes == 3000 && a.tx_packets == 2);
    assert(a.rx_bytes == 1000 && a.rx_packets == 1);
    pppoe(&nf.rroute[1]);
    assert(!natflow_ppp_ready(&nf));
    natflow_ppp_learn(&nf, 1, &second);
    assert(natflow_ppp_ready(&nf));
    account(&nf, 0, 2000, 2);
    account(&nf, 1, 500, 1);
    assert(a.tx_bytes == 5000 && a.rx_bytes == 1500);
    assert(b.rx_bytes == 2000 && b.rx_packets == 2);
    assert(b.tx_bytes == 500 && b.tx_packets == 1);

    /* Old endpoint identities cannot credit an ifindex reused after teardown. */
    natflow_ppp_invalidate();
    devices[0] = &reused;
    assert(path_generation == 1 && !natflow_ppp_ready(&nf));
    account(&nf, 0, 9000, 9);
    assert(!replacement.tx_bytes && b.rx_bytes == 2000);
    natflow_ppp_learn(&nf, 0, &reused);
    natflow_ppp_learn(&nf, 1, &second);
    nf.magic = path_generation;
    assert(natflow_ppp_ready(&nf));
    /* A pre-event keepalive must not credit a newly learned endpoint. */
    natflow_ppp_account(&nf, 0, 9000, 9, path_generation - 1, 0);
    assert(!replacement.tx_bytes);
    account(&nf, 0, 1234, 3);
    assert(replacement.tx_bytes == 1234 && replacement.tx_packets == 3);
    assert(a.tx_bytes == 5000);

    /* Slow-fast samples credit only sides that still bypass native PPP. */
    uint64_t before_rx = b.rx_bytes;
    natflow_ppp_account(&nf, 0, 600, 1, path_generation, second.ifindex);
    assert(replacement.tx_bytes == 1834 && b.rx_bytes == before_rx);
    natflow_ppp_account(&nf, 1, 400, 1, path_generation, reused.ifindex);
    assert(replacement.rx_bytes == 0 && b.tx_bytes == 900);

    /* Bridged PPPoE and native L3 PPP forwarding must not be double counted. */
    nf.status |= NF_FF_BRIDGE;
    account(&nf, 0, 9000, 9);
    assert(natflow_ppp_ready(&nf) && replacement.tx_bytes == 1834);
    nf.status &= ~NF_FF_BRIDGE;
    nf.rroute[0].l2_head_len = 0;
    account(&nf, 0, 9000, 9);
    assert(replacement.tx_bytes == 1834);
    pppoe(&nf.rroute[0]);

    /* No private-layout access for old PPP; reject absent/down/wrong devices. */
    reused.tstats = NULL;
    account(&nf, 0, 9000, 9);
    assert(replacement.tx_bytes == 1834);
    reused.tstats = &replacement;
    reused.running = 0;
    account(&nf, 0, 9000, 9);
    reused.running = 1;
    reused.type = 1;
    account(&nf, 0, 9000, 9);
    reused.type = ARPHRD_PPP;
    devices[0] = NULL;
    account(&nf, 0, 9000, 9);
    assert(replacement.tx_bytes == 1834);
    assert(!lock_depth && !rcu_depth);
    puts("PPP accounting: directions, two endpoints, readiness, reuse, bridge and legacy PASS");
}
"""

with tempfile.TemporaryDirectory(prefix="natflow-ppp-test-") as tmp:
    source = Path(tmp) / "test.c"
    binary = Path(tmp) / "test"
    source.write_text("\n".join((pre, types, legacy, helpers, tests)))
    subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
        "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-g", "-O1",
        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        str(source), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
