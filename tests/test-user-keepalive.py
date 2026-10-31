#!/usr/bin/env python3
"""Exercise production user keepalive with a fake clock and conntrack lifetime."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
source = (repo / "natflow_user.c").read_text()
keepalive_refresh = next(line for line in source.splitlines()
                         if line.startswith("#define NATFLOW_USER_KEEPALIVE_REFRESH "))


def function(signature):
    start = source.index(signature)
    body = source.index("{", start)
    depth = 1
    end = body + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


prelude = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
typedef uint32_t u32;
#define HZ 100
#define ETH_ALEN 6
#define AUTH_TYPE_UNKNOWN 0
#define NATFLOW_USER_TIMEOUT 300
#define NATFLOW_USER_TIMESTAMP_REFRESH (32 * HZ)
#define NATFLOW_USER_TIMESTAMP_NEW_REFRESH (2 * HZ)
#define READ_ONCE(v) __atomic_load_n(&(v), __ATOMIC_RELAXED)
#define WRITE_ONCE(v, n) __atomic_store_n(&(v), (n), __ATOMIC_RELAXED)
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define cmpxchg(ptr, old, new) ({ \
    __typeof__(*(ptr)) previous = (old); \
    __atomic_compare_exchange_n((ptr), &previous, (new), false, \
                                __ATOMIC_RELAXED, __ATOMIC_RELAXED); \
    previous; \
})
enum ip_conntrack_info { IP_CT_NEW, IP_CT_ESTABLISHED };
#define CTINFO2DIR(info) 0
union nf_inet_addr { uint32_t ip; };
struct fakeuser_data_t {
    u32 timestamp;
    unsigned int auth_type;
    char ifname[16];
};
struct nf_conn {
    struct fakeuser_data_t data;
    u32 expires;
    bool dying;
    unsigned int touches;
    struct {
        struct { struct { union nf_inet_addr u3; unsigned int l3num; } src; } tuple;
    } tuplehash[2];
};
typedef struct nf_conn natflow_fakeuser_t;
struct sk_buff { int unused; };
static unsigned long jiffies;
static unsigned int natflow_user_timeout = 1800, source_updates, events;
#define natflow_fakeuser_data(user) (&(user)->data)
#define nf_ct_is_dying(user) READ_ONCE((user)->dying)
static bool expired(const struct nf_conn *user)
{
    return (int32_t)(READ_ONCE(user->expires) - (u32)jiffies) <= 0;
}
#define nf_ct_is_expired(user) expired(user)
static void natflow_ct_timeout_set(struct nf_conn *user, unsigned long expires)
{
    WRITE_ONCE(user->expires, (u32)expires);
    __atomic_add_fetch(&user->touches, 1, __ATOMIC_RELAXED);
}
static unsigned int timestamp_offset(unsigned int a, unsigned int b)
{
    return b > a ? b - a : a - b;
}
static int natflow_user_ifname_update_from_session(struct fakeuser_data_t *fud,
                                                  struct nf_conn *ct, int dir)
{
    (void)fud; (void)ct; (void)dir;
    return 0;
}
static const uint8_t *natflow_get_mac_or_fake(struct sk_buff *skb,
        const union nf_inet_addr *addr, unsigned int family, uint8_t *mac)
{
    (void)skb; (void)addr; (void)family;
    memset(mac, 1, ETH_ALEN);
    return mac;
}
static void natflow_user_source_update(struct fakeuser_data_t *fud,
        const uint8_t *mac, struct nf_conn *ct, int dir)
{
    (void)fud; (void)mac; (void)ct; (void)dir;
    ++source_updates;
}
static void userinfo_event_queue(struct nf_conn *user)
{
    (void)user;
    ++events;
}
"""

tests = r"""
static struct nf_conn fresh(unsigned int timeout)
{
    struct nf_conn user = {0};
    natflow_user_timeout = timeout;
    user.data.auth_type = 1;
    user.data.timestamp = (u32)jiffies;
    strcpy(user.data.ifname, "lan");
    natflow_user_timeout_touch(&user);
    return user;
}
static pthread_barrier_t start;
static void *concurrent_touch(void *arg)
{
    int ret = pthread_barrier_wait(&start);
    assert(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
    natflow_user_keepalive(arg);
    return NULL;
}
int main(void)
{
    jiffies = 100 * HZ;
    struct nf_conn user = fresh(1800);
    /* Valid offload callbacks keep the user alive, even with zero counters. */
    for (unsigned int seconds = 20; seconds <= 3600; seconds += 20) {
        jiffies += 20 * HZ;
        assert(!expired(&user));
        natflow_user_keepalive(&user);
        assert(natflow_user_idle_time(&user.data) < 64);
    }
    assert(user.touches > 1 && user.touches < 60);
    assert(!events && !source_updates);

    /* No traffic and no keepalive callbacks still allow normal expiry. */
    user = fresh(1800);
    u32 deadline = user.expires, timestamp = user.data.timestamp;
    jiffies += 1800 * HZ;
    assert(expired(&user) && user.expires == deadline);
    assert(user.data.timestamp == timestamp && user.touches == 1);

    /* Repeated keepalive callbacks still throttle timeout writes. */
    user = fresh(1800);
    jiffies += 63 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1);
    jiffies += HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 2);
    natflow_user_keepalive(&user);
    assert(user.touches == 2);
    jiffies += 64 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 3);

    /* Short timeouts work when the helper is called frequently enough. */
    user = fresh(1);
    for (int i = 0; i < 100; ++i) {
        jiffies += HZ / 2;
        assert(!expired(&user));
        natflow_user_keepalive(&user);
        assert(!expired(&user));
    }
    user = fresh(1800);
    user.data.auth_type = AUTH_TYPE_UNKNOWN;
    jiffies += 64 * HZ;
    natflow_user_keepalive(&user);
    assert(user.expires == (u32)(jiffies + NATFLOW_USER_TIMEOUT * HZ));

    /* Unsigned timestamp wrap must keep the refresh window intact. */
    jiffies = UINT32_MAX - 10 * HZ;
    user = fresh(1800);
    jiffies += 63 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1);
    jiffies += HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 2 && !expired(&user));

    /* Pure keepalive leaves the 32-second source-learning window open. */
    user = fresh(1800);
    jiffies += 32 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1);
    struct sk_buff skb = {0};
    natflow_user_source_refresh(&user, &user.data, &skb, &user, IP_CT_ESTABLISHED);
    assert(source_updates == 1 && events == 1);
    assert(user.touches == 2 && user.data.timestamp == (u32)jiffies);

    /* A new connection may still refresh its source after two seconds. */
    user = fresh(1800);
    jiffies += 2 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1);
    natflow_user_source_refresh(&user, &user.data, &skb, &user, IP_CT_NEW);
    assert(source_updates == 2 && events == 2 && user.touches == 2);

    /* Parallel packet accounting coalesces into one timeout write. */
    user = fresh(1800);
    jiffies += 64 * HZ;
    pthread_t threads[16];
    assert(!pthread_barrier_init(&start, NULL, 16));
    for (unsigned int i = 0; i < 16; ++i)
        assert(!pthread_create(&threads[i], NULL, concurrent_touch, &user));
    for (unsigned int i = 0; i < 16; ++i)
        assert(!pthread_join(threads[i], NULL));
    assert(!pthread_barrier_destroy(&start));
    assert(user.touches == 2);

    /* Never use keepalive to resurrect a dying or expired node. */
    user = fresh(1800);
    user.dying = true;
    jiffies += 64 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1);
#if NATFLOW_HAVE_NF_CT_IS_EXPIRED
    user = fresh(1800);
    jiffies += 1800 * HZ;
    natflow_user_keepalive(&user);
    assert(user.touches == 1 && expired(&user));
#endif
    puts("user keepalive: PASS");
    return 0;
}
"""

helpers = "\n".join(function(signature) for signature in (
    "void natflow_user_timeout_touch(",
    "void natflow_user_keepalive(",
    "static inline unsigned int natflow_user_idle_time(",
    "static inline void natflow_user_source_refresh(",
))
with tempfile.TemporaryDirectory(prefix="natflow-user-keepalive-") as directory:
    test_source = Path(directory) / "test.c"
    test_source.write_text(prelude + keepalive_refresh + "\n" + helpers + tests)
    for has_expired in (0, 1):
        binary = Path(directory) / f"test-{has_expired}"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
            f"-DNATFLOW_HAVE_NF_CT_IS_EXPIRED={has_expired}",
            str(test_source), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)
