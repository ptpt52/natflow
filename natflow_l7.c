/*
 * Shared L7 hook lifecycle.
 *
 * L7 owns the shared hook entry and parser producers. Legacy URL storage and
 * Host ACL handling still live in natflow_urllogger.c.
 */
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include "natflow_common.h"
#include "natflow_l7.h"
#if defined(CONFIG_NATFLOW_DPI) && defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_dpi.h"
#endif
#if defined(CONFIG_NATFLOW_URLLOGGER)
#include "natflow_urllogger.h"
#endif

static int natflow_l7_started;

static unsigned int natflow_l7_active_consumer_mask(void)
{
	unsigned int mask = 0;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	if (natflow_urllogger_url_enabled())
		mask |= NATFLOW_L7_CONSUMER_URL;
#endif
#if defined(CONFIG_NATFLOW_DPI) && defined(CONFIG_NATFLOW_URLLOGGER)
	if (natflow_dpi_host_consumer_enabled())
		mask |= NATFLOW_L7_CONSUMER_DPI;
#endif

	return mask;
}

unsigned int natflow_l7_consumer_mask(void)
{
	return natflow_l7_active_consumer_mask();
}

int natflow_l7_consumer_active(unsigned int consumer)
{
	return (natflow_l7_active_consumer_mask() & consumer) != 0;
}

struct natflow_l7_tls_cache_node {
	unsigned long active_jiffies;
	union {
		__be32 src_ip;
		struct in6_addr src_ipv6;
	};
	union {
		__be32 dst_ip;
		struct in6_addr dst_ipv6;
	};
	__be16 src_port;
	__be16 dst_port;
	__u32 seq;
	unsigned int data_len;
	unsigned char *data;
};

#define NATFLOW_L7_TLS_CACHE_TIMEOUT 4
#define NATFLOW_L7_TLS_CACHE_NODE_MAX 64
static struct natflow_l7_tls_cache_node (*natflow_l7_tls_cache)[NATFLOW_L7_TLS_CACHE_NODE_MAX];
static unsigned int natflow_l7_tls_cache_cpu_num;

#define NATFLOW_L7_QUIC_V1_VERSION 0x00000001u
#define NATFLOW_L7_QUIC_CACHE_TIMEOUT 4
#define NATFLOW_L7_QUIC_CACHE_NODE_MAX 64
#define NATFLOW_L7_QUIC_INITIAL_SECRET_LEN 32
#define NATFLOW_L7_QUIC_INITIAL_KEY_LEN 16
#define NATFLOW_L7_QUIC_INITIAL_IV_LEN 12
#define NATFLOW_L7_QUIC_INITIAL_TAG_LEN 16
#define NATFLOW_L7_QUIC_HP_SAMPLE_LEN 16
#define NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN 4
#define NATFLOW_L7_QUIC_INITIAL_SCRATCH_PACKET_LEN 2048
#define NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT (32 * 1024)

static const unsigned char natflow_l7_quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

struct natflow_l7_quic_crypto_ctx {
	struct crypto_shash *hmac;
	struct crypto_skcipher *hp;
	struct skcipher_request *hp_req;
	struct crypto_aead *aead;
	struct aead_request *aead_req;
	unsigned char key[NATFLOW_L7_QUIC_INITIAL_KEY_LEN];
	unsigned char iv[NATFLOW_L7_QUIC_INITIAL_IV_LEN];
	unsigned char hp_key[NATFLOW_L7_QUIC_INITIAL_KEY_LEN];
	unsigned char mask[NATFLOW_L7_QUIC_HP_SAMPLE_LEN];
	unsigned char nonce[NATFLOW_L7_QUIC_INITIAL_IV_LEN];
	unsigned char hkdf_input[128];
	unsigned char hkdf_digest[NATFLOW_L7_QUIC_INITIAL_SECRET_LEN];
	unsigned char hkdf_info[80];
	unsigned char initial_secret[NATFLOW_L7_QUIC_INITIAL_SECRET_LEN];
	unsigned char client_secret[NATFLOW_L7_QUIC_INITIAL_SECRET_LEN];
	unsigned char scratch_packet[NATFLOW_L7_QUIC_INITIAL_SCRATCH_PACKET_LEN];
	char desc_buf[sizeof(struct shash_desc) + HASH_MAX_DESCSIZE] __aligned(__alignof__(struct shash_desc));
};

struct natflow_l7_quic_cache_node {
	unsigned long active_jiffies;
	union {
		__be32 src_ip;
		struct in6_addr src_ipv6;
	};
	union {
		__be32 dst_ip;
		struct in6_addr dst_ipv6;
	};
	__be16 src_port;
	__be16 dst_port;
	unsigned int version;
	unsigned int dcid_len;
	unsigned char dcid[NATFLOW_L7_QUIC_MAX_CID_LEN];
	unsigned int crypto_len;
	unsigned char *crypto_data;
};

static struct natflow_l7_quic_crypto_ctx *natflow_l7_quic_crypto_ctx;
static unsigned int natflow_l7_quic_crypto_cpu_num;
static int natflow_l7_quic_crypto_ready;
static struct natflow_l7_quic_cache_node (*natflow_l7_quic_cache)[NATFLOW_L7_QUIC_CACHE_NODE_MAX];
static unsigned int natflow_l7_quic_cache_cpu_num;

#if defined(CONFIG_NATFLOW_URLLOGGER)
static int natflow_l7_tls_cache_init(void)
{
	natflow_l7_tls_cache_cpu_num = nr_cpu_ids;
	natflow_l7_tls_cache = kcalloc(natflow_l7_tls_cache_cpu_num,
	                               sizeof(*natflow_l7_tls_cache),
	                               GFP_KERNEL);
	if (natflow_l7_tls_cache == NULL)
		return -ENOMEM;

	return 0;
}

static void natflow_l7_tls_cache_cleanup(void)
{
	int i, j;

	if (natflow_l7_tls_cache == NULL)
		return;

	for (i = 0; i < natflow_l7_tls_cache_cpu_num; i++) {
		for (j = 0; j < NATFLOW_L7_TLS_CACHE_NODE_MAX; j++) {
			kfree(natflow_l7_tls_cache[i][j].data);
			natflow_l7_tls_cache[i][j].data = NULL;
		}
	}

	kfree(natflow_l7_tls_cache);
	natflow_l7_tls_cache = NULL;
	natflow_l7_tls_cache_cpu_num = 0;
}
#endif

int natflow_l7_tls_cache_attach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port, __u32 seq,
        unsigned char *data, unsigned int data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = NATFLOW_L7_TLS_CACHE_NODE_MAX;

	if (natflow_l7_tls_cache == NULL || i >= natflow_l7_tls_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < NATFLOW_L7_TLS_CACHE_NODE_MAX; j++) {
		if (natflow_l7_tls_cache[i][j].data != NULL) {
			if (time_after(jiffies,
			               natflow_l7_tls_cache[i][j].active_jiffies +
			               NATFLOW_L7_TLS_CACHE_TIMEOUT * HZ)) {
				kfree(natflow_l7_tls_cache[i][j].data);
				natflow_l7_tls_cache[i][j].data = NULL;
			} else if (natflow_l7_tls_cache[i][j].src_ip == src_ip &&
			           natflow_l7_tls_cache[i][j].src_port == src_port &&
			           natflow_l7_tls_cache[i][j].dst_ip == dst_ip &&
			           natflow_l7_tls_cache[i][j].dst_port == dst_port) {
				return -EEXIST;
			}
		}

		if (next_to_use == NATFLOW_L7_TLS_CACHE_NODE_MAX &&
		        natflow_l7_tls_cache[i][j].data == NULL)
			next_to_use = j;
	}
	if (next_to_use == NATFLOW_L7_TLS_CACHE_NODE_MAX)
		return -ENOMEM;

	natflow_l7_tls_cache[i][next_to_use].src_ip = src_ip;
	natflow_l7_tls_cache[i][next_to_use].src_port = src_port;
	natflow_l7_tls_cache[i][next_to_use].dst_ip = dst_ip;
	natflow_l7_tls_cache[i][next_to_use].dst_port = dst_port;
	natflow_l7_tls_cache[i][next_to_use].seq = seq;
	natflow_l7_tls_cache[i][next_to_use].data_len = data_len;
	natflow_l7_tls_cache[i][next_to_use].data = data;
	natflow_l7_tls_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

int natflow_l7_tls_cache_attach6(const struct in6_addr *src_ip,
        __be16 src_port, const struct in6_addr *dst_ip, __be16 dst_port,
        __u32 seq, unsigned char *data, unsigned int data_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = NATFLOW_L7_TLS_CACHE_NODE_MAX;

	if (natflow_l7_tls_cache == NULL || i >= natflow_l7_tls_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < NATFLOW_L7_TLS_CACHE_NODE_MAX; j++) {
		if (natflow_l7_tls_cache[i][j].data != NULL) {
			if (time_after(jiffies,
			               natflow_l7_tls_cache[i][j].active_jiffies +
			               NATFLOW_L7_TLS_CACHE_TIMEOUT * HZ)) {
				kfree(natflow_l7_tls_cache[i][j].data);
				natflow_l7_tls_cache[i][j].data = NULL;
			} else if (memcmp(&natflow_l7_tls_cache[i][j].src_ipv6,
			                  src_ip, sizeof(*src_ip)) == 0 &&
			           natflow_l7_tls_cache[i][j].src_port == src_port &&
			           memcmp(&natflow_l7_tls_cache[i][j].dst_ipv6,
			                  dst_ip, sizeof(*dst_ip)) == 0 &&
			           natflow_l7_tls_cache[i][j].dst_port == dst_port) {
				return -EEXIST;
			}
		}

		if (next_to_use == NATFLOW_L7_TLS_CACHE_NODE_MAX &&
		        natflow_l7_tls_cache[i][j].data == NULL)
			next_to_use = j;
	}
	if (next_to_use == NATFLOW_L7_TLS_CACHE_NODE_MAX)
		return -ENOMEM;

	memcpy(&natflow_l7_tls_cache[i][next_to_use].src_ipv6, src_ip,
	       sizeof(*src_ip));
	natflow_l7_tls_cache[i][next_to_use].src_port = src_port;
	memcpy(&natflow_l7_tls_cache[i][next_to_use].dst_ipv6, dst_ip,
	       sizeof(*dst_ip));
	natflow_l7_tls_cache[i][next_to_use].dst_port = dst_port;
	natflow_l7_tls_cache[i][next_to_use].seq = seq;
	natflow_l7_tls_cache[i][next_to_use].data_len = data_len;
	natflow_l7_tls_cache[i][next_to_use].data = data;
	natflow_l7_tls_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;

	return 0;
}

unsigned char *natflow_l7_tls_cache_detach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port, __u32 *seq,
        unsigned int *data_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *data = NULL;

	if (natflow_l7_tls_cache == NULL || i >= natflow_l7_tls_cache_cpu_num)
		return NULL;

	for (j = 0; j < NATFLOW_L7_TLS_CACHE_NODE_MAX; j++) {
		if (natflow_l7_tls_cache[i][j].data != NULL) {
			if (time_after(jiffies,
			               natflow_l7_tls_cache[i][j].active_jiffies +
			               NATFLOW_L7_TLS_CACHE_TIMEOUT * HZ)) {
				kfree(natflow_l7_tls_cache[i][j].data);
				natflow_l7_tls_cache[i][j].data = NULL;
			} else if (natflow_l7_tls_cache[i][j].src_ip == src_ip &&
			           natflow_l7_tls_cache[i][j].src_port == src_port &&
			           natflow_l7_tls_cache[i][j].dst_ip == dst_ip &&
			           natflow_l7_tls_cache[i][j].dst_port == dst_port) {
				/* Only origin-path cache lookup is supported, so keep dst strict. */
				data = natflow_l7_tls_cache[i][j].data;
				*seq = natflow_l7_tls_cache[i][j].seq;
				*data_len = natflow_l7_tls_cache[i][j].data_len;
				natflow_l7_tls_cache[i][j].data = NULL;
			}
		}
	}

	return data;
}

unsigned char *natflow_l7_tls_cache_detach6(const struct in6_addr *src_ip,
        __be16 src_port, const struct in6_addr *dst_ip, __be16 dst_port,
        __u32 *seq, unsigned int *data_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *data = NULL;

	if (natflow_l7_tls_cache == NULL || i >= natflow_l7_tls_cache_cpu_num)
		return NULL;

	for (j = 0; j < NATFLOW_L7_TLS_CACHE_NODE_MAX; j++) {
		if (natflow_l7_tls_cache[i][j].data != NULL) {
			if (time_after(jiffies,
			               natflow_l7_tls_cache[i][j].active_jiffies +
			               NATFLOW_L7_TLS_CACHE_TIMEOUT * HZ)) {
				kfree(natflow_l7_tls_cache[i][j].data);
				natflow_l7_tls_cache[i][j].data = NULL;
			} else if (memcmp(&natflow_l7_tls_cache[i][j].src_ipv6,
			                  src_ip, sizeof(*src_ip)) == 0 &&
			           natflow_l7_tls_cache[i][j].src_port == src_port &&
			           memcmp(&natflow_l7_tls_cache[i][j].dst_ipv6,
			                  dst_ip, sizeof(*dst_ip)) == 0 &&
			           natflow_l7_tls_cache[i][j].dst_port == dst_port) {
				/* Only origin-path cache lookup is supported, so keep dst strict. */
				data = natflow_l7_tls_cache[i][j].data;
				*seq = natflow_l7_tls_cache[i][j].seq;
				*data_len = natflow_l7_tls_cache[i][j].data_len;
				natflow_l7_tls_cache[i][j].data = NULL;
			}
		}
	}

	return data;
}

#if defined(CONFIG_NATFLOW_URLLOGGER)
static int natflow_l7_quic_cache_init(void)
{
	natflow_l7_quic_cache_cpu_num = nr_cpu_ids;
	natflow_l7_quic_cache = kcalloc(natflow_l7_quic_cache_cpu_num,
	                                sizeof(*natflow_l7_quic_cache),
	                                GFP_KERNEL);
	if (natflow_l7_quic_cache == NULL)
		return -ENOMEM;

	return 0;
}

static void natflow_l7_quic_cache_cleanup(void)
{
	int i, j;

	if (natflow_l7_quic_cache == NULL)
		return;

	for (i = 0; i < natflow_l7_quic_cache_cpu_num; i++) {
		for (j = 0; j < NATFLOW_L7_QUIC_CACHE_NODE_MAX; j++) {
			kfree(natflow_l7_quic_cache[i][j].crypto_data);
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
		}
	}

	kfree(natflow_l7_quic_cache);
	natflow_l7_quic_cache = NULL;
	natflow_l7_quic_cache_cpu_num = 0;
}

static void natflow_l7_quic_crypto_cleanup(void)
{
	int i;

	natflow_l7_quic_crypto_ready = 0;
	if (natflow_l7_quic_crypto_ctx == NULL)
		return;

	for (i = 0; i < natflow_l7_quic_crypto_cpu_num; i++) {
		if (natflow_l7_quic_crypto_ctx[i].aead_req != NULL)
			aead_request_free(natflow_l7_quic_crypto_ctx[i].aead_req);
		if (natflow_l7_quic_crypto_ctx[i].aead != NULL)
			crypto_free_aead(natflow_l7_quic_crypto_ctx[i].aead);
		if (natflow_l7_quic_crypto_ctx[i].hp_req != NULL)
			skcipher_request_free(natflow_l7_quic_crypto_ctx[i].hp_req);
		if (natflow_l7_quic_crypto_ctx[i].hp != NULL)
			crypto_free_skcipher(natflow_l7_quic_crypto_ctx[i].hp);
		if (natflow_l7_quic_crypto_ctx[i].hmac != NULL)
			crypto_free_shash(natflow_l7_quic_crypto_ctx[i].hmac);
	}

	kfree(natflow_l7_quic_crypto_ctx);
	natflow_l7_quic_crypto_ctx = NULL;
	natflow_l7_quic_crypto_cpu_num = 0;
}

static int natflow_l7_quic_crypto_init(void)
{
	int i;
	int ret = 0;

	natflow_l7_quic_crypto_cpu_num = nr_cpu_ids;
	natflow_l7_quic_crypto_ctx = kcalloc(natflow_l7_quic_crypto_cpu_num,
	                                     sizeof(*natflow_l7_quic_crypto_ctx),
	                                     GFP_KERNEL);
	if (natflow_l7_quic_crypto_ctx == NULL)
		return -ENOMEM;

	for (i = 0; i < natflow_l7_quic_crypto_cpu_num; i++) {
		natflow_l7_quic_crypto_ctx[i].hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
		if (IS_ERR(natflow_l7_quic_crypto_ctx[i].hmac)) {
			ret = PTR_ERR(natflow_l7_quic_crypto_ctx[i].hmac);
			natflow_l7_quic_crypto_ctx[i].hmac = NULL;
			goto failed;
		}

		natflow_l7_quic_crypto_ctx[i].hp = crypto_alloc_skcipher("ecb(aes)", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(natflow_l7_quic_crypto_ctx[i].hp)) {
			ret = PTR_ERR(natflow_l7_quic_crypto_ctx[i].hp);
			natflow_l7_quic_crypto_ctx[i].hp = NULL;
			goto failed;
		}

		natflow_l7_quic_crypto_ctx[i].hp_req = skcipher_request_alloc(natflow_l7_quic_crypto_ctx[i].hp, GFP_KERNEL);
		if (natflow_l7_quic_crypto_ctx[i].hp_req == NULL) {
			ret = -ENOMEM;
			goto failed;
		}

		natflow_l7_quic_crypto_ctx[i].aead = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(natflow_l7_quic_crypto_ctx[i].aead)) {
			ret = PTR_ERR(natflow_l7_quic_crypto_ctx[i].aead);
			natflow_l7_quic_crypto_ctx[i].aead = NULL;
			goto failed;
		}

		natflow_l7_quic_crypto_ctx[i].aead_req = aead_request_alloc(natflow_l7_quic_crypto_ctx[i].aead, GFP_KERNEL);
		if (natflow_l7_quic_crypto_ctx[i].aead_req == NULL) {
			ret = -ENOMEM;
			goto failed;
		}
	}

	natflow_l7_quic_crypto_ready = 1;
	return 0;

failed:
	natflow_l7_quic_crypto_cleanup();
	return ret;
}
#endif

static int natflow_l7_quic_hmac_sha256(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *key, unsigned int key_len,
        const unsigned char *data, unsigned int data_len,
        unsigned char *out)
{
	struct shash_desc *desc = (struct shash_desc *)ctx->desc_buf;
	int ret;

	ret = crypto_shash_setkey(ctx->hmac, key, key_len);
	if (ret != 0)
		return ret;

	desc->tfm = ctx->hmac;
	ret = crypto_shash_digest(desc, data, data_len, out);

	shash_desc_zero(desc);
	return ret;
}

static int natflow_l7_quic_hkdf_expand(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *secret, unsigned int secret_len,
        const unsigned char *info, unsigned int info_len,
        unsigned char *out, unsigned int out_len)
{
	unsigned char *input = ctx->hkdf_input;
	unsigned char *digest = ctx->hkdf_digest;
	int ret;

	if (out_len > NATFLOW_L7_QUIC_INITIAL_SECRET_LEN ||
	        info_len + 1 > sizeof(ctx->hkdf_input))
		return -EINVAL;

	memcpy(input, info, info_len);
	input[info_len] = 1;
	ret = natflow_l7_quic_hmac_sha256(ctx, secret, secret_len,
	                                  input, info_len + 1, digest);
	if (ret == 0)
		memcpy(out, digest, out_len);

	memzero_explicit(input, sizeof(ctx->hkdf_input));
	memzero_explicit(digest, sizeof(ctx->hkdf_digest));
	return ret;
}

static int natflow_l7_quic_hkdf_expand_label(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *secret, unsigned int secret_len,
        const char *label,
        unsigned char *out, unsigned int out_len)
{
	unsigned char *info = ctx->hkdf_info;
	unsigned int label_len = strlen(label);
	unsigned int full_label_len = strlen("tls13 ") + label_len;
	int ret;

	if (full_label_len > 255 || 4 + full_label_len > sizeof(ctx->hkdf_info))
		return -EINVAL;

	info[0] = (out_len >> 8) & 0xff;
	info[1] = out_len & 0xff;
	info[2] = full_label_len;
	memcpy(info + 3, "tls13 ", strlen("tls13 "));
	memcpy(info + 3 + strlen("tls13 "), label, label_len);
	info[3 + full_label_len] = 0;

	ret = natflow_l7_quic_hkdf_expand(ctx, secret, secret_len,
	                                  info, 4 + full_label_len, out, out_len);
	memzero_explicit(info, sizeof(ctx->hkdf_info));
	return ret;
}

static int natflow_l7_quic_initial_keys(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *dcid, unsigned int dcid_len,
        unsigned char *key, unsigned char *iv, unsigned char *hp)
{
	unsigned char *initial_secret = ctx->initial_secret;
	unsigned char *client_secret = ctx->client_secret;
	int ret;

	ret = natflow_l7_quic_hmac_sha256(ctx, natflow_l7_quic_v1_initial_salt,
	                                  sizeof(natflow_l7_quic_v1_initial_salt),
	                                  dcid, dcid_len, initial_secret);
	if (ret != 0)
		goto out;

	ret = natflow_l7_quic_hkdf_expand_label(ctx, initial_secret,
	                                        NATFLOW_L7_QUIC_INITIAL_SECRET_LEN,
	                                        "client in", client_secret,
	                                        NATFLOW_L7_QUIC_INITIAL_SECRET_LEN);
	if (ret != 0)
		goto out;

	ret = natflow_l7_quic_hkdf_expand_label(ctx, client_secret,
	                                        NATFLOW_L7_QUIC_INITIAL_SECRET_LEN,
	                                        "quic key", key,
	                                        NATFLOW_L7_QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		goto out;

	ret = natflow_l7_quic_hkdf_expand_label(ctx, client_secret,
	                                        NATFLOW_L7_QUIC_INITIAL_SECRET_LEN,
	                                        "quic iv", iv,
	                                        NATFLOW_L7_QUIC_INITIAL_IV_LEN);
	if (ret != 0)
		goto out;

	ret = natflow_l7_quic_hkdf_expand_label(ctx, client_secret,
	                                        NATFLOW_L7_QUIC_INITIAL_SECRET_LEN,
	                                        "quic hp", hp,
	                                        NATFLOW_L7_QUIC_INITIAL_KEY_LEN);

out:
	memzero_explicit(initial_secret, sizeof(ctx->initial_secret));
	memzero_explicit(client_secret, sizeof(ctx->client_secret));
	return ret;
}

static int natflow_l7_quic_header_protection_mask(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *hp_key,
        const unsigned char *sample,
        unsigned char *mask)
{
	struct skcipher_request *req = ctx->hp_req;
	struct scatterlist src;
	struct scatterlist dst;
	int ret;

	ret = crypto_skcipher_setkey(ctx->hp, hp_key,
	                             NATFLOW_L7_QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		return ret;

	sg_init_one(&src, sample, NATFLOW_L7_QUIC_HP_SAMPLE_LEN);
	sg_init_one(&dst, mask, NATFLOW_L7_QUIC_HP_SAMPLE_LEN);
	skcipher_request_set_callback(req, 0, NULL, NULL);
	skcipher_request_set_crypt(req, &src, &dst,
	                           NATFLOW_L7_QUIC_HP_SAMPLE_LEN, NULL);
	return crypto_skcipher_encrypt(req);
}

static int natflow_l7_quic_initial_decrypt(struct natflow_l7_quic_crypto_ctx *ctx,
        const unsigned char *key,
        const unsigned char *iv,
        unsigned char *packet,
        unsigned int packet_len,
        unsigned int header_len,
        u64 packet_number,
        unsigned char **payload,
        unsigned int *payload_len)
{
	struct aead_request *req = ctx->aead_req;
	struct scatterlist sg;
	unsigned int crypt_len;
	int i;
	int ret;

	if (header_len >= packet_len)
		return -EINVAL;

	crypt_len = packet_len - header_len;
	if (crypt_len < NATFLOW_L7_QUIC_INITIAL_TAG_LEN)
		return -EINVAL;

	memcpy(ctx->nonce, iv, sizeof(ctx->nonce));
	for (i = 0; i < 8; i++)
		ctx->nonce[sizeof(ctx->nonce) - 1 - i] ^= (packet_number >> (i * 8)) & 0xff;

	ret = crypto_aead_setauthsize(ctx->aead, NATFLOW_L7_QUIC_INITIAL_TAG_LEN);
	if (ret != 0)
		goto out;
	ret = crypto_aead_setkey(ctx->aead, key, NATFLOW_L7_QUIC_INITIAL_KEY_LEN);
	if (ret != 0)
		goto out;

	sg_init_one(&sg, packet, packet_len);
	aead_request_set_callback(req, 0, NULL, NULL);
	aead_request_set_ad(req, header_len);
	aead_request_set_crypt(req, &sg, &sg, crypt_len, ctx->nonce);
	ret = crypto_aead_decrypt(req);
	if (ret == 0) {
		*payload = packet + header_len;
		*payload_len = crypt_len - NATFLOW_L7_QUIC_INITIAL_TAG_LEN;
	}

out:
	return ret;
}

enum natflow_l7_tls_search_result natflow_l7_quic_initial_sni_search(const unsigned char *data,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len)
{
	struct natflow_l7_quic_crypto_ctx *ctx;
	unsigned char *packet;
	unsigned char *payload = NULL;
	unsigned int payload_len = 0;
	unsigned int pn_len;
	unsigned int header_len;
	u64 packet_number = 0;
	int cpu = smp_processor_id();
	int i;
	int ret;

	*host = NULL;

	if (!natflow_l7_quic_crypto_ready ||
	        natflow_l7_quic_crypto_ctx == NULL ||
	        cpu >= natflow_l7_quic_crypto_cpu_num)
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;

	ctx = &natflow_l7_quic_crypto_ctx[cpu];

	/* Fits regular MTU-sized skb UDP payloads; larger Initial packets are not parsed. */
	if (info->packet_len > sizeof(ctx->scratch_packet))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	packet = ctx->scratch_packet;
	memcpy(packet, data, info->packet_len);

	ret = natflow_l7_quic_initial_keys(ctx, info->dcid, info->dcid_len,
	                                   ctx->key, ctx->iv, ctx->hp_key);
	if (ret != 0)
		goto malformed;

	ret = natflow_l7_quic_header_protection_mask(ctx, ctx->hp_key,
	        packet + info->pn_offset + NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN,
	        ctx->mask);
	if (ret != 0)
		goto malformed;

	packet[0] ^= ctx->mask[0] & 0x0f;
	pn_len = (packet[0] & 0x03) + 1;
	if (!natflow_l7_quic_has_bytes(info->pn_offset, pn_len,
	                               info->packet_len))
		goto malformed;

	for (i = 0; i < pn_len; i++) {
		packet[info->pn_offset + i] ^= ctx->mask[i + 1];
		packet_number = (packet_number << 8) | packet[info->pn_offset + i];
	}

	header_len = info->pn_offset + pn_len;
	ret = natflow_l7_quic_initial_decrypt(ctx, ctx->key, ctx->iv,
	                                      packet, info->packet_len,
	                                      header_len, packet_number,
	                                      &payload, &payload_len);
	if (ret != 0)
		goto malformed;

	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	memzero_explicit(ctx->hp_key, sizeof(ctx->hp_key));
	memzero_explicit(ctx->mask, sizeof(ctx->mask));
	memzero_explicit(ctx->nonce, sizeof(ctx->nonce));

	return natflow_l7_quic_crypto_frames_search(payload, payload_len,
	        crypto_data, crypto_len, host, host_len);

malformed:
	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));
	memzero_explicit(ctx->hp_key, sizeof(ctx->hp_key));
	memzero_explicit(ctx->mask, sizeof(ctx->mask));
	memzero_explicit(ctx->nonce, sizeof(ctx->nonce));
	return NATFLOW_L7_TLS_SEARCH_MALFORMED;
}

static int natflow_l7_quic_cache_match(const struct natflow_l7_quic_cache_node *node,
        __be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info)
{
	return node->crypto_data != NULL &&
	       node->src_ip == src_ip &&
	       node->src_port == src_port &&
	       node->dst_ip == dst_ip &&
	       node->dst_port == dst_port &&
	       node->version == info->version &&
	       node->dcid_len == info->dcid_len &&
	       memcmp(node->dcid, info->dcid, info->dcid_len) == 0;
}

static int natflow_l7_quic_cache_match6(const struct natflow_l7_quic_cache_node *node,
        const struct in6_addr *src_ip, __be16 src_port,
        const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info)
{
	return node->crypto_data != NULL &&
	       memcmp(&node->src_ipv6, src_ip, sizeof(*src_ip)) == 0 &&
	       node->src_port == src_port &&
	       memcmp(&node->dst_ipv6, dst_ip, sizeof(*dst_ip)) == 0 &&
	       node->dst_port == dst_port &&
	       node->version == info->version &&
	       node->dcid_len == info->dcid_len &&
	       memcmp(node->dcid, info->dcid, info->dcid_len) == 0;
}

int natflow_l7_quic_cache_attach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char *crypto_data,
        unsigned int crypto_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = NATFLOW_L7_QUIC_CACHE_NODE_MAX;

	if (crypto_data == NULL || crypto_len == 0)
		return -EINVAL;
	if (natflow_l7_quic_cache == NULL || i >= natflow_l7_quic_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < NATFLOW_L7_QUIC_CACHE_NODE_MAX; j++) {
		if (natflow_l7_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies,
		                   natflow_l7_quic_cache[i][j].active_jiffies +
		                   NATFLOW_L7_QUIC_CACHE_TIMEOUT * HZ)) {
			kfree(natflow_l7_quic_cache[i][j].crypto_data);
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
		}
		if (natflow_l7_quic_cache_match(&natflow_l7_quic_cache[i][j],
		                                 src_ip, src_port, dst_ip, dst_port,
		                                 info))
			return -EEXIST;
		if (next_to_use == NATFLOW_L7_QUIC_CACHE_NODE_MAX &&
		        natflow_l7_quic_cache[i][j].crypto_data == NULL)
			next_to_use = j;
	}
	if (next_to_use == NATFLOW_L7_QUIC_CACHE_NODE_MAX)
		return -ENOMEM;

	natflow_l7_quic_cache[i][next_to_use].src_ip = src_ip;
	natflow_l7_quic_cache[i][next_to_use].src_port = src_port;
	natflow_l7_quic_cache[i][next_to_use].dst_ip = dst_ip;
	natflow_l7_quic_cache[i][next_to_use].dst_port = dst_port;
	natflow_l7_quic_cache[i][next_to_use].version = info->version;
	natflow_l7_quic_cache[i][next_to_use].dcid_len = info->dcid_len;
	memcpy(natflow_l7_quic_cache[i][next_to_use].dcid, info->dcid,
	       info->dcid_len);
	natflow_l7_quic_cache[i][next_to_use].crypto_len = crypto_len;
	natflow_l7_quic_cache[i][next_to_use].crypto_data = crypto_data;
	natflow_l7_quic_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;
	return 0;
}

int natflow_l7_quic_cache_attach6(const struct in6_addr *src_ip,
        __be16 src_port, const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned char *crypto_data,
        unsigned int crypto_len)
{
	int i = smp_processor_id();
	int j;
	int next_to_use = NATFLOW_L7_QUIC_CACHE_NODE_MAX;

	if (crypto_data == NULL || crypto_len == 0)
		return -EINVAL;
	if (natflow_l7_quic_cache == NULL || i >= natflow_l7_quic_cache_cpu_num)
		return -ENOMEM;

	for (j = 0; j < NATFLOW_L7_QUIC_CACHE_NODE_MAX; j++) {
		if (natflow_l7_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies,
		                   natflow_l7_quic_cache[i][j].active_jiffies +
		                   NATFLOW_L7_QUIC_CACHE_TIMEOUT * HZ)) {
			kfree(natflow_l7_quic_cache[i][j].crypto_data);
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
		}
		if (natflow_l7_quic_cache_match6(&natflow_l7_quic_cache[i][j],
		                                  src_ip, src_port, dst_ip, dst_port,
		                                  info))
			return -EEXIST;
		if (next_to_use == NATFLOW_L7_QUIC_CACHE_NODE_MAX &&
		        natflow_l7_quic_cache[i][j].crypto_data == NULL)
			next_to_use = j;
	}
	if (next_to_use == NATFLOW_L7_QUIC_CACHE_NODE_MAX)
		return -ENOMEM;

	memcpy(&natflow_l7_quic_cache[i][next_to_use].src_ipv6, src_ip,
	       sizeof(*src_ip));
	natflow_l7_quic_cache[i][next_to_use].src_port = src_port;
	memcpy(&natflow_l7_quic_cache[i][next_to_use].dst_ipv6, dst_ip,
	       sizeof(*dst_ip));
	natflow_l7_quic_cache[i][next_to_use].dst_port = dst_port;
	natflow_l7_quic_cache[i][next_to_use].version = info->version;
	natflow_l7_quic_cache[i][next_to_use].dcid_len = info->dcid_len;
	memcpy(natflow_l7_quic_cache[i][next_to_use].dcid, info->dcid,
	       info->dcid_len);
	natflow_l7_quic_cache[i][next_to_use].crypto_len = crypto_len;
	natflow_l7_quic_cache[i][next_to_use].crypto_data = crypto_data;
	natflow_l7_quic_cache[i][next_to_use].active_jiffies = (unsigned long)jiffies;
	return 0;
}

unsigned char *natflow_l7_quic_cache_detach(__be32 src_ip, __be16 src_port,
        __be32 dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *crypto_data = NULL;

	if (natflow_l7_quic_cache == NULL || i >= natflow_l7_quic_cache_cpu_num)
		return NULL;

	for (j = 0; j < NATFLOW_L7_QUIC_CACHE_NODE_MAX; j++) {
		if (natflow_l7_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies,
		                   natflow_l7_quic_cache[i][j].active_jiffies +
		                   NATFLOW_L7_QUIC_CACHE_TIMEOUT * HZ)) {
			kfree(natflow_l7_quic_cache[i][j].crypto_data);
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
		} else if (natflow_l7_quic_cache_match(&natflow_l7_quic_cache[i][j],
		                                       src_ip, src_port, dst_ip,
		                                       dst_port, info)) {
			crypto_data = natflow_l7_quic_cache[i][j].crypto_data;
			*crypto_len = natflow_l7_quic_cache[i][j].crypto_len;
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
			break;
		}
	}

	return crypto_data;
}

unsigned char *natflow_l7_quic_cache_detach6(const struct in6_addr *src_ip,
        __be16 src_port, const struct in6_addr *dst_ip, __be16 dst_port,
        const struct natflow_l7_quic_initial_info *info,
        unsigned int *crypto_len)
{
	int i = smp_processor_id();
	int j;
	unsigned char *crypto_data = NULL;

	if (natflow_l7_quic_cache == NULL || i >= natflow_l7_quic_cache_cpu_num)
		return NULL;

	for (j = 0; j < NATFLOW_L7_QUIC_CACHE_NODE_MAX; j++) {
		if (natflow_l7_quic_cache[i][j].crypto_data != NULL &&
		        time_after(jiffies,
		                   natflow_l7_quic_cache[i][j].active_jiffies +
		                   NATFLOW_L7_QUIC_CACHE_TIMEOUT * HZ)) {
			kfree(natflow_l7_quic_cache[i][j].crypto_data);
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
		} else if (natflow_l7_quic_cache_match6(&natflow_l7_quic_cache[i][j],
		                                        src_ip, src_port, dst_ip,
		                                        dst_port, info)) {
			crypto_data = natflow_l7_quic_cache[i][j].crypto_data;
			*crypto_len = natflow_l7_quic_cache[i][j].crypto_len;
			natflow_l7_quic_cache[i][j].crypto_data = NULL;
			break;
		}
	}

	return crypto_data;
}

#if defined(CONFIG_NATFLOW_URLLOGGER)
#if NATFLOW_HAVE_IP_SET_STATE_API
#define NATFLOW_L7_URL_CONSUMER_ARGS \
	unsigned int hooknum, const struct nf_hook_state *state, struct sk_buff *skb
#define NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, state, in, out) \
	natflow_l7_url_consume_common(hooknum, state, skb)
#define NATFLOW_L7_DISPATCH_PACKET_VIEW(view, consumer_mask) \
	natflow_l7_dispatch_packet_view(hooknum, state, view, consumer_mask)
#define NATFLOW_L7_DISPATCH_HOST_VIEW(view, host_view, reply_dev, bridge) \
	natflow_l7_dispatch_host_view(hooknum, state, view, host_view, reply_dev, bridge)
#else
#define NATFLOW_L7_URL_CONSUMER_ARGS \
	unsigned int hooknum, const struct net_device *in, \
	const struct net_device *out, struct sk_buff *skb
#define NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, state, in, out) \
	natflow_l7_url_consume_common(hooknum, in, out, skb)
#define NATFLOW_L7_DISPATCH_PACKET_VIEW(view, consumer_mask) \
	natflow_l7_dispatch_packet_view(hooknum, in, out, view, consumer_mask)
#define NATFLOW_L7_DISPATCH_HOST_VIEW(view, host_view, reply_dev, bridge) \
	natflow_l7_dispatch_host_view(hooknum, in, out, view, host_view, reply_dev, bridge)
#endif

#if NATFLOW_HAVE_IP_SET_STATE_API
static unsigned int natflow_l7_dispatch_host_view(unsigned int hooknum,
        const struct nf_hook_state *state,
        const struct natflow_l7_packet_view *view,
        const struct natflow_l7_host_view *host_view,
        const struct net_device *reply_dev,
        int bridge)
#else
static unsigned int natflow_l7_dispatch_host_view(unsigned int hooknum,
        const struct net_device *in,
        const struct net_device *out,
        const struct natflow_l7_packet_view *view,
        const struct natflow_l7_host_view *host_view,
        const struct net_device *reply_dev,
        int bridge)
#endif
{
	if (!view ||
	        !(view->consumer_mask & (NATFLOW_L7_CONSUMER_URL |
	                                 NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

#if NATFLOW_HAVE_IP_SET_STATE_API
	return natflow_urllogger_consume_host_view(hooknum, state, view,
	                                           host_view, reply_dev, bridge);
#else
	return natflow_urllogger_consume_host_view(hooknum, in, out, view,
	                                           host_view, reply_dev, bridge);
#endif
}

static noinline unsigned int natflow_l7_quic4(NATFLOW_L7_URL_CONSUMER_ARGS,
        const struct natflow_l7_packet_view *view)
{
	struct natflow_l7_quic_initial_info quic_info;
	enum natflow_l7_tls_search_result sni_result;
	unsigned char *host = NULL;
	unsigned char *crypto_data = NULL;
	natflow_t *nf = NULL;
	struct iphdr *iph;
	void *l4;
	unsigned int crypto_len = 0;
	unsigned int udp_len;
	int host_len = 0;
	int data_len;
	int quic_ret;
	unsigned char *data;
	unsigned int ret = NF_ACCEPT;

	if (!view || !view->ct)
		return ret;

	if (skb_try_make_writable(skb, ip_hdr(skb)->ihl * 4 + sizeof(struct udphdr)))
		return ret;
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	if (UDPH(l4)->dest != __constant_htons(443))
		return ret;

	udp_len = ntohs(UDPH(l4)->len);
	if (udp_len <= sizeof(struct udphdr))
		goto skip;

	data_len = udp_len - sizeof(struct udphdr);
	if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr) + data_len))
		return ret;

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;
	data = skb->data + iph->ihl * 4 + sizeof(struct udphdr);

	quic_ret = natflow_l7_quic_initial_parse_info(data, data_len, &quic_info);
	if (quic_ret != 0)
		goto skip;

	nf = natflow_session_get(view->ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	crypto_data = natflow_l7_quic_cache_detach(iph->saddr, UDPH(l4)->source,
	              iph->daddr, UDPH(l4)->dest, &quic_info, &crypto_len);
	sni_result = natflow_l7_quic_initial_sni_search(data, &quic_info,
	                                                &crypto_data,
	                                                &crypto_len,
	                                                &host, &host_len);
	if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
		if (crypto_data != NULL && crypto_len > 0 &&
		        natflow_l7_quic_cache_attach(iph->saddr, UDPH(l4)->source,
		                                     iph->daddr, UDPH(l4)->dest,
		                                     &quic_info, crypto_data, crypto_len) == 0) {
			crypto_data = NULL;
			goto done;
		}
		kfree(crypto_data);
		crypto_data = NULL;
	}

skip:
	set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &view->ct->status);
	if (nf && (nf->status & NF_FF_L7_USE))
		simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

	if (host) {
		struct natflow_l7_host_view host_view;

		if (natflow_l7_host_view_init(&host_view, NATFLOW_L7_SOURCE_QUIC,
		                              host, host_len, 0) == 0)
			ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
			                                    NULL, 0);
	}

done:
	kfree(crypto_data);
	return ret;
}

static noinline unsigned int natflow_l7_quic6(NATFLOW_L7_URL_CONSUMER_ARGS,
        const struct natflow_l7_packet_view *view)
{
	struct natflow_l7_quic_initial_info quic_info;
	enum natflow_l7_tls_search_result sni_result;
	unsigned char *host = NULL;
	unsigned char *crypto_data = NULL;
	natflow_t *nf = NULL;
	struct ipv6hdr *ip6h;
	void *l4;
	unsigned int crypto_len = 0;
	unsigned int udp_len;
	int host_len = 0;
	int data_len;
	int quic_ret;
	unsigned char *data;
	unsigned int ret = NF_ACCEPT;

	if (!view || !view->ct)
		return ret;

	if (skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
		return ret;
	ip6h = ipv6_hdr(skb);
	l4 = (void *)ip6h + sizeof(struct ipv6hdr);
	if (UDPH(l4)->dest != __constant_htons(443))
		return ret;

	udp_len = ntohs(UDPH(l4)->len);
	if (udp_len <= sizeof(struct udphdr))
		goto skip;

	data_len = udp_len - sizeof(struct udphdr);
	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr) + data_len))
		return ret;

	ip6h = ipv6_hdr(skb);
	l4 = (void *)ip6h + sizeof(struct ipv6hdr);
	data = skb->data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);

	quic_ret = natflow_l7_quic_initial_parse_info(data, data_len, &quic_info);
	if (quic_ret != 0)
		goto skip;

	nf = natflow_session_get(view->ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	crypto_data = natflow_l7_quic_cache_detach6(&ip6h->saddr, UDPH(l4)->source,
	              &ip6h->daddr, UDPH(l4)->dest, &quic_info, &crypto_len);
	sni_result = natflow_l7_quic_initial_sni_search(data, &quic_info,
	                                                &crypto_data,
	                                                &crypto_len,
	                                                &host, &host_len);
	if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
		if (crypto_data != NULL && crypto_len > 0 &&
		        natflow_l7_quic_cache_attach6(&ip6h->saddr, UDPH(l4)->source,
		                                      &ip6h->daddr, UDPH(l4)->dest,
		                                      &quic_info, crypto_data, crypto_len) == 0) {
			crypto_data = NULL;
			goto done;
		}
		kfree(crypto_data);
		crypto_data = NULL;
	}

skip:
	set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &view->ct->status);
	if (nf && (nf->status & NF_FF_L7_USE))
		simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

	if (host) {
		struct natflow_l7_host_view host_view;

		if (natflow_l7_host_view_init(&host_view, NATFLOW_L7_SOURCE_QUIC,
		                              host, host_len, 0) == 0)
			ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
			                                    NULL, 0);
	}

done:
	kfree(crypto_data);
	return ret;
}

static noinline unsigned int natflow_l7_tcp4(NATFLOW_L7_URL_CONSUMER_ARGS,
        const struct natflow_l7_packet_view *view)
{
	const struct net_device *reply_dev;
	struct nf_conn *ct;
	natflow_t *nf = NULL;
	struct iphdr *iph;
	void *l4;
	int bridge;
	int data_len;
	unsigned char *data;
	unsigned int ret = NF_ACCEPT;

	if (!view || !view->ct)
		return ret;

#if NATFLOW_HAVE_IP_SET_STATE_API
	reply_dev = state->in;
#else
	reply_dev = in;
#endif
	ct = view->ct;
	bridge = (view->flags & NATFLOW_L7_PACKET_F_PPPOE) != 0;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return ret;
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return ret;

	if (skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
		return ret;
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	data_len = ntohs(iph->tot_len) - (iph->ihl * 4 + TCPH(l4)->doff * 4);
	if (data_len > 0) {
		unsigned char *prev_data = NULL;
		__u32 prev_seq = 0;
		unsigned int prev_data_len = 0;
		unsigned char *host = NULL;
		int host_len;
		int allow_http = 0;
		enum natflow_l7_tls_search_result sni_result;

		if (skb_try_make_writable(skb, skb->len))
			goto skip;
		iph = ip_hdr(skb);
		l4 = (void *)iph + iph->ihl * 4;
		data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
		allow_http = 1;

		prev_data = natflow_l7_tls_cache_detach(iph->saddr, TCPH(l4)->source,
		                                        iph->daddr, TCPH(l4)->dest,
		                                        &prev_seq, &prev_data_len);
		if (prev_data) {
			unsigned int append_len = data_len;
			unsigned int next_data_len;

			if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq) + prev_data_len) {
				unsigned char *new_data;

				if (prev_data_len >= NATFLOW_L7_TLS_CACHE_DATA_LIMIT ||
				        append_len > NATFLOW_L7_TLS_CACHE_DATA_LIMIT - prev_data_len) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": sni cache data too large, prev_data_len=%u, data_len=%u\n",
					              DEBUG_TCP_ARG(iph,l4), prev_data_len, append_len);
					goto skip;
				}
				next_data_len = prev_data_len + append_len;

				new_data = krealloc(prev_data, next_data_len, GFP_ATOMIC);
				if (!new_data) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to krealloc data\n",
					              DEBUG_TCP_ARG(iph,l4));
					kfree(prev_data);
					prev_data = NULL;
					goto skip;
				}
				prev_data = new_data;

				memcpy(prev_data + prev_data_len, data, data_len);
				prev_data_len = next_data_len;

				host_len = prev_data_len;
				sni_result = natflow_l7_tls_sni_search(prev_data, &host_len,
				                                       &host);
				if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
					if (prev_data_len >= NATFLOW_L7_TLS_CACHE_DATA_LIMIT ||
					        natflow_l7_tls_cache_attach(iph->saddr, TCPH(l4)->source,
					                                    iph->daddr, TCPH(l4)->dest,
					                                    prev_seq, prev_data,
					                                    prev_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach l7 tls cache, prev_data_len=%u\n",
						              DEBUG_TCP_ARG(iph,l4), prev_data_len);
						goto skip;
					}
					prev_data = NULL;
					goto done;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq)) {
				if (natflow_l7_tls_cache_attach(iph->saddr, TCPH(l4)->source,
				                                iph->daddr, TCPH(l4)->dest,
				                                prev_seq, prev_data,
				                                prev_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach l7 tls cache\n",
					              DEBUG_TCP_ARG(iph,l4));
					goto skip;
				}
				prev_data = NULL;
				goto done;
			} else {
				goto skip;
			}
		} else {
			host_len = data_len;
			sni_result = natflow_l7_tls_sni_search(data, &host_len, &host);
			if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
				prev_data = kmemdup(data, data_len, GFP_ATOMIC);
				if (!prev_data)
					goto skip;
				if (natflow_l7_tls_cache_attach(iph->saddr, TCPH(l4)->source,
				                                iph->daddr, TCPH(l4)->dest,
				                                TCPH(l4)->seq, prev_data,
				                                data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT ": failed to attach l7 tls cache\n",
					              DEBUG_TCP_ARG(iph,l4));
					goto skip;
				}
				prev_data = NULL;
				goto done;
			}
		}

skip:
		set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_L7_USE))
			simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

		if (host) {
			struct natflow_l7_host_view host_view;

			if (natflow_l7_host_view_init(&host_view, NATFLOW_L7_SOURCE_TLS,
			                              host, host_len, 0) == 0)
				ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
				                                    reply_dev, bridge);
			kfree(prev_data);
			goto done;
		}

		kfree(prev_data);
		prev_data = NULL;
		if (!allow_http)
			goto done;
		data = skb->data + iph->ihl * 4 + TCPH(l4)->doff * 4;
		{
			struct natflow_l7_feature feature;
			struct natflow_l7_host_view host_view;

			if (natflow_l7_http_parse(data, data_len, &feature) > 0 &&
			        natflow_l7_host_view_from_feature(&host_view, &feature) == 0)
				ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
				                                    reply_dev, bridge);
		}
	}

done:
	return ret;
}

static noinline unsigned int natflow_l7_tcp6(NATFLOW_L7_URL_CONSUMER_ARGS,
        const struct natflow_l7_packet_view *view)
{
	const struct net_device *reply_dev;
	struct nf_conn *ct;
	natflow_t *nf = NULL;
	struct iphdr *iph;
	void *l4;
	int bridge;
	int data_len;
	unsigned char *data;
	unsigned int ret = NF_ACCEPT;

	if (!view || !view->ct)
		return ret;

#if NATFLOW_HAVE_IP_SET_STATE_API
	reply_dev = state->in;
#else
	reply_dev = in;
#endif
	ct = view->ct;
	bridge = (view->flags & NATFLOW_L7_PACKET_F_PPPOE) != 0;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return ret;
	iph = (void *)ipv6_hdr(skb);
	if (IPV6H->version != 6 || IPV6H->nexthdr != IPPROTO_TCP)
		return ret;

	if (skb_try_make_writable(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr)))
		return ret;
	iph = (void *)ipv6_hdr(skb);
	l4 = (void *)iph + sizeof(struct ipv6hdr);

	nf = natflow_session_get(ct);
	if (nf && !(nf->status & NF_FF_L7_USE))
		simple_set_bit(NF_FF_L7_USE_BIT, &nf->status);

	data_len = ntohs(IPV6H->payload_len) - TCPH(l4)->doff * 4;
	if (data_len > 0) {
		unsigned char *prev_data = NULL;
		__u32 prev_seq = 0;
		unsigned int prev_data_len = 0;
		unsigned char *host = NULL;
		int host_len;
		int allow_http = 0;
		enum natflow_l7_tls_search_result sni_result;

		if (skb_try_make_writable(skb, skb->len))
			goto skip;
		iph = (void *)ipv6_hdr(skb);
		l4 = (void *)iph + sizeof(struct ipv6hdr);
		data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;
		allow_http = 1;

		prev_data = natflow_l7_tls_cache_detach6(&IPV6H->saddr,
		                                         TCPH(l4)->source,
		                                         &IPV6H->daddr,
		                                         TCPH(l4)->dest,
		                                         &prev_seq,
		                                         &prev_data_len);
		if (prev_data) {
			unsigned int append_len = data_len;
			unsigned int next_data_len;

			if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq) + prev_data_len) {
				unsigned char *new_data;

				if (prev_data_len >= NATFLOW_L7_TLS_CACHE_DATA_LIMIT ||
				        append_len > NATFLOW_L7_TLS_CACHE_DATA_LIMIT - prev_data_len) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": sni cache data too large, prev_data_len=%u, data_len=%u\n",
					              DEBUG_TCP_ARG6(iph,l4), prev_data_len, append_len);
					goto skip;
				}
				next_data_len = prev_data_len + append_len;

				new_data = krealloc(prev_data, next_data_len, GFP_ATOMIC);
				if (!new_data) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to krealloc data\n",
					              DEBUG_TCP_ARG6(iph,l4));
					kfree(prev_data);
					prev_data = NULL;
					goto skip;
				}
				prev_data = new_data;

				memcpy(prev_data + prev_data_len, data, data_len);
				prev_data_len = next_data_len;

				host_len = prev_data_len;
				sni_result = natflow_l7_tls_sni_search(prev_data, &host_len,
				                                       &host);
				if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
					if (prev_data_len >= NATFLOW_L7_TLS_CACHE_DATA_LIMIT ||
					        natflow_l7_tls_cache_attach6(&IPV6H->saddr,
					                                     TCPH(l4)->source,
					                                     &IPV6H->daddr,
					                                     TCPH(l4)->dest,
					                                     prev_seq, prev_data,
					                                     prev_data_len) != 0) {
						NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach l7 tls cache6, prev_data_len=%u\n",
						              DEBUG_TCP_ARG6(iph,l4), prev_data_len);
						goto skip;
					}
					prev_data = NULL;
					goto done;
				}
			} else if (ntohl(TCPH(l4)->seq) == ntohl(prev_seq)) {
				if (natflow_l7_tls_cache_attach6(&IPV6H->saddr,
				                                 TCPH(l4)->source,
				                                 &IPV6H->daddr,
				                                 TCPH(l4)->dest,
				                                 prev_seq, prev_data,
				                                 prev_data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach l7 tls cache6\n",
					              DEBUG_TCP_ARG6(iph,l4));
					goto skip;
				}
				prev_data = NULL;
				goto done;
			} else {
				goto skip;
			}
		} else {
			host_len = data_len;
			sni_result = natflow_l7_tls_sni_search(data, &host_len, &host);
			if (sni_result == NATFLOW_L7_TLS_SEARCH_NEED_MORE) {
				prev_data = kmemdup(data, data_len, GFP_ATOMIC);
				if (!prev_data)
					goto skip;
				if (natflow_l7_tls_cache_attach6(&IPV6H->saddr,
				                                 TCPH(l4)->source,
				                                 &IPV6H->daddr,
				                                 TCPH(l4)->dest,
				                                 TCPH(l4)->seq, prev_data,
				                                 data_len) != 0) {
					NATFLOW_ERROR("(NUHv1)" DEBUG_TCP_FMT6 ": failed to attach l7 tls cache6\n",
					              DEBUG_TCP_ARG6(iph,l4));
					goto skip;
				}
				prev_data = NULL;
				goto done;
			}
		}

skip:
		set_bit(IPS_NATFLOW_L7_HANDLED_BIT, &ct->status);
		if (nf && (nf->status & NF_FF_L7_USE))
			simple_clear_bit(NF_FF_L7_USE_BIT, &nf->status);

		if (host) {
			struct natflow_l7_host_view host_view;

			if (natflow_l7_host_view_init(&host_view, NATFLOW_L7_SOURCE_TLS,
			                              host, host_len, 0) == 0)
				ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
				                                    reply_dev, bridge);
			kfree(prev_data);
			goto done;
		}

		kfree(prev_data);
		prev_data = NULL;
		if (!allow_http)
			goto done;
		data = skb->data + sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4;
		{
			struct natflow_l7_feature feature;
			struct natflow_l7_host_view host_view;

			if (natflow_l7_http_parse(data, data_len, &feature) > 0 &&
			        natflow_l7_host_view_from_feature(&host_view, &feature) == 0)
				ret = NATFLOW_L7_DISPATCH_HOST_VIEW(view, &host_view,
				                                    reply_dev, bridge);
		}
	}

done:
	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
static unsigned int natflow_l7_dispatch_packet_view(unsigned int hooknum,
        const struct nf_hook_state *state,
        const struct natflow_l7_packet_view *view,
        unsigned int consumer_mask)
#else
static unsigned int natflow_l7_dispatch_packet_view(unsigned int hooknum,
        const struct net_device *in,
        const struct net_device *out,
        const struct natflow_l7_packet_view *view,
        unsigned int consumer_mask)
#endif
{
	struct sk_buff *skb;

	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;
	if (!view || !view->skb)
		return NF_ACCEPT;

	skb = view->skb;
	if (view->l3num == AF_INET6) {
		struct ipv6hdr *ip6h;

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return NF_ACCEPT;
		ip6h = ipv6_hdr(skb);
		if (ip6h->version != 6)
			return NF_ACCEPT;
		if (ip6h->nexthdr == IPPROTO_UDP) {
#if NATFLOW_HAVE_IP_SET_STATE_API
			return natflow_l7_quic6(hooknum, state, skb, view);
#else
			return natflow_l7_quic6(hooknum, in, out, skb, view);
#endif
		}
		if (ip6h->nexthdr == IPPROTO_TCP) {
#if NATFLOW_HAVE_IP_SET_STATE_API
			return natflow_l7_tcp6(hooknum, state, skb, view);
#else
			return natflow_l7_tcp6(hooknum, in, out, skb, view);
#endif
		}
	} else {
		struct iphdr *iph;

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return NF_ACCEPT;
		iph = ip_hdr(skb);
		if (iph->protocol == IPPROTO_UDP) {
#if NATFLOW_HAVE_IP_SET_STATE_API
			return natflow_l7_quic4(hooknum, state, skb, view);
#else
			return natflow_l7_quic4(hooknum, in, out, skb, view);
#endif
		}
		if (iph->protocol == IPPROTO_TCP) {
#if NATFLOW_HAVE_IP_SET_STATE_API
			return natflow_l7_tcp4(hooknum, state, skb, view);
#else
			return natflow_l7_tcp4(hooknum, in, out, skb, view);
#endif
		}
	}

	return NF_ACCEPT;
}

static unsigned int natflow_l7_url_consume_common(NATFLOW_L7_URL_CONSUMER_ARGS)
{
	struct natflow_l7_packet_view view;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	unsigned int consumer_mask;
	unsigned int ret = NF_ACCEPT;

	consumer_mask = natflow_l7_active_consumer_mask();
	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

	memset(&view, 0, sizeof(view));
	view.skb = skb;

	if (skb->protocol == __constant_htons(ETH_P_PPP_SES)) {
		if (!pskb_may_pull(skb, PPPOE_SES_HLEN))
			return NF_DROP;

		if (pppoe_proto(skb) == __constant_htons(PPP_IP)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IP);
			skb->network_header += PPPOE_SES_HLEN;
			view.flags |= NATFLOW_L7_PACKET_F_PPPOE;
		} else if (pppoe_proto(skb) == __constant_htons(PPP_IPV6)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IPV6);
			skb->network_header += PPPOE_SES_HLEN;
			view.flags |= NATFLOW_L7_PACKET_F_PPPOE;
		} else {
			return NF_ACCEPT;
		}
	} else if (skb->protocol != __constant_htons(ETH_P_IP) &&
	           skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		goto out;
	if ((ct->status & IPS_NATFLOW_CT_DROP)) {
		ret = NF_DROP;
		goto out;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		goto out;
	if ((ct->status & IPS_NATFLOW_L7_HANDLED))
		goto out;

	view.ct = ct;
	view.consumer_mask = consumer_mask;
	view.l3num = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num;
	if (view.l3num == AF_INET6)
		view.l3 = ipv6_hdr(skb);
	else
		view.l3 = ip_hdr(skb);

	ret = NATFLOW_L7_DISPATCH_PACKET_VIEW(&view, consumer_mask);

out:
	if (view.flags & NATFLOW_L7_PACKET_F_PPPOE) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}

	return ret;
}

#if !defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG
static unsigned int natflow_l7_url_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	return NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, NULL, in, out);
}
#elif NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
static unsigned int natflow_l7_url_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	return NATFLOW_L7_URL_CONSUMER_CALL(ops->hooknum, skb, NULL, in, out);
}
#elif NATFLOW_NF_HOOK_OPS_HAVE_STATE_ARG
static unsigned int natflow_l7_url_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in,
	                                    state->out);
}
#else
static unsigned int natflow_l7_url_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if NATFLOW_NF_HOOK_STATE_HAS_OUTDEV
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in,
	                                    state->out);
#else
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, state->in, NULL);
#endif
}
#endif
#endif /* !CONFIG_NATFLOW_URLLOGGER_LOCAL_IN */

#if defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG
static unsigned int natflow_l7_url_local_in(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
static unsigned int natflow_l7_url_local_in(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif NATFLOW_NF_HOOK_OPS_HAVE_STATE_ARG
static unsigned int natflow_l7_url_local_in(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if !NATFLOW_HAVE_IP_SET_STATE_API
	const struct net_device *in = state->in;
	const struct net_device *out = state->out;
#endif
#else
static unsigned int natflow_l7_url_local_in(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#if !NATFLOW_HAVE_IP_SET_STATE_API
	const struct net_device *in = state->in;
#if NATFLOW_NF_HOOK_STATE_HAS_OUTDEV
	const struct net_device *out = state->out;
#else
	const struct net_device *out = NULL;
#endif
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	unsigned int consumer_mask;

	consumer_mask = natflow_l7_active_consumer_mask();
	if (!(consumer_mask & (NATFLOW_L7_CONSUMER_URL | NATFLOW_L7_CONSUMER_DPI)))
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;
	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num != AF_INET)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG || NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
	return NATFLOW_L7_URL_CONSUMER_CALL(hooknum, skb, NULL, in, out);
#else
	return NATFLOW_L7_URL_CONSUMER_CALL(state->hook, skb, state, in, out);
#endif
}
#endif /* CONFIG_NATFLOW_URLLOGGER_LOCAL_IN */

static struct nf_hook_ops natflow_l7_url_hooks[] = {
#if defined(CONFIG_NATFLOW_URLLOGGER_LOCAL_IN)
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_local_in,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER + 5,
	},
#else
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = AF_INET6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_l7_url_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 5,
	},
#endif
};

static int natflow_l7_url_hooks_register(void)
{
	return nf_register_hooks(natflow_l7_url_hooks,
	                         ARRAY_SIZE(natflow_l7_url_hooks));
}

static void natflow_l7_url_hooks_unregister(void)
{
	nf_unregister_hooks(natflow_l7_url_hooks,
	                    ARRAY_SIZE(natflow_l7_url_hooks));
}
#endif /* CONFIG_NATFLOW_URLLOGGER */

static inline int natflow_l7_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return offset <= len && bytes <= len - offset;
}

static inline int natflow_l7_is_digit(unsigned char c)
{
	return c >= '0' && c <= '9';
}

static inline int natflow_l7_host_char_valid(unsigned char c)
{
	return (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') ||
	       c == '-' ||
	       c == '.';
}

ssize_t natflow_l7_copy_host_tolower(unsigned char *dst,
        const unsigned char *src, ssize_t n, unsigned int flags)
{
	ssize_t i = 0;
	ssize_t end = n;
	ssize_t out = 0;
	ssize_t label_len = 0;
	unsigned char last = 0;

	if (n <= 0)
		return -EINVAL;

	if ((flags & NATFLOW_L7_HOST_ALLOW_PORT)) {
		ssize_t colon = -1;
		unsigned int port = 0;

		for (i = 0; i < end; i++) {
			if (src[i] != ':')
				continue;
			if (colon >= 0)
				return -EINVAL;
			colon = i;
		}

		if (colon >= 0) {
			if (colon == 0 || colon + 1 >= end)
				return -EINVAL;
			for (i = colon + 1; i < end; i++) {
				unsigned int digit;

				if (!natflow_l7_is_digit(src[i]))
					return -EINVAL;
				digit = src[i] - '0';
				if (port > 6553 || (port == 6553 && digit > 5))
					return -EINVAL;
				port = port * 10 + digit;
			}
			end = colon;
		}
	}

	if (end > 0 && src[end - 1] == '.')
		end--;
	if (end <= 0 || end > NATFLOW_L7_HOST_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < end; i++) {
		unsigned char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = c - 'A' + 'a';
		if (!natflow_l7_host_char_valid(c))
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

	return out;
}

int natflow_l7_uri_validate(const unsigned char *uri, int uri_len)
{
	int i;

	if (uri_len <= 0)
		return -EINVAL;

	for (i = 0; i < uri_len; i++) {
		if (uri[i] < 0x20 || uri[i] == 0x7f)
			return -EINVAL;
	}

	return 0;
}

void natflow_l7_feature_init(struct natflow_l7_feature *feature,
        enum natflow_l7_feature_source source)
{
	memset(feature, 0, sizeof(*feature));
	feature->source = source;
	feature->http_method = NATFLOW_L7_HTTP_NONE;
}

int natflow_l7_feature_set_host(struct natflow_l7_feature *feature,
        const unsigned char *host, int host_len, unsigned int host_flags)
{
	ssize_t copied_host_len;

	if (!feature || !host || host_len <= 0)
		return -EINVAL;

	copied_host_len = natflow_l7_copy_host_tolower(feature->host, host,
	                  host_len, host_flags);
	if (copied_host_len < 0)
		return -EINVAL;

	feature->host_len = copied_host_len;
	feature->host[copied_host_len] = 0;
	feature->host_flags = host_flags;
	feature->raw_host.data = host;
	feature->raw_host.len = host_len;
	feature->flags |= NATFLOW_L7_FEATURE_HOST;

	return 0;
}

int natflow_l7_feature_set_uri(struct natflow_l7_feature *feature,
        const unsigned char *uri, int uri_len)
{
	if (!feature || !uri || natflow_l7_uri_validate(uri, uri_len) < 0)
		return -EINVAL;

	feature->raw_uri.data = uri;
	feature->raw_uri.len = uri_len;
	feature->uri_len = uri_len;
	feature->flags |= NATFLOW_L7_FEATURE_URI;

	return 0;
}

int natflow_l7_host_view_init(struct natflow_l7_host_view *view,
        enum natflow_l7_feature_source source, const unsigned char *host,
        int host_len, unsigned int host_flags)
{
	if (!view || !host || host_len <= 0)
		return -EINVAL;

	memset(view, 0, sizeof(*view));
	view->source = source;
	view->http_method = NATFLOW_L7_HTTP_NONE;
	view->host.data = host;
	view->host.len = host_len;
	view->host_flags = host_flags;

	return 0;
}

int natflow_l7_host_view_from_feature(struct natflow_l7_host_view *view,
        const struct natflow_l7_feature *feature)
{
	int ret;

	if (!feature || !(feature->flags & NATFLOW_L7_FEATURE_HOST))
		return -EINVAL;

	ret = natflow_l7_host_view_init(view, feature->source, feature->host,
	                                feature->host_len, 0);
	if (ret != 0)
		return ret;

	view->http_method = feature->http_method;
	if (feature->flags & NATFLOW_L7_FEATURE_URI)
		view->uri = feature->raw_uri;

	return 0;
}

/* Simple request-line + Host header parser matching legacy URL logger behavior. */
int natflow_l7_http_parse(unsigned char *data, int data_len,
        struct natflow_l7_feature *feature)
{
	unsigned char *host = NULL;
	unsigned char *uri = NULL;
	unsigned char *p = data;
	int host_len;
	int uri_len;
	int p_len = data_len;
	unsigned int i = 0;
	enum natflow_l7_http_method http_method;

	if (!data || !feature)
		return -1;

	natflow_l7_feature_init(feature, NATFLOW_L7_SOURCE_HTTP);

	if (i + 5 > p_len)
		return -1;
	if ((p[i] == 'G' || p[i] == 'g') &&
	        (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	        (p[i + 2] == 'T' || p[i + 2] == 't') &&
	        p[i + 3] == ' ') {
		i += 4;
		http_method = NATFLOW_L7_HTTP_GET;
	} else if ((p[i] == 'P' || p[i] == 'p') &&
	           (p[i + 1] == 'O' || p[i + 1] == 'o') &&
	           (p[i + 2] == 'S' || p[i + 2] == 's') &&
	           (p[i + 3] == 'T' || p[i + 3] == 't') &&
	           p[i + 4] == ' ') {
		i += 5;
		http_method = NATFLOW_L7_HTTP_POST;
	} else if ((p[i] == 'H' || p[i] == 'h') &&
	           (p[i + 1] == 'E' || p[i + 1] == 'e') &&
	           (p[i + 2] == 'A' || p[i + 2] == 'a') &&
	           (p[i + 3] == 'D' || p[i + 3] == 'd') &&
	           p[i + 4] == ' ') {
		i += 5;
		http_method = NATFLOW_L7_HTTP_HEAD;
	} else {
		return 0;
	}

	while (i < p_len && p[i] == ' ')
		i++;
	if (i >= p_len)
		return -1;
	if (p[i] != '/')
		return -1;
	uri = p + i;

	i++;
	while (i < p_len && p[i] != ' ')
		i++;
	if (i >= p_len)
		return -1;
	if (p[i] != ' ')
		return -1;
	uri_len = p + i - uri;
	i++;

	while (i < p_len && p[i] != '\n')
		i++;
	if (i >= p_len)
		return -1;
	i++;

	do {
		if (i + 5 > p_len)
			return -1;
		if ((p[i] == 'H' || p[i] == 'h') &&
		        (p[i + 1] == 'o' || p[i + 1] == 'O') &&
		        (p[i + 2] == 's' || p[i + 2] == 'S') &&
		        (p[i + 3] == 't' || p[i + 3] == 'T') &&
		        p[i + 4] == ':') {
			i += 5;
			while (i < p_len && p[i] == ' ')
				i++;
			if (i >= p_len)
				return -1;
			host = p + i;

			i++;
			while (i < p_len && p[i] != ' ' && p[i] != '\r' && p[i] != '\n')
				i++;
			if (i >= p_len)
				return -1;
			if (p[i] != ' ' && p[i] != '\r' && p[i] != '\n')
				return -1;
			host_len = p + i - host;

			if (natflow_l7_feature_set_host(feature, host, host_len,
			                                NATFLOW_L7_HOST_ALLOW_PORT) < 0)
				return -1;
			feature->raw_uri.data = uri;
			feature->raw_uri.len = uri_len;
			feature->uri_len = uri_len;
			feature->flags |= NATFLOW_L7_FEATURE_URI;
			feature->http_method = http_method;

			return host_len + uri_len;
		}
		while (i < p_len && p[i] != '\n')
			i++;
		i++;
	} while (1);

	return 0;
}

static inline int natflow_l7_tls_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return offset <= len && bytes <= len - offset;
}

enum natflow_l7_tls_search_result natflow_l7_tls_client_hello_search(unsigned char *data,
        int *data_len, unsigned char **host)
{
	unsigned char *p = data;
	unsigned int p_len;
	unsigned int i_data_len;
	unsigned int i = 0;
	unsigned int len;

	*host = NULL;

	if (*data_len <= 0)
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;

	p_len = *data_len;
	i_data_len = p_len;

	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	if (p[i + 0] != 0x01) {
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
		goto need_more;
	len = ((unsigned int)p[i + 0] << 16) |
	      ((unsigned int)p[i + 1] << 8) |
	      ((unsigned int)p[i + 2]);
	i += 1 + 2;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	if (!natflow_l7_tls_has_bytes(i, 2 + 32, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2 + 32, i_data_len))
		goto need_more;
	i += 2 + 32;

	if (!natflow_l7_tls_has_bytes(i, 1, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		goto need_more;
	len = p[i + 0];
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 1, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		goto need_more;
	len = p[i + 0];
	i += 1;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
		goto need_more;
	i += len;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_NO_SNI;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (!natflow_l7_tls_has_bytes(i, 4, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 4, i_data_len))
			goto need_more;
		len = ntohs(get_byte2(p + i + 0 + 2));
		if (ntohs(get_byte2(p + i + 0)) != 0) {
			if (!natflow_l7_tls_has_bytes(i + 4, len, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i + 4, len, i_data_len))
				goto need_more;
			i += 4 + len;
			continue;
		}
		i += 4;
		if (!natflow_l7_tls_has_bytes(i, len, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;

		p = p + i;
		p_len = len;
		i_data_len -= i;
		i = 0;
		break;
	}
	if (i >= i_data_len && i < p_len)
		goto need_more;
	if (i >= p_len)
		return NATFLOW_L7_TLS_SEARCH_NO_SNI;

	if (!natflow_l7_tls_has_bytes(i, 2, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, p_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p = p + i;
	p_len = len;
	i_data_len -= i;
	i = 0;

	while (i < p_len && i < i_data_len) {
		if (!natflow_l7_tls_has_bytes(i, 1, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
			goto need_more;
		if (p[i + 0] != 0) {
			if (!natflow_l7_tls_has_bytes(i, 3, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
				goto need_more;
			len = ntohs(get_byte2(p + i + 0 + 1));
			if (!natflow_l7_tls_has_bytes(i + 3, len, p_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			if (!natflow_l7_tls_has_bytes(i + 3, len, i_data_len))
				goto need_more;
			i += 3 + len;
			continue;
		}
		if (!natflow_l7_tls_has_bytes(i, 3, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, 3, i_data_len))
			goto need_more;
		len = ntohs(get_byte2(p + i + 0 + 1));
		i += 3;
		if (!natflow_l7_tls_has_bytes(i, len, p_len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
		if (!natflow_l7_tls_has_bytes(i, len, i_data_len))
			goto need_more;

		*data_len = len;
		*host = p + i;
		return NATFLOW_L7_TLS_SEARCH_FOUND;
	}
	if (i >= i_data_len && i < p_len)
		goto need_more;

	return NATFLOW_L7_TLS_SEARCH_NO_SNI;

need_more:
	return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
}

enum natflow_l7_tls_search_result natflow_l7_tls_sni_search(unsigned char *data,
        int *data_len, unsigned char **host)
{
	unsigned char *p = data;
	unsigned int p_len;
	unsigned int i_data_len;
	unsigned int actual_len;
	unsigned int i = 0;
	unsigned int len;

	*host = NULL;

	if (*data_len <= 0)
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;

	p_len = *data_len;
	i_data_len = p_len;

	if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
		return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	if (p[i + 0] != 0x16) {
		return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}
	i += 1 + 2;
	if (!natflow_l7_tls_has_bytes(i, 2, i_data_len))
		goto need_more;
	len = ntohs(get_byte2(p + i + 0));
	i += 2;
	if (!natflow_l7_tls_has_bytes(i, len, i_data_len)) {
		if (!natflow_l7_tls_has_bytes(i, 1, i_data_len))
			goto need_more;
		if (p[i] != 0x01)
			return NATFLOW_L7_TLS_SEARCH_NOT_CLIENT_HELLO;
	}

	actual_len = min_t(unsigned int, len, i_data_len - i);
	if (actual_len == len && !natflow_l7_tls_has_bytes(0, 4, actual_len))
		return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	if (natflow_l7_tls_has_bytes(0, 4, actual_len)) {
		unsigned int handshake_len = ((unsigned int)p[i + 1] << 16) |
		                             ((unsigned int)p[i + 2] << 8) |
		                             ((unsigned int)p[i + 3]);

		if (!natflow_l7_tls_has_bytes(4, handshake_len, len))
			return NATFLOW_L7_TLS_SEARCH_MALFORMED;
	}

	*data_len = actual_len;
	return natflow_l7_tls_client_hello_search(p + i, data_len, host);

need_more:
	return NATFLOW_L7_TLS_SEARCH_NEED_MORE;
}

int natflow_l7_quic_has_bytes(unsigned int offset,
        unsigned int bytes, unsigned int len)
{
	return natflow_l7_has_bytes(offset, bytes, len);
}

static int natflow_l7_quic_read_varint(const unsigned char *data,
        unsigned int data_len, unsigned int *offset, u64 *value)
{
	unsigned int pos = *offset;
	unsigned int len;
	unsigned int i;

	if (!natflow_l7_quic_has_bytes(pos, 1, data_len))
		return -EINVAL;

	len = 1u << (data[pos] >> 6);
	if (!natflow_l7_quic_has_bytes(pos, len, data_len))
		return -EINVAL;

	*value = data[pos] & 0x3f;
	for (i = 1; i < len; i++)
		*value = (*value << 8) | data[pos + i];

	*offset = pos + len;
	return 0;
}

int natflow_l7_quic_initial_parse_info(const unsigned char *data,
        unsigned int data_len, struct natflow_l7_quic_initial_info *info)
{
	unsigned int offset = 0;
	unsigned int scid_len;
	u64 token_len;
	u64 packet_len;

	if (!info || !natflow_l7_quic_has_bytes(offset, 1 + 4 + 1, data_len))
		return -EINVAL;

	if ((data[offset] & 0x80) == 0 || (data[offset] & 0x40) == 0)
		return -ENOENT;
	if ((data[offset] & 0x30) != 0)
		return -ENOENT;
	offset++;

	info->version = ntohl(get_byte4(data + offset));
	offset += 4;
	if (info->version != NATFLOW_L7_QUIC_V1_VERSION)
		return -ENOENT;

	info->dcid_len = data[offset++];
	if (info->dcid_len == 0 || info->dcid_len > NATFLOW_L7_QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (!natflow_l7_quic_has_bytes(offset, info->dcid_len + 1, data_len))
		return -EINVAL;
	memcpy(info->dcid, data + offset, info->dcid_len);
	offset += info->dcid_len;

	scid_len = data[offset++];
	if (scid_len > NATFLOW_L7_QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (!natflow_l7_quic_has_bytes(offset, scid_len, data_len))
		return -EINVAL;
	offset += scid_len;

	if (natflow_l7_quic_read_varint(data, data_len, &offset, &token_len) != 0)
		return -EINVAL;
	if (token_len > UINT_MAX ||
	        !natflow_l7_quic_has_bytes(offset, (unsigned int)token_len, data_len))
		return -EINVAL;
	offset += (unsigned int)token_len;

	if (natflow_l7_quic_read_varint(data, data_len, &offset, &packet_len) != 0)
		return -EINVAL;
	if (packet_len > UINT_MAX ||
	        !natflow_l7_quic_has_bytes(offset, (unsigned int)packet_len, data_len))
		return -EINVAL;
	if (packet_len < NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN + NATFLOW_L7_QUIC_INITIAL_TAG_LEN)
		return -EINVAL;

	info->pn_offset = offset;
	info->packet_len = offset + (unsigned int)packet_len;
	if (!natflow_l7_quic_has_bytes(info->pn_offset + NATFLOW_L7_QUIC_MAX_PACKET_NUMBER_LEN,
	                               NATFLOW_L7_QUIC_HP_SAMPLE_LEN,
	                               info->packet_len))
		return -EINVAL;

	return 0;
}

static int natflow_l7_quic_crypto_data_merge(unsigned char **crypto_data,
        unsigned int *crypto_len, u64 offset,
        const unsigned char *data, unsigned int data_len)
{
	unsigned char *new_data;
	unsigned int new_len;
	unsigned int copy_offset;

	if (offset > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT ||
	        data_len > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT ||
	        offset + data_len > NATFLOW_L7_QUIC_CRYPTO_DATA_LIMIT)
		return -ENOSPC;

	if (offset > *crypto_len)
		return -EAGAIN;

	new_len = (unsigned int)offset + data_len;
	if (new_len <= *crypto_len)
		return 0;

	new_data = kmalloc(new_len, GFP_ATOMIC);
	if (new_data == NULL)
		return -ENOMEM;

	if (*crypto_data != NULL && *crypto_len > 0)
		memcpy(new_data, *crypto_data, *crypto_len);

	copy_offset = *crypto_len - (unsigned int)offset;
	memcpy(new_data + *crypto_len, data + copy_offset, data_len - copy_offset);

	kfree(*crypto_data);
	*crypto_data = new_data;
	*crypto_len = new_len;
	return 0;
}

static int natflow_l7_quic_skip_ack_frame(const unsigned char *data,
        unsigned int data_len, unsigned int *offset, unsigned char frame_type)
{
	u64 ack_range_count;
	u64 value;
	u64 i;

	if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &ack_range_count) != 0 ||
	        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
		return -EINVAL;
	}

	for (i = 0; i < ack_range_count; i++) {
		if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
			return -EINVAL;
		}
	}

	if (frame_type == 0x03) {
		if (natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0 ||
		        natflow_l7_quic_read_varint(data, data_len, offset, &value) != 0) {
			return -EINVAL;
		}
	}

	return 0;
}

enum natflow_l7_tls_search_result natflow_l7_quic_crypto_frames_search(const unsigned char *data,
        unsigned int data_len,
        unsigned char **crypto_data,
        unsigned int *crypto_len,
        unsigned char **host,
        int *host_len)
{
	enum natflow_l7_tls_search_result sni_result = NATFLOW_L7_TLS_SEARCH_NEED_MORE;
	unsigned int offset = 0;
	int has_crypto = 0;

	while (offset < data_len) {
		unsigned char frame_type = data[offset++];

		switch (frame_type) {
		case 0x00:
		case 0x01:
			break;
		case 0x02:
		case 0x03:
			if (natflow_l7_quic_skip_ack_frame(data, data_len, &offset, frame_type) != 0)
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			break;
		case 0x06: {
			u64 crypto_offset;
			u64 crypto_frame_len;
			int merge_ret;

			if (natflow_l7_quic_read_varint(data, data_len, &offset, &crypto_offset) != 0 ||
			        natflow_l7_quic_read_varint(data, data_len, &offset, &crypto_frame_len) != 0) {
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;
			}
			if (crypto_frame_len > UINT_MAX ||
			        !natflow_l7_quic_has_bytes(offset, (unsigned int)crypto_frame_len, data_len))
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;

			merge_ret = natflow_l7_quic_crypto_data_merge(crypto_data, crypto_len, crypto_offset,
			            data + offset, (unsigned int)crypto_frame_len);
			offset += (unsigned int)crypto_frame_len;
			if (merge_ret == -EAGAIN) {
				has_crypto = 1;
				continue;
			}
			if (merge_ret != 0)
				return NATFLOW_L7_TLS_SEARCH_MALFORMED;

			has_crypto = 1;
			*host_len = *crypto_len;
			sni_result = natflow_l7_tls_client_hello_search(*crypto_data, host_len, host);
			if (sni_result != NATFLOW_L7_TLS_SEARCH_NEED_MORE)
				return sni_result;
			break;
		}
		default:
			return has_crypto ? sni_result : NATFLOW_L7_TLS_SEARCH_NO_SNI;
		}
	}

	if (*crypto_data != NULL && *crypto_len > 0) {
		*host_len = *crypto_len;
		sni_result = natflow_l7_tls_client_hello_search(*crypto_data, host_len, host);
	}

	return has_crypto ? sni_result : NATFLOW_L7_TLS_SEARCH_NO_SNI;
}

int natflow_l7_dns_parse(const unsigned char *data, unsigned int data_len,
        unsigned char l4proto, struct natflow_l7_feature *feature)
{
	unsigned char host[NATFLOW_L7_HOST_MAX_LEN + 1];
	unsigned int offset;
	unsigned int qdcount;
	unsigned int host_len = 0;
	unsigned int flags;
	unsigned int msg_len;

	if (!data || !feature)
		return -EINVAL;

	natflow_l7_feature_init(feature, NATFLOW_L7_SOURCE_DNS);

	if (l4proto == IPPROTO_TCP) {
		unsigned int available;

		if (data_len < 2)
			return -EINVAL;
		msg_len = ntohs(get_byte2(data));
		if (msg_len < 12)
			return -EINVAL;
		available = data_len - 2;
		data += 2;
		data_len = msg_len < available ? msg_len : available;
	} else if (l4proto != IPPROTO_UDP) {
		return -EINVAL;
	}

	if (data_len < 12)
		return -EINVAL;

	flags = ntohs(get_byte2(data + 2));
	if (flags & 0x8000)
		return 0;
	if ((flags & 0x7800) != 0)
		return 0;
	qdcount = ntohs(get_byte2(data + 4));
	if (qdcount == 0)
		return 0;

	offset = 12;
	do {
		unsigned int label_len;

		if (!natflow_l7_has_bytes(offset, 1, data_len))
			return -EINVAL;
		label_len = data[offset++];
		if (label_len == 0)
			break;
		if ((label_len & 0xc0) != 0 || label_len > 63)
			return -EINVAL;
		if (!natflow_l7_has_bytes(offset, label_len, data_len))
			return -EINVAL;
		if (host_len != 0) {
			if (host_len >= NATFLOW_L7_HOST_MAX_LEN)
				return -EINVAL;
			host[host_len++] = '.';
		}
		if (label_len > NATFLOW_L7_HOST_MAX_LEN - host_len)
			return -EINVAL;
		memcpy(host + host_len, data + offset, label_len);
		host_len += label_len;
		offset += label_len;
	} while (offset < data_len);

	if (host_len == 0)
		return 0;
	if (!natflow_l7_has_bytes(offset, 4, data_len))
		return -EINVAL;

	if (natflow_l7_feature_set_host(feature, host, host_len, 0) < 0)
		return -EINVAL;
	feature->raw_host.data = feature->host;
	feature->raw_host.len = feature->host_len;

	return 1;
}

int natflow_l7_init(void)
{
	int ret;

	ret = natflow_ct_ext_layout_validate();
	if (ret != 0)
		return ret;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	ret = natflow_l7_tls_cache_init();
	if (ret != 0)
		return ret;

	ret = natflow_l7_quic_cache_init();
	if (ret != 0) {
		natflow_l7_tls_cache_cleanup();
		return ret;
	}

	ret = natflow_l7_quic_crypto_init();
	if (ret != 0)
		NATFLOW_WARN("QUIC hostname parser disabled, crypto init error=%d\n", ret);

	ret = natflow_l7_url_hooks_register();
	if (ret != 0) {
		natflow_l7_quic_crypto_cleanup();
		natflow_l7_quic_cache_cleanup();
		natflow_l7_tls_cache_cleanup();
		return ret;
	}
#endif

	natflow_l7_started = 1;
	return 0;
}

void natflow_l7_exit(void)
{
	if (!natflow_l7_started)
		return;

#if defined(CONFIG_NATFLOW_URLLOGGER)
	natflow_l7_url_hooks_unregister();
	natflow_l7_quic_crypto_cleanup();
	natflow_l7_quic_cache_cleanup();
	natflow_l7_tls_cache_cleanup();
#endif
	natflow_l7_started = 0;
}
