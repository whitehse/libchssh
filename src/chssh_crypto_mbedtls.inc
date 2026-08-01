/**
 * @file chssh_crypto_mbedtls.inc
 * @brief mbedTLS backend for production SSH crypto (from chssh_crypto.c).
 *
 * Pure compute only (no sockets) — safe on non-blocking CPE poll paths.
 * Supports: RSA host keys, DH group14, AES-128-CTR, HMAC-SHA2-256, SHA-256.
 * ECDH nistp256 is implemented for client/server parity with OpenSSL builds.
 */
#include "chssh_openssh_key.h"
#include "chssh.h"

#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#if defined(MBEDTLS_ED25519_C) || defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
/* ed25519 via mbedtls_pk or mbedtls_ecp — OpenWrt mbedTLS often has ED25519 */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mbedTLS 3.x exposes mbedtls_pk with MBEDTLS_PK_ECKEY and ED25519 via PSA or
 * mbedtls_pk_parse. Prefer mbedtls_pk with MBEDTLS_PK_ED25519 when available. */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN) || 1
/* use mbedtls_pk for ED25519 when MBEDTLS_PK_HAVE_ECC_KEYS */
#endif

static const char *GROUP14_P_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

struct chssh_rsa_key {
    mbedtls_pk_context pk;
};

struct chssh_ed25519_key {
    /* 32-byte seed; public derived on demand */
    uint8_t seed[32];
    uint8_t pub[32];
    int     has_pub;
};

struct chssh_dh_ctx {
    mbedtls_mpi p;
    mbedtls_mpi g;
    mbedtls_mpi priv;
    mbedtls_mpi pub;
};

struct chssh_cipher {
    mbedtls_aes_context aes;
    unsigned char key[16];
    unsigned char nonce_counter[16];
    unsigned char stream_block[16];
    size_t nc_off;
};

struct chssh_hash_ctx {
    mbedtls_sha256_context sha;
};

struct chssh_ecdh_ctx {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
};

static mbedtls_ctr_drbg_context g_drbg;
static mbedtls_entropy_context g_entropy;
static int g_drbg_ok;

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int ensure_drbg(void)
{
    if (g_drbg_ok) {
        return 0;
    }
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_drbg);
    if (mbedtls_ctr_drbg_seed(&g_drbg, mbedtls_entropy_func, &g_entropy,
                              (const unsigned char *)"chssh", 5) != 0) {
        return -1;
    }
    g_drbg_ok = 1;
    return 0;
}

static int mpi_to_mpint(const mbedtls_mpi *x, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    size_t n;
    size_t need;
    int prepend = 0;

    if (!x || !out || !out_len) {
        return -1;
    }
    n = mbedtls_mpi_size(x);
    if (n == 0) {
        if (cap < 4) {
            return -1;
        }
        put_u32(out, 0);
        *out_len = 4;
        return 0;
    }
    if (4 + n > cap) {
        return -1;
    }
    if (mbedtls_mpi_write_binary(x, out + 4, n) != 0) {
        return -1;
    }
    if (out[4] & 0x80) {
        prepend = 1;
    }
    need = 4 + n + (size_t)prepend;
    if (need > cap) {
        return -1;
    }
    if (prepend) {
        memmove(out + 5, out + 4, n);
        out[4] = 0;
        put_u32(out, (uint32_t)(n + 1));
    } else {
        put_u32(out, (uint32_t)n);
    }
    *out_len = need;
    return 0;
}

static int mpint_to_mpi(const uint8_t *p, size_t len, mbedtls_mpi *x)
{
    uint32_t n;
    if (!p || len < 4 || !x) {
        return -1;
    }
    n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
        (uint32_t)p[3];
    if ((size_t)4 + n > len) {
        return -1;
    }
    return mbedtls_mpi_read_binary(x, p + 4, n) == 0 ? 0 : -1;
}

int chssh_crypto_init(void)
{
    return ensure_drbg() == 0 ? 1 : 0;
}

const char *chssh_crypto_backend(void)
{
    return "mbedtls";
}

int chssh_crypto_random(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return -1;
    }
    if (ensure_drbg() != 0) {
        return -1;
    }
    return mbedtls_ctr_drbg_random(&g_drbg, buf, len) == 0 ? 0 : -1;
}

chssh_rsa_key_t *chssh_rsa_generate(int bits)
{
    chssh_rsa_key_t *k;
    if (bits < 2048) {
        bits = 2048;
    }
    if (ensure_drbg() != 0) {
        return NULL;
    }
    k = (chssh_rsa_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        return NULL;
    }
    mbedtls_pk_init(&k->pk);
    if (mbedtls_pk_setup(&k->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) !=
            0 ||
        mbedtls_rsa_gen_key(mbedtls_pk_rsa(k->pk), mbedtls_ctr_drbg_random,
                            &g_drbg, (unsigned)bits, 65537) != 0) {
        mbedtls_pk_free(&k->pk);
        free(k);
        return NULL;
    }
    return k;
}

chssh_rsa_key_t *chssh_rsa_load_pem(const char *path)
{
    uint8_t *data = NULL;
    size_t len = 0;
    chssh_rsa_key_t *k;
    if (chssh_read_file(path, &data, &len) != 0) {
        return NULL;
    }
    k = chssh_rsa_load_pem_mem(data, len);
    free(data);
    return k;
}

chssh_rsa_key_t *chssh_rsa_load_pem_mem(const void *pem, size_t pem_len)
{
    chssh_rsa_key_t *k;
    if (!pem || pem_len == 0 || ensure_drbg() != 0) {
        return NULL;
    }
    /* Encrypted PEM heuristic */
    if (strstr((const char *)pem, "ENCRYPTED") != NULL ||
        strstr((const char *)pem, "Proc-Type:") != NULL) {
        return NULL;
    }
    k = (chssh_rsa_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        return NULL;
    }
    mbedtls_pk_init(&k->pk);
    if (mbedtls_pk_parse_key(&k->pk, (const unsigned char *)pem, pem_len + 1,
                             NULL, 0, mbedtls_ctr_drbg_random, &g_drbg) != 0 ||
        !mbedtls_pk_can_do(&k->pk, MBEDTLS_PK_RSA)) {
        /* try without requiring NUL beyond pem_len */
        mbedtls_pk_free(&k->pk);
        mbedtls_pk_init(&k->pk);
        if (mbedtls_pk_parse_key(&k->pk, (const unsigned char *)pem, pem_len,
                                 NULL, 0, mbedtls_ctr_drbg_random,
                                 &g_drbg) != 0 ||
            !mbedtls_pk_can_do(&k->pk, MBEDTLS_PK_RSA)) {
            mbedtls_pk_free(&k->pk);
            free(k);
            return NULL;
        }
    }
    return k;
}

static chssh_rsa_key_t *rsa_from_openssh_decoded(const chssh_openssh_decoded_t *d)
{
    chssh_rsa_key_t *k;
    mbedtls_mpi N, E, D, P, Q;
    if (!d || d->alg != CHSSH_PUBKEY_ALG_SSH_RSA || ensure_drbg() != 0) {
        return NULL;
    }
    k = (chssh_rsa_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        return NULL;
    }
    mbedtls_pk_init(&k->pk);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    if (mbedtls_mpi_read_binary(&N, d->rsa_n, d->rsa_n_len) != 0 ||
        mbedtls_mpi_read_binary(&E, d->rsa_e, d->rsa_e_len) != 0 ||
        mbedtls_mpi_read_binary(&D, d->rsa_d, d->rsa_d_len) != 0 ||
        mbedtls_mpi_read_binary(&P, d->rsa_p, d->rsa_p_len) != 0 ||
        mbedtls_mpi_read_binary(&Q, d->rsa_q, d->rsa_q_len) != 0 ||
        mbedtls_pk_setup(&k->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) !=
            0 ||
        mbedtls_rsa_import(mbedtls_pk_rsa(k->pk), &N, &P, &Q, &D, &E) != 0 ||
        mbedtls_rsa_complete(mbedtls_pk_rsa(k->pk)) != 0) {
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        mbedtls_mpi_free(&D);
        mbedtls_mpi_free(&P);
        mbedtls_mpi_free(&Q);
        mbedtls_pk_free(&k->pk);
        free(k);
        return NULL;
    }
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    return k;
}

chssh_rsa_key_t *chssh_rsa_load_openssh_mem(const void *pem, size_t pem_len)
{
    chssh_openssh_decoded_t d;
    chssh_rsa_key_t *k;
    if (chssh_openssh_decode_pem((const char *)pem, pem_len, &d) != 0) {
        return NULL;
    }
    k = rsa_from_openssh_decoded(&d);
    chssh_openssh_decoded_clear(&d);
    return k;
}

chssh_rsa_key_t *chssh_rsa_load_openssh(const char *path)
{
    uint8_t *data = NULL;
    size_t len = 0;
    chssh_rsa_key_t *k;
    if (chssh_read_file(path, &data, &len) != 0) {
        return NULL;
    }
    k = chssh_rsa_load_openssh_mem(data, len);
    free(data);
    return k;
}

void chssh_rsa_free(chssh_rsa_key_t *k)
{
    if (!k) {
        return;
    }
    mbedtls_pk_free(&k->pk);
    free(k);
}

/* Portable ed25519 (orlp/ed25519, public domain) for mbedTLS CPE builds. */
#include "ed25519.h"

chssh_ed25519_key_t *chssh_ed25519_generate(void)
{
    chssh_ed25519_key_t *k;
    uint8_t sk[64];
    if (ensure_drbg() != 0) {
        return NULL;
    }
    k = (chssh_ed25519_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        return NULL;
    }
    if (mbedtls_ctr_drbg_random(&g_drbg, k->seed, 32) != 0) {
        free(k);
        return NULL;
    }
    ed25519_create_keypair(k->pub, sk, k->seed);
    /* sk = seed||pub; keep seed only */
    memset(sk, 0, sizeof(sk));
    k->has_pub = 1;
    return k;
}

chssh_ed25519_key_t *chssh_ed25519_load_openssh_mem(const void *pem,
                                                    size_t pem_len)
{
    chssh_openssh_decoded_t d;
    chssh_ed25519_key_t *k;
    if (chssh_openssh_decode_pem((const char *)pem, pem_len, &d) != 0) {
        return NULL;
    }
    if (d.alg != CHSSH_PUBKEY_ALG_SSH_ED25519) {
        chssh_openssh_decoded_clear(&d);
        return NULL;
    }
    k = (chssh_ed25519_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        chssh_openssh_decoded_clear(&d);
        return NULL;
    }
    memcpy(k->seed, d.ed_seed, 32);
    memcpy(k->pub, d.ed_pub, 32);
    k->has_pub = 1;
    chssh_openssh_decoded_clear(&d);
    return k;
}

chssh_ed25519_key_t *chssh_ed25519_load_openssh(const char *path)
{
    uint8_t *data = NULL;
    size_t len = 0;
    chssh_ed25519_key_t *k;
    if (chssh_read_file(path, &data, &len) != 0) {
        return NULL;
    }
    k = chssh_ed25519_load_openssh_mem(data, len);
    free(data);
    return k;
}

void chssh_ed25519_free(chssh_ed25519_key_t *k)
{
    if (!k) {
        return;
    }
    memset(k->seed, 0, sizeof(k->seed));
    free(k);
}

int chssh_ed25519_public_blob(const chssh_ed25519_key_t *k, uint8_t *out,
                              size_t cap, size_t *out_len)
{
    if (!k || !k->has_pub || !out || !out_len) {
        return -1;
    }
    return chssh_pubkey_blob_encode_ed25519(k->pub, out, cap, out_len);
}

int chssh_ed25519_sign(const chssh_ed25519_key_t *k, const uint8_t *msg,
                       size_t msg_len, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    uint8_t sk[64];
    uint8_t pk[32];
    uint8_t sig[64];
    size_t off = 0;
    const char *alg = "ssh-ed25519";
    if (!k || !msg || !out || !out_len) {
        return -1;
    }
    /*
     * orlp private_key is SHA512(seed) (64 bytes, first half clamped),
     * NOT OpenSSH seed||pub. Expand seed via create_keypair.
     */
    ed25519_create_keypair(pk, sk, k->seed);
    if (k->has_pub && memcmp(pk, k->pub, 32) != 0) {
        memset(sk, 0, sizeof(sk));
        return -1;
    }
    ed25519_sign(sig, msg, msg_len, pk, sk);
    memset(sk, 0, sizeof(sk));
    if (4 + 11 + 4 + 64 > cap) {
        return -1;
    }
    put_u32(out + off, 11);
    off += 4;
    memcpy(out + off, alg, 11);
    off += 11;
    put_u32(out + off, 64);
    off += 4;
    memcpy(out + off, sig, 64);
    off += 64;
    *out_len = off;
    return 0;
}

int chssh_ed25519_verify(const uint8_t *pubkey_blob, size_t blob_len,
                         const uint8_t *sig_blob, size_t sig_len,
                         const uint8_t *msg, size_t msg_len)
{
    chssh_pubkey_alg_t alg;
    uint32_t tlen, slen, rawlen;
    size_t off;
    const uint8_t *raw_pk;
    const uint8_t *raw_sig;

    if (!pubkey_blob || !sig_blob || !msg) {
        return -1;
    }
    if (chssh_pubkey_blob_parse(pubkey_blob, blob_len, &alg) != 0 ||
        alg != CHSSH_PUBKEY_ALG_SSH_ED25519) {
        return -1;
    }
    tlen = ((uint32_t)pubkey_blob[0] << 24) | ((uint32_t)pubkey_blob[1] << 16) |
           ((uint32_t)pubkey_blob[2] << 8) | (uint32_t)pubkey_blob[3];
    off = 4 + tlen;
    if (off + 4 > blob_len) {
        return -1;
    }
    slen = ((uint32_t)pubkey_blob[off] << 24) |
           ((uint32_t)pubkey_blob[off + 1] << 16) |
           ((uint32_t)pubkey_blob[off + 2] << 8) |
           (uint32_t)pubkey_blob[off + 3];
    off += 4;
    if (slen != 32 || off + 32 > blob_len) {
        return -1;
    }
    raw_pk = pubkey_blob + off;
    if (sig_len < 19 + 64) {
        return -1;
    }
    tlen = ((uint32_t)sig_blob[0] << 24) | ((uint32_t)sig_blob[1] << 16) |
           ((uint32_t)sig_blob[2] << 8) | (uint32_t)sig_blob[3];
    if (tlen != 11 || memcmp(sig_blob + 4, "ssh-ed25519", 11) != 0) {
        return -1;
    }
    rawlen = ((uint32_t)sig_blob[15] << 24) | ((uint32_t)sig_blob[16] << 16) |
             ((uint32_t)sig_blob[17] << 8) | (uint32_t)sig_blob[18];
    if (rawlen != 64) {
        return -1;
    }
    raw_sig = sig_blob + 19;
    if (ed25519_verify(raw_sig, msg, msg_len, raw_pk) != 1) {
        return -1;
    }
    return 0;
}

int chssh_rsa_public_blob(const chssh_rsa_key_t *k, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    mbedtls_mpi N, E;
    size_t off = 0;
    size_t ml;
    const char *t = "ssh-rsa";
    mbedtls_pk_context *pk;

    if (!k || !out || !out_len) {
        return -1;
    }
    pk = (mbedtls_pk_context *)&k->pk;
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&E);
    if (mbedtls_rsa_export(mbedtls_pk_rsa(*pk), &N, NULL, NULL, NULL, &E) != 0) {
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        return -1;
    }
    if (4 + 7 + 8 + mbedtls_mpi_size(&E) + mbedtls_mpi_size(&N) + 2 > cap) {
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        return -1;
    }
    put_u32(out + off, 7);
    off += 4;
    memcpy(out + off, t, 7);
    off += 7;
    if (mpi_to_mpint(&E, out + off, cap - off, &ml) != 0) {
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        return -1;
    }
    off += ml;
    if (mpi_to_mpint(&N, out + off, cap - off, &ml) != 0) {
        mbedtls_mpi_free(&N);
        mbedtls_mpi_free(&E);
        return -1;
    }
    off += ml;
    *out_len = off;
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&E);
    return 0;
}

int chssh_rsa_sign(const chssh_rsa_key_t *k, const char *sig_alg,
                   const uint8_t *msg, size_t msg_len, uint8_t *out, size_t cap,
                   size_t *out_len)
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char digest[32];
    size_t dig_len;
    size_t siglen = 0;
    size_t alglen;
    size_t off = 0;
    mbedtls_md_type_t md;
    const mbedtls_md_info_t *info;
    mbedtls_pk_context *pk;

    if (!k || !sig_alg || !msg || !out || !out_len || ensure_drbg() != 0) {
        return -1;
    }
    if (strcmp(sig_alg, "rsa-sha2-256") == 0) {
        md = MBEDTLS_MD_SHA256;
        dig_len = 32;
    } else if (strcmp(sig_alg, "ssh-rsa") == 0) {
        md = MBEDTLS_MD_SHA1;
        dig_len = 20;
    } else {
        return -1;
    }
    info = mbedtls_md_info_from_type(md);
    if (!info || mbedtls_md(info, msg, msg_len, digest) != 0) {
        return -1;
    }
    pk = (mbedtls_pk_context *)&k->pk;
    if (mbedtls_pk_sign(pk, md, digest, dig_len, sig, sizeof(sig), &siglen,
                        mbedtls_ctr_drbg_random, &g_drbg) != 0) {
        return -1;
    }
    alglen = strlen(sig_alg);
    if (4 + alglen + 4 + siglen > cap) {
        return -1;
    }
    put_u32(out + off, (uint32_t)alglen);
    off += 4;
    memcpy(out + off, sig_alg, alglen);
    off += alglen;
    put_u32(out + off, (uint32_t)siglen);
    off += 4;
    memcpy(out + off, sig, siglen);
    off += siglen;
    *out_len = off;
    return 0;
}

int chssh_rsa_verify(const uint8_t *host_key_blob, size_t hk_len,
                     const uint8_t *sig_blob, size_t sig_len,
                     const uint8_t *msg, size_t msg_len)
{
    uint32_t n;
    size_t off = 0;
    mbedtls_mpi bn_e, bn_n;
    mbedtls_pk_context pk;
    uint32_t alglen, rawlen;
    const unsigned char *alg;
    const unsigned char *raw;
    mbedtls_md_type_t md;
    unsigned char digest[32];
    size_t dig_len;
    const mbedtls_md_info_t *info;
    int rc = -1;

    if (!host_key_blob || hk_len < 12 || !sig_blob || sig_len < 8 || !msg) {
        return -1;
    }
    n = ((uint32_t)host_key_blob[0] << 24) | ((uint32_t)host_key_blob[1] << 16) |
        ((uint32_t)host_key_blob[2] << 8) | (uint32_t)host_key_blob[3];
    off = 4;
    if (off + n > hk_len || n != 7 ||
        memcmp(host_key_blob + off, "ssh-rsa", 7) != 0) {
        return -1;
    }
    off += n;
    mbedtls_mpi_init(&bn_e);
    mbedtls_mpi_init(&bn_n);
    mbedtls_pk_init(&pk);
    if (mpint_to_mpi(host_key_blob + off, hk_len - off, &bn_e) != 0) {
        goto done;
    }
    {
        uint32_t elen = ((uint32_t)host_key_blob[off] << 24) |
                        ((uint32_t)host_key_blob[off + 1] << 16) |
                        ((uint32_t)host_key_blob[off + 2] << 8) |
                        (uint32_t)host_key_blob[off + 3];
        off += 4 + elen;
    }
    if (mpint_to_mpi(host_key_blob + off, hk_len - off, &bn_n) != 0) {
        goto done;
    }
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0 ||
        mbedtls_rsa_import(mbedtls_pk_rsa(pk), &bn_n, NULL, NULL, NULL, &bn_e) !=
            0 ||
        mbedtls_rsa_complete(mbedtls_pk_rsa(pk)) != 0) {
        goto done;
    }
    alglen = ((uint32_t)sig_blob[0] << 24) | ((uint32_t)sig_blob[1] << 16) |
             ((uint32_t)sig_blob[2] << 8) | (uint32_t)sig_blob[3];
    if (4 + alglen + 4 > sig_len) {
        goto done;
    }
    alg = sig_blob + 4;
    rawlen = ((uint32_t)sig_blob[4 + alglen] << 24) |
             ((uint32_t)sig_blob[5 + alglen] << 16) |
             ((uint32_t)sig_blob[6 + alglen] << 8) |
             (uint32_t)sig_blob[7 + alglen];
    raw = sig_blob + 8 + alglen;
    if (8 + alglen + rawlen > sig_len) {
        goto done;
    }
    if (alglen == 12 && memcmp(alg, "rsa-sha2-256", 12) == 0) {
        md = MBEDTLS_MD_SHA256;
        dig_len = 32;
    } else if (alglen == 7 && memcmp(alg, "ssh-rsa", 7) == 0) {
        md = MBEDTLS_MD_SHA1;
        dig_len = 20;
    } else {
        goto done;
    }
    info = mbedtls_md_info_from_type(md);
    if (!info || mbedtls_md(info, msg, msg_len, digest) != 0) {
        goto done;
    }
    if (mbedtls_pk_verify(&pk, md, digest, dig_len, raw, rawlen) == 0) {
        rc = 0;
    }
done:
    mbedtls_pk_free(&pk);
    mbedtls_mpi_free(&bn_e);
    mbedtls_mpi_free(&bn_n);
    return rc;
}

chssh_dh_ctx_t *chssh_dh_new(void)
{
    chssh_dh_ctx_t *dh = (chssh_dh_ctx_t *)calloc(1, sizeof(*dh));
    if (!dh) {
        return NULL;
    }
    mbedtls_mpi_init(&dh->p);
    mbedtls_mpi_init(&dh->g);
    mbedtls_mpi_init(&dh->priv);
    mbedtls_mpi_init(&dh->pub);
    if (mbedtls_mpi_read_string(&dh->p, 16, GROUP14_P_HEX) != 0 ||
        mbedtls_mpi_lset(&dh->g, 2) != 0) {
        chssh_dh_free(dh);
        return NULL;
    }
    return dh;
}

void chssh_dh_free(chssh_dh_ctx_t *dh)
{
    if (!dh) {
        return;
    }
    mbedtls_mpi_free(&dh->p);
    mbedtls_mpi_free(&dh->g);
    mbedtls_mpi_free(&dh->priv);
    mbedtls_mpi_free(&dh->pub);
    free(dh);
}

int chssh_dh_gen_public(chssh_dh_ctx_t *dh, uint8_t *pub, size_t cap,
                        size_t *pub_len)
{
    unsigned char rnd[32];
    mbedtls_mpi RP;
    if (!dh || !pub || !pub_len || ensure_drbg() != 0) {
        return -1;
    }
    if (chssh_crypto_random(rnd, sizeof(rnd)) != 0 ||
        mbedtls_mpi_read_binary(&dh->priv, rnd, sizeof(rnd)) != 0) {
        return -1;
    }
    mbedtls_mpi_init(&RP);
    if (mbedtls_mpi_exp_mod(&dh->pub, &dh->g, &dh->priv, &dh->p, &RP) != 0) {
        mbedtls_mpi_free(&RP);
        return -1;
    }
    mbedtls_mpi_free(&RP);
    return mpi_to_mpint(&dh->pub, pub, cap, pub_len);
}

int chssh_dh_compute(chssh_dh_ctx_t *dh, const uint8_t *peer_pub,
                     size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    mbedtls_mpi peer;
    mbedtls_mpi shared;
    mbedtls_mpi RP;
    int rc = -1;
    if (!dh || !peer_pub || !K || !K_len) {
        return -1;
    }
    mbedtls_mpi_init(&peer);
    mbedtls_mpi_init(&shared);
    mbedtls_mpi_init(&RP);
    if (mpint_to_mpi(peer_pub, peer_len, &peer) != 0) {
        goto done;
    }
    if (mbedtls_mpi_exp_mod(&shared, &peer, &dh->priv, &dh->p, &RP) != 0) {
        goto done;
    }
    rc = mpi_to_mpint(&shared, K, cap, K_len);
done:
    mbedtls_mpi_free(&peer);
    mbedtls_mpi_free(&shared);
    mbedtls_mpi_free(&RP);
    return rc;
}

chssh_ecdh_ctx_t *chssh_ecdh_p256_new(void)
{
    chssh_ecdh_ctx_t *e = (chssh_ecdh_ctx_t *)calloc(1, sizeof(*e));
    if (!e) {
        return NULL;
    }
    mbedtls_ecp_group_init(&e->grp);
    mbedtls_mpi_init(&e->d);
    mbedtls_ecp_point_init(&e->Q);
    mbedtls_ctr_drbg_init(&e->drbg);
    mbedtls_entropy_init(&e->entropy);
    if (mbedtls_ctr_drbg_seed(&e->drbg, mbedtls_entropy_func, &e->entropy,
                              (const unsigned char *)"chssh-ecdh", 10) != 0 ||
        mbedtls_ecp_group_load(&e->grp, MBEDTLS_ECP_DP_SECP256R1) != 0 ||
        mbedtls_ecp_gen_keypair(&e->grp, &e->d, &e->Q, mbedtls_ctr_drbg_random,
                                &e->drbg) != 0) {
        chssh_ecdh_free(e);
        return NULL;
    }
    return e;
}

void chssh_ecdh_free(chssh_ecdh_ctx_t *e)
{
    if (!e) {
        return;
    }
    mbedtls_ecp_group_free(&e->grp);
    mbedtls_mpi_free(&e->d);
    mbedtls_ecp_point_free(&e->Q);
    mbedtls_ctr_drbg_free(&e->drbg);
    mbedtls_entropy_free(&e->entropy);
    free(e);
}

int chssh_ecdh_public_string(chssh_ecdh_ctx_t *e, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    unsigned char buf[128];
    size_t olen = 0;
    if (!e || !out || !out_len) {
        return -1;
    }
    if (mbedtls_ecp_point_write_binary(&e->grp, &e->Q,
                                       MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf,
                                       sizeof(buf)) != 0 ||
        4 + olen > cap) {
        return -1;
    }
    put_u32(out, (uint32_t)olen);
    memcpy(out + 4, buf, olen);
    *out_len = 4 + olen;
    return 0;
}

int chssh_ecdh_compute(chssh_ecdh_ctx_t *e, const uint8_t *peer_q_str,
                       size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    uint32_t qlen;
    const uint8_t *q;
    mbedtls_ecp_point peer;
    mbedtls_mpi z;
    int rc = -1;
    if (!e || !peer_q_str || peer_len < 5 || !K || !K_len) {
        return -1;
    }
    qlen = ((uint32_t)peer_q_str[0] << 24) | ((uint32_t)peer_q_str[1] << 16) |
           ((uint32_t)peer_q_str[2] << 8) | (uint32_t)peer_q_str[3];
    if (4u + qlen > peer_len) {
        return -1;
    }
    q = peer_q_str + 4;
    mbedtls_ecp_point_init(&peer);
    mbedtls_mpi_init(&z);
    if (mbedtls_ecp_point_read_binary(&e->grp, &peer, q, qlen) != 0) {
        goto done;
    }
    if (mbedtls_ecdh_compute_shared(&e->grp, &z, &peer, &e->d,
                                    mbedtls_ctr_drbg_random, &e->drbg) != 0) {
        goto done;
    }
    rc = mpi_to_mpint(&z, K, cap, K_len);
done:
    mbedtls_ecp_point_free(&peer);
    mbedtls_mpi_free(&z);
    return rc;
}

int chssh_sha256(const uint8_t *data, size_t len, uint8_t out[CHSSH_HASH_LEN])
{
    if (!out) {
        return -1;
    }
    return mbedtls_sha256(data, len, out, 0) == 0 ? 0 : -1;
}

chssh_hash_ctx_t *chssh_hash_new(void)
{
    chssh_hash_ctx_t *h = (chssh_hash_ctx_t *)calloc(1, sizeof(*h));
    if (!h) {
        return NULL;
    }
    mbedtls_sha256_init(&h->sha);
    if (mbedtls_sha256_starts(&h->sha, 0) != 0) {
        free(h);
        return NULL;
    }
    return h;
}

void chssh_hash_free(chssh_hash_ctx_t *h)
{
    if (!h) {
        return;
    }
    mbedtls_sha256_free(&h->sha);
    free(h);
}

int chssh_hash_update(chssh_hash_ctx_t *h, const uint8_t *data, size_t len)
{
    if (!h) {
        return -1;
    }
    return mbedtls_sha256_update(&h->sha, data, len) == 0 ? 0 : -1;
}

int chssh_hash_update_string(chssh_hash_ctx_t *h, const uint8_t *data,
                             size_t len)
{
    uint8_t hdr[4];
    if (!h) {
        return -1;
    }
    put_u32(hdr, (uint32_t)len);
    if (chssh_hash_update(h, hdr, 4) != 0) {
        return -1;
    }
    if (len > 0 && data) {
        return chssh_hash_update(h, data, len);
    }
    return 0;
}

int chssh_hash_update_cstring(chssh_hash_ctx_t *h, const char *s)
{
    if (!s) {
        s = "";
    }
    return chssh_hash_update_string(h, (const uint8_t *)s, strlen(s));
}

int chssh_hash_final(chssh_hash_ctx_t *h, uint8_t out[CHSSH_HASH_LEN])
{
    if (!h || !out) {
        return -1;
    }
    return mbedtls_sha256_finish(&h->sha, out) == 0 ? 0 : -1;
}

static int derive_one_ssh(const uint8_t *K, size_t K_len, const uint8_t *H,
                          char letter, const uint8_t *session_id,
                          size_t session_id_len, uint8_t *out, size_t out_len)
{
    /* Match OpenSSL backend: HASH(K||H||X||session_id), then HASH(K||H||prev). */
    uint8_t buf[CHSSH_HASH_LEN];
    uint8_t letter_b = (uint8_t)letter;
    chssh_hash_ctx_t *h = chssh_hash_new();
    size_t got = 0;

    if (!h) {
        return -1;
    }
    if (chssh_hash_update(h, K, K_len) != 0 ||
        chssh_hash_update(h, H, CHSSH_HASH_LEN) != 0 ||
        chssh_hash_update(h, &letter_b, 1) != 0 ||
        chssh_hash_update(h, session_id, session_id_len) != 0 ||
        chssh_hash_final(h, buf) != 0) {
        chssh_hash_free(h);
        return -1;
    }
    chssh_hash_free(h);
    while (got < out_len) {
        size_t take = out_len - got;
        if (take > CHSSH_HASH_LEN) {
            take = CHSSH_HASH_LEN;
        }
        memcpy(out + got, buf, take);
        got += take;
        if (got < out_len) {
            uint8_t next[CHSSH_HASH_LEN];
            h = chssh_hash_new();
            if (!h || chssh_hash_update(h, K, K_len) != 0 ||
                chssh_hash_update(h, H, CHSSH_HASH_LEN) != 0 ||
                chssh_hash_update(h, out, got) != 0 ||
                chssh_hash_final(h, next) != 0) {
                chssh_hash_free(h);
                return -1;
            }
            chssh_hash_free(h);
            memcpy(buf, next, CHSSH_HASH_LEN);
        }
    }
    return 0;
}

int chssh_derive_keys(const uint8_t *K, size_t K_len, const uint8_t *H,
                      const uint8_t *session_id, size_t session_id_len,
                      uint8_t iv_c2s[CHSSH_AES_IV_LEN],
                      uint8_t iv_s2c[CHSSH_AES_IV_LEN],
                      uint8_t key_c2s[CHSSH_AES_KEY_LEN],
                      uint8_t key_s2c[CHSSH_AES_KEY_LEN],
                      uint8_t mac_c2s[CHSSH_MAC_KEY_LEN],
                      uint8_t mac_s2c[CHSSH_MAC_KEY_LEN])
{
    if (derive_one_ssh(K, K_len, H, 'A', session_id, session_id_len, iv_c2s,
                       CHSSH_AES_IV_LEN) != 0 ||
        derive_one_ssh(K, K_len, H, 'B', session_id, session_id_len, iv_s2c,
                       CHSSH_AES_IV_LEN) != 0 ||
        derive_one_ssh(K, K_len, H, 'C', session_id, session_id_len, key_c2s,
                       CHSSH_AES_KEY_LEN) != 0 ||
        derive_one_ssh(K, K_len, H, 'D', session_id, session_id_len, key_s2c,
                       CHSSH_AES_KEY_LEN) != 0 ||
        derive_one_ssh(K, K_len, H, 'E', session_id, session_id_len, mac_c2s,
                       CHSSH_MAC_KEY_LEN) != 0 ||
        derive_one_ssh(K, K_len, H, 'F', session_id, session_id_len, mac_s2c,
                       CHSSH_MAC_KEY_LEN) != 0) {
        return -1;
    }
    return 0;
}

chssh_cipher_t *chssh_cipher_new(const uint8_t key[CHSSH_AES_KEY_LEN],
                                 const uint8_t iv[CHSSH_AES_IV_LEN],
                                 int encrypt)
{
    chssh_cipher_t *c = (chssh_cipher_t *)calloc(1, sizeof(*c));
    (void)encrypt;
    if (!c) {
        return NULL;
    }
    mbedtls_aes_init(&c->aes);
    memcpy(c->key, key, 16);
    if (mbedtls_aes_setkey_enc(&c->aes, c->key, 128) != 0) {
        free(c);
        return NULL;
    }
    memcpy(c->nonce_counter, iv, 16);
    c->nc_off = 0;
    return c;
}

chssh_cipher_t *chssh_cipher_dup(const chssh_cipher_t *c)
{
    chssh_cipher_t *n;
    if (!c) {
        return NULL;
    }
    n = chssh_cipher_new(c->key, c->nonce_counter, 1);
    if (!n) {
        return NULL;
    }
    memcpy(n->nonce_counter, c->nonce_counter, 16);
    memcpy(n->stream_block, c->stream_block, 16);
    n->nc_off = c->nc_off;
    return n;
}

void chssh_cipher_free(chssh_cipher_t *c)
{
    if (!c) {
        return;
    }
    mbedtls_aes_free(&c->aes);
    free(c);
}

int chssh_cipher_crypt(chssh_cipher_t *c, uint8_t *data, size_t len)
{
    if (!c || !data) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    return mbedtls_aes_crypt_ctr(&c->aes, len, &c->nc_off, c->nonce_counter,
                                 c->stream_block, data, data) == 0
               ? 0
               : -1;
}

int chssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                      size_t data_len, uint8_t out[CHSSH_MAC_LEN])
{
    const mbedtls_md_info_t *info;
    if (!key || !out) {
        return -1;
    }
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info) {
        return -1;
    }
    return mbedtls_md_hmac(info, key, key_len, data, data_len, out) == 0 ? 0
                                                                        : -1;
}
