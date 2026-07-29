/**
 * @file chssh_crypto.c
 * @brief OpenSSL crypto for production SSH Call Home.
 */

#include "chssh_crypto.h"

#if HAVE_OPENSSL

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* RFC 3526 2048-bit MODP Group 14 */
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
    EVP_PKEY *pkey;
};

struct chssh_dh_ctx {
    BIGNUM *p;
    BIGNUM *g;
    BIGNUM *priv;
    BIGNUM *pub;
};

struct chssh_cipher {
    EVP_CIPHER_CTX *ctx;
};

struct chssh_hash_ctx {
    EVP_MD_CTX *md;
};

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int bn_to_mpint(const BIGNUM *bn, uint8_t *out, size_t cap, size_t *out_len)
{
    int n;
    size_t need;
    if (!bn || !out || !out_len) {
        return -1;
    }
    n = BN_num_bytes(bn);
    if (n < 0) {
        return -1;
    }
    /* If high bit set, prepend 0x00 per SSH mpint */
    {
        int prepend = 0;
        if (n > 0) {
            unsigned char first;
            unsigned char *tmp = (unsigned char *)OPENSSL_malloc((size_t)n);
            if (!tmp) {
                return -1;
            }
            BN_bn2bin(bn, tmp);
            first = tmp[0];
            OPENSSL_free(tmp);
            if (first & 0x80) {
                prepend = 1;
            }
        }
        need = 4 + (size_t)n + (size_t)prepend;
        if (need > cap) {
            return -1;
        }
        put_u32(out, (uint32_t)(n + prepend));
        if (prepend) {
            out[4] = 0;
            BN_bn2bin(bn, out + 5);
        } else if (n > 0) {
            BN_bn2bin(bn, out + 4);
        }
        *out_len = need;
    }
    return 0;
}

static BIGNUM *mpint_to_bn(const uint8_t *p, size_t len)
{
    uint32_t n;
    if (len < 4) {
        return NULL;
    }
    n = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
        (uint32_t)p[3];
    if (4 + n > len) {
        return NULL;
    }
    return BN_bin2bn(p + 4, (int)n, NULL);
}

int chssh_crypto_init(void)
{
    return 1;
}

int chssh_crypto_random(uint8_t *buf, size_t len)
{
    if (!buf || len == 0) {
        return -1;
    }
    return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}

chssh_rsa_key_t *chssh_rsa_generate(int bits)
{
    chssh_rsa_key_t *k;
    EVP_PKEY_CTX *pctx = NULL; (void)pctx;
    EVP_PKEY *pkey = NULL;

    if (bits < 2048) {
        bits = 2048;
    }
    k = (chssh_rsa_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        return NULL;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, bits) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        free(k);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    k->pkey = pkey;
    return k;
}

chssh_rsa_key_t *chssh_rsa_load_pem(const char *path)
{
    FILE *f;
    chssh_rsa_key_t *k;
    EVP_PKEY *pkey;

    if (!path || !path[0]) {
        return NULL;
    }
    f = fopen(path, "r");
    if (!f) {
        return NULL;
    }
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    k = (chssh_rsa_key_t *)calloc(1, sizeof(*k));
    if (!k) {
        EVP_PKEY_free(pkey);
        return NULL;
    }
    k->pkey = pkey;
    return k;
}

void chssh_rsa_free(chssh_rsa_key_t *k)
{
    if (!k) {
        return;
    }
    EVP_PKEY_free(k->pkey);
    free(k);
}

int chssh_rsa_public_blob(const chssh_rsa_key_t *k, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    BIGNUM *n = NULL, *e = NULL;
    size_t off = 0;
    size_t ml;
    const char *t = "ssh-rsa";
    size_t tl = 7;

    if (!k || !k->pkey || !out || !out_len) {
        return -1;
    }
    if (EVP_PKEY_get_bn_param(k->pkey, "n", &n) != 1 ||
        EVP_PKEY_get_bn_param(k->pkey, "e", &e) != 1) {
        BN_free(n);
        BN_free(e);
        return -1;
    }
    if (off + 4 + tl > cap) {
        BN_free(n);
        BN_free(e);
        return -1;
    }
    put_u32(out + off, (uint32_t)tl);
    off += 4;
    memcpy(out + off, t, tl);
    off += tl;
    if (bn_to_mpint(e, out + off, cap - off, &ml) != 0) {
        BN_free(n);
        BN_free(e);
        return -1;
    }
    off += ml;
    if (bn_to_mpint(n, out + off, cap - off, &ml) != 0) {
        BN_free(n);
        BN_free(e);
        return -1;
    }
    off += ml;
    BN_free(n);
    BN_free(e);
    *out_len = off;
    return 0;
}

int chssh_rsa_sign(const chssh_rsa_key_t *k, const char *sig_alg,
                   const uint8_t *H, size_t H_len, uint8_t *out, size_t cap,
                   size_t *out_len)
{
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md;
    uint8_t sig[512];
    size_t siglen = sizeof(sig);
    size_t alglen;
    size_t off = 0;

    if (!k || !k->pkey || !sig_alg || !H || !out || !out_len) {
        return -1;
    }
    if (strcmp(sig_alg, "rsa-sha2-256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(sig_alg, "ssh-rsa") == 0) {
        md = EVP_sha1();
    } else {
        return -1;
    }
    alglen = strlen(sig_alg);
    mdctx = EVP_MD_CTX_new();
    if (!mdctx || EVP_DigestSignInit(mdctx, NULL, md, NULL, k->pkey) <= 0 ||
        EVP_DigestSign(mdctx, sig, &siglen, H, H_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);
    /* string alg || string sig */
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
                     const uint8_t *H, size_t H_len)
{
    /* Parse host key: string "ssh-rsa" || mpint e || mpint n */
    uint32_t n;
    size_t off = 0;
    BIGNUM *bn_e = NULL, *bn_n = NULL;
    EVP_PKEY *pkey = NULL;
    uint32_t alglen, rawlen;
    const char *alg;
    const uint8_t *raw;
    const EVP_MD *md;
    EVP_MD_CTX *mdctx = NULL;
    int ok = -1;

    if (!host_key_blob || hk_len < 12 || !sig_blob || sig_len < 8 || !H) {
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
    bn_e = mpint_to_bn(host_key_blob + off, hk_len - off);
    if (!bn_e) {
        return -1;
    }
    {
        uint32_t elen = ((uint32_t)host_key_blob[off] << 24) |
                        ((uint32_t)host_key_blob[off + 1] << 16) |
                        ((uint32_t)host_key_blob[off + 2] << 8) |
                        (uint32_t)host_key_blob[off + 3];
        off += 4 + elen;
    }
    bn_n = mpint_to_bn(host_key_blob + off, hk_len - off);
    if (!bn_n) {
        BN_free(bn_e);
        return -1;
    }

    /* Build public RSA key */
    {
        RSA *rsa = RSA_new();
        /* RSA_set0_key takes ownership of BIGNUMs */
        if (!rsa || RSA_set0_key(rsa, bn_n, bn_e, NULL) != 1) {
            RSA_free(rsa);
            BN_free(bn_e);
            BN_free(bn_n);
            return -1;
        }
        bn_n = bn_e = NULL; /* owned by rsa */
        pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            return -1;
        }
        /* rsa owned by pkey */
    }

    /* Parse signature blob */
    alglen = ((uint32_t)sig_blob[0] << 24) | ((uint32_t)sig_blob[1] << 16) |
             ((uint32_t)sig_blob[2] << 8) | (uint32_t)sig_blob[3];
    if (4 + alglen + 4 > sig_len) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    alg = (const char *)(sig_blob + 4);
    rawlen = ((uint32_t)sig_blob[4 + alglen] << 24) |
             ((uint32_t)sig_blob[5 + alglen] << 16) |
             ((uint32_t)sig_blob[6 + alglen] << 8) |
             (uint32_t)sig_blob[7 + alglen];
    raw = sig_blob + 8 + alglen;
    if (8 + alglen + rawlen > sig_len) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    if (alglen == 12 && memcmp(alg, "rsa-sha2-256", 12) == 0) {
        md = EVP_sha256();
    } else if (alglen == 7 && memcmp(alg, "ssh-rsa", 7) == 0) {
        md = EVP_sha1();
    } else {
        EVP_PKEY_free(pkey);
        return -1;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx && EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) > 0 &&
        EVP_DigestVerify(mdctx, raw, rawlen, H, H_len) == 1) {
        ok = 0;
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ok;
}

chssh_dh_ctx_t *chssh_dh_new(void)
{
    chssh_dh_ctx_t *dh = (chssh_dh_ctx_t *)calloc(1, sizeof(*dh));
    if (!dh) {
        return NULL;
    }
    if (BN_hex2bn(&dh->p, GROUP14_P_HEX) == 0) {
        free(dh);
        return NULL;
    }
    dh->g = BN_new();
    if (!dh->g || !BN_set_word(dh->g, 2)) {
        BN_free(dh->p);
        BN_free(dh->g);
        free(dh);
        return NULL;
    }
    return dh;
}

void chssh_dh_free(chssh_dh_ctx_t *dh)
{
    if (!dh) {
        return;
    }
    BN_free(dh->p);
    BN_free(dh->g);
    BN_free(dh->priv);
    BN_free(dh->pub);
    free(dh);
}

int chssh_dh_gen_public(chssh_dh_ctx_t *dh, uint8_t *pub, size_t cap,
                        size_t *pub_len)
{
    BN_CTX *ctx;
    if (!dh || !pub || !pub_len) {
        return -1;
    }
    BN_free(dh->priv);
    BN_free(dh->pub);
    dh->priv = BN_new();
    dh->pub = BN_new();
    ctx = BN_CTX_new();
    if (!dh->priv || !dh->pub || !ctx) {
        BN_CTX_free(ctx);
        return -1;
    }
    /* private: random 1..p-2, use BN_rand_range */
    {
        BIGNUM *max = BN_dup(dh->p);
        if (!max || !BN_sub_word(max, 2) || !BN_rand_range(dh->priv, max) ||
            !BN_add_word(dh->priv, 1)) {
            BN_free(max);
            BN_CTX_free(ctx);
            return -1;
        }
        BN_free(max);
    }
    if (!BN_mod_exp(dh->pub, dh->g, dh->priv, dh->p, ctx)) {
        BN_CTX_free(ctx);
        return -1;
    }
    BN_CTX_free(ctx);
    return bn_to_mpint(dh->pub, pub, cap, pub_len);
}

int chssh_dh_compute(chssh_dh_ctx_t *dh, const uint8_t *peer_pub,
                     size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    BIGNUM *peer = NULL;
    BIGNUM *secret = NULL;
    BN_CTX *ctx = NULL;
    int rc = -1;

    if (!dh || !dh->priv || !peer_pub || !K || !K_len) {
        return -1;
    }
    peer = mpint_to_bn(peer_pub, peer_len);
    secret = BN_new();
    ctx = BN_CTX_new();
    if (!peer || !secret || !ctx) {
        goto done;
    }
    if (!BN_mod_exp(secret, peer, dh->priv, dh->p, ctx)) {
        goto done;
    }
    rc = bn_to_mpint(secret, K, cap, K_len);
done:
    BN_free(peer);
    BN_free(secret);
    BN_CTX_free(ctx);
    return rc;
}

int chssh_sha256(const uint8_t *data, size_t len, uint8_t out[CHSSH_HASH_LEN])
{
    unsigned int outl = CHSSH_HASH_LEN;
    if (!out) {
        return -1;
    }
    return EVP_Digest(data, len, out, &outl, EVP_sha256(), NULL) == 1 ? 0 : -1;
}

chssh_hash_ctx_t *chssh_hash_new(void)
{
    chssh_hash_ctx_t *h = (chssh_hash_ctx_t *)calloc(1, sizeof(*h));
    if (!h) {
        return NULL;
    }
    h->md = EVP_MD_CTX_new();
    if (!h->md || EVP_DigestInit_ex(h->md, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(h->md);
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
    EVP_MD_CTX_free(h->md);
    free(h);
}

int chssh_hash_update(chssh_hash_ctx_t *h, const uint8_t *data, size_t len)
{
    if (!h || !h->md) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    return EVP_DigestUpdate(h->md, data, len) == 1 ? 0 : -1;
}

int chssh_hash_update_string(chssh_hash_ctx_t *h, const uint8_t *data,
                             size_t len)
{
    uint8_t hdr[4];
    put_u32(hdr, (uint32_t)len);
    if (chssh_hash_update(h, hdr, 4) != 0) {
        return -1;
    }
    return chssh_hash_update(h, data, len);
}

int chssh_hash_update_cstring(chssh_hash_ctx_t *h, const char *s)
{
    return chssh_hash_update_string(h, (const uint8_t *)s, s ? strlen(s) : 0);
}

int chssh_hash_final(chssh_hash_ctx_t *h, uint8_t out[CHSSH_HASH_LEN])
{
    unsigned int outl = CHSSH_HASH_LEN;
    if (!h || !h->md || !out) {
        return -1;
    }
    return EVP_DigestFinal_ex(h->md, out, &outl) == 1 ? 0 : -1;
}

static int derive_one(const uint8_t *K, size_t K_len, const uint8_t *H,
                      char letter, const uint8_t *sid, size_t sid_len,
                      uint8_t *out, size_t out_len)
{
    /* K is stored as mpint (with length prefix) for HASH input in RFC 4253.
     * Actually: HASH(K || H || X || session_id) where K is mpint encoding. */
    uint8_t buf[CHSSH_HASH_LEN];
    uint8_t letter_b = (uint8_t)letter;
    chssh_hash_ctx_t *h = chssh_hash_new();
    size_t got = 0;

    if (!h) {
        return -1;
    }
    /* K is already full mpint bytes including length prefix */
    if (chssh_hash_update(h, K, K_len) != 0 ||
        chssh_hash_update(h, H, CHSSH_HASH_LEN) != 0 ||
        chssh_hash_update(h, &letter_b, 1) != 0 ||
        chssh_hash_update(h, sid, sid_len) != 0 ||
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
            /* extend: HASH(K || H || prev) */
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
    if (derive_one(K, K_len, H, 'A', session_id, session_id_len, iv_c2s,
                   CHSSH_AES_IV_LEN) != 0 ||
        derive_one(K, K_len, H, 'B', session_id, session_id_len, iv_s2c,
                   CHSSH_AES_IV_LEN) != 0 ||
        derive_one(K, K_len, H, 'C', session_id, session_id_len, key_c2s,
                   CHSSH_AES_KEY_LEN) != 0 ||
        derive_one(K, K_len, H, 'D', session_id, session_id_len, key_s2c,
                   CHSSH_AES_KEY_LEN) != 0 ||
        derive_one(K, K_len, H, 'E', session_id, session_id_len, mac_c2s,
                   CHSSH_MAC_KEY_LEN) != 0 ||
        derive_one(K, K_len, H, 'F', session_id, session_id_len, mac_s2c,
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
    if (!c) {
        return NULL;
    }
    c->ctx = EVP_CIPHER_CTX_new();
    if (!c->ctx ||
        EVP_CipherInit_ex(c->ctx, EVP_aes_128_ctr(), NULL, key, iv, encrypt) !=
            1) {
        EVP_CIPHER_CTX_free(c->ctx);
        free(c);
        return NULL;
    }
    return c;
}

chssh_cipher_t *chssh_cipher_dup(const chssh_cipher_t *c)
{
    chssh_cipher_t *n;
    if (!c || !c->ctx) {
        return NULL;
    }
    n = (chssh_cipher_t *)calloc(1, sizeof(*n));
    if (!n) {
        return NULL;
    }
    n->ctx = EVP_CIPHER_CTX_new();
    if (!n->ctx || EVP_CIPHER_CTX_copy(n->ctx, c->ctx) != 1) {
        EVP_CIPHER_CTX_free(n->ctx);
        free(n);
        return NULL;
    }
    return n;
}

void chssh_cipher_free(chssh_cipher_t *c)
{
    if (!c) {
        return;
    }
    EVP_CIPHER_CTX_free(c->ctx);
    free(c);
}

int chssh_cipher_crypt(chssh_cipher_t *c, uint8_t *data, size_t len)
{
    int outl = 0;
    if (!c || !c->ctx || !data) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    /* CTR: in-place, outl should equal len */
    if (EVP_CipherUpdate(c->ctx, data, &outl, data, (int)len) != 1) {
        return -1;
    }
    return 0;
}

int chssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                      size_t data_len, uint8_t out[CHSSH_MAC_LEN])
{
    unsigned int outl = CHSSH_MAC_LEN;
    if (!key || !out) {
        return -1;
    }
    return HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &outl)
               ? 0
               : -1;
}


/* --- ECDH P-256 --- */
struct chssh_ecdh_ctx {
    EVP_PKEY *local;
};

chssh_ecdh_ctx_t *chssh_ecdh_p256_new(void)
{
    chssh_ecdh_ctx_t *e;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *key = NULL;
    OSSL_PARAM prm[2];

    e = (chssh_ecdh_ctx_t *)calloc(1, sizeof(*e));
    if (!e) {
        return NULL;
    }
    prm[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256", 0);
    prm[1] = OSSL_PARAM_construct_end();
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_params(pctx, prm) <= 0 ||
        EVP_PKEY_generate(pctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        free(e);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);
    e->local = key;
    return e;
}

void chssh_ecdh_free(chssh_ecdh_ctx_t *e)
{
    if (!e) {
        return;
    }
    EVP_PKEY_free(e->local);
    free(e);
}

int chssh_ecdh_public_string(chssh_ecdh_ctx_t *e, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    unsigned char *pt = NULL;
    size_t pt_len;

    if (!e || !e->local || !out || !out_len) {
        return -1;
    }
    pt_len = EVP_PKEY_get1_encoded_public_key(e->local, &pt);
    if (pt_len == 0 || !pt) {
        return -1;
    }
    if (4 + pt_len > cap) {
        OPENSSL_free(pt);
        return -1;
    }
    put_u32(out, (uint32_t)pt_len);
    memcpy(out + 4, pt, pt_len);
    *out_len = 4 + pt_len;
    OPENSSL_free(pt);
    return 0;
}

int chssh_ecdh_compute(chssh_ecdh_ctx_t *e, const uint8_t *peer_q_str,
                       size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    uint32_t qlen;
    const uint8_t *q;
    EVP_PKEY *peer = NULL;
    EVP_PKEY_CTX *pctx = NULL, *bctx = NULL;
    size_t secret_len = 0;
    uint8_t secret[66];
    BIGNUM *bn = NULL;
    int rc = -1;
    OSSL_PARAM prm[3];

    if (!e || !e->local || !peer_q_str || peer_len < 5 || !K || !K_len) {
        return -1;
    }
    qlen = ((uint32_t)peer_q_str[0] << 24) | ((uint32_t)peer_q_str[1] << 16) |
           ((uint32_t)peer_q_str[2] << 8) | (uint32_t)peer_q_str[3];
    if (4u + qlen > peer_len || qlen < 1) {
        return -1;
    }
    q = peer_q_str + 4;
    prm[0] = OSSL_PARAM_construct_utf8_string("group", (char *)"P-256", 0);
    prm[1] = OSSL_PARAM_construct_octet_string("pub", (void *)q, qlen);
    prm[2] = OSSL_PARAM_construct_end();
    bctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!bctx || EVP_PKEY_fromdata_init(bctx) <= 0 ||
        EVP_PKEY_fromdata(bctx, &peer, EVP_PKEY_PUBLIC_KEY, prm) <= 0) {
        EVP_PKEY_CTX_free(bctx);
        return -1;
    }
    EVP_PKEY_CTX_free(bctx);
    pctx = EVP_PKEY_CTX_new(e->local, NULL);
    if (!pctx || EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_derive_set_peer(pctx, peer) <= 0 ||
        EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0 ||
        secret_len == 0 || secret_len > sizeof(secret) ||
        EVP_PKEY_derive(pctx, secret, &secret_len) <= 0) {
        goto done;
    }
    bn = BN_bin2bn(secret, (int)secret_len, NULL);
    if (!bn) {
        goto done;
    }
    rc = bn_to_mpint(bn, K, cap, K_len);
done:
    BN_free(bn);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(peer);
    return rc;
}

#else /* !HAVE_OPENSSL — lab_mode dialectic only; production KEX unavailable */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chssh_rsa_key { int dummy; };
struct chssh_dh_ctx { int dummy; };
struct chssh_cipher { int dummy; };
struct chssh_hash_ctx { int dummy; };
struct chssh_ecdh_ctx { int dummy; };

int chssh_crypto_init(void)
{
    return 0;
}

int chssh_crypto_random(uint8_t *buf, size_t len)
{
    size_t i;
    if (!buf) {
        return -1;
    }
    /* Weak deterministic fill — production path requires OpenSSL. */
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0x5A ^ (unsigned)i);
    }
    return 0;
}

chssh_rsa_key_t *chssh_rsa_generate(int bits)
{
    (void)bits;
    return NULL;
}
chssh_rsa_key_t *chssh_rsa_load_pem(const char *path)
{
    (void)path;
    return NULL;
}
void chssh_rsa_free(chssh_rsa_key_t *k)
{
    free(k);
}
int chssh_rsa_public_blob(const chssh_rsa_key_t *k, uint8_t *out, size_t cap,
                          size_t *out_len)
{
    (void)k;
    (void)out;
    (void)cap;
    (void)out_len;
    return -1;
}
int chssh_rsa_sign(const chssh_rsa_key_t *k, const char *sig_alg,
                   const uint8_t *H, size_t H_len, uint8_t *out, size_t cap,
                   size_t *out_len)
{
    (void)k;
    (void)sig_alg;
    (void)H;
    (void)H_len;
    (void)out;
    (void)cap;
    (void)out_len;
    return -1;
}
int chssh_rsa_verify(const uint8_t *host_key_blob, size_t hk_len,
                     const uint8_t *sig_blob, size_t sig_len,
                     const uint8_t *H, size_t H_len)
{
    (void)host_key_blob;
    (void)hk_len;
    (void)sig_blob;
    (void)sig_len;
    (void)H;
    (void)H_len;
    return -1;
}
chssh_dh_ctx_t *chssh_dh_new(void) { return NULL; }
void chssh_dh_free(chssh_dh_ctx_t *dh) { free(dh); }
int chssh_dh_gen_public(chssh_dh_ctx_t *dh, uint8_t *pub, size_t cap,
                        size_t *pub_len)
{
    (void)dh;
    (void)pub;
    (void)cap;
    (void)pub_len;
    return -1;
}
int chssh_dh_compute(chssh_dh_ctx_t *dh, const uint8_t *peer_pub,
                     size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    (void)dh;
    (void)peer_pub;
    (void)peer_len;
    (void)K;
    (void)cap;
    (void)K_len;
    return -1;
}
chssh_ecdh_ctx_t *chssh_ecdh_p256_new(void) { return NULL; }
void chssh_ecdh_free(chssh_ecdh_ctx_t *e) { free(e); }
int chssh_ecdh_public_string(chssh_ecdh_ctx_t *e, uint8_t *out, size_t cap,
                             size_t *out_len)
{
    (void)e;
    (void)out;
    (void)cap;
    (void)out_len;
    return -1;
}
int chssh_ecdh_compute(chssh_ecdh_ctx_t *e, const uint8_t *peer_q_str,
                       size_t peer_len, uint8_t *K, size_t cap, size_t *K_len)
{
    (void)e;
    (void)peer_q_str;
    (void)peer_len;
    (void)K;
    (void)cap;
    (void)K_len;
    return -1;
}
int chssh_sha256(const uint8_t *data, size_t len, uint8_t out[CHSSH_HASH_LEN])
{
    (void)data;
    (void)len;
    if (out) {
        memset(out, 0, CHSSH_HASH_LEN);
    }
    return -1;
}
chssh_hash_ctx_t *chssh_hash_new(void) { return NULL; }
void chssh_hash_free(chssh_hash_ctx_t *h) { free(h); }
int chssh_hash_update(chssh_hash_ctx_t *h, const uint8_t *data, size_t len)
{
    (void)h;
    (void)data;
    (void)len;
    return -1;
}
int chssh_hash_update_string(chssh_hash_ctx_t *h, const uint8_t *data,
                             size_t len)
{
    (void)h;
    (void)data;
    (void)len;
    return -1;
}
int chssh_hash_update_cstring(chssh_hash_ctx_t *h, const char *s)
{
    (void)h;
    (void)s;
    return -1;
}
int chssh_hash_final(chssh_hash_ctx_t *h, uint8_t out[CHSSH_HASH_LEN])
{
    (void)h;
    if (out) {
        memset(out, 0, CHSSH_HASH_LEN);
    }
    return -1;
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
    (void)K;
    (void)K_len;
    (void)H;
    (void)session_id;
    (void)session_id_len;
    (void)iv_c2s;
    (void)iv_s2c;
    (void)key_c2s;
    (void)key_s2c;
    (void)mac_c2s;
    (void)mac_s2c;
    return -1;
}
chssh_cipher_t *chssh_cipher_new(const uint8_t key[CHSSH_AES_KEY_LEN],
                                 const uint8_t iv[CHSSH_AES_IV_LEN],
                                 int encrypt)
{
    (void)key;
    (void)iv;
    (void)encrypt;
    return NULL;
}
chssh_cipher_t *chssh_cipher_dup(const chssh_cipher_t *c)
{
    (void)c;
    return NULL;
}
void chssh_cipher_free(chssh_cipher_t *c) { free(c); }
int chssh_cipher_crypt(chssh_cipher_t *c, uint8_t *data, size_t len)
{
    (void)c;
    (void)data;
    (void)len;
    return -1;
}
int chssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                      size_t data_len, uint8_t out[CHSSH_MAC_LEN])
{
    (void)key;
    (void)key_len;
    (void)data;
    (void)data_len;
    if (out) {
        memset(out, 0, CHSSH_MAC_LEN);
    }
    return -1;
}

#endif /* HAVE_OPENSSL */
