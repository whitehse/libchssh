/**
 * @file chssh_openssh_key.c
 * @brief Unencrypted OpenSSH private key decoder (PR-1b/1c).
 */

#include "chssh_openssh_key.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

static int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_cap,
                      size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;
    while (i < in_len) {
        int v[4];
        int n = 0;
        int c;
        while (n < 4 && i < in_len) {
            c = (unsigned char)in[i++];
            if (c == '=' || isspace(c)) {
                if (c == '=') {
                    v[n++] = -2;
                }
                continue;
            }
            v[n] = b64_val(c);
            if (v[n] < 0) {
                return -1;
            }
            n++;
        }
        if (n == 0) {
            break;
        }
        if (n < 2 || o + 3 > out_cap) {
            return -1;
        }
        out[o++] = (uint8_t)((v[0] << 2) | ((v[1] & 0x30) >> 4));
        if (n > 2 && v[2] != -2) {
            out[o++] =
                (uint8_t)(((v[1] & 0x0f) << 4) | ((v[2] & 0x3c) >> 2));
        }
        if (n > 3 && v[3] != -2) {
            out[o++] = (uint8_t)(((v[2] & 0x03) << 6) | v[3]);
        }
        if (n < 4 || v[2] == -2 || v[3] == -2) {
            break;
        }
    }
    *out_len = o;
    return 0;
}

static int get_u32(const uint8_t *p, size_t len, size_t off, uint32_t *out)
{
    if (off + 4 > len) {
        return -1;
    }
    *out = ((uint32_t)p[off] << 24) | ((uint32_t)p[off + 1] << 16) |
           ((uint32_t)p[off + 2] << 8) | (uint32_t)p[off + 3];
    return 0;
}

static int get_string(const uint8_t *p, size_t len, size_t *off, size_t *d_off,
                      size_t *d_len)
{
    uint32_t n;
    if (get_u32(p, len, *off, &n) != 0) {
        return -1;
    }
    *off += 4;
    if (*off + n > len) {
        return -1;
    }
    *d_off = *off;
    *d_len = n;
    *off += n;
    return 0;
}

static int get_mpint_copy(const uint8_t *p, size_t len, size_t *off, uint8_t **out,
                          size_t *out_len)
{
    size_t d_off, d_len;
    uint8_t *buf;
    if (get_string(p, len, off, &d_off, &d_len) != 0) {
        return -1;
    }
    if (d_len > 0 && (p[d_off] & 0x80)) {
        return -1;
    }
    buf = (uint8_t *)malloc(d_len ? d_len : 1);
    if (!buf) {
        return -1;
    }
    if (d_len) {
        memcpy(buf, p + d_off, d_len);
    }
    *out = buf;
    *out_len = d_len;
    return 0;
}

void chssh_openssh_decoded_clear(chssh_openssh_decoded_t *d)
{
    if (!d) {
        return;
    }
    free(d->rsa_n);
    free(d->rsa_e);
    free(d->rsa_d);
    free(d->rsa_p);
    free(d->rsa_q);
    free(d->rsa_iqmp);
    memset(d, 0, sizeof(*d));
}

int chssh_read_file(const char *path, uint8_t **data_out, size_t *len_out)
{
    FILE *f;
    long sz;
    uint8_t *buf;
    size_t n;
    if (!path || !data_out || !len_out) {
        return -1;
    }
    f = fopen(path, "rb");
    if (!f) {
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (n != (size_t)sz) {
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    *data_out = buf;
    *len_out = n;
    return 0;
}

int chssh_openssh_decode_pem(const char *pem, size_t pem_len,
                             chssh_openssh_decoded_t *out)
{
    const char *begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const char *end = "-----END OPENSSH PRIVATE KEY-----";
    const char *p;
    const char *e;
    char b64[16384];
    size_t b64_len = 0;
    uint8_t raw[16384];
    size_t raw_len = 0;
    size_t off = 0;
    size_t s_off, s_len;
    uint32_t nkeys, check1, check2;
    /* wire magic is "openssh-key-v1\0" (15 bytes) */
    static const char magic[] = "openssh-key-v1";
    chssh_openssh_decoded_t dec;
    chssh_pubkey_alg_t pub_alg;

    if (!pem || !out) {
        return -1;
    }
    memset(&dec, 0, sizeof(dec));
    p = strstr(pem, begin);
    if (!p) {
        return -1;
    }
    p += strlen(begin);
    while (*p == '\r' || *p == '\n') {
        p++;
    }
    e = strstr(p, end);
    if (!e || (size_t)(e - pem) > pem_len) {
        return -1;
    }
    while (p < e && b64_len + 1 < sizeof(b64)) {
        if (!isspace((unsigned char)*p)) {
            b64[b64_len++] = *p;
        }
        p++;
    }
    b64[b64_len] = '\0';
    if (b64_decode(b64, b64_len, raw, sizeof(raw), &raw_len) != 0) {
        return -1;
    }
    /* sizeof(magic) includes trailing NUL → 15 bytes */
    if (raw_len < sizeof(magic) || memcmp(raw, magic, sizeof(magic)) != 0) {
        return -1;
    }
    off = sizeof(magic);
    /* ciphername */
    if (get_string(raw, raw_len, &off, &s_off, &s_len) != 0) {
        return -1;
    }
    if (s_len != 4 || memcmp(raw + s_off, "none", 4) != 0) {
        return -1; /* encrypted — reject (K13) */
    }
    /* kdfname */
    if (get_string(raw, raw_len, &off, &s_off, &s_len) != 0) {
        return -1;
    }
    if (s_len != 4 || memcmp(raw + s_off, "none", 4) != 0) {
        return -1;
    }
    /* kdf options */
    if (get_string(raw, raw_len, &off, &s_off, &s_len) != 0) {
        return -1;
    }
    if (s_len != 0) {
        return -1;
    }
    if (get_u32(raw, raw_len, off, &nkeys) != 0) {
        return -1;
    }
    off += 4;
    if (nkeys != 1) {
        return -1;
    }
    /* public key blob */
    if (get_string(raw, raw_len, &off, &s_off, &s_len) != 0) {
        return -1;
    }
    if (s_len == 0 || s_len > sizeof(dec.pub_blob)) {
        return -1;
    }
    memcpy(dec.pub_blob, raw + s_off, s_len);
    dec.pub_blob_len = s_len;
    if (chssh_pubkey_blob_parse(dec.pub_blob, dec.pub_blob_len, &pub_alg) != 0) {
        return -1;
    }
    dec.alg = pub_alg;
    /* private block */
    if (get_string(raw, raw_len, &off, &s_off, &s_len) != 0) {
        return -1;
    }
    {
        const uint8_t *priv = raw + s_off;
        size_t plen = s_len;
        size_t po = 0;
        size_t t_off, t_len;
        if (get_u32(priv, plen, po, &check1) != 0) {
            return -1;
        }
        po += 4;
        if (get_u32(priv, plen, po, &check2) != 0) {
            return -1;
        }
        po += 4;
        if (check1 != check2) {
            return -1;
        }
        if (get_string(priv, plen, &po, &t_off, &t_len) != 0) {
            return -1;
        }
        if (t_len == 7 && memcmp(priv + t_off, "ssh-rsa", 7) == 0) {
            if (dec.alg != CHSSH_PUBKEY_ALG_SSH_RSA) {
                return -1;
            }
            if (get_mpint_copy(priv, plen, &po, &dec.rsa_n, &dec.rsa_n_len) !=
                    0 ||
                get_mpint_copy(priv, plen, &po, &dec.rsa_e, &dec.rsa_e_len) !=
                    0 ||
                get_mpint_copy(priv, plen, &po, &dec.rsa_d, &dec.rsa_d_len) !=
                    0 ||
                get_mpint_copy(priv, plen, &po, &dec.rsa_iqmp,
                               &dec.rsa_iqmp_len) != 0 ||
                get_mpint_copy(priv, plen, &po, &dec.rsa_p, &dec.rsa_p_len) !=
                    0 ||
                get_mpint_copy(priv, plen, &po, &dec.rsa_q, &dec.rsa_q_len) !=
                    0) {
                chssh_openssh_decoded_clear(&dec);
                return -1;
            }
        } else if (t_len == 11 && memcmp(priv + t_off, "ssh-ed25519", 11) == 0) {
            size_t pk_off, pk_len, sk_off, sk_len;
            if (dec.alg != CHSSH_PUBKEY_ALG_SSH_ED25519) {
                return -1;
            }
            if (get_string(priv, plen, &po, &pk_off, &pk_len) != 0 ||
                pk_len != 32) {
                return -1;
            }
            memcpy(dec.ed_pub, priv + pk_off, 32);
            if (get_string(priv, plen, &po, &sk_off, &sk_len) != 0) {
                return -1;
            }
            /* OpenSSH: 64 bytes = seed||public, or 32-byte seed */
            if (sk_len == 64) {
                memcpy(dec.ed_seed, priv + sk_off, 32);
                if (memcmp(priv + sk_off + 32, dec.ed_pub, 32) != 0) {
                    return -1;
                }
            } else if (sk_len == 32) {
                memcpy(dec.ed_seed, priv + sk_off, 32);
            } else {
                return -1;
            }
        } else {
            return -1;
        }
        /* comment string (ignore) */
        if (get_string(priv, plen, &po, &t_off, &t_len) != 0) {
            chssh_openssh_decoded_clear(&dec);
            return -1;
        }
    }
    *out = dec;
    return 0;
}
