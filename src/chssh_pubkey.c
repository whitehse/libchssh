/**
 * @file chssh_pubkey.c
 * @brief SSH public key blob parse/encode + OpenSSH SHA256 fingerprints (PR-1a).
 *
 * Pure helpers: no sockets, no userauth. Fingerprint needs chssh_sha256
 * (OpenSSL or mbedTLS production crypto).
 */

#include "chssh.h"
#include "chssh_crypto.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* --- wire helpers --- */

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static int get_u32(const uint8_t *p, size_t len, size_t off, uint32_t *out)
{
    if (!p || !out || off + 4 > len) {
        return -1;
    }
    *out = ((uint32_t)p[off] << 24) | ((uint32_t)p[off + 1] << 16) |
           ((uint32_t)p[off + 2] << 8) | (uint32_t)p[off + 3];
    return 0;
}

/** Read SSH string; sets *data_off to payload start, *data_len length. */
static int get_string(const uint8_t *p, size_t len, size_t *off, size_t *data_off,
                      size_t *data_len)
{
    uint32_t n;
    size_t o;
    if (!p || !off || !data_off || !data_len) {
        return -1;
    }
    o = *off;
    if (get_u32(p, len, o, &n) != 0) {
        return -1;
    }
    o += 4;
    if (o + n > len) {
        return -1;
    }
    *data_off = o;
    *data_len = n;
    *off = o + n;
    return 0;
}

/** SSH mpint: uint32 len + big-endian; reject negative (MSB of first byte). */
static int get_mpint(const uint8_t *p, size_t len, size_t *off, size_t *data_off,
                     size_t *data_len)
{
    size_t d_off, d_len;
    if (get_string(p, len, off, &d_off, &d_len) != 0) {
        return -1;
    }
    if (d_len > 0 && (p[d_off] & 0x80) != 0) {
        return -1; /* negative mpint not used for RSA e/n */
    }
    /* Leading zero only allowed when next byte would have high bit set. */
    if (d_len >= 2 && p[d_off] == 0 && (p[d_off + 1] & 0x80) == 0) {
        return -1;
    }
    *data_off = d_off;
    *data_len = d_len;
    return 0;
}

static int put_string(uint8_t *out, size_t cap, size_t *off, const void *data,
                      size_t data_len)
{
    size_t o;
    if (!out || !off || (!data && data_len)) {
        return -1;
    }
    o = *off;
    if (o + 4 + data_len > cap) {
        return -1;
    }
    put_u32(out + o, (uint32_t)data_len);
    o += 4;
    if (data_len) {
        memcpy(out + o, data, data_len);
        o += data_len;
    }
    *off = o;
    return 0;
}

/** Encode big-endian unsigned as SSH mpint (prepend 0x00 if high bit set). */
static int put_mpint_be(uint8_t *out, size_t cap, size_t *off, const uint8_t *be,
                        size_t be_len)
{
    size_t start = 0;
    size_t need;
    size_t o;
    int lead0 = 0;

    if (!out || !off || (!be && be_len)) {
        return -1;
    }
    while (start < be_len && be[start] == 0) {
        start++;
    }
    if (start == be_len) {
        /* zero */
        return put_string(out, cap, off, "", 0);
    }
    if (be[start] & 0x80) {
        lead0 = 1;
    }
    need = be_len - start + (size_t)lead0;
    o = *off;
    if (o + 4 + need > cap) {
        return -1;
    }
    put_u32(out + o, (uint32_t)need);
    o += 4;
    if (lead0) {
        out[o++] = 0;
    }
    memcpy(out + o, be + start, be_len - start);
    o += be_len - start;
    *off = o;
    return 0;
}

/* --- base64 (encode unpadded for fingerprint; decode for .pub lines) --- */

static const char B64_TAB[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

/** Standard base64 encode; if unpadded, omit '='. */
static int b64_encode(const uint8_t *in, size_t in_len, int unpadded, char *out,
                      size_t out_cap)
{
    size_t i = 0;
    size_t o = 0;
    if (!in || !out) {
        return -1;
    }
    while (i < in_len) {
        uint32_t v = (uint32_t)in[i++] << 16;
        int n = 1;
        if (i < in_len) {
            v |= (uint32_t)in[i++] << 8;
            n = 2;
        }
        if (i < in_len) {
            v |= (uint32_t)in[i++];
            n = 3;
        }
        if (o + 4 >= out_cap) {
            return -1;
        }
        out[o++] = B64_TAB[(v >> 18) & 63];
        out[o++] = B64_TAB[(v >> 12) & 63];
        if (n >= 2) {
            out[o++] = B64_TAB[(v >> 6) & 63];
        } else if (!unpadded) {
            out[o++] = '=';
        }
        if (n >= 3) {
            out[o++] = B64_TAB[v & 63];
        } else if (!unpadded) {
            out[o++] = '=';
        } else if (n == 1) {
            /* only two chars for 1-byte input when unpadded — already wrote 2 */
        }
        if (n == 1 && unpadded) {
            /* OpenSSH fingerprint still uses two chars only for remainder 1? */
            /* Standard: 1 byte → 2 chars + pad; unpadded → 2 chars. OK */
        }
        if (n == 2 && unpadded) {
            /* 2 bytes → 3 chars */
        }
    }
    if (o >= out_cap) {
        return -1;
    }
    out[o] = '\0';
    return 0;
}

static int b64_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;
    int val[4];
    int n;
    int c;

    if (!in || !out || !out_len) {
        return -1;
    }
    while (in[i]) {
        n = 0;
        while (n < 4 && in[i]) {
            c = (unsigned char)in[i++];
            if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                if (c == '=') {
                    val[n++] = -2; /* pad */
                    break;
                }
                continue;
            }
            val[n] = b64_val(c);
            if (val[n] < 0) {
                return -1;
            }
            n++;
        }
        if (n == 0) {
            break;
        }
        if (n < 2) {
            return -1;
        }
        if (o + 3 > out_cap) {
            return -1;
        }
        out[o++] = (uint8_t)((val[0] << 2) | ((val[1] & 0x30) >> 4));
        if (n > 2 && val[2] != -2) {
            out[o++] = (uint8_t)(((val[1] & 0x0f) << 4) | ((val[2] & 0x3c) >> 2));
        }
        if (n > 3 && val[3] != -2) {
            out[o++] = (uint8_t)(((val[2] & 0x03) << 6) | val[3]);
        }
        if (n < 4 || val[2] == -2 || val[3] == -2) {
            break;
        }
    }
    *out_len = o;
    return 0;
}

/* --- public API --- */

const char *chssh_pubkey_alg_name(chssh_pubkey_alg_t alg)
{
    switch (alg) {
    case CHSSH_PUBKEY_ALG_SSH_RSA:
        return "ssh-rsa";
    case CHSSH_PUBKEY_ALG_SSH_ED25519:
        return "ssh-ed25519";
    default:
        return NULL;
    }
}

int chssh_pubkey_blob_parse(const uint8_t *blob, size_t len,
                            chssh_pubkey_alg_t *alg_out)
{
    size_t off = 0;
    size_t t_off, t_len;
    size_t a_off, a_len;
    size_t b_off, b_len;
    chssh_pubkey_alg_t alg = CHSSH_PUBKEY_ALG_UNKNOWN;

    if (!blob || len < 8) {
        return -1;
    }
    if (get_string(blob, len, &off, &t_off, &t_len) != 0) {
        return -1;
    }
    if (t_len == 7 && memcmp(blob + t_off, "ssh-rsa", 7) == 0) {
        alg = CHSSH_PUBKEY_ALG_SSH_RSA;
        if (get_mpint(blob, len, &off, &a_off, &a_len) != 0) {
            return -1;
        }
        if (a_len == 0 || a_len > CHSSH_MAX_MPINT) {
            return -1;
        }
        if (get_mpint(blob, len, &off, &b_off, &b_len) != 0) {
            return -1;
        }
        if (b_len == 0 || b_len > CHSSH_MAX_MPINT) {
            return -1;
        }
        /* Trailing garbage not allowed. */
        if (off != len) {
            return -1;
        }
    } else if (t_len == 11 && memcmp(blob + t_off, "ssh-ed25519", 11) == 0) {
        alg = CHSSH_PUBKEY_ALG_SSH_ED25519;
        if (get_string(blob, len, &off, &a_off, &a_len) != 0) {
            return -1;
        }
        if (a_len != 32) {
            return -1;
        }
        if (off != len) {
            return -1;
        }
    } else {
        return -1;
    }
    if (alg_out) {
        *alg_out = alg;
    }
    return 0;
}

int chssh_pubkey_fingerprint_sha256(const uint8_t *blob, size_t len,
                                    char out[CHSSH_FP_SHA256_MAX])
{
    uint8_t dig[CHSSH_HASH_LEN];
    char b64[64];

    if (!blob || len == 0 || !out) {
        return -1;
    }
    if (chssh_sha256(blob, len, dig) != 0) {
        return -1;
    }
    if (b64_encode(dig, CHSSH_HASH_LEN, 1 /* unpadded */, b64, sizeof(b64)) !=
        0) {
        return -1;
    }
    if (strlen(b64) + 8 >= CHSSH_FP_SHA256_MAX) {
        return -1;
    }
    /* OpenSSH: SHA256:<base64 without padding> */
    out[0] = 'S';
    out[1] = 'H';
    out[2] = 'A';
    out[3] = '2';
    out[4] = '5';
    out[5] = '6';
    out[6] = ':';
    memcpy(out + 7, b64, strlen(b64) + 1);
    return 0;
}

int chssh_pubkey_blob_encode_ed25519(const uint8_t pk[32], uint8_t *out,
                                     size_t cap, size_t *out_len)
{
    size_t off = 0;
    if (!pk || !out || !out_len) {
        return -1;
    }
    if (put_string(out, cap, &off, "ssh-ed25519", 11) != 0) {
        return -1;
    }
    if (put_string(out, cap, &off, pk, 32) != 0) {
        return -1;
    }
    *out_len = off;
    return 0;
}

int chssh_pubkey_blob_encode_rsa(const uint8_t *e, size_t e_len,
                                 const uint8_t *n, size_t n_len, uint8_t *out,
                                 size_t cap, size_t *out_len)
{
    size_t off = 0;
    if (!e || e_len == 0 || !n || n_len == 0 || !out || !out_len) {
        return -1;
    }
    if (put_string(out, cap, &off, "ssh-rsa", 7) != 0) {
        return -1;
    }
    if (put_mpint_be(out, cap, &off, e, e_len) != 0) {
        return -1;
    }
    if (put_mpint_be(out, cap, &off, n, n_len) != 0) {
        return -1;
    }
    *out_len = off;
    return 0;
}

int chssh_pubkey_openssh_line_encode(const uint8_t *blob, size_t blob_len,
                                     const char *comment, char *line,
                                     size_t line_cap)
{
    chssh_pubkey_alg_t alg;
    const char *name;
    char b64[CHSSH_PUBKEY_BLOB_MAX * 2];
    int n;

    if (!blob || blob_len == 0 || !line || line_cap < 16) {
        return -1;
    }
    if (chssh_pubkey_blob_parse(blob, blob_len, &alg) != 0) {
        return -1;
    }
    name = chssh_pubkey_alg_name(alg);
    if (!name) {
        return -1;
    }
    if (b64_encode(blob, blob_len, 0 /* padded OK for .pub lines */, b64,
                   sizeof(b64)) != 0) {
        return -1;
    }
    if (comment && comment[0]) {
        n = snprintf(line, line_cap, "%s %s %s", name, b64, comment);
    } else {
        n = snprintf(line, line_cap, "%s %s", name, b64);
    }
    if (n < 0 || (size_t)n >= line_cap) {
        return -1;
    }
    return 0;
}

int chssh_pubkey_openssh_line_parse(const char *line, uint8_t *blob,
                                    size_t blob_cap, size_t *blob_len,
                                    chssh_pubkey_alg_t *alg_out, char *comment,
                                    size_t comment_cap)
{
    char *p;
    char *tok[8];
    size_t ntok = 0;
    size_t i;
    size_t type_i = 0;
    size_t b64_i;
    size_t blen = 0;
    chssh_pubkey_alg_t alg;
    char tokbuf[CHSSH_OPENSSH_LINE_MAX];
    size_t tlen;
    const char *src;

    if (!line || !blob || !blob_len) {
        return -1;
    }
    if (comment && comment_cap) {
        comment[0] = '\0';
    }
    /* Copy and strip CR/LF */
    tlen = 0;
    for (src = line; *src && tlen + 1 < sizeof(tokbuf); src++) {
        if (*src == '\r' || *src == '\n') {
            break;
        }
        tokbuf[tlen++] = *src;
    }
    tokbuf[tlen] = '\0';
    /* Trim */
    p = tokbuf;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '#' || *p == '\0') {
        return -1;
    }
    /* Split on whitespace into up to 8 tokens (algo + b64 + comment parts). */
    while (*p && ntok < 8) {
        tok[ntok++] = p;
        while (*p && !isspace((unsigned char)*p)) {
            p++;
        }
        if (*p) {
            *p = '\0';
            p++;
            while (*p && isspace((unsigned char)*p)) {
                p++;
            }
        }
    }
    if (ntok < 2) {
        return -1;
    }
    /*
     * OpenSSH options (if any) contain '='. Skip leading option-like tokens
     * until we see a known key type.
     */
    type_i = 0;
    for (i = 0; i + 1 < ntok; i++) {
        if (strcmp(tok[i], "ssh-rsa") == 0 ||
            strcmp(tok[i], "ssh-ed25519") == 0 ||
            strcmp(tok[i], "ecdsa-sha2-nistp256") == 0 ||
            strcmp(tok[i], "ecdsa-sha2-nistp384") == 0 ||
            strcmp(tok[i], "ecdsa-sha2-nistp521") == 0) {
            type_i = i;
            break;
        }
        if (strchr(tok[i], '=') == NULL && i == 0) {
            /* first token is type without options */
            type_i = 0;
            break;
        }
        if (strchr(tok[i], '=') != NULL) {
            continue; /* option */
        }
        type_i = i;
        break;
    }
    b64_i = type_i + 1;
    if (b64_i >= ntok) {
        return -1;
    }
    if (b64_decode(tok[b64_i], blob, blob_cap, &blen) != 0 || blen == 0) {
        return -1;
    }
    if (chssh_pubkey_blob_parse(blob, blen, &alg) != 0) {
        return -1;
    }
    /* Optional consistency: line type matches blob type when known. */
    if (strcmp(tok[type_i], "ssh-rsa") == 0 &&
        alg != CHSSH_PUBKEY_ALG_SSH_RSA) {
        return -1;
    }
    if (strcmp(tok[type_i], "ssh-ed25519") == 0 &&
        alg != CHSSH_PUBKEY_ALG_SSH_ED25519) {
        return -1;
    }
    *blob_len = blen;
    if (alg_out) {
        *alg_out = alg;
    }
    if (comment && comment_cap && b64_i + 1 < ntok) {
        size_t c = 0;
        for (i = b64_i + 1; i < ntok && c + 1 < comment_cap; i++) {
            size_t tl = strlen(tok[i]);
            if (c && c + 1 < comment_cap) {
                comment[c++] = ' ';
            }
            if (c + tl >= comment_cap) {
                tl = comment_cap - c - 1;
            }
            memcpy(comment + c, tok[i], tl);
            c += tl;
        }
        comment[c] = '\0';
    }
    return 0;
}
