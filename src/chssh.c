#define _GNU_SOURCE
/**
 * @file chssh.c
 * @brief Call Home SSH transport — pure state machine (no sockets).
 *
 * lab_mode=1: dialectic cleartext after NEWKEYS (not wire-interop).
 * lab_mode=0: OpenSSL production path:
 *   diffie-hellman-group14-sha256, ssh-rsa/rsa-sha2-256 host key,
 *   aes128-ctr, hmac-sha2-256, multi-channel named subsystems (ADR 015).
 */

#include "chssh_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t cfg_default_size(size_t v, size_t d)
{
    return v ? v : d;
}

static char *cfg_dup(chssh_ctx_t *ctx, const char *s)
{
    size_t n;
    char *p;
    if (!s) {
        return NULL;
    }
    n = strlen(s) + 1;
    if (ctx->cfg_store_used + n > sizeof(ctx->cfg_store)) {
        return NULL;
    }
    p = ctx->cfg_store + ctx->cfg_store_used;
    memcpy(p, s, n);
    ctx->cfg_store_used += n;
    return p;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int name_list_append(uint8_t *buf, size_t cap, size_t *off,
                            const char *s)
{
    size_t n = strlen(s);
    if (*off + 4 + n > cap) {
        return -1;
    }
    put_u32(buf + *off, (uint32_t)n);
    *off += 4;
    memcpy(buf + *off, s, n);
    *off += n;
    return 0;
}

void chssh_i_set_error(chssh_ctx_t *ctx, int code, const char *fmt, ...)
{
    va_list ap;
    chssh_event_t ev;
    if (!ctx) {
        return;
    }
    ctx->error = 1;
    ctx->state = CHSSH_STATE_ERROR;
    va_start(ap, fmt);
    vsnprintf(ctx->error_msg, sizeof(ctx->error_msg), fmt, ap);
    va_end(ap);
    memset(&ev, 0, sizeof(ev));
    ev.type = CHSSH_EVENT_ERROR;
    ev.u.error.code = code;
    snprintf(ev.u.error.message, sizeof(ev.u.error.message), "%s",
             ctx->error_msg);
    (void)chssh_i_push_event(ctx, &ev);
}

int chssh_i_push_event(chssh_ctx_t *ctx, const chssh_event_t *ev)
{
    if (!ctx || !ev || !ctx->events) {
        return -1;
    }
    if (ctx->event_count >= ctx->event_cap) {
        ctx->event_drops++;
        return -1;
    }
    ctx->events[ctx->event_head] = *ev;
    ctx->event_head = (ctx->event_head + 1) % ctx->event_cap;
    ctx->event_count++;
    return 0;
}

int chssh_i_out_append(chssh_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || (!data && len) || len == 0) {
        return 0;
    }
    if (ctx->out_len + len > ctx->out_cap) {
        return -1;
    }
    memcpy(ctx->out_buf + ctx->out_len, data, len);
    ctx->out_len += len;
    return 0;
}

static void free_crypto(chssh_ctx_t *ctx)
{
    chssh_rsa_free(ctx->host_key);
    ctx->host_key = NULL;
    chssh_dh_free(ctx->dh);
    ctx->dh = NULL;
    chssh_ecdh_free(ctx->ecdh);
    ctx->ecdh = NULL;
    free(ctx->local_kexinit);
    ctx->local_kexinit = NULL;
    free(ctx->peer_kexinit);
    ctx->peer_kexinit = NULL;
    chssh_cipher_free(ctx->ciph_out);
    ctx->ciph_out = NULL;
    chssh_cipher_free(ctx->ciph_in);
    ctx->ciph_in = NULL;
}

/* RFC 4253 binary packet (+ optional AES-CTR + HMAC-SHA2-256). */
int chssh_i_send_packet(chssh_ctx_t *ctx, const uint8_t *payload, size_t len)
{
    size_t block = ctx->encrypt_out ? 16 : 8;
    size_t padding;
    size_t packet_len;
    size_t total;
    uint8_t *pkt = NULL;
    size_t i;
    uint8_t mac[CHSSH_MAC_LEN];
    uint8_t seqb[4];

    if (!ctx || !payload || len == 0) {
        return -1;
    }
    padding = block - ((5 + len) % block);
    if (padding < 4) {
        padding += block;
    }
    packet_len = 1 + len + padding;
    total = 4 + packet_len;
    pkt = (uint8_t *)malloc(total + CHSSH_MAC_LEN);
    if (!pkt) {
        return -1;
    }
    put_u32(pkt, (uint32_t)packet_len);
    pkt[4] = (uint8_t)padding;
    memcpy(pkt + 5, payload, len);
    for (i = 0; i < padding; i++) {
        pkt[5 + len + i] = (uint8_t)(i + 1);
    }

    if (ctx->encrypt_out && ctx->ciph_out) {
        put_u32(seqb, ctx->send_seq);
        {
            uint8_t mac_in[4 + 65536];
            size_t mac_len = 4 + total;
            if (mac_len > sizeof(mac_in)) {
                free(pkt);
                return -1;
            }
            memcpy(mac_in, seqb, 4);
            memcpy(mac_in + 4, pkt, total);
            if (chssh_hmac_sha256(ctx->mac_key_out, CHSSH_MAC_KEY_LEN, mac_in,
                                  mac_len, mac) != 0) {
                free(pkt);
                return -1;
            }
        }
        if (chssh_cipher_crypt(ctx->ciph_out, pkt, total) != 0) {
            free(pkt);
            return -1;
        }
        if (chssh_i_out_append(ctx, pkt, total) != 0 ||
            chssh_i_out_append(ctx, mac, CHSSH_MAC_LEN) != 0) {
            free(pkt);
            return -1;
        }
    } else {
        if (chssh_i_out_append(ctx, pkt, total) != 0) {
            free(pkt);
            return -1;
        }
    }
    free(pkt);
    ctx->send_seq++;
    return 0;
}

static int send_ident(chssh_ctx_t *ctx)
{
    char line[CHSSH_IDENT_MAX + 3];
    size_t n;
    chssh_event_t ev;

    if (ctx->ident_flushed) {
        return 0;
    }
    n = (size_t)snprintf(line, sizeof(line), "%s\r\n", ctx->local_ident);
    if (n >= sizeof(line) ||
        chssh_i_out_append(ctx, (const uint8_t *)line, n) != 0) {
        return -1;
    }
    ctx->ident_flushed = 1;
    memset(&ev, 0, sizeof(ev));
    ev.type = CHSSH_EVENT_IDENT_SENT;
    snprintf(ev.u.ident.banner, sizeof(ev.u.ident.banner), "%s",
             ctx->local_ident);
    ev.u.ident.banner_len = strlen(ctx->local_ident);
    (void)chssh_i_push_event(ctx, &ev);
    return 0;
}

static int store_blob(uint8_t **dst, size_t *dst_len, const uint8_t *p,
                      size_t n)
{
    free(*dst);
    *dst = (uint8_t *)malloc(n);
    if (!*dst) {
        *dst_len = 0;
        return -1;
    }
    memcpy(*dst, p, n);
    *dst_len = n;
    return 0;
}

static void maybe_enable_strict_kex(chssh_ctx_t *ctx);

static int send_kexinit(chssh_ctx_t *ctx)
{
    uint8_t pl[512];
    size_t off = 0;
    size_t i;
    const char *kex, *hk, *enc, *mac;

    pl[off++] = CHSSH_MSG_KEXINIT;
    if (ctx->lab_mode) {
        for (i = 0; i < 16; i++) {
            pl[off++] = (uint8_t)(0xA0 + i);
        }
        kex = "chssh-lab-v1";
        hk = "ssh-rsa";
        enc = "none";
        mac = "none";
    } else {
        if (chssh_crypto_random(pl + off, 16) != 0) {
            return -1;
        }
        off += 16;
        /*
         * Client prefers ECDH (Calix E7 server lists ecdh-sha2-nistp256, not
         * always group14). Server lists group14 first for lab dialectic, ECDH
         * second for field gear that prefers it when we are SSH server.
         */
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            /* Include strict-kex client marker for OpenSSH 9+ field gear. */
            kex = "ecdh-sha2-nistp256,diffie-hellman-group14-sha256,"
                  "kex-strict-c-v00@openssh.com";
        } else {
            kex = "diffie-hellman-group14-sha256,ecdh-sha2-nistp256,"
                  "kex-strict-s-v00@openssh.com";
        }
        hk = "rsa-sha2-256,ssh-rsa";
        enc = "aes128-ctr";
        mac = "hmac-sha2-256";
    }
    if (name_list_append(pl, sizeof(pl), &off, kex) != 0 ||
        name_list_append(pl, sizeof(pl), &off, hk) != 0 ||
        name_list_append(pl, sizeof(pl), &off, enc) != 0 ||
        name_list_append(pl, sizeof(pl), &off, enc) != 0 ||
        name_list_append(pl, sizeof(pl), &off, mac) != 0 ||
        name_list_append(pl, sizeof(pl), &off, mac) != 0 ||
        name_list_append(pl, sizeof(pl), &off, "none") != 0 ||
        name_list_append(pl, sizeof(pl), &off, "none") != 0 ||
        name_list_append(pl, sizeof(pl), &off, "") != 0 ||
        name_list_append(pl, sizeof(pl), &off, "") != 0) {
        return -1;
    }
    if (off + 5 > sizeof(pl)) {
        return -1;
    }
    pl[off++] = 0;
    put_u32(pl + off, 0);
    off += 4;

    if (store_blob(&ctx->local_kexinit, &ctx->local_kexinit_len, pl, off) !=
        0) {
        return -1;
    }
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    ctx->kex_sent = 1;
    maybe_enable_strict_kex(ctx);
    return 0;
}

/* Peer offered the matching strict-KEX marker for our role. */
static int peer_offers_strict_kex(const chssh_ctx_t *ctx)
{
    /* Client looks for server marker; server looks for client marker. */
    static const char s[] = "kex-strict-s-v00@openssh.com";
    static const char c[] = "kex-strict-c-v00@openssh.com";
    const char *needle;
    size_t nlen;

    if (!ctx || !ctx->peer_kexinit || ctx->lab_mode) {
        return 0;
    }
    if (ctx->role == CHSSH_ROLE_CLIENT) {
        needle = s;
        nlen = sizeof(s) - 1;
    } else {
        needle = c;
        nlen = sizeof(c) - 1;
    }
    return memmem(ctx->peer_kexinit, ctx->peer_kexinit_len, needle, nlen) !=
           NULL;
}

/** Enable strict KEX once both KEXINITs are known (production only). */
static void maybe_enable_strict_kex(chssh_ctx_t *ctx)
{
    if (!ctx || ctx->lab_mode || !ctx->kex_sent || !ctx->kex_received) {
        return;
    }
    /* We always advertise kex-strict-* in production send_kexinit. */
    ctx->strict_kex = peer_offers_strict_kex(ctx) ? 1 : 0;
}

static int send_newkeys(chssh_ctx_t *ctx)
{
    uint8_t pl[1] = {CHSSH_MSG_NEWKEYS};
    if (chssh_i_send_packet(ctx, pl, 1) != 0) {
        return -1;
    }
    ctx->newkeys_sent = 1;
    /*
     * OpenSSH strict KEX: after sending NEWKEYS, reset send sequence to 0
     * so the first post-NEWKEYS packet (e.g. SERVICE_REQUEST) uses seq 0.
     */
    if (ctx->strict_kex) {
        ctx->send_seq = 0;
    }
    return 0;
}

static int activate_keys_after_newkeys_sent(chssh_ctx_t *ctx)
{
    /* Outbound encryption starts after we send NEWKEYS (production). */
    uint8_t iv_c2s[CHSSH_AES_IV_LEN], iv_s2c[CHSSH_AES_IV_LEN];
    uint8_t key_c2s[CHSSH_AES_KEY_LEN], key_s2c[CHSSH_AES_KEY_LEN];
    uint8_t mac_c2s[CHSSH_MAC_KEY_LEN], mac_s2c[CHSSH_MAC_KEY_LEN];

    if (ctx->lab_mode || ctx->encrypt_out) {
        return 0;
    }
    if (chssh_derive_keys(ctx->K_mpint, ctx->K_len, ctx->H, ctx->session_id,
                          ctx->session_id_len, iv_c2s, iv_s2c, key_c2s, key_s2c,
                          mac_c2s, mac_s2c) != 0) {
        return -1;
    }
    if (ctx->role == CHSSH_ROLE_SERVER) {
        ctx->ciph_out = chssh_cipher_new(key_s2c, iv_s2c, 1);
        memcpy(ctx->mac_key_out, mac_s2c, CHSSH_MAC_KEY_LEN);
        /* inbound cipher created when peer NEWKEYS received */
        ctx->ciph_in = chssh_cipher_new(key_c2s, iv_c2s, 0);
        memcpy(ctx->mac_key_in, mac_c2s, CHSSH_MAC_KEY_LEN);
    } else {
        ctx->ciph_out = chssh_cipher_new(key_c2s, iv_c2s, 1);
        memcpy(ctx->mac_key_out, mac_c2s, CHSSH_MAC_KEY_LEN);
        ctx->ciph_in = chssh_cipher_new(key_s2c, iv_s2c, 0);
        memcpy(ctx->mac_key_in, mac_s2c, CHSSH_MAC_KEY_LEN);
    }
    if (!ctx->ciph_out || !ctx->ciph_in) {
        return -1;
    }
    ctx->encrypt_out = 1;
    return 0;
}

static int on_peer_newkeys(chssh_ctx_t *ctx)
{
    ctx->newkeys_received = 1;
    if (!ctx->lab_mode) {
        ctx->encrypt_in = 1;
    }
    return 0;
}

static int compute_exchange_hash(chssh_ctx_t *ctx, int we_are_client,
                                 const uint8_t *host_key, size_t hk_len,
                                 const uint8_t *e, size_t e_len,
                                 const uint8_t *f, size_t f_len,
                                 const uint8_t *K, size_t K_len)
{
    chssh_hash_ctx_t *h;
    const char *vc = we_are_client ? ctx->local_ident : ctx->peer_ident;
    const char *vs = we_are_client ? ctx->peer_ident : ctx->local_ident;
    const uint8_t *ic =
        we_are_client ? ctx->local_kexinit : ctx->peer_kexinit;
    size_t ic_len =
        we_are_client ? ctx->local_kexinit_len : ctx->peer_kexinit_len;
    const uint8_t *is =
        we_are_client ? ctx->peer_kexinit : ctx->local_kexinit;
    size_t is_len =
        we_are_client ? ctx->peer_kexinit_len : ctx->local_kexinit_len;

    h = chssh_hash_new();
    if (!h) {
        return -1;
    }
    if (chssh_hash_update_cstring(h, vc) != 0 ||
        chssh_hash_update_cstring(h, vs) != 0 ||
        chssh_hash_update_string(h, ic, ic_len) != 0 ||
        chssh_hash_update_string(h, is, is_len) != 0 ||
        chssh_hash_update_string(h, host_key, hk_len) != 0 ||
        chssh_hash_update(h, e, e_len) != 0 || /* e,f,K already mpint-encoded */
        chssh_hash_update(h, f, f_len) != 0 ||
        chssh_hash_update(h, K, K_len) != 0 ||
        chssh_hash_final(h, ctx->H) != 0) {
        chssh_hash_free(h);
        return -1;
    }
    chssh_hash_free(h);
    if (ctx->session_id_len == 0) {
        memcpy(ctx->session_id, ctx->H, CHSSH_HASH_LEN);
        ctx->session_id_len = CHSSH_HASH_LEN;
    }
    return 0;
}

static int server_handle_kexdh_init(chssh_ctx_t *ctx, const uint8_t *p,
                                    size_t len)
{
    uint8_t e_mpint[CHSSH_MAX_MPINT];
    size_t e_len;
    uint8_t f_mpint[CHSSH_MAX_MPINT];
    size_t f_len = 0;
    uint8_t host_blob[CHSSH_MAX_BLOB];
    size_t hk_len = 0;
    uint8_t sig[CHSSH_MAX_SIG];
    size_t sig_len = 0;
    uint8_t *reply = NULL;
    size_t roff = 0;
    uint32_t el;

    if (len < 5 || !ctx->host_key) {
        return -1;
    }
    el = get_u32(p + 1);
    e_len = 4 + el;
    if (1 + e_len > len || e_len > sizeof(e_mpint)) {
        return -1;
    }
    memcpy(e_mpint, p + 1, e_len);

    /* Uncompressed SEC1 P-256 point is 65 bytes starting with 0x04. */
    ctx->use_ecdh = (el == 65 && e_mpint[4] == 0x04) ? 1 : 0;
    if (ctx->use_ecdh) {
        chssh_ecdh_free(ctx->ecdh);
        ctx->ecdh = chssh_ecdh_p256_new();
        if (!ctx->ecdh ||
            chssh_ecdh_public_string(ctx->ecdh, f_mpint, sizeof(f_mpint),
                                     &f_len) != 0 ||
            chssh_ecdh_compute(ctx->ecdh, e_mpint, e_len, ctx->K_mpint,
                               sizeof(ctx->K_mpint), &ctx->K_len) != 0 ||
            chssh_rsa_public_blob(ctx->host_key, host_blob, sizeof(host_blob),
                                  &hk_len) != 0) {
            chssh_i_set_error(ctx, 30, "server ECDH kex failed");
            return -1;
        }
    } else {
        chssh_dh_free(ctx->dh);
        ctx->dh = chssh_dh_new();
        if (!ctx->dh ||
            chssh_dh_gen_public(ctx->dh, f_mpint, sizeof(f_mpint), &f_len) !=
                0 ||
            chssh_dh_compute(ctx->dh, e_mpint, e_len, ctx->K_mpint,
                             sizeof(ctx->K_mpint), &ctx->K_len) != 0 ||
            chssh_rsa_public_blob(ctx->host_key, host_blob, sizeof(host_blob),
                                  &hk_len) != 0) {
            chssh_i_set_error(ctx, 30, "server DH kex failed");
            return -1;
        }
    }
    snprintf(ctx->sig_alg, sizeof(ctx->sig_alg), "%s", "rsa-sha2-256");
    if (compute_exchange_hash(ctx, 0, host_blob, hk_len, e_mpint, e_len, f_mpint,
                              f_len, ctx->K_mpint, ctx->K_len) != 0 ||
        chssh_rsa_sign(ctx->host_key, ctx->sig_alg, ctx->H, CHSSH_HASH_LEN, sig,
                       sizeof(sig), &sig_len) != 0) {
        return -1;
    }

    reply = (uint8_t *)malloc(1 + 4 + hk_len + f_len + sig_len + 16);
    if (!reply) {
        return -1;
    }
    reply[roff++] = CHSSH_MSG_KEXDH_REPLY;
    put_u32(reply + roff, (uint32_t)hk_len);
    roff += 4;
    memcpy(reply + roff, host_blob, hk_len);
    roff += hk_len;
    memcpy(reply + roff, f_mpint, f_len);
    roff += f_len;
    put_u32(reply + roff, (uint32_t)sig_len);
    roff += 4;
    memcpy(reply + roff, sig, sig_len);
    roff += sig_len;

    if (chssh_i_send_packet(ctx, reply, roff) != 0) {
        free(reply);
        return -1;
    }
    free(reply);
    ctx->kexdh_done = 1;
    if (send_newkeys(ctx) != 0 || activate_keys_after_newkeys_sent(ctx) != 0) {
        return -1;
    }
    return 0;
}

static int send_service_and_auth_client(chssh_ctx_t *ctx);
static int mark_channel_ready(chssh_ctx_t *ctx, chssh_channel_t *ch,
                              const char *sub);

static int finish_kex_lab(chssh_ctx_t *ctx)
{
    chssh_event_t ev;
    if (!(ctx->kex_sent && ctx->kex_received)) {
        return 0;
    }
    if (!ctx->newkeys_sent) {
        if (send_newkeys(ctx) != 0) {
            return -1;
        }
    }
    if (ctx->newkeys_sent && ctx->newkeys_received &&
        ctx->state == CHSSH_STATE_KEX) {
        ctx->state = CHSSH_STATE_SERVICE;
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_KEX_COMPLETE;
        (void)chssh_i_push_event(ctx, &ev);
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            return send_service_and_auth_client(ctx);
        }
    }
    return 0;
}

static int client_send_kexdh_init_fixed(chssh_ctx_t *ctx);

static int maybe_start_prod_kex(chssh_ctx_t *ctx)
{
    if (ctx->lab_mode) {
        return finish_kex_lab(ctx);
    }
    if (!(ctx->kex_sent && ctx->kex_received)) {
        return 0;
    }
    if (ctx->role == CHSSH_ROLE_CLIENT && !ctx->kexdh_sent) {
        return client_send_kexdh_init_fixed(ctx);
    }
    return 0;
}

/* ---- service / auth / channel (shared) ---- */

#define CHSSH_AUTH_PEND_NONE         0
#define CHSSH_AUTH_PEND_NONE_METHOD  1
#define CHSSH_AUTH_PEND_PASSWORD     2
#define CHSSH_AUTH_PEND_PK_QUERY     3
#define CHSSH_AUTH_PEND_PK_SIGNED    4

static void free_auth_pending_blob(chssh_ctx_t *ctx)
{
    free(ctx->pk_pending_blob);
    ctx->pk_pending_blob = NULL;
    ctx->pk_pending_blob_len = 0;
    ctx->pk_pending_algo[0] = '\0';
    ctx->pk_pending_fp[0] = '\0';
}

static int client_has_password(const chssh_ctx_t *ctx)
{
    return ctx->cfg.client_password && ctx->cfg.client_password[0];
}

static int client_load_identity(chssh_ctx_t *ctx)
{
    if (ctx->client_identity) {
        return 0;
    }
    if (ctx->cfg.client_private_key_path &&
        ctx->cfg.client_private_key_path[0]) {
        ctx->client_identity =
            chssh_identity_load_file(ctx->cfg.client_private_key_path);
    } else if (ctx->cfg.client_private_key_pem &&
               ctx->cfg.client_private_key_pem[0]) {
        ctx->client_identity = chssh_identity_load_mem(
            ctx->cfg.client_private_key_pem,
            strlen(ctx->cfg.client_private_key_pem));
    }
    return ctx->client_identity ? 0 : -1;
}

static int send_userauth_password(chssh_ctx_t *ctx)
{
    uint8_t pl[512];
    size_t off = 0;
    const char *user =
        ctx->cfg.client_username ? ctx->cfg.client_username : "sysadmin";
    const char *pass =
        ctx->cfg.client_password ? ctx->cfg.client_password : "";
    const char *svc = "ssh-connection";
    const char *method = "password";
    size_t nu = strlen(user), np = strlen(pass), ns = strlen(svc),
           nm = strlen(method);

    pl[off++] = CHSSH_MSG_USERAUTH_REQUEST;
    put_u32(pl + off, (uint32_t)nu);
    off += 4;
    memcpy(pl + off, user, nu);
    off += nu;
    put_u32(pl + off, (uint32_t)ns);
    off += 4;
    memcpy(pl + off, svc, ns);
    off += ns;
    put_u32(pl + off, (uint32_t)nm);
    off += 4;
    memcpy(pl + off, method, nm);
    off += nm;
    pl[off++] = 0;
    put_u32(pl + off, (uint32_t)np);
    off += 4;
    memcpy(pl + off, pass, np);
    off += np;
    ctx->client_auth_stage = 2;
    return chssh_i_send_packet(ctx, pl, off);
}

/**
 * Client: signed publickey USERAUTH_REQUEST (skip bare query; OpenSSH-compatible).
 */
static int send_userauth_publickey(chssh_ctx_t *ctx)
{
    uint8_t pub[CHSSH_PUBKEY_BLOB_MAX];
    size_t pub_len = 0;
    uint8_t signed_msg[2048];
    size_t signed_len = 0;
    uint8_t sig[CHSSH_MAX_SIG + 64];
    size_t sig_len = 0;
    uint8_t pl[CHSSH_PUBKEY_BLOB_MAX + 1024];
    size_t off = 0;
    const char *user =
        ctx->cfg.client_username ? ctx->cfg.client_username : "sysadmin";
    const char *svc = "ssh-connection";
    const char *method = "publickey";
    const char *pk_alg;
    size_t nu, ns, nm, na;

    if (!ctx->client_identity) {
        return -1;
    }
    if (ctx->session_id_len == 0) {
        chssh_i_set_error(ctx, 2, "publickey auth needs session id (prod KEX)");
        return -1;
    }
    pk_alg = chssh_identity_sig_alg(ctx->client_identity);
    if (!pk_alg ||
        chssh_identity_public_blob(ctx->client_identity, pub, sizeof(pub),
                                   &pub_len) != 0) {
        return -1;
    }
    if (chssh_userauth_build_signed_data(
            ctx->session_id, ctx->session_id_len, user, svc, pk_alg, pub,
            pub_len, signed_msg, sizeof(signed_msg), &signed_len) != 0) {
        return -1;
    }
    if (chssh_identity_sign(ctx->client_identity, signed_msg, signed_len, sig,
                            sizeof(sig), &sig_len) != 0) {
        return -1;
    }
    nu = strlen(user);
    ns = strlen(svc);
    nm = strlen(method);
    na = strlen(pk_alg);
    if (1 + 4 + nu + 4 + ns + 4 + nm + 1 + 4 + na + 4 + pub_len + 4 + sig_len >
        sizeof(pl)) {
        return -1;
    }
    pl[off++] = CHSSH_MSG_USERAUTH_REQUEST;
    put_u32(pl + off, (uint32_t)nu);
    off += 4;
    memcpy(pl + off, user, nu);
    off += nu;
    put_u32(pl + off, (uint32_t)ns);
    off += 4;
    memcpy(pl + off, svc, ns);
    off += ns;
    put_u32(pl + off, (uint32_t)nm);
    off += 4;
    memcpy(pl + off, method, nm);
    off += nm;
    pl[off++] = 1; /* TRUE — signature follows */
    put_u32(pl + off, (uint32_t)na);
    off += 4;
    memcpy(pl + off, pk_alg, na);
    off += na;
    put_u32(pl + off, (uint32_t)pub_len);
    off += 4;
    memcpy(pl + off, pub, pub_len);
    off += pub_len;
    put_u32(pl + off, (uint32_t)sig_len);
    off += 4;
    memcpy(pl + off, sig, sig_len);
    off += sig_len;
    ctx->client_auth_stage = 1;
    return chssh_i_send_packet(ctx, pl, off);
}

/** After SERVICE_ACCEPT: publickey first if identity loads, else password. */
static int client_start_userauth(chssh_ctx_t *ctx)
{
    if (client_load_identity(ctx) == 0) {
        if (send_userauth_publickey(ctx) == 0) {
            return 0;
        }
        /* fall through to password if pubkey send failed */
    }
    if (client_has_password(ctx)) {
        return send_userauth_password(ctx);
    }
    chssh_i_set_error(ctx, 2, "no client credentials configured");
    return -1;
}

/** Build FAILURE method name-list from offers. */
static int send_userauth_failure(chssh_ctx_t *ctx, int partial)
{
    char methods[64];
    size_t n = 0;
    uint8_t pl[96];
    size_t off = 0;
    methods[0] = '\0';
    if (ctx->server_offer_publickey) {
        n += (size_t)snprintf(methods + n, sizeof(methods) - n, "%s%s",
                              n ? "," : "", "publickey");
    }
    if (ctx->server_offer_password) {
        n += (size_t)snprintf(methods + n, sizeof(methods) - n, "%s%s",
                              n ? "," : "", "password");
    }
    if (n == 0) {
        /* always advertise something so OpenSSH can discover */
        n = (size_t)snprintf(methods, sizeof(methods), "publickey,password");
    }
    pl[off++] = CHSSH_MSG_USERAUTH_FAILURE;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, methods, n);
    off += n;
    pl[off++] = partial ? 1 : 0;
    return chssh_i_send_packet(ctx, pl, off);
}

static int send_service_and_auth_client(chssh_ctx_t *ctx)
{
    uint8_t pl[64];
    size_t off = 0;
    const char *svc = "ssh-userauth";
    size_t n = strlen(svc);
    pl[off++] = CHSSH_MSG_SERVICE_REQUEST;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, svc, n);
    off += n;
    return chssh_i_send_packet(ctx, pl, off);
}

/* ---- multi-channel helpers (ADR 015) ---- */

static uint32_t default_channel_window(const chssh_ctx_t *ctx)
{
    uint32_t win = (uint32_t)ctx->cfg.max_channel_size;
    if (win == 0) {
        win = (uint32_t)CHSSH_DEFAULT_CHANNEL;
    }
    return win;
}

static chssh_channel_t *channel_by_local(chssh_ctx_t *ctx, uint32_t local_id)
{
    size_t i;
    for (i = 0; i < CHSSH_MAX_CHANNELS; i++) {
        if (ctx->channels[i].state != CHSSH_CH_FREE &&
            ctx->channels[i].local_id == local_id) {
            return &ctx->channels[i];
        }
    }
    return NULL;
}

static chssh_channel_t *channel_alloc(chssh_ctx_t *ctx)
{
    size_t i;
    for (i = 0; i < CHSSH_MAX_CHANNELS; i++) {
        if (ctx->channels[i].state == CHSSH_CH_FREE) {
            memset(&ctx->channels[i], 0, sizeof(ctx->channels[i]));
            return &ctx->channels[i];
        }
    }
    return NULL;
}

static chssh_channel_t *channel_primary_ready(chssh_ctx_t *ctx)
{
    size_t i;
    chssh_channel_t *any = NULL;
    for (i = 0; i < CHSSH_MAX_CHANNELS; i++) {
        if (ctx->channels[i].state == CHSSH_CH_READY) {
            if (strcmp(ctx->channels[i].subsystem, CHSSH_SUBSYSTEM_NETCONF) ==
                0) {
                return &ctx->channels[i];
            }
            if (!any) {
                any = &ctx->channels[i];
            }
        }
    }
    return any;
}

static int subsystem_allowed(const chssh_ctx_t *ctx, const char *name)
{
    int i;
    if (!name || !name[0]) {
        return 0;
    }
    for (i = 0; i < ctx->n_allowed_subsys; i++) {
        if (strcmp(ctx->allowed_subsys[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static void parse_allowed_subsystems(chssh_ctx_t *ctx, const char *csv)
{
    char buf[512];
    char *save = NULL;
    char *tok;
    size_t n;

    ctx->n_allowed_subsys = 0;
    if (!csv || !csv[0]) {
        snprintf(ctx->allowed_subsys[0], sizeof(ctx->allowed_subsys[0]), "%s",
                 CHSSH_SUBSYSTEM_NETCONF);
        ctx->n_allowed_subsys = 1;
        return;
    }
    n = strlen(csv);
    if (n >= sizeof(buf)) {
        n = sizeof(buf) - 1;
    }
    memcpy(buf, csv, n);
    buf[n] = '\0';
    for (tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        if (ctx->n_allowed_subsys >= CHSSH_MAX_ALLOWED_SUBSYS) {
            break;
        }
        snprintf(ctx->allowed_subsys[ctx->n_allowed_subsys],
                 sizeof(ctx->allowed_subsys[0]), "%s", tok);
        ctx->n_allowed_subsys++;
    }
    if (ctx->n_allowed_subsys == 0) {
        snprintf(ctx->allowed_subsys[0], sizeof(ctx->allowed_subsys[0]), "%s",
                 CHSSH_SUBSYSTEM_NETCONF);
        ctx->n_allowed_subsys = 1;
    }
}

static int send_window_adjust_ch(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                 uint32_t bytes)
{
    uint8_t pl[9];
    size_t off = 0;
    if (!ctx || !ch || bytes == 0) {
        return 0;
    }
    pl[off++] = CHSSH_MSG_CHANNEL_WINDOW_ADJUST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, bytes);
    off += 4;
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    ch->local_window += bytes;
    return 0;
}

/** After consuming peer CHANNEL_DATA, replenish RX window when low. */
static int maybe_replenish_local_window(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                        uint32_t consumed)
{
    uint32_t target;
    uint32_t add;
    if (!ctx || !ch || consumed == 0) {
        return 0;
    }
    if (ch->local_window >= consumed) {
        ch->local_window -= consumed;
    } else {
        ch->local_window = 0;
    }
    target = default_channel_window(ctx);
    /*
     * Replenish aggressively for large NETCONF transfers (get-config).
     * Waiting until half-empty stalls peers that buffer multi-MB replies.
     * Top up whenever we drop below 75% of target (or any time window is 0).
     */
    if (ch->local_window > (target - target / 4) && ch->local_window > 0) {
        return 0;
    }
    add = target - ch->local_window;
    if (add == 0) {
        return 0;
    }
    if (add < 32768u && ch->local_window > 65536u) {
        return 0; /* skip tiny top-ups while still comfortably stocked */
    }
    return send_window_adjust_ch(ctx, ch, add);
}

static int send_channel_open_session_slot(chssh_ctx_t *ctx, chssh_channel_t *ch)
{
    uint8_t pl[64];
    size_t off = 0;
    const char *t = "session";
    size_t n = strlen(t);
    uint32_t win = default_channel_window(ctx);

    ch->local_window = win;
    ch->local_max_packet = 32768;
    ch->state = CHSSH_CH_OPENING;
    snprintf(ch->open_type, sizeof(ch->open_type), "session");

    pl[off++] = CHSSH_MSG_CHANNEL_OPEN;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, t, n);
    off += n;
    put_u32(pl + off, ch->local_id);
    off += 4;
    put_u32(pl + off, win);
    off += 4;
    put_u32(pl + off, ch->local_max_packet);
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

static int send_shell_request_ch(chssh_ctx_t *ctx, chssh_channel_t *ch)
{
    uint8_t pl[64];
    size_t off = 0;
    const char *req = "shell";
    size_t nr = strlen(req);
    if (!ch || ch->state != CHSSH_CH_OPEN) {
        return -1;
    }
    ch->pending_shell = 1;
    ch->pending_exec = 0;
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 1; /* want_reply */
    return chssh_i_send_packet(ctx, pl, off);
}

/**
 * CHANNEL_REQUEST "exec" + command string (RFC 4254 §6.5). Used for SCP and
 * stock OpenSSH remote commands.
 */
static int send_exec_request_ch(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                const char *command)
{
    uint8_t pl[32 + CHSSH_CMD_MAX];
    size_t off = 0;
    const char *req = "exec";
    size_t nr = strlen(req);
    size_t nc;
    if (!ch || ch->state != CHSSH_CH_OPEN || !command) {
        return -1;
    }
    nc = strlen(command);
    if (nc == 0 || nc > CHSSH_CMD_MAX) {
        return -1;
    }
    snprintf(ch->exec_command, sizeof(ch->exec_command), "%s", command);
    ch->pending_exec = 1;
    ch->pending_shell = 0;
    ch->is_exec = 1;
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 1; /* want_reply */
    put_u32(pl + off, (uint32_t)nc);
    off += 4;
    memcpy(pl + off, command, nc);
    off += nc;
    return chssh_i_send_packet(ctx, pl, off);
}

/**
 * RFC 4254 pty-req: term, cols, rows, width_px, height_px, modes string.
 * Modes are empty (length 0) — peers ignore for lab/staff reverse shell.
 */
static int send_pty_request_ch(chssh_ctx_t *ctx, chssh_channel_t *ch,
                               const char *term, uint32_t cols, uint32_t rows)
{
    uint8_t pl[160];
    size_t off = 0;
    const char *req = "pty-req";
    size_t nr = strlen(req);
    size_t nt;
    if (!ch || (ch->state != CHSSH_CH_OPEN && ch->state != CHSSH_CH_READY)) {
        return -1;
    }
    if (!term || !term[0]) {
        term = "xterm";
    }
    nt = strlen(term);
    if (nt > CHSSH_TERM_MAX) {
        nt = CHSSH_TERM_MAX;
    }
    if (cols == 0) {
        cols = 80;
    }
    if (rows == 0) {
        rows = 24;
    }
    ch->pending_pty = 1;
    snprintf(ch->term, sizeof(ch->term), "%.*s", (int)nt, term);
    ch->pty_cols = cols;
    ch->pty_rows = rows;
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 1; /* want_reply */
    put_u32(pl + off, (uint32_t)nt);
    off += 4;
    memcpy(pl + off, term, nt);
    off += nt;
    put_u32(pl + off, cols);
    off += 4;
    put_u32(pl + off, rows);
    off += 4;
    put_u32(pl + off, 0); /* width_px */
    off += 4;
    put_u32(pl + off, 0); /* height_px */
    off += 4;
    put_u32(pl + off, 0); /* encoded terminal modes len */
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

static void fill_pty_event(chssh_event_t *ev, chssh_event_type_t type,
                           const chssh_channel_t *ch)
{
    memset(ev, 0, sizeof(*ev));
    ev->type = type;
    ev->u.pty.channel_id = ch->local_id;
    if (ch->term[0]) {
        snprintf(ev->u.pty.term, sizeof(ev->u.pty.term), "%s", ch->term);
    }
    ev->u.pty.cols = ch->pty_cols;
    ev->u.pty.rows = ch->pty_rows;
    ev->u.pty.width_px = ch->pty_width_px;
    ev->u.pty.height_px = ch->pty_height_px;
}

static int send_channel_req_reply(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                  int success)
{
    uint8_t pl[5];
    pl[0] = success ? CHSSH_MSG_CHANNEL_SUCCESS : CHSSH_MSG_CHANNEL_FAILURE;
    put_u32(pl + 1, ch->peer_id);
    return chssh_i_send_packet(ctx, pl, 5);
}

static int send_subsystem_request_ch(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                     const char *sub)
{
    uint8_t pl[128];
    size_t off = 0;
    const char *req = "subsystem";
    size_t nr = strlen(req), ns;
    char name[CHSSH_SUBSYS_NAME_MAX + 1];
    if (!sub || !sub[0]) {
        return -1;
    }
    ns = strlen(sub);
    if (ns > CHSSH_SUBSYS_NAME_MAX) {
        return -1;
    }
    /* Copy first: callers may pass ch->pending_subsystem (no overlap UB). */
    memcpy(name, sub, ns);
    name[ns] = '\0';
    memcpy(ch->pending_subsystem, name, ns + 1);
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 1; /* want_reply */
    put_u32(pl + off, (uint32_t)ns);
    off += 4;
    memcpy(pl + off, name, ns);
    off += ns;
    return chssh_i_send_packet(ctx, pl, off);
}

static int mark_channel_ready(chssh_ctx_t *ctx, chssh_channel_t *ch,
                              const char *sub)
{
    chssh_event_t ev;
    if (!ctx || !ch) {
        return -1;
    }
    ch->state = CHSSH_CH_READY;
    if (sub && sub[0]) {
        snprintf(ch->subsystem, sizeof(ch->subsystem), "%s", sub);
        if (strcmp(sub, "shell") == 0) {
            ch->is_shell = 1;
            ch->is_exec = 0;
        } else if (strcmp(sub, "exec") == 0) {
            ch->is_exec = 1;
            ch->is_shell = 0;
        }
    }
    ch->pending_subsystem[0] = '\0';
    ch->pending_shell = 0;
    ch->pending_exec = 0;
    ch->shell_req_pending = 0;
    ctx->channel_ready = 1;
    ctx->state = CHSSH_STATE_READY;

    if (ch->is_exec) {
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_EXEC;
        ev.u.exec.channel_id = ch->local_id;
        if (ch->exec_command[0]) {
            snprintf(ev.u.exec.command, sizeof(ev.u.exec.command), "%s",
                     ch->exec_command);
        }
        (void)chssh_i_push_event(ctx, &ev);
    } else if (ch->is_shell) {
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_SHELL;
        ev.u.channel.channel_id = ch->local_id;
        snprintf(ev.u.channel.chan_type, sizeof(ev.u.channel.chan_type),
                 "shell-ready");
        (void)chssh_i_push_event(ctx, &ev);
    } else {
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_SUBSYSTEM;
        ev.u.subsystem.channel_id = ch->local_id;
        snprintf(ev.u.subsystem.name, sizeof(ev.u.subsystem.name), "%s",
                 ch->subsystem);
        (void)chssh_i_push_event(ctx, &ev);

        /* E7 compat: READY only for netconf */
        if (strcmp(ch->subsystem, CHSSH_SUBSYSTEM_NETCONF) == 0) {
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_READY;
            (void)chssh_i_push_event(ctx, &ev);
        }
    }
    return 0;
}

static int send_channel_open_failure(chssh_ctx_t *ctx, uint32_t peer_ch,
                                     const char *reason)
{
    uint8_t fail[96];
    size_t fo = 0;
    size_t rn;
    if (!reason) {
        reason = "administratively prohibited";
    }
    rn = strlen(reason);
    if (rn > 48) {
        rn = 48;
    }
    fail[fo++] = CHSSH_MSG_CHANNEL_OPEN_FAILURE;
    put_u32(fail + fo, peer_ch);
    fo += 4;
    put_u32(fail + fo, 1); /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
    fo += 4;
    put_u32(fail + fo, (uint32_t)rn);
    fo += 4;
    memcpy(fail + fo, reason, rn);
    fo += rn;
    put_u32(fail + fo, 0);
    fo += 4;
    return chssh_i_send_packet(ctx, fail, fo);
}

static int send_channel_open_confirm(chssh_ctx_t *ctx, chssh_channel_t *ch)
{
    uint8_t conf[32];
    size_t co = 0;
    conf[co++] = CHSSH_MSG_CHANNEL_OPEN_CONFIRM;
    put_u32(conf + co, ch->peer_id);
    co += 4;
    put_u32(conf + co, ch->local_id);
    co += 4;
    put_u32(conf + co, ch->local_window);
    co += 4;
    put_u32(conf + co, ch->local_max_packet);
    co += 4;
    return chssh_i_send_packet(ctx, conf, co);
}

/** Parse string at p[o], advance o. Returns 0 ok. */
static int parse_ssh_string(const uint8_t *p, size_t len, size_t *o, char *out,
                            size_t out_sz)
{
    uint32_t n;
    if (!o || *o + 4 > len) {
        return -1;
    }
    n = get_u32(p + *o);
    *o += 4;
    if (*o + n > len || n >= out_sz) {
        return -1;
    }
    if (out && out_sz) {
        memcpy(out, p + *o, n);
        out[n] = '\0';
    }
    *o += n;
    return 0;
}

static void fill_tcpip_event(chssh_event_t *ev, chssh_event_type_t type,
                             const chssh_channel_t *ch)
{
    memset(ev, 0, sizeof(*ev));
    ev->type = type;
    ev->u.tcpip.channel_id = ch->local_id;
    snprintf(ev->u.tcpip.dest_host, sizeof(ev->u.tcpip.dest_host), "%s",
             ch->tcpip_dest);
    ev->u.tcpip.dest_port = ch->tcpip_dest_port;
    snprintf(ev->u.tcpip.originator, sizeof(ev->u.tcpip.originator), "%s",
             ch->tcpip_orig);
    ev->u.tcpip.originator_port = ch->tcpip_orig_port;
    snprintf(ev->u.tcpip.chan_type, sizeof(ev->u.tcpip.chan_type), "%s",
             ch->open_type);
}

/**
 * Accept peer CHANNEL_OPEN: session | direct-tcpip | forwarded-tcpip.
 * direct-tcpip is deferred (host dials) until chssh_channel_open_decide.
 * forwarded-tcpip is auto-confirmed (host already accepted reverse conn).
 */
static int accept_session_open(chssh_ctx_t *ctx, const uint8_t *p, size_t len)
{
    size_t o = 1;
    uint32_t n, peer_ch, peer_win, peer_max;
    chssh_channel_t *ch;
    char ctype[32];
    chssh_event_t ev;
    int is_direct = 0;
    int is_forwarded = 0;

    n = get_u32(p + o);
    o += 4;
    if (o + n > len || n >= sizeof(ctype)) {
        return 0;
    }
    memcpy(ctype, p + o, n);
    ctype[n] = '\0';
    o += n;
    if (o + 12 > len) {
        return 0;
    }
    peer_ch = get_u32(p + o);
    o += 4;
    peer_win = get_u32(p + o);
    o += 4;
    peer_max = get_u32(p + o);
    o += 4;

    if (strcmp(ctype, "session") == 0) {
        /* no extra data */
    } else if (strcmp(ctype, "direct-tcpip") == 0) {
        is_direct = 1;
    } else if (strcmp(ctype, "forwarded-tcpip") == 0) {
        is_forwarded = 1;
    } else {
        (void)send_channel_open_failure(ctx, peer_ch, "unknown channel type");
        return 0;
    }

    ch = channel_alloc(ctx);
    if (!ch) {
        (void)send_channel_open_failure(ctx, peer_ch, "no free channels");
        return 0;
    }
    ch->local_id = ctx->next_local_id++;
    ch->peer_id = peer_ch;
    ch->remote_window = peer_win;
    ch->remote_max_packet = peer_max ? peer_max : 32768;
    ch->local_window = default_channel_window(ctx);
    ch->local_max_packet = 32768;
    snprintf(ch->open_type, sizeof(ch->open_type), "%s", ctype);

    if (is_direct || is_forwarded) {
        char host[CHSSH_ADDR_MAX + 1];
        char orig[CHSSH_ADDR_MAX + 1];
        uint32_t dport = 0, oport = 0;
        host[0] = orig[0] = '\0';
        if (parse_ssh_string(p, len, &o, host, sizeof(host)) != 0 ||
            o + 4 > len) {
            memset(ch, 0, sizeof(*ch));
            ch->state = CHSSH_CH_FREE;
            (void)send_channel_open_failure(ctx, peer_ch, "bad tcpip open");
            return 0;
        }
        dport = get_u32(p + o);
        o += 4;
        if (parse_ssh_string(p, len, &o, orig, sizeof(orig)) != 0 ||
            o + 4 > len) {
            memset(ch, 0, sizeof(*ch));
            ch->state = CHSSH_CH_FREE;
            (void)send_channel_open_failure(ctx, peer_ch, "bad tcpip open");
            return 0;
        }
        oport = get_u32(p + o);
        ch->is_tcpip = 1;
        snprintf(ch->tcpip_dest, sizeof(ch->tcpip_dest), "%s", host);
        ch->tcpip_dest_port = dport;
        snprintf(ch->tcpip_orig, sizeof(ch->tcpip_orig), "%s", orig);
        ch->tcpip_orig_port = oport;
    }

    if (is_direct) {
        /* Defer confirm until host dials and decides. */
        ch->state = CHSSH_CH_OPEN;
        ch->open_deferred = 1;
        ctx->state = CHSSH_STATE_CHANNEL;
        fill_tcpip_event(&ev, CHSSH_EVENT_DIRECT_TCPIP, ch);
        (void)chssh_i_push_event(ctx, &ev);
        return 0;
    }

    ch->state = CHSSH_CH_OPEN;
    if (send_channel_open_confirm(ctx, ch) != 0) {
        return -1;
    }
    ctx->state = CHSSH_STATE_CHANNEL;

    if (is_forwarded) {
        ch->state = CHSSH_CH_READY;
        ctx->channel_ready = 1;
        ctx->state = CHSSH_STATE_READY;
        fill_tcpip_event(&ev, CHSSH_EVENT_FORWARDED_TCPIP, ch);
        (void)chssh_i_push_event(ctx, &ev);
        return 0;
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = CHSSH_EVENT_CHANNEL_OPEN;
    ev.u.channel.channel_id = ch->local_id;
    snprintf(ev.u.channel.chan_type, sizeof(ev.u.channel.chan_type), "%s",
             ctype);
    (void)chssh_i_push_event(ctx, &ev);
    return 0;
}

static int on_channel_open_confirm(chssh_ctx_t *ctx, const uint8_t *p,
                                   size_t len)
{
    uint32_t local_id;
    chssh_channel_t *ch;
    chssh_event_t ev;
    if (len < 17) {
        return 0;
    }
    local_id = get_u32(p + 1);
    ch = channel_by_local(ctx, local_id);
    if (!ch || ch->state != CHSSH_CH_OPENING) {
        return 0;
    }
    ch->peer_id = get_u32(p + 5);
    ch->remote_window = get_u32(p + 9);
    ch->remote_max_packet = get_u32(p + 13);
    ch->state = CHSSH_CH_OPEN;

    if (ch->is_tcpip) {
        /* direct/forwarded: data-ready immediately after confirm */
        ch->state = CHSSH_CH_READY;
        ctx->channel_ready = 1;
        ctx->state = CHSSH_STATE_READY;
        fill_tcpip_event(&ev,
                         strcmp(ch->open_type, "forwarded-tcpip") == 0
                             ? CHSSH_EVENT_FORWARDED_TCPIP
                             : CHSSH_EVENT_DIRECT_TCPIP,
                         ch);
        (void)chssh_i_push_event(ctx, &ev);
        return 0;
    }

    memset(&ev, 0, sizeof(ev));
    ev.type = CHSSH_EVENT_CHANNEL_OPEN;
    ev.u.channel.channel_id = ch->local_id;
    snprintf(ev.u.channel.chan_type, sizeof(ev.u.channel.chan_type), "%s",
             ch->open_type[0] ? ch->open_type : "session");
    (void)chssh_i_push_event(ctx, &ev);
    if (ch->pending_subsystem[0]) {
        return send_subsystem_request_ch(ctx, ch, ch->pending_subsystem);
    }
    if (ch->pending_exec && ch->exec_command[0]) {
        return send_exec_request_ch(ctx, ch, ch->exec_command);
    }
    if (ch->pending_shell) {
        return send_shell_request_ch(ctx, ch);
    }
    return 0;
}

/** Legacy: auto-open netconf after client auth (E7). */
static int send_channel_open_session(chssh_ctx_t *ctx)
{
    chssh_channel_t *ch = channel_alloc(ctx);
    if (!ch) {
        chssh_i_set_error(ctx, 20, "no free channel slots");
        return -1;
    }
    ch->local_id = ctx->next_local_id++;
    snprintf(ch->pending_subsystem, sizeof(ch->pending_subsystem), "%s",
             CHSSH_SUBSYSTEM_NETCONF);
    return send_channel_open_session_slot(ctx, ch);
}

static int peer_offers_ecdh_p256(const chssh_ctx_t *ctx)
{
    static const char needle[] = "ecdh-sha2-nistp256";
    if (!ctx || !ctx->peer_kexinit || ctx->peer_kexinit_len < sizeof(needle)) {
        return 0;
    }
    return memmem(ctx->peer_kexinit, ctx->peer_kexinit_len, needle,
                  sizeof(needle) - 1) != NULL;
}

/* Client KEX init: prefer ECDH nistp256 (Calix E7), else group14. */
static int client_send_kexdh_init_fixed(chssh_ctx_t *ctx)
{
    uint8_t pl[CHSSH_MAX_MPINT + 8];
    size_t off = 0;
    size_t pub_len = 0;

    if (ctx->kexdh_sent) {
        return 0;
    }
    /* Prefer ECDH only when peer does not offer group14 (e.g. Calix E7). */
    ctx->use_ecdh = 0;
    if (peer_offers_ecdh_p256(ctx)) {
        static const char g14[] = "diffie-hellman-group14-sha256";
        int has_g14 =
            ctx->peer_kexinit &&
            memmem(ctx->peer_kexinit, ctx->peer_kexinit_len, g14,
                   sizeof(g14) - 1) != NULL;
        ctx->use_ecdh = has_g14 ? 0 : 1;
    }
    if (ctx->use_ecdh) {
        chssh_ecdh_free(ctx->ecdh);
        ctx->ecdh = chssh_ecdh_p256_new();
        if (!ctx->ecdh ||
            chssh_ecdh_public_string(ctx->ecdh, ctx->K_mpint,
                                     sizeof(ctx->K_mpint), &pub_len) != 0) {
            return -1;
        }
        ctx->K_len = pub_len; /* temporarily holds Q_C string */
        pl[off++] = CHSSH_MSG_KEXDH_INIT; /* same id as ECDH_INIT */
        memcpy(pl + off, ctx->K_mpint, pub_len);
        off += pub_len;
    } else {
        chssh_dh_free(ctx->dh);
        ctx->dh = chssh_dh_new();
        if (!ctx->dh ||
            chssh_dh_gen_public(ctx->dh, ctx->K_mpint, sizeof(ctx->K_mpint),
                                &pub_len) != 0) {
            return -1;
        }
        ctx->K_len = pub_len;
        pl[off++] = CHSSH_MSG_KEXDH_INIT;
        memcpy(pl + off, ctx->K_mpint, pub_len);
        off += pub_len;
    }
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    ctx->kexdh_sent = 1;
    return 0;
}

static int client_handle_kexdh_reply_fixed(chssh_ctx_t *ctx, const uint8_t *p,
                                           size_t len)
{
    size_t off = 1;
    uint32_t hk_len, fl, sig_len;
    const uint8_t *host_blob;
    const uint8_t *f_mpint;
    size_t f_len;
    const uint8_t *sig;
    uint8_t e_copy[CHSSH_MAX_MPINT];
    size_t e_len;
    chssh_event_t ev;

    /* ECDH path uses ctx->ecdh (ctx->dh is NULL); DH path uses ctx->dh. */
    if (len < 9 || ctx->K_len == 0) {
        chssh_i_set_error(ctx, 22, "kex reply: empty state");
        return -1;
    }
    if (ctx->use_ecdh) {
        if (!ctx->ecdh) {
            chssh_i_set_error(ctx, 22, "kex reply: missing ECDH state");
            return -1;
        }
    } else if (!ctx->dh) {
        chssh_i_set_error(ctx, 22, "kex reply: missing DH state");
        return -1;
    }
    e_len = ctx->K_len;
    if (e_len > sizeof(e_copy)) {
        chssh_i_set_error(ctx, 22, "kex reply: Q_C too large");
        return -1;
    }
    memcpy(e_copy, ctx->K_mpint, e_len);

    hk_len = get_u32(p + off);
    off += 4;
    if (off + hk_len + 4 > len) {
        chssh_i_set_error(ctx, 22, "kex reply: truncated host key");
        return -1;
    }
    host_blob = p + off;
    off += hk_len;
    fl = get_u32(p + off);
    f_len = 4 + fl;
    if (off + f_len + 4 > len) {
        chssh_i_set_error(ctx, 22, "kex reply: truncated Q_S/f");
        return -1;
    }
    f_mpint = p + off;
    off += f_len;
    sig_len = get_u32(p + off);
    off += 4;
    if (off + sig_len > len) {
        chssh_i_set_error(ctx, 22, "kex reply: truncated signature");
        return -1;
    }
    sig = p + off;

    if (ctx->use_ecdh) {
        if (chssh_ecdh_compute(ctx->ecdh, f_mpint, f_len, ctx->K_mpint,
                               sizeof(ctx->K_mpint), &ctx->K_len) != 0) {
            chssh_i_set_error(ctx, 22, "ECDH compute failed");
            return -1;
        }
    } else {
        if (chssh_dh_compute(ctx->dh, f_mpint, f_len, ctx->K_mpint,
                             sizeof(ctx->K_mpint), &ctx->K_len) != 0) {
            chssh_i_set_error(ctx, 22, "DH compute failed");
            return -1;
        }
    }
    /* ECDH and DH: H = HASH(V_C||V_S||I_C||I_S||K_S||Q_C||Q_S||K) */
    if (compute_exchange_hash(ctx, 1, host_blob, hk_len, e_copy, e_len, f_mpint,
                              f_len, ctx->K_mpint, ctx->K_len) != 0) {
        chssh_i_set_error(ctx, 22, "exchange hash failed");
        return -1;
    }
    if (chssh_rsa_verify(host_blob, hk_len, sig, sig_len, ctx->H,
                         CHSSH_HASH_LEN) != 0) {
        chssh_i_set_error(ctx, 21, "host key signature verify failed");
        return -1;
    }
    ctx->kexdh_done = 1;
    if (send_newkeys(ctx) != 0 || activate_keys_after_newkeys_sent(ctx) != 0) {
        chssh_i_set_error(ctx, 22, "NEWKEYS / activate keys failed");
        return -1;
    }
    if (ctx->newkeys_received) {
        ctx->state = CHSSH_STATE_SERVICE;
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_KEX_COMPLETE;
        (void)chssh_i_push_event(ctx, &ev);
        return send_service_and_auth_client(ctx);
    }
    return 0;
}

static int handle_payload(chssh_ctx_t *ctx, const uint8_t *p, size_t len)
{
    uint8_t type;
    chssh_event_t ev;

    if (len < 1) {
        return 0;
    }
    type = p[0];

    switch (type) {
    case CHSSH_MSG_DISCONNECT: {
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_DISCONNECTED;
        (void)chssh_i_push_event(ctx, &ev);
        ctx->state = CHSSH_STATE_CLOSED;
        return 0;
    }
    case CHSSH_MSG_IGNORE:
    case CHSSH_MSG_DEBUG:
        return 0;
    case CHSSH_MSG_REQUEST_SUCCESS:
        if (ctx->pending_tcpip_forward) {
            ctx->pending_tcpip_forward = 0;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_TCPIP_FORWARD_OK;
            snprintf(ev.u.forward.addr, sizeof(ev.u.forward.addr), "%s",
                     ctx->pending_forward_addr);
            if (len >= 5) {
                /* RFC 4254: bound port when request port was 0 */
                ev.u.forward.port = get_u32(p + 1);
            } else {
                ev.u.forward.port = ctx->pending_forward_port;
            }
            if (ev.u.forward.port == 0) {
                ev.u.forward.port = ctx->pending_forward_port;
            }
            (void)chssh_i_push_event(ctx, &ev);
        }
        return 0;
    case CHSSH_MSG_REQUEST_FAILURE:
        if (ctx->pending_tcpip_forward) {
            ctx->pending_tcpip_forward = 0;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_TCPIP_FORWARD_FAIL;
            snprintf(ev.u.forward.addr, sizeof(ev.u.forward.addr), "%s",
                     ctx->pending_forward_addr);
            ev.u.forward.port = ctx->pending_forward_port;
            (void)chssh_i_push_event(ctx, &ev);
        }
        return 0;
    case CHSSH_MSG_GLOBAL_REQUEST:
        /*
         * tcpip-forward / cancel-tcpip-forward → host (socket-free library).
         * Other names (keepalive, hostkeys-00@openssh.com): FAILURE if want_reply.
         */
        if (len >= 6) {
            uint32_t nlen = get_u32(p + 1);
            size_t o = 5;
            char name[64];
            uint8_t want;
            if (o + nlen > len || nlen >= sizeof(name)) {
                return 0;
            }
            memcpy(name, p + o, nlen);
            name[nlen] = '\0';
            o += nlen;
            if (o >= len) {
                return 0;
            }
            want = p[o++];
            if (strcmp(name, "tcpip-forward") == 0 ||
                strcmp(name, "cancel-tcpip-forward") == 0) {
                char addr[CHSSH_ADDR_MAX + 1];
                uint32_t port = 0;
                addr[0] = '\0';
                if (parse_ssh_string(p, len, &o, addr, sizeof(addr)) != 0 ||
                    o + 4 > len) {
                    if (want) {
                        uint8_t rep[1] = {CHSSH_MSG_REQUEST_FAILURE};
                        (void)chssh_i_send_packet(ctx, rep, 1);
                    }
                    return 0;
                }
                port = get_u32(p + o);
                if (ctx->global_req_pending) {
                    /* one outstanding decision */
                    if (want) {
                        uint8_t rep[1] = {CHSSH_MSG_REQUEST_FAILURE};
                        (void)chssh_i_send_packet(ctx, rep, 1);
                    }
                    return 0;
                }
                ctx->global_req_pending =
                    (strcmp(name, "tcpip-forward") == 0) ? 1 : 2;
                ctx->global_req_want_reply = want ? 1 : 0;
                snprintf(ctx->global_req_addr, sizeof(ctx->global_req_addr),
                         "%s", addr);
                ctx->global_req_port = port;
                memset(&ev, 0, sizeof(ev));
                ev.type = (ctx->global_req_pending == 1)
                              ? CHSSH_EVENT_TCPIP_FORWARD
                              : CHSSH_EVENT_TCPIP_FORWARD_CANCEL;
                snprintf(ev.u.forward.addr, sizeof(ev.u.forward.addr), "%s",
                         addr);
                ev.u.forward.port = port;
                ev.u.forward.want_reply = want ? 1 : 0;
                (void)chssh_i_push_event(ctx, &ev);
                return 0;
            }
            if (want) {
                uint8_t rep[1] = {CHSSH_MSG_REQUEST_FAILURE};
                (void)chssh_i_send_packet(ctx, rep, 1);
            }
        }
        return 0;
    case CHSSH_MSG_KEXINIT:
        if (store_blob(&ctx->peer_kexinit, &ctx->peer_kexinit_len, p, len) !=
            0) {
            return -1;
        }
        ctx->kex_received = 1;
        if (!ctx->kex_sent && ctx->ident_flushed && ctx->peer_ident_seen) {
            if (send_kexinit(ctx) != 0) {
                return -1;
            }
        }
        maybe_enable_strict_kex(ctx);
        if (ctx->lab_mode) {
            return finish_kex_lab(ctx);
        }
        return maybe_start_prod_kex(ctx);
    case CHSSH_MSG_NEWKEYS:
        if (on_peer_newkeys(ctx) != 0) {
            return -1;
        }
        if (ctx->lab_mode) {
            return finish_kex_lab(ctx);
        }
        if (ctx->kexdh_done && ctx->newkeys_sent && ctx->newkeys_received) {
            if (ctx->state == CHSSH_STATE_KEX) {
                ctx->state = CHSSH_STATE_SERVICE;
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_KEX_COMPLETE;
                (void)chssh_i_push_event(ctx, &ev);
                if (ctx->role == CHSSH_ROLE_CLIENT) {
                    return send_service_and_auth_client(ctx);
                }
            }
        }
        return 0;
    case CHSSH_MSG_KEXDH_INIT:
        if (!ctx->lab_mode && ctx->role == CHSSH_ROLE_SERVER) {
            return server_handle_kexdh_init(ctx, p, len);
        }
        return 0;
    case CHSSH_MSG_KEXDH_REPLY:
        if (!ctx->lab_mode && ctx->role == CHSSH_ROLE_CLIENT) {
            if (client_handle_kexdh_reply_fixed(ctx, p, len) != 0) {
                if (!ctx->error) {
                    chssh_i_set_error(ctx, 22, "KEXDH/ECDH reply handling failed");
                }
                return -1;
            }
            return 0;
        }
        return 0;
    case CHSSH_MSG_SERVICE_REQUEST:
        if (ctx->role == CHSSH_ROLE_SERVER && len >= 5) {
            uint8_t out[64];
            size_t o = 0;
            uint32_t n = get_u32(p + 1);
            out[o++] = CHSSH_MSG_SERVICE_ACCEPT;
            if (1 + 4 + n <= len) {
                put_u32(out + o, n);
                o += 4;
                memcpy(out + o, p + 5, n);
                o += n;
            }
            if (chssh_i_send_packet(ctx, out, o) != 0) {
                return -1;
            }
            ctx->state = CHSSH_STATE_AUTH;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_SERVICE_ACCEPTED;
            (void)chssh_i_push_event(ctx, &ev);
        }
        return 0;
    case CHSSH_MSG_SERVICE_ACCEPT:
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            ctx->state = CHSSH_STATE_AUTH;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_SERVICE_ACCEPTED;
            (void)chssh_i_push_event(ctx, &ev);
            return client_start_userauth(ctx);
        }
        return 0;
    case CHSSH_MSG_USERAUTH_REQUEST:
        if (ctx->role != CHSSH_ROLE_SERVER || len < 5) {
            return 0;
        }
        {
            size_t o = 1;
            uint32_t ulen, slen, mlen;
            char method[32];
            if (ctx->auth_pending) {
                /* previous still waiting decide — reject new */
                return send_userauth_failure(ctx, 0);
            }
            ctx->server_auth_attempts++;
            if (ctx->server_auth_attempts > ctx->server_max_auth_attempts) {
                chssh_i_set_error(ctx, 2, "too many auth attempts");
                return -1;
            }
            free_auth_pending_blob(ctx);
            ulen = get_u32(p + o);
            o += 4;
            if (o + ulen > len || ulen >= CHSSH_USER_MAX) {
                return 0;
            }
            memcpy(ctx->pending_user, p + o, ulen);
            ctx->pending_user[ulen] = '\0';
            o += ulen;
            slen = get_u32(p + o);
            o += 4 + slen;
            if (o + 4 > len) {
                return 0;
            }
            mlen = get_u32(p + o);
            o += 4;
            if (o + mlen > len || mlen >= sizeof(method)) {
                return 0;
            }
            memcpy(method, p + o, mlen);
            method[mlen] = '\0';
            o += mlen;
            ctx->pending_pass[0] = '\0';
            ctx->pending_is_none = 0;
            ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE;

            if (strcmp(method, "none") == 0) {
                ctx->pending_is_none = 1;
                ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE_METHOD;
                ctx->auth_pending = 1;
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_AUTH_NONE;
                snprintf(ev.u.auth.username, sizeof(ev.u.auth.username), "%s",
                         ctx->pending_user);
                (void)chssh_i_push_event(ctx, &ev);
                {
                    int accept = ctx->cfg.allow_none_auth ? 1 : 0;
                    (void)chssh_auth_decide(ctx, accept);
                }
                return 0;
            }

            if (strcmp(method, "password") == 0) {
                if (o + 1 + 4 <= len) {
                    uint32_t plen;
                    o += 1; /* boolean FALSE */
                    plen = get_u32(p + o);
                    o += 4;
                    if (o + plen <= len && plen < CHSSH_PASS_MAX) {
                        memcpy(ctx->pending_pass, p + o, plen);
                        ctx->pending_pass[plen] = '\0';
                    }
                }
                ctx->auth_pend_kind = CHSSH_AUTH_PEND_PASSWORD;
                ctx->auth_pending = 1;
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_AUTH_PASSWORD;
                snprintf(ev.u.auth.username, sizeof(ev.u.auth.username), "%s",
                         ctx->pending_user);
                snprintf(ev.u.auth.password, sizeof(ev.u.auth.password), "%s",
                         ctx->pending_pass);
                (void)chssh_i_push_event(ctx, &ev);
                if (ctx->cfg.server_password) {
                    int user_ok = 1;
                    int accept;
                    if (ctx->cfg.server_username &&
                        ctx->cfg.server_username[0]) {
                        user_ok = strcmp(ctx->pending_user,
                                         ctx->cfg.server_username) == 0;
                    }
                    accept = user_ok && strcmp(ctx->pending_pass,
                                               ctx->cfg.server_password) == 0;
                    (void)chssh_auth_decide(ctx, accept);
                }
                return 0;
            }

            if (strcmp(method, "publickey") == 0) {
                uint8_t has_sig;
                uint32_t alglen, bloblen, siglen;
                const char *algo;
                const uint8_t *blob;
                const uint8_t *sig;
                chssh_pubkey_alg_t palg;
                if (!ctx->server_offer_publickey || o + 1 + 4 > len) {
                    return send_userauth_failure(ctx, 0);
                }
                has_sig = p[o++];
                alglen = get_u32(p + o);
                o += 4;
                if (o + alglen + 4 > len || alglen >= CHSSH_ALGO_MAX) {
                    return send_userauth_failure(ctx, 0);
                }
                algo = (const char *)(p + o);
                o += alglen;
                bloblen = get_u32(p + o);
                o += 4;
                if (o + bloblen > len || bloblen == 0 ||
                    bloblen > CHSSH_PUBKEY_BLOB_MAX) {
                    return send_userauth_failure(ctx, 0);
                }
                blob = p + o;
                o += bloblen;
                if (chssh_pubkey_blob_parse(blob, bloblen, &palg) != 0) {
                    return send_userauth_failure(ctx, 0);
                }
                free_auth_pending_blob(ctx);
                ctx->pk_pending_blob = (uint8_t *)malloc(bloblen);
                if (!ctx->pk_pending_blob) {
                    return -1;
                }
                memcpy(ctx->pk_pending_blob, blob, bloblen);
                ctx->pk_pending_blob_len = bloblen;
                memcpy(ctx->pk_pending_algo, algo, alglen);
                ctx->pk_pending_algo[alglen] = '\0';
                if (chssh_pubkey_fingerprint_sha256(
                        blob, bloblen, ctx->pk_pending_fp) != 0) {
                    free_auth_pending_blob(ctx);
                    return send_userauth_failure(ctx, 0);
                }

                if (!has_sig) {
                    /* Query path — no crypto; host inventory check */
                    ctx->auth_pend_kind = CHSSH_AUTH_PEND_PK_QUERY;
                    ctx->auth_pending = 1;
                    memset(&ev, 0, sizeof(ev));
                    ev.type = CHSSH_EVENT_AUTH_PUBLICKEY;
                    snprintf(ev.u.auth_pk.username,
                             sizeof(ev.u.auth_pk.username), "%s",
                             ctx->pending_user);
                    snprintf(ev.u.auth_pk.algo, sizeof(ev.u.auth_pk.algo), "%s",
                             ctx->pk_pending_algo);
                    ev.u.auth_pk.public_blob = ctx->pk_pending_blob;
                    ev.u.auth_pk.public_blob_len = ctx->pk_pending_blob_len;
                    snprintf(ev.u.auth_pk.fingerprint_sha256,
                             sizeof(ev.u.auth_pk.fingerprint_sha256), "%s",
                             ctx->pk_pending_fp);
                    ev.u.auth_pk.signature_present = 0;
                    (void)chssh_i_push_event(ctx, &ev);
                    return 0;
                }

                /* Signed path — verify before host event (K11) */
                if (o + 4 > len) {
                    free_auth_pending_blob(ctx);
                    return send_userauth_failure(ctx, 0);
                }
                siglen = get_u32(p + o);
                o += 4;
                if (o + siglen > len || siglen == 0) {
                    free_auth_pending_blob(ctx);
                    return send_userauth_failure(ctx, 0);
                }
                sig = p + o;
                {
                    uint8_t signed_msg[2048];
                    size_t signed_len = 0;
                    const char *pk_alg = ctx->pk_pending_algo;
                    /* Map wire type ssh-rsa blob + rsa-sha2-256 sig alg */
                    if (ctx->session_id_len == 0 ||
                        chssh_userauth_build_signed_data(
                            ctx->session_id, ctx->session_id_len,
                            ctx->pending_user, "ssh-connection", pk_alg,
                            ctx->pk_pending_blob, ctx->pk_pending_blob_len,
                            signed_msg, sizeof(signed_msg),
                            &signed_len) != 0 ||
                        chssh_userauth_verify(pk_alg, ctx->pk_pending_blob,
                                              ctx->pk_pending_blob_len, sig,
                                              siglen, signed_msg,
                                              signed_len) != 0) {
                        free_auth_pending_blob(ctx);
                        return send_userauth_failure(ctx, 0);
                    }
                }
                ctx->auth_pend_kind = CHSSH_AUTH_PEND_PK_SIGNED;
                ctx->auth_pending = 1;
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_AUTH_PUBLICKEY;
                snprintf(ev.u.auth_pk.username, sizeof(ev.u.auth_pk.username),
                         "%s", ctx->pending_user);
                snprintf(ev.u.auth_pk.algo, sizeof(ev.u.auth_pk.algo), "%s",
                         ctx->pk_pending_algo);
                ev.u.auth_pk.public_blob = ctx->pk_pending_blob;
                ev.u.auth_pk.public_blob_len = ctx->pk_pending_blob_len;
                snprintf(ev.u.auth_pk.fingerprint_sha256,
                         sizeof(ev.u.auth_pk.fingerprint_sha256), "%s",
                         ctx->pk_pending_fp);
                ev.u.auth_pk.signature_present = 1;
                (void)chssh_i_push_event(ctx, &ev);
                return 0;
            }

            /* unknown method */
            return send_userauth_failure(ctx, 0);
        }
    case CHSSH_MSG_USERAUTH_SUCCESS:
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            ctx->auth_ok = 1;
            ctx->state = CHSSH_STATE_CHANNEL;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_AUTHENTICATED;
            (void)chssh_i_push_event(ctx, &ev);
            if (ctx->auto_open_netconf) {
                return send_channel_open_session(ctx);
            }
        }
        return 0;
    case CHSSH_MSG_USERAUTH_FAILURE:
        if (ctx->role != CHSSH_ROLE_CLIENT) {
            return 0;
        }
        /* Dual-auth: after publickey fail, try password once if configured. */
        if (ctx->client_auth_stage == 1 && client_has_password(ctx)) {
            return send_userauth_password(ctx);
        }
        chssh_i_set_error(ctx, 2, "userauth failure");
        return -1;
    case CHSSH_MSG_USERAUTH_PK_OK:
        /* Client sent signed-only requests; PK_OK unused. Ignore. */
        return 0;
    case CHSSH_MSG_CHANNEL_OPEN:
        /* Either role may receive session opens (staff shell: server→client). */
        if (len >= 5) {
            return accept_session_open(ctx, p, len);
        }
        return 0;
    case CHSSH_MSG_CHANNEL_OPEN_CONFIRM:
        return on_channel_open_confirm(ctx, p, len);
    case CHSSH_MSG_CHANNEL_WINDOW_ADJUST:
        if (len >= 9) {
            uint32_t local_id = get_u32(p + 1);
            uint32_t add = get_u32(p + 5);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (ch) {
                ch->remote_window += add;
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_REQUEST:
        if (len >= 10) {
            size_t o = 1;
            uint32_t local_id, rn;
            char req[32];
            uint8_t want;
            chssh_channel_t *ch;
            local_id = get_u32(p + o);
            o += 4;
            ch = channel_by_local(ctx, local_id);
            rn = get_u32(p + o);
            o += 4;
            if (!ch || o + rn > len || rn >= sizeof(req)) {
                return 0;
            }
            memcpy(req, p + o, rn);
            req[rn] = '\0';
            o += rn;
            want = p[o++];
            if (strcmp(req, "subsystem") == 0 && o + 4 <= len) {
                /*
                 * SERVER: staff/client requests sftp|tun|tap|edge-*.
                 * CLIENT: peer (edgehost) requests sftp|tun|tap toward CPE.
                 * Both enforce allowed_subsystems allowlist.
                 */
                uint32_t sn = get_u32(p + o);
                o += 4;
                if (o + sn <= len && sn <= CHSSH_SUBSYS_NAME_MAX) {
                    char sub[CHSSH_SUBSYS_NAME_MAX + 1];
                    memcpy(sub, p + o, sn);
                    sub[sn] = '\0';
                    if (subsystem_allowed(ctx, sub)) {
                        if (want &&
                            send_channel_req_reply(ctx, ch, 1) != 0) {
                            return -1;
                        }
                        return mark_channel_ready(ctx, ch, sub);
                    }
                    if (want) {
                        (void)send_channel_req_reply(ctx, ch, 0);
                    }
                }
            } else if (strcmp(req, "shell") == 0) {
                /* Interactive shell (staff reverse / OpenSSH login). */
                ch->shell_req_pending = 1;
                ch->shell_want_reply = want ? 1 : 0;
                ch->is_exec = 0;
                ch->exec_command[0] = '\0';
                if (ctx->auto_accept_shell) {
                    if (want && send_channel_req_reply(ctx, ch, 1) != 0) {
                        return -1;
                    }
                    return mark_channel_ready(ctx, ch, "shell");
                }
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_SHELL;
                ev.u.channel.channel_id = ch->local_id;
                snprintf(ev.u.channel.chan_type, sizeof(ev.u.channel.chan_type),
                         "shell");
                (void)chssh_i_push_event(ctx, &ev);
            } else if (strcmp(req, "exec") == 0) {
                /*
                 * OpenSSH remote command / SCP. Parse command string; do not
                 * collapse to shell (SCP needs pipes, not a PTY).
                 */
                uint32_t cn = 0;
                ch->shell_req_pending = 1;
                ch->shell_want_reply = want ? 1 : 0;
                ch->is_exec = 1;
                ch->exec_command[0] = '\0';
                if (o + 4 <= len) {
                    cn = get_u32(p + o);
                    o += 4;
                    if (o + cn <= len && cn > 0 && cn <= CHSSH_CMD_MAX) {
                        memcpy(ch->exec_command, p + o, cn);
                        ch->exec_command[cn] = '\0';
                    }
                }
                if (ctx->auto_accept_shell) {
                    if (want && send_channel_req_reply(ctx, ch, 1) != 0) {
                        return -1;
                    }
                    return mark_channel_ready(ctx, ch, "exec");
                }
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_EXEC;
                ev.u.exec.channel_id = ch->local_id;
                if (ch->exec_command[0]) {
                    snprintf(ev.u.exec.command, sizeof(ev.u.exec.command), "%s",
                             ch->exec_command);
                }
                (void)chssh_i_push_event(ctx, &ev);
            } else if (strcmp(req, "pty-req") == 0) {
                /*
                 * OpenSSH interactive clients always send pty-req with
                 * want_reply=1 before shell. Must reply or client hangs.
                 */
                uint32_t tn = 0;
                uint32_t cols = 80, rows = 24, wpx = 0, hpx = 0;
                char term[CHSSH_TERM_MAX + 1];
                term[0] = '\0';
                if (o + 4 <= len) {
                    tn = get_u32(p + o);
                    o += 4;
                    if (o + tn <= len && tn > 0) {
                        size_t copy = tn > CHSSH_TERM_MAX ? CHSSH_TERM_MAX : tn;
                        memcpy(term, p + o, copy);
                        term[copy] = '\0';
                        o += tn;
                    }
                    if (o + 16 <= len) {
                        cols = get_u32(p + o);
                        o += 4;
                        rows = get_u32(p + o);
                        o += 4;
                        wpx = get_u32(p + o);
                        o += 4;
                        hpx = get_u32(p + o);
                        o += 4;
                    }
                    /* skip encoded terminal modes string if present */
                }
                if (cols == 0) {
                    cols = 80;
                }
                if (rows == 0) {
                    rows = 24;
                }
                if (ctx->auto_accept_pty) {
                    ch->has_pty = 1;
                    ch->pty_cols = cols;
                    ch->pty_rows = rows;
                    ch->pty_width_px = wpx;
                    ch->pty_height_px = hpx;
                    if (term[0]) {
                        snprintf(ch->term, sizeof(ch->term), "%s", term);
                    }
                    if (want && send_channel_req_reply(ctx, ch, 1) != 0) {
                        return -1;
                    }
                    fill_pty_event(&ev, CHSSH_EVENT_PTY, ch);
                    (void)chssh_i_push_event(ctx, &ev);
                } else if (want) {
                    (void)send_channel_req_reply(ctx, ch, 0);
                }
            } else if (strcmp(req, "window-change") == 0) {
                if (o + 16 <= len) {
                    ch->pty_cols = get_u32(p + o);
                    o += 4;
                    ch->pty_rows = get_u32(p + o);
                    o += 4;
                    ch->pty_width_px = get_u32(p + o);
                    o += 4;
                    ch->pty_height_px = get_u32(p + o);
                    if (ch->pty_cols == 0) {
                        ch->pty_cols = 80;
                    }
                    if (ch->pty_rows == 0) {
                        ch->pty_rows = 24;
                    }
                    fill_pty_event(&ev, CHSSH_EVENT_WINDOW_CHANGE, ch);
                    (void)chssh_i_push_event(ctx, &ev);
                }
                if (want && send_channel_req_reply(ctx, ch, 1) != 0) {
                    return -1;
                }
            } else if (strcmp(req, "env") == 0) {
                /* Accept env requests so OpenSSH clients do not hang. */
                if (want && send_channel_req_reply(ctx, ch, 1) != 0) {
                    return -1;
                }
            } else {
                /*
                 * Unknown channel request: always answer want_reply.
                 * Silent drop is the historic OpenSSH hang source for pty-req
                 * before this path handled it; keep discipline for the rest.
                 */
                if (want) {
                    (void)send_channel_req_reply(ctx, ch, 0);
                }
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_SUCCESS:
        if (len >= 5) {
            uint32_t local_id = get_u32(p + 1);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (!ch) {
                return 0;
            }
            if (ch->pending_pty) {
                ch->pending_pty = 0;
                ch->has_pty = 1;
                fill_pty_event(&ev, CHSSH_EVENT_PTY, ch);
                (void)chssh_i_push_event(ctx, &ev);
                return 0;
            }
            if (ch->pending_shell) {
                return mark_channel_ready(ctx, ch, "shell");
            }
            if (ch->pending_exec) {
                return mark_channel_ready(ctx, ch, "exec");
            }
            if (ch->pending_subsystem[0] || ctx->role == CHSSH_ROLE_CLIENT) {
                const char *sub = ch->pending_subsystem[0]
                                      ? ch->pending_subsystem
                                      : CHSSH_SUBSYSTEM_NETCONF;
                return mark_channel_ready(ctx, ch, sub);
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_FAILURE:
        if (len >= 5) {
            uint32_t local_id = get_u32(p + 1);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (ch) {
                ch->pending_shell = 0;
                ch->pending_exec = 0;
                ch->pending_subsystem[0] = '\0';
            }
            chssh_i_set_error(ctx, 21, "channel request failure");
            return -1;
        }
        return 0;
    case CHSSH_MSG_CHANNEL_DATA:
        if (len >= 9) {
            uint32_t local_id = get_u32(p + 1);
            uint32_t dlen = get_u32(p + 5);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (ch && 9 + dlen <= len && dlen <= CHSSH_DATA_MAX) {
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_CHANNEL_DATA;
                ev.u.data.channel_id = ch->local_id;
                memcpy(ev.u.data.data, p + 9, dlen);
                ev.u.data.len = dlen;
                (void)chssh_i_push_event(ctx, &ev);
                /* RFC 4254: consumer must WINDOW_ADJUST or peer stalls/closes. */
                if (maybe_replenish_local_window(ctx, ch, dlen) != 0) {
                    return -1;
                }
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_EOF:
        if (len >= 5) {
            uint32_t local_id = get_u32(p + 1);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (ch) {
                ch->state = CHSSH_CH_EOF_RCVD;
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_CHANNEL_EOF;
                ev.u.channel.channel_id = ch->local_id;
                (void)chssh_i_push_event(ctx, &ev);
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_CLOSE:
        if (len >= 5) {
            uint32_t local_id = get_u32(p + 1);
            chssh_channel_t *ch = channel_by_local(ctx, local_id);
            if (ch) {
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_CHANNEL_CLOSE;
                ev.u.channel.channel_id = ch->local_id;
                (void)chssh_i_push_event(ctx, &ev);
                memset(ch, 0, sizeof(*ch));
                ch->state = CHSSH_CH_FREE;
            }
        }
        return 0;
    default:
        return 0;
    }
}

static int parse_one_packet(chssh_ctx_t *ctx)
{
    size_t avail = ctx->in_len - ctx->in_pos;
    const uint8_t *base = ctx->in_buf + ctx->in_pos;
    uint32_t packet_len;
    size_t total;
    uint8_t padding;
    size_t payload_len;
    const uint8_t *payload;

    if (ctx->encrypt_in) {
        chssh_cipher_t *peek;
        uint8_t *work;
        size_t need;
        uint8_t mac_calc[CHSSH_MAC_LEN];
        uint8_t *mac_in;
        size_t mac_len;

        if (avail < 4 || !ctx->ciph_in) {
            return 0;
        }
        /* Peek packet_length without advancing real CTR state. */
        peek = chssh_cipher_dup(ctx->ciph_in);
        if (!peek) {
            return -1;
        }
        {
            uint8_t lenb[4];
            memcpy(lenb, base, 4);
            if (chssh_cipher_crypt(peek, lenb, 4) != 0) {
                chssh_cipher_free(peek);
                return -1;
            }
            packet_len = get_u32(lenb);
            chssh_cipher_free(peek);
        }
        if (packet_len < 5 || packet_len > ctx->cfg.max_packet_size) {
            chssh_i_set_error(ctx, 3, "bad encrypted packet_length");
            return -1;
        }
        total = 4 + packet_len;
        need = total + CHSSH_MAC_LEN;
        if (avail < need) {
            return 0;
        }
        work = (uint8_t *)malloc(total);
        if (!work) {
            return -1;
        }
        memcpy(work, base, total);
        if (chssh_cipher_crypt(ctx->ciph_in, work, total) != 0) {
            free(work);
            return -1;
        }
        mac_len = 4 + total;
        mac_in = (uint8_t *)malloc(mac_len);
        if (!mac_in) {
            free(work);
            return -1;
        }
        put_u32(mac_in, ctx->recv_seq);
        memcpy(mac_in + 4, work, total);
        if (chssh_hmac_sha256(ctx->mac_key_in, CHSSH_MAC_KEY_LEN, mac_in,
                              mac_len, mac_calc) != 0 ||
            memcmp(mac_calc, base + total, CHSSH_MAC_LEN) != 0) {
            free(mac_in);
            free(work);
            chssh_i_set_error(ctx, 3, "MAC verify failed");
            return -1;
        }
        free(mac_in);
        padding = work[4];
        if (padding < 4 || (size_t)padding + 1 > packet_len) {
            free(work);
            chssh_i_set_error(ctx, 3, "bad padding (enc)");
            return -1;
        }
        payload_len = packet_len - 1 - padding;
        payload = work + 5;
        {
            uint8_t msg_type = (payload_len > 0) ? payload[0] : 0;
            if (handle_payload(ctx, payload, payload_len) != 0) {
                free(work);
                return -1;
            }
            free(work);
            ctx->in_pos += need;
            ctx->recv_seq++;
            /* Strict KEX: first encrypted packet after peer NEWKEYS uses seq 0. */
            if (msg_type == CHSSH_MSG_NEWKEYS && ctx->strict_kex) {
                ctx->recv_seq = 0;
            }
        }
        return 1;
    }

    /* cleartext */
    if (avail < 5) {
        return 0;
    }
    packet_len = get_u32(base);
    if (packet_len < 5 || packet_len > ctx->cfg.max_packet_size) {
        chssh_i_set_error(ctx, 3, "invalid packet_length");
        return -1;
    }
    total = 4 + packet_len;
    if (avail < total) {
        return 0;
    }
    padding = base[4];
    if (padding < 4 || (size_t)padding + 1 > packet_len) {
        chssh_i_set_error(ctx, 3, "bad padding");
        return -1;
    }
    payload_len = packet_len - 1 - padding;
    payload = base + 5;
    if (handle_payload(ctx, payload, payload_len) != 0) {
        return -1;
    }
    ctx->in_pos += total;
    ctx->recv_seq++;
    /* Strict KEX: NEWKEYS is last pre-reset packet; then recv_seq = 0. */
    if (payload_len > 0 && payload[0] == CHSSH_MSG_NEWKEYS &&
        ctx->strict_kex) {
        ctx->recv_seq = 0;
    }
    return 1;
}

static int parse_ident(chssh_ctx_t *ctx)
{
    size_t i;
    chssh_event_t ev;
    if (ctx->peer_ident_seen) {
        return 0;
    }
    for (i = 0; i < ctx->in_len; i++) {
        if (ctx->in_buf[i] == '\n') {
            size_t line_len = i;
            if (line_len > 0 && ctx->in_buf[line_len - 1] == '\r') {
                line_len--;
            }
            if (line_len < 4 || line_len > CHSSH_IDENT_MAX ||
                memcmp(ctx->in_buf, "SSH-", 4) != 0) {
                chssh_i_set_error(ctx, 4, "bad peer identification");
                return -1;
            }
            memcpy(ctx->peer_ident, ctx->in_buf, line_len);
            ctx->peer_ident[line_len] = '\0';
            ctx->peer_ident_len = line_len;
            ctx->peer_ident_seen = 1;
            memmove(ctx->in_buf, ctx->in_buf + i + 1, ctx->in_len - (i + 1));
            ctx->in_len -= (i + 1);
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_IDENT_RECEIVED;
            snprintf(ev.u.ident.banner, sizeof(ev.u.ident.banner), "%s",
                     ctx->peer_ident);
            ev.u.ident.banner_len = ctx->peer_ident_len;
            (void)chssh_i_push_event(ctx, &ev);
            ctx->state = CHSSH_STATE_KEX;
            if (ctx->ident_flushed && !ctx->kex_sent) {
                if (send_kexinit(ctx) != 0) {
                    return -1;
                }
            }
            return 0;
        }
    }
    if (ctx->in_len > CHSSH_IDENT_MAX + 2) {
        chssh_i_set_error(ctx, 4, "identification too long");
        return -1;
    }
    return 0;
}

int chssh_i_pump(chssh_ctx_t *ctx)
{
    int r;
    if (!ctx || ctx->error) {
        return -1;
    }
    if (!ctx->peer_ident_seen) {
        if (parse_ident(ctx) != 0) {
            return -1;
        }
    }
    if (ctx->peer_ident_seen && ctx->ident_flushed) {
        for (;;) {
            r = parse_one_packet(ctx);
            if (r < 0) {
                return -1;
            }
            if (r == 0) {
                break;
            }
        }
        if (ctx->in_pos > 0) {
            size_t rem = ctx->in_len - ctx->in_pos;
            if (rem) {
                memmove(ctx->in_buf, ctx->in_buf + ctx->in_pos, rem);
            }
            ctx->in_len = rem;
            ctx->in_pos = 0;
        }
    }
    return 0;
}

/* ---- public API ---- */

chssh_ctx_t *chssh_create(chssh_role_t role, const chssh_config_t *cfg)
{
    chssh_ctx_t *ctx;
    const char *ident;

    (void)chssh_crypto_init();
    ctx = (chssh_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }
    ctx->role = role;
    ctx->state = CHSSH_STATE_IDENT;
    if (cfg) {
        ctx->cfg = *cfg;
    }
    ctx->cfg.event_queue_size =
        cfg_default_size(ctx->cfg.event_queue_size, CHSSH_DEFAULT_EVENT_Q);
    ctx->cfg.max_packet_size =
        cfg_default_size(ctx->cfg.max_packet_size, CHSSH_DEFAULT_PKT);
    ctx->cfg.max_output_size =
        cfg_default_size(ctx->cfg.max_output_size, CHSSH_DEFAULT_OUTPUT);
    ctx->cfg.max_channel_size =
        cfg_default_size(ctx->cfg.max_channel_size, CHSSH_DEFAULT_CHANNEL);

    ctx->cfg.ident = cfg_dup(ctx, cfg && cfg->ident ? cfg->ident : NULL);
    ctx->cfg.server_username =
        cfg_dup(ctx, cfg ? cfg->server_username : NULL);
    ctx->cfg.server_password =
        cfg_dup(ctx, cfg ? cfg->server_password : NULL);
    ctx->cfg.client_username =
        cfg_dup(ctx, cfg ? cfg->client_username : NULL);
    ctx->cfg.client_password =
        cfg_dup(ctx, cfg ? cfg->client_password : NULL);
    ctx->cfg.client_private_key_path =
        cfg_dup(ctx, cfg ? cfg->client_private_key_path : NULL);
    /* PEM may be large — keep caller pointer (host-owned lifetime). */
    ctx->cfg.client_private_key_pem =
        cfg ? cfg->client_private_key_pem : NULL;
    ctx->cfg.host_key_path = cfg_dup(ctx, cfg ? cfg->host_key_path : NULL);
    ctx->cfg.allowed_subsystems =
        cfg_dup(ctx, cfg ? cfg->allowed_subsystems : NULL);

    ctx->hold_ident = cfg ? cfg->hold_ident : 0;
    ctx->lab_mode = cfg ? cfg->lab_mode : 0;
    /*
     * Method offers (PR-2): zero-init configs get both when production crypto
     * is available; lab_mode defaults to password-only advertisement.
     */
    {
        int have_crypto = strcmp(chssh_crypto_backend(), "none") != 0;
        if (cfg && (cfg->server_offer_publickey || cfg->server_offer_password)) {
            ctx->server_offer_publickey = cfg->server_offer_publickey ? 1 : 0;
            ctx->server_offer_password = cfg->server_offer_password ? 1 : 0;
        } else {
            ctx->server_offer_password = 1;
            ctx->server_offer_publickey =
                (have_crypto && !(cfg && cfg->lab_mode)) ? 1 : 0;
        }
        ctx->server_max_auth_attempts =
            (cfg && cfg->server_max_auth_attempts > 0)
                ? cfg->server_max_auth_attempts
                : 6;
    }
    /*
     * auto_open_netconf defaults ON for E7 / zero-init configs.
     * Set auto_open_netconf=0 together with allowed_subsystems for CPE
     * multi-channel clients (app opens sessions after AUTHENTICATED).
     */
    if (!cfg) {
        ctx->auto_open_netconf = 1;
    } else if (cfg->auto_open_netconf) {
        ctx->auto_open_netconf = 1;
    } else if (cfg->allowed_subsystems && cfg->allowed_subsystems[0]) {
        ctx->auto_open_netconf = 0;
    } else {
        ctx->auto_open_netconf = 1;
    }
    parse_allowed_subsystems(ctx, cfg ? cfg->allowed_subsystems : NULL);
    ctx->auto_accept_shell = cfg ? (cfg->auto_accept_shell ? 1 : 0) : 0;
    /*
     * OpenSSH interactive clients require pty-req SUCCESS before shell.
     * Always accept (including zero-init configs). The config field is
     * reserved for a future refuse policy; product staff faces always accept.
     */
    ctx->auto_accept_pty = 1;
    ctx->next_local_id = 0;
    memset(ctx->channels, 0, sizeof(ctx->channels));

    ident = (cfg && cfg->ident && cfg->ident[0]) ? cfg->ident
                                                 : CHSSH_DEFAULT_IDENT;
    snprintf(ctx->local_ident, sizeof(ctx->local_ident), "%s", ident);

    if (!ctx->lab_mode && role == CHSSH_ROLE_SERVER) {
        if (ctx->cfg.host_key_path && ctx->cfg.host_key_path[0]) {
            ctx->host_key = chssh_rsa_load_pem(ctx->cfg.host_key_path);
        }
        if (!ctx->host_key) {
            ctx->host_key = chssh_rsa_generate(2048);
        }
        if (!ctx->host_key) {
            chssh_destroy(ctx);
            return NULL;
        }
    }

    ctx->event_cap = ctx->cfg.event_queue_size;
    ctx->events =
        (chssh_event_t *)calloc(ctx->event_cap, sizeof(chssh_event_t));
    ctx->in_cap = ctx->cfg.max_packet_size + 64;
    ctx->out_cap = ctx->cfg.max_output_size;
    ctx->in_buf = (uint8_t *)malloc(ctx->in_cap);
    ctx->out_buf = (uint8_t *)malloc(ctx->out_cap);
    if (!ctx->events || !ctx->in_buf || !ctx->out_buf) {
        chssh_destroy(ctx);
        return NULL;
    }
    if (!ctx->hold_ident) {
        if (send_ident(ctx) != 0) {
            chssh_destroy(ctx);
            return NULL;
        }
    }
    return ctx;
}

void chssh_destroy(chssh_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    free_crypto(ctx);
    chssh_identity_free(ctx->client_identity);
    ctx->client_identity = NULL;
    free_auth_pending_blob(ctx);
    free(ctx->events);
    free(ctx->in_buf);
    free(ctx->out_buf);
    free(ctx);
}

void chssh_reset(chssh_ctx_t *ctx)
{
    chssh_role_t role;
    chssh_config_t cfg;
    int hold, lab;
    char local[CHSSH_IDENT_MAX + 1];
    char store[1024];
    size_t store_used;
    if (!ctx) {
        return;
    }
    role = ctx->role;
    cfg = ctx->cfg;
    hold = ctx->hold_ident;
    lab = ctx->lab_mode;
    store_used = ctx->cfg_store_used;
    memcpy(store, ctx->cfg_store, sizeof(store));
    snprintf(local, sizeof(local), "%s", ctx->local_ident);
    free_crypto(ctx);
    free(ctx->events);
    free(ctx->in_buf);
    free(ctx->out_buf);
    memset(ctx, 0, sizeof(*ctx));
    ctx->role = role;
    ctx->cfg = cfg;
    ctx->cfg_store_used = store_used;
    memcpy(ctx->cfg_store, store, sizeof(store));
    /* re-fix string pointers into store */
    ctx->hold_ident = hold;
    ctx->lab_mode = lab;
    snprintf(ctx->local_ident, sizeof(ctx->local_ident), "%s", local);
    ctx->state = CHSSH_STATE_IDENT;
    ctx->event_cap = cfg.event_queue_size;
    ctx->events =
        (chssh_event_t *)calloc(ctx->event_cap, sizeof(chssh_event_t));
    ctx->in_cap = cfg.max_packet_size + 64;
    ctx->out_cap = cfg.max_output_size;
    ctx->in_buf = (uint8_t *)malloc(ctx->in_cap);
    ctx->out_buf = (uint8_t *)malloc(ctx->out_cap);
    if (!ctx->lab_mode && role == CHSSH_ROLE_SERVER) {
        ctx->host_key = chssh_rsa_generate(2048);
    }
    if (!ctx->hold_ident && ctx->out_buf) {
        (void)send_ident(ctx);
    }
}

chssh_state_t chssh_current_state(const chssh_ctx_t *ctx)
{
    return ctx ? ctx->state : CHSSH_STATE_ERROR;
}

chssh_role_t chssh_role(const chssh_ctx_t *ctx)
{
    return ctx ? ctx->role : CHSSH_ROLE_SERVER;
}

size_t chssh_feed_input(chssh_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t space;
    if (!ctx || !data || len == 0 || ctx->error) {
        return 0;
    }
    space = ctx->in_cap - ctx->in_len;
    if (len > space) {
        len = space;
    }
    if (len == 0) {
        return 0;
    }
    memcpy(ctx->in_buf + ctx->in_len, data, len);
    ctx->in_len += len;
    (void)chssh_i_pump(ctx);
    return len;
}

size_t chssh_get_output(chssh_ctx_t *ctx, uint8_t *buf, size_t max_len)
{
    size_t n;
    if (!ctx || !buf || max_len == 0) {
        return 0;
    }
    n = ctx->out_len < max_len ? ctx->out_len : max_len;
    if (n == 0) {
        return 0;
    }
    memcpy(buf, ctx->out_buf, n);
    if (n < ctx->out_len) {
        memmove(ctx->out_buf, ctx->out_buf + n, ctx->out_len - n);
    }
    ctx->out_len -= n;
    return n;
}

int chssh_next_event(chssh_ctx_t *ctx, chssh_event_t *event)
{
    if (!ctx || !event || ctx->event_count == 0) {
        return 0;
    }
    *event = ctx->events[ctx->event_tail];
    ctx->event_tail = (ctx->event_tail + 1) % ctx->event_cap;
    ctx->event_count--;
    return 1;
}

int chssh_flush_ident(chssh_ctx_t *ctx)
{
    if (!ctx) {
        return -1;
    }
    if (send_ident(ctx) != 0) {
        return -1;
    }
    if (ctx->peer_ident_seen && !ctx->kex_sent) {
        if (send_kexinit(ctx) != 0) {
            return -1;
        }
    }
    return chssh_i_pump(ctx);
}

int chssh_ident_flushed(const chssh_ctx_t *ctx)
{
    return ctx ? ctx->ident_flushed : 0;
}

int chssh_peer_ident_seen(const chssh_ctx_t *ctx)
{
    return ctx ? ctx->peer_ident_seen : 0;
}

int chssh_auth_decide(chssh_ctx_t *ctx, int accept)
{
    uint8_t pl[CHSSH_PUBKEY_BLOB_MAX + 64];
    chssh_event_t ev;
    int kind;
    if (!ctx || ctx->role != CHSSH_ROLE_SERVER || !ctx->auth_pending) {
        return -1;
    }
    kind = ctx->auth_pend_kind;
    ctx->auth_pending = 0;
    ctx->auth_decided = 1;

    if (kind == CHSSH_AUTH_PEND_PK_QUERY) {
        if (accept) {
            /* SSH_MSG_USERAUTH_PK_OK: algo string || public blob string */
            size_t off = 0;
            size_t na = strlen(ctx->pk_pending_algo);
            pl[off++] = CHSSH_MSG_USERAUTH_PK_OK;
            put_u32(pl + off, (uint32_t)na);
            off += 4;
            memcpy(pl + off, ctx->pk_pending_algo, na);
            off += na;
            put_u32(pl + off, (uint32_t)ctx->pk_pending_blob_len);
            off += 4;
            memcpy(pl + off, ctx->pk_pending_blob, ctx->pk_pending_blob_len);
            off += ctx->pk_pending_blob_len;
            free_auth_pending_blob(ctx);
            ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE;
            return chssh_i_send_packet(ctx, pl, off);
        }
        free_auth_pending_blob(ctx);
        ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE;
        return send_userauth_failure(ctx, 0);
    }

    if (accept) {
        pl[0] = CHSSH_MSG_USERAUTH_SUCCESS;
        if (chssh_i_send_packet(ctx, pl, 1) != 0) {
            return -1;
        }
        ctx->auth_ok = 1;
        ctx->state = CHSSH_STATE_CHANNEL;
        free_auth_pending_blob(ctx);
        ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE;
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_AUTHENTICATED;
        (void)chssh_i_push_event(ctx, &ev);
        return 0;
    }
    /* Reject: stay open for further attempts (K12) */
    free_auth_pending_blob(ctx);
    ctx->auth_pend_kind = CHSSH_AUTH_PEND_NONE;
    return send_userauth_failure(ctx, 0);
}

int chssh_channel_open_session(chssh_ctx_t *ctx, uint32_t *local_id_out)
{
    chssh_channel_t *ch;
    if (!ctx || !ctx->auth_ok || ctx->error) {
        return -1;
    }
    if (ctx->state != CHSSH_STATE_CHANNEL && ctx->state != CHSSH_STATE_READY &&
        ctx->state != CHSSH_STATE_AUTH) {
        /* allow after auth */
        if (!ctx->auth_ok) {
            return -1;
        }
    }
    ch = channel_alloc(ctx);
    if (!ch) {
        return -1;
    }
    ch->local_id = ctx->next_local_id++;
    if (send_channel_open_session_slot(ctx, ch) != 0) {
        memset(ch, 0, sizeof(*ch));
        return -1;
    }
    ctx->state = CHSSH_STATE_CHANNEL;
    if (local_id_out) {
        *local_id_out = ch->local_id;
    }
    return 0;
}

int chssh_channel_request_subsystem(chssh_ctx_t *ctx, uint32_t local_id,
                                    const char *name)
{
    chssh_channel_t *ch;
    if (!ctx || !name || !name[0] || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch) {
        return -1;
    }
    if (ch->state == CHSSH_CH_OPENING) {
        /* Defer subsystem request until OPEN confirm */
        size_t ns = strlen(name);
        if (ns > CHSSH_SUBSYS_NAME_MAX) {
            return -1;
        }
        memcpy(ch->pending_subsystem, name, ns + 1);
        return 0;
    }
    if (ch->state != CHSSH_CH_OPEN) {
        return -1;
    }
    return send_subsystem_request_ch(ctx, ch, name);
}

int chssh_channel_request_shell(chssh_ctx_t *ctx, uint32_t local_id)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch) {
        return -1;
    }
    if (ch->state == CHSSH_CH_OPENING) {
        /* Request shell after confirm */
        ch->pending_shell = 1;
        ch->pending_exec = 0;
        return 0;
    }
    if (ch->state != CHSSH_CH_OPEN) {
        return -1;
    }
    return send_shell_request_ch(ctx, ch);
}

int chssh_channel_request_exec(chssh_ctx_t *ctx, uint32_t local_id,
                               const char *command)
{
    chssh_channel_t *ch;
    size_t nc;
    if (!ctx || !command || !command[0] || ctx->error) {
        return -1;
    }
    nc = strlen(command);
    if (nc > CHSSH_CMD_MAX) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch) {
        return -1;
    }
    snprintf(ch->exec_command, sizeof(ch->exec_command), "%s", command);
    ch->is_exec = 1;
    if (ch->state == CHSSH_CH_OPENING) {
        ch->pending_exec = 1;
        ch->pending_shell = 0;
        return 0;
    }
    if (ch->state != CHSSH_CH_OPEN) {
        return -1;
    }
    return send_exec_request_ch(ctx, ch, command);
}

int chssh_channel_request_pty(chssh_ctx_t *ctx, uint32_t local_id,
                              const char *term, uint32_t cols, uint32_t rows)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch) {
        return -1;
    }
    if (ch->state != CHSSH_CH_OPEN && ch->state != CHSSH_CH_READY) {
        return -1;
    }
    return send_pty_request_ch(ctx, ch, term, cols, rows);
}

int chssh_channel_window_change(chssh_ctx_t *ctx, uint32_t local_id,
                                uint32_t cols, uint32_t rows)
{
    chssh_channel_t *ch;
    uint8_t pl[64];
    size_t off = 0;
    const char *req = "window-change";
    size_t nr = strlen(req);

    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch || (ch->state != CHSSH_CH_OPEN && ch->state != CHSSH_CH_READY)) {
        return -1;
    }
    if (cols == 0) {
        cols = 80;
    }
    if (rows == 0) {
        rows = 24;
    }
    ch->pty_cols = cols;
    ch->pty_rows = rows;
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 0; /* want_reply = false */
    put_u32(pl + off, cols);
    off += 4;
    put_u32(pl + off, rows);
    off += 4;
    put_u32(pl + off, 0); /* width_px */
    off += 4;
    put_u32(pl + off, 0); /* height_px */
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

int chssh_channel_request_decide(chssh_ctx_t *ctx, uint32_t local_id,
                                 int accept)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch || !ch->shell_req_pending) {
        return -1;
    }
    ch->shell_req_pending = 0;
    if (ch->shell_want_reply) {
        if (send_channel_req_reply(ctx, ch, accept ? 1 : 0) != 0) {
            return -1;
        }
    }
    if (accept) {
        if (ch->is_exec) {
            return mark_channel_ready(ctx, ch, "exec");
        }
        return mark_channel_ready(ctx, ch, "shell");
    }
    return 0;
}

static int send_global_tcpip_request(chssh_ctx_t *ctx, const char *name,
                                     const char *addr, uint32_t port)
{
    uint8_t pl[320];
    size_t off = 0;
    size_t nn, na;
    if (!ctx || !name || !addr) {
        return -1;
    }
    nn = strlen(name);
    na = strlen(addr);
    if (na > CHSSH_ADDR_MAX || nn > 40) {
        return -1;
    }
    pl[off++] = CHSSH_MSG_GLOBAL_REQUEST;
    put_u32(pl + off, (uint32_t)nn);
    off += 4;
    memcpy(pl + off, name, nn);
    off += nn;
    pl[off++] = 1; /* want_reply */
    put_u32(pl + off, (uint32_t)na);
    off += 4;
    memcpy(pl + off, addr, na);
    off += na;
    put_u32(pl + off, port);
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

int chssh_request_tcpip_forward(chssh_ctx_t *ctx, const char *addr,
                                uint32_t port)
{
    if (!ctx || ctx->error || !addr || !addr[0]) {
        return -1;
    }
    if (!ctx->auth_ok) {
        return -1;
    }
    if (ctx->pending_tcpip_forward) {
        return -1;
    }
    ctx->pending_tcpip_forward = 1;
    snprintf(ctx->pending_forward_addr, sizeof(ctx->pending_forward_addr), "%s",
             addr);
    ctx->pending_forward_port = port;
    if (send_global_tcpip_request(ctx, "tcpip-forward", addr, port) != 0) {
        ctx->pending_tcpip_forward = 0;
        return -1;
    }
    return 0;
}

int chssh_request_cancel_tcpip_forward(chssh_ctx_t *ctx, const char *addr,
                                       uint32_t port)
{
    if (!ctx || ctx->error || !addr || !addr[0]) {
        return -1;
    }
    if (!ctx->auth_ok) {
        return -1;
    }
    return send_global_tcpip_request(ctx, "cancel-tcpip-forward", addr, port);
}

int chssh_global_request_decide(chssh_ctx_t *ctx, int accept,
                                uint32_t bound_port)
{
    if (!ctx || ctx->error || !ctx->global_req_pending) {
        return -1;
    }
    if (ctx->global_req_want_reply) {
        if (accept && ctx->global_req_pending == 1) {
            /* REQUEST_SUCCESS; include port when peer asked for 0 */
            uint8_t pl[8];
            size_t off = 0;
            pl[off++] = CHSSH_MSG_REQUEST_SUCCESS;
            if (ctx->global_req_port == 0 || bound_port != 0) {
                uint32_t p = bound_port ? bound_port : ctx->global_req_port;
                put_u32(pl + off, p);
                off += 4;
            }
            if (chssh_i_send_packet(ctx, pl, off) != 0) {
                return -1;
            }
        } else if (accept && ctx->global_req_pending == 2) {
            uint8_t pl[1] = {CHSSH_MSG_REQUEST_SUCCESS};
            if (chssh_i_send_packet(ctx, pl, 1) != 0) {
                return -1;
            }
        } else {
            uint8_t pl[1] = {CHSSH_MSG_REQUEST_FAILURE};
            if (chssh_i_send_packet(ctx, pl, 1) != 0) {
                return -1;
            }
        }
    }
    ctx->global_req_pending = 0;
    ctx->global_req_want_reply = 0;
    (void)bound_port;
    return 0;
}

static int send_channel_open_tcpip(chssh_ctx_t *ctx, chssh_channel_t *ch,
                                   const char *ctype, const char *host,
                                   uint32_t port, const char *orig,
                                   uint32_t oport)
{
    uint8_t pl[640];
    size_t off = 0;
    size_t nt, nh, no;
    uint32_t win;
    if (!ch || !ctype || !host || !orig) {
        return -1;
    }
    nt = strlen(ctype);
    nh = strlen(host);
    no = strlen(orig);
    if (nh > CHSSH_ADDR_MAX || no > CHSSH_ADDR_MAX) {
        return -1;
    }
    win = default_channel_window(ctx);
    ch->local_window = win;
    ch->local_max_packet = 32768;
    ch->state = CHSSH_CH_OPENING;
    ch->is_tcpip = 1;
    snprintf(ch->open_type, sizeof(ch->open_type), "%s", ctype);
    snprintf(ch->tcpip_dest, sizeof(ch->tcpip_dest), "%s", host);
    ch->tcpip_dest_port = port;
    snprintf(ch->tcpip_orig, sizeof(ch->tcpip_orig), "%s", orig);
    ch->tcpip_orig_port = oport;
    pl[off++] = CHSSH_MSG_CHANNEL_OPEN;
    put_u32(pl + off, (uint32_t)nt);
    off += 4;
    memcpy(pl + off, ctype, nt);
    off += nt;
    put_u32(pl + off, ch->local_id);
    off += 4;
    put_u32(pl + off, win);
    off += 4;
    put_u32(pl + off, ch->local_max_packet);
    off += 4;
    put_u32(pl + off, (uint32_t)nh);
    off += 4;
    memcpy(pl + off, host, nh);
    off += nh;
    put_u32(pl + off, port);
    off += 4;
    put_u32(pl + off, (uint32_t)no);
    off += 4;
    memcpy(pl + off, orig, no);
    off += no;
    put_u32(pl + off, oport);
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

int chssh_channel_open_forwarded_tcpip(chssh_ctx_t *ctx, const char *conn_addr,
                                       uint32_t conn_port, const char *orig_addr,
                                       uint32_t orig_port,
                                       uint32_t *local_id_out)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error || !conn_addr || !orig_addr || !local_id_out) {
        return -1;
    }
    if (!ctx->auth_ok) {
        return -1;
    }
    ch = channel_alloc(ctx);
    if (!ch) {
        return -1;
    }
    ch->local_id = ctx->next_local_id++;
    *local_id_out = ch->local_id;
    return send_channel_open_tcpip(ctx, ch, "forwarded-tcpip", conn_addr,
                                   conn_port, orig_addr, orig_port);
}

int chssh_channel_open_direct_tcpip(chssh_ctx_t *ctx, const char *dest_host,
                                    uint32_t dest_port, const char *orig_addr,
                                    uint32_t orig_port,
                                    uint32_t *local_id_out)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error || !dest_host || !orig_addr || !local_id_out) {
        return -1;
    }
    if (!ctx->auth_ok) {
        return -1;
    }
    ch = channel_alloc(ctx);
    if (!ch) {
        return -1;
    }
    ch->local_id = ctx->next_local_id++;
    *local_id_out = ch->local_id;
    return send_channel_open_tcpip(ctx, ch, "direct-tcpip", dest_host, dest_port,
                                   orig_addr, orig_port);
}

int chssh_channel_open_decide(chssh_ctx_t *ctx, uint32_t local_id, int accept)
{
    chssh_channel_t *ch;
    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch || !ch->open_deferred) {
        return -1;
    }
    ch->open_deferred = 0;
    if (!accept) {
        (void)send_channel_open_failure(ctx, ch->peer_id, "connect failed");
        memset(ch, 0, sizeof(*ch));
        ch->state = CHSSH_CH_FREE;
        return 0;
    }
    if (send_channel_open_confirm(ctx, ch) != 0) {
        return -1;
    }
    ch->state = CHSSH_CH_READY;
    ctx->channel_ready = 1;
    ctx->state = CHSSH_STATE_READY;
    return 0;
}

int chssh_channel_send_id(chssh_ctx_t *ctx, uint32_t local_id,
                          const uint8_t *data, size_t len)
{
    uint8_t pl[CHSSH_DATA_MAX + 16];
    size_t off = 0;
    chssh_channel_t *ch;
    if (!ctx || !data || len == 0 || len > CHSSH_DATA_MAX) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch || ch->state != CHSSH_CH_READY) {
        return -1;
    }
    if (!ctx->lab_mode && ch->remote_window < len) {
        chssh_i_set_error(ctx, 23, "channel send: remote window exhausted");
        return -1;
    }
    pl[off++] = CHSSH_MSG_CHANNEL_DATA;
    put_u32(pl + off, ch->peer_id);
    off += 4;
    put_u32(pl + off, (uint32_t)len);
    off += 4;
    memcpy(pl + off, data, len);
    off += len;
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    if (!ctx->lab_mode && ch->remote_window >= len) {
        ch->remote_window -= (uint32_t)len;
    }
    return 0;
}

int chssh_channel_send(chssh_ctx_t *ctx, const uint8_t *data, size_t len)
{
    chssh_channel_t *ch;
    if (!ctx || !ctx->channel_ready) {
        return -1;
    }
    ch = channel_primary_ready(ctx);
    if (!ch) {
        return -1;
    }
    return chssh_channel_send_id(ctx, ch->local_id, data, len);
}

int chssh_channel_close(chssh_ctx_t *ctx, uint32_t local_id)
{
    chssh_channel_t *ch;
    uint8_t pl[8];
    size_t off;

    if (!ctx || ctx->error) {
        return -1;
    }
    ch = channel_by_local(ctx, local_id);
    if (!ch) {
        return -1;
    }
    if (ch->state == CHSSH_CH_FREE || ch->state == CHSSH_CH_CLOSED) {
        return 0;
    }
    /* EOF then CLOSE (best-effort) so peer can drop sticky reverse shells. */
    if (ch->peer_id != 0) {
        if (ch->state != CHSSH_CH_EOF_RCVD) {
            off = 0;
            pl[off++] = CHSSH_MSG_CHANNEL_EOF;
            put_u32(pl + off, ch->peer_id);
            off += 4;
            (void)chssh_i_send_packet(ctx, pl, off);
        }
        off = 0;
        pl[off++] = CHSSH_MSG_CHANNEL_CLOSE;
        put_u32(pl + off, ch->peer_id);
        off += 4;
        if (chssh_i_send_packet(ctx, pl, off) != 0) {
            return -1;
        }
    }
    ch->state = CHSSH_CH_CLOSED;
    return 0;
}

int chssh_channel_is_ready(const chssh_ctx_t *ctx, uint32_t local_id)
{
    size_t i;
    if (!ctx) {
        return 0;
    }
    for (i = 0; i < CHSSH_MAX_CHANNELS; i++) {
        if (ctx->channels[i].state == CHSSH_CH_READY &&
            ctx->channels[i].local_id == local_id) {
            return 1;
        }
    }
    return 0;
}

int chssh_send_keepalive(chssh_ctx_t *ctx)
{
    /*
     * OpenSSH ServerAlive: GLOBAL_REQUEST "keepalive@openssh.com" want_reply=1.
     * Also send SSH_MSG_IGNORE as belt-and-suspenders for stacks that ignore
     * unknown global requests without want_reply handling.
     */
    static const char name[] = "keepalive@openssh.com";
    uint8_t pl[64];
    size_t off = 0;
    size_t n = sizeof(name) - 1;

    if (!ctx || ctx->error) {
        return -1;
    }
    if (ctx->lab_mode) {
        /* Lab has no wire idle timers; treat as success no-op. */
        return 0;
    }
    if (!ctx->encrypt_out) {
        return -1;
    }

    pl[off++] = CHSSH_MSG_GLOBAL_REQUEST;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, name, n);
    off += n;
    pl[off++] = 1; /* want_reply */
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }

    /* SSH_MSG_IGNORE string "chssh-ka" */
    {
        static const char data[] = "chssh-ka";
        size_t dlen = sizeof(data) - 1;
        off = 0;
        pl[off++] = CHSSH_MSG_IGNORE;
        put_u32(pl + off, (uint32_t)dlen);
        off += 4;
        memcpy(pl + off, data, dlen);
        off += dlen;
        if (chssh_i_send_packet(ctx, pl, off) != 0) {
            return -1;
        }
    }
    return 0;
}

int chssh_disconnect(chssh_ctx_t *ctx, const char *description)
{
    uint8_t pl[300];
    size_t off = 0;
    const char *desc = description ? description : "closed";
    size_t n = strlen(desc);
    if (!ctx) {
        return -1;
    }
    pl[off++] = CHSSH_MSG_DISCONNECT;
    put_u32(pl + off, 11);
    off += 4;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, desc, n);
    off += n;
    put_u32(pl + off, 0);
    off += 4;
    (void)chssh_i_send_packet(ctx, pl, off);
    ctx->state = CHSSH_STATE_CLOSED;
    return 0;
}

