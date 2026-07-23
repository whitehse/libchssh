#define _GNU_SOURCE
/**
 * @file chssh.c
 * @brief Call Home SSH transport — pure state machine (no sockets).
 *
 * lab_mode=1: dialectic cleartext after NEWKEYS (not wire-interop).
 * lab_mode=0: OpenSSL production path:
 *   diffie-hellman-group14-sha256, ssh-rsa/rsa-sha2-256 host key,
 *   aes128-ctr, hmac-sha2-256, subsystem netconf.
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
static int mark_ready(chssh_ctx_t *ctx);

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

static int send_window_adjust(chssh_ctx_t *ctx, uint32_t bytes)
{
    uint8_t pl[9];
    size_t off = 0;
    if (!ctx || bytes == 0 || !ctx->channel_ready) {
        return 0;
    }
    pl[off++] = CHSSH_MSG_CHANNEL_WINDOW_ADJUST;
    put_u32(pl + off, ctx->peer_channel);
    off += 4;
    put_u32(pl + off, bytes);
    off += 4;
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    ctx->local_window += bytes;
    return 0;
}

/** After consuming peer CHANNEL_DATA, replenish RX window when low. */
static int maybe_replenish_local_window(chssh_ctx_t *ctx, uint32_t consumed)
{
    uint32_t target;
    uint32_t add;
    if (!ctx || consumed == 0) {
        return 0;
    }
    if (ctx->local_window >= consumed) {
        ctx->local_window -= consumed;
    } else {
        ctx->local_window = 0;
    }
    target = (uint32_t)ctx->cfg.max_channel_size;
    if (target == 0) {
        target = (uint32_t)CHSSH_DEFAULT_CHANNEL;
    }
    /*
     * Replenish aggressively for large NETCONF transfers (get-config).
     * Waiting until half-empty stalls peers that buffer multi-MB replies.
     * Top up whenever we drop below 75% of target (or any time window is 0).
     */
    if (ctx->local_window > (target - target / 4) && ctx->local_window > 0) {
        return 0;
    }
    add = target - ctx->local_window;
    if (add == 0) {
        return 0;
    }
    if (add < 32768u && ctx->local_window > 65536u) {
        return 0; /* skip tiny top-ups while still comfortably stocked */
    }
    return send_window_adjust(ctx, add);
}

static int send_channel_open_session(chssh_ctx_t *ctx)
{
    uint8_t pl[64];
    size_t off = 0;
    const char *t = "session";
    size_t n = strlen(t);
    uint32_t win = (uint32_t)ctx->cfg.max_channel_size;
    if (win == 0) {
        win = (uint32_t)CHSSH_DEFAULT_CHANNEL;
    }
    ctx->local_channel = 0;
    ctx->local_window = win;
    ctx->local_max_packet = 32768;
    pl[off++] = CHSSH_MSG_CHANNEL_OPEN;
    put_u32(pl + off, (uint32_t)n);
    off += 4;
    memcpy(pl + off, t, n);
    off += n;
    put_u32(pl + off, ctx->local_channel);
    off += 4;
    put_u32(pl + off, win);
    off += 4;
    put_u32(pl + off, ctx->local_max_packet);
    off += 4;
    return chssh_i_send_packet(ctx, pl, off);
}

static int send_subsystem_request(chssh_ctx_t *ctx)
{
    uint8_t pl[128];
    size_t off = 0;
    const char *req = "subsystem";
    const char *sub = CHSSH_SUBSYSTEM_NETCONF;
    size_t nr = strlen(req), ns = strlen(sub);
    pl[off++] = CHSSH_MSG_CHANNEL_REQUEST;
    put_u32(pl + off, ctx->peer_channel);
    off += 4;
    put_u32(pl + off, (uint32_t)nr);
    off += 4;
    memcpy(pl + off, req, nr);
    off += nr;
    pl[off++] = 1;
    put_u32(pl + off, (uint32_t)ns);
    off += 4;
    memcpy(pl + off, sub, ns);
    off += ns;
    return chssh_i_send_packet(ctx, pl, off);
}

static int mark_ready(chssh_ctx_t *ctx)
{
    chssh_event_t ev;
    ctx->channel_ready = 1;
    ctx->state = CHSSH_STATE_READY;
    memset(&ev, 0, sizeof(ev));
    ev.type = CHSSH_EVENT_READY;
    (void)chssh_i_push_event(ctx, &ev);
    return 0;
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
    case CHSSH_MSG_REQUEST_SUCCESS:
    case CHSSH_MSG_REQUEST_FAILURE:
        /* Keepalive / global-request replies — no app action. */
        return 0;
    case CHSSH_MSG_GLOBAL_REQUEST:
        /*
         * Peer global request (e.g. hostkeys-00@openssh.com, keepalive).
         * If want_reply is set, answer FAILURE (we do not implement payloads)
         * so the peer does not hang waiting.
         */
        if (len >= 6) {
            uint32_t nlen = get_u32(p + 1);
            size_t want_off = 5 + (size_t)nlen;
            if (want_off < len && p[want_off] != 0) {
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
            return send_userauth_password(ctx);
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
            ctx->pending_is_none = (strcmp(method, "none") == 0);
            if (strcmp(method, "password") == 0 && o + 1 + 4 <= len) {
                uint32_t plen;
                o += 1;
                plen = get_u32(p + o);
                o += 4;
                if (o + plen <= len && plen < CHSSH_PASS_MAX) {
                    memcpy(ctx->pending_pass, p + o, plen);
                    ctx->pending_pass[plen] = '\0';
                }
            }
            ctx->auth_pending = 1;
            memset(&ev, 0, sizeof(ev));
            ev.type = ctx->pending_is_none ? CHSSH_EVENT_AUTH_NONE
                                           : CHSSH_EVENT_AUTH_PASSWORD;
            snprintf(ev.u.auth.username, sizeof(ev.u.auth.username), "%s",
                     ctx->pending_user);
            snprintf(ev.u.auth.password, sizeof(ev.u.auth.password), "%s",
                     ctx->pending_pass);
            (void)chssh_i_push_event(ctx, &ev);
            {
                int accept = 0;
                if (ctx->pending_is_none) {
                    accept = ctx->cfg.allow_none_auth ? 1 : 0;
                } else if (ctx->cfg.server_password) {
                    int user_ok = 1;
                    if (ctx->cfg.server_username &&
                        ctx->cfg.server_username[0]) {
                        user_ok = strcmp(ctx->pending_user,
                                         ctx->cfg.server_username) == 0;
                    }
                    accept = user_ok && strcmp(ctx->pending_pass,
                                               ctx->cfg.server_password) == 0;
                }
                (void)chssh_auth_decide(ctx, accept);
            }
        }
        return 0;
    case CHSSH_MSG_USERAUTH_SUCCESS:
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            ctx->auth_ok = 1;
            ctx->state = CHSSH_STATE_CHANNEL;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_AUTHENTICATED;
            (void)chssh_i_push_event(ctx, &ev);
            return send_channel_open_session(ctx);
        }
        return 0;
    case CHSSH_MSG_USERAUTH_FAILURE:
        chssh_i_set_error(ctx, 2, "userauth failure");
        return -1;
    case CHSSH_MSG_CHANNEL_OPEN:
        if (ctx->role == CHSSH_ROLE_SERVER && len >= 5) {
            size_t o = 1;
            uint32_t n, peer_ch;
            uint8_t conf[32];
            size_t co = 0;
            n = get_u32(p + o);
            o += 4 + n;
            peer_ch = get_u32(p + o);
            ctx->peer_channel = peer_ch;
            ctx->local_channel = 0;
            conf[co++] = CHSSH_MSG_CHANNEL_OPEN_CONFIRM;
            put_u32(conf + co, peer_ch);
            co += 4;
            put_u32(conf + co, ctx->local_channel);
            co += 4;
            put_u32(conf + co, (uint32_t)ctx->cfg.max_channel_size);
            co += 4;
            put_u32(conf + co, 32768);
            co += 4;
            if (chssh_i_send_packet(ctx, conf, co) != 0) {
                return -1;
            }
            ctx->state = CHSSH_STATE_CHANNEL;
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_CHANNEL_OPEN;
            (void)chssh_i_push_event(ctx, &ev);
        }
        return 0;
    case CHSSH_MSG_CHANNEL_OPEN_CONFIRM:
        if (ctx->role == CHSSH_ROLE_CLIENT && len >= 17) {
            /* type | recipient | sender | window | max_packet */
            ctx->peer_channel = get_u32(p + 5);
            ctx->remote_window = get_u32(p + 9);
            ctx->remote_max_packet = get_u32(p + 13);
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_CHANNEL_OPEN;
            (void)chssh_i_push_event(ctx, &ev);
            return send_subsystem_request(ctx);
        }
        return 0;
    case CHSSH_MSG_CHANNEL_WINDOW_ADJUST:
        if (len >= 9) {
            uint32_t add = get_u32(p + 5);
            ctx->remote_window += add;
        }
        return 0;
    case CHSSH_MSG_CHANNEL_REQUEST:
        if (ctx->role == CHSSH_ROLE_SERVER && len >= 10) {
            size_t o = 1;
            uint32_t rn;
            char req[32];
            uint8_t want;
            o += 4;
            rn = get_u32(p + o);
            o += 4;
            if (o + rn > len || rn >= sizeof(req)) {
                return 0;
            }
            memcpy(req, p + o, rn);
            req[rn] = '\0';
            o += rn;
            want = p[o++];
            if (strcmp(req, "subsystem") == 0 && o + 4 <= len) {
                uint32_t sn = get_u32(p + o);
                o += 4;
                if (o + sn <= len && sn < 64) {
                    char sub[64];
                    memcpy(sub, p + o, sn);
                    sub[sn] = '\0';
                    memset(&ev, 0, sizeof(ev));
                    ev.type = CHSSH_EVENT_SUBSYSTEM;
                    snprintf(ev.u.subsystem.name, sizeof(ev.u.subsystem.name),
                             "%s", sub);
                    (void)chssh_i_push_event(ctx, &ev);
                    if (strcmp(sub, CHSSH_SUBSYSTEM_NETCONF) == 0) {
                        if (want) {
                            uint8_t pl[5];
                            pl[0] = CHSSH_MSG_CHANNEL_SUCCESS;
                            put_u32(pl + 1, ctx->peer_channel);
                            if (chssh_i_send_packet(ctx, pl, 5) != 0) {
                                return -1;
                            }
                        }
                        return mark_ready(ctx);
                    }
                }
            }
        }
        return 0;
    case CHSSH_MSG_CHANNEL_SUCCESS:
        if (ctx->role == CHSSH_ROLE_CLIENT) {
            memset(&ev, 0, sizeof(ev));
            ev.type = CHSSH_EVENT_SUBSYSTEM;
            snprintf(ev.u.subsystem.name, sizeof(ev.u.subsystem.name), "%s",
                     CHSSH_SUBSYSTEM_NETCONF);
            (void)chssh_i_push_event(ctx, &ev);
            return mark_ready(ctx);
        }
        return 0;
    case CHSSH_MSG_CHANNEL_DATA:
        if (len >= 9) {
            uint32_t dlen = get_u32(p + 5);
            if (9 + dlen <= len && dlen <= CHSSH_DATA_MAX) {
                memset(&ev, 0, sizeof(ev));
                ev.type = CHSSH_EVENT_CHANNEL_DATA;
                memcpy(ev.u.data.data, p + 9, dlen);
                ev.u.data.len = dlen;
                (void)chssh_i_push_event(ctx, &ev);
                /* RFC 4254: consumer must WINDOW_ADJUST or peer stalls/closes. */
                if (maybe_replenish_local_window(ctx, dlen) != 0) {
                    return -1;
                }
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
    ctx->cfg.host_key_path = cfg_dup(ctx, cfg ? cfg->host_key_path : NULL);

    ctx->hold_ident = cfg ? cfg->hold_ident : 0;
    ctx->lab_mode = cfg ? cfg->lab_mode : 0;

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
    uint8_t pl[64];
    chssh_event_t ev;
    if (!ctx || ctx->role != CHSSH_ROLE_SERVER || !ctx->auth_pending) {
        return -1;
    }
    ctx->auth_pending = 0;
    ctx->auth_decided = 1;
    if (accept) {
        pl[0] = CHSSH_MSG_USERAUTH_SUCCESS;
        if (chssh_i_send_packet(ctx, pl, 1) != 0) {
            return -1;
        }
        ctx->auth_ok = 1;
        memset(&ev, 0, sizeof(ev));
        ev.type = CHSSH_EVENT_AUTHENTICATED;
        (void)chssh_i_push_event(ctx, &ev);
    } else {
        const char *methods = "password";
        size_t n = strlen(methods);
        size_t off = 0;
        pl[off++] = CHSSH_MSG_USERAUTH_FAILURE;
        put_u32(pl + off, (uint32_t)n);
        off += 4;
        memcpy(pl + off, methods, n);
        off += n;
        pl[off++] = 0;
        if (chssh_i_send_packet(ctx, pl, off) != 0) {
            return -1;
        }
    }
    return 0;
}

int chssh_channel_send(chssh_ctx_t *ctx, const uint8_t *data, size_t len)
{
    uint8_t pl[CHSSH_DATA_MAX + 16];
    size_t off = 0;
    if (!ctx || !ctx->channel_ready || !data || len == 0 ||
        len > CHSSH_DATA_MAX) {
        return -1;
    }
    if (!ctx->lab_mode && ctx->remote_window < len) {
        /* Peer has not granted enough window; refuse rather than violate RFC. */
        chssh_i_set_error(ctx, 23, "channel send: remote window exhausted");
        return -1;
    }
    pl[off++] = CHSSH_MSG_CHANNEL_DATA;
    put_u32(pl + off, ctx->peer_channel);
    off += 4;
    put_u32(pl + off, (uint32_t)len);
    off += 4;
    memcpy(pl + off, data, len);
    off += len;
    if (chssh_i_send_packet(ctx, pl, off) != 0) {
        return -1;
    }
    if (!ctx->lab_mode && ctx->remote_window >= len) {
        ctx->remote_window -= (uint32_t)len;
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

