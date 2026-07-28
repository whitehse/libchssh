#ifndef CHSSH_INTERNAL_H
#define CHSSH_INTERNAL_H

#include "chssh.h"
#include "chssh_crypto.h"

#include <stddef.h>
#include <stdint.h>

#define CHSSH_DEFAULT_EVENT_Q    16
#define CHSSH_DEFAULT_PKT        (256 * 1024)
#define CHSSH_DEFAULT_OUTPUT     (256 * 1024)
#define CHSSH_DEFAULT_CHANNEL    (256 * 1024)

#define CHSSH_MSG_DISCONNECT            1
#define CHSSH_MSG_IGNORE                2
#define CHSSH_MSG_UNIMPLEMENTED         3
#define CHSSH_MSG_DEBUG                 4
#define CHSSH_MSG_SERVICE_REQUEST       5
#define CHSSH_MSG_SERVICE_ACCEPT        6
#define CHSSH_MSG_KEXINIT               20
#define CHSSH_MSG_NEWKEYS               21
#define CHSSH_MSG_KEXDH_INIT            30
#define CHSSH_MSG_KEXDH_REPLY           31
#define CHSSH_MSG_USERAUTH_REQUEST      50
#define CHSSH_MSG_USERAUTH_FAILURE      51
#define CHSSH_MSG_USERAUTH_SUCCESS      52
#define CHSSH_MSG_USERAUTH_BANNER       53
#define CHSSH_MSG_GLOBAL_REQUEST        80
#define CHSSH_MSG_REQUEST_SUCCESS       81
#define CHSSH_MSG_REQUEST_FAILURE       82
#define CHSSH_MSG_CHANNEL_OPEN          90
#define CHSSH_MSG_CHANNEL_OPEN_CONFIRM  91
#define CHSSH_MSG_CHANNEL_OPEN_FAILURE  92
#define CHSSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define CHSSH_MSG_CHANNEL_DATA          94
#define CHSSH_MSG_CHANNEL_EOF           96
#define CHSSH_MSG_CHANNEL_CLOSE         97
#define CHSSH_MSG_CHANNEL_REQUEST       98
#define CHSSH_MSG_CHANNEL_SUCCESS       99
#define CHSSH_MSG_CHANNEL_FAILURE       100

#define CHSSH_MAX_ALLOWED_SUBSYS 8

typedef enum {
    CHSSH_CH_FREE = 0,
    CHSSH_CH_OPENING, /* we sent OPEN, waiting for confirm */
    CHSSH_CH_OPEN,    /* confirmed; subsystem optional */
    CHSSH_CH_READY,   /* subsystem accepted */
    CHSSH_CH_EOF_RCVD,
    CHSSH_CH_CLOSED
} chssh_ch_state_t;

typedef struct {
    chssh_ch_state_t state;
    uint32_t local_id;
    uint32_t peer_id;
    uint32_t local_window;  /* remaining RX window we advertised */
    uint32_t remote_window; /* remaining TX window peer advertised */
    uint32_t local_max_packet;
    uint32_t remote_max_packet;
    char pending_subsystem[CHSSH_SUBSYS_NAME_MAX + 1];
    char subsystem[CHSSH_SUBSYS_NAME_MAX + 1];
} chssh_channel_t;

struct chssh_ctx {
    chssh_role_t  role;
    chssh_state_t state;
    chssh_config_t cfg;
    char cfg_store[2048];
    size_t cfg_store_used;

    char local_ident[CHSSH_IDENT_MAX + 1];
    char peer_ident[CHSSH_IDENT_MAX + 1];
    size_t peer_ident_len;

    int hold_ident;
    int lab_mode;
    int ident_flushed;
    int peer_ident_seen;
    int kex_sent;
    int kex_received;
    int kexdh_sent;
    int kexdh_done;
    int newkeys_sent;
    int newkeys_received;
    int auth_ok;
    int channel_ready; /* 1 if any channel READY (or netconf for E7) */
    int strict_kex; /* both peers offered kex-strict-* markers */
    int auto_open_netconf;

    chssh_channel_t channels[CHSSH_MAX_CHANNELS];
    uint32_t next_local_id;

    int n_allowed_subsys;
    char allowed_subsys[CHSSH_MAX_ALLOWED_SUBSYS][CHSSH_SUBSYS_NAME_MAX + 1];

    uint32_t send_seq;
    uint32_t recv_seq;

    int auth_pending;
    int auth_decided;
    int auth_accept;
    char pending_user[CHSSH_USER_MAX + 1];
    char pending_pass[CHSSH_PASS_MAX + 1];
    int pending_is_none;

    /* Production crypto */
    chssh_rsa_key_t *host_key;       /* server host key; client unused */
    chssh_dh_ctx_t  *dh;
    chssh_ecdh_ctx_t *ecdh;
    int use_ecdh; /* negotiated ecdh-sha2-nistp256 */
    uint8_t *local_kexinit;
    size_t   local_kexinit_len;
    uint8_t *peer_kexinit;
    size_t   peer_kexinit_len;
    uint8_t  session_id[CHSSH_HASH_LEN];
    size_t   session_id_len;
    uint8_t  K_mpint[CHSSH_MAX_MPINT];
    size_t   K_len;
    uint8_t  H[CHSSH_HASH_LEN];
    char     sig_alg[32];            /* rsa-sha2-256 or ssh-rsa */
    int      encrypt_out;           /* after we sent NEWKEYS */
    int      encrypt_in;            /* after we received NEWKEYS */
    chssh_cipher_t *ciph_out;
    chssh_cipher_t *ciph_in;
    uint8_t  mac_key_out[CHSSH_MAC_KEY_LEN];
    uint8_t  mac_key_in[CHSSH_MAC_KEY_LEN];

    uint8_t *in_buf;
    size_t   in_len;
    size_t   in_cap;
    size_t   in_pos;

    uint8_t *out_buf;
    size_t   out_len;
    size_t   out_cap;

    chssh_event_t *events;
    size_t event_cap;
    size_t event_head;
    size_t event_tail;
    size_t event_count;
    uint64_t event_drops;

    int error;
    char error_msg[CHSSH_ERROR_MAX];
};

int  chssh_i_push_event(chssh_ctx_t *ctx, const chssh_event_t *ev);
void chssh_i_set_error(chssh_ctx_t *ctx, int code, const char *fmt, ...);
int  chssh_i_out_append(chssh_ctx_t *ctx, const uint8_t *data, size_t len);
int  chssh_i_send_packet(chssh_ctx_t *ctx, const uint8_t *payload, size_t len);
int  chssh_i_pump(chssh_ctx_t *ctx);

#endif /* CHSSH_INTERNAL_H */
