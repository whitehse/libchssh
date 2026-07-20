/**
 * @file chssh.h
 * @brief Call Home SSH transport (RFC 8071) — pure plumbing API.
 *
 * System-call free, callback free. Caller owns sockets and policy.
 * Specialized for NETCONF subsystem "netconf" after SSH is ready.
 *
 * Roles (SSH layer; orthogonal to NETCONF app roles):
 *   CHSSH_ROLE_SERVER — NMS after TCP accept (RFC 8071 Call Home)
 *   CHSSH_ROLE_CLIENT — device (TCP initiator) or outbound NMS
 */

#ifndef CHSSH_H
#define CHSSH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHSSH_VERSION_MAJOR 0
#define CHSSH_VERSION_MINOR 1
#define CHSSH_VERSION_PATCH 0

/** Default identification (OpenSSH-like; some field gear rejects exotic idents). */
#define CHSSH_DEFAULT_IDENT "SSH-2.0-OpenSSH_8.9"

/** Fixed NETCONF subsystem name (RFC 6242). */
#define CHSSH_SUBSYSTEM_NETCONF "netconf"

/* --- Role: SSH transport role (not NETCONF client/server) --- */
typedef enum {
    CHSSH_ROLE_SERVER = 0, /* NMS Call Home: SSH server after accept */
    CHSSH_ROLE_CLIENT = 1  /* Device Call Home initiator / outbound SSH client */
} chssh_role_t;

/* --- Config (ADR 009 consistent interface) --- */
typedef struct {
    size_t      event_queue_size;   /* 0 = default 16 */
    size_t      max_packet_size;    /* 0 = default 256 KiB (SSH binary packet) */
    size_t      max_output_size;    /* 0 = default 256 KiB */
    size_t      max_channel_size;   /* 0 = default 256 KiB (plaintext NETCONF) */

    /**
     * SSH identification string without CR/LF (default CHSSH_DEFAULT_IDENT).
     * Library appends \r\n on the wire.
     */
    const char *ident;

    /**
     * 1 = do not emit local identification until chssh_flush_ident().
     * Field Call Home: host parses Calix identity preamble first, then flushes.
     */
    int hold_ident;

    /**
     * 1 = lab dialectic mode: complete handshake with paired chssh peers
     * without production crypto. Not interoperable with real SSH clients.
     * 0 = production path (OpenSSL-backed KEX when built with HAVE_OPENSSL).
     */
    int lab_mode;

    /* --- Server (CALLHOME) expected credentials; NULL password rejects all --- */
    const char *server_username; /* NULL = any username */
    const char *server_password; /* NULL = reject password auth */

    /* --- Client credentials --- */
    const char *client_username;
    const char *client_password;

    int accept_any_hostkey; /* CLIENT lab: accept peer host key without pin */
    int allow_none_auth;    /* SERVER lab: allow USERAUTH none */

    const char *host_key_path; /* SERVER: PEM path; NULL = ephemeral when possible */
} chssh_config_t;

typedef struct chssh_ctx chssh_ctx_t;

typedef enum {
    CHSSH_STATE_IDLE = 0,
    CHSSH_STATE_IDENT,           /* exchanging SSH-2.0 banners */
    CHSSH_STATE_KEX,             /* key exchange */
    CHSSH_STATE_SERVICE,         /* service request/accept */
    CHSSH_STATE_AUTH,            /* user authentication */
    CHSSH_STATE_CHANNEL,         /* session + subsystem */
    CHSSH_STATE_READY,           /* netconf channel open — app data */
    CHSSH_STATE_CLOSING,
    CHSSH_STATE_CLOSED,
    CHSSH_STATE_ERROR
} chssh_state_t;

typedef enum {
    CHSSH_EVENT_NONE = 0,

    CHSSH_EVENT_IDENT_SENT,
    CHSSH_EVENT_IDENT_RECEIVED,  /* peer banner available in event.ident */
    CHSSH_EVENT_KEX_COMPLETE,
    CHSSH_EVENT_SERVICE_ACCEPTED,

    /* Auth: plumbing emits request; caller may call chssh_auth_decide (server) */
    CHSSH_EVENT_AUTH_PASSWORD,   /* server: peer offered password */
    CHSSH_EVENT_AUTH_NONE,       /* server: peer tried none */
    CHSSH_EVENT_AUTHENTICATED,

    CHSSH_EVENT_CHANNEL_OPEN,    /* session channel open */
    CHSSH_EVENT_SUBSYSTEM,       /* subsystem request (server) or ready (client) */
    CHSSH_EVENT_READY,           /* netconf channel ready for app data */

    CHSSH_EVENT_CHANNEL_DATA,    /* plaintext NETCONF bytes in event.data */
    CHSSH_EVENT_DISCONNECTED,
    CHSSH_EVENT_ERROR
} chssh_event_type_t;

#define CHSSH_IDENT_MAX 255
#define CHSSH_USER_MAX  128
#define CHSSH_PASS_MAX  256
#define CHSSH_ERROR_MAX 256
#define CHSSH_DATA_MAX  (64 * 1024)

typedef struct {
    chssh_event_type_t type;
    union {
        struct {
            char     banner[CHSSH_IDENT_MAX + 1];
            size_t   banner_len;
        } ident;
        struct {
            char     username[CHSSH_USER_MAX + 1];
            char     password[CHSSH_PASS_MAX + 1];
        } auth;
        struct {
            char     name[64]; /* e.g. "netconf" */
        } subsystem;
        struct {
            uint8_t  data[CHSSH_DATA_MAX];
            size_t   len;
        } data;
        struct {
            char     message[CHSSH_ERROR_MAX];
            int      code;
        } error;
    } u;
} chssh_event_t;

/* --- Lifecycle --- */

/**
 * Create context. @p cfg may be NULL (defaults: lab_mode=0, hold_ident=0).
 * Returns NULL on allocation failure or unsupported config.
 */
chssh_ctx_t *chssh_create(chssh_role_t role, const chssh_config_t *cfg);

void chssh_destroy(chssh_ctx_t *ctx);
void chssh_reset(chssh_ctx_t *ctx);

chssh_state_t chssh_current_state(const chssh_ctx_t *ctx);
chssh_role_t  chssh_role(const chssh_ctx_t *ctx);

/* --- I/O plumbing (no sockets) --- */

/**
 * Feed wire bytes from the peer (SSH stream, possibly after Calix identity).
 * @return bytes consumed (may be less than @p len if buffer full).
 */
size_t chssh_feed_input(chssh_ctx_t *ctx, const uint8_t *data, size_t len);

/** Drain bytes to write to the peer socket. */
size_t chssh_get_output(chssh_ctx_t *ctx, uint8_t *buf, size_t max_len);

/** Pull next event (1 = filled, 0 = empty). */
int chssh_next_event(chssh_ctx_t *ctx, chssh_event_t *event);

/* --- Call Home host control --- */

/**
 * When hold_ident was set, flush local SSH identification to the output buffer.
 * No-op if already flushed or hold_ident was 0.
 * @return 0 ok, -1 error.
 */
int chssh_flush_ident(chssh_ctx_t *ctx);

/** 1 if local identification has been queued/sent. */
int chssh_ident_flushed(const chssh_ctx_t *ctx);

/** 1 if peer identification line has been received. */
int chssh_peer_ident_seen(const chssh_ctx_t *ctx);

/**
 * Server: accept or reject the pending password/none auth from
 * CHSSH_EVENT_AUTH_PASSWORD / CHSSH_EVENT_AUTH_NONE.
 * If never called, library uses config server_password / allow_none_auth.
 */
int chssh_auth_decide(chssh_ctx_t *ctx, int accept);

/**
 * After CHSSH_STATE_READY: queue plaintext for the netconf channel
 * (encrypted on the wire in production mode; clear in lab_mode).
 * @return 0 ok, -1 not ready / overflow.
 */
int chssh_channel_send(chssh_ctx_t *ctx, const uint8_t *data, size_t len);

/** Request orderly close (sends disconnect when possible). */
int chssh_disconnect(chssh_ctx_t *ctx, const char *description);

#ifdef __cplusplus
}
#endif

#endif /* CHSSH_H */
