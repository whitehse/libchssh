/**
 * @file chssh.h
 * @brief Call Home SSH transport (RFC 8071) — pure plumbing API.
 *
 * System-call free, callback free. Caller owns sockets and policy.
 *
 * Channels: session channels with named subsystems. Default client path
 * auto-opens subsystem "netconf" (E7). Set auto_open_netconf=0 and use
 * chssh_channel_open_session + chssh_channel_request_subsystem for CPE
 * multi-service call-home (ADR 015).
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
#define CHSSH_VERSION_MINOR 3
#define CHSSH_VERSION_PATCH 0

/**
 * Crypto backend for lab_mode=0 production path.
 * "openssl" | "mbedtls" | "none" (lab-only build).
 */
const char *chssh_crypto_backend(void);

/** Default identification (OpenSSH-like; some field gear rejects exotic idents). */
#define CHSSH_DEFAULT_IDENT "SSH-2.0-OpenSSH_8.9"

/** Fixed NETCONF subsystem name (RFC 6242). */
#define CHSSH_SUBSYSTEM_NETCONF "netconf"

/** CPE call-home subsystem names (edgehost design). */
#define CHSSH_SUBSYSTEM_EDGE_TELEMETRY "edge-telemetry"
#define CHSSH_SUBSYSTEM_EDGE_PG        "edge-pg"
#define CHSSH_SUBSYSTEM_EDGE_AI        "edge-ai"
#define CHSSH_SUBSYSTEM_EDGE_CONTROL   "edge-control"

/** Staff reverse-access subsystems (over callhome SSH tunnel). */
#define CHSSH_SUBSYSTEM_SFTP "sftp"
#define CHSSH_SUBSYSTEM_TUN  "tun"  /* L3 IP tunnel (framed packets) */
#define CHSSH_SUBSYSTEM_TAP  "tap"  /* L2 Ethernet tunnel (framed frames) */

/** Max concurrent channels per connection (fixed table). */
#define CHSSH_MAX_CHANNELS 16

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
    size_t      max_channel_size;   /* 0 = default 256 KiB (plaintext channel) */

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
    const char *server_password; /* NULL = reject password auth (auto-decide) */

    /* --- Client credentials --- */
    const char *client_username;
    const char *client_password;
    /**
     * Client publickey identity (PR-2 dual-auth). Unencrypted OpenSSH or RSA PEM.
     * Tried before password when load succeeds. Host-owned path/PEM lifetime
     * must cover chssh_create…destroy.
     */
    const char *client_private_key_path;
    const char *client_private_key_pem; /* optional alternate to path */

    int accept_any_hostkey; /* CLIENT lab: accept peer host key without pin */
    int allow_none_auth;    /* SERVER lab: allow USERAUTH none */

    /**
     * SERVER method advertisement (PR-2). Zero-init defaults after create:
     * offer password=1, offer publickey=1 when production crypto available.
     * Set explicitly to 0 to disable a method.
     */
    int server_offer_publickey;
    int server_offer_password;
    /** SERVER max userauth attempts; 0 → default 6. */
    int server_max_auth_attempts;

    const char *host_key_path; /* SERVER: PEM path; NULL = ephemeral when possible */

    /**
     * Comma-separated subsystem allowlist for SERVER (and client peer-accept).
     * NULL or empty → "netconf" only. Example CPE host:
     * "edge-telemetry,edge-pg,edge-ai,edge-control,sftp,tun,tap"
     * Staff face: "sftp,tun,tap". CLIENT also uses this list when the peer
     * (server) requests a subsystem (staff reverse SFTP/TUN/TAP).
     */
    const char *allowed_subsystems;

    /**
     * CLIENT: after auth, automatically open a session and request "netconf".
     * Default 1 (E7 path). Set 0 for app-driven multi-channel (CPE call-home).
     */
    int auto_open_netconf;

    /**
     * When peer requests shell (CHANNEL_REQUEST "shell"), auto-accept if 1.
     * Default 0: emit CHSSH_EVENT_SHELL and wait for chssh_channel_request_decide.
     * Lab tests and simple CPE agents may set 1.
     */
    int auto_accept_shell;

    /**
     * When peer requests pty-req, auto-accept if 1 (reply SUCCESS + event).
     * Default 1: required for stock OpenSSH interactive clients (they send
     * pty-req with want_reply before shell). Set 0 only for strict tests.
     * Note: zero-init configs get default 1 in chssh_create.
     */
    int auto_accept_pty;
} chssh_config_t;

typedef struct chssh_ctx chssh_ctx_t;

typedef enum {
    CHSSH_STATE_IDLE = 0,
    CHSSH_STATE_IDENT,           /* exchanging SSH-2.0 banners */
    CHSSH_STATE_KEX,             /* key exchange */
    CHSSH_STATE_SERVICE,         /* service request/accept */
    CHSSH_STATE_AUTH,            /* user authentication */
    CHSSH_STATE_CHANNEL,         /* session + subsystem(s) */
    CHSSH_STATE_READY,           /* netconf (or multi-channel) active */
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
    CHSSH_EVENT_AUTH_PUBLICKEY,  /* server: publickey query or verified sig */
    CHSSH_EVENT_AUTHENTICATED,

    CHSSH_EVENT_CHANNEL_OPEN,    /* session channel open (u.channel) */
    CHSSH_EVENT_SUBSYSTEM,       /* subsystem request/ready (u.subsystem) */
    CHSSH_EVENT_SHELL,           /* peer requested shell (u.channel); decide */
    CHSSH_EVENT_EXEC,            /* peer/we requested exec (u.exec); SCP path */
    CHSSH_EVENT_PTY,             /* peer pty-req accepted (u.pty) */
    CHSSH_EVENT_WINDOW_CHANGE,   /* peer window-change (u.pty dims) */
    CHSSH_EVENT_READY,           /* netconf channel ready (E7 compat) */

    /* Port forward (RFC 4254 §7) — library is socket-free; host binds/dials */
    CHSSH_EVENT_TCPIP_FORWARD,         /* peer tcpip-forward (u.forward) */
    CHSSH_EVENT_TCPIP_FORWARD_CANCEL,  /* peer cancel-tcpip-forward */
    CHSSH_EVENT_TCPIP_FORWARD_OK,      /* our request accepted (u.forward) */
    CHSSH_EVENT_TCPIP_FORWARD_FAIL,    /* our request rejected */
    CHSSH_EVENT_DIRECT_TCPIP,          /* peer direct-tcpip open (u.tcpip) */
    CHSSH_EVENT_FORWARDED_TCPIP, /* peer/us forwarded-tcpip open (u.tcpip) */

    CHSSH_EVENT_CHANNEL_DATA,    /* plaintext bytes (u.data) */
    CHSSH_EVENT_CHANNEL_EOF,     /* peer EOF on channel (u.channel) */
    CHSSH_EVENT_CHANNEL_CLOSE,   /* channel closed (u.channel) */
    CHSSH_EVENT_DISCONNECTED,
    CHSSH_EVENT_ERROR
} chssh_event_type_t;

#define CHSSH_IDENT_MAX 255
#define CHSSH_USER_MAX  128
#define CHSSH_PASS_MAX  256
#define CHSSH_ERROR_MAX 256
#define CHSSH_DATA_MAX  (64 * 1024)
#define CHSSH_SUBSYS_NAME_MAX 63
#define CHSSH_TERM_MAX  32
#define CHSSH_ADDR_MAX  255
#define CHSSH_CMD_MAX   512   /* CHANNEL_REQUEST exec command string */
/** OpenSSH-style SHA256 fingerprint string: "SHA256:" + unpadded base64. */
#define CHSSH_FP_SHA256_MAX 96
/** Max algorithm name (e.g. ssh-ed25519, rsa-sha2-256). */
#define CHSSH_ALGO_MAX 64
/** Max SSH public key wire blob (RSA-4096-ish + headroom). */
#define CHSSH_PUBKEY_BLOB_MAX 8192
/** Max authorized_keys line when encoding. */
#define CHSSH_OPENSSH_LINE_MAX 16384

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
        /**
         * AUTH_PUBLICKEY: pointers valid until chssh_auth_decide / next
         * pending auth event. Host should copy fingerprint if needed.
         */
        struct {
            char     username[CHSSH_USER_MAX + 1];
            char     algo[CHSSH_ALGO_MAX];
            const uint8_t *public_blob;
            size_t   public_blob_len;
            char     fingerprint_sha256[CHSSH_FP_SHA256_MAX];
            int      signature_present; /* 0=query, 1=signed+verified */
        } auth_pk;
        struct {
            uint32_t channel_id; /* local channel id */
            char     name[CHSSH_SUBSYS_NAME_MAX + 1];
        } subsystem;
        struct {
            uint32_t channel_id; /* local channel id */
            char     chan_type[32]; /* e.g. "session" */
        } channel;
        struct {
            uint32_t channel_id; /* local channel id */
            char     command[CHSSH_CMD_MAX + 1];
        } exec;
        struct {
            uint32_t channel_id;
            char     term[CHSSH_TERM_MAX + 1]; /* empty on window-change */
            uint32_t cols;
            uint32_t rows;
            uint32_t width_px;
            uint32_t height_px;
        } pty;
        struct {
            char     addr[CHSSH_ADDR_MAX + 1]; /* bind address */
            uint32_t port;                    /* 0 = allocate */
            int      want_reply;
        } forward;
        struct {
            uint32_t channel_id; /* local channel id */
            char     dest_host[CHSSH_ADDR_MAX + 1];
            uint32_t dest_port;
            char     originator[CHSSH_ADDR_MAX + 1];
            uint32_t originator_port;
            char     chan_type[32]; /* "direct-tcpip" | "forwarded-tcpip" */
        } tcpip;
        struct {
            uint32_t channel_id; /* local channel id */
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
 * Create context. @p cfg may be NULL (defaults: lab_mode=0, hold_ident=0,
 * auto_open_netconf=1, allowed_subsystems=netconf).
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
 * Server: accept or reject pending auth from AUTH_PASSWORD / AUTH_NONE /
 * AUTH_PUBLICKEY.
 *   - password/none: SUCCESS or FAILURE (session stays open on reject)
 *   - publickey query (signature_present=0): accept → PK_OK; reject → FAILURE
 *   - publickey signed (signature_present=1): accept → SUCCESS; reject → FAILURE
 * FAILURE advertises remaining offered methods. Invalid crypto signatures
 * never raise AUTH_PUBLICKEY (library sends FAILURE itself).
 */
int chssh_auth_decide(chssh_ctx_t *ctx, int accept);

/* --- Multi-channel API (ADR 015) --- */

/**
 * After authentication: open a session channel (either role).
 * On success fills @p local_id_out with the local channel id.
 * Server uses this to open a staff shell channel toward a CPE client.
 * @return 0 ok, -1 error.
 */
int chssh_channel_open_session(chssh_ctx_t *ctx, uint32_t *local_id_out);

/**
 * Request subsystem @p name on an open session channel (after OPEN confirm).
 * Name must be on the server allowlist when we are server (peer request);
 * client may request any name (server enforces).
 * @return 0 ok, -1 error.
 */
int chssh_channel_request_subsystem(chssh_ctx_t *ctx, uint32_t local_id,
                                    const char *name);

/**
 * Request an interactive shell on an open session channel (after OPEN confirm).
 * Used by edgehost toward CPE for staff reverse shell (no CPE sshd).
 * @return 0 ok, -1 error.
 */
int chssh_channel_request_shell(chssh_ctx_t *ctx, uint32_t local_id);

/**
 * Request CHANNEL_REQUEST "exec" with @p command (OpenSSH remote command / SCP).
 * May be called while channel is still OPENING (deferred until OPEN confirm).
 * On success peer emits CHSSH_EVENT_EXEC (or we receive SUCCESS → EXEC ready).
 * @return 0 ok, -1 error.
 */
int chssh_channel_request_exec(chssh_ctx_t *ctx, uint32_t local_id,
                               const char *command);

/**
 * Request a pseudo-terminal on an open session channel (OpenSSH-compatible
 * CHANNEL_REQUEST "pty-req"). Peer should accept before shell for interactive
 * clients. Modes blob is empty (peer may ignore).
 * @return 0 ok, -1 error.
 */
int chssh_channel_request_pty(chssh_ctx_t *ctx, uint32_t local_id,
                              const char *term, uint32_t cols, uint32_t rows);

/**
 * Send CHANNEL_REQUEST "window-change" (no want_reply). Used for browser
 * xterm.js resize → CPE PTY TIOCSWINSZ path.
 */
int chssh_channel_window_change(chssh_ctx_t *ctx, uint32_t local_id,
                                uint32_t cols, uint32_t rows);

/**
 * Accept or reject a pending channel request (shell) after CHSSH_EVENT_SHELL.
 * @return 0 ok, -1 no pending / error.
 */
int chssh_channel_request_decide(chssh_ctx_t *ctx, uint32_t local_id,
                                 int accept);

/* --- Port forward (RFC 4254 §7; host owns sockets) --- */

/**
 * Client (or either role): request peer to listen for reverse connections
 * (GLOBAL_REQUEST "tcpip-forward"). Peer emits CHSSH_EVENT_TCPIP_FORWARD;
 * on success we get CHSSH_EVENT_TCPIP_FORWARD_OK (port may be allocated).
 * @p port 0 asks peer to choose. @return 0 ok, -1 error.
 */
int chssh_request_tcpip_forward(chssh_ctx_t *ctx, const char *addr,
                                uint32_t port);

/**
 * Cancel a previous reverse listen (GLOBAL_REQUEST "cancel-tcpip-forward").
 */
int chssh_request_cancel_tcpip_forward(chssh_ctx_t *ctx, const char *addr,
                                       uint32_t port);

/**
 * After CHSSH_EVENT_TCPIP_FORWARD: accept (bind done) or reject.
 * On accept with requested port 0, pass the actually bound port in
 * @p bound_port (sent in REQUEST_SUCCESS payload per RFC 4254).
 */
int chssh_global_request_decide(chssh_ctx_t *ctx, int accept,
                                uint32_t bound_port);

/**
 * After host accept on reverse listener: open "forwarded-tcpip" toward peer
 * (typically CPE client). On confirm channel is READY for data.
 */
int chssh_channel_open_forwarded_tcpip(chssh_ctx_t *ctx, const char *conn_addr,
                                       uint32_t conn_port, const char *orig_addr,
                                       uint32_t orig_port,
                                       uint32_t *local_id_out);

/**
 * Open "direct-tcpip" (local forward) toward peer. Peer emits
 * CHSSH_EVENT_DIRECT_TCPIP and must chssh_channel_open_decide.
 */
int chssh_channel_open_direct_tcpip(chssh_ctx_t *ctx, const char *dest_host,
                                    uint32_t dest_port, const char *orig_addr,
                                    uint32_t orig_port,
                                    uint32_t *local_id_out);

/**
 * Accept/reject pending direct-tcpip (or other deferred open) after event.
 * Accept sends OPEN_CONFIRM and marks channel READY.
 */
int chssh_channel_open_decide(chssh_ctx_t *ctx, uint32_t local_id, int accept);

/**
 * Queue plaintext for a specific channel (encrypted on wire in production).
 * @return 0 ok, -1 not ready / overflow / window.
 */
int chssh_channel_send_id(chssh_ctx_t *ctx, uint32_t local_id,
                          const uint8_t *data, size_t len);

/**
 * Send on the primary ready channel (first READY). E7/netconf compat wrapper.
 * Prefer chssh_channel_send_id for multi-channel.
 */
int chssh_channel_send(chssh_ctx_t *ctx, const uint8_t *data, size_t len);

/** 1 if @p local_id is open and subsystem accepted (or netconf READY). */
int chssh_channel_is_ready(const chssh_ctx_t *ctx, uint32_t local_id);

/**
 * Send CHANNEL_EOF then CHANNEL_CLOSE for @p local_id (best-effort).
 * Used when a reverse staff shell PTY dies so the peer drops sticky state.
 * @return 0 ok (or already closed), -1 unknown channel / send fail.
 */
int chssh_channel_close(chssh_ctx_t *ctx, uint32_t local_id);

/**
 * Send a transport keepalive after keys are active (post-NEWKEYS).
 * Uses OpenSSH-compatible SSH_MSG_GLOBAL_REQUEST "keepalive@openssh.com"
 * (want_reply=1). Peer SUCCESS/FAILURE is ignored. Safe once encrypt_out
 * is on (KEX complete); preferred while CHSSH_STATE_READY to prevent
 * field gear idle disconnects.
 * @return 0 ok, -1 not ready / not encrypted / send failed.
 */
int chssh_send_keepalive(chssh_ctx_t *ctx);

/** Request orderly close (sends disconnect when possible). */
int chssh_disconnect(chssh_ctx_t *ctx, const char *description);

/* --- Public key blob / fingerprint helpers (PR-1a) --- */

typedef enum {
    CHSSH_PUBKEY_ALG_UNKNOWN = 0,
    CHSSH_PUBKEY_ALG_SSH_RSA = 1,     /* wire type "ssh-rsa" */
    CHSSH_PUBKEY_ALG_SSH_ED25519 = 2  /* wire type "ssh-ed25519" */
} chssh_pubkey_alg_t;

/**
 * SHA256 fingerprint of an SSH public key blob (OpenSSH form).
 * @p out must hold CHSSH_FP_SHA256_MAX bytes; always NUL-terminated on success.
 * @return 0 ok, -1 bad args / crypto backend unavailable.
 */
int chssh_pubkey_fingerprint_sha256(const uint8_t *blob, size_t len,
                                    char out[CHSSH_FP_SHA256_MAX]);

/**
 * Validate SSH public key wire blob and report algorithm.
 * RSA: string "ssh-rsa" || mpint e || mpint n.
 * ed25519: string "ssh-ed25519" || string (32-byte public key).
 * @return 0 ok, -1 invalid / truncated / unknown type.
 */
int chssh_pubkey_blob_parse(const uint8_t *blob, size_t len,
                            chssh_pubkey_alg_t *alg_out);

/**
 * Parse one OpenSSH authorized_keys / .pub line:
 *   &lt;algo&gt; &lt;base64-blob&gt; [comment…]
 * Skips leading options fields only when they contain '=' (OpenSSH option
 * tokens); plain algorithm tokens are accepted as type.
 * @return 0 ok, -1 parse / size / validation error.
 */
int chssh_pubkey_openssh_line_parse(const char *line, uint8_t *blob,
                                    size_t blob_cap, size_t *blob_len,
                                    chssh_pubkey_alg_t *alg_out, char *comment,
                                    size_t comment_cap);

/**
 * Encode blob as OpenSSH single-line public key (algo base64 [comment]).
 * @return 0 ok, -1 bad blob / buffer too small.
 */
int chssh_pubkey_openssh_line_encode(const uint8_t *blob, size_t blob_len,
                                     const char *comment, char *line,
                                     size_t line_cap);

/**
 * Build RFC 4253 RSA public key blob from bare big-endian e and n
 * (no mpint length headers; high-bit zero-pad applied as needed).
 */
int chssh_pubkey_blob_encode_rsa(const uint8_t *e, size_t e_len,
                                 const uint8_t *n, size_t n_len, uint8_t *out,
                                 size_t cap, size_t *out_len);

/** Build ssh-ed25519 public key blob from 32-byte raw public key. */
int chssh_pubkey_blob_encode_ed25519(const uint8_t pk[32], uint8_t *out,
                                     size_t cap, size_t *out_len);

/** Wire algorithm name for @p alg, or NULL if unknown. */
const char *chssh_pubkey_alg_name(chssh_pubkey_alg_t alg);

/* --- Identity + userauth signatures (PR-1b RSA / PR-1c ed25519) --- */

/**
 * RFC 4252 §7 publickey signature message (session id string +
 * USERAUTH_REQUEST fields with signature-follows = TRUE).
 */
int chssh_userauth_build_signed_data(const uint8_t *session_id,
                                     size_t session_id_len,
                                     const char *username, const char *service,
                                     const char *pk_alg,
                                     const uint8_t *pubkey_blob,
                                     size_t pubkey_blob_len, uint8_t *out,
                                     size_t cap, size_t *out_len);

/**
 * Opaque private identity (RSA PEM/PKCS#8/OpenSSH, or ed25519 OpenSSH).
 * Passphrase-protected keys rejected.
 */
typedef struct chssh_identity chssh_identity_t;

chssh_identity_t *chssh_identity_load_file(const char *path);
chssh_identity_t *chssh_identity_load_mem(const void *data, size_t len);
void              chssh_identity_free(chssh_identity_t *id);

chssh_pubkey_alg_t chssh_identity_alg(const chssh_identity_t *id);
/** "rsa-sha2-256" or "ssh-ed25519". */
const char *chssh_identity_sig_alg(const chssh_identity_t *id);
int chssh_identity_public_blob(const chssh_identity_t *id, uint8_t *out,
                               size_t cap, size_t *out_len);
/** SSH signature blob: string alg || string raw. */
int chssh_identity_sign(const chssh_identity_t *id, const uint8_t *msg,
                        size_t msg_len, uint8_t *sig_out, size_t cap,
                        size_t *sig_len);

/**
 * Verify userauth (or host-key) signature over @p msg with public key blob.
 * @p pk_alg: rsa-sha2-256 | ssh-rsa | ssh-ed25519
 */
int chssh_userauth_verify(const char *pk_alg, const uint8_t *pubkey_blob,
                          size_t pubkey_blob_len, const uint8_t *sig_blob,
                          size_t sig_len, const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif

#endif /* CHSSH_H */
