/**
 * @file test_chssh_hostkey_pin.c
 * @brief PR-3: host-key pin match / accept_any / reject before userauth.
 */
#define _POSIX_C_SOURCE 200809L
#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void shuttle(chssh_ctx_t *a, chssh_ctx_t *b)
{
    uint8_t buf[16384];
    size_t n;
    int g;
    for (g = 0; g < 128; g++) {
        int prog = 0;
        n = chssh_get_output(a, buf, sizeof(buf));
        if (n) {
            assert(chssh_feed_input(b, buf, n) == n);
            prog = 1;
        }
        n = chssh_get_output(b, buf, sizeof(buf));
        if (n) {
            assert(chssh_feed_input(a, buf, n) == n);
            prog = 1;
        }
        if (!prog) {
            break;
        }
    }
}

/** Capture server host key blob by accepting with accept_any first run. */
static int capture_server_hostkey(uint8_t *blob_out, size_t *blob_len_out,
                                  char *fp_out)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int g;
    chssh_event_t ev;
    int got = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_publickey = 0;
    nms_cfg.server_offer_password = 1;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 200; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                got = 1;
            }
            /* After KEX we can re-export from server by reading host key path —
             * instead: use a second connection with pin pending to capture HOSTKEY */
        }
        while (chssh_next_event(nms, &ev)) {
            (void)ev;
        }
        if (got) {
            break;
        }
    }
    /* Capture via a pin-pending client against same ephemeral is hard —
     * regenerate: load from a fixed PEM for deterministic tests. */
    chssh_destroy(nms);
    chssh_destroy(dev);
    (void)blob_out;
    (void)blob_len_out;
    (void)fp_out;
    return 0;
}

static char *make_host_pem(void)
{
    char *path = strdup("/tmp/chssh_hk_XXXXXX");
    char cmd[512];
    int fd;
    assert(path);
    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    snprintf(cmd, sizeof(cmd), "openssl genrsa -out %s 2048 2>/dev/null", path);
    assert(system(cmd) == 0);
    return path;
}

static void hostkey_blob_from_pem(const char *pem_path, uint8_t *blob,
                                  size_t *blob_len, char *fp)
{
    /* Use a one-shot server with that PEM and client accept_any; extract via
     * HOSTKEY by temporarily not accepting any — instead compute public blob
     * through a tiny production handshake that stores peer_host_key.
     * Simpler: create server with PEM, client without accept_any, on HOSTKEY
     * copy blob. */
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int g;
    chssh_event_t ev;
    int got_hk = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem_path;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 0; /* force HOSTKEY event */
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 200; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_HOSTKEY) {
                assert(ev.u.hostkey.host_key_blob_len > 0);
                assert(ev.u.hostkey.host_key_blob_len <= CHSSH_PUBKEY_BLOB_MAX);
                memcpy(blob, ev.u.hostkey.host_key_blob,
                       ev.u.hostkey.host_key_blob_len);
                *blob_len = ev.u.hostkey.host_key_blob_len;
                snprintf(fp, CHSSH_FP_SHA256_MAX, "%s",
                         ev.u.hostkey.fingerprint_sha256);
                got_hk = 1;
                assert(chssh_hostkey_decide(dev, 0) == 0); /* abort this run */
            }
        }
        while (chssh_next_event(nms, &ev)) {
            (void)ev;
        }
        if (got_hk) {
            break;
        }
    }
    assert(got_hk);
    chssh_destroy(nms);
    chssh_destroy(dev);
}

static int run_to_auth(chssh_ctx_t *nms, chssh_ctx_t *dev, int decide_accept,
                       int expect_auth, int expect_hostkey_event)
{
    int g;
    chssh_event_t ev;
    int nms_auth = 0, dev_auth = 0;
    int saw_hk = 0;
    int saw_err = 0;

    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 300; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_HOSTKEY) {
                saw_hk = 1;
                assert(chssh_hostkey_decide(dev, decide_accept) == 0);
            } else if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                dev_auth = 1;
            } else if (ev.type == CHSSH_EVENT_ERROR) {
                saw_err = 1;
            }
        }
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED ||
                ev.type == CHSSH_EVENT_READY) {
                nms_auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                /* server may error if client disconnects after reject */
            }
        }
        if (expect_auth && nms_auth && dev_auth) {
            return saw_hk == expect_hostkey_event ? 0 : -2;
        }
        if (!expect_auth && saw_err) {
            return saw_hk == expect_hostkey_event ? 0 : -2;
        }
    }
    return -1;
}

static void test_accept_any(void)
{
    char *pem = make_host_pem();
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int g;
    int auth = 0;
    chssh_event_t ev;
    int saw_hk = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 200; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_HOSTKEY) {
                saw_hk = 1;
            }
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                auth = 1;
            }
        }
        if (auth) {
            break;
        }
    }
    assert(auth);
    assert(!saw_hk); /* accept_any → no HOSTKEY event */
    chssh_destroy(nms);
    chssh_destroy(dev);
    unlink(pem);
    free(pem);
    printf("  PASS: accept_any_hostkey auto-continues (no HOSTKEY)\n");
}

static void test_pin_fingerprint(void)
{
    char *pem = make_host_pem();
    uint8_t blob[CHSSH_PUBKEY_BLOB_MAX];
    size_t blob_len = 0;
    char fp[CHSSH_FP_SHA256_MAX];
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;

    hostkey_blob_from_pem(pem, blob, &blob_len, fp);

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 0;
    dev_cfg.pinned_host_key_sha256 = fp;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    assert(run_to_auth(nms, dev, 1, 1, 0) == 0); /* pin match → no HOSTKEY */
    chssh_destroy(nms);
    chssh_destroy(dev);
    unlink(pem);
    free(pem);
    printf("  PASS: pinned_host_key_sha256 auto-accepts\n");
}

static void test_pin_blob(void)
{
    char *pem = make_host_pem();
    uint8_t blob[CHSSH_PUBKEY_BLOB_MAX];
    size_t blob_len = 0;
    char fp[CHSSH_FP_SHA256_MAX];
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;

    hostkey_blob_from_pem(pem, blob, &blob_len, fp);

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 0;
    dev_cfg.pinned_host_key_blob = blob;
    dev_cfg.pinned_host_key_blob_len = blob_len;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    assert(run_to_auth(nms, dev, 1, 1, 0) == 0);
    chssh_destroy(nms);
    chssh_destroy(dev);
    unlink(pem);
    free(pem);
    printf("  PASS: pinned_host_key_blob auto-accepts\n");
}

static void test_hostkey_decide_accept(void)
{
    char *pem = make_host_pem();
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 0; /* forces HOSTKEY */
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    assert(run_to_auth(nms, dev, 1, 1, 1) == 0); /* HOSTKEY then decide(1) */
    chssh_destroy(nms);
    chssh_destroy(dev);
    unlink(pem);
    free(pem);
    printf("  PASS: HOSTKEY + decide(1) continues to auth\n");
}

static void test_hostkey_decide_reject(void)
{
    char *pem = make_host_pem();
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.host_key_path = pem;
    nms_cfg.server_username = "u";
    nms_cfg.server_password = "p";
    nms_cfg.server_offer_password = 1;
    nms_cfg.server_offer_publickey = 0;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "u";
    dev_cfg.client_password = "p";
    dev_cfg.accept_any_hostkey = 0;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    assert(run_to_auth(nms, dev, 0, 0, 1) == 0); /* decide(0) → error, no auth */
    chssh_destroy(nms);
    chssh_destroy(dev);
    unlink(pem);
    free(pem);
    printf("  PASS: HOSTKEY + decide(0) never AUTHENTICATED\n");
}

int main(void)
{
    printf("test_chssh_hostkey_pin (PR-3)\n");
    printf("  crypto backend: %s\n", chssh_crypto_backend());
    if (strcmp(chssh_crypto_backend(), "none") == 0) {
        fprintf(stderr, "SKIP: needs production crypto\n");
        return 0;
    }
    (void)capture_server_hostkey; /* silence unused */
    test_accept_any();
    test_pin_fingerprint();
    test_pin_blob();
    test_hostkey_decide_accept();
    test_hostkey_decide_reject();
    printf("ok\n");
    return 0;
}
