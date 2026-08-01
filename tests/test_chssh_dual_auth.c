/**
 * @file test_chssh_dual_auth.c
 * @brief PR-2: client dual-auth (pubkey→password) + server publickey events.
 *
 * Uses production crypto (lab_mode=0) so session_id exists for signatures.
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

static int pump_until_auth(chssh_ctx_t *nms, chssh_ctx_t *dev, int *nms_auth,
                           int *dev_auth, const char *expect_fp, int accept_pk,
                           int accept_pw, const char *expect_user,
                           const char *expect_pass)
{
    int g;
    chssh_event_t ev;
    *nms_auth = *dev_auth = 0;
    for (g = 0; g < 300; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTH_PUBLICKEY) {
                int ok = 1;
                if (expect_fp && expect_fp[0] &&
                    strcmp(ev.u.auth_pk.fingerprint_sha256, expect_fp) != 0) {
                    ok = 0;
                }
                if (expect_user &&
                    strcmp(ev.u.auth_pk.username, expect_user) != 0) {
                    ok = 0;
                }
                assert(ev.u.auth_pk.signature_present == 1 ||
                       ev.u.auth_pk.signature_present == 0);
                assert(chssh_auth_decide(nms, accept_pk && ok) == 0);
            } else if (ev.type == CHSSH_EVENT_AUTH_PASSWORD) {
                int ok = 1;
                if (expect_user &&
                    strcmp(ev.u.auth.username, expect_user) != 0) {
                    ok = 0;
                }
                if (expect_pass &&
                    strcmp(ev.u.auth.password, expect_pass) != 0) {
                    ok = 0;
                }
                assert(chssh_auth_decide(nms, accept_pw && ok) == 0);
            } else if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                *nms_auth = 1;
            } else if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms error: %s\n", ev.u.error.message);
                return -1;
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                *dev_auth = 1;
            } else if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev error: %s\n", ev.u.error.message);
                return -1;
            }
        }
        if (*nms_auth && *dev_auth) {
            return 0;
        }
    }
    return -1;
}

static char *make_ed25519_key(void)
{
    char *path = strdup("/tmp/chssh_dual_ed_XXXXXX");
    char cmd[512];
    int fd;
    assert(path);
    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -t ed25519 -N '' -f %s -C dual-auth -q", path);
    assert(system(cmd) == 0);
    return path;
}

static void fingerprint_of_key(const char *path, char *fp_out)
{
    chssh_identity_t *id = chssh_identity_load_file(path);
    uint8_t pub[256];
    size_t plen = 0;
    assert(id);
    assert(chssh_identity_public_blob(id, pub, sizeof(pub), &plen) == 0);
    assert(chssh_pubkey_fingerprint_sha256(pub, plen, fp_out) == 0);
    chssh_identity_free(id);
}

/** Pubkey success: server accepts matching fingerprint; password unused. */
static void test_pubkey_success(void)
{
    char *keypath = make_ed25519_key();
    char fp[CHSSH_FP_SHA256_MAX];
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int nms_auth = 0, dev_auth = 0;
    char pubpath[256];

    fingerprint_of_key(keypath, fp);

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.server_password = NULL; /* host decides */
    nms_cfg.server_offer_publickey = 1;
    nms_cfg.server_offer_password = 1;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "cpe1";
    dev_cfg.client_password = "wrong-should-not-be-used";
    dev_cfg.client_private_key_path = keypath;
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    assert(pump_until_auth(nms, dev, &nms_auth, &dev_auth, fp, 1, 0, "cpe1",
                           NULL) == 0);
    assert(nms_auth && dev_auth);
    chssh_destroy(nms);
    chssh_destroy(dev);
    snprintf(pubpath, sizeof(pubpath), "%s.pub", keypath);
    unlink(keypath);
    unlink(pubpath);
    free(keypath);
    printf("  PASS: publickey success (password not required)\n");
}

/** Pubkey rejected → password success. */
static void test_pubkey_fail_password_ok(void)
{
    char *keypath = make_ed25519_key();
    char fp[CHSSH_FP_SHA256_MAX];
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int nms_auth = 0, dev_auth = 0;
    char pubpath[256];

    fingerprint_of_key(keypath, fp);

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.server_password = NULL;
    nms_cfg.server_offer_publickey = 1;
    nms_cfg.server_offer_password = 1;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "cpe1";
    dev_cfg.client_password = "secret";
    dev_cfg.client_private_key_path = keypath;
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    /* reject publickey (accept_pk=0), accept password */
    assert(pump_until_auth(nms, dev, &nms_auth, &dev_auth, fp, 0, 1, "cpe1",
                           "secret") == 0);
    assert(nms_auth && dev_auth);
    chssh_destroy(nms);
    chssh_destroy(dev);
    snprintf(pubpath, sizeof(pubpath), "%s.pub", keypath);
    unlink(keypath);
    unlink(pubpath);
    free(keypath);
    printf("  PASS: publickey reject → password success\n");
}

/** Both fail → client ERROR. */
static void test_both_fail(void)
{
    char *keypath = make_ed25519_key();
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int g;
    int saw_err = 0;
    chssh_event_t ev;
    char pubpath[256];

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.server_password = NULL;
    nms_cfg.server_offer_publickey = 1;
    nms_cfg.server_offer_password = 1;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "cpe1";
    dev_cfg.client_password = "nope";
    dev_cfg.client_private_key_path = keypath;
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 300; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTH_PUBLICKEY ||
                ev.type == CHSSH_EVENT_AUTH_PASSWORD) {
                assert(chssh_auth_decide(nms, 0) == 0);
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_ERROR) {
                saw_err = 1;
            }
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                assert(0 && "should not authenticate");
            }
        }
        if (saw_err) {
            break;
        }
    }
    assert(saw_err);
    chssh_destroy(nms);
    chssh_destroy(dev);
    snprintf(pubpath, sizeof(pubpath), "%s.pub", keypath);
    unlink(keypath);
    unlink(pubpath);
    free(keypath);
    printf("  PASS: both methods fail → client error\n");
}

/** Password-only still works (existing production path). */
static void test_password_only_compat(void)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int nms_ready = 0, dev_ready = 0;
    int g;
    chssh_event_t ev;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.hold_ident = 1;
    nms_cfg.server_username = "sysadmin";
    nms_cfg.server_password = "sysadmin";
    nms_cfg.server_offer_publickey = 0;
    nms_cfg.server_offer_password = 1;

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "sysadmin";
    dev_cfg.client_password = "sysadmin";
    dev_cfg.accept_any_hostkey = 1;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);
    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 200; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_READY ||
                ev.type == CHSSH_EVENT_AUTHENTICATED) {
                nms_ready = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_READY ||
                ev.type == CHSSH_EVENT_AUTHENTICATED) {
                dev_ready = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (nms_ready && dev_ready) {
            break;
        }
    }
    assert(nms_ready && dev_ready);
    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: password-only production still works\n");
}

int main(void)
{
    printf("test_chssh_dual_auth (PR-2)\n");
    printf("  crypto backend: %s\n", chssh_crypto_backend());
    if (strcmp(chssh_crypto_backend(), "none") == 0) {
        fprintf(stderr, "SKIP: needs production crypto\n");
        return 0;
    }
    test_password_only_compat();
    test_pubkey_success();
    test_pubkey_fail_password_ok();
    test_both_fail();
    printf("ok\n");
    return 0;
}
