/**
 * Production OpenSSL KEX dialectic: NMS server ↔ device client (lab_mode=0).
 */
#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void shuttle(chssh_ctx_t *a, chssh_ctx_t *b)
{
    uint8_t buf[16384];
    size_t n;
    int guard;
    for (guard = 0; guard < 128; guard++) {
        int progress = 0;
        n = chssh_get_output(a, buf, sizeof(buf));
        if (n) {
            assert(chssh_feed_input(b, buf, n) == n);
            progress = 1;
        }
        n = chssh_get_output(b, buf, sizeof(buf));
        if (n) {
            assert(chssh_feed_input(a, buf, n) == n);
            progress = 1;
        }
        if (!progress) {
            break;
        }
    }
}

static void drain(chssh_ctx_t *ctx, int *ready, const char *who)
{
    chssh_event_t ev;
    while (chssh_next_event(ctx, &ev)) {
        if (ev.type == CHSSH_EVENT_READY) {
            *ready = 1;
        }
        if (ev.type == CHSSH_EVENT_ERROR) {
            fprintf(stderr, "%s error: %s\n", who, ev.u.error.message);
            assert(0);
        }
    }
}

int main(void)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int nms_ready = 0, dev_ready = 0;
    int guard;
    const char *msg = "urn:ietf:params:netconf:base:1.0";
    chssh_event_t ev;
    int saw = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0; /* production crypto */
    nms_cfg.hold_ident = 1;
    nms_cfg.server_username = "sysadmin";
    nms_cfg.server_password = "sysadmin";

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "sysadmin";
    dev_cfg.client_password = "sysadmin";
    dev_cfg.accept_any_hostkey = 1;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);

    shuttle(dev, nms);
    assert(chssh_peer_ident_seen(nms));
    assert(chssh_flush_ident(nms) == 0);

    for (guard = 0; guard < 200; guard++) {
        shuttle(nms, dev);
        drain(nms, &nms_ready, "nms");
        drain(dev, &dev_ready, "dev");
        if (nms_ready && dev_ready) {
            break;
        }
    }
    if (!nms_ready || !dev_ready) {
        fprintf(stderr, "timeout: nms_ready=%d dev_ready=%d nms_st=%d dev_st=%d\n",
                nms_ready, dev_ready, (int)chssh_current_state(nms),
                (int)chssh_current_state(dev));
        return 1;
    }

    assert(chssh_channel_send(dev, (const uint8_t *)msg, strlen(msg)) == 0);
    shuttle(dev, nms);
    while (chssh_next_event(nms, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA) {
            assert(ev.u.data.len == strlen(msg));
            assert(memcmp(ev.u.data.data, msg, ev.u.data.len) == 0);
            saw = 1;
        }
        if (ev.type == CHSSH_EVENT_ERROR) {
            fprintf(stderr, "nms post-ready error: %s\n", ev.u.error.message);
            return 1;
        }
    }
    assert(saw);

    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: production OpenSSL KEX dialectic (group14-sha256 + aes128-ctr)\n");
    return 0;
}
