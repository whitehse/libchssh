/**
 * Dialectic: NMS SSH server (Call Home) ↔ device SSH client.
 * Lab mode buffer exchange until CHSSH_STATE_READY, then channel data.
 */
#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void shuttle(chssh_ctx_t *a, chssh_ctx_t *b)
{
    uint8_t buf[8192];
    size_t n;
    int guard;
    for (guard = 0; guard < 64; guard++) {
        int progress = 0;
        n = chssh_get_output(a, buf, sizeof(buf));
        if (n) {
            size_t used = chssh_feed_input(b, buf, n);
            assert(used == n);
            progress = 1;
        }
        n = chssh_get_output(b, buf, sizeof(buf));
        if (n) {
            size_t used = chssh_feed_input(a, buf, n);
            assert(used == n);
            progress = 1;
        }
        if (!progress) {
            break;
        }
    }
}

static void drain_events(chssh_ctx_t *ctx, int *ready)
{
    chssh_event_t ev;
    while (chssh_next_event(ctx, &ev)) {
        if (ev.type == CHSSH_EVENT_READY) {
            *ready = 1;
        }
        if (ev.type == CHSSH_EVENT_ERROR) {
            fprintf(stderr, "error: %s\n", ev.u.error.message);
            assert(0 && "unexpected error event");
        }
    }
}

int main(void)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int nms_ready = 0, dev_ready = 0;
    int guard;
    const char *hello = "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>";
    chssh_event_t ev;
    int saw_data = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 1;
    nms_cfg.hold_ident = 1; /* simulate post-identity flush */
    nms_cfg.server_username = "sysadmin";
    nms_cfg.server_password = "sysadmin";

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 1;
    dev_cfg.client_username = "sysadmin";
    dev_cfg.client_password = "sysadmin";
    dev_cfg.accept_any_hostkey = 1;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);

    /* Device speaks first on wire after TCP (SSH client); NMS holds. */
    shuttle(dev, nms);
    assert(chssh_peer_ident_seen(nms) == 1);
    assert(chssh_ident_flushed(nms) == 0);

    /* Host finishes Calix identity → flush SSH server banner. */
    assert(chssh_flush_ident(nms) == 0);

    for (guard = 0; guard < 100; guard++) {
        shuttle(nms, dev);
        drain_events(nms, &nms_ready);
        drain_events(dev, &dev_ready);
        if (nms_ready && dev_ready) {
            break;
        }
    }
    assert(nms_ready && dev_ready);
    assert(chssh_current_state(nms) == CHSSH_STATE_READY);
    assert(chssh_current_state(dev) == CHSSH_STATE_READY);

    /* NETCONF-shaped app data over channel */
    assert(chssh_channel_send(nms, (const uint8_t *)hello, strlen(hello)) == 0);
    shuttle(nms, dev);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA) {
            assert(ev.u.data.len == strlen(hello));
            assert(memcmp(ev.u.data.data, hello, ev.u.data.len) == 0);
            saw_data = 1;
        }
    }
    assert(saw_data);

    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: Call Home dialectic (hold→auth→subsystem netconf→data)\n");
    return 0;
}
