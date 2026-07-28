/**
 * Server-initiated session + shell (staff reverse path).
 * NMS/server opens session toward CPE client; client auto-accepts shell;
 * bidirectional channel data.
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

int main(void)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int guard;
    int nms_auth = 0, dev_auth = 0;
    int nms_shell = 0, dev_shell = 0;
    uint32_t shell_ch = 0;
    chssh_event_t ev;
    const char *up = "whoami\n";
    const char *down = "root\n";
    int saw_up = 0, saw_down = 0;

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 1;
    nms_cfg.server_username = "cpe-1";
    nms_cfg.server_password = "pw";
    nms_cfg.allowed_subsystems = "edge-telemetry,edge-ai";

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 1;
    dev_cfg.client_username = "cpe-1";
    dev_cfg.client_password = "pw";
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;
    dev_cfg.allowed_subsystems = "edge-telemetry,edge-ai";
    dev_cfg.auto_accept_shell = 1;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);

    for (guard = 0; guard < 100; guard++) {
        shuttle(dev, nms);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                nms_auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                dev_auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (nms_auth && dev_auth) {
            break;
        }
    }
    assert(nms_auth && dev_auth);

    /* Server opens shell channel toward CPE */
    assert(chssh_channel_open_session(nms, &shell_ch) == 0);
    shuttle(nms, dev);
    while (chssh_next_event(nms, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_OPEN &&
            ev.u.channel.channel_id == shell_ch) {
            assert(chssh_channel_request_shell(nms, shell_ch) == 0);
        }
    }
    shuttle(nms, dev);
    for (guard = 0; guard < 20; guard++) {
        shuttle(nms, dev);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_SHELL &&
                strcmp(ev.u.channel.chan_type, "shell-ready") == 0) {
                nms_shell = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_SHELL &&
                strcmp(ev.u.channel.chan_type, "shell-ready") == 0) {
                dev_shell = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (nms_shell && dev_shell) {
            break;
        }
    }
    assert(nms_shell && dev_shell);
    assert(chssh_channel_is_ready(nms, shell_ch));

    assert(chssh_channel_send_id(nms, shell_ch, (const uint8_t *)up,
                                 strlen(up)) == 0);
    shuttle(nms, dev);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA &&
            ev.u.data.len == strlen(up) &&
            memcmp(ev.u.data.data, up, ev.u.data.len) == 0) {
            saw_up = 1;
            assert(chssh_channel_send_id(dev, ev.u.data.channel_id,
                                         (const uint8_t *)down,
                                         strlen(down)) == 0);
        }
    }
    assert(saw_up);
    shuttle(dev, nms);
    while (chssh_next_event(nms, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA &&
            ev.u.data.len == strlen(down) &&
            memcmp(ev.u.data.data, down, ev.u.data.len) == 0) {
            saw_down = 1;
        }
    }
    assert(saw_down);

    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: server-initiated shell channel + data\n");
    return 0;
}
