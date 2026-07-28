/**
 * Multi-channel dialectic: CPE-style client opens two named subsystems
 * (auto_open_netconf=0) after auth; exchange data on each channel.
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

int main(void)
{
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int guard;
    int authed = 0;
    uint32_t ch_tel = 0, ch_ai = 0;
    int tel_ready = 0, ai_ready = 0;
    int saw_tel = 0, saw_ai = 0;
    chssh_event_t ev;
    const char *tel_msg = "{\"type\":\"cpe_perf\"}\n";
    const char *ai_msg = "POST /v1/chat/completions HTTP/1.1\r\n\r\n";

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 1;
    nms_cfg.server_username = "cpe-42";
    nms_cfg.server_password = "secret";
    nms_cfg.allowed_subsystems =
        "edge-telemetry,edge-pg,edge-ai,edge-control";

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 1;
    dev_cfg.client_username = "cpe-42";
    dev_cfg.client_password = "secret";
    dev_cfg.accept_any_hostkey = 1;
    dev_cfg.auto_open_netconf = 0;
    dev_cfg.allowed_subsystems =
        "edge-telemetry,edge-pg,edge-ai,edge-control";

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);

    for (guard = 0; guard < 100; guard++) {
        shuttle(dev, nms);
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                authed = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev error: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms error: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (authed) {
            break;
        }
    }
    assert(authed);
    assert(chssh_current_state(dev) == CHSSH_STATE_CHANNEL ||
           chssh_current_state(dev) == CHSSH_STATE_AUTH ||
           chssh_current_state(dev) == CHSSH_STATE_READY);

    /* Open two session channels + named subsystems */
    assert(chssh_channel_open_session(dev, &ch_tel) == 0);
    shuttle(dev, nms);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_OPEN &&
            ev.u.channel.channel_id == ch_tel) {
            assert(chssh_channel_request_subsystem(
                       dev, ch_tel, CHSSH_SUBSYSTEM_EDGE_TELEMETRY) == 0);
        }
    }
    shuttle(dev, nms);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_SUBSYSTEM &&
            ev.u.subsystem.channel_id == ch_tel) {
            assert(strcmp(ev.u.subsystem.name, CHSSH_SUBSYSTEM_EDGE_TELEMETRY) ==
                   0);
            tel_ready = 1;
        }
        /* Must NOT get READY (netconf-only) */
        assert(ev.type != CHSSH_EVENT_READY);
    }
    while (chssh_next_event(nms, &ev)) {
        if (ev.type == CHSSH_EVENT_SUBSYSTEM &&
            strcmp(ev.u.subsystem.name, CHSSH_SUBSYSTEM_EDGE_TELEMETRY) == 0) {
            /* server saw subsystem */
        }
        assert(ev.type != CHSSH_EVENT_READY);
    }
    assert(tel_ready);
    assert(chssh_channel_is_ready(dev, ch_tel));

    assert(chssh_channel_open_session(dev, &ch_ai) == 0);
    shuttle(dev, nms);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_OPEN &&
            ev.u.channel.channel_id == ch_ai) {
            assert(chssh_channel_request_subsystem(dev, ch_ai,
                                                   CHSSH_SUBSYSTEM_EDGE_AI) ==
                   0);
        }
    }
    shuttle(dev, nms);
    while (chssh_next_event(dev, &ev)) {
        if (ev.type == CHSSH_EVENT_SUBSYSTEM &&
            ev.u.subsystem.channel_id == ch_ai) {
            assert(strcmp(ev.u.subsystem.name, CHSSH_SUBSYSTEM_EDGE_AI) == 0);
            ai_ready = 1;
        }
        assert(ev.type != CHSSH_EVENT_READY);
    }
    assert(ai_ready);
    assert(ch_tel != ch_ai);

    /* Cross traffic on both channels */
    assert(chssh_channel_send_id(dev, ch_tel, (const uint8_t *)tel_msg,
                                 strlen(tel_msg)) == 0);
    assert(chssh_channel_send_id(dev, ch_ai, (const uint8_t *)ai_msg,
                                 strlen(ai_msg)) == 0);
    shuttle(dev, nms);
    while (chssh_next_event(nms, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA) {
            /* Server local channel ids differ from client; match by payload. */
            if (ev.u.data.len == strlen(tel_msg) &&
                memcmp(ev.u.data.data, tel_msg, ev.u.data.len) == 0) {
                saw_tel = 1;
            }
            if (ev.u.data.len == strlen(ai_msg) &&
                memcmp(ev.u.data.data, ai_msg, ev.u.data.len) == 0) {
                saw_ai = 1;
            }
        }
    }
    assert(saw_tel && saw_ai);

    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: multi-channel edge-telemetry + edge-ai\n");
    return 0;
}
