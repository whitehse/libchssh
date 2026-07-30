/**
 * Reverse port-forward dialectic: client tcpip-forward → server decide →
 * server opens forwarded-tcpip → bidirectional data.
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
    chssh_config_t srv_cfg, cli_cfg;
    chssh_ctx_t *srv, *cli;
    int guard;
    int srv_auth = 0, cli_auth = 0;
    int saw_fwd_req = 0, saw_fwd_ok = 0, saw_fwd_ch = 0;
    uint32_t fwd_ch = 0;
    chssh_event_t ev;
    const char *payload = "tunnel-bytes\n";
    int saw_data = 0;

    memset(&srv_cfg, 0, sizeof(srv_cfg));
    srv_cfg.lab_mode = 1;
    srv_cfg.server_username = "cpe-1";
    srv_cfg.server_password = "pw";
    srv_cfg.auto_open_netconf = 0;
    srv_cfg.allowed_subsystems = "edge-telemetry";

    memset(&cli_cfg, 0, sizeof(cli_cfg));
    cli_cfg.lab_mode = 1;
    cli_cfg.client_username = "cpe-1";
    cli_cfg.client_password = "pw";
    cli_cfg.accept_any_hostkey = 1;
    cli_cfg.auto_open_netconf = 0;
    cli_cfg.allowed_subsystems = "edge-telemetry";

    srv = chssh_create(CHSSH_ROLE_SERVER, &srv_cfg);
    cli = chssh_create(CHSSH_ROLE_CLIENT, &cli_cfg);
    assert(srv && cli);

    for (guard = 0; guard < 100; guard++) {
        shuttle(cli, srv);
        while (chssh_next_event(srv, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                srv_auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "srv: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(cli, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                cli_auth = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "cli: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (srv_auth && cli_auth) {
            break;
        }
    }
    assert(srv_auth && cli_auth);

    /* CPE client requests reverse listen on port 0 (allocate) */
    assert(chssh_request_tcpip_forward(cli, "127.0.0.1", 0) == 0);
    for (guard = 0; guard < 40; guard++) {
        shuttle(cli, srv);
        while (chssh_next_event(srv, &ev)) {
            if (ev.type == CHSSH_EVENT_TCPIP_FORWARD) {
                assert(strcmp(ev.u.forward.addr, "127.0.0.1") == 0);
                assert(ev.u.forward.port == 0);
                /* Host "bound" 19080 */
                assert(chssh_global_request_decide(srv, 1, 19080) == 0);
                saw_fwd_req = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "srv: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(cli, &ev)) {
            if (ev.type == CHSSH_EVENT_TCPIP_FORWARD_OK) {
                assert(ev.u.forward.port == 19080);
                saw_fwd_ok = 1;
            }
            if (ev.type == CHSSH_EVENT_TCPIP_FORWARD_FAIL) {
                fprintf(stderr, "cli: forward fail\n");
                assert(0);
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "cli: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (saw_fwd_req && saw_fwd_ok) {
            break;
        }
    }
    assert(saw_fwd_req && saw_fwd_ok);

    /* Host accepts consumer → open forwarded-tcpip toward CPE */
    assert(chssh_channel_open_forwarded_tcpip(srv, "127.0.0.1", 19080,
                                              "10.0.0.1", 45678, &fwd_ch) == 0);
    for (guard = 0; guard < 40; guard++) {
        shuttle(srv, cli);
        while (chssh_next_event(cli, &ev)) {
            if (ev.type == CHSSH_EVENT_FORWARDED_TCPIP) {
                assert(ev.u.tcpip.dest_port == 19080);
                assert(strcmp(ev.u.tcpip.originator, "10.0.0.1") == 0);
                assert(ev.u.tcpip.originator_port == 45678);
                assert(chssh_channel_is_ready(cli, ev.u.tcpip.channel_id));
                saw_fwd_ch = 1;
                /* CPE would dial local target; echo data path */
                assert(chssh_channel_send_id(cli, ev.u.tcpip.channel_id,
                                             (const uint8_t *)payload,
                                             strlen(payload)) == 0);
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "cli: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(srv, &ev)) {
            if (ev.type == CHSSH_EVENT_FORWARDED_TCPIP &&
                ev.u.tcpip.channel_id == fwd_ch) {
                /* open confirm on server side */
            }
            if (ev.type == CHSSH_EVENT_CHANNEL_DATA &&
                ev.u.data.channel_id == fwd_ch &&
                ev.u.data.len == strlen(payload) &&
                memcmp(ev.u.data.data, payload, ev.u.data.len) == 0) {
                saw_data = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "srv: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (saw_fwd_ch && saw_data) {
            break;
        }
    }
    assert(saw_fwd_ch);
    assert(saw_data);
    assert(chssh_channel_is_ready(srv, fwd_ch));

    chssh_destroy(srv);
    chssh_destroy(cli);
    printf("  PASS: tcpip-forward + forwarded-tcpip data\n");
    return 0;
}
