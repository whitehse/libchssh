/**
 * OpenSSH-style interactive path: client opens session, pty-req, shell.
 * Server must SUCCESS pty-req (want_reply) or stock ssh hangs.
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
    int saw_pty = 0, saw_shell = 0, cli_shell = 0;
    int shell_sent = 0;
    uint32_t ch_id = 0;
    chssh_event_t ev;
    const char *msg = "hello-pty\n";
    int saw_data = 0;

    memset(&srv_cfg, 0, sizeof(srv_cfg));
    srv_cfg.lab_mode = 1;
    srv_cfg.server_username = "staff";
    srv_cfg.server_password = "staff-lab";
    srv_cfg.auto_accept_shell = 1;
    srv_cfg.auto_open_netconf = 0;
    srv_cfg.allowed_subsystems = "edge-telemetry";

    memset(&cli_cfg, 0, sizeof(cli_cfg));
    cli_cfg.lab_mode = 1;
    cli_cfg.client_username = "staff";
    cli_cfg.client_password = "staff-lab";
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

    /* Client (OpenSSH-like): session → pty-req → shell */
    assert(chssh_channel_open_session(cli, &ch_id) == 0);
    shuttle(cli, srv);
    while (chssh_next_event(cli, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_OPEN &&
            ev.u.channel.channel_id == ch_id) {
            assert(chssh_channel_request_pty(cli, ch_id, "xterm", 120, 40) ==
                   0);
        }
    }
    shuttle(cli, srv);
    for (guard = 0; guard < 40; guard++) {
        shuttle(cli, srv);
        while (chssh_next_event(srv, &ev)) {
            if (ev.type == CHSSH_EVENT_PTY) {
                assert(ev.u.pty.cols == 120);
                assert(ev.u.pty.rows == 40);
                assert(strcmp(ev.u.pty.term, "xterm") == 0);
                saw_pty = 1;
            }
            if (ev.type == CHSSH_EVENT_SHELL &&
                strcmp(ev.u.channel.chan_type, "shell-ready") == 0) {
                saw_shell = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "srv: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        while (chssh_next_event(cli, &ev)) {
            if (ev.type == CHSSH_EVENT_PTY && !shell_sent) {
                /* pty-req SUCCESS — OpenSSH would send shell next */
                assert(chssh_channel_request_shell(cli, ch_id) == 0);
                shell_sent = 1;
            }
            if (ev.type == CHSSH_EVENT_SHELL &&
                strcmp(ev.u.channel.chan_type, "shell-ready") == 0) {
                cli_shell = 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "cli: %s\n", ev.u.error.message);
                assert(0);
            }
        }
        if (saw_pty && saw_shell && cli_shell) {
            break;
        }
    }
    assert(saw_pty);
    assert(saw_shell && cli_shell);
    assert(chssh_channel_is_ready(cli, ch_id));
    assert(chssh_channel_is_ready(srv, ch_id));

    assert(chssh_channel_send_id(cli, ch_id, (const uint8_t *)msg,
                                 strlen(msg)) == 0);
    shuttle(cli, srv);
    while (chssh_next_event(srv, &ev)) {
        if (ev.type == CHSSH_EVENT_CHANNEL_DATA &&
            ev.u.data.len == strlen(msg) &&
            memcmp(ev.u.data.data, msg, ev.u.data.len) == 0) {
            saw_data = 1;
        }
    }
    assert(saw_data);

    chssh_destroy(srv);
    chssh_destroy(cli);
    printf("  PASS: client pty-req + shell (OpenSSH interactive path)\n");
    return 0;
}
