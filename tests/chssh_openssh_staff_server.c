/**
 * Production-crypto staff face for OpenSSH interactive shell interop.
 * Usage: chssh_openssh_staff_server <port>
 *
 * OpenSSH: ssh -p PORT -o PreferredAuthentications=password staff@127.0.0.1
 * Password: staff-lab
 * Runs: echo STAFF_SHELL_OK
 */
#define _DEFAULT_SOURCE
#include "chssh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 2223;
    int lfd, cfd;
    struct sockaddr_in addr, peer;
    socklen_t plen = sizeof(peer);
    chssh_config_t cfg;
    chssh_ctx_t *ssh;
    uint8_t buf[16384];
    int one = 1;
    int shell_ready = 0;
    uint32_t shell_ch = 0;

    memset(&cfg, 0, sizeof(cfg));
    cfg.lab_mode = 0; /* production — required for OpenSSH */
    cfg.hold_ident = 0;
    cfg.server_username = "staff";
    cfg.server_password = "staff-lab";
    cfg.auto_accept_shell = 1;
    cfg.auto_open_netconf = 0;
    cfg.allowed_subsystems = "edge-telemetry";

    fprintf(stderr, "chssh crypto backend: %s\n", chssh_crypto_backend());
    if (strcmp(chssh_crypto_backend(), "none") == 0) {
        fprintf(stderr, "SKIP: no production crypto backend\n");
        return 0;
    }

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(lfd, 1) != 0) {
        perror("bind/listen");
        return 1;
    }
    fprintf(stderr, "chssh_openssh_staff_server 127.0.0.1:%d (staff/staff-lab)\n",
            port);
    cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
    if (cfd < 0) {
        perror("accept");
        return 1;
    }
    ssh = chssh_create(CHSSH_ROLE_SERVER, &cfg);
    if (!ssh) {
        fprintf(stderr, "create failed (production crypto?)\n");
        return 1;
    }

    for (;;) {
        size_t n;
        ssize_t rn;
        chssh_event_t ev;

        n = chssh_get_output(ssh, buf, sizeof(buf));
        if (n) {
            if (write(cfd, buf, n) < 0) {
                break;
            }
        }
        rn = read(cfd, buf, sizeof(buf));
        if (rn > 0) {
            (void)chssh_feed_input(ssh, buf, (size_t)rn);
        } else if (rn == 0) {
            break;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        while (chssh_next_event(ssh, &ev)) {
            if (ev.type == CHSSH_EVENT_AUTHENTICATED) {
                fprintf(stderr, "AUTHENTICATED\n");
            }
            if (ev.type == CHSSH_EVENT_PTY) {
                fprintf(stderr, "PTY term=%s %ux%u\n",
                        ev.u.pty.term[0] ? ev.u.pty.term : "?",
                        (unsigned)ev.u.pty.cols, (unsigned)ev.u.pty.rows);
            }
            if (ev.type == CHSSH_EVENT_SHELL &&
                (strcmp(ev.u.channel.chan_type, "shell-ready") == 0 ||
                 strcmp(ev.u.channel.chan_type, "shell") == 0 ||
                 strcmp(ev.u.channel.chan_type, "exec") == 0)) {
                shell_ready = 1;
                shell_ch = ev.u.channel.channel_id;
                fprintf(stderr, "SHELL ready ch=%u\n", (unsigned)shell_ch);
                {
                    const char *msg = "STAFF_SHELL_OK\n";
                    (void)chssh_channel_send_id(ssh, shell_ch,
                                                (const uint8_t *)msg,
                                                strlen(msg));
                }
            }
            if (ev.type == CHSSH_EVENT_CHANNEL_DATA && shell_ready) {
                const char *msg = "echo-ok\n";
                (void)chssh_channel_send_id(ssh, ev.u.data.channel_id,
                                            (const uint8_t *)msg, strlen(msg));
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "ERROR: %s\n", ev.u.error.message);
            }
            if (ev.type == CHSSH_EVENT_DISCONNECTED ||
                ev.type == CHSSH_EVENT_CHANNEL_EOF ||
                ev.type == CHSSH_EVENT_CHANNEL_CLOSE) {
                goto done;
            }
        }
        /* keep pumping until peer closes (client got STAFF_SHELL_OK) */
    }
done:
    chssh_destroy(ssh);
    close(cfd);
    close(lfd);
    return shell_ready ? 0 : 1;
}
