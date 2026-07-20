/**
 * Tiny TCP host for OpenSSH client interop (Call Home SSH server role).
 * Usage: chssh_openssh_server <port>
 */
#define _POSIX_C_SOURCE 200809L
#include "chssh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int set_nb(int fd)
{
    /* blocking is fine for this test harness */
    (void)fd;
    return 0;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 2222;
    int lfd, cfd;
    struct sockaddr_in addr, peer;
    socklen_t plen = sizeof(peer);
    chssh_config_t cfg;
    chssh_ctx_t *ssh;
    uint8_t buf[8192];
    int one = 1;

    memset(&cfg, 0, sizeof(cfg));
    cfg.lab_mode = 0;
    cfg.hold_ident = 0; /* no Calix preamble in this interop */
    cfg.server_username = "sysadmin";
    cfg.server_password = "sysadmin";

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
    fprintf(stderr, "chssh_openssh_server listening on 127.0.0.1:%d\n", port);
    cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
    if (cfd < 0) {
        perror("accept");
        return 1;
    }
    set_nb(cfd);
    ssh = chssh_create(CHSSH_ROLE_SERVER, &cfg);
    if (!ssh) {
        fprintf(stderr, "create failed\n");
        return 1;
    }

    for (;;) {
        size_t n;
        ssize_t rn;
        chssh_event_t ev;
        int ready = 0;

        n = chssh_get_output(ssh, buf, sizeof(buf));
        if (n) {
            ssize_t wn = write(cfd, buf, n);
            if (wn < 0) {
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
            if (ev.type == CHSSH_EVENT_READY) {
                ready = 1;
                fprintf(stderr, "READY subsystem netconf\n");
            }
            if (ev.type == CHSSH_EVENT_CHANNEL_DATA) {
                fprintf(stderr, "channel data %zu bytes\n", ev.u.data.len);
                /* echo a minimal hello so client can exit cleanly */
                const char *hello =
                    "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                    "<capabilities><capability>urn:ietf:params:netconf:base:1.0"
                    "</capability></capabilities>"
                    "<session-id>1</session-id></hello>]]>]]>";
                (void)chssh_channel_send(ssh, (const uint8_t *)hello,
                                         strlen(hello));
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "error: %s\n", ev.u.error.message);
                goto done;
            }
            if (ev.type == CHSSH_EVENT_DISCONNECTED) {
                goto done;
            }
        }
        (void)ready;
        {
            struct pollfd pfd = {.fd = cfd, .events = POLLIN};
            (void)poll(&pfd, 1, 1);
        }
    }
done:
    chssh_destroy(ssh);
    close(cfd);
    close(lfd);
    return 0;
}
