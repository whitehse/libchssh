/**
 * Tiny TCP host for OpenSSH client interop (Call Home SSH server role).
 * Usage: chssh_openssh_server <port>
 *
 * Non-blocking I/O + wall-clock deadline so the harness cannot hang forever
 * if the client stalls mid-handshake.
 */
#define _POSIX_C_SOURCE 200809L
#include "chssh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define HARNESS_DEADLINE_SEC 20

static int set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int write_all(int fd, const uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t wn = write(fd, buf + off, n - off);
        if (wn < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                if (poll(&pfd, 1, 500) <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        off += (size_t)wn;
    }
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
    time_t deadline;
    struct pollfd pfd;

    memset(&cfg, 0, sizeof(cfg));
    cfg.lab_mode = 0;
    cfg.hold_ident = 0; /* no Calix preamble in this interop */
    cfg.server_username = "sysadmin";
    cfg.server_password = "sysadmin";
    /* Prefer password path for OpenSSH password-only client */
    cfg.server_offer_publickey = 0;
    cfg.server_offer_password = 1;

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
    if (set_nb(lfd) != 0) {
        perror("fcntl listen");
        return 1;
    }
    fprintf(stderr, "chssh_openssh_server listening on 127.0.0.1:%d\n", port);
    deadline = time(NULL) + HARNESS_DEADLINE_SEC;

    cfd = -1;
    while (cfd < 0) {
        if (time(NULL) > deadline) {
            fprintf(stderr, "timeout waiting for accept\n");
            close(lfd);
            return 1;
        }
        pfd.fd = lfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 200) <= 0) {
            continue;
        }
        plen = sizeof(peer);
        cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("accept");
            close(lfd);
            return 1;
        }
    }
    if (set_nb(cfd) != 0) {
        perror("fcntl client");
        close(cfd);
        close(lfd);
        return 1;
    }
    ssh = chssh_create(CHSSH_ROLE_SERVER, &cfg);
    if (!ssh) {
        fprintf(stderr, "create failed\n");
        close(cfd);
        close(lfd);
        return 1;
    }

    {
        static const char hello[] =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<capabilities><capability>urn:ietf:params:netconf:base:1.0"
            "</capability></capabilities>"
            "<session-id>1</session-id></hello>]]>]]>";
        int hello_sent = 0;
        int saw_client = 0;

        while (time(NULL) <= deadline) {
            size_t n;
            ssize_t rn;
            chssh_event_t ev;
            int progress = 0;

            for (;;) {
                n = chssh_get_output(ssh, buf, sizeof(buf));
                if (!n) {
                    break;
                }
                if (write_all(cfd, buf, n) != 0) {
                    goto done;
                }
                progress = 1;
            }

            rn = read(cfd, buf, sizeof(buf));
            if (rn > 0) {
                (void)chssh_feed_input(ssh, buf, (size_t)rn);
                progress = 1;
            } else if (rn == 0) {
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }

            while (chssh_next_event(ssh, &ev)) {
                progress = 1;
                if (ev.type == CHSSH_EVENT_READY) {
                    fprintf(stderr, "READY subsystem netconf\n");
                    /* Server hello first (RFC 6242); client may wait on it. */
                    if (!hello_sent) {
                        (void)chssh_channel_send(ssh, (const uint8_t *)hello,
                                                 sizeof(hello) - 1);
                        hello_sent = 1;
                    }
                }
                if (ev.type == CHSSH_EVENT_CHANNEL_DATA) {
                    fprintf(stderr, "channel data %zu bytes\n", ev.u.data.len);
                    saw_client = 1;
                    if (!hello_sent) {
                        (void)chssh_channel_send(ssh, (const uint8_t *)hello,
                                                 sizeof(hello) - 1);
                        hello_sent = 1;
                    }
                }
                if (ev.type == CHSSH_EVENT_ERROR) {
                    fprintf(stderr, "error: %s\n", ev.u.error.message);
                    goto done;
                }
                if (ev.type == CHSSH_EVENT_DISCONNECTED) {
                    goto done;
                }
            }

            /* Flush any hello we just queued before blocking again. */
            for (;;) {
                n = chssh_get_output(ssh, buf, sizeof(buf));
                if (!n) {
                    break;
                }
                if (write_all(cfd, buf, n) != 0) {
                    goto done;
                }
                progress = 1;
            }

            /* Client got hello and sent its own: tear down so ssh exits. */
            if (hello_sent && saw_client) {
                (void)chssh_disconnect(ssh, "interop complete");
                for (;;) {
                    n = chssh_get_output(ssh, buf, sizeof(buf));
                    if (!n) {
                        break;
                    }
                    (void)write_all(cfd, buf, n);
                }
                goto done;
            }

            if (!progress) {
                pfd.fd = cfd;
                pfd.events = POLLIN;
                if (poll(&pfd, 1, 100) < 0 && errno != EINTR) {
                    break;
                }
            }
        }
        if (time(NULL) > deadline) {
            fprintf(stderr, "timeout during session\n");
        }
    }
done:
    chssh_destroy(ssh);
    close(cfd);
    close(lfd);
    return 0;
}
