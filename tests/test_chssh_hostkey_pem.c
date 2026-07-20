/**
 * Load RSA host key from PEM and complete production dialectic.
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

int main(void)
{
    char path[] = "/tmp/chssh_test_hostkey_XXXXXX";
    int fd;
    char cmd[512];
    chssh_config_t nms_cfg, dev_cfg;
    chssh_ctx_t *nms, *dev;
    int ready = 0, g;
    chssh_event_t ev;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    snprintf(cmd, sizeof(cmd),
             "openssl genrsa -out %s 2048 2>/dev/null", path);
    assert(system(cmd) == 0);

    memset(&nms_cfg, 0, sizeof(nms_cfg));
    nms_cfg.lab_mode = 0;
    nms_cfg.host_key_path = path;
    nms_cfg.server_password = "lab";
    nms_cfg.server_username = "netconf";

    memset(&dev_cfg, 0, sizeof(dev_cfg));
    dev_cfg.lab_mode = 0;
    dev_cfg.client_username = "netconf";
    dev_cfg.client_password = "lab";
    dev_cfg.accept_any_hostkey = 1;

    nms = chssh_create(CHSSH_ROLE_SERVER, &nms_cfg);
    dev = chssh_create(CHSSH_ROLE_CLIENT, &dev_cfg);
    assert(nms && dev);

    shuttle(dev, nms);
    assert(chssh_flush_ident(nms) == 0);
    for (g = 0; g < 200; g++) {
        shuttle(nms, dev);
        while (chssh_next_event(nms, &ev)) {
            if (ev.type == CHSSH_EVENT_READY) {
                ready |= 1;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "nms: %s\n", ev.u.error.message);
                unlink(path);
                return 1;
            }
        }
        while (chssh_next_event(dev, &ev)) {
            if (ev.type == CHSSH_EVENT_READY) {
                ready |= 2;
            }
            if (ev.type == CHSSH_EVENT_ERROR) {
                fprintf(stderr, "dev: %s\n", ev.u.error.message);
                unlink(path);
                return 1;
            }
        }
        if (ready == 3) {
            break;
        }
    }
    unlink(path);
    assert(ready == 3);
    chssh_destroy(nms);
    chssh_destroy(dev);
    printf("  PASS: PEM host key load + production dialectic\n");
    return 0;
}
