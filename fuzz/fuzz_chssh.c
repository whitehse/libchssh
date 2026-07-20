/* libFuzzer harness — build with -DENABLE_FUZZ=ON */
#include "chssh.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    chssh_config_t cfg;
    chssh_ctx_t *ctx;
    chssh_event_t ev;
    uint8_t out[4096];

    if (size < 1) {
        return 0;
    }
    memset(&cfg, 0, sizeof(cfg));
    cfg.lab_mode = 1;
    cfg.hold_ident = data[0] & 1;
    cfg.server_password = "x";
    ctx = chssh_create((data[0] & 2) ? CHSSH_ROLE_CLIENT : CHSSH_ROLE_SERVER,
                       &cfg);
    if (!ctx) {
        return 0;
    }
    if (cfg.hold_ident) {
        (void)chssh_flush_ident(ctx);
    }
    if (size > 1) {
        (void)chssh_feed_input(ctx, data + 1, size - 1);
    }
    while (chssh_next_event(ctx, &ev)) {
    }
    (void)chssh_get_output(ctx, out, sizeof(out));
    chssh_destroy(ctx);
    return 0;
}
