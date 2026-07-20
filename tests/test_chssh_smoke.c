#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    chssh_config_t cfg;
    chssh_ctx_t *s;
    uint8_t out[256];
    size_t n;

    memset(&cfg, 0, sizeof(cfg));
    cfg.lab_mode = 1;
    cfg.hold_ident = 0;
    cfg.server_password = "sysadmin";
    cfg.server_username = "sysadmin";

    s = chssh_create(CHSSH_ROLE_SERVER, &cfg);
    assert(s);
    assert(chssh_current_state(s) == CHSSH_STATE_IDENT);
    assert(chssh_ident_flushed(s) == 1);

    n = chssh_get_output(s, out, sizeof(out));
    assert(n >= 10);
    assert(memcmp(out, "SSH-2.0-", 8) == 0);
    assert(out[n - 2] == '\r' && out[n - 1] == '\n');

    chssh_destroy(s);
    printf("  PASS: chssh smoke (server ident)\n");
    return 0;
}
