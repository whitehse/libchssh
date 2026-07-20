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
    cfg.hold_ident = 1; /* Calix identity first */
    cfg.ident = "SSH-2.0-OpenSSH_8.9";

    s = chssh_create(CHSSH_ROLE_SERVER, &cfg);
    assert(s);
    assert(chssh_ident_flushed(s) == 0);
    n = chssh_get_output(s, out, sizeof(out));
    assert(n == 0); /* held */

    assert(chssh_flush_ident(s) == 0);
    assert(chssh_ident_flushed(s) == 1);
    n = chssh_get_output(s, out, sizeof(out));
    assert(n == strlen("SSH-2.0-OpenSSH_8.9\r\n"));
    assert(memcmp(out, "SSH-2.0-OpenSSH_8.9\r\n", n) == 0);

    chssh_destroy(s);
    printf("  PASS: hold_ident + flush (Call Home host control)\n");
    return 0;
}
