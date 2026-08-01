/**
 * @file test_chssh_userauth_crypto.c
 * @brief PR-1b RSA + PR-1c ed25519 userauth sign/verify round-trips.
 */
#define _POSIX_C_SOURCE 200809L
#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_tmp(const char *path, const char *cmd)
{
    char full[512];
    snprintf(full, sizeof(full), cmd, path);
    assert(system(full) == 0);
}

static void test_rsa_pem_userauth(void)
{
    char path[] = "/tmp/chssh_ua_rsa_XXXXXX";
    int fd;
    chssh_identity_t *id;
    uint8_t pub[CHSSH_PUBKEY_BLOB_MAX];
    size_t pub_len = 0;
    uint8_t sess[16];
    uint8_t msg[1024];
    size_t msg_len = 0;
    uint8_t sig[512];
    size_t sig_len = 0;
    char fp[CHSSH_FP_SHA256_MAX];
    size_t i;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    write_tmp(path, "openssl genrsa -out %s 2048 2>/dev/null");

    id = chssh_identity_load_file(path);
    assert(id);
    assert(chssh_identity_alg(id) == CHSSH_PUBKEY_ALG_SSH_RSA);
    assert(strcmp(chssh_identity_sig_alg(id), "rsa-sha2-256") == 0);
    assert(chssh_identity_public_blob(id, pub, sizeof(pub), &pub_len) == 0);
    assert(chssh_pubkey_fingerprint_sha256(pub, pub_len, fp) == 0);

    for (i = 0; i < sizeof(sess); i++) {
        sess[i] = (uint8_t)(i + 1);
    }
    assert(chssh_userauth_build_signed_data(
               sess, sizeof(sess), "eco_ro", "ssh-connection", "rsa-sha2-256",
               pub, pub_len, msg, sizeof(msg), &msg_len) == 0);
    assert(msg_len > 20);
    assert(msg[sizeof(sess) + 4] == 50); /* after session string → msg type */

    assert(chssh_identity_sign(id, msg, msg_len, sig, sizeof(sig), &sig_len) ==
           0);
    assert(sig_len > 20);
    assert(chssh_userauth_verify("rsa-sha2-256", pub, pub_len, sig, sig_len, msg,
                                 msg_len) == 0);
    /* tamper */
    msg[msg_len / 2] ^= 0x01;
    assert(chssh_userauth_verify("rsa-sha2-256", pub, pub_len, sig, sig_len, msg,
                                 msg_len) != 0);

    chssh_identity_free(id);
    unlink(path);
    printf("  PASS: RSA PEM userauth sign/verify\n");
}

static void test_ed25519_openssh_userauth(void)
{
    char path[] = "/tmp/chssh_ua_ed_XXXXXX";
    int fd;
    char cmd[512];
    chssh_identity_t *id;
    uint8_t pub[128];
    size_t pub_len = 0;
    uint8_t sess[32];
    uint8_t msg[1024];
    size_t msg_len = 0;
    uint8_t sig[256];
    size_t sig_len = 0;
    size_t i;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -t ed25519 -N '' -f %s -C chssh-test -q", path);
    assert(system(cmd) == 0);

    id = chssh_identity_load_file(path);
    assert(id);
    assert(chssh_identity_alg(id) == CHSSH_PUBKEY_ALG_SSH_ED25519);
    assert(strcmp(chssh_identity_sig_alg(id), "ssh-ed25519") == 0);
    assert(chssh_identity_public_blob(id, pub, sizeof(pub), &pub_len) == 0);

    for (i = 0; i < sizeof(sess); i++) {
        sess[i] = (uint8_t)(0xa0 + i);
    }
    assert(chssh_userauth_build_signed_data(
               sess, sizeof(sess), "router1", "ssh-connection", "ssh-ed25519",
               pub, pub_len, msg, sizeof(msg), &msg_len) == 0);
    assert(chssh_identity_sign(id, msg, msg_len, sig, sizeof(sig), &sig_len) ==
           0);
    assert(chssh_userauth_verify("ssh-ed25519", pub, pub_len, sig, sig_len, msg,
                                 msg_len) == 0);
    sig[20] ^= 0xff;
    assert(chssh_userauth_verify("ssh-ed25519", pub, pub_len, sig, sig_len, msg,
                                 msg_len) != 0);

    chssh_identity_free(id);
    unlink(path);
    {
        char pubpath[sizeof(path) + 8];
        snprintf(pubpath, sizeof(pubpath), "%s.pub", path);
        unlink(pubpath);
    }
    printf("  PASS: ed25519 OpenSSH userauth sign/verify\n");
}

static void test_rsa_openssh_if_available(void)
{
    char path[] = "/tmp/chssh_ua_rsa_os_XXXXXX";
    int fd;
    char cmd[512];
    chssh_identity_t *id;
    uint8_t pub[CHSSH_PUBKEY_BLOB_MAX];
    size_t pub_len = 0;
    uint8_t msg[64];
    uint8_t sig[512];
    size_t sig_len = 0;
    size_t i;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unlink(path);
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -t rsa -b 2048 -N '' -f %s -C chssh-rsa -q", path);
    if (system(cmd) != 0) {
        printf("  SKIP: ssh-keygen rsa openssh\n");
        return;
    }
    id = chssh_identity_load_file(path);
    assert(id);
    assert(chssh_identity_alg(id) == CHSSH_PUBKEY_ALG_SSH_RSA);
    assert(chssh_identity_public_blob(id, pub, sizeof(pub), &pub_len) == 0);
    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)i;
    }
    assert(chssh_identity_sign(id, msg, sizeof(msg), sig, sizeof(sig),
                               &sig_len) == 0);
    assert(chssh_userauth_verify("rsa-sha2-256", pub, pub_len, sig, sig_len, msg,
                                 sizeof(msg)) == 0);
    chssh_identity_free(id);
    unlink(path);
    {
        char pubpath[sizeof(path) + 8];
        snprintf(pubpath, sizeof(pubpath), "%s.pub", path);
        unlink(pubpath);
    }
    printf("  PASS: RSA OpenSSH private key load + sign\n");
}

int main(void)
{
    printf("test_chssh_userauth_crypto (PR-1b/1c)\n");
    printf("  crypto backend: %s\n", chssh_crypto_backend());
    if (strcmp(chssh_crypto_backend(), "none") == 0) {
        fprintf(stderr, "SKIP: needs production crypto\n");
        return 0;
    }
    test_rsa_pem_userauth();
    test_ed25519_openssh_userauth();
    test_rsa_openssh_if_available();
    printf("ok\n");
    return 0;
}
