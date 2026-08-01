/**
 * @file chssh_openssh_key.h
 * @brief Decode unencrypted OpenSSH private keys (PR-1b/1c).
 * Internal — not part of public chssh.h.
 */
#ifndef CHSSH_OPENSSH_KEY_H
#define CHSSH_OPENSSH_KEY_H

#include "chssh.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    chssh_pubkey_alg_t alg;
    uint8_t            pub_blob[CHSSH_PUBKEY_BLOB_MAX];
    size_t             pub_blob_len;
    /* ed25519: 32-byte seed + matching public */
    uint8_t            ed_seed[32];
    uint8_t            ed_pub[32];
    /* RSA: big-endian integers (no SSH mpint header); heap-allocated */
    uint8_t           *rsa_n;
    size_t             rsa_n_len;
    uint8_t           *rsa_e;
    size_t             rsa_e_len;
    uint8_t           *rsa_d;
    size_t             rsa_d_len;
    uint8_t           *rsa_p;
    size_t             rsa_p_len;
    uint8_t           *rsa_q;
    size_t             rsa_q_len;
    uint8_t           *rsa_iqmp;
    size_t             rsa_iqmp_len;
} chssh_openssh_decoded_t;

void chssh_openssh_decoded_clear(chssh_openssh_decoded_t *d);

/**
 * Decode PEM text "-----BEGIN OPENSSH PRIVATE KEY-----" …
 * Only cipher=none / kdf=none (unencrypted). Passphrase keys rejected.
 * @return 0 ok, -1 error.
 */
int chssh_openssh_decode_pem(const char *pem, size_t pem_len,
                             chssh_openssh_decoded_t *out);

/** Read entire file into malloc buffer; caller frees. */
int chssh_read_file(const char *path, uint8_t **data_out, size_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* CHSSH_OPENSSH_KEY_H */
