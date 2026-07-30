/**
 * @file chssh_crypto.h
 * @brief Production SSH crypto (OpenSSL or mbedTLS backend; internal).
 *
 * All crypto is synchronous/non-blocking (no network I/O). Library remains
 * socket-free plumbing; host/agent pump feed/get_output on their threads.
 */
#ifndef CHSSH_CRYPTO_H
#define CHSSH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHSSH_AES_KEY_LEN  16
#define CHSSH_AES_IV_LEN   16
#define CHSSH_MAC_KEY_LEN  32
#define CHSSH_MAC_LEN      32
#define CHSSH_HASH_LEN     32
#define CHSSH_MAX_BLOB     4096
#define CHSSH_MAX_MPINT    512
#define CHSSH_MAX_SIG      512

typedef struct chssh_rsa_key chssh_rsa_key_t;
typedef struct chssh_dh_ctx  chssh_dh_ctx_t;
typedef struct chssh_cipher  chssh_cipher_t;

/* --- init / random --- */
int  chssh_crypto_init(void);
int  chssh_crypto_random(uint8_t *buf, size_t len);
/** "openssl" | "mbedtls" | "none" */
const char *chssh_crypto_backend(void);

/* --- RSA host key (ssh-rsa / rsa-sha2-256) --- */
chssh_rsa_key_t *chssh_rsa_generate(int bits); /* ephemeral, typically 2048 */
chssh_rsa_key_t *chssh_rsa_load_pem(const char *path);
void             chssh_rsa_free(chssh_rsa_key_t *k);

/** RFC 4253 public key blob: string "ssh-rsa" || mpint e || mpint n */
int chssh_rsa_public_blob(const chssh_rsa_key_t *k, uint8_t *out, size_t cap,
                          size_t *out_len);

/**
 * Sign exchange hash H.
 * @p sig_alg "rsa-sha2-256" or "ssh-rsa"
 * Output: string alg || string sigblob
 */
int chssh_rsa_sign(const chssh_rsa_key_t *k, const char *sig_alg,
                   const uint8_t *H, size_t H_len, uint8_t *out, size_t cap,
                   size_t *out_len);

/** Verify peer host key signature over H. */
int chssh_rsa_verify(const uint8_t *host_key_blob, size_t hk_len,
                     const uint8_t *sig_blob, size_t sig_len,
                     const uint8_t *H, size_t H_len);

/* --- Diffie-Hellman group14 --- */
chssh_dh_ctx_t *chssh_dh_new(void);
void            chssh_dh_free(chssh_dh_ctx_t *dh);

/** Generate private; write public as SSH mpint to @p pub. */
int chssh_dh_gen_public(chssh_dh_ctx_t *dh, uint8_t *pub, size_t cap,
                        size_t *pub_len);

/** Compute shared secret K as SSH mpint from peer public mpint. */
int chssh_dh_compute(chssh_dh_ctx_t *dh, const uint8_t *peer_pub,
                     size_t peer_len, uint8_t *K, size_t cap, size_t *K_len);

/* --- ECDH nistp256 (RFC 5656 ecdh-sha2-nistp256) --- */
typedef struct chssh_ecdh_ctx chssh_ecdh_ctx_t;
chssh_ecdh_ctx_t *chssh_ecdh_p256_new(void);
void              chssh_ecdh_free(chssh_ecdh_ctx_t *e);
/** Public point as SSH string (uint32 len + 0x04||X||Y). */
int chssh_ecdh_public_string(chssh_ecdh_ctx_t *e, uint8_t *out, size_t cap,
                             size_t *out_len);
/** Peer public is SSH string; K out as SSH mpint of shared X coordinate. */
int chssh_ecdh_compute(chssh_ecdh_ctx_t *e, const uint8_t *peer_q_str,
                       size_t peer_len, uint8_t *K, size_t cap, size_t *K_len);

/* --- SHA-256 --- */
int chssh_sha256(const uint8_t *data, size_t len, uint8_t out[CHSSH_HASH_LEN]);

/**
 * Incremental exchange-hash helper: hash a sequence of SSH strings / mpints.
 * Call begin, feed fields, finish → H.
 */
typedef struct chssh_hash_ctx chssh_hash_ctx_t;
chssh_hash_ctx_t *chssh_hash_new(void);
void              chssh_hash_free(chssh_hash_ctx_t *h);
int  chssh_hash_update(chssh_hash_ctx_t *h, const uint8_t *data, size_t len);
int  chssh_hash_update_string(chssh_hash_ctx_t *h, const uint8_t *data,
                              size_t len);
int  chssh_hash_update_cstring(chssh_hash_ctx_t *h, const char *s);
int  chssh_hash_final(chssh_hash_ctx_t *h, uint8_t out[CHSSH_HASH_LEN]);

/* --- Key derivation (RFC 4253) --- */
int chssh_derive_keys(const uint8_t *K, size_t K_len, const uint8_t *H,
                      const uint8_t *session_id, size_t session_id_len,
                      uint8_t iv_c2s[CHSSH_AES_IV_LEN],
                      uint8_t iv_s2c[CHSSH_AES_IV_LEN],
                      uint8_t key_c2s[CHSSH_AES_KEY_LEN],
                      uint8_t key_s2c[CHSSH_AES_KEY_LEN],
                      uint8_t mac_c2s[CHSSH_MAC_KEY_LEN],
                      uint8_t mac_s2c[CHSSH_MAC_KEY_LEN]);

/* --- AES-128-CTR + HMAC-SHA2-256 --- */
chssh_cipher_t *chssh_cipher_new(const uint8_t key[CHSSH_AES_KEY_LEN],
                                 const uint8_t iv[CHSSH_AES_IV_LEN],
                                 int encrypt);
chssh_cipher_t *chssh_cipher_dup(const chssh_cipher_t *c);
void            chssh_cipher_free(chssh_cipher_t *c);
int             chssh_cipher_crypt(chssh_cipher_t *c, uint8_t *data, size_t len);

int chssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
                      size_t data_len, uint8_t out[CHSSH_MAC_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* CHSSH_CRYPTO_H */
