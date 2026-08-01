/**
 * @file chssh_identity.c
 * @brief High-level identity load + userauth signed-data helper (PR-1b/1c).
 */

#include "chssh.h"
#include "chssh_crypto.h"
#include "chssh_openssh_key.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chssh_identity {
    chssh_pubkey_alg_t alg;
    chssh_rsa_key_t   *rsa;
    chssh_ed25519_key_t *ed;
};

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static int put_string(uint8_t *out, size_t cap, size_t *off, const void *data,
                      size_t data_len)
{
    size_t o = *off;
    if (o + 4 + data_len > cap) {
        return -1;
    }
    put_u32(out + o, (uint32_t)data_len);
    o += 4;
    if (data_len) {
        memcpy(out + o, data, data_len);
        o += data_len;
    }
    *off = o;
    return 0;
}

int chssh_userauth_build_signed_data(const uint8_t *session_id,
                                     size_t session_id_len,
                                     const char *username, const char *service,
                                     const char *pk_alg,
                                     const uint8_t *pubkey_blob,
                                     size_t pubkey_blob_len, uint8_t *out,
                                     size_t cap, size_t *out_len)
{
    size_t off = 0;
    uint8_t bool_true = 1;
    if (!session_id || session_id_len == 0 || !username || !service || !pk_alg ||
        !pubkey_blob || !out || !out_len) {
        return -1;
    }
    /* session_id as string */
    if (put_string(out, cap, &off, session_id, session_id_len) != 0) {
        return -1;
    }
    /* SSH_MSG_USERAUTH_REQUEST = 50 */
    if (off + 1 > cap) {
        return -1;
    }
    out[off++] = 50;
    if (put_string(out, cap, &off, username, strlen(username)) != 0) {
        return -1;
    }
    if (put_string(out, cap, &off, service, strlen(service)) != 0) {
        return -1;
    }
    if (put_string(out, cap, &off, "publickey", 9) != 0) {
        return -1;
    }
    /* TRUE — signature follows */
    if (off + 1 > cap) {
        return -1;
    }
    out[off++] = bool_true;
    if (put_string(out, cap, &off, pk_alg, strlen(pk_alg)) != 0) {
        return -1;
    }
    if (put_string(out, cap, &off, pubkey_blob, pubkey_blob_len) != 0) {
        return -1;
    }
    *out_len = off;
    return 0;
}

void chssh_identity_free(chssh_identity_t *id)
{
    if (!id) {
        return;
    }
    chssh_rsa_free(id->rsa);
    chssh_ed25519_free(id->ed);
    free(id);
}

chssh_identity_t *chssh_identity_load_mem(const void *data, size_t len)
{
    chssh_identity_t *id;
    const char *s;
    if (!data || len == 0) {
        return NULL;
    }
    s = (const char *)data;
    id = (chssh_identity_t *)calloc(1, sizeof(*id));
    if (!id) {
        return NULL;
    }
    if (strstr(s, "BEGIN OPENSSH PRIVATE KEY") != NULL) {
        chssh_openssh_decoded_t d;
        if (chssh_openssh_decode_pem(s, len, &d) != 0) {
            free(id);
            return NULL;
        }
        id->alg = d.alg;
        if (d.alg == CHSSH_PUBKEY_ALG_SSH_RSA) {
            chssh_openssh_decoded_clear(&d);
            id->rsa = chssh_rsa_load_openssh_mem(data, len);
            if (!id->rsa) {
                free(id);
                return NULL;
            }
        } else if (d.alg == CHSSH_PUBKEY_ALG_SSH_ED25519) {
            chssh_openssh_decoded_clear(&d);
            id->ed = chssh_ed25519_load_openssh_mem(data, len);
            if (!id->ed) {
                free(id);
                return NULL;
            }
        } else {
            chssh_openssh_decoded_clear(&d);
            free(id);
            return NULL;
        }
        return id;
    }
    if (strstr(s, "BEGIN") != NULL && strstr(s, "PRIVATE KEY") != NULL) {
        id->alg = CHSSH_PUBKEY_ALG_SSH_RSA;
        id->rsa = chssh_rsa_load_pem_mem(data, len);
        if (!id->rsa) {
            free(id);
            return NULL;
        }
        return id;
    }
    free(id);
    return NULL;
}

chssh_identity_t *chssh_identity_load_file(const char *path)
{
    uint8_t *data = NULL;
    size_t len = 0;
    chssh_identity_t *id;
    if (chssh_read_file(path, &data, &len) != 0) {
        return NULL;
    }
    id = chssh_identity_load_mem(data, len);
    free(data);
    return id;
}

chssh_pubkey_alg_t chssh_identity_alg(const chssh_identity_t *id)
{
    return id ? id->alg : CHSSH_PUBKEY_ALG_UNKNOWN;
}

const char *chssh_identity_sig_alg(const chssh_identity_t *id)
{
    if (!id) {
        return NULL;
    }
    if (id->alg == CHSSH_PUBKEY_ALG_SSH_RSA) {
        return "rsa-sha2-256";
    }
    if (id->alg == CHSSH_PUBKEY_ALG_SSH_ED25519) {
        return "ssh-ed25519";
    }
    return NULL;
}

int chssh_identity_public_blob(const chssh_identity_t *id, uint8_t *out,
                               size_t cap, size_t *out_len)
{
    if (!id) {
        return -1;
    }
    if (id->rsa) {
        return chssh_rsa_public_blob(id->rsa, out, cap, out_len);
    }
    if (id->ed) {
        return chssh_ed25519_public_blob(id->ed, out, cap, out_len);
    }
    return -1;
}

int chssh_identity_sign(const chssh_identity_t *id, const uint8_t *msg,
                        size_t msg_len, uint8_t *sig_out, size_t cap,
                        size_t *sig_len)
{
    if (!id || !msg || !sig_out || !sig_len) {
        return -1;
    }
    if (id->rsa) {
        return chssh_rsa_sign(id->rsa, "rsa-sha2-256", msg, msg_len, sig_out,
                              cap, sig_len);
    }
    if (id->ed) {
        return chssh_ed25519_sign(id->ed, msg, msg_len, sig_out, cap, sig_len);
    }
    return -1;
}

int chssh_userauth_verify(const char *pk_alg, const uint8_t *pubkey_blob,
                          size_t pubkey_blob_len, const uint8_t *sig_blob,
                          size_t sig_len, const uint8_t *msg, size_t msg_len)
{
    if (!pk_alg || !pubkey_blob || !sig_blob || !msg) {
        return -1;
    }
    if (strcmp(pk_alg, "ssh-ed25519") == 0) {
        return chssh_ed25519_verify(pubkey_blob, pubkey_blob_len, sig_blob,
                                    sig_len, msg, msg_len);
    }
    if (strcmp(pk_alg, "rsa-sha2-256") == 0 || strcmp(pk_alg, "ssh-rsa") == 0) {
        return chssh_rsa_verify(pubkey_blob, pubkey_blob_len, sig_blob, sig_len,
                                msg, msg_len);
    }
    return -1;
}
