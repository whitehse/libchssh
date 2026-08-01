/**
 * @file test_chssh_pubkey.c
 * @brief PR-1a: public key blob parse/encode + OpenSSH SHA256 fingerprints.
 *
 * Vectors from ssh-keygen -t ed25519 / -t rsa -b 2048; fingerprints via
 * ssh-keygen -lf -E sha256 (unpadded SHA256: base64).
 */
#include "chssh.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABGlQfdyPqM8290wafLWNGBhKDNeIOHEwX1TqcwiBA4 */
static const uint8_t ed_blob[] = {
    0x00, 0x00, 0x00, 0x0b, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35,
    0x35, 0x31, 0x39, 0x00, 0x00, 0x00, 0x20, 0x00, 0x46, 0x95, 0x07, 0xdd,
    0xc8, 0xfa, 0x8c, 0xf3, 0x6f, 0x74, 0xc1, 0xa7, 0xcb, 0x58, 0xd1, 0x81,
    0x84, 0xa0, 0xcd, 0x78, 0x83, 0x87, 0x13, 0x05, 0xf5, 0x4e, 0xa7, 0x30,
    0x88, 0x10, 0x38,
};
static const char ed_fp[] = "SHA256:a59rtYtwZFYbTpZzIJTTEZVu7fHXa/v+PryDRhWnua4";
static const char ed_line[] =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIABGlQfdyPqM8290wafLWNGBhKDNeIOHEwX1TqcwiBA4 "
    "test@edge";

/* 2048-bit RSA test vector (ssh-keygen) */
static const uint8_t rsa_blob[] = {
    0x00, 0x00, 0x00, 0x07, 0x73, 0x73, 0x68, 0x2d, 0x72, 0x73, 0x61, 0x00,
    0x00, 0x00, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0xa6,
    0x49, 0xc6, 0x7e, 0xdf, 0x02, 0xc5, 0x30, 0xac, 0xd5, 0x70, 0x2a, 0x3b,
    0x03, 0xab, 0xf9, 0x11, 0x9c, 0x5d, 0x77, 0xfc, 0x56, 0x60, 0x9d, 0x6e,
    0x2d, 0x16, 0x2a, 0xd8, 0xd2, 0xee, 0xe5, 0x0a, 0xa7, 0xa9, 0xa8, 0x27,
    0x7a, 0xa2, 0xb9, 0x2a, 0xf4, 0xb1, 0x5c, 0xee, 0x4e, 0xe0, 0xa9, 0x25,
    0x68, 0x85, 0xd8, 0x75, 0x7b, 0x5f, 0xe8, 0x3c, 0x51, 0x13, 0x35, 0xcc,
    0x58, 0x43, 0x20, 0x83, 0x3a, 0x76, 0x2d, 0xce, 0x69, 0x34, 0x3c, 0x0b,
    0xb6, 0xbf, 0x20, 0x69, 0xe0, 0x8a, 0x1f, 0x71, 0xe0, 0x13, 0x12, 0x1b,
    0x2b, 0xd9, 0x6e, 0x06, 0xd9, 0x57, 0x1b, 0x49, 0x9d, 0x80, 0x60, 0x76,
    0x3b, 0x9e, 0x10, 0x3d, 0xf1, 0x3f, 0x75, 0xbe, 0x3c, 0x18, 0xf3, 0x38,
    0x38, 0xbd, 0xec, 0x00, 0x5a, 0x33, 0x19, 0x80, 0xdc, 0xb6, 0x99, 0x7b,
    0x97, 0x87, 0x43, 0x6a, 0x39, 0x24, 0x5f, 0x5c, 0x83, 0x01, 0x74, 0x26,
    0x90, 0xcf, 0xe7, 0x44, 0x8f, 0xa3, 0xaa, 0xfb, 0x05, 0x33, 0x13, 0x46,
    0xb0, 0x26, 0xc3, 0x6d, 0xc0, 0x54, 0x1b, 0x33, 0x65, 0x1b, 0xcc, 0x3e,
    0x47, 0x49, 0x91, 0x3f, 0x4a, 0x7a, 0x77, 0x37, 0x50, 0xf5, 0x14, 0x2f,
    0x6d, 0x61, 0x77, 0x4e, 0xae, 0x68, 0x48, 0x04, 0xce, 0x73, 0xb0, 0xbf,
    0xbc, 0x6a, 0x26, 0xdc, 0xed, 0x5c, 0x7e, 0x3d, 0xb7, 0x60, 0xfb, 0x11,
    0x15, 0x44, 0xda, 0x2e, 0x9d, 0x76, 0x4f, 0x13, 0xd8, 0x47, 0x8a, 0x9f,
    0x65, 0xd1, 0xe4, 0xfe, 0xe9, 0x8b, 0x1c, 0xc8, 0x4a, 0x16, 0xc1, 0x9f,
    0xa8, 0x69, 0x77, 0xf5, 0xb3, 0xcd, 0x5c, 0xea, 0x9d, 0x91, 0x2b, 0x02,
    0x63, 0x71, 0x72, 0x52, 0x7d, 0x74, 0x27, 0xfc, 0x95, 0xb4, 0x75, 0x35,
    0xb7, 0xcb, 0x95, 0x08, 0xae, 0x1b, 0x08, 0x13, 0xc0, 0x87, 0xf0, 0x86,
    0xbe, 0x58, 0xcd,
};
static const char rsa_fp[] = "SHA256:G56tGeWzIBJmtfSclq2Vmaky+IFUorvWGqFAkvLncek";
static const char rsa_line[] =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCmScZ+3wLFMKzVcCo7A6v5EZxdd/"
    "xWYJ1uLRYq2NLu5QqnqagneqK5KvSxXO5O4KklaIXYdXtf6DxREzXMWEMggzp2Lc5pNDwLtr8gaeCKH3HgExIbK9luBtlXG0mdgGB2O54QPfE/"
    "db48GPM4OL3sAFozGYDctpl7l4dDajkkX1yDAXQmkM/nRI+jqvsFMxNGsCbDbcBUGzNlG8w+R0mRP0p6dzdQ9RQvbWF3Tq5oSATOc7C/"
    "vGom3O1cfj23YPsRFUTaLp12TxPYR4qfZdHk/umLHMhKFsGfqGl39bPNXOqdkSsCY3FyUn10J/"
    "yVtHU1t8uVCK4bCBPAh/CGvljN test-rsa@edge";

static void test_ed25519_blob(void)
{
    chssh_pubkey_alg_t alg = CHSSH_PUBKEY_ALG_UNKNOWN;
    char fp[CHSSH_FP_SHA256_MAX];
    uint8_t raw_pk[32];
    uint8_t rebuilt[128];
    size_t rebuilt_len = 0;

    assert(chssh_pubkey_blob_parse(ed_blob, sizeof(ed_blob), &alg) == 0);
    assert(alg == CHSSH_PUBKEY_ALG_SSH_ED25519);
    assert(strcmp(chssh_pubkey_alg_name(alg), "ssh-ed25519") == 0);

    assert(chssh_pubkey_fingerprint_sha256(ed_blob, sizeof(ed_blob), fp) == 0);
    assert(strcmp(fp, ed_fp) == 0);

    /* Wire: string type || string 32-byte key — key starts at offset 19 */
    assert(sizeof(ed_blob) == 51);
    memcpy(raw_pk, ed_blob + 19, 32);
    assert(chssh_pubkey_blob_encode_ed25519(raw_pk, rebuilt, sizeof(rebuilt),
                                            &rebuilt_len) == 0);
    assert(rebuilt_len == sizeof(ed_blob));
    assert(memcmp(rebuilt, ed_blob, rebuilt_len) == 0);

    printf("  PASS: ed25519 parse/fingerprint/encode\n");
}

static void test_rsa_blob(void)
{
    chssh_pubkey_alg_t alg = CHSSH_PUBKEY_ALG_UNKNOWN;
    char fp[CHSSH_FP_SHA256_MAX];

    assert(chssh_pubkey_blob_parse(rsa_blob, sizeof(rsa_blob), &alg) == 0);
    assert(alg == CHSSH_PUBKEY_ALG_SSH_RSA);
    assert(chssh_pubkey_fingerprint_sha256(rsa_blob, sizeof(rsa_blob), fp) ==
           0);
    assert(strcmp(fp, rsa_fp) == 0);
    printf("  PASS: rsa parse/fingerprint\n");
}

static void test_openssh_line_roundtrip(void)
{
    uint8_t blob[CHSSH_PUBKEY_BLOB_MAX];
    size_t blob_len = 0;
    chssh_pubkey_alg_t alg = CHSSH_PUBKEY_ALG_UNKNOWN;
    char comment[128];
    char line[CHSSH_OPENSSH_LINE_MAX];
    char fp[CHSSH_FP_SHA256_MAX];

    assert(chssh_pubkey_openssh_line_parse(ed_line, blob, sizeof(blob),
                                           &blob_len, &alg, comment,
                                           sizeof(comment)) == 0);
    assert(alg == CHSSH_PUBKEY_ALG_SSH_ED25519);
    assert(blob_len == sizeof(ed_blob));
    assert(memcmp(blob, ed_blob, blob_len) == 0);
    assert(strcmp(comment, "test@edge") == 0);

    assert(chssh_pubkey_openssh_line_encode(blob, blob_len, "test@edge", line,
                                            sizeof(line)) == 0);
    /* re-parse encoded line */
    blob_len = 0;
    assert(chssh_pubkey_openssh_line_parse(line, blob, sizeof(blob), &blob_len,
                                           &alg, comment, sizeof(comment)) ==
           0);
    assert(blob_len == sizeof(ed_blob));
    assert(chssh_pubkey_fingerprint_sha256(blob, blob_len, fp) == 0);
    assert(strcmp(fp, ed_fp) == 0);

    assert(chssh_pubkey_openssh_line_parse(rsa_line, blob, sizeof(blob),
                                           &blob_len, &alg, comment,
                                           sizeof(comment)) == 0);
    assert(alg == CHSSH_PUBKEY_ALG_SSH_RSA);
    assert(blob_len == sizeof(rsa_blob));
    assert(memcmp(blob, rsa_blob, blob_len) == 0);
    assert(strcmp(comment, "test-rsa@edge") == 0);

    printf("  PASS: openssh line parse/encode roundtrip\n");
}

static void test_reject_garbage(void)
{
    chssh_pubkey_alg_t alg;
    uint8_t bad[] = {0x00, 0x00, 0x00, 0x03, 'f', 'o', 'o'};
    uint8_t blob[64];
    size_t blen = 0;
    char fp[CHSSH_FP_SHA256_MAX];

    assert(chssh_pubkey_blob_parse(bad, sizeof(bad), &alg) != 0);
    assert(chssh_pubkey_blob_parse(ed_blob, sizeof(ed_blob) - 1, &alg) != 0);
    assert(chssh_pubkey_openssh_line_parse("not-a-key", blob, sizeof(blob),
                                           &blen, &alg, NULL, 0) != 0);
    assert(chssh_pubkey_openssh_line_parse("# comment only", blob, sizeof(blob),
                                           &blen, &alg, NULL, 0) != 0);
    assert(chssh_pubkey_fingerprint_sha256(NULL, 0, fp) != 0);
    printf("  PASS: reject garbage\n");
}

static void test_rsa_encode_from_parts(void)
{
    /* e = 65537 = 01 00 01; n from rsa_blob after type+e */
    const uint8_t e[] = {0x01, 0x00, 0x01};
    /* n starts at offset 4+7+4+3 = 18 in rsa_blob; length 0x101 at 18 */
    const uint8_t *n = rsa_blob + 22; /* after 00 00 01 01 length of n */
    size_t n_len = 0x101;
    uint8_t out[512];
    size_t out_len = 0;
    char fp[CHSSH_FP_SHA256_MAX];

    assert(rsa_blob[18] == 0x00 && rsa_blob[19] == 0x00 &&
           rsa_blob[20] == 0x01 && rsa_blob[21] == 0x01);
    assert(chssh_pubkey_blob_encode_rsa(e, sizeof(e), n, n_len, out,
                                        sizeof(out), &out_len) == 0);
    assert(out_len == sizeof(rsa_blob));
    assert(memcmp(out, rsa_blob, out_len) == 0);
    assert(chssh_pubkey_fingerprint_sha256(out, out_len, fp) == 0);
    assert(strcmp(fp, rsa_fp) == 0);
    printf("  PASS: rsa encode from e,n\n");
}

int main(void)
{
    printf("test_chssh_pubkey (PR-1a)\n");
    printf("  crypto backend: %s\n", chssh_crypto_backend());
    if (strcmp(chssh_crypto_backend(), "none") == 0) {
        fprintf(stderr,
                "SKIP: production crypto required for fingerprint SHA-256\n");
        return 0;
    }
    test_ed25519_blob();
    test_rsa_blob();
    test_openssh_line_roundtrip();
    test_reject_garbage();
    test_rsa_encode_from_parts();
    printf("ok\n");
    return 0;
}
