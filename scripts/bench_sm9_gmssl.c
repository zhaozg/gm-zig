#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <gmssl/sm9.h>
#include <gmssl/sm9_z256.h>
#include <gmssl/sm3.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

#define ID "bench@example.com"
#define MSG "SM9 benchmark message for GmSSL 3.3"

int main(void) {
    SM9_SIGN_MASTER_KEY smk;
    SM9_SIGN_KEY sk;
    SM9_SIGNATURE sig;
    SM9_ENC_MASTER_KEY emk;
    SM9_ENC_KEY ek;
    uint8_t msg[32] = {0};
    uint8_t c2[32];
    uint8_t c3[32];
    SM9_Z256_POINT C1;
    SM3_CTX sm3;
    uint64_t t0, t1;
    int i, n;

    if (sm9_sign_master_key_generate(&smk) != 1) return 1;
    if (sm9_sign_master_key_extract_key(&smk, ID, strlen(ID), &sk) != 1) return 1;
    if (sm9_enc_master_key_generate(&emk) != 1) return 1;
    if (sm9_enc_master_key_extract_key(&emk, ID, strlen(ID), &ek) != 1) return 1;
    for (i = 0; i < 32; i++) msg[i] = (uint8_t)i;

    // pairing
    n = 1000; t0 = now_ns();
    sm9_z256_fp12_t gt;
    for (i = 0; i < n; i++) {
        sm9_z256_pairing(gt, sm9_z256_twist_generator(), sm9_z256_generator());
    }
    t1 = now_ns();
    printf("pairing_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    // key extraction
    n = 1000; t0 = now_ns();
    for (i = 0; i < n; i++) {
        SM9_SIGN_KEY tmp;
        sm9_sign_master_key_extract_key(&smk, ID, strlen(ID), &tmp);
    }
    t1 = now_ns();
    printf("sign_key_extract_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    // sign
    n = 1000; t0 = now_ns();
    for (i = 0; i < n; i++) {
        sm3_init(&sm3); sm3_update(&sm3, msg, sizeof(msg));
        sm9_do_sign(&sk, &sm3, &sig);
    }
    t1 = now_ns();
    printf("sign_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    // verify
    n = 1000; t0 = now_ns();
    for (i = 0; i < n; i++) {
        sm3_init(&sm3); sm3_update(&sm3, msg, sizeof(msg));
        sm9_do_verify(&smk, ID, strlen(ID), &sm3, &sig);
    }
    t1 = now_ns();
    printf("verify_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    // encrypt/decrypt
    n = 1000;
    uint8_t k1[32], c2buf[32], c3buf[32];
    t0 = now_ns();
    for (i = 0; i < n; i++) {
        sm9_do_encrypt(&emk, ID, strlen(ID), msg, sizeof(msg), &C1, c2buf, c3buf);
    }
    t1 = now_ns();
    printf("encrypt_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    t0 = now_ns();
    for (i = 0; i < n; i++) {
        sm9_do_decrypt(&ek, ID, strlen(ID), &C1, c2buf, sizeof(c2buf), c3buf, k1);
    }
    t1 = now_ns();
    printf("decrypt_ns_per_op=%llu\n", (unsigned long long)((t1 - t0) / n));

    return 0;
}
