#pragma once

#include <stdint.h>

#include <axolotl/axolotl.h>

void axc_crypto_init(void);
void axc_crypto_teardown(void);

int random_bytes(uint8_t *data, size_t len, void *user_data);

int hmac_sha256_init(void **hmac_context, const uint8_t *key, size_t key_len, void *user_data);
int hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len, void *user_data);
int hmac_sha256_final(void *hmac_context, axolotl_buffer **output, void *user_data);
void hmac_sha256_cleanup(void *hmac_context, void *user_data);

int sha512_digest(axolotl_buffer **output, const uint8_t *data, size_t data_len, void *user_data);

int aes_encrypt(axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);
int aes_decrypt(axolotl_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);
