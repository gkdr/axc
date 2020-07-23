/*
 * Copyright (C) 2017-2020 Richard Bayerle <riba@firemail.cc>
 * SPDX-License-Identifier: GPL-3.0-only
 * Author: Richard Bayerle <riba@firemail.cc>
 */


#pragma once

#include <stdint.h>

#include "signal_protocol.h"

void axc_crypto_init(void);
void axc_crypto_teardown(void);

int random_bytes(uint8_t * data_p, size_t len, void * user_data_p);

int hmac_sha256_init(void ** hmac_context_pp, const uint8_t * key_p, size_t key_len, void * user_data_p);
int hmac_sha256_update(void * hmac_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p);
int hmac_sha256_final(void * hmac_context_p, signal_buffer ** output_pp, void * user_data_p);
void hmac_sha256_cleanup(void * hmac_context_p, void * user_data_p);

int sha512_digest_init(void ** digest_context_pp, void * user_data_p);
int sha512_digest_update(void * digest_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p);
int sha512_digest_final(void * digest_context_p, signal_buffer ** output_pp, void * user_data_p);
void sha512_digest_cleanup(void * digest_context_p, void * user_data_p);

int aes_encrypt(signal_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * plaintext_p, size_t plaintext_len,
        void * user_data_p);
int aes_decrypt(signal_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * ciphertext_p, size_t ciphertext_len,
        void * user_data_p);
