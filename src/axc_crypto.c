#include <stdint.h> // int types
#include <stdio.h> // fprintf
#include <stdlib.h> // malloc

#include <openssl/err.h> // err_*
#include <openssl/evp.h> // EVP_*
#include <openssl/hmac.h> // hmac_*
#include <openssl/rand.h> // RAND_bytes

#include "axolotl.h"

#include "axc.h"

void axc_crypto_init(void) {
  // openssl lib init
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  //TODO: possibly set openssl locking functions
  // see: https://www.openssl.org/docs/man1.0.1/crypto/threads.html
}

void axc_crypto_teardown(void) {
  EVP_cleanup();
  ERR_free_strings();
}

int random_bytes(uint8_t * data_p, size_t len, void * user_data_p) {
  axc_context * ctx_p = (axc_context *) user_data_p;

  if (!RAND_bytes(data_p, len)) {
    axc_log(ctx_p, AXC_LOG_ERROR, "failed to get random bytes\n");
    return AX_ERR_UNKNOWN;
  }

  return AX_SUCCESS;
}

int hmac_sha256_init(void ** hmac_context_pp, const uint8_t * key_p, size_t key_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  // intialise ctx_p
  HMAC_CTX * hmac_ctx_p = malloc(sizeof(HMAC_CTX));
  if(!hmac_ctx_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to malloc hmac ctx\n");
    return AX_ERR_NOMEM;
  }
  HMAC_CTX_init(hmac_ctx_p);

  // set key_p
  if (!HMAC_Init_ex(hmac_ctx_p, key_p, key_len, EVP_sha256(), 0)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to init sha256\n");
    return AX_ERR_UNKNOWN;
  }

  // set return value
  *hmac_context_pp = hmac_ctx_p;

  return AX_SUCCESS;
}

int hmac_sha256_update(void * hmac_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  axc_context * ctx_p = (axc_context *) user_data_p;

  if (!HMAC_Update(hmac_context_p, data_p, data_len)) {
    axc_log(ctx_p, AXC_LOG_ERROR, "failed to update sha256\n");
    return AX_ERR_UNKNOWN;
  }

  return AX_SUCCESS;
}

int hmac_sha256_final(void * hmac_context_p, axolotl_buffer ** output_pp, void * user_data_p) {
  axc_context * ctx_p = (axc_context *) user_data_p;

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;

  if (!HMAC_Final(hmac_context_p, md, &len)) {
    axc_log(ctx_p, AXC_LOG_ERROR, "failed to finalise sha256\n");
    return AX_ERR_UNKNOWN;
  }

  axolotl_buffer * out_buf_p = axolotl_buffer_create(md, len);
  if (!out_buf_p) {
    axc_log(ctx_p, AXC_LOG_ERROR, "failed to create output_pp buf when finalising sha256\n");
    return AX_ERR_NOMEM;
  }

  *output_pp = out_buf_p;
  return AX_SUCCESS;
}

void hmac_sha256_cleanup(void * hmac_context_p, void * user_data_p) {
  HMAC_CTX_cleanup(hmac_context_p);
  free(hmac_context_p);
  (void)user_data_p;
}

int sha512_digest(axolotl_buffer ** output_pp, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  // create context
  EVP_MD_CTX * md_ctx_p = EVP_MD_CTX_create();

  // init digest
  if (!EVP_DigestInit(md_ctx_p, EVP_sha512())) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to init sha512 digest\n");
    EVP_MD_CTX_destroy(md_ctx_p);
    return AX_ERR_UNKNOWN;
  }

  // update digest with data_p
  if (!EVP_DigestUpdate(md_ctx_p, data_p, data_len)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to update sha512 digest\n");
    EVP_MD_CTX_destroy(md_ctx_p);
    return AX_ERR_UNKNOWN;
  }

  // prepare buffer to return
  axolotl_buffer * md_buf_p = axolotl_buffer_alloc(EVP_MAX_MD_SIZE);
  if (!md_buf_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to allocate buffer for sha512 digest\n");
    EVP_MD_CTX_destroy(md_ctx_p);
    return AX_ERR_NOMEM;
  }

  // write result into buffer
  if (!EVP_DigestFinal(md_ctx_p, axolotl_buffer_data(md_buf_p), (void *) 0)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to finalise sha512 digest\n");
    axolotl_buffer_free(md_buf_p);
    EVP_MD_CTX_destroy(md_ctx_p);
    return AX_ERR_UNKNOWN;
  }

  // prepare result and return
  *output_pp = md_buf_p;
  return AX_SUCCESS;
}

// shamelessly copied from axolotl testcases
const EVP_CIPHER *choose_aes_cipher(int cipher, size_t key_len)
{
    if(cipher == AX_CIPHER_AES_CBC_PKCS5) {
        if(key_len == 16) {
            return EVP_aes_128_cbc();
        }
        else if(key_len == 24) {
            return EVP_aes_192_cbc();
        }
        else if(key_len == 32) {
            return EVP_aes_256_cbc();
        }
    }
    else if(cipher == AX_CIPHER_AES_CTR_NOPADDING) {
        if(key_len == 16) {
            return EVP_aes_128_ctr();
        }
        else if(key_len == 24) {
            return EVP_aes_192_ctr();
        }
        else if(key_len == 32) {
            return EVP_aes_256_ctr();
        }
    }
    return 0;
}

// some parts also taken from axolotl testcases
// (there aren't really any ways to do/say it differently...)
int aes_encrypt(axolotl_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * plaintext_p, size_t plaintext_len,
        void * user_data_p) {

  int ret_val = AX_SUCCESS;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  EVP_CIPHER_CTX cipher_ctx = {0};
  uint8_t * out_buf_p = (void *) 0;
  int out_len = 0;
  int final_len = 0;

  const EVP_CIPHER * evp_cipher_p = choose_aes_cipher(cipher, key_len);

  if(iv_len != 16) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "invalid AES IV size: %zu\n", iv_len);
    return AX_ERR_UNKNOWN;
  }

  // pick correct cipher function according to mode and key length
  if (!evp_cipher_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "invalid AES mode or key size: %zu\n", key_len);
    return AX_ERR_UNKNOWN;
  }

  // init context
  EVP_CIPHER_CTX_init(&cipher_ctx);

  // init cipher
  if (!EVP_EncryptInit_ex(&cipher_ctx, evp_cipher_p, (void *) 0, key_p, iv_p)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to initialise encrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  if (cipher == AX_CIPHER_AES_CTR_NOPADDING) {
    EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
  }

  // allocate result buffer
  out_buf_p = malloc(sizeof(uint8_t) * (plaintext_len + EVP_MAX_BLOCK_LENGTH));
  if (!out_buf_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to malloc encrypt AES output buffer\n");
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

  // update cipher with plaintext_p etc
  if(!EVP_EncryptUpdate(&cipher_ctx, out_buf_p, &out_len, plaintext_p, plaintext_len)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to encrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  // finalise
  if (!EVP_EncryptFinal_ex(&cipher_ctx, out_buf_p + out_len, &final_len)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to finalise encrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  *output_pp = axolotl_buffer_create(out_buf_p, out_len + final_len);
  if (!*output_pp) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to create encrypt output buffer\n");
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

cleanup:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  free(out_buf_p);

  return ret_val;
}

int aes_decrypt(axolotl_buffer ** output_pp,
        int cipher,
        const uint8_t * key, size_t key_len,
        const uint8_t * iv, size_t iv_len,
        const uint8_t * ciphertext, size_t ciphertext_len,
        void * user_data_p) {

  int ret_val = AX_SUCCESS;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  EVP_CIPHER_CTX cipher_ctx = {0};
  uint8_t * out_buf_p = (void *) 0;
  int out_len = 0;
  int final_len = 0;
  const EVP_CIPHER * evp_cipher_p = choose_aes_cipher(cipher, key_len);

  if(iv_len != 16) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "invalid AES IV size: %zu\n", iv_len);
    return AX_ERR_UNKNOWN;
  }

  // pick correct cipher function according to mode and key length
  if (!evp_cipher_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "invalid AES mode or key size: %zu\n", key_len);
    return AX_ERR_UNKNOWN;
  }

  // init context
  EVP_CIPHER_CTX_init(&cipher_ctx);

  // init cipher
  if (!EVP_DecryptInit_ex(&cipher_ctx, evp_cipher_p, (void *) 0, key, iv)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to initialise decrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  if (cipher == AX_CIPHER_AES_CTR_NOPADDING) {
    EVP_CIPHER_CTX_set_padding(&cipher_ctx, 0);
  }

  // allocate result buffer
  out_buf_p = malloc(sizeof(uint8_t) * (ciphertext_len + EVP_MAX_BLOCK_LENGTH));
  if (!out_buf_p) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to malloc AES decrypt output_pp buffer\n");
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

  // update cipher with plaintext etc
  if(!EVP_DecryptUpdate(&cipher_ctx, out_buf_p, &out_len, ciphertext, ciphertext_len)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to decrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  // finalise
  if (!EVP_DecryptFinal_ex(&cipher_ctx, out_buf_p + out_len, &final_len)) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to finalise decrypt AES cipher\n");
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  *output_pp = axolotl_buffer_create(out_buf_p, out_len + final_len);
  if (!*output_pp) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "failed to create decrypt output_pp buffer\n");
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

cleanup:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  free(out_buf_p);

  return ret_val;
}
