#include <stdint.h> // int types
#include <stdio.h> // fprintf
#include <stdlib.h> // malloc

#include <gcrypt.h>

#include "axolotl.h"

#include "axc.h"

void axc_crypto_init(void) {
  (void) gcry_check_version((void *) 0);
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control(GCRYCTL_USE_SECURE_RNDPOOL);
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

void axc_crypto_teardown(void) {
}

int random_bytes(uint8_t * data_p, size_t len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  (void) axc_ctx_p;

  gcry_randomize(data_p, len, GCRY_STRONG_RANDOM);

  return AX_SUCCESS;
}

int hmac_sha256_init(void ** hmac_context_pp, const uint8_t * key_p, size_t key_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  gcry_mac_hd_t * hmac_hd_p = (void *) 0;

  hmac_hd_p = malloc(sizeof(gcry_mac_hd_t));
  if (!hmac_hd_p) {
    err_msg = "could not malloc sha256 ctx";
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_mac_open(hmac_hd_p, GCRY_MAC_HMAC_SHA256, 0, (void *) 0);
  if (ret_val) {
    err_msg = "could not create sha256 ctx";
    goto cleanup;
  }

  ret_val = gcry_mac_setkey(*hmac_hd_p, key_p, key_len);
  if (ret_val) {
    err_msg = "could not set key for hmac";
    goto cleanup;
  }

  // set return value
  *hmac_context_pp = hmac_hd_p;

cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = AX_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }

    gcry_mac_close(*hmac_hd_p);
    free(hmac_hd_p);
  }

  return ret_val;
}

int hmac_sha256_update(void * hmac_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  (void) axc_ctx_p;

  gcry_mac_write(*((gcry_mac_hd_t *) hmac_context_p), data_p, data_len);

  return AX_SUCCESS;
}

int hmac_sha256_final(void * hmac_context_p, axolotl_buffer ** output_pp, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  int algo = GCRY_MAC_HMAC_SHA256;
  size_t mac_len = 0;
  uint8_t * mac_data_p = (void *) 0;
  axolotl_buffer * out_buf_p = (void *) 0;

  mac_len = gcry_mac_get_algo_maclen(algo);

  mac_data_p = malloc(sizeof(uint8_t) * mac_len);
  if (!mac_data_p) {
    ret_val = AX_ERR_NOMEM;
    err_msg = "failed to malloc mac buf";
    goto cleanup;
  }

  ret_val = gcry_mac_read(*((gcry_mac_hd_t *) hmac_context_p), mac_data_p, &mac_len);
  if (ret_val) {
    err_msg = "failed to read mac";
    goto cleanup;
  }

  out_buf_p = axolotl_buffer_create(mac_data_p, mac_len);
  if (!out_buf_p) {
    ret_val = AX_ERR_NOMEM;
    err_msg = "failed to create mac output buf";
    goto cleanup;
  }

  *output_pp = out_buf_p;

cleanup:
if (ret_val) {
  if (ret_val > 0) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
    ret_val = AX_ERR_UNKNOWN;
  } else {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
  }
}
  free(mac_data_p);

  return ret_val;
}

void hmac_sha256_cleanup(void * hmac_context_p, void * user_data_p) {
  (void) user_data_p;

  gcry_mac_hd_t * mac_hd_p = (gcry_mac_hd_t *) hmac_context_p;

  gcry_mac_close(*mac_hd_p);
  free(mac_hd_p);

}

int sha512_digest(axolotl_buffer ** output_pp, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  int algo = GCRY_MAC_HMAC_SHA512;
  size_t md_len = 0;
  uint8_t * md_data_p = (void *) 0;
  axolotl_buffer * out_buf_p = (void *) 0;


  md_len = gcry_md_get_algo_dlen(algo);

  md_data_p = malloc(sizeof(uint8_t) * md_len);
  if (!md_data_p) {
    ret_val = AX_ERR_NOMEM;
    err_msg = "failed to malloc md buf";
    goto cleanup;
  }

  gcry_md_hash_buffer(algo, md_data_p, data_p, data_len);

  out_buf_p = axolotl_buffer_create(md_data_p, md_len);
  if (!out_buf_p) {
    ret_val = AX_ERR_NOMEM;
    err_msg = "failed to create md output buf";
    goto cleanup;
  }

  *output_pp = out_buf_p;

cleanup:
  if (ret_val) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);

    axolotl_buffer_free(out_buf_p);
  }

  free(md_data_p);

  return ret_val;
}

static int choose_aes(int cipher, size_t key_len, int * algo_p, int * mode_p) {
  int algo = 0;
  int mode = 0;

  switch(key_len) {
    case 16:
      algo = GCRY_CIPHER_AES128;
      break;
    case 24:
      algo = GCRY_CIPHER_AES192;
      break;
    case 32:
      algo = GCRY_CIPHER_AES256;
      break;
    default:
      return AX_ERR_UNKNOWN;
  }

  switch (cipher) {
    case AX_CIPHER_AES_CBC_PKCS5:
      mode = GCRY_CIPHER_MODE_CBC;
      break;
    case AX_CIPHER_AES_CTR_NOPADDING:
      mode = GCRY_CIPHER_MODE_CTR;
      break;
    default:
      return AX_ERR_UNKNOWN;
  }

  *algo_p = algo;
  *mode_p = mode;

  return 0;
}

int aes_encrypt(axolotl_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * plaintext_p, size_t plaintext_len,
        void * user_data_p) {

  int ret_val = AX_SUCCESS;
  char * err_msg = (void *) 0;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int algo = 0;
  int mode = 0;
  size_t pad_len = 0;
  size_t ct_len = 0;
  gcry_cipher_hd_t cipher_hd = {0};
  uint8_t * pt_p = (void *) 0;
  uint8_t * out_p = (void *) 0;
  axolotl_buffer * out_buf_p = (void *) 0;

  if(iv_len != 16) {
    err_msg = "invalid AES IV size (must be 16)";
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = choose_aes(cipher, key_len, &algo, &mode);
  if (ret_val) {
    err_msg = "failed to choose cipher";
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = gcry_cipher_open(&cipher_hd, algo, mode, 0);
  if (ret_val) {
    err_msg = "failed to init cipher";
    goto cleanup;
  }

  ret_val = gcry_cipher_setkey(cipher_hd, key_p, key_len);
  if (ret_val) {
    err_msg = "failed to set key";
    goto cleanup;
  }

  switch (cipher) {
    case AX_CIPHER_AES_CBC_PKCS5:
      pad_len = 16 - (plaintext_len % 16);
      if (pad_len == 0) {
        pad_len = 16;
      }
      ct_len = plaintext_len + pad_len;
      ret_val = gcry_cipher_setiv(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    case AX_CIPHER_AES_CTR_NOPADDING:
      ct_len = plaintext_len;
      ret_val = gcry_cipher_setctr(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    default:
      ret_val = AX_ERR_UNKNOWN;
      err_msg = "unknown cipher";
      goto cleanup;
  }

  pt_p = malloc(sizeof(uint8_t) * ct_len);
  if (!pt_p) {
    err_msg = "failed to malloc pt buf";
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }
  memset(pt_p, pad_len, ct_len);
  memcpy(pt_p, plaintext_p, plaintext_len);

  out_p = malloc(sizeof(uint8_t) * ct_len);
  if (!out_p) {
    err_msg = "failed to malloc ct buf";
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_cipher_encrypt(cipher_hd, out_p, ct_len, pt_p, ct_len);
  if (ret_val) {
    err_msg = "failed to encrypt";
    goto cleanup;
  }

  out_buf_p = axolotl_buffer_create(out_p, ct_len);
  *output_pp = out_buf_p;

cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = AX_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }
  }

  free(out_p);
  gcry_cipher_close(cipher_hd);

  return ret_val;
}

int aes_decrypt(axolotl_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * ciphertext_p, size_t ciphertext_len,
        void * user_data_p) {

  int ret_val = AX_SUCCESS;
  char * err_msg = (void *) 0;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int algo = 0;
  int mode = 0;
  gcry_cipher_hd_t cipher_hd = {0};
  uint8_t * out_p = (void *) 0;
  size_t pad_len = 0;
  axolotl_buffer * out_buf_p = (void *) 0;

  if(iv_len != 16) {
    err_msg = "invalid AES IV size (must be 16)";
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = choose_aes(cipher, key_len, &algo, &mode);
  if (ret_val) {
    err_msg = "failed to choose cipher";
    ret_val = AX_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = gcry_cipher_open(&cipher_hd, algo, mode, 0);
  if (ret_val) {
    err_msg = "failed to init cipher";
    goto cleanup;
  }

  ret_val = gcry_cipher_setkey(cipher_hd, key_p, key_len);
  if (ret_val) {
    err_msg = "failed to set key";
    goto cleanup;
  }

  switch (cipher) {
    case AX_CIPHER_AES_CBC_PKCS5:
      pad_len = 1;
      ret_val = gcry_cipher_setiv(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    case AX_CIPHER_AES_CTR_NOPADDING:
      ret_val = gcry_cipher_setctr(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    default:
      ret_val = AX_ERR_UNKNOWN;
      err_msg = "unknown cipher";
      goto cleanup;
  }

  out_p = malloc(sizeof(uint8_t) * ciphertext_len);
  if (!out_p) {
    err_msg = "failed to malloc pt buf";
    ret_val = AX_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_cipher_decrypt(cipher_hd, out_p, ciphertext_len, ciphertext_p, ciphertext_len);
  if (ret_val) {
    err_msg = "failed to decrypt";
    goto cleanup;
  }

  if (pad_len) {
    pad_len = out_p[ciphertext_len - 1];
  }

  out_buf_p = axolotl_buffer_create(out_p, ciphertext_len - pad_len);
  *output_pp = out_buf_p;


cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = AX_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }
  }

  free(out_p);
  gcry_cipher_close(cipher_hd);

  return ret_val;
}
