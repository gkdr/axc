#include <stdint.h> // int types
#include <stdio.h> // fprintf
#include <stdlib.h> // malloc

#include <gcrypt.h>

#include "signal_protocol.h"

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

  return SG_SUCCESS;
}

int hmac_sha256_init(void ** hmac_context_pp, const uint8_t * key_p, size_t key_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  gcry_mac_hd_t * hmac_hd_p = (void *) 0;

  hmac_hd_p = malloc(sizeof(gcry_mac_hd_t));
  if (!hmac_hd_p) {
    err_msg = "could not malloc hmac-sha256 ctx";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_mac_open(hmac_hd_p, GCRY_MAC_HMAC_SHA256, 0, (void *) 0);
  if (ret_val) {
    err_msg = "could not create hmac-sha256 ctx";
    goto cleanup;
  }

  ret_val = gcry_mac_setkey(*hmac_hd_p, key_p, key_len);
  if (ret_val) {
    err_msg = "could not set key for hmac";
    goto cleanup;
  }

  *hmac_context_pp = hmac_hd_p;

cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = SG_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }

    if (hmac_hd_p) {
      gcry_mac_close(*hmac_hd_p);
      free(hmac_hd_p);
    }
  }

  return ret_val;
}

int hmac_sha256_update(void * hmac_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  (void) axc_ctx_p;

  gcry_mac_write(*((gcry_mac_hd_t *) hmac_context_p), data_p, data_len);

  return SG_SUCCESS;
}

int hmac_sha256_final(void * hmac_context_p, signal_buffer ** output_pp, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  int algo = GCRY_MAC_HMAC_SHA256;
  size_t mac_len = 0;
  uint8_t * mac_data_p = (void *) 0;
  signal_buffer * out_buf_p = (void *) 0;

  mac_len = gcry_mac_get_algo_maclen(algo);

  mac_data_p = malloc(sizeof(uint8_t) * mac_len);
  if (!mac_data_p) {
    ret_val = SG_ERR_NOMEM;
    err_msg = "failed to malloc mac buf";
    goto cleanup;
  }

  ret_val = gcry_mac_read(*((gcry_mac_hd_t *) hmac_context_p), mac_data_p, &mac_len);
  if (ret_val) {
    err_msg = "failed to read mac";
    goto cleanup;
  }

  out_buf_p = signal_buffer_create(mac_data_p, mac_len);
  if (!out_buf_p) {
    ret_val = SG_ERR_NOMEM;
    err_msg = "failed to create mac output buf";
    goto cleanup;
  }

  *output_pp = out_buf_p;

cleanup:
if (ret_val) {
  if (ret_val > 0) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
    ret_val = SG_ERR_UNKNOWN;
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

int sha512_digest_init(void ** digest_context_pp, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  gcry_md_hd_t * hash_hd_p = (void *) 0;
  hash_hd_p = malloc(sizeof(gcry_mac_hd_t));
  if (!hash_hd_p) {
    err_msg = "could not malloc sha512 ctx";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_md_open(hash_hd_p, GCRY_MD_SHA512, 0);
  if (ret_val) {
    err_msg = "could not create sha512 ctx";
    goto cleanup;
  }

  *digest_context_pp = hash_hd_p;

cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = SG_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }

    if (hash_hd_p) {
      gcry_md_close(*hash_hd_p);
      free(hash_hd_p);
    }
  }

  return ret_val;
}

int sha512_digest_update(void * digest_context_p, const uint8_t * data_p, size_t data_len, void * user_data_p) {
  (void) user_data_p;

  gcry_md_write(*((gcry_md_hd_t *) digest_context_p), data_p, data_len);

  return 0;
}

int sha512_digest_final(void * digest_context_p, signal_buffer ** output_pp, void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;
  gcry_md_hd_t * hash_hd_p = (gcry_md_hd_t *) digest_context_p;
  int ret_val = 0;
  char * err_msg = (void *) 0;

  int algo = GCRY_MD_SHA512;
  size_t hash_len = 0;
  unsigned char * hash_data_p = (void *) 0;
  signal_buffer * out_buf_p = (void *) 0;

  hash_len = gcry_md_get_algo_dlen(algo);

  hash_data_p = gcry_md_read(*hash_hd_p, algo);
  if (!hash_data_p) {
    ret_val = SG_ERR_UNKNOWN;
    err_msg = "failed to read hash";
    goto cleanup;
  }

  out_buf_p = signal_buffer_create((uint8_t *) hash_data_p, hash_len);
  if (!out_buf_p) {
    ret_val = SG_ERR_NOMEM;
    err_msg = "failed to create hash output buf";
    goto cleanup;
  }

  gcry_md_reset(*hash_hd_p);

  *output_pp = out_buf_p;

cleanup:
if (ret_val) {
  if (ret_val > 0) {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
    ret_val = SG_ERR_UNKNOWN;
  } else {
    axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
  }
}

  return ret_val;
}

void sha512_digest_cleanup(void * digest_context_p, void * user_data_p) {
  (void) user_data_p;

  gcry_md_hd_t * hash_hd_p = (gcry_md_hd_t *) digest_context_p;

  gcry_md_close(*hash_hd_p);
  free(hash_hd_p);
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
      return SG_ERR_UNKNOWN;
  }

  switch (cipher) {
    case SG_CIPHER_AES_CBC_PKCS5:
      mode = GCRY_CIPHER_MODE_CBC;
      break;
    case SG_CIPHER_AES_CTR_NOPADDING:
      mode = GCRY_CIPHER_MODE_CTR;
      break;
    default:
      return SG_ERR_UNKNOWN;
  }

  *algo_p = algo;
  *mode_p = mode;

  return 0;
}

int aes_encrypt(signal_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * plaintext_p, size_t plaintext_len,
        void * user_data_p) {

  int ret_val = SG_SUCCESS;
  char * err_msg = (void *) 0;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int algo = 0;
  int mode = 0;
  size_t pad_len = 0;
  size_t ct_len = 0;
  gcry_cipher_hd_t cipher_hd = {0};
  uint8_t * pt_p = (void *) 0;
  uint8_t * out_p = (void *) 0;
  signal_buffer * out_buf_p = (void *) 0;

  if(iv_len != 16) {
    err_msg = "invalid AES IV size (must be 16)";
    ret_val = SG_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = choose_aes(cipher, key_len, &algo, &mode);
  if (ret_val) {
    err_msg = "failed to choose cipher";
    ret_val = SG_ERR_UNKNOWN;
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
    case SG_CIPHER_AES_CBC_PKCS5:
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
    case SG_CIPHER_AES_CTR_NOPADDING:
      ct_len = plaintext_len;
      ret_val = gcry_cipher_setctr(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    default:
      ret_val = SG_ERR_UNKNOWN;
      err_msg = "unknown cipher";
      goto cleanup;
  }

  pt_p = malloc(sizeof(uint8_t) * ct_len);
  if (!pt_p) {
    err_msg = "failed to malloc pt buf";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }
  memset(pt_p, pad_len, ct_len);
  memcpy(pt_p, plaintext_p, plaintext_len);

  out_p = malloc(sizeof(uint8_t) * ct_len);
  if (!out_p) {
    err_msg = "failed to malloc ct buf";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }

  ret_val = gcry_cipher_encrypt(cipher_hd, out_p, ct_len, pt_p, ct_len);
  if (ret_val) {
    err_msg = "failed to encrypt";
    goto cleanup;
  }

  out_buf_p = signal_buffer_create(out_p, ct_len);
  *output_pp = out_buf_p;

cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = SG_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }
  }

  free(out_p);
  gcry_cipher_close(cipher_hd);

  return ret_val;
}

int aes_decrypt(signal_buffer ** output_pp,
        int cipher,
        const uint8_t * key_p, size_t key_len,
        const uint8_t * iv_p, size_t iv_len,
        const uint8_t * ciphertext_p, size_t ciphertext_len,
        void * user_data_p) {

  int ret_val = SG_SUCCESS;
  char * err_msg = (void *) 0;
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int algo = 0;
  int mode = 0;
  gcry_cipher_hd_t cipher_hd = {0};
  uint8_t * out_p = (void *) 0;
  size_t pad_len = 0;
  signal_buffer * out_buf_p = (void *) 0;

  if(iv_len != 16) {
    err_msg = "invalid AES IV size (must be 16)";
    ret_val = SG_ERR_UNKNOWN;
    goto cleanup;
  }

  ret_val = choose_aes(cipher, key_len, &algo, &mode);
  if (ret_val) {
    err_msg = "failed to choose cipher";
    ret_val = SG_ERR_UNKNOWN;
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
    case SG_CIPHER_AES_CBC_PKCS5:
      pad_len = 1;
      ret_val = gcry_cipher_setiv(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    case SG_CIPHER_AES_CTR_NOPADDING:
      ret_val = gcry_cipher_setctr(cipher_hd, iv_p, iv_len);
      if (ret_val) {
        err_msg = "failed to set iv";
        goto cleanup;
      }
      break;
    default:
      ret_val = SG_ERR_UNKNOWN;
      err_msg = "unknown cipher";
      goto cleanup;
  }

  out_p = malloc(sizeof(uint8_t) * ciphertext_len);
  if (!out_p) {
    err_msg = "failed to malloc pt buf";
    ret_val = SG_ERR_NOMEM;
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

  out_buf_p = signal_buffer_create(out_p, ciphertext_len - pad_len);
  *output_pp = out_buf_p;


cleanup:
  if (ret_val) {
    if (ret_val > 0) {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s (%s: %s)\n", __func__, err_msg, gcry_strsource(ret_val), gcry_strerror(ret_val));
      ret_val = SG_ERR_UNKNOWN;
    } else {
      axc_log(axc_ctx_p, AXC_LOG_ERROR, "%s: %s\n", __func__, err_msg);
    }
  }

  free(out_p);
  gcry_cipher_close(cipher_hd);

  return ret_val;
}

const signal_crypto_provider axc_crypto_provider_tmpl = {
  .random_func = random_bytes,
  .hmac_sha256_init_func = hmac_sha256_init,
  .hmac_sha256_update_func = hmac_sha256_update,
  .hmac_sha256_final_func = hmac_sha256_final,
  .hmac_sha256_cleanup_func = hmac_sha256_cleanup,
  .sha512_digest_init_func = sha512_digest_init,
  .sha512_digest_update_func = sha512_digest_update,
  .sha512_digest_final_func = sha512_digest_final,
  .sha512_digest_cleanup_func = sha512_digest_cleanup,
  .encrypt_func = aes_encrypt,
  .decrypt_func = aes_decrypt,
  .user_data = (void *) 0
};
