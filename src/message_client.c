#include <ctype.h> // toupper
#include <stdio.h> // printf, getline
#include <stdlib.h> // exit codes
#include <sys/types.h> // socket
#include <sys/socket.h> // socket
#include <netdb.h> // getaddrinfo
#include <string.h> // memset, strlen
#include <unistd.h> // write


#include "axc.h"

#define PORT "5555"

int main(void) {
  printf("sup\n");
  printf("initializing context for alice...\n");
  axc_context * ctx_a_p;
  if (axc_context_create(&ctx_a_p)) {
    fprintf(stderr, "failed to create axc context\n");
    return EXIT_FAILURE;
  }

  axc_context_set_log_func(ctx_a_p, axc_default_log);
  axc_context_set_log_level(ctx_a_p, AXC_LOG_DEBUG);

  char * db_a_fn = "client/a.sqlite";
  if (axc_context_set_db_fn(ctx_a_p, db_a_fn, strlen(db_a_fn))) {
    fprintf(stderr, "failed to set db filename\n");
    return EXIT_FAILURE;
  }

  printf("set db fn\n");

  if (axc_init(ctx_a_p)) {
    fprintf(stderr, "failed to init axc\n");
    return EXIT_FAILURE;
  }

  printf("installing client for alice...\n");
  if (axc_install(ctx_a_p)) {
    fprintf(stderr, "failed to install axc\n");
    axc_cleanup(ctx_a_p);
    return EXIT_FAILURE;
  }

  printf("initializing context for bob...\n");
  axc_context * ctx_b_p;
  if (axc_context_create(&ctx_b_p)) {
    fprintf(stderr, "failed to create axc context\n");
    return EXIT_FAILURE;
  }

  char * db_b_fn = "client/b.sqlite";
  if (axc_context_set_db_fn(ctx_b_p, db_b_fn, strlen(db_b_fn))) {
    fprintf(stderr, "failed to set db filename\n");
    return EXIT_FAILURE;
  }

  axc_context_set_log_func(ctx_b_p, axc_default_log);
  axc_context_set_log_level(ctx_b_p, AXC_LOG_DEBUG);

  if (axc_init(ctx_b_p)) {
    fprintf(stderr, "failed to init axc\n");
    return EXIT_FAILURE;
  }

  printf("installing client for bob...\n");
  if (axc_install(ctx_b_p)) {
    fprintf(stderr, "failed to install axc\n");
    axc_cleanup(ctx_b_p);
    return EXIT_FAILURE;
  }

  axc_address addr_a = {
      .name = "alice",
      .name_len = 5,
      .device_id = 1
  };

  axc_address addr_b = {
      .name = "bob",
      .name_len = 3,
      .device_id = 1
  };

  printf("checking if session already exists\n");
  if (!axc_session_exists_initiated(&addr_b, ctx_a_p)) {
    printf("creating session between alice and bob\n");
    axc_bundle *bundle_bob;
    if (axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, ctx_b_p, &bundle_bob)) {
      fprintf(stderr, "failed to collect bob's bundle\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    // addr_b.device_id = axc_bundle_get_reg_id(bundle_bob);
    if (axc_session_from_bundle(axc_buf_list_item_get_id(axc_bundle_get_pre_key_list(bundle_bob)),
                                axc_buf_list_item_get_buf(axc_bundle_get_pre_key_list(bundle_bob)),
                                axc_bundle_get_signed_pre_key_id(bundle_bob),
                                axc_bundle_get_signed_pre_key(bundle_bob),
                                axc_bundle_get_signature(bundle_bob),
                                axc_bundle_get_identity_key(bundle_bob),
                                &addr_b,
                                ctx_a_p)) {
      fprintf(stderr, "failed to create session from bob's bundle\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    axc_bundle_destroy(bundle_bob);
    axc_buf * msg_buf_p = axc_buf_create((const uint8_t *)"hello", strlen("hello") + 1);
    if (!msg_buf_p) {
      fprintf(stderr, "failed to create 'hello' msg buffer\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    axc_buf * ct_buf_p;
    if (axc_message_encrypt_and_serialize(msg_buf_p, &addr_b, ctx_a_p, &ct_buf_p)) {
      fprintf(stderr, "failed to encrypt 'hello' message\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    uint32_t alice_id;
    if (axc_get_device_id(ctx_a_p, &alice_id)) {
      fprintf(stderr, "failed to retrieve alice's device_id\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    addr_a.device_id = alice_id;

    axc_buf * pt_buf_p;
    if (axc_pre_key_message_process(ct_buf_p, &addr_a, ctx_b_p, &pt_buf_p)) {
      fprintf(stderr, "failed to process 'hello' pre_key_message\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    axc_buf_free(ct_buf_p);
    axc_buf_free(pt_buf_p);

    if (axc_message_encrypt_and_serialize(msg_buf_p, &addr_a, ctx_b_p, &ct_buf_p)) {
      fprintf(stderr, "failed encrypting 2nd 'hello' message\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    if (axc_message_decrypt_from_serialized(ct_buf_p, &addr_b, ctx_a_p, &pt_buf_p)) {
      fprintf(stderr, "failed decrypting 3rd 'hello' message\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    axc_buf_free(ct_buf_p);
    axc_buf_free(pt_buf_p);

    axc_buf_free(msg_buf_p);

#if 0
    printf("creating handshake initiation message\n");
    axc_handshake * handshake_a;
    if (axc_handshake_initiate(&addr_b, ctx_a_p, &handshake_a)) {
      fprintf(stderr, "failed to initialize handshake from alice to bob\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("'sending' the message to bob and accepting it\n");
    axc_handshake * handshake_b;
    if (axc_handshake_accept(axc_handshake_get_data(handshake_a), &addr_a, ctx_b_p, &handshake_b)) {
      fprintf(stderr, "failed to accept handshake on bob's side\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }

    printf("'sending' response from bob back to alice\n");
    if (axc_handshake_acknowledge(axc_handshake_get_data(handshake_b), handshake_a, ctx_a_p)) {
      fprintf(stderr, "failed to acknowledge handhshake on alice' side\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
#endif
    printf("session created on each side\n");
  } else {
    printf("session exists.\n");
    uint32_t alice_id;
    if (axc_get_device_id(ctx_a_p, &alice_id)) {
      fprintf(stderr, "failed to retrieve alice's device_id\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    addr_a.device_id = alice_id;
  }
  printf("now trying to ready to 'send' and 'receive' messages\n");

  char * line = (void *) 0;
  size_t len = 0;
  printf("enter message: ");
  //goto cleanup;
  while(getline(&line, &len, stdin) > 0) {
    axc_buf * ciphertext_p;
    {
    axc_buf * msg_p = axc_buf_create((uint8_t *) line, strlen(line) + 1);
    if (axc_message_encrypt_and_serialize(msg_p, &addr_b, ctx_a_p, &ciphertext_p)) {
      fprintf(stderr, "failed to encrypt message from alice to bob\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    printf("encrypted message from alice to bob: %s\n", line);
    axc_buf_free(msg_p);
    }

    uint8_t * buf = signal_buffer_data(ciphertext_p);

    printf("serialized ciphertext (hex):\n");
    for (size_t i = 0; i < axc_buf_get_len(ciphertext_p); i++) {
      printf("%02X ", buf[i]);
    }
    printf("\n");

    axc_buf * upper_buf;
    axc_buf * plaintext_p;
    if (axc_message_decrypt_from_serialized(ciphertext_p, &addr_a, ctx_b_p, &plaintext_p)) {
      fprintf(stderr, "failed to decrypt message from alice to bob\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    axc_buf_free(ciphertext_p);

    printf("decrypted message: %s\n", axc_buf_get_data(plaintext_p));

    char * upper = (char *)axc_buf_get_data(plaintext_p);
    for (size_t i = 0; i < strlen(upper); i++) {
      upper[i] = toupper(upper[i]);
    }
    printf("bob sending reply...\n");

    upper_buf = axc_buf_create((uint8_t *) upper, strlen(upper) + 1);
    axc_buf_free(plaintext_p);

    if (axc_message_encrypt_and_serialize(upper_buf, &addr_a, ctx_b_p, &ciphertext_p)) {
      fprintf(stderr, "failed to encrypt message from bob to alice\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    axc_buf_free(upper_buf);

    buf = signal_buffer_data(ciphertext_p);

    printf("serialized ciphertext (hex):\n");
    for (size_t i = 0; i < axc_buf_get_len(ciphertext_p); i++) {
      printf("%02X ", buf[i]);
    }
    printf("\n");

    if (axc_message_decrypt_from_serialized(ciphertext_p, &addr_b, ctx_a_p, &plaintext_p)) {
      fprintf(stderr, "failed to decrypt message from bob to alice\n");
      axc_cleanup(ctx_b_p);
      return EXIT_FAILURE;
    }
    axc_buf_free(ciphertext_p);

    printf("received reply from bob: %s\n", axc_buf_get_data(plaintext_p));
    axc_buf_free(plaintext_p);

    printf("enter message: ");
  }
  free(line);

  printf("done, exiting.\n");
  axc_cleanup(ctx_a_p);
  axc_cleanup(ctx_b_p);
}
