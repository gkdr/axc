/*
 * Copyright (C) 2017-2020 Richard Bayerle <riba@firemail.cc>
 * SPDX-License-Identifier: GPL-3.0-only
 * Author: Richard Bayerle <riba@firemail.cc>
 */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/axc_crypto.h"

#include "../src/axc.c"
#include "../src/axc_store.c"

char * test_fn = "test/test.sqlite";
char * a_fn = "test/a.sqlite";
char * b_fn = "test/b.sqlite";

signal_protocol_address addr_alice_42 = {.name = "alice", .name_len = 5, .device_id = 42};
signal_protocol_address addr_alice_21 = {.name = "alice", .name_len = 5, .device_id = 21};
signal_protocol_address addr_alice = {.name = "alice", .name_len = 5, .device_id = 0};

signal_protocol_address addr_bob_12 = {.name = "bob", .name_len = 3, .device_id = 12};
axc_address addr_bob = {.name = "bob", .name_len = 3, .device_id = 0};

axc_context * ctx_global_p;
axc_context * ctx_a_p = (void *) 0;
axc_context * ctx_b_p = (void *) 0;

int global_setup(void ** state) {
  (void) state;

  axc_crypto_init();

  return 0;
}

int global_teardown(void ** state) {
  (void) state;

  axc_crypto_teardown();

  return 0;
}

int client_setup(void **state) {
  (void) state;

  ctx_global_p = (void *) 0;

  assert_int_equal(axc_context_create(&ctx_global_p), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_global_p, test_fn, strlen(test_fn)), 0);
  //axc_context_set_log_func(ctx_global_p, axc_default_log);
  //axc_context_set_log_level(ctx_global_p, AXC_LOG_DEBUG);

  return axc_init(ctx_global_p);
}

int client_teardown(void ** state) {
  (void) state;

  axc_crypto_teardown();
  axc_cleanup(ctx_global_p);
  ctx_global_p = (void *) 0;
  remove(test_fn);
  return 0;
}

int client_setup_two_dbs(void ** state) {
  (void) state;

  ctx_a_p = (void *) 0;
  ctx_b_p = (void *) 0;

  assert_int_equal(axc_context_create(&ctx_a_p), 0);
  assert_int_equal(axc_context_create(&ctx_b_p), 0);

  assert_int_equal(axc_context_set_db_fn(ctx_a_p, a_fn, strlen(a_fn)), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_b_p, b_fn, strlen(b_fn)), 0);

  /*
  axc_context_set_log_func(ctx_a_p, axc_default_log);
  axc_context_set_log_level(ctx_a_p, AXC_LOG_DEBUG);
  axc_context_set_log_func(ctx_b_p, axc_default_log);
  axc_context_set_log_level(ctx_b_p, AXC_LOG_DEBUG);
  */

  assert_int_equal(axc_init(ctx_a_p), 0);
  assert_int_equal(axc_init(ctx_b_p), 0);

  assert_int_equal(axc_install(ctx_a_p), 0);
  assert_int_equal(axc_install(ctx_b_p), 0);

  return 0;
}

int client_setup_sessions(void ** state) {
  assert_int_equal(client_setup_two_dbs(state), 0);

  axc_bundle * bundle_bob_p;
  assert_int_equal(axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, ctx_b_p, &bundle_bob_p), 0);
  addr_bob.device_id = bundle_bob_p->registration_id;

  assert_int_equal(axc_session_from_bundle(axc_buf_list_item_get_id(bundle_bob_p->pre_keys_head_p),
                                            axc_buf_list_item_get_buf(bundle_bob_p->pre_keys_head_p),
                                            bundle_bob_p->signed_pre_key_id,
                                            bundle_bob_p->signed_pre_key_public_serialized_p,
                                            bundle_bob_p->signed_pre_key_signature_p,
                                            bundle_bob_p->identity_key_public_serialized_p,
                                            &addr_bob,
                                            ctx_a_p),
                    0);

  const char * data = "hello";
  axc_buf * msg_buf_p = axc_buf_create((uint8_t *) data, strlen(data) + 1);
  assert_ptr_not_equal(msg_buf_p, (void *) 0);

  axc_buf * ct_buf_p;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_bob, ctx_a_p, &ct_buf_p), 0);

  uint32_t alice_id;
  assert_int_equal(axc_get_device_id(ctx_a_p, &alice_id), 0);

  addr_alice.device_id = alice_id;

  axc_buf * pt_buf_p;
  assert_int_equal(axc_pre_key_message_process(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p), 0);

  axc_buf_free(ct_buf_p);
  axc_buf_free(pt_buf_p);

  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_alice, ctx_b_p, &ct_buf_p), 0);
  assert_int_equal(axc_message_decrypt_from_serialized(ct_buf_p, &addr_bob, ctx_a_p, &pt_buf_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);
  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 1);

  axc_buf_free(msg_buf_p);
  axc_buf_free(ct_buf_p);
  axc_buf_free(pt_buf_p);

  return 0;
}

int client_teardown_two_dbs(void **state) {
  (void) state;

  axc_cleanup(ctx_a_p);
  axc_cleanup(ctx_b_p);

  remove(a_fn);
  remove(b_fn);

  return 0;
}

void test_init(void **state) {
  (void) state;

  ctx_global_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_global_p), 0);
  assert_ptr_not_equal(ctx_global_p, (void *) 0);

  assert_int_equal(axc_context_set_db_fn(ctx_global_p, test_fn, strlen(test_fn)), 0);
  assert_int_equal(axc_init(ctx_global_p), 0);

  #ifndef NO_THREADS
  assert_ptr_not_equal(ctx_global_p->mutexes_p, (void *) 0);
  assert_ptr_not_equal(ctx_global_p->mutexes_p->mutex_p, (void *) 0);
  assert_ptr_not_equal(ctx_global_p->mutexes_p->mutex_attr_p, (void *) 0);
  int type = 0;
  assert_int_equal(pthread_mutexattr_gettype(ctx_global_p->mutexes_p->mutex_attr_p, &type), 0);
  assert_int_equal(type, PTHREAD_MUTEX_RECURSIVE);
  #endif

  assert_ptr_not_equal(ctx_global_p->axolotl_global_context_p, (void *) 0);

  assert_ptr_not_equal(ctx_global_p->axolotl_store_context_p, (void *) 0);
}

void test_recursive_mutex_lock(void **state) {
  (void) state;

  #ifndef NO_THREADS
  assert_ptr_not_equal(ctx_global_p->mutexes_p, (void *) 0);
  recursive_mutex_lock(ctx_global_p);
  assert_int_equal(pthread_mutex_unlock(ctx_global_p->mutexes_p->mutex_p), 0);
  #else
  skip();
  #endif
}

void test_recursive_mutex_unlock(void **state){
  (void) state;

  #ifndef NO_THREADS
  recursive_mutex_lock(ctx_global_p);
  recursive_mutex_unlock(ctx_global_p);
  assert_int_not_equal(pthread_mutex_unlock(ctx_global_p->mutexes_p->mutex_p), 0);
  #else
  skip();
  #endif
}

void test_install_should_generate_necessary_data(void **state) {
  (void) state;

  assert_int_equal(axc_install(ctx_global_p), 0);

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;

  char stmt[100];
  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM identity_key_store WHERE name IS '%s';", OWN_PUBLIC_KEY_NAME), 0);
  assert_int_equal(sqlite3_open(test_fn, &db_p), SQLITE_OK);

  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM identity_key_store WHERE name IS '%s';", OWN_PRIVATE_KEY_NAME), 0);
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM settings WHERE name IS '%s';", REG_ID_NAME), 0);
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM pre_key_store;"), 0);
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), AXC_PRE_KEYS_AMOUNT);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM signed_pre_key_store;"), 0);
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  assert_int_equal(sqlite3_close(db_p), SQLITE_OK);

  int result = 0;
  assert_int_equal(axc_db_init_status_get(&result, ctx_global_p), 0);
  assert_int_equal(result, AXC_DB_INITIALIZED);
}

void test_install_should_not_do_anything_if_already_initialiased(void **state) {
  (void) state;

  assert_int_equal(axc_install(ctx_global_p), 0);
  
  uint32_t reg_id_1 = 0;
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_global_p, &reg_id_1), 0);
  assert_int_not_equal(reg_id_1, 0);

  uint32_t reg_id_2 = 0;
  assert_int_equal(axc_install(ctx_global_p), 0);
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_global_p, &reg_id_2), 0);
  assert_int_not_equal(reg_id_2, 0);

  assert_int_equal(reg_id_1, reg_id_2);
}

void test_install_should_reset_if_needed(void **state) {
  (void) state;

  assert_int_equal(axc_install(ctx_global_p), 0);
  
  uint32_t reg_id_1 = 0;
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_global_p, &reg_id_1), 0);
  assert_int_not_equal(reg_id_1, 0);

  assert_int_equal(axc_db_init_status_set(0, ctx_global_p), 0);

  uint32_t reg_id_2 = 0;
  assert_int_equal(axc_install(ctx_global_p), 0);
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_global_p, &reg_id_2), 0);
  assert_int_not_equal(reg_id_2, 0);

  assert_int_not_equal(reg_id_1, reg_id_2);
}

void test_message_encrypt_decrypt(void **state) {
  (void) state;

  axc_buf * msg_a1_p = axc_buf_create((uint8_t *) "hallo", 6);
  axc_buf * msg_a2_p = axc_buf_create((uint8_t *) "sup", 4);
  axc_buf * msg_b1_p = axc_buf_create((uint8_t *) "0123456789abcdef", 16);
  axc_buf * msg_b2_p = axc_buf_create((uint8_t *) "na", 3);

  assert_int_not_equal(axc_message_encrypt_and_serialize((void *) 0, (void *) 0, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_encrypt_and_serialize(msg_a1_p, (void *) 0, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_encrypt_and_serialize(msg_a1_p, &addr_bob_12, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_encrypt_and_serialize(msg_a1_p, &addr_bob_12, ctx_a_p, (void *) 0), 0);

  axc_buf * ct_a1_p = (void *) 0;
  axc_buf * ct_a2_p = (void *) 0;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_a1_p, &addr_bob, ctx_a_p, &ct_a1_p), 0);
  assert_int_equal(axc_message_encrypt_and_serialize(msg_a2_p, &addr_bob, ctx_a_p, &ct_a2_p), 0);

  axc_buf * pt_a1_p = (void *) 0;
  axc_buf * pt_a2_p = (void *) 0;

  assert_int_not_equal(axc_message_decrypt_from_serialized((void *) 0, (void *) 0, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_decrypt_from_serialized(ct_a1_p, (void *) 0, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_decrypt_from_serialized(ct_a1_p, &addr_alice, (void *) 0, (void *) 0), 0);
  assert_int_not_equal(axc_message_decrypt_from_serialized(ct_a1_p, &addr_alice, ctx_b_p, (void *) 0), 0);

  assert_int_equal(axc_message_decrypt_from_serialized(ct_a1_p, &addr_alice, ctx_b_p, &pt_a1_p), 0);
  assert_int_equal(axc_message_decrypt_from_serialized(ct_a2_p, &addr_alice, ctx_b_p, &pt_a2_p), 0);

  axc_buf * ct_b1_p = (void *) 0;
  axc_buf * ct_b2_p = (void *) 0;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_b1_p, &addr_alice, ctx_b_p, &ct_b1_p), 0);
  assert_int_equal(axc_message_encrypt_and_serialize(msg_b2_p, &addr_alice, ctx_b_p, &ct_b2_p), 0);

  axc_buf * pt_b1_p = (void *) 0;
  axc_buf * pt_b2_p = (void *) 0;
  assert_int_equal(axc_message_decrypt_from_serialized(ct_b2_p, &addr_bob, ctx_a_p, &pt_b2_p), 0);
  assert_int_equal(axc_message_decrypt_from_serialized(ct_b1_p, &addr_bob, ctx_a_p, &pt_b1_p), 0);

  assert_int_equal(axc_buf_get_len(msg_a1_p), axc_buf_get_len(pt_a1_p));
  assert_memory_equal(axc_buf_get_data(msg_a1_p), axc_buf_get_data(pt_a1_p), axc_buf_get_len(pt_a1_p));

  assert_int_equal(axc_buf_get_len(msg_a2_p), axc_buf_get_len(pt_a2_p));
  assert_memory_equal(axc_buf_get_data(msg_a2_p), axc_buf_get_data(pt_a2_p), axc_buf_get_len(pt_a2_p));

  assert_int_equal(axc_buf_get_len(msg_b1_p), axc_buf_get_len(pt_b1_p));
  assert_memory_equal(axc_buf_get_data(msg_b1_p), axc_buf_get_data(pt_b1_p), axc_buf_get_len(pt_b1_p));

  assert_int_equal(axc_buf_get_len(msg_b2_p), axc_buf_get_len(pt_b2_p));
  assert_memory_equal(axc_buf_get_data(msg_b2_p), axc_buf_get_data(pt_b2_p), axc_buf_get_len(pt_b2_p));

  axc_buf_free(msg_a1_p);
  axc_buf_free(msg_a2_p);
  axc_buf_free(msg_b1_p);
  axc_buf_free(msg_b2_p);

  axc_buf_free(ct_a1_p);
  axc_buf_free(ct_a2_p);
  axc_buf_free(ct_b1_p);
  axc_buf_free(ct_b2_p);

  axc_buf_free(pt_a1_p);
  axc_buf_free(pt_a2_p);
  axc_buf_free(pt_b1_p);
  axc_buf_free(pt_b2_p);
}

void test_session_exists_any(void ** state) {
  (void) state;

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 0);
  assert_int_equal(axc_session_exists_any(addr_bob.name, ctx_a_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 0);
  assert_int_equal(axc_session_exists_any(addr_alice.name, ctx_b_p), 0);

  axc_bundle * bundle_bob_p;
  assert_int_equal(axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, ctx_b_p, &bundle_bob_p), 0);
  addr_bob.device_id = bundle_bob_p->registration_id;

  assert_int_equal(axc_session_from_bundle(axc_buf_list_item_get_id(bundle_bob_p->pre_keys_head_p),
                                            axc_buf_list_item_get_buf(bundle_bob_p->pre_keys_head_p),
                                            bundle_bob_p->signed_pre_key_id,
                                            bundle_bob_p->signed_pre_key_public_serialized_p,
                                            bundle_bob_p->signed_pre_key_signature_p,
                                            bundle_bob_p->identity_key_public_serialized_p,
                                            &addr_bob,
                                            ctx_a_p),
                    0);

  const char * data = "hello";
  axc_buf * msg_buf_p = axc_buf_create((uint8_t *) data, strlen(data) + 1);
  assert_ptr_not_equal(msg_buf_p, (void *) 0);

  axc_buf * ct_buf_p;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_bob, ctx_a_p, &ct_buf_p), 0);

  uint32_t alice_id;
  assert_int_equal(axc_get_device_id(ctx_a_p, &alice_id), 0);

  addr_alice.device_id = alice_id;

  axc_buf * pt_buf_p;
  assert_int_equal(axc_pre_key_message_process(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 1);
  assert_int_equal(axc_session_exists_initiated(&addr_alice_42, ctx_b_p), 0);
  assert_int_equal(axc_session_exists_any(addr_alice.name, ctx_b_p), 1);

}

void test_session_from_bundle_and_handle_prekey_message(void **state) {
  (void) state;

  axc_address addr_bob = {.name = "bob", .name_len = 3, .device_id = 0};
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_b_p, (uint32_t *)&(addr_bob.device_id)), 0);
  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 0);

  uint32_t pre_key_id_bob = 10;
  session_pre_key * pre_key_bob_p = (void *) 0;
  assert_int_equal(signal_protocol_pre_key_load_key(ctx_b_p->axolotl_store_context_p, &pre_key_bob_p, pre_key_id_bob), 0);
  ec_key_pair * pre_key_pair_p = session_pre_key_get_key_pair(pre_key_bob_p);
  ec_public_key * pre_key_public_p = ec_key_pair_get_public(pre_key_pair_p);
  axc_buf * pre_key_public_data_p = (void *) 0;
  assert_int_equal(ec_public_key_serialize(&pre_key_public_data_p, pre_key_public_p), 0);

  uint32_t signed_pre_key_id_bob = 0;
  session_signed_pre_key * signed_pre_key_bob_p = (void *) 0;
  assert_int_equal(signal_protocol_signed_pre_key_load_key(ctx_b_p->axolotl_store_context_p, &signed_pre_key_bob_p, signed_pre_key_id_bob), 0);
  ec_key_pair * signed_pre_key_pair_p = session_signed_pre_key_get_key_pair(signed_pre_key_bob_p);
  ec_public_key * signed_pre_key_public_p = ec_key_pair_get_public(signed_pre_key_pair_p);
  axc_buf * signed_pre_key_public_data_p = (void *) 0;
  assert_int_equal(ec_public_key_serialize(&signed_pre_key_public_data_p, signed_pre_key_public_p), 0);


  axc_buf * signed_pre_key_signature_p = axc_buf_create(session_signed_pre_key_get_signature(signed_pre_key_bob_p),
                                                        session_signed_pre_key_get_signature_len(signed_pre_key_bob_p));
  assert_ptr_not_equal(signed_pre_key_signature_p, (void *) 0);

  axc_buf * identity_public_key_bob_p = (void *) 0;
  axc_buf * identity_private_key_throwaway = (void *) 0;
  assert_int_equal(axc_db_identity_get_key_pair(&identity_public_key_bob_p, &identity_private_key_throwaway, ctx_b_p), 0);


  assert_int_equal(axc_session_from_bundle(pre_key_id_bob,
                                           pre_key_public_data_p,
                                           signed_pre_key_id_bob,
                                           signed_pre_key_public_data_p,
                                           signed_pre_key_signature_p,
                                           identity_public_key_bob_p,
                                           &addr_bob,
                                           ctx_a_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);

  char * test_msg_p = "butter für den buttergott";
  axc_buf * test_msg_data_p = axc_buf_create((uint8_t *) test_msg_p, strlen(test_msg_p) + 1);
  axc_buf * test_msg_ct_p = (void *) 0;
  assert_int_equal(axc_message_encrypt_and_serialize(test_msg_data_p, &addr_bob, ctx_a_p, &test_msg_ct_p), 0);

  size_t pre_keys_count_bob = 0;
  uint32_t max_id_bob = 0;
  assert_int_equal(axc_db_pre_key_get_count(ctx_b_p, &pre_keys_count_bob), 0);
  assert_int_equal(pre_keys_count_bob, AXC_PRE_KEYS_AMOUNT);
  assert_int_equal(axc_db_pre_key_get_max_id(ctx_b_p, &max_id_bob), 0);
  assert_int_equal(max_id_bob, AXC_PRE_KEYS_AMOUNT - 1);

  axc_buf * test_msg_decrypted_p = (void *) 0;
  assert_int_equal(axc_pre_key_message_process(test_msg_ct_p, &addr_alice_21, ctx_b_p, &test_msg_decrypted_p), 0);

  assert_string_equal(test_msg_p, (char *) axc_buf_get_data(test_msg_decrypted_p));

  assert_int_equal(axc_db_pre_key_contains(pre_key_id_bob, ctx_b_p), 0);
  assert_int_equal(axc_db_pre_key_get_count(ctx_b_p, &pre_keys_count_bob), 0);
  assert_int_equal(pre_keys_count_bob, AXC_PRE_KEYS_AMOUNT);
  assert_int_equal(axc_db_pre_key_get_max_id(ctx_b_p, &max_id_bob), 0);
  assert_int_equal(max_id_bob, AXC_PRE_KEYS_AMOUNT);
}

void test_bundle_collect(void ** state) {
  (void) state;

  assert_int_equal(axc_install(ctx_global_p), 0);

  axc_bundle * bundle_p;
  assert_int_equal(axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, ctx_global_p, &bundle_p), 0);
  assert_ptr_not_equal(bundle_p, (void *) 0);

  uint32_t reg_id;
  assert_int_equal(axc_get_device_id(ctx_global_p, &reg_id), 0);
  assert_int_equal(bundle_p->registration_id, reg_id);

  assert_ptr_not_equal(bundle_p->pre_keys_head_p, (void *) 0);

  ec_public_key * signed_pre_key_p;
  assert_ptr_not_equal(bundle_p->signed_pre_key_public_serialized_p, (void *) 0);
  assert_int_equal(curve_decode_point(&signed_pre_key_p,
                                      axc_buf_get_data(bundle_p->signed_pre_key_public_serialized_p),
                                      axc_buf_get_len(bundle_p->signed_pre_key_public_serialized_p),
                                      ctx_global_p->axolotl_global_context_p),
                   0);
  assert_ptr_not_equal(bundle_p->signed_pre_key_signature_p, (void *) 0);

  ec_public_key * identity_key_p;
  assert_ptr_not_equal(bundle_p->identity_key_public_serialized_p, (void *) 0);
  assert_int_equal(curve_decode_point(&identity_key_p,
                                      axc_buf_get_data(bundle_p->identity_key_public_serialized_p),
                                      axc_buf_get_len(bundle_p->identity_key_public_serialized_p),
                                      ctx_global_p->axolotl_global_context_p),
                   0);

  axc_bundle_destroy(bundle_p);
}

void test_session_exists_prekeys(void ** state) {
  (void) state;

  axc_bundle * bundle_bob_p;
  assert_int_equal(axc_bundle_collect(AXC_PRE_KEYS_AMOUNT, ctx_b_p, &bundle_bob_p), 0);

  axc_address addr_bob = {.name = "bob", .name_len = 3, .device_id = bundle_bob_p->registration_id};
  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 0);

  assert_int_equal(axc_session_from_bundle(axc_buf_list_item_get_id(bundle_bob_p->pre_keys_head_p),
                                            axc_buf_list_item_get_buf(bundle_bob_p->pre_keys_head_p),
                                            bundle_bob_p->signed_pre_key_id,
                                            bundle_bob_p->signed_pre_key_public_serialized_p,
                                            bundle_bob_p->signed_pre_key_signature_p,
                                            bundle_bob_p->identity_key_public_serialized_p,
                                            &addr_bob,
                                            ctx_a_p),
                    0);

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);

  const char * data = "hello";
  axc_buf * msg_buf_p = axc_buf_create((uint8_t *) data, strlen(data) + 1);
  assert_ptr_not_equal(msg_buf_p, (void *) 0);

  axc_buf * ct_buf_p;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_bob, ctx_a_p, &ct_buf_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);

  uint32_t alice_id;
  assert_int_equal(axc_get_device_id(ctx_a_p, &alice_id), 0);

  axc_address addr_alice = {.name = "alice", .name_len = strlen("alice"), .device_id = alice_id};
  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 0);

  axc_buf * pt_buf_p;
  assert_int_equal(axc_pre_key_message_process(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p), 0);
  assert_string_equal(axc_buf_get_data(pt_buf_p), "hello");
  assert_memory_equal(axc_buf_get_data(msg_buf_p), axc_buf_get_data(pt_buf_p), axc_buf_get_len(msg_buf_p));
  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 1);

  axc_buf_free(msg_buf_p);
  axc_buf_free(ct_buf_p);
  axc_buf_free(pt_buf_p);

  const char * other_data = "hello 234";
  msg_buf_p = axc_buf_create((uint8_t *) other_data, strlen(other_data) + 1);
  assert_ptr_not_equal(msg_buf_p, (void *) 0);

  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_bob, ctx_a_p, &ct_buf_p), 0);
  int ret_val = axc_message_decrypt_from_serialized(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p);
  assert_int_not_equal(ret_val, 0); // if no reply was received yet, axolotl keeps sending prekey messages
  assert_int_equal(axc_pre_key_message_process(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p), 0);
  assert_memory_equal(axc_buf_get_data(msg_buf_p), axc_buf_get_data(pt_buf_p), axc_buf_get_len(msg_buf_p));

  axc_buf_free(msg_buf_p);
  axc_buf_free(ct_buf_p);
  axc_buf_free(pt_buf_p);
}

void test_key_load_public_own(void ** state) {
  (void) state;

  axc_buf * key_buf_p;
  assert_int_not_equal(axc_key_load_public_own(ctx_global_p, &key_buf_p), 0);

  assert_int_equal(axc_install(ctx_global_p), 0);

  assert_int_equal(axc_key_load_public_own(ctx_global_p, &key_buf_p), 0);

  ratchet_identity_key_pair * kp_p;
  assert_int_equal(signal_protocol_identity_get_key_pair(ctx_global_p->axolotl_store_context_p, &kp_p), 0);

  axc_buf * db_key_buf_p;
  assert_int_equal(ec_public_key_serialize(&db_key_buf_p, ratchet_identity_key_pair_get_public(kp_p)), 0);

  assert_memory_equal(axc_buf_get_data(key_buf_p), axc_buf_get_data(db_key_buf_p), axc_buf_get_len(key_buf_p));
}


void test_key_load_public_addr(void ** state) {
  (void) state;

  assert_int_equal(axc_session_exists_any("bob", ctx_a_p), 1);
  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);

  axc_buf * key_buf_p;
  assert_int_equal(axc_key_load_public_addr(addr_bob.name, 1337, ctx_a_p, &key_buf_p), 0);
  assert_int_equal(axc_key_load_public_addr(addr_bob.name, addr_bob.device_id, ctx_a_p, &key_buf_p), 1);

  session_record * sr_p;
  assert_int_equal(signal_protocol_session_load_session(ctx_a_p->axolotl_store_context_p, &sr_p, &addr_bob), 0);
  assert_int_equal(session_record_is_fresh(sr_p), 0);

  axc_buf * db_key_buf_p;
  assert_int_equal(ec_public_key_serialize(&db_key_buf_p, session_state_get_remote_identity_key(session_record_get_state(sr_p))), 0);
  assert_memory_equal(axc_buf_get_data(key_buf_p), axc_buf_get_data(db_key_buf_p), axc_buf_get_len(key_buf_p));

  axc_buf_free(key_buf_p);
  axc_buf_free(db_key_buf_p);
  SIGNAL_UNREF(sr_p);
}



int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test_teardown(test_init, client_teardown),

      cmocka_unit_test_setup_teardown(test_recursive_mutex_lock, client_setup, client_teardown),
      cmocka_unit_test_setup_teardown(test_recursive_mutex_unlock, client_setup, client_teardown),

      cmocka_unit_test_setup_teardown(test_install_should_generate_necessary_data, client_setup, client_teardown),
      cmocka_unit_test_setup_teardown(test_install_should_not_do_anything_if_already_initialiased, client_setup, client_teardown),
      cmocka_unit_test_setup_teardown(test_install_should_reset_if_needed, client_setup, client_teardown),

      cmocka_unit_test_setup_teardown(test_message_encrypt_decrypt, client_setup_sessions, client_teardown_two_dbs),

      cmocka_unit_test_setup_teardown(test_session_exists_any, client_setup_two_dbs, client_teardown_two_dbs),
      cmocka_unit_test_setup_teardown(test_session_exists_prekeys, client_setup_two_dbs, client_teardown_two_dbs),

      cmocka_unit_test_setup_teardown(test_session_from_bundle_and_handle_prekey_message, client_setup_two_dbs, client_teardown_two_dbs),

      cmocka_unit_test_setup_teardown(test_bundle_collect, client_setup, client_teardown),

      cmocka_unit_test_setup_teardown(test_key_load_public_own, client_setup, client_teardown),
      cmocka_unit_test_setup_teardown(test_key_load_public_addr, client_setup_sessions, client_teardown_two_dbs)
  };

  return cmocka_run_group_tests(tests, global_setup, global_teardown);
 }
