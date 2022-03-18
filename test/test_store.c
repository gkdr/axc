/*
 * Copyright (C) 2017-2020 Richard Bayerle <riba@firemail.cc>
 * SPDX-License-Identifier: GPL-3.0-only
 * Author: Richard Bayerle <riba@firemail.cc>
 */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <stdio.h> // remove
#include <string.h> // strlen
#include <unistd.h> // access

#include "../src/axc.c"
#include "../src/axc_store.c"

sqlite3 * db_p;
sqlite3_stmt * pstmt_p;

char * db_filename = "test.sqlite";
axc_context * ctx_global_p;

signal_protocol_address addr_alice_42 = {.name = "alice", .name_len = 5, .device_id = 42};
signal_protocol_address addr_alice_21 = {.name = "alice", .name_len = 5, .device_id = 21};

signal_protocol_address addr_bob_12 = {.name = "bob", .name_len = 3, .device_id = 12};

uint8_t bytes_1[] = {0xB1, 0x6B, 0x00, 0xB5};
size_t bytes_1_len = sizeof(bytes_1);

uint8_t bytes_2[] = {0xBA, 0xDF, 0xEE, 0x15};
uint8_t bytes_2_len = sizeof(bytes_2);

const int id = 1337;

int db_setup_internal(void **state) {
  (void) state;

  ctx_global_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_global_p), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_global_p, db_filename, strlen(db_filename)), 0);

  db_p = (void *) 0;
  pstmt_p = (void *) 0;

  return 0;
}

int db_setup(void **state) {
  (void) state;

  db_setup_internal((void *) 0);

  assert_int_equal(axc_db_create(ctx_global_p), 0);

  return 0;
}

int db_teardown(void ** state) {
  (void) state;
  
  int ret_val = 0;
  ret_val = sqlite3_finalize(pstmt_p);
  if (ret_val) {
    fprintf(stderr, "failed to finalize statement, SQLite error code: %d\n", ret_val);
  }
  
  ret_val = sqlite3_close(db_p);
  if (ret_val) {
    fprintf(stderr, "failed to close not finalized db");
  }

  axc_context_destroy_all(ctx_global_p);

  db_p = (void *) 0;
  pstmt_p = (void *) 0;

  if (remove(AXC_DB_DEFAULT_FN)) {
    perror("failed to remove default db");
  }
  if (remove(db_filename)) {
    perror("failed to remove test db");
  }

  // as the call to remove often fails intentionally as at least one of the two DVs does not exist, don't let cleanup fail the test
  return 0;
}


void test_db_conn_open_should_create_db_default_filename(void **state) {
  (void) state;

  axc_context * ctx_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "", ctx_p), 0);
  assert_int_equal(access(AXC_DB_DEFAULT_FN, F_OK), 0);

  axc_context_destroy_all(ctx_p);
}

void test_db_conn_open_should_create_db(void **state) {
  (void) state;

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "", ctx_global_p), 0);
  assert_int_not_equal(db_p, 0);
  assert_int_equal(access(db_filename, F_OK), 0);
}

void test_db_conn_open_should_prepare_statement(void **state) {
  (void) state;

  const char * stmt = "VACUUM;";
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_global_p), 0);
  assert_int_not_equal(pstmt_p, (void *) 0);
}

void test_db_conn_open_should_fail_on_null_pointer(void **state) {
  (void) state;

  assert_int_not_equal(db_conn_open(&db_p, &pstmt_p, (void *) 0, ctx_global_p), 0);
  assert_int_equal(pstmt_p, (void *) 0);
}

void test_db_exec_single_change_should_only_succeed_on_correct_number_of_changes(void **state) {
  (void) state;

  const char * stmt1 = "CREATE TABLE test(id INTEGER);";
  const char * stmt2 = "INSERT INTO test VALUES (1)";
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt1, ctx_global_p), 0);
  assert_int_not_equal(db_exec_single_change(db_p, pstmt_p, ctx_global_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt2, ctx_global_p), 0);
  assert_int_equal(db_exec_single_change(db_p, pstmt_p, ctx_global_p), 0);
}

void test_db_exec_quick_should_exec(void **state) {
  (void) state;

  const char * stmt1 = "CREATE TABLE test(id INTEGER);";
  const char * stmt2 = "INSERT INTO test VALUES (1)";

  db_exec_quick(stmt1, ctx_global_p);
  db_exec_quick(stmt2, ctx_global_p);

  const char * stmt3 ="SELECT * FROM test;";
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt3, ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
}

void test_db_create_should_create_necessary_tables(void **state) {
  (void) state;

  char * stmt = "PRAGMA table_info(session_store);";

  assert_int_equal(axc_db_create(ctx_global_p), 0);
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_global_p), 0);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "name");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "TEXT");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "name_len");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "device_id");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "session_record");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "BLOB");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "record_len");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(pre_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "id");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "pre_key_record");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "BLOB");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "record_len");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(signed_pre_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "id");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "signed_pre_key_record");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "BLOB");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "record_len");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(identity_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "name");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "TEXT");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "key");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "BLOB");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "key_len");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "trusted");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(settings);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "name");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "TEXT");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 1), "property");
  assert_string_equal(sqlite3_column_text(pstmt_p, 2), "INTEGER");

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_destroy_should_drop_all_tables(void **state) {
  (void) state;

  char * stmt = "PRAGMA table_info(session_store);";

  assert_int_equal(axc_db_create(ctx_global_p), 0);
  assert_int_equal(axc_db_destroy(ctx_global_p), 0);
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_global_p), 0);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);

  stmt = "PRAGMA table_info(pre_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(signed_pre_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(identity_key_store);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  stmt = "PRAGMA table_info(settings);";
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_property_set_should_set_property_correctly(void **state) {
  (void) state;

  assert_int_equal(axc_db_property_set("test", 1337, ctx_global_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "SELECT property FROM settings WHERE name='test';", ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1337);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_property_get_should_get_correctly(void **state) {
  (void) state;

  const char * prop_name = "test";
  const int prop_val = 1337;

  assert_int_equal(axc_db_property_set(prop_name, prop_val, ctx_global_p), 0);

  int result = 0;
  assert_int_equal(axc_db_property_get(prop_name, &result, ctx_global_p), 0);
  assert_int_equal(result, prop_val);
}

void test_db_property_get_should_fail_on_no_results(void **state) {
  (void) state;

  int result = 0;
  assert_int_not_equal(axc_db_property_get("test", &result, ctx_global_p), 0);
}

void test_db_init_status_set_should_work(void **state) {
  (void) state;

  const int val = 1337;

  assert_int_equal(axc_db_init_status_set(val, ctx_global_p), 0);

  int result = 0;
  assert_int_equal(axc_db_property_get(INIT_STATUS_NAME, &result, ctx_global_p), 0);
  assert_int_equal(result, val);
}

void test_db_init_status_get_should_work(void **state) {
  (void) state;

  const int val = 1337;
  assert_int_equal(axc_db_init_status_set(val, ctx_global_p), 0);

  int result = 0;
  assert_int_equal(axc_db_init_status_get(&result, ctx_global_p), 0);
  assert_int_equal(result, val);
}

void test_db_session_store_should_work(void **state) {
  (void) state;

  assert_int_equal(axc_db_session_store(&addr_alice_42, bytes_1, bytes_1_len, (void *) 0, 0, ctx_global_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "SELECT * FROM session_store WHERE name='alice' AND device_id IS 42;", ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 0), addr_alice_42.name);
  assert_int_equal(sqlite3_column_int(pstmt_p, 1), strlen(addr_alice_42.name));
  assert_int_equal(sqlite3_column_int(pstmt_p, 2), addr_alice_42.device_id);
  assert_memory_equal(sqlite3_column_blob(pstmt_p, 3), bytes_1, bytes_1_len);
  assert_int_equal(sqlite3_column_int(pstmt_p, 4), bytes_1_len);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_session_load_should_find_session(void **state) {
  (void) state;

  assert_int_equal(axc_db_session_store(&addr_alice_42, bytes_1, bytes_1_len, (void *) 0, 0, ctx_global_p), 0);

  signal_buffer * buf = (void *) 0;
  assert_int_equal(axc_db_session_load(&buf, (void *) 0, &addr_alice_42, ctx_global_p), 1);
  assert_memory_equal(signal_buffer_data(buf), bytes_1, bytes_1_len);
  assert_int_equal(signal_buffer_len(buf), bytes_1_len);
}

void test_db_session_load_should_not_find_session(void **state) {
  (void) state;

  signal_buffer * buf = (void *) 0;
  assert_int_equal(axc_db_session_load(&buf, (void *) 0, &addr_alice_42, ctx_global_p), 0);
}

void test_db_session_get_sub_device_sessions_should_find_and_return_correct_number(void **state) {
  (void) state;

  assert_int_equal(axc_db_session_store(&addr_alice_42, bytes_1, bytes_1_len, (void *) 0, 0, ctx_global_p), 0);
  assert_int_equal(axc_db_session_store(&addr_alice_21, bytes_2, bytes_2_len, (void *) 0, 0, ctx_global_p), 0);

  signal_int_list * list_a = (void *) 0;
  assert_int_equal(axc_db_session_get_sub_device_sessions(&list_a, addr_alice_42.name, addr_alice_42.name_len, ctx_global_p), 2);

  signal_int_list * list_b = (void *) 0;
  assert_int_equal(axc_db_session_get_sub_device_sessions(&list_b, addr_bob_12.name, addr_bob_12.name_len, ctx_global_p), 0);

  assert_int_equal(signal_int_list_size(list_a), 2);
  assert_int_equal(signal_int_list_size(list_b), 0);
}

void test_db_session_contains_should_return_correct_values(void ** state) {
  (void) state;

  char * a_db_filename = "a.sqlite";
  char * b_db_filename = "b.sqlite";

  axc_context * ctx_a_p = (void *) 0;
  axc_context * ctx_b_p = (void *) 0;

  signal_protocol_address addr_alice = {.name = "alice", .name_len = 5, .device_id = 0};
  axc_address addr_bob = {.name = "bob", .name_len = 3, .device_id = 0};

  assert_int_equal(axc_context_create(&ctx_a_p), 0);
  assert_int_equal(axc_context_create(&ctx_b_p), 0);

  assert_int_equal(axc_context_set_db_fn(ctx_a_p, a_db_filename, strlen(a_db_filename)), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_b_p, b_db_filename, strlen(b_db_filename)), 0);

  assert_int_equal(axc_init(ctx_a_p), 0);
  assert_int_equal(axc_init(ctx_b_p), 0);

  assert_int_equal(axc_install(ctx_a_p), 0);
  assert_int_equal(axc_install(ctx_b_p), 0);

  assert_int_equal(axc_db_session_contains(&addr_alice, ctx_b_p), 0);
  assert_int_equal(axc_db_session_contains(&addr_bob, ctx_a_p), 0);

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
  axc_buf * msg_buf_p = axc_buf_create((uint8_t *)data, strlen(data) + 1);
  assert_ptr_not_equal(msg_buf_p, (void *) 0);

  axc_buf * ct_buf_p;
  assert_int_equal(axc_message_encrypt_and_serialize(msg_buf_p, &addr_bob, ctx_a_p, &ct_buf_p), 0);

  uint32_t alice_id;
  assert_int_equal(axc_get_device_id(ctx_a_p, &alice_id), 0);

  addr_alice.device_id = alice_id;

  axc_buf * pt_buf_p;
  assert_int_equal(axc_pre_key_message_process(ct_buf_p, &addr_alice, ctx_b_p, &pt_buf_p), 0);

  assert_int_equal(axc_session_exists_initiated(&addr_bob, ctx_a_p), 1);
  assert_int_equal(axc_session_exists_initiated(&addr_alice, ctx_b_p), 1);

  axc_buf_free(msg_buf_p);
  axc_buf_free(ct_buf_p);
  axc_buf_free(pt_buf_p);

  axc_cleanup(ctx_a_p);
  axc_cleanup(ctx_b_p);

  remove(a_db_filename);
  remove(b_db_filename);
}

void test_db_session_delete_should_return_correct_values(void **state) {
  (void) state;

  assert_int_equal(axc_db_session_delete(&addr_alice_21, ctx_global_p), 0);
  assert_int_equal(axc_db_session_store(&addr_alice_42, bytes_1, bytes_1_len, (void *) 0, 0, ctx_global_p), 0);
  assert_int_equal(axc_db_session_delete(&addr_alice_42, ctx_global_p), 1);
}

void test_db_session_delete_all_should_return_correct_values(void **state) {
  (void) state;

  signal_int_list * sessions = (void *) 0;

  assert_int_equal(axc_db_session_store(&addr_alice_42, bytes_1, bytes_1_len, (void *) 0, 0, ctx_global_p), 0);
  assert_int_equal(axc_db_session_store(&addr_alice_21, bytes_2, bytes_2_len, (void *) 0, 0, ctx_global_p), 0);
  assert_int_equal(axc_db_session_get_sub_device_sessions(&sessions, addr_alice_42.name, addr_alice_42.name_len, ctx_global_p), 2);

  assert_int_equal(axc_db_session_delete_all(addr_alice_42.name, addr_alice_42.name_len, ctx_global_p), 2);
  assert_int_equal(axc_db_session_get_sub_device_sessions(&sessions, addr_alice_42.name, addr_alice_42.name_len, ctx_global_p), 0);
}


void test_db_pre_key_store_should_work(void **state) {
  (void) state;

  assert_int_equal(axc_db_pre_key_store(1337, bytes_1, bytes_1_len, ctx_global_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "SELECT * FROM pre_key_store WHERE id IS 1337;", ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1337);
  assert_memory_equal(sqlite3_column_blob(pstmt_p, 1), bytes_1, bytes_1_len);
  assert_int_equal(sqlite3_column_int(pstmt_p, 2), bytes_1_len);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_pre_key_load_should_return_correct_values_and_key(void **state) {
  (void) state;

  assert_int_equal(axc_db_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);

  signal_buffer * buf = (void *) 0;
  assert_int_equal(axc_db_pre_key_load(&buf, id, ctx_global_p), SG_SUCCESS);
  assert_memory_equal(signal_buffer_data(buf), bytes_1, bytes_1_len);

  assert_int_equal(axc_db_pre_key_load(&buf, id + 1, ctx_global_p), SG_ERR_INVALID_KEY_ID);
}

void test_db_pre_key_contains_should_return_correct_values(void **state) {
  (void) state;

  assert_int_equal(axc_db_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);
  assert_int_equal(axc_db_pre_key_contains(id, ctx_global_p), 1);
  assert_int_equal(axc_db_pre_key_contains(id + 1, ctx_global_p), 0);
}

void test_db_pre_key_remove(void **state) {
  (void) state;

  assert_int_not_equal(axc_db_pre_key_remove(id, ctx_global_p), 0);
  assert_int_equal(axc_db_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);
  assert_int_equal(axc_db_pre_key_remove(id, ctx_global_p), 0);
  assert_int_equal(axc_db_pre_key_contains(id, ctx_global_p), 0);
}

void test_db_pre_key_store_list(void **state) {
  (void) state;

  const int pre_key_num = 5;
  char stmt[100];

  axc_context * ctx_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_p), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_p, db_filename, strlen(db_filename)), 0);

  assert_int_equal(axc_init(ctx_p), 0);

  signal_protocol_key_helper_pre_key_list_node * pre_keys_head_p = (void *) 0;
  // for some reason, key IDs is not inclusive and starts at +1!
  assert_int_equal(signal_protocol_key_helper_generate_pre_keys(&pre_keys_head_p, 0, pre_key_num, ctx_p->axolotl_global_context_p), 0);
  assert_int_equal(axc_db_pre_key_store_list(pre_keys_head_p, ctx_p), 0);

  assert_int_not_equal(sprintf(stmt, "SELECT count(*) FROM pre_key_store;"), 0);
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), pre_key_num);
  assert_int_equal(sqlite3_finalize(pstmt_p), SQLITE_OK);

  session_pre_key * pre_key_p = signal_protocol_key_helper_key_list_element(pre_keys_head_p);
  assert_ptr_not_equal(pre_key_p, (void *) 0);

  signal_buffer * key_buf_p = (void *) 0;
  assert_int_equal(session_pre_key_serialize(&key_buf_p, pre_key_p), 0);


  assert_int_not_equal(sprintf(stmt, "SELECT * FROM pre_key_store WHERE id IS %i;", session_pre_key_get_id(pre_key_p)), 0);
  assert_int_equal(sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), session_pre_key_get_id(pre_key_p));
  assert_memory_equal(sqlite3_column_blob(pstmt_p, 1), signal_buffer_data(key_buf_p), signal_buffer_len(key_buf_p));
  assert_int_equal(sqlite3_column_int(pstmt_p, 2), signal_buffer_len(key_buf_p));
}

void test_db_pre_key_get_list(void ** state) {
  (void) state;

  assert_int_equal(axc_init(ctx_global_p), 0);
  assert_int_equal(axc_install(ctx_global_p), 0);

  axc_buf_list_item * head_p = (void *) 0;
  assert_int_equal(axc_db_pre_key_get_list(AXC_PRE_KEYS_AMOUNT, ctx_global_p, &head_p), 0);
  assert_ptr_not_equal(head_p, (void *) 0);

  axc_buf_list_item * curr = head_p;
  int count = 0;
  ec_public_key * pre_key_public_p = (void *) 0;
  axc_buf * buf_p = (void *) 0;
  while (curr) {
    count++;
    buf_p = axc_buf_list_item_get_buf(curr);
    assert_int_equal(curve_decode_point(&pre_key_public_p, axc_buf_get_data(buf_p), axc_buf_get_len(buf_p), ctx_global_p->axolotl_global_context_p), 0);
    SIGNAL_UNREF(pre_key_public_p);
    curr = curr->next_p;
  }

  assert_int_equal(count, AXC_PRE_KEYS_AMOUNT);

  axc_buf_list_free(head_p);
}

void test_db_pre_key_get_max_id(void ** state) {
  (void) state;

  assert_int_equal(axc_init(ctx_global_p), 0);
  assert_int_equal(axc_install(ctx_global_p), 0);

  uint32_t id = 10;
  assert_int_equal(axc_db_pre_key_get_max_id(ctx_global_p, &id), 0);
  assert_int_equal(id, AXC_PRE_KEYS_AMOUNT - 1); // ids start with 0
}

void test_db_signed_pre_key_store_should_work(void **state) {
  (void) state;

  assert_int_equal(axc_db_signed_pre_key_store(1337, bytes_1, bytes_1_len, ctx_global_p), 0);

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, "SELECT * FROM signed_pre_key_store WHERE id IS 1337;", ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_int_equal(sqlite3_column_int(pstmt_p, 0), 1337);
  assert_memory_equal(sqlite3_column_blob(pstmt_p, 1), bytes_1, bytes_1_len);
  assert_int_equal(sqlite3_column_int(pstmt_p, 2), bytes_1_len);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

void test_db_signed_pre_key_load_should_return_correct_values_and_key(void **state) {
  (void) state;

  assert_int_equal(axc_db_signed_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);

  signal_buffer * buf = (void *) 0;
  assert_int_equal(axc_db_signed_pre_key_load(&buf, id, ctx_global_p), SG_SUCCESS);
  assert_memory_equal(signal_buffer_data(buf), bytes_1, bytes_1_len);

  assert_int_equal(axc_db_signed_pre_key_load(&buf, id + 1, ctx_global_p), SG_ERR_INVALID_KEY_ID);
}

void test_db_signed_pre_key_contains_should_return_correct_values(void **state) {
  (void) state;

  assert_int_equal(axc_db_signed_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);
  assert_int_equal(axc_db_signed_pre_key_contains(id, ctx_global_p), 1);
  assert_int_equal(axc_db_signed_pre_key_contains(id + 1, ctx_global_p), 0);
}

void test_db_signed_pre_key_remove(void **state) {
  (void) state;

  assert_int_not_equal(axc_db_signed_pre_key_remove(id, ctx_global_p), 0);
  assert_int_equal(axc_db_signed_pre_key_store(id, bytes_1, bytes_1_len, ctx_global_p), 0);
  assert_int_equal(axc_db_signed_pre_key_remove(id, ctx_global_p), 0);
  assert_int_equal(axc_db_signed_pre_key_contains(id, ctx_global_p), 0);
}

void test_db_identity_set_and_get_key_pair(void **state) {
  (void) state;

  axc_context * ctx_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_p), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_p, db_filename, strlen(db_filename)), 0);
  assert_int_equal(axc_init(ctx_p), 0);

  ratchet_identity_key_pair * identity_key_pair_p = (void *) 0;
  assert_int_equal(signal_protocol_key_helper_generate_identity_key_pair(&identity_key_pair_p, ctx_p->axolotl_global_context_p), 0);

  assert_int_equal(axc_db_identity_set_key_pair(identity_key_pair_p, ctx_p), 0);

  signal_buffer * pubkey_saved_p = (void *) 0;
  signal_buffer * privkey_saved_p = (void *) 0;
  assert_int_equal(axc_db_identity_get_key_pair(&pubkey_saved_p, &privkey_saved_p, ctx_p), 0);

  signal_buffer * pubkey_orig_p = (void *) 0;
  signal_buffer * privkey_orig_p = (void *) 0;
  assert_int_equal(ec_public_key_serialize(&pubkey_orig_p,
      ratchet_identity_key_pair_get_public(identity_key_pair_p)), 0);
  assert_memory_equal(signal_buffer_data(pubkey_orig_p), signal_buffer_data(pubkey_saved_p), signal_buffer_len(pubkey_saved_p));

  assert_int_equal(ec_private_key_serialize(&privkey_orig_p,
      ratchet_identity_key_pair_get_private(identity_key_pair_p)), 0);
  assert_memory_equal(signal_buffer_data(privkey_orig_p), signal_buffer_data(privkey_saved_p), signal_buffer_len(privkey_saved_p));

  signal_buffer_free(pubkey_orig_p);
  signal_buffer_free(pubkey_saved_p);
  signal_buffer_free(privkey_orig_p);
  signal_buffer_free(privkey_saved_p);
}

void test_db_identity_get_key_pair_keys_not_found(void ** state) {
  (void) state;

  assert_int_equal(axc_db_identity_get_key_pair((void * ) 0, (void *) 0, ctx_global_p), SG_ERR_INVALID_KEY_ID);

  axc_context * ctx_p = (void *) 0;
  assert_int_equal(axc_context_create(&ctx_p), 0);
  assert_int_equal(axc_context_set_db_fn(ctx_p, db_filename, strlen(db_filename)), 0);
  assert_int_equal(axc_init(ctx_p), 0);
  assert_int_equal(axc_install(ctx_p), 0);

  char stmt[100];
  assert_int_not_equal(sprintf(stmt, "DELETE FROM identity_key_store WHERE name IS '%s';", OWN_PRIVATE_KEY_NAME), 0);
  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);

  assert_int_equal(axc_db_identity_get_key_pair((void *) 0, (void *) 0, ctx_p), SG_ERR_INVALID_KEY_ID);
}

void test_db_identity_set_local_registration_id(void ** state) {
  (void) state;

  assert_int_equal(axc_db_identity_set_local_registration_id(id, ctx_global_p), 0);

  int result = 0;
  assert_int_equal(axc_db_property_get(REG_ID_NAME, &result, ctx_global_p), 0);
  assert_int_equal(id, result);
}

void test_db_identity_get_local_registration_id(void **state) {
  (void) state;

  assert_int_equal(axc_db_identity_set_local_registration_id(id, ctx_global_p), 0);

  uint32_t result = 0;
  assert_int_equal(axc_db_identity_get_local_registration_id(ctx_global_p, &result), 0);
  assert_int_equal(id, result);
}

void test_db_identity_save(void **state) {
  (void) state;

  assert_int_equal(axc_db_identity_save(&addr_alice_21, bytes_1, bytes_1_len, ctx_global_p), 0);

  const char * stmt = "SELECT * FROM identity_key_store WHERE name='alice';";

  assert_int_equal(db_conn_open(&db_p, &pstmt_p, stmt, ctx_global_p), 0);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_ROW);
  assert_string_equal(sqlite3_column_text(pstmt_p, 0), addr_alice_21.name);
  assert_memory_equal(sqlite3_column_blob(pstmt_p, 1), bytes_1, bytes_1_len);
  assert_int_equal(sqlite3_column_int(pstmt_p, 2), bytes_1_len);
  assert_int_equal(sqlite3_column_int(pstmt_p, 3), IDENTITY_KEY_TRUSTED);

  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);

  assert_int_equal(axc_db_identity_save(&addr_alice_21, (void *) 0, 0, ctx_global_p), 0);

  assert_int_equal(sqlite3_reset(pstmt_p), SQLITE_OK);
  assert_int_equal(sqlite3_step(pstmt_p), SQLITE_DONE);
}

/*
void test_db_identity_is_trusted(void **state) {
  (void) state;

  assert_int_equal(axc_db_identity_save(addr_alice_21.name, 0, bytes_1, bytes_1_len, ctx_global_p), 0);
  assert_int_equal(axc_db_identity_is_trusted(addr_alice_21.name, addr_alice_21.name_len, bytes_1, bytes_1_len, ctx_global_p), 1);
  assert_int_equal(axc_db_identity_is_trusted(addr_alice_21.name, addr_alice_21.name_len, bytes_2, bytes_2_len, ctx_global_p), 0);
  assert_int_equal(axc_db_identity_is_trusted(addr_bob_12.name, addr_bob_12.name_len, bytes_2, bytes_2_len, ctx_global_p), 1);
}
*/

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_db_conn_open_should_create_db_default_filename, db_setup_internal, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_conn_open_should_create_db, db_setup_internal, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_conn_open_should_prepare_statement, db_setup_internal, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_conn_open_should_fail_on_null_pointer, db_setup_internal, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_exec_single_change_should_only_succeed_on_correct_number_of_changes, db_setup_internal, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_exec_quick_should_exec, db_setup_internal, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_create_should_create_necessary_tables, db_setup_internal, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_destroy_should_drop_all_tables, db_setup_internal, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_property_set_should_set_property_correctly, db_setup, db_teardown),
        
        cmocka_unit_test_setup_teardown(test_db_property_get_should_get_correctly, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_property_get_should_fail_on_no_results, db_setup, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_init_status_set_should_work, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_init_status_get_should_work, db_setup, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_session_store_should_work, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_load_should_find_session, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_load_should_not_find_session, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_get_sub_device_sessions_should_find_and_return_correct_number, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_contains_should_return_correct_values, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_delete_should_return_correct_values, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_session_delete_all_should_return_correct_values, db_setup, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_pre_key_store_should_work, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_store_list, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_get_list, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_load_should_return_correct_values_and_key, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_contains_should_return_correct_values, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_remove, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_pre_key_get_max_id, db_setup, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_signed_pre_key_store_should_work, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_signed_pre_key_load_should_return_correct_values_and_key, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_signed_pre_key_contains_should_return_correct_values, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_signed_pre_key_remove, db_setup, db_teardown),

        cmocka_unit_test_setup_teardown(test_db_identity_set_local_registration_id, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_identity_get_local_registration_id, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_identity_set_and_get_key_pair, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_identity_save, db_setup, db_teardown),
        //cmocka_unit_test_setup_teardown(test_db_identity_is_trusted, db_setup, db_teardown),
        cmocka_unit_test_setup_teardown(test_db_identity_get_key_pair_keys_not_found, db_setup, db_teardown)

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

