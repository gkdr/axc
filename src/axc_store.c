#include <stdint.h> // int types
#include <stdio.h> // printf
#include <stdlib.h> // exit
#include <string.h> // strlen

#include "signal_protocol.h"
#include "key_helper.h"

#include <sqlite3.h>

#include "axc.h"
#include "axc_store.h"

#define INIT_STATUS_NAME "init_status"
#define OWN_PUBLIC_KEY_NAME "own_public_key"
#define OWN_PRIVATE_KEY_NAME "own_private_key"
#define OWN_KEY 2
#define REG_ID_NAME "axolotl_registration_id"
#define IDENTITY_KEY_TRUSTED 1
#define IDENTITY_KEY_UNTRUSTED 1

#define SESSION_STORE_TABLE_NAME "session_store"
#define SESSION_STORE_NAME_NAME "name"
#define SESSION_STORE_NAME_LEN_NAME "name_len"
#define SESSION_STORE_DEVICE_ID_NAME "device_id"
#define SESSION_STORE_RECORD_NAME "session_record"
#define SESSION_STORE_RECORD_LEN_NAME "record_len"
#define PRE_KEY_STORE_TABLE_NAME "pre_key_store"
#define PRE_KEY_STORE_ID_NAME "id"
#define PRE_KEY_STORE_RECORD_NAME "pre_key_record"
#define PRE_KEY_STORE_RECORD_LEN_NAME "record_len"
#define SIGNED_PRE_KEY_STORE_TABLE_NAME "signed_pre_key_store"
#define SIGNED_PRE_KEY_STORE_ID_NAME "id"
#define SIGNED_PRE_KEY_STORE_RECORD_NAME "signed_pre_key_record"
#define SIGNED_PRE_KEY_STORE_RECORD_LEN_NAME "record_len"
#define IDENTITY_KEY_STORE_TABLE_NAME "identity_key_store"
#define IDENTITY_KEY_STORE_NAME_NAME "name"
#define IDENTITY_KEY_STORE_KEY_NAME "key"
#define IDENTITY_KEY_STORE_KEY_LEN_NAME "key_len"
#define IDENTITY_KEY_STORE_TRUSTED_NAME "trusted"
#define SETTINGS_STORE_TABLE_NAME "settings"
#define SETTINGS_STORE_NAME_NAME "name"
#define SETTINGS_STORE_PROPERTY_NAME "property"

//TODO: clarify error return values
//TODO: maybe change the db scheme to that there is a connection between clients and their keys (???)
//TODO: maybe reimplement saving of own key by means of the save_identity function
//FIXME: add option to cleanup function to see if it's a db error or not and change output accordingly

/**
 * Logs the error message and closes the db connection.
 * If the error message is an empty string, only cleans up.
 * Both the database and statement can be NULL, then only the error message is logged.
 *
 * @param db_p Database connetion to close.
 * @param pstmt_p Prepared statement to finalize.
 * @param msg Error message to log.
 */
static void db_conn_cleanup(sqlite3 * db_p, sqlite3_stmt * pstmt_p, const char * err_msg, const char * func_name, axc_context * ctx_p) {
  if (err_msg) {
    axc_log(ctx_p, AXC_LOG_ERROR, "%s: %s (sqlite err: %s)\n", func_name, err_msg, sqlite3_errmsg(db_p));
  }

  (void) sqlite3_finalize(pstmt_p);
  (void) sqlite3_close(db_p);
}

/**
 * Convenience function for opening a db "connection" and at the same time preparing a statement.
 *
 * @param db_pp Will be set to the db connection pointer.
 * @param pstmt_pp Will be set to the pointer of the prepared statement
 * @param stmt The SQL statement.
 * @param user_data_p Optional. The user_data as received from the axolotl interface, will be used to set the database name.
 * @return 0 on success, negative on failure
 */
static int db_conn_open(sqlite3 ** db_pp, sqlite3_stmt ** pstmt_pp, const char stmt[], void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  int ret_val = 0;
  char * err_msg = (void *) 0;

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;

  if (!stmt) {
    ret_val = -1;
    err_msg = "stmt is null";
    goto cleanup;
  }


  ret_val = sqlite3_open(axc_context_get_db_fn(axc_ctx_p), &db_p);
  if (ret_val) {
    err_msg = "Failed to open db_p";
    goto cleanup;
  }


  if (sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0)) {
    ret_val = -2;
    err_msg = "Failed to prepare statement";
    goto cleanup;
  }

  *db_pp = db_p;
  *pstmt_pp = pstmt_p;

cleanup:
  if (ret_val) {
    db_conn_cleanup(db_p, (void *) 0, err_msg, __func__, axc_ctx_p);
  }

  return ret_val;
}

/**
 * Executes the sqlite_step() function once and checks if there was a corresponding change in the db.
 * Can be used for single insert or delete.
 *
 * @param pstmt_p Pointer to the completely prepared (i.e. including bound values) statement that finishes in one step.
 * @return 0 on success, negative on failure
 */
int db_exec_single_change(sqlite3 * db_p, sqlite3_stmt * pstmt_p, axc_context * axc_ctx_p) {
  if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to execute statement", __func__, axc_ctx_p);
    return -3;
  }

  int changes = sqlite3_changes(db_p);
  if (changes != 1) {
    db_conn_cleanup(db_p, pstmt_p, "less or more than 1 change", __func__, axc_ctx_p);
    return -3;
  }

  return 0;
}

/**
 * Uses the one-step query execution interface to execute the given statement.
 * Ignores any results or errors.
 *
 * @param stmt The SQL statement to execute.
 * @param user_data_p Optional. The user_data as received from the axolotl interface, will be used to set the database name.
 */
void db_exec_quick(const char stmt[], void * user_data_p) {
  axc_context * axc_ctx_p = (axc_context *) user_data_p;

  sqlite3 * db_p = (void *) 0;
  if (sqlite3_open(axc_context_get_db_fn(axc_ctx_p), &db_p)) {
    db_conn_cleanup(db_p, (void *) 0, "Failed to open db", __func__, axc_ctx_p);
  }

  sqlite3_exec(db_p, stmt, (void *) 0, (void *) 0, (void *) 0);

  db_conn_cleanup(db_p, (void *) 0, (void *) 0, __func__, axc_ctx_p);
}

int axc_db_create(axc_context * axc_ctx_p) {
  const char stmt[] =  "BEGIN TRANSACTION;"
                             "CREATE TABLE IF NOT EXISTS " SESSION_STORE_TABLE_NAME "("
                               SESSION_STORE_NAME_NAME " TEXT NOT NULL, "
                               SESSION_STORE_NAME_LEN_NAME " INTEGER NOT NULL, "
                               SESSION_STORE_DEVICE_ID_NAME " INTEGER NOT NULL, "
                               SESSION_STORE_RECORD_NAME " BLOB NOT NULL, "
                               SESSION_STORE_RECORD_LEN_NAME " INTEGER NOT NULL, "
                             "  PRIMARY KEY("SESSION_STORE_NAME_NAME", "SESSION_STORE_DEVICE_ID_NAME")); "
                             "CREATE TABLE IF NOT EXISTS " PRE_KEY_STORE_TABLE_NAME "("
                               PRE_KEY_STORE_ID_NAME " INTEGER NOT NULL PRIMARY KEY, "
                               PRE_KEY_STORE_RECORD_NAME " BLOB NOT NULL, "
                               PRE_KEY_STORE_RECORD_LEN_NAME " INTEGER NOT NULL); "
                             "CREATE TABLE IF NOT EXISTS " SIGNED_PRE_KEY_STORE_TABLE_NAME "("
                               SIGNED_PRE_KEY_STORE_ID_NAME " INTEGER NOT NULL PRIMARY KEY, "
                               SIGNED_PRE_KEY_STORE_RECORD_NAME " BLOB NOT NULL, "
                               SIGNED_PRE_KEY_STORE_RECORD_LEN_NAME " INTEGER NOT NULL);"
                             "CREATE TABLE IF NOT EXISTS " IDENTITY_KEY_STORE_TABLE_NAME "("
                               IDENTITY_KEY_STORE_NAME_NAME " TEXT NOT NULL PRIMARY KEY, "
                               IDENTITY_KEY_STORE_KEY_NAME " BLOB NOT NULL, "
                               IDENTITY_KEY_STORE_KEY_LEN_NAME " INTEGER NOT NULL, "
                               IDENTITY_KEY_STORE_TRUSTED_NAME " INTEGER NOT NULL);"
                             "CREATE TABLE IF NOT EXISTS " SETTINGS_STORE_TABLE_NAME "("
                               SETTINGS_STORE_NAME_NAME " TEXT NOT NULL PRIMARY KEY, "
                               SETTINGS_STORE_PROPERTY_NAME " INTEGER NOT NULL);"
                             "COMMIT TRANSACTION;";

  sqlite3 * db_p = (void *) 0;
  char * err_msg = (void *) 0;

  if (sqlite3_open(axc_context_get_db_fn(axc_ctx_p), &db_p)) {
    db_conn_cleanup(db_p, (void *) 0, "Failed to open db", __func__, axc_ctx_p);
    return -1;
  }

  sqlite3_exec(db_p, stmt, (void *) 0, (void *) 0, &err_msg);
  if (err_msg) {
    db_conn_cleanup(db_p, (void *) 0, err_msg, __func__, axc_ctx_p);
    sqlite3_free(err_msg);
    return -1;
  }

  db_conn_cleanup(db_p, (void *) 0, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

/**
 * Drops all tables.
 *
 * @param axc_ctx_p Pointer to the axc context.
 */
int axc_db_destroy(axc_context * axc_ctx_p) {
  const char stmt[] = "BEGIN TRANSACTION;"
                      "DROP TABLE IF EXISTS " SESSION_STORE_TABLE_NAME ";"
                      "DROP TABLE IF EXISTS " PRE_KEY_STORE_TABLE_NAME ";"
                      "DROP TABLE IF EXISTS " SIGNED_PRE_KEY_STORE_TABLE_NAME ";"
                      "DROP TABLE IF EXISTS " IDENTITY_KEY_STORE_TABLE_NAME ";"
                      "DROP TABLE IF EXISTS " SETTINGS_STORE_TABLE_NAME ";"
                      "COMMIT TRANSACTION;";

  sqlite3 * db_p = (void *) 0;
  char * err_msg = (void *) 0;

  if (sqlite3_open(axc_context_get_db_fn(axc_ctx_p), &db_p)) {
    db_conn_cleanup(db_p, (void *) 0, "Failed to open db", __func__, axc_ctx_p);
    return -1;
  }

  sqlite3_exec(db_p, stmt, (void *) 0, (void *) 0, &err_msg);
  if (err_msg) {
    db_conn_cleanup(db_p, (void *) 0, err_msg, __func__, axc_ctx_p);
    sqlite3_free(err_msg);
    return -1;
  }

  db_conn_cleanup(db_p, (void *) 0, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_property_set(const char * name, const int val, axc_context * axc_ctx_p) {
  // 1 - name of property
  // 2 - value
  const char stmt[] = "INSERT OR REPLACE INTO " SETTINGS_STORE_TABLE_NAME " VALUES (?1, ?2);";

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_STATIC)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_bind_int(pstmt_p, 2, val)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -22;
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_property_get(const char * name, int * val_p, axc_context * axc_ctx_p) {
  const char stmt[] = "SELECT * FROM " SETTINGS_STORE_TABLE_NAME " WHERE name IS ?1;";

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_STATIC)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  const int step_result = sqlite3_step(pstmt_p);
  if (step_result == SQLITE_DONE) {
    db_conn_cleanup(db_p, pstmt_p, "Result not found", __func__, axc_ctx_p);
    return 1;
  } else if (step_result == SQLITE_ROW) {
    const int temp = sqlite3_column_int(pstmt_p, 1);

    // exactly one result
    if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
      db_conn_cleanup(db_p, pstmt_p, "Too many results", __func__, axc_ctx_p);
      return -3;
    }

    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    *val_p = temp;
    return 0;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed to execute statement", __func__, axc_ctx_p);
    return -3;
  }
}

int axc_db_init_status_set(const int status, axc_context * axc_ctx_p) {
  return axc_db_property_set(INIT_STATUS_NAME, status, axc_ctx_p);
}

int axc_db_init_status_get(int * init_status_p, axc_context * axc_ctx_p) {
  return axc_db_property_get(INIT_STATUS_NAME, init_status_p, axc_ctx_p);
}

// session store impl
int axc_db_session_load(signal_buffer ** record, signal_buffer ** user_record, const signal_protocol_address * address, void * user_data) {
  const char stmt[] = "SELECT * FROM " SESSION_STORE_TABLE_NAME
                      " WHERE " SESSION_STORE_NAME_NAME " IS ?1"
                      " AND " SESSION_STORE_DEVICE_ID_NAME " IS ?2;";

  (void) user_record;

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, address->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name when trying to load a session", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_bind_int(pstmt_p, 2, address->device_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind device_id when trying to load a session", __func__, axc_ctx_p);
    return -22;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // session not found
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 0;
  } else if (step_result == SQLITE_ROW) {
    const int record_len = sqlite3_column_int(pstmt_p, 4);
    *record = signal_buffer_create(sqlite3_column_blob(pstmt_p, 3), record_len);

    if (*record == 0) {
      db_conn_cleanup(db_p, pstmt_p, "Buffer could not be initialised", __func__, axc_ctx_p);
      return -3;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 1;
}

int axc_db_session_get_sub_device_sessions(signal_int_list ** sessions, const char * name, size_t name_len, void * user_data) {
  const char stmt[] = "SELECT * FROM " SESSION_STORE_TABLE_NAME " WHERE " SESSION_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;
  
  signal_int_list * session_list_p = (void *) 0;
  char * err_msg = (void *) 0;
  int ret_val = 0;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_TRANSIENT)) {
    err_msg = "Failed to bind name when trying to find sub device sessions";
    ret_val = -21;
    goto cleanup;
  }
  
  session_list_p = signal_int_list_alloc();

  int step_result = sqlite3_step(pstmt_p);
  while (step_result == SQLITE_ROW) {
    signal_int_list_push_back(session_list_p, sqlite3_column_int(pstmt_p, 2));

    step_result = sqlite3_step(pstmt_p);
  }

  if (step_result != SQLITE_DONE) {
    err_msg = "Error while retrieving result rows";
    ret_val = -3;
    goto cleanup;
  }

  (void) name_len;

  *sessions = session_list_p;
  ret_val = signal_int_list_size(*sessions);

cleanup:
  if (ret_val < 0) {
    if (session_list_p) {
      signal_int_list_free(session_list_p);
    }
  }
  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}

int axc_db_session_store(const signal_protocol_address *address, uint8_t *record, size_t record_len, uint8_t *user_record, size_t user_record_len, void *user_data) {
  const char stmt[] = "INSERT OR REPLACE INTO " SESSION_STORE_TABLE_NAME " VALUES (:name, :name_len, :device_id, :session_record, :record_len);";

  (void) user_record;
  (void) user_record_len;

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if(sqlite3_bind_text(pstmt_p, 1, address->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name when trying to store a session", __func__, axc_ctx_p);
    return -21;
  }
  if (sqlite3_bind_int(pstmt_p, 2, address->name_len)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name length when trying to store a session", __func__, axc_ctx_p);
    return -22;
  }
  if (sqlite3_bind_int(pstmt_p, 3, address->device_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind device id when trying to store a session", __func__, axc_ctx_p);
    return -23;
  }
  if (sqlite3_bind_blob(pstmt_p, 4, record, record_len, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind record when trying to store a session", __func__, axc_ctx_p);
    return -24;
  }
  if (sqlite3_bind_int(pstmt_p, 5, record_len)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind record length when trying to store a session", __func__, axc_ctx_p);
    return -25;
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_session_contains(const signal_protocol_address * address, void * user_data) {
  const char stmt[] = "SELECT * FROM " SESSION_STORE_TABLE_NAME
                      " WHERE " SESSION_STORE_NAME_NAME " IS ?1"
                      " AND " SESSION_STORE_DEVICE_ID_NAME " IS ?2;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, address->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name when checking if session exists", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_bind_int(pstmt_p, 2, address->device_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind device id when checking if session exists", __func__, axc_ctx_p);
    return -22;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // no result
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 0;
  } else if (step_result == SQLITE_ROW) {
    // result exists
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 1;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }
}

int axc_db_session_delete(const signal_protocol_address * address, void * user_data) {
  const char stmt[] = "DELETE FROM " SESSION_STORE_TABLE_NAME
                      " WHERE " SESSION_STORE_NAME_NAME " IS ?1"
                      " AND " SESSION_STORE_DEVICE_ID_NAME " IS ?2;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, address->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name when trying to delete session", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_bind_int(pstmt_p, 2, address->device_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind device id when trying to delete session", __func__, axc_ctx_p);
    return -22;
  }

  if (sqlite3_step(pstmt_p) == SQLITE_DONE) {
    if (sqlite3_changes(db_p)) {
      db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
      return 1;
    } else {
      db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
      return 0;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed to delete session", __func__, axc_ctx_p);
    return -4;
  }
}

int axc_db_session_delete_all(const char * name, size_t name_len, void * user_data) {
  const char stmt[] = "DELETE FROM " SESSION_STORE_TABLE_NAME " WHERE " SESSION_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind name when trying to delete all sessions", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_step(pstmt_p) == SQLITE_DONE) {
    const int changes = sqlite3_changes(db_p);
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return changes;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed to delete sessions", __func__, axc_ctx_p);
    return -4;
  }

  (void)name_len;
}

void axc_db_session_destroy_store_ctx(void * user_data) {
  (void) user_data;
  //const char stmt[] = "DELETE FROM session_store; VACUUM;";

  //db_exec_quick(stmt, user_data);
}

// pre key store impl
int axc_db_pre_key_load(signal_buffer ** record, uint32_t pre_key_id, void * user_data) {
  const char stmt[] = "SELECT * FROM " PRE_KEY_STORE_TABLE_NAME " WHERE " PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // session not found
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return SG_ERR_INVALID_KEY_ID;
  } else if (step_result == SQLITE_ROW) {
    const int record_len = sqlite3_column_int(pstmt_p, 2);
    *record = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), record_len);

    if (*record == 0) {
      db_conn_cleanup(db_p, pstmt_p, "Buffer could not be initialised", __func__, axc_ctx_p);
      return -3;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return SG_SUCCESS;
}

int axc_db_pre_key_store(uint32_t pre_key_id, uint8_t * record, size_t record_len, void * user_data) {
  const char stmt[] = "INSERT OR REPLACE INTO " PRE_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3);";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if(sqlite3_bind_int(pstmt_p, 1, pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }
  if (sqlite3_bind_blob(pstmt_p, 2, record, record_len, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -22;
  }
  if (sqlite3_bind_int(pstmt_p, 3, record_len)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -23;
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_pre_key_store_list(signal_protocol_key_helper_pre_key_list_node * pre_keys_head, axc_context * axc_ctx_p) {
  const char stmt_begin[] = "BEGIN TRANSACTION;";
  const char stmt[] = "INSERT OR REPLACE INTO " PRE_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3);";
  const char stmt_commit[] = "COMMIT TRANSACTION;";

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  signal_buffer * key_buf_p = (void *) 0;
  signal_protocol_key_helper_pre_key_list_node * pre_keys_curr_p = (void *) 0;
  session_pre_key * pre_key_p = (void *) 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt_begin, axc_ctx_p)) return -1;

  if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to execute statement", __func__, axc_ctx_p);
    return -3;
  }

  sqlite3_finalize(pstmt_p);

  if (sqlite3_prepare_v2(db_p, stmt, -1, &pstmt_p, (void *) 0)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to prepare statement", __func__, axc_ctx_p);
    return -2;
  }


  pre_keys_curr_p = pre_keys_head;
  while (pre_keys_curr_p) {
    pre_key_p = signal_protocol_key_helper_key_list_element(pre_keys_curr_p);
    if (session_pre_key_serialize(&key_buf_p, pre_key_p)) {
      db_conn_cleanup(db_p, pstmt_p, "failed to serialize pre key", __func__, axc_ctx_p);
      return -1;
    }

    if(sqlite3_bind_int(pstmt_p, 1, session_pre_key_get_id(pre_key_p))) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -21;
    }
    if (sqlite3_bind_blob(pstmt_p, 2, signal_buffer_data(key_buf_p), signal_buffer_len(key_buf_p), SQLITE_TRANSIENT)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -22;
    }
    if (sqlite3_bind_int(pstmt_p, 3, signal_buffer_len(key_buf_p))) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -23;
    }

    if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to execute statement", __func__, axc_ctx_p);
      return -3;
    }

    signal_buffer_bzero_free(key_buf_p);
    sqlite3_reset(pstmt_p);
    sqlite3_clear_bindings(pstmt_p);

    pre_keys_curr_p = signal_protocol_key_helper_key_list_next(pre_keys_curr_p);
  }
  sqlite3_finalize(pstmt_p);

  if (sqlite3_prepare_v2(db_p, stmt_commit, -1, &pstmt_p, (void *) 0)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to prepare statement", __func__, axc_ctx_p);
    return -2;
  }
  if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to execute statement", __func__, axc_ctx_p);
    return -3;
  }

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_pre_key_get_list(size_t amount, axc_context * axc_ctx_p, axc_buf_list_item ** list_head_pp) {
  const char stmt[] = "SELECT * FROM " PRE_KEY_STORE_TABLE_NAME
                      " ORDER BY " PRE_KEY_STORE_ID_NAME " ASC LIMIT ?1;";

  int ret_val = -1;
  char * err_msg = (void *) 0;

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  axc_buf_list_item * head_p = (void *) 0;
  axc_buf_list_item * curr_p = (void *) 0;
  uint32_t key_id = 0;
  axc_buf * serialized_keypair_data_p = (void *) 0;
  size_t record_len = 0;
  session_pre_key * pre_key_p = (void *) 0;
  ec_key_pair * pre_key_pair_p = (void *) 0;
  ec_public_key * pre_key_public_p = (void *) 0;
  axc_buf * pre_key_public_serialized_p = (void *) 0;
  axc_buf_list_item * temp_item_p = (void *) 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  ret_val = sqlite3_bind_int(pstmt_p, 1, amount);
  if (ret_val) {
    err_msg = "failed to bind";
    goto cleanup;
  }

  ret_val = axc_buf_list_item_create(&head_p, (void *) 0, (void *) 0);
  if (ret_val) {
    err_msg = "failed to create list";
    goto cleanup;
  }

  curr_p = head_p;
  ret_val = sqlite3_step(pstmt_p);
  while (ret_val == SQLITE_ROW) {
    key_id = sqlite3_column_int(pstmt_p, 0);
    record_len = sqlite3_column_int(pstmt_p, 2);

    serialized_keypair_data_p = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), record_len);
    if (!serialized_keypair_data_p) {
      err_msg = "failed to initialize buffer";
      ret_val = -3;
      goto cleanup;
    }

    ret_val = session_pre_key_deserialize(&pre_key_p, axc_buf_get_data(serialized_keypair_data_p), record_len, axc_context_get_axolotl_ctx(axc_ctx_p));
    if (ret_val) {
      err_msg = "failed to deserialize keypair";
      goto cleanup;
    }

    pre_key_pair_p = session_pre_key_get_key_pair(pre_key_p);
    pre_key_public_p = ec_key_pair_get_public(pre_key_pair_p);

    ret_val = ec_public_key_serialize(&pre_key_public_serialized_p, pre_key_public_p);
    if (ret_val) {
      err_msg = "failed to serialize public key";
      goto cleanup;
    }

    ret_val = axc_buf_list_item_create(&temp_item_p, &key_id, pre_key_public_serialized_p);
    if (ret_val) {
      err_msg = "failed to create list item";
      goto cleanup;
    }

    axc_buf_list_item_set_next(curr_p, temp_item_p);
    curr_p = axc_buf_list_item_get_next(curr_p);

    axc_buf_free(serialized_keypair_data_p);

    SIGNAL_UNREF(pre_key_p);
    pre_key_p = (void *) 0;
    ret_val = sqlite3_step(pstmt_p);
  }

  if (ret_val != SQLITE_DONE) {
    err_msg = "sql error when retrieving keys";
    goto cleanup;
  }

  *list_head_pp = axc_buf_list_item_get_next(head_p);
  ret_val = 0;

cleanup:
  if (ret_val) {
    axc_buf_free(serialized_keypair_data_p);
    SIGNAL_UNREF(pre_key_p);
    axc_buf_free(pre_key_public_serialized_p);
    axc_buf_list_free(head_p);
  }

  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}

int axc_db_pre_key_contains(uint32_t pre_key_id, void * user_data) {
  const char stmt[] = "SELECT * FROM " PRE_KEY_STORE_TABLE_NAME " WHERE " PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // no result
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 0;
  } else if (step_result == SQLITE_ROW) {
    // result exists
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 1;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }
}

int axc_db_pre_key_get_max_id(axc_context * axc_ctx_p, uint32_t * max_id_p) {
  const char * stmt = "SELECT MAX(" PRE_KEY_STORE_ID_NAME ") FROM " PRE_KEY_STORE_TABLE_NAME
                      " WHERE " PRE_KEY_STORE_ID_NAME " IS NOT ("
                      "   SELECT MAX(" PRE_KEY_STORE_ID_NAME ") FROM " PRE_KEY_STORE_TABLE_NAME
                      " );";

  char * err_msg = (void *) 0;
  int ret_val = 0;
  uint32_t id = 0;


  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  ret_val = sqlite3_step(pstmt_p);
  if (ret_val == SQLITE_ROW) {
    id = sqlite3_column_int(pstmt_p, 0);
    if (!id) {
      err_msg = "db not initialized";
      ret_val = -1;
    } else {
      *max_id_p = id;
      ret_val = 0;
    }
  } else {
    err_msg = "db error";
    ret_val = -ret_val;
  }

  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}

int axc_db_pre_key_get_count(axc_context * axc_ctx_p, size_t * count_p) {
  const char * stmt = "SELECT count(" PRE_KEY_STORE_ID_NAME") FROM " PRE_KEY_STORE_TABLE_NAME ";";

  int ret_val = 0;
  char * err_msg = (void *) 0;

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  ret_val = sqlite3_step(pstmt_p);
  if (ret_val != SQLITE_ROW) {
    err_msg = "count returned an error";
    ret_val = -1;
  } else {
    *count_p = sqlite3_column_int(pstmt_p, 0);
    ret_val = 0;
  }

  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);

  return ret_val;
}

int axc_db_pre_key_remove(uint32_t pre_key_id, void * user_data) {
  const char stmt[] = "DELETE FROM " PRE_KEY_STORE_TABLE_NAME " WHERE " PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_step(pstmt_p) == SQLITE_DONE) {
    if (sqlite3_changes(db_p)) {
      db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
      return 0;
    } else {
      db_conn_cleanup(db_p, pstmt_p, "Key does not exist", __func__, axc_ctx_p);
      return -4;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed to delete session", __func__, axc_ctx_p);
    return -4;
  }
}

void axc_db_pre_key_destroy_ctx(void * user_data) {
  (void) user_data;
  //const char stmt[] = "DELETE FROM pre_key_store; VACUUM;";

  //db_exec_quick(stmt, user_data);
}

// signed pre key store impl
int axc_db_signed_pre_key_load(signal_buffer ** record, uint32_t signed_pre_key_id, void * user_data) {
  const char stmt[] = "SELECT * FROM " SIGNED_PRE_KEY_STORE_TABLE_NAME " WHERE " SIGNED_PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, signed_pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // session not found
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return SG_ERR_INVALID_KEY_ID;
  } else if (step_result == SQLITE_ROW) {
    const int record_len = sqlite3_column_int(pstmt_p, 2);
    *record = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), record_len);

    if (*record == 0) {
      db_conn_cleanup(db_p, pstmt_p, "Buffer could not be initialised", __func__, axc_ctx_p);
      return -3;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return SG_SUCCESS;
}

int axc_db_signed_pre_key_store(uint32_t signed_pre_key_id, uint8_t * record, size_t record_len, void * user_data) {
  const char stmt[] = "INSERT OR REPLACE INTO " SIGNED_PRE_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3);";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if(sqlite3_bind_int(pstmt_p, 1, signed_pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }
  if (sqlite3_bind_blob(pstmt_p, 2, record, record_len, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -22;
  }
  if (sqlite3_bind_int(pstmt_p, 3, record_len)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -23;
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_signed_pre_key_contains(uint32_t signed_pre_key_id, void * user_data) {
  const char stmt[] = "SELECT * FROM " SIGNED_PRE_KEY_STORE_TABLE_NAME " WHERE " SIGNED_PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, signed_pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // no result
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 0;
  } else if (step_result == SQLITE_ROW) {
    // result exists
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 1;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -3;
  }
}

int axc_db_signed_pre_key_remove(uint32_t signed_pre_key_id, void * user_data) {
  const char stmt[] = "DELETE FROM " SIGNED_PRE_KEY_STORE_TABLE_NAME " WHERE " SIGNED_PRE_KEY_STORE_ID_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_int(pstmt_p, 1, signed_pre_key_id)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (sqlite3_step(pstmt_p) == SQLITE_DONE) {
    if (sqlite3_changes(db_p)) {
      db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
      return 0;
    } else {
      db_conn_cleanup(db_p, pstmt_p, "Key does not exist", __func__, axc_ctx_p);
      return -4;
    }
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed to delete session", __func__, axc_ctx_p);
    return -4;
  }
}

void axc_db_signed_pre_key_destroy_ctx(void * user_data) {
  (void) user_data;
  //const char stmt[] = "DELETE FROM signed_pre_key_store; VACUUM;";

  //db_exec_quick(stmt, user_data);
}

// identity key store impl
/**
 * saves the public and private key by using the api serialization calls, as this format (and not the higher-level key type) is needed by the getter.
 */
int axc_db_identity_set_key_pair(const ratchet_identity_key_pair * key_pair_p, axc_context * axc_ctx_p) {
  // 1 - name ("public" or "private")
  // 2 - key blob
  // 3 - length of the key
  // 4 - trusted (1 for true, 0 for false)
  const char stmt[] = "INSERT INTO " IDENTITY_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3, ?4);";

  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;

  char * err_msg = (void *) 0;
  int ret_val = 0;
  signal_buffer * pubkey_buf_p = (void *) 0;
  signal_buffer * privkey_buf_p = (void *) 0;
  size_t pubkey_buf_len = 0;
  uint8_t * pubkey_buf_data_p = (void *) 0;
  size_t privkey_buf_len = 0;
  uint8_t * privkey_buf_data_p = (void *) 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt, axc_ctx_p)) return -1;

  // public key
  if (sqlite3_bind_text(pstmt_p, 1, OWN_PUBLIC_KEY_NAME, -1, SQLITE_STATIC)) {
    err_msg = "Failed to bind";
    ret_val = -21;
    goto cleanup;
  }

  if (ec_public_key_serialize(&pubkey_buf_p, ratchet_identity_key_pair_get_public(key_pair_p))) {
    err_msg = "Failed to allocate memory to serialize the public key";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }
  pubkey_buf_len = signal_buffer_len(pubkey_buf_p);
  pubkey_buf_data_p = signal_buffer_data(pubkey_buf_p);

  if (sqlite3_bind_blob(pstmt_p, 2, pubkey_buf_data_p, pubkey_buf_len, SQLITE_TRANSIENT)) {
    err_msg = "Failed to bind";
    ret_val = -22;
    goto cleanup;
  }

  if(sqlite3_bind_int(pstmt_p, 3, pubkey_buf_len)) {
    err_msg = "Failed to bind";
    ret_val = -23;
    goto cleanup;
  }

  if (sqlite3_bind_int(pstmt_p, 4, OWN_KEY)) {
    err_msg = "Failed to bind";
    ret_val = -24;
    goto cleanup;
  }

  if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
    err_msg = "Failed to execute statement";
    ret_val = -3;
    goto cleanup;
  }

  if (sqlite3_changes(db_p) != 1) {
    err_msg = "Failed to insert";
    ret_val = -3;
    goto cleanup;
  }

  // private key
  if (sqlite3_reset(pstmt_p)) {
    err_msg = "Failed to reset prepared statement";
    ret_val = -2;
    goto cleanup;
  }
  sqlite3_clear_bindings(pstmt_p);

  if (sqlite3_bind_text(pstmt_p, 1, OWN_PRIVATE_KEY_NAME, -1, SQLITE_STATIC)) {
    err_msg = "Failed to bind";
    ret_val = -21;
    goto cleanup;
  }

  if (ec_private_key_serialize(&privkey_buf_p, ratchet_identity_key_pair_get_private(key_pair_p))) {
    err_msg = "Failed to allocate memory to serialize the private key";
    ret_val = SG_ERR_NOMEM;
    goto cleanup;
  }
  privkey_buf_len = signal_buffer_len(privkey_buf_p);
  privkey_buf_data_p = signal_buffer_data(privkey_buf_p);

  if (sqlite3_bind_blob(pstmt_p, 2, privkey_buf_data_p, privkey_buf_len, SQLITE_TRANSIENT)) {
    err_msg = "Failed to bind";
    ret_val = -22;
    goto cleanup;
  }

  if(sqlite3_bind_int(pstmt_p, 3, privkey_buf_len)) {
    err_msg = "Failed to bind";
    ret_val = -23;
    goto cleanup;
  }

  if (sqlite3_bind_int(pstmt_p, 4, OWN_KEY)) {
    err_msg = "Failed to bind";
    ret_val = -24;
    goto cleanup;
  }

  if (sqlite3_step(pstmt_p) != SQLITE_DONE) {
    err_msg = "Failed to execute statement";
    ret_val = -3;
    goto cleanup;
  }

  if (sqlite3_changes(db_p) != 1) {
    err_msg = "Failed to insert";
    ret_val = -3;
    goto cleanup;
  }

cleanup:
  if (pubkey_buf_p) {
    signal_buffer_bzero_free(pubkey_buf_p);
  }
  if (privkey_buf_p) {
    signal_buffer_bzero_free(privkey_buf_p);
  }
  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}


int axc_db_identity_get_key_pair(signal_buffer ** public_data, signal_buffer ** private_data, void * user_data) {
  const char stmt[] = "SELECT * FROM " IDENTITY_KEY_STORE_TABLE_NAME " WHERE " IDENTITY_KEY_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  char * err_msg = (void *) 0;
  int ret_val = 0;
  signal_buffer * pubkey_buf_p = (void *) 0;
  signal_buffer * privkey_buf_p = (void *) 0;

  // public key
  if (sqlite3_bind_text(pstmt_p, 1, OWN_PUBLIC_KEY_NAME, -1, SQLITE_STATIC)) {
    err_msg = "Failed to bind public key name when trying to get the identity key pair";
    ret_val = -21;
    goto cleanup;
  }

  size_t pubkey_len = 0;
  int step_result = sqlite3_step(pstmt_p);
  if (step_result == SQLITE_DONE) {
    // public key not found
    err_msg = "Own public key not found";
    ret_val = SG_ERR_INVALID_KEY_ID;
    goto cleanup;
  } else if (step_result == SQLITE_ROW) {
    pubkey_len = sqlite3_column_int(pstmt_p, 2);
    pubkey_buf_p = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), pubkey_len);

    if (pubkey_buf_p == 0) {
      err_msg = "Buffer could not be initialised";
      ret_val = -3;
      goto cleanup;
    }
  } else {
    err_msg = "Failed executing SQL statement";
    ret_val = -3;
    goto cleanup;
  }

  sqlite3_reset(pstmt_p);
  sqlite3_clear_bindings(pstmt_p);

  // private key
  if (sqlite3_bind_text(pstmt_p, 1, OWN_PRIVATE_KEY_NAME, -1, SQLITE_STATIC)) {
    err_msg = "Failed to bind private key name when trying to get the identity key pair";
    ret_val = -21;
    goto cleanup;
  }

  size_t privkey_len = 0;
  step_result = sqlite3_step(pstmt_p);
  if (step_result == SQLITE_DONE) {
    // private key not found
    err_msg = "Own private key not found";
    ret_val = SG_ERR_INVALID_KEY_ID;
    goto cleanup;
  } else if (step_result == SQLITE_ROW) {
    privkey_len = sqlite3_column_int(pstmt_p, 2);
    privkey_buf_p = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), privkey_len);

    if (privkey_buf_p == 0) {
      err_msg = "Buffer could not be initialised";
      ret_val = -3;
      goto cleanup;
    }
  } else {
    err_msg = "Failed executing SQL statement";
    ret_val = -3;
    goto cleanup;
  }

  *public_data = pubkey_buf_p;
  *private_data = privkey_buf_p;

cleanup:
  if (ret_val < 0) {
    if (pubkey_buf_p) {
      signal_buffer_bzero_free(pubkey_buf_p);
    }
    if (privkey_buf_p) {
      signal_buffer_bzero_free(privkey_buf_p);
    }
  }
  db_conn_cleanup(db_p, pstmt_p, err_msg, __func__, axc_ctx_p);
  return ret_val;
}

int axc_db_identity_set_local_registration_id(const uint32_t reg_id, axc_context * axc_ctx_p) {
  return (axc_db_property_set(REG_ID_NAME, reg_id, axc_ctx_p)) ? -1 : 0;
}

int axc_db_identity_get_local_registration_id(void * user_data, uint32_t * registration_id) {
  const char stmt[] = "SELECT * FROM " SETTINGS_STORE_TABLE_NAME " WHERE " SETTINGS_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, REG_ID_NAME, -1, SQLITE_STATIC)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  const int step_result = sqlite3_step(pstmt_p);

  if (step_result == SQLITE_DONE) {
    // registration ID not found
    db_conn_cleanup(db_p, pstmt_p, "Own registration ID not found", __func__, axc_ctx_p);
    return -31;
  } else if (step_result == SQLITE_ROW) {
    *registration_id = sqlite3_column_int(pstmt_p, 1);
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -32;
  }

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_identity_save(const signal_protocol_address * addr_p, uint8_t * key_data, size_t key_len, void * user_data) {
  // 1 - name ("public" or "private" for own keys, name for contacts)
  // 2 - key blob
  // 3 - length of the key
  // 4 - trusted (1 for true, 0 for false)
  char save_stmt[] = "INSERT OR REPLACE INTO " IDENTITY_KEY_STORE_TABLE_NAME " VALUES (?1, ?2, ?3, ?4);";
  char del_stmt[] = "DELETE FROM " IDENTITY_KEY_STORE_TABLE_NAME " WHERE " IDENTITY_KEY_STORE_NAME_NAME " IS ?1;";
  char * stmt = (void *) 0;

  if (key_data) {
    stmt = save_stmt;
  } else {
    stmt = del_stmt;
  }

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, addr_p->name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  if (key_data) {
    if (sqlite3_bind_blob(pstmt_p, 2, key_data, key_len, SQLITE_TRANSIENT)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -22;
    }
    if(sqlite3_bind_int(pstmt_p, 3, key_len)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -23;
    }
    if(sqlite3_bind_int(pstmt_p, 4, IDENTITY_KEY_TRUSTED)) {
      db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
      return -24;
    }
  }

  if (db_exec_single_change(db_p, pstmt_p, axc_ctx_p)) return -3;

  db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
  return 0;
}

int axc_db_identity_is_trusted(const char * name, size_t name_len, uint8_t * key_data, size_t key_len, void * user_data) {
  const char stmt[] = "SELECT * FROM " IDENTITY_KEY_STORE_TABLE_NAME " WHERE " IDENTITY_KEY_STORE_NAME_NAME " IS ?1;";

  axc_context * axc_ctx_p = (axc_context *) user_data;
  sqlite3 * db_p = (void *) 0;
  sqlite3_stmt * pstmt_p = (void *) 0;
  signal_buffer * key_record = (void *) 0;
  int step_result = 0;
  size_t record_len = 0;

  if (db_conn_open(&db_p, &pstmt_p, stmt, user_data)) return -1;

  if (sqlite3_bind_text(pstmt_p, 1, name, -1, SQLITE_TRANSIENT)) {
    db_conn_cleanup(db_p, pstmt_p, "Failed to bind", __func__, axc_ctx_p);
    return -21;
  }

  step_result = sqlite3_step(pstmt_p);
  if (step_result == SQLITE_DONE) {
    // no entry = trusted, according to docs
    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    return 1;
  } else if (step_result == SQLITE_ROW) {
    // theoretically could be checked if trusted or not but it's TOFU

    record_len = sqlite3_column_int(pstmt_p, 2);
    if (record_len != key_len) {
      db_conn_cleanup(db_p, pstmt_p, "Key length does not match", __func__, axc_ctx_p);
      return 0;
    }

    key_record = signal_buffer_create(sqlite3_column_blob(pstmt_p, 1), record_len);
    if (key_record == 0) {
      db_conn_cleanup(db_p, pstmt_p, "Buffer could not be initialised", __func__, axc_ctx_p);
      return -3;
    }

    if (memcmp(key_data, signal_buffer_data(key_record), key_len)) {
      db_conn_cleanup(db_p, pstmt_p, "Key data does not match", __func__, axc_ctx_p);
    }

    db_conn_cleanup(db_p, pstmt_p, (void *) 0, __func__, axc_ctx_p);
    signal_buffer_bzero_free(key_record);
    return 1;
  } else {
    db_conn_cleanup(db_p, pstmt_p, "Failed executing SQL statement", __func__, axc_ctx_p);
    return -32;
  }

  (void)name_len;
}

int axc_db_identity_always_trusted(const signal_protocol_address * addr_p, uint8_t * key_data, size_t key_len, void * user_data) {
  (void) addr_p;
  (void) key_data;
  (void) key_len;
  (void) user_data;

  return 1;
}

void axc_db_identity_destroy_ctx(void * user_data) {
  (void) user_data;
  //const char stmt[] = "DELETE FROM identity_key_store; VACUUM;";

  //db_exec_quick(stmt, user_data);
}
