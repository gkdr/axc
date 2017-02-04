#pragma once

#include "axolotl.h"
#include "key_helper.h"

#include "axc.h"

// For docs see axolotl.h

#define AXC_DB_NOT_INITIALIZED (-1)
#define AXC_DB_NEEDS_ROLLBACK 0
#define AXC_DB_INITIALIZED 1

// session store
int axc_db_session_load(axolotl_buffer **record, const axolotl_address *address, void *user_data);
int axc_db_session_get_sub_device_sessions(axolotl_int_list **sessions, const char *name, size_t name_len, void *user_data);
int axc_db_session_store(const axolotl_address *address, uint8_t *record, size_t record_len, void *user_data);
int axc_db_session_contains(const axolotl_address *address, void *user_data);
int axc_db_session_delete(const axolotl_address *address, void *user_data);
int axc_db_session_delete_all(const char *name, size_t name_len, void *user_data);
void axc_db_session_destroy_store_ctx(void *user_data);

// pre key store
int axc_db_pre_key_load(axolotl_buffer **record, uint32_t pre_key_id, void *user_data);
int axc_db_pre_key_store(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int axc_db_pre_key_contains(uint32_t pre_key_id, void *user_data);
int axc_db_pre_key_remove(uint32_t pre_key_id, void *user_data);
void axc_db_pre_key_destroy_ctx(void *user_data);
/**
 * Stores a whole list of pre keys at once, inside a single transaction.
 *
 * @param pre_keys_head Pointer to the first element of the list.
 * @param user_data_p Optional. The user_data as received from the axolotl interface, will be used to set the database name.
 */
int axc_db_pre_key_store_list(axolotl_key_helper_pre_key_list_node * pre_keys_head, axc_context * ctx_p);

/**
 * Gets the specified number of pre keys for publishing, i.e. only their public part.
 *
 * @param amount Number of keys to retrieve.
 * @param ctx_p Pointer to the initialized axc context.
 * @param list_head_pp Will be set to the head of the list.
 * @return 0 on success, negative on error.
 */
int axc_db_pre_key_get_list(size_t amount, axc_context * ctx_p, axc_buf_list_item ** list_head_pp);

/**
 * Retrieves the highest existing pre key ID that is not the last resort key's ID.
 *
 * @param ctx_p Pointer to the axc context.
 * @param max_id_p Will be set to the highest ID that is not MAX_INT.
 * @return 0 on success, negative on error.
 */
int axc_db_pre_key_get_max_id(axc_context * ctx_p, uint32_t * max_id_p);

/**
 * Returns the count of pre keys saved in the database.
 * This includes the "last resort" key that is additionally generated at db init.
 *
 * @param ctx_p Pointer to the axc context.
 * @param count_p Will point to the number of pre keys.
 * @return 0 on success, negative on error.
 */
int axc_db_pre_key_get_count(axc_context * ctx_p, size_t * count_p);

// signed pre key store
int axc_db_signed_pre_key_load(axolotl_buffer **record, uint32_t signed_pre_key_id, void *user_data);
int axc_db_signed_pre_key_store(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);
int axc_db_signed_pre_key_contains(uint32_t signed_pre_key_id, void *user_data);
int axc_db_signed_pre_key_remove(uint32_t signed_pre_key_id, void *user_data);
void axc_db_signed_pre_key_destroy_ctx(void *user_data);

// identity key store
int axc_db_identity_get_key_pair(axolotl_buffer **public_data, axolotl_buffer **private_data, void *user_data);
int axc_db_identity_get_local_registration_id(void *user_data, uint32_t *registration_id);
int axc_db_identity_save(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);
int axc_db_identity_is_trusted(const char *name, size_t name_len, uint8_t *key_data, size_t key_len, void *user_data);
int axc_db_identity_always_trusted(const char * name, size_t name_len, uint8_t * key_data, size_t key_len, void * user_data);
void axc_db_identity_destroy_ctx(void *user_data);

// additional helper functions
/**
 * Saves the public and private key by using the api serialization calls, as this format (and not the higher-level key type) is needed by the getter.
 *
 * @param Pointer to the keypair as returned by axolotl_key_helper_generate_identity_key_pair
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_identity_set_key_pair(const ratchet_identity_key_pair * key_pair_p, axc_context * axc_ctx_p);

/**
 * Saves the axolotl registration ID which was obtained by a call to axolotl_key_helper_generate_registration_id().
 *
 * @param reg_id The ID.
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_identity_set_local_registration_id(const uint32_t reg_id, axc_context * axc_ctx_p);

// other
/**
 * Creates the necessary tables. Safe to call if they already exist.
 *
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_create(axc_context * axc_ctx_p);

/**
 * Drops all the tables so that the db can be reset.
 *
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_destroy(axc_context * axc_ctx_p);


/**
 * Sets the value of a property in the database's "settings" table.
 *
 * @param name The name of the property.
 * @param status The int value of the property.
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_property_set(const char * name, const int val, axc_context * axc_ctx_p);

/**
 * Gets a property from the settings table.
 *
 * @param name Name of the property
 * @param val_p Pointer to where the saved value should be stored.
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error, 1 if no sql error but no result
 */
int axc_db_property_get(const char * name, int * val_p, axc_context * axc_ctx_p);

/**
 * "Partial application" of db_set_property, setting the init status value.
 *
 * @param status AXC_DB_NOT INITIALIZED, AXC_DB_NEEDS_ROOLBACK, or AXC_DB_INITIALIZED
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error
 */
int axc_db_init_status_set(const int status, axc_context * axc_ctx_p);

/**
 * "Partial application" of db_get_property, getting the init status value.
 *
 * @param init_status_p The value behind this pointer will be set to the init status number.
 * @param axc_ctx_p Pointer to the axc context.
 * @return 0 on success, negative on error, 1 if no sql error but no result
 */
int axc_db_init_status_get(int * init_status_p, axc_context * axc_ctx_p);
