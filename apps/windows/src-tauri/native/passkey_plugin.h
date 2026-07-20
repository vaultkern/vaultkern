#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VK_CALL __stdcall

typedef struct VkBytes {
    const uint8_t* data;
    uint32_t len;
} VkBytes;

typedef struct VkOwnedBytes {
    uint8_t* data;
    uint32_t len;
} VkOwnedBytes;

typedef struct VkMakeCredentialInput {
    const uint16_t* rp_id;
    const uint16_t* rp_name;
    const uint16_t* user_name;
    const uint16_t* user_display_name;
    VkBytes user_handle;
    int32_t public_key_algorithm;
    const VkBytes* excluded_credential_ids;
    uint32_t excluded_credential_count;
} VkMakeCredentialInput;

typedef struct VkMakeCredentialOutput {
    VkOwnedBytes credential_id;
    VkOwnedBytes authenticator_data;
} VkMakeCredentialOutput;

typedef struct VkGetAssertionInput {
    const uint16_t* rp_id;
    const VkBytes* allowed_credential_ids;
    uint32_t allowed_credential_count;
    VkBytes client_data_hash;
} VkGetAssertionInput;

typedef struct VkGetAssertionOutput {
    VkOwnedBytes credential_id;
    VkOwnedBytes authenticator_data;
    VkOwnedBytes signature_der;
    VkOwnedBytes user_handle;
} VkGetAssertionOutput;

typedef struct VkCredentialMetadata {
    VkBytes credential_id;
    const uint16_t* rp_id;
    const uint16_t* rp_name;
    VkBytes user_handle;
    const uint16_t* user_name;
    const uint16_t* user_display_name;
} VkCredentialMetadata;

typedef int32_t (VK_CALL *VkIsUnlockedCallback)(void* context);
typedef void (VK_CALL *VkRetainContextCallback)(void* context);
typedef void (VK_CALL *VkReleaseContextCallback)(void* context);
typedef int32_t (VK_CALL *VkMakeCredentialCallback)(
    void* context,
    const VkMakeCredentialInput* input,
    VkMakeCredentialOutput* output);
typedef int32_t (VK_CALL *VkGetAssertionCallback)(
    void* context,
    const VkGetAssertionInput* input,
    VkGetAssertionOutput* output);
typedef int32_t (VK_CALL *VkBeginOperationCallback)(void* context, VkBytes transaction_id);
typedef int32_t (VK_CALL *VkIsOperationCancelledCallback)(
    void* context,
    VkBytes transaction_id);
typedef int32_t (VK_CALL *VkCancelOperationCallback)(void* context, VkBytes transaction_id);
typedef void (VK_CALL *VkEndOperationCallback)(void* context, VkBytes transaction_id);
typedef void (VK_CALL *VkFreeBytesCallback)(void* context, VkOwnedBytes bytes);

typedef struct VkPluginCallbacks {
    uint32_t version;
    void* context;
    VkRetainContextCallback retain_context;
    VkReleaseContextCallback release_context;
    VkIsUnlockedCallback is_unlocked;
    VkMakeCredentialCallback make_credential;
    VkGetAssertionCallback get_assertion;
    VkBeginOperationCallback begin_operation;
    VkIsOperationCancelledCallback is_operation_cancelled;
    VkCancelOperationCallback cancel_operation;
    VkEndOperationCallback end_operation;
    VkFreeBytesCallback free_bytes;
} VkPluginCallbacks;

int32_t VK_CALL vaultkern_plugin_start(
    const VkPluginCallbacks* callbacks,
    uint32_t* registration_cookie);
int32_t VK_CALL vaultkern_plugin_stop(uint32_t registration_cookie);
int32_t VK_CALL vaultkern_plugin_ensure_registered(int32_t* authenticator_state);
int32_t VK_CALL vaultkern_plugin_remove_registered(void);
int32_t VK_CALL vaultkern_plugin_sync_credentials(
    const VkCredentialMetadata* credentials,
    uint32_t credential_count);

int32_t VK_CALL vaultkern_plugin_test_replaces_cached_account_credential(void);

#ifdef __cplusplus
}
#endif
