#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <ncrypt.h>
#include <unknwn.h>
#include <webauthn.h>
#include <webauthnplugin.h>
#include <pluginauthenticator.h>

#include "passkey_plugin.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

constexpr GUID kPluginClsid{
    0x6f29d3c5,
    0x8a13,
    0x4d6f,
    {0x9c, 0x3a, 0x2b, 0x7e, 0x41, 0xa5, 0x90, 0xd2}};
constexpr GUID kPluginInterfaceId{
    0xd26bcf6f,
    0xb54c,
    0x43ff,
    {0x9f, 0x06, 0xd5, 0xbf, 0x14, 0x86, 0x25, 0xf7}};

constexpr wchar_t kPluginName[] = L"VaultKern";
constexpr wchar_t kPluginRpId[] = L"vaultkern.app";
constexpr wchar_t kHelloDisplayHint[] = L"Verify this VaultKern passkey operation";

struct CachedCredential {
    std::vector<BYTE> credential_id;
    std::wstring rp_id;
    std::wstring rp_name;
    std::vector<BYTE> user_id;
    std::wstring user_name;
    std::wstring user_display_name;
};

std::mutex g_credential_cache_mutex;
std::mutex g_credential_metadata_mutex;
std::vector<CachedCredential> g_credential_cache;

void CacheCredential(
    const BYTE* credential_id,
    DWORD credential_id_size,
    PCWSTR rp_id,
    PCWSTR rp_name,
    const BYTE* user_id,
    DWORD user_id_size,
    PCWSTR user_name,
    PCWSTR user_display_name) {
    CachedCredential cached{
        {credential_id, credential_id + credential_id_size},
        rp_id,
        rp_name,
        {user_id, user_id + user_id_size},
        user_name,
        user_display_name};
    std::lock_guard<std::mutex> lock(g_credential_cache_mutex);
    g_credential_cache.erase(
        std::remove_if(
            g_credential_cache.begin(),
            g_credential_cache.end(),
            [&cached](const CachedCredential& credential) {
                return credential.credential_id == cached.credential_id ||
                    (credential.rp_id == cached.rp_id &&
                     credential.user_id == cached.user_id);
            }),
        g_credential_cache.end());
    g_credential_cache.push_back(std::move(cached));
}

std::vector<CachedCredential> SupersededCredentials(
    const BYTE* credential_id,
    DWORD credential_id_size,
    PCWSTR rp_id,
    const BYTE* user_id,
    DWORD user_id_size) {
    std::vector<BYTE> next_credential_id(
        credential_id,
        credential_id + credential_id_size);
    std::vector<BYTE> account_user_id(user_id, user_id + user_id_size);
    std::vector<CachedCredential> superseded;
    std::lock_guard<std::mutex> lock(g_credential_cache_mutex);
    for (const auto& credential : g_credential_cache) {
        if (credential.rp_id == rp_id &&
            credential.user_id == account_user_id &&
            credential.credential_id != next_credential_id) {
            superseded.push_back(credential);
        }
    }
    return superseded;
}

WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS NativeCredential(
    const CachedCredential& credential) noexcept {
    return {
        static_cast<DWORD>(credential.credential_id.size()),
        credential.credential_id.data(),
        credential.rp_id.c_str(),
        credential.rp_name.c_str(),
        static_cast<DWORD>(credential.user_id.size()),
        credential.user_id.data(),
        credential.user_name.c_str(),
        credential.user_display_name.c_str()};
}

void ReplaceCredentialCache(std::vector<CachedCredential> credentials) {
    std::lock_guard<std::mutex> lock(g_credential_cache_mutex);
    g_credential_cache = std::move(credentials);
}

struct SelectedCredential {
    std::vector<BYTE> credential_id;
    std::wstring user_name;
};

using CredentialChooser = HRESULT (*)(
    HWND,
    PCWSTR,
    const std::vector<CachedCredential>&,
    size_t&);

HRESULT ChooseCredentialWithTaskDialog(
    HWND parent,
    PCWSTR rp_id,
    const std::vector<CachedCredential>& credentials,
    size_t& selected_index) {
    constexpr int kFirstCredentialButton = 1000;
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    if (!InitCommonControlsEx(&controls)) {
        const DWORD error = GetLastError();
        return error == ERROR_SUCCESS ? E_FAIL : HRESULT_FROM_WIN32(error);
    }

    std::vector<std::wstring> labels;
    labels.reserve(credentials.size());
    for (const auto& credential : credentials) {
        std::wstring label = credential.user_display_name.empty()
            ? credential.user_name
            : credential.user_display_name;
        if (!credential.user_name.empty() && label != credential.user_name) {
            label.append(L"\n");
            label.append(credential.user_name);
        }
        labels.push_back(std::move(label));
    }

    std::vector<TASKDIALOG_BUTTON> buttons;
    buttons.reserve(labels.size());
    for (size_t index = 0; index < labels.size(); ++index) {
        buttons.push_back({
            kFirstCredentialButton + static_cast<int>(index),
            labels[index].c_str()});
    }

    TASKDIALOGCONFIG config{};
    config.cbSize = sizeof(config);
    config.hwndParent = parent;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION |
        TDF_POSITION_RELATIVE_TO_WINDOW |
        TDF_USE_COMMAND_LINKS;
    config.dwCommonButtons = TDCBF_CANCEL_BUTTON;
    config.pszWindowTitle = L"VaultKern";
    config.pszMainInstruction = L"Choose a passkey account";
    config.pszContent = rp_id;
    config.cButtons = static_cast<UINT>(buttons.size());
    config.pButtons = buttons.data();
    config.nDefaultButton = kFirstCredentialButton;

    int selected_button = 0;
    const HRESULT result = TaskDialogIndirect(
        &config,
        &selected_button,
        nullptr,
        nullptr);
    if (FAILED(result)) {
        return result;
    }
    if (selected_button == IDCANCEL) {
        return NTE_USER_CANCELLED;
    }
    const int selected_offset = selected_button - kFirstCredentialButton;
    if (selected_offset < 0 ||
        static_cast<size_t>(selected_offset) >= credentials.size()) {
        return E_FAIL;
    }
    selected_index = static_cast<size_t>(selected_offset);
    return S_OK;
}

HRESULT SelectCredential(
    HWND parent,
    PCWSTR rp_id,
    const std::vector<VkBytes>& allowed,
    SelectedCredential& selected,
    CredentialChooser chooser = ChooseCredentialWithTaskDialog) noexcept {
    try {
        std::vector<CachedCredential> candidates;
        {
            std::lock_guard<std::mutex> lock(g_credential_cache_mutex);
            for (const auto& credential : g_credential_cache) {
                if (credential.rp_id != rp_id) {
                    continue;
                }
                bool is_allowed = allowed.empty();
                for (const auto& candidate : allowed) {
                    if (candidate.len == credential.credential_id.size() &&
                        candidate.data &&
                        memcmp(
                            candidate.data,
                            credential.credential_id.data(),
                            candidate.len) == 0) {
                        is_allowed = true;
                        break;
                    }
                }
                if (is_allowed && !credential.user_name.empty()) {
                    candidates.push_back(credential);
                }
            }
        }
        if (candidates.empty()) {
            return NTE_NOT_FOUND;
        }

        size_t selected_index = 0;
        if (candidates.size() > 1) {
            if (!chooser) {
                return E_INVALIDARG;
            }
            const HRESULT result = chooser(parent, rp_id, candidates, selected_index);
            if (FAILED(result)) {
                return result;
            }
        }
        if (selected_index >= candidates.size()) {
            return E_FAIL;
        }
        const auto& credential = candidates[selected_index];
        selected.credential_id = credential.credential_id;
        selected.user_name = credential.user_name;
        return S_OK;
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_FAIL;
    }
}

void Trace(const char* operation, const char* stage, HRESULT status) noexcept {
#ifdef VAULTKERN_PLUGIN_DIAGNOSTICS
    char line[384]{};
    int length = snprintf(
        line,
        sizeof(line),
        "%llu pid=%lu operation=%s stage=%s hr=0x%08lx\r\n",
        GetTickCount64(),
        GetCurrentProcessId(),
        operation,
        stage,
        static_cast<unsigned long>(status));
    if (length <= 0) {
        return;
    }
    OutputDebugStringA(line);
    wchar_t path[MAX_PATH]{};
    DWORD path_length = GetTempPathW(ARRAYSIZE(path), path);
    if (path_length == 0 || path_length >= ARRAYSIZE(path) ||
        wcscat_s(path, L"vaultkern-passkey-debug.log") != 0) {
        return;
    }
    HANDLE file = CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    WriteFile(file, line, static_cast<DWORD>(length), &written, nullptr);
    CloseHandle(file);
#else
    (void)operation;
    (void)stage;
    (void)status;
#endif
}

HMODULE WebAuthnModule() noexcept {
    static HMODULE module =
        LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    return module;
}

template <typename Function>
Function WebAuthnFunction(const char* name) noexcept {
    HMODULE module = WebAuthnModule();
    if (!module) {
        return nullptr;
    }
    return reinterpret_cast<Function>(GetProcAddress(module, name));
}

HRESULT Sha256(const BYTE* data, DWORD size, std::vector<BYTE>& digest) noexcept {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::vector<BYTE> object;
    DWORD object_size = 0;
    DWORD digest_size = 0;
    DWORD read = 0;
    NTSTATUS status =
        BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }
    status = BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<BYTE*>(&object_size),
        sizeof(object_size),
        &read,
        0);
    if (status >= 0) {
        status = BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<BYTE*>(&digest_size),
            sizeof(digest_size),
            &read,
            0);
    }
    if (status >= 0) {
        try {
            object.resize(object_size);
            digest.resize(digest_size);
        } catch (...) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return E_OUTOFMEMORY;
        }
        status = BCryptCreateHash(
            algorithm,
            &hash,
            object.empty() ? nullptr : object.data(),
            static_cast<ULONG>(object.size()),
            nullptr,
            0,
            0);
    }
    if (status >= 0 && size != 0) {
        status = BCryptHashData(hash, const_cast<BYTE*>(data), size, 0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, digest.data(), digest_size, 0);
    }
    if (hash) {
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return status < 0 ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT VerifySignedBuffer(
    const BYTE* data,
    DWORD data_size,
    const BYTE* public_key,
    DWORD public_key_size,
    const BYTE* signature,
    DWORD signature_size) noexcept {
    if ((!data && data_size != 0) || !public_key || public_key_size < sizeof(BCRYPT_KEY_BLOB) ||
        !signature || signature_size == 0) {
        return E_INVALIDARG;
    }

    std::vector<BYTE> digest;
    HRESULT result = Sha256(data, data_size, digest);
    if (FAILED(result)) {
        return result;
    }

    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&provider, nullptr, 0);
    if (status == ERROR_SUCCESS) {
        status = NCryptImportKey(
            provider,
            0,
            BCRYPT_PUBLIC_KEY_BLOB,
            nullptr,
            &key,
            const_cast<BYTE*>(public_key),
            public_key_size,
            0);
    }

    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    void* padding_info = nullptr;
    DWORD flags = 0;
    if (status == ERROR_SUCCESS) {
        const auto* header = reinterpret_cast<const BCRYPT_KEY_BLOB*>(public_key);
        if (header->Magic == BCRYPT_RSAPUBLIC_MAGIC) {
            padding_info = &padding;
            flags = BCRYPT_PAD_PKCS1;
        }
        status = NCryptVerifySignature(
            key,
            padding_info,
            digest.data(),
            static_cast<DWORD>(digest.size()),
            const_cast<BYTE*>(signature),
            signature_size,
            flags);
    }
    if (key) {
        NCryptFreeObject(key);
    }
    if (provider) {
        NCryptFreeObject(provider);
    }
    return static_cast<HRESULT>(status);
}

HRESULT VerifyPlatformRequest(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request) noexcept {
    if (!request || request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR ||
        !request->pbEncodedRequest || request->cbEncodedRequest == 0 ||
        !request->pbRequestSignature || request->cbRequestSignature == 0) {
        return E_INVALIDARG;
    }
    using GetKey = HRESULT(WINAPI*)(REFCLSID, DWORD*, PBYTE*);
    using FreeKey = void(WINAPI*)(PBYTE);
    auto get_key =
        WebAuthnFunction<GetKey>("WebAuthNPluginGetOperationSigningPublicKey");
    auto free_key =
        WebAuthnFunction<FreeKey>("WebAuthNPluginFreePublicKeyResponse");
    if (!get_key || !free_key) {
        return E_NOTIMPL;
    }
    DWORD public_key_size = 0;
    PBYTE public_key = nullptr;
    HRESULT result = get_key(kPluginClsid, &public_key_size, &public_key);
    if (SUCCEEDED(result)) {
        result = VerifySignedBuffer(
            request->pbEncodedRequest,
            request->cbEncodedRequest,
            public_key,
            public_key_size,
            request->pbRequestSignature,
            request->cbRequestSignature);
    }
    if (public_key) {
        free_key(public_key);
    }
    return result;
}

HRESULT PerformHelloVerification(
    PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
    PCWSTR username) noexcept {
    using GetKey = HRESULT(WINAPI*)(REFCLSID, DWORD*, PBYTE*);
    using FreeKey = void(WINAPI*)(PBYTE);
    using Perform = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST,
        DWORD*,
        PBYTE*);
    using FreeResponse = void(WINAPI*)(PBYTE);

    auto get_key =
        WebAuthnFunction<GetKey>("WebAuthNPluginGetUserVerificationPublicKey");
    auto free_key =
        WebAuthnFunction<FreeKey>("WebAuthNPluginFreePublicKeyResponse");
    auto perform =
        WebAuthnFunction<Perform>("WebAuthNPluginPerformUserVerification");
    auto free_response =
        WebAuthnFunction<FreeResponse>("WebAuthNPluginFreeUserVerificationResponse");
    if (!get_key || !free_key || !perform || !free_response) {
        return E_NOTIMPL;
    }

    DWORD public_key_size = 0;
    PBYTE public_key = nullptr;
    HRESULT result = get_key(kPluginClsid, &public_key_size, &public_key);
    if (FAILED(result)) {
        return result;
    }

    WEBAUTHN_PLUGIN_USER_VERIFICATION_REQUEST verification{
        request->hWnd,
        request->transactionId,
        username,
        kHelloDisplayHint};
    DWORD response_size = 0;
    PBYTE response = nullptr;
    result = perform(&verification, &response_size, &response);
    if (SUCCEEDED(result)) {
        result = VerifySignedBuffer(
            request->pbEncodedRequest,
            request->cbEncodedRequest,
            public_key,
            public_key_size,
            response,
            response_size);
    }
    if (response) {
        free_response(response);
    }
    free_key(public_key);
    return result;
}

class RustBytes final {
public:
    RustBytes(const VkPluginCallbacks& callbacks, VkOwnedBytes bytes) noexcept
        : callbacks_(callbacks), bytes_(bytes) {}
    RustBytes(const RustBytes&) = delete;
    RustBytes& operator=(const RustBytes&) = delete;
    ~RustBytes() {
        if (bytes_.data) {
            callbacks_.free_bytes(callbacks_.context, bytes_);
        }
    }
    BYTE* data() const noexcept { return bytes_.data; }
    DWORD size() const noexcept { return bytes_.len; }

private:
    VkPluginCallbacks callbacks_;
    VkOwnedBytes bytes_;
};

class PluginOperation final {
public:
    PluginOperation(const VkPluginCallbacks& callbacks, const GUID& transaction_id) noexcept
        : callbacks_(callbacks), transaction_id_(transaction_id) {
        status_ = callbacks_.begin_operation(callbacks_.context, TransactionBytes());
        active_ = SUCCEEDED(status_);
    }
    PluginOperation(const PluginOperation&) = delete;
    PluginOperation& operator=(const PluginOperation&) = delete;
    ~PluginOperation() {
        if (active_) {
            callbacks_.end_operation(callbacks_.context, TransactionBytes());
        }
    }

    HRESULT status() const noexcept { return status_; }

    HRESULT CheckCancelled() const noexcept {
        if (!active_) {
            return status_;
        }
        return callbacks_.is_operation_cancelled(callbacks_.context, TransactionBytes())
            ? NTE_USER_CANCELLED
            : S_OK;
    }

private:
    VkBytes TransactionBytes() const noexcept {
        return {
            reinterpret_cast<const uint8_t*>(&transaction_id_),
            static_cast<uint32_t>(sizeof(transaction_id_))};
    }

    VkPluginCallbacks callbacks_;
    GUID transaction_id_{};
    HRESULT status_{E_FAIL};
    bool active_{false};
};

HRESULT AddCredentialMetadata(
    const VkOwnedBytes& credential_id,
    PCWSTR rp_id,
    PCWSTR rp_name,
    const BYTE* user_id,
    DWORD user_id_size,
    PCWSTR user_name,
    PCWSTR user_display_name) noexcept {
    using AddCredentials = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD,
        PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    using RemoveCredentials = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD,
        PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    auto add =
        WebAuthnFunction<AddCredentials>("WebAuthNPluginAuthenticatorAddCredentials");
    auto remove = WebAuthnFunction<RemoveCredentials>(
        "WebAuthNPluginAuthenticatorRemoveCredentials");
    if (!add || !remove) {
        return E_NOTIMPL;
    }
    std::lock_guard<std::mutex> metadata_lock(g_credential_metadata_mutex);
    std::vector<CachedCredential> superseded;
    std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> superseded_details;
    try {
        superseded = SupersededCredentials(
            credential_id.data,
            credential_id.len,
            rp_id,
            user_id,
            user_id_size);
        superseded_details.reserve(superseded.size());
        for (const auto& credential : superseded) {
            superseded_details.push_back(NativeCredential(credential));
        }
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_FAIL;
    }
    if (!superseded_details.empty()) {
        const HRESULT remove_result = remove(
            kPluginClsid,
            static_cast<DWORD>(superseded_details.size()),
            superseded_details.data());
        if (FAILED(remove_result)) {
            return remove_result;
        }
    }
    WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS details{
        credential_id.len,
        credential_id.data,
        rp_id,
        rp_name ? rp_name : rp_id,
        user_id_size,
        user_id,
        user_name,
        user_display_name ? user_display_name : user_name};
    HRESULT result = add(kPluginClsid, 1, &details);
    if (SUCCEEDED(result)) {
        try {
            CacheCredential(
                credential_id.data,
                credential_id.len,
                rp_id,
                rp_name ? rp_name : rp_id,
                user_id,
                user_id_size,
                user_name,
                user_display_name ? user_display_name : user_name);
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_FAIL;
        }
    }
    return result;
}

class PluginAuthenticator final : public IPluginAuthenticator {
public:
    explicit PluginAuthenticator(const VkPluginCallbacks& callbacks) noexcept
        : callbacks_(callbacks) {
        callbacks_.retain_context(callbacks_.context);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) noexcept override {
        if (!result) {
            return E_POINTER;
        }
        *result = nullptr;
        if (IsEqualIID(iid, __uuidof(IUnknown)) ||
            IsEqualIID(iid, kPluginInterfaceId)) {
            *result = static_cast<IPluginAuthenticator*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override {
        return ++references_;
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override {
        ULONG remaining = --references_;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE MakeCredential(
        PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
        Trace("make", "entry", S_OK);
        if (!request || !response) {
            return E_INVALIDARG;
        }
        *response = {};
        HRESULT result = VerifyPlatformRequest(request);
        Trace("make", "verify-platform-request", result);
        if (FAILED(result)) {
            return result;
        }
        if (!callbacks_.is_unlocked(callbacks_.context)) {
            return NTE_NOT_FOUND;
        }
        PluginOperation operation(callbacks_, request->transactionId);
        if (FAILED(operation.status())) {
            return operation.status();
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        using Decode = HRESULT(WINAPI*)(
            DWORD,
            const BYTE*,
            PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST*);
        using FreeDecoded = void(WINAPI*)(PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST);
        using Encode = HRESULT(WINAPI*)(
            PCWEBAUTHN_CREDENTIAL_ATTESTATION,
            DWORD*,
            BYTE**);
        auto decode =
            WebAuthnFunction<Decode>("WebAuthNDecodeMakeCredentialRequest");
        auto free_decoded =
            WebAuthnFunction<FreeDecoded>("WebAuthNFreeDecodedMakeCredentialRequest");
        auto encode =
            WebAuthnFunction<Encode>("WebAuthNEncodeMakeCredentialResponse");
        if (!decode || !free_decoded || !encode) {
            return E_NOTIMPL;
        }

        PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST decoded = nullptr;
        result = decode(
            request->cbEncodedRequest,
            request->pbEncodedRequest,
            &decoded);
        Trace("make", "decode", result);
        if (FAILED(result)) {
            return result;
        }
        std::unique_ptr<
            WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST,
            decltype(free_decoded)>
            decoded_guard(decoded, free_decoded);
        if (!decoded->pRpInformation || !decoded->pUserInformation ||
            !decoded->pRpInformation->pwszId ||
            !decoded->pUserInformation->pwszName ||
            !decoded->pUserInformation->pbId ||
            decoded->pUserInformation->cbId == 0) {
            return E_INVALIDARG;
        }

        LONG algorithm = 0;
        for (DWORD index = 0;
             index < decoded->WebAuthNCredentialParameters.cCredentialParameters;
             ++index) {
            auto* parameter =
                &decoded->WebAuthNCredentialParameters.pCredentialParameters[index];
            if (parameter->lAlg == WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256) {
                algorithm = parameter->lAlg;
                break;
            }
        }
        if (algorithm == 0) {
            return NTE_NOT_SUPPORTED;
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        result = PerformHelloVerification(
            request,
            decoded->pUserInformation->pwszName);
        Trace("make", "hello-uv", result);
        if (FAILED(result)) {
            return result;
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        try {
            std::vector<VkBytes> excluded;
            excluded.reserve(decoded->CredentialList.cCredentials);
            for (DWORD index = 0; index < decoded->CredentialList.cCredentials; ++index) {
                const auto* credential = decoded->CredentialList.ppCredentials[index];
                if (credential && credential->pbId && credential->cbId != 0) {
                    excluded.push_back({credential->pbId, credential->cbId});
                }
            }
            VkMakeCredentialInput input{
                reinterpret_cast<const uint16_t*>(decoded->pRpInformation->pwszId),
                reinterpret_cast<const uint16_t*>(
                    decoded->pRpInformation->pwszName
                        ? decoded->pRpInformation->pwszName
                        : decoded->pRpInformation->pwszId),
                reinterpret_cast<const uint16_t*>(decoded->pUserInformation->pwszName),
                reinterpret_cast<const uint16_t*>(
                    decoded->pUserInformation->pwszDisplayName
                        ? decoded->pUserInformation->pwszDisplayName
                        : decoded->pUserInformation->pwszName),
                {decoded->pUserInformation->pbId, decoded->pUserInformation->cbId},
                algorithm,
                excluded.empty() ? nullptr : excluded.data(),
                static_cast<uint32_t>(excluded.size())};
            VkMakeCredentialOutput output{};
            if (FAILED(result = operation.CheckCancelled())) {
                return result;
            }
            result = callbacks_.make_credential(callbacks_.context, &input, &output);
            Trace("make", "rust-callback", result);
            if (FAILED(result)) {
                return result;
            }
            RustBytes credential_id(callbacks_, output.credential_id);
            RustBytes authenticator_data(callbacks_, output.authenticator_data);
            // The Rust callback is the durable registration commit point. A
            // cancellation observed after it returns cannot roll that commit
            // back, so complete the ceremony instead of reporting a failure
            // for a credential that now exists in the vault.
            if (!credential_id.data() || credential_id.size() == 0 ||
                !authenticator_data.data() || authenticator_data.size() == 0) {
                return E_FAIL;
            }

            WEBAUTHN_CREDENTIAL_ATTESTATION attestation{};
            attestation.dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION;
            attestation.pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE;
            attestation.cbAuthenticatorData = authenticator_data.size();
            attestation.pbAuthenticatorData = authenticator_data.data();
            result = encode(
                &attestation,
                &response->cbEncodedResponse,
                &response->pbEncodedResponse);
            Trace("make", "encode", result);
            if (FAILED(result)) {
                return result;
            }

            // The durable KPEX save already succeeded. Cache population is recoverable
            // and is retried when the resident app next refreshes its unlocked vault.
            HRESULT cache_result = AddCredentialMetadata(
                output.credential_id,
                decoded->pRpInformation->pwszId,
                decoded->pRpInformation->pwszName,
                decoded->pUserInformation->pbId,
                decoded->pUserInformation->cbId,
                decoded->pUserInformation->pwszName,
                decoded->pUserInformation->pwszDisplayName);
            Trace("make", "credential-cache", cache_result);
            return S_OK;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_FAIL;
        }
    }

    HRESULT STDMETHODCALLTYPE GetAssertion(
        PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) noexcept override {
        Trace("get", "entry", S_OK);
        if (!request || !response) {
            return E_INVALIDARG;
        }
        *response = {};
        HRESULT result = VerifyPlatformRequest(request);
        Trace("get", "verify-platform-request", result);
        if (FAILED(result)) {
            return result;
        }
        if (!callbacks_.is_unlocked(callbacks_.context)) {
            return NTE_NOT_FOUND;
        }
        PluginOperation operation(callbacks_, request->transactionId);
        if (FAILED(operation.status())) {
            return operation.status();
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        using Decode = HRESULT(WINAPI*)(
            DWORD,
            const BYTE*,
            PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST*);
        using FreeDecoded = void(WINAPI*)(PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST);
        using Encode = HRESULT(WINAPI*)(
            PCWEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE,
            DWORD*,
            BYTE**);
        auto decode =
            WebAuthnFunction<Decode>("WebAuthNDecodeGetAssertionRequest");
        auto free_decoded =
            WebAuthnFunction<FreeDecoded>("WebAuthNFreeDecodedGetAssertionRequest");
        auto encode =
            WebAuthnFunction<Encode>("WebAuthNEncodeGetAssertionResponse");
        if (!decode || !free_decoded || !encode) {
            return E_NOTIMPL;
        }

        PWEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST decoded = nullptr;
        result = decode(
            request->cbEncodedRequest,
            request->pbEncodedRequest,
            &decoded);
        Trace("get", "decode", result);
        if (FAILED(result)) {
            return result;
        }
        std::unique_ptr<
            WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST,
            decltype(free_decoded)>
            decoded_guard(decoded, free_decoded);
        if (!decoded->pwszRpId || !decoded->pbClientDataHash ||
            decoded->cbClientDataHash != 32) {
            return E_INVALIDARG;
        }

        std::vector<VkBytes> allowed;
        try {
            allowed.reserve(decoded->CredentialList.cCredentials);
            for (DWORD index = 0; index < decoded->CredentialList.cCredentials; ++index) {
                const auto* credential = decoded->CredentialList.ppCredentials[index];
                if (credential && credential->pbId && credential->cbId != 0) {
                    allowed.push_back({credential->pbId, credential->cbId});
                }
            }
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        }
        SelectedCredential selected;
        result = SelectCredential(
            request->hWnd,
            decoded->pwszRpId,
            allowed,
            selected);
        Trace("get", "select-credential", result);
        if (FAILED(result)) {
            return result;
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        result = PerformHelloVerification(request, selected.user_name.c_str());
        Trace("get", "hello-uv", result);
        if (FAILED(result)) {
            return result;
        }
        if (FAILED(result = operation.CheckCancelled())) {
            return result;
        }

        try {
            VkBytes selected_credential{
                selected.credential_id.data(),
                static_cast<uint32_t>(selected.credential_id.size())};
            VkGetAssertionInput input{
                reinterpret_cast<const uint16_t*>(decoded->pwszRpId),
                &selected_credential,
                1,
                {decoded->pbClientDataHash, decoded->cbClientDataHash}};
            VkGetAssertionOutput output{};
            if (FAILED(result = operation.CheckCancelled())) {
                return result;
            }
            result = callbacks_.get_assertion(callbacks_.context, &input, &output);
            Trace("get", "rust-callback", result);
            if (FAILED(result)) {
                return result;
            }
            RustBytes credential_id(callbacks_, output.credential_id);
            RustBytes authenticator_data(callbacks_, output.authenticator_data);
            RustBytes signature(callbacks_, output.signature_der);
            RustBytes user_handle(callbacks_, output.user_handle);
            if (FAILED(result = operation.CheckCancelled())) {
                return result;
            }
            if (!credential_id.data() || credential_id.size() == 0 ||
                !authenticator_data.data() || authenticator_data.size() == 0 ||
                !signature.data() || signature.size() == 0 ||
                !user_handle.data() || user_handle.size() == 0) {
                return E_FAIL;
            }

            WEBAUTHN_ASSERTION assertion{};
            assertion.dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION;
            assertion.Credential.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
            assertion.Credential.cbId = credential_id.size();
            assertion.Credential.pbId = credential_id.data();
            assertion.Credential.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
            assertion.cbAuthenticatorData = authenticator_data.size();
            assertion.pbAuthenticatorData = authenticator_data.data();
            assertion.cbSignature = signature.size();
            assertion.pbSignature = signature.data();
            assertion.cbUserId = user_handle.size();
            assertion.pbUserId = user_handle.data();

            WEBAUTHN_USER_ENTITY_INFORMATION user{};
            user.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
            user.cbId = user_handle.size();
            user.pbId = user_handle.data();

            WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE ctap{};
            ctap.WebAuthNAssertion = assertion;
            ctap.pUserInformation = &user;
            ctap.dwNumberOfCredentials = 1;
            ctap.lUserSelected = 1;
            result = encode(
                &ctap,
                &response->cbEncodedResponse,
                &response->pbEncodedResponse);
            Trace("get", "encode", result);
            return result;
        } catch (const std::bad_alloc&) {
            return E_OUTOFMEMORY;
        } catch (...) {
            return E_FAIL;
        }
    }

    HRESULT STDMETHODCALLTYPE CancelOperation(
        PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) noexcept override {
        if (!request) {
            return E_INVALIDARG;
        }
        VkBytes transaction_id{
            reinterpret_cast<const uint8_t*>(&request->transactionId),
            static_cast<uint32_t>(sizeof(request->transactionId))};
        HRESULT result = callbacks_.cancel_operation(callbacks_.context, transaction_id);
        Trace("cancel", "transaction", result);
        return result;
    }

    HRESULT STDMETHODCALLTYPE GetLockStatus(
        PLUGIN_LOCK_STATUS* lock_status) noexcept override {
        if (!lock_status) {
            return E_INVALIDARG;
        }
        *lock_status =
            callbacks_.is_unlocked(callbacks_.context) ? PluginUnlocked : PluginLocked;
        return S_OK;
    }

private:
    ~PluginAuthenticator() {
        callbacks_.release_context(callbacks_.context);
    }
    std::atomic<ULONG> references_{1};
    VkPluginCallbacks callbacks_;
};

class PluginFactory final : public IClassFactory {
public:
    explicit PluginFactory(const VkPluginCallbacks& callbacks) noexcept
        : callbacks_(callbacks) {
        callbacks_.retain_context(callbacks_.context);
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** result) noexcept override {
        if (!result) {
            return E_POINTER;
        }
        *result = nullptr;
        if (IsEqualIID(iid, __uuidof(IUnknown)) ||
            IsEqualIID(iid, __uuidof(IClassFactory))) {
            *result = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override {
        return ++references_;
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override {
        ULONG remaining = --references_;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(
        IUnknown* outer,
        REFIID iid,
        void** result) noexcept override {
        if (outer) {
            return CLASS_E_NOAGGREGATION;
        }
        if (!result) {
            return E_POINTER;
        }
        *result = nullptr;
        auto* plugin = new (std::nothrow) PluginAuthenticator(callbacks_);
        if (!plugin) {
            return E_OUTOFMEMORY;
        }
        HRESULT status = plugin->QueryInterface(iid, result);
        plugin->Release();
        return status;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL) noexcept override {
        return S_OK;
    }

private:
    ~PluginFactory() {
        callbacks_.release_context(callbacks_.context);
    }
    std::atomic<ULONG> references_{1};
    VkPluginCallbacks callbacks_;
};

std::vector<BYTE> AuthenticatorInfo() {
    constexpr char hex[] =
        "A50182684649444F5F325F30684649444F5F325F310350"
        "C8B2F4A17D314E599A620FD3B6E4C721"
        "04A362726BF5627570F5627576F5"
        "098168696E7465726E616C"
        "0A81A263616C672664747970656A7075626C69632D6B6579";
    auto nibble = [](char value) -> BYTE {
        if (value >= '0' && value <= '9') {
            return static_cast<BYTE>(value - '0');
        }
        return static_cast<BYTE>(value - 'A' + 10);
    };
    std::vector<BYTE> bytes;
    bytes.reserve((sizeof(hex) - 1) / 2);
    for (size_t index = 0; index + 1 < sizeof(hex) - 1; index += 2) {
        bytes.push_back(static_cast<BYTE>((nibble(hex[index]) << 4) | nibble(hex[index + 1])));
    }
    return bytes;
}

}  // namespace

extern "C" int32_t VK_CALL vaultkern_plugin_start(
    const VkPluginCallbacks* callbacks,
    uint32_t* registration_cookie) {
    if (!callbacks || !registration_cookie || callbacks->version != 3 ||
        !callbacks->context || !callbacks->retain_context ||
        !callbacks->release_context || !callbacks->is_unlocked ||
        !callbacks->make_credential || !callbacks->get_assertion ||
        !callbacks->begin_operation || !callbacks->is_operation_cancelled ||
        !callbacks->cancel_operation || !callbacks->end_operation ||
        !callbacks->free_bytes) {
        return E_INVALIDARG;
    }
    *registration_cookie = 0;
    HRESULT apartment = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(apartment) && apartment != RPC_E_CHANGED_MODE) {
        return apartment;
    }
    auto* factory = new (std::nothrow) PluginFactory(*callbacks);
    if (!factory) {
        return E_OUTOFMEMORY;
    }
    DWORD cookie = 0;
    HRESULT result = CoRegisterClassObject(
        kPluginClsid,
        factory,
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &cookie);
    factory->Release();
    if (SUCCEEDED(result)) {
        *registration_cookie = cookie;
    }
    return result;
}

extern "C" int32_t VK_CALL vaultkern_plugin_stop(uint32_t registration_cookie) {
    if (registration_cookie == 0) {
        return S_OK;
    }
    return CoRevokeClassObject(registration_cookie);
}

extern "C" int32_t VK_CALL vaultkern_plugin_ensure_registered(
    int32_t* authenticator_state) {
    if (!authenticator_state) {
        return E_INVALIDARG;
    }
    *authenticator_state = AuthenticatorState_Disabled;
    using GetState = HRESULT(WINAPI*)(REFCLSID, AUTHENTICATOR_STATE*);
    using Add = HRESULT(WINAPI*)(
        PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS,
        PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE*);
    using FreeAdd = void(WINAPI*)(PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE);
    using Update = HRESULT(WINAPI*)(PCWEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS);
    auto get_state =
        WebAuthnFunction<GetState>("WebAuthNPluginGetAuthenticatorState");
    auto add = WebAuthnFunction<Add>("WebAuthNPluginAddAuthenticator");
    auto free_add =
        WebAuthnFunction<FreeAdd>("WebAuthNPluginFreeAddAuthenticatorResponse");
    auto update =
        WebAuthnFunction<Update>("WebAuthNPluginUpdateAuthenticatorDetails");
    if (!get_state || !add || !free_add) {
        return E_NOTIMPL;
    }

    AUTHENTICATOR_STATE state = AuthenticatorState_Disabled;
    HRESULT result = get_state(kPluginClsid, &state);
    std::vector<BYTE> info;
    try {
        info = AuthenticatorInfo();
    } catch (...) {
        return E_OUTOFMEMORY;
    }
    if (SUCCEEDED(result)) {
        if (update) {
            WEBAUTHN_PLUGIN_UPDATE_AUTHENTICATOR_DETAILS details{
                kPluginName,
                kPluginClsid,
                kPluginClsid,
                nullptr,
                nullptr,
                static_cast<DWORD>(info.size()),
                info.data(),
                0,
                nullptr};
            (void)update(&details);
        }
        *authenticator_state = state;
        return S_OK;
    }
    if (result != NTE_NOT_FOUND) {
        return result;
    }

    WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS options{
        kPluginName,
        kPluginClsid,
        kPluginRpId,
        nullptr,
        nullptr,
        static_cast<DWORD>(info.size()),
        info.data(),
        0,
        nullptr};
    PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE response = nullptr;
    result = add(&options, &response);
    if (response) {
        free_add(response);
    }
    if (SUCCEEDED(result)) {
        (void)get_state(kPluginClsid, &state);
        *authenticator_state = state;
    }
    return result;
}

extern "C" int32_t VK_CALL vaultkern_plugin_remove_registered(void) {
    using Remove = HRESULT(WINAPI*)(REFCLSID);
    auto remove = WebAuthnFunction<Remove>("WebAuthNPluginRemoveAuthenticator");
    if (!remove) {
        return E_NOTIMPL;
    }
    std::lock_guard<std::mutex> metadata_lock(g_credential_metadata_mutex);
    HRESULT result = remove(kPluginClsid);
    if (result == NTE_NOT_FOUND) {
        result = S_OK;
    }
    if (SUCCEEDED(result)) {
        ReplaceCredentialCache({});
    }
    return result;
}

extern "C" int32_t VK_CALL vaultkern_plugin_sync_credentials(
    const VkCredentialMetadata* credentials,
    uint32_t credential_count) {
    if (credential_count != 0 && !credentials) {
        return E_INVALIDARG;
    }
    using RemoveAll = HRESULT(WINAPI*)(REFCLSID);
    using Add = HRESULT(WINAPI*)(
        REFCLSID,
        DWORD,
        PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS);
    auto remove_all =
        WebAuthnFunction<RemoveAll>("WebAuthNPluginAuthenticatorRemoveAllCredentials");
    auto add =
        WebAuthnFunction<Add>("WebAuthNPluginAuthenticatorAddCredentials");
    if (!remove_all || !add) {
        return E_NOTIMPL;
    }
    std::lock_guard<std::mutex> metadata_lock(g_credential_metadata_mutex);
    HRESULT result = remove_all(kPluginClsid);
    if (FAILED(result)) {
        return result;
    }
    if (credential_count == 0) {
        ReplaceCredentialCache({});
        return S_OK;
    }
    try {
        std::vector<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS> details;
        std::vector<CachedCredential> cached;
        details.reserve(credential_count);
        cached.reserve(credential_count);
        for (uint32_t index = 0; index < credential_count; ++index) {
            const auto& credential = credentials[index];
            if (!credential.credential_id.data || credential.credential_id.len == 0 ||
                !credential.rp_id || !credential.rp_name ||
                !credential.user_handle.data || credential.user_handle.len == 0 ||
                !credential.user_name || !credential.user_display_name) {
                return E_INVALIDARG;
            }
            details.push_back({
                credential.credential_id.len,
                credential.credential_id.data,
                reinterpret_cast<PCWSTR>(credential.rp_id),
                reinterpret_cast<PCWSTR>(credential.rp_name),
                credential.user_handle.len,
                credential.user_handle.data,
                reinterpret_cast<PCWSTR>(credential.user_name),
                reinterpret_cast<PCWSTR>(credential.user_display_name)});
            cached.push_back({
                {credential.credential_id.data,
                 credential.credential_id.data + credential.credential_id.len},
                reinterpret_cast<PCWSTR>(credential.rp_id),
                reinterpret_cast<PCWSTR>(credential.rp_name),
                {credential.user_handle.data,
                 credential.user_handle.data + credential.user_handle.len},
                reinterpret_cast<PCWSTR>(credential.user_name),
                reinterpret_cast<PCWSTR>(credential.user_display_name)});
        }
        result = add(
            kPluginClsid,
            static_cast<DWORD>(details.size()),
            details.data());
        if (SUCCEEDED(result)) {
            ReplaceCredentialCache(std::move(cached));
        }
        return result;
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_FAIL;
    }
}

extern "C" int32_t VK_CALL
vaultkern_plugin_test_replaces_cached_account_credential(void) {
    const BYTE old_credential_id[]{0x01};
    const BYTE new_credential_id[]{0x02};
    const BYTE user_id[]{0x0a};
    ReplaceCredentialCache({});
    CacheCredential(
        old_credential_id,
        ARRAYSIZE(old_credential_id),
        L"example.com",
        L"Example",
        user_id,
        ARRAYSIZE(user_id),
        L"old-name",
        L"Old Name");
    CacheCredential(
        new_credential_id,
        ARRAYSIZE(new_credential_id),
        L"example.com",
        L"Example",
        user_id,
        ARRAYSIZE(user_id),
        L"new-name",
        L"New Name");
    SelectedCredential selected;
    const HRESULT result = SelectCredential(
        nullptr,
        L"example.com",
        {},
        selected);
    ReplaceCredentialCache({});
    if (FAILED(result)) {
        return result;
    }
    return selected.credential_id ==
            std::vector<BYTE>(new_credential_id, new_credential_id + ARRAYSIZE(new_credential_id))
        ? S_OK
        : E_FAIL;
}

extern "C" int32_t VK_CALL
vaultkern_plugin_test_can_select_second_matching_credential(void) {
    const BYTE first_credential_id[]{0x01};
    const BYTE second_credential_id[]{0x02};
    const BYTE first_user_id[]{0x0a};
    const BYTE second_user_id[]{0x0b};
    ReplaceCredentialCache({});
    CacheCredential(
        first_credential_id,
        ARRAYSIZE(first_credential_id),
        L"example.com",
        L"Example",
        first_user_id,
        ARRAYSIZE(first_user_id),
        L"first@example.com",
        L"First");
    CacheCredential(
        second_credential_id,
        ARRAYSIZE(second_credential_id),
        L"example.com",
        L"Example",
        second_user_id,
        ARRAYSIZE(second_user_id),
        L"second@example.com",
        L"Second");
    SelectedCredential selected;
    auto choose_second = [](
        HWND,
        PCWSTR,
        const std::vector<CachedCredential>& credentials,
        size_t& selected_index) -> HRESULT {
        if (credentials.size() < 2) {
            return E_FAIL;
        }
        selected_index = 1;
        return S_OK;
    };
    const HRESULT result = SelectCredential(
        nullptr,
        L"example.com",
        {},
        selected,
        choose_second);
    ReplaceCredentialCache({});
    if (FAILED(result)) {
        return result;
    }
    return selected.credential_id == std::vector<BYTE>(
            second_credential_id,
            second_credential_id + ARRAYSIZE(second_credential_id))
        ? S_OK
        : E_FAIL;
}
