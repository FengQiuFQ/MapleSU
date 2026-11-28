#pragma once

#include "module_err_def.h"
#include "../../../ultra/authorization/request_protocol.h"

/* SDK-local constants mirror the private command31 seam without including
 * kernel-only provider headers; numeric values are not public ABI. */
#ifndef MAPLESU_EARLY_FIXED_OEM_MTK
#define MAPLESU_EARLY_FIXED_OEM_MTK 1u
#define MAPLESU_EARLY_FIXED_OEM_OPLUS_GUARD 2u
#define MAPLESU_EARLY_FIXED_OEM_OPLUS_INTE 3u
#define MAPLESU_EARLY_FIXED_ROOT_ENV 4u
#define MAPLESU_EARLY_FIXED_SELINUX_PREPARE 5u
#define MAPLESU_EARLY_FIXED_SELINUX_ENABLE 6u
#define MAPLESU_EARLY_FIXED_SELINUX_READ_STATUS 7u
#define MAPLESU_EARLY_FIXED_SELINUX_WRITE_SEQUENCE 8u
#define MAPLESU_EARLY_FIXED_MODE_MAX 3u
#define MAPLESU_EARLY_FIXED_EXPLOIT_MAX 31u
#endif

namespace kernel_module {
enum class RequestAuthMode : uint8_t { LegacyKey = 0, ManagerOwner = 1, EarlyHelper = 3 };
// New threads default to ManagerOwner. LegacyKey requires explicit selection
// and a real historical credential. Request failures never select another protocol. Selecting a mode grants nothing; the gateway
// authenticates every operation. No automatic downgrade or cross-thread change.
KModErr maplesu_request_set_auth_mode(RequestAuthMode mode);
// Compatibility only: explicit selection with the actual historical credential.
// Current-task request failures never call this entry automatically.
KModErr maplesu_request_select_legacy(const char* credential);
void maplesu_request_clear_legacy();
uint64_t maplesu_request_auth_state();
// Low two bits identify the authentication source, not its granted permissions.
// Exhaustion/invalid tags stay closed and never enter the Legacy Key boundary.
inline RequestAuthMode maplesu_request_auth_mode(uint64_t state) {
    return static_cast<RequestAuthMode>(state & 3);
}
inline bool maplesu_request_auth_usable(uint64_t state) {
    return state != 0 && state != UINT64_MAX && (state & 3) != 2;
}
inline bool maplesu_request_auth_legacy(uint64_t state) {
    return maplesu_request_auth_usable(state) && maplesu_request_auth_mode(state) == RequestAuthMode::LegacyKey;
}
inline bool maplesu_request_auth_manager(uint64_t state) {
    return maplesu_request_auth_usable(state) && maplesu_request_auth_mode(state) == RequestAuthMode::ManagerOwner;
}
inline bool maplesu_request_auth_helper(uint64_t state) {
    return maplesu_request_auth_usable(state) && maplesu_request_auth_mode(state) == RequestAuthMode::EarlyHelper;
}
inline bool maplesu_request_auth_authenticated(uint64_t state) {
    return maplesu_request_auth_manager(state) || maplesu_request_auth_helper(state);
}
// Historical name for the shared authenticated transport, not Manager identity.
inline bool maplesu_request_owner_mode() { return !maplesu_request_auth_legacy(maplesu_request_auth_state()); }
inline bool maplesu_request_manager_mode() { return maplesu_request_auth_manager(maplesu_request_auth_state()); }
inline bool maplesu_request_helper_mode() { return maplesu_request_auth_helper(maplesu_request_auth_state()); }

struct RequestOwnerBinding {
    uint64_t auth_state = 0;
    uint64_t process = 0;
    uint32_t full_uid = 0;
    uint32_t actual_uid = 0;
    uint32_t epoch = 0;
    maplesu_host_instance host{};
};
bool maplesu_request_owner_binding_matches(const RequestOwnerBinding& binding);
// A local worker-lifetime witness, never an authority or a wire session ID.
// Capture only after an existing management session (normally after ROOT).
class RequestOwnerLifetimeToken {
public:
    RequestOwnerLifetimeToken() = default;
private:
    RequestOwnerBinding binding_{};
    uint64_t session_ = 0;
    friend bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken& token);
    friend bool maplesu_request_owner_lifetime_matches(const RequestOwnerLifetimeToken& token);
};
// No QUERY/OPEN, I/O or signature checks; failure clears the output token.
// This witnesses local session continuity; the gateway still revalidates authority.
bool maplesu_request_owner_lifetime_capture(RequestOwnerLifetimeToken& token);
bool maplesu_request_owner_lifetime_matches(const RequestOwnerLifetimeToken& token);
// Cold QUERY + internal descriptor READ; warm bound descriptor READ confirms
// current authority before returning cached facts. Failed operations are not replayed.
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3& metadata,
    uint64_t& descriptor, RequestOwnerBinding& binding);
// Explicit EarlyHelper mode only: native current-executable/installation/service
// authentication opens this worker's own restricted session. No Manager claim,
// vendor-READ promotion, Key fallback or uncertain-OPEN replay. Subsequent typed
// namespace/binding/lifetime and ROOT/task/procattr/CLOSE reuse this same session.
KModErr maplesu_request_helper_open();
// Worker creation preserves the selected protocol; each child authenticates its operations.
KModErr maplesu_request_worker_admission();
KModErr maplesu_request_owner_read(uint64_t source, void* destination, uint32_t size,
    const RequestOwnerBinding& binding);
KModErr maplesu_request_owner_echo(uint64_t value, uint64_t& result);


// A completed wire error keeps the actual errno and effects. Missing/invalid
// completion is uncertain; mutating requests are never retried automatically.
// A complete command receipt can survive a later identity failure; it records
// effects, never continued authority or permission to publish success outputs.
struct RequestManagementReply {
    int32_t status = 0;
    uint32_t effects = 0;
    uint64_t result = 0, handle = 0;
    uint32_t command = 0;
    bool completed = false;
};
RequestManagementReply maplesu_request_management_reply();
enum class RequestUidReadbackPhase : uint32_t {
    None, Output, Identity, CapabilityQuery, CapabilityMissing, Exchange,
    Metadata, Records, Binding, Allocation, Complete
};
// Diagnostics from this thread/process's latest typed UID READ only. The
// original reply survives local shape rejection and subsequent session CLOSE.
// Neither malformed metadata nor these saved scalars grant current authority.
struct RequestUidReadbackDiagnostic {
    int64_t errorCode = 0;
    int32_t systemErrno = 0;
    RequestUidReadbackPhase phase = RequestUidReadbackPhase::None;
    uint64_t capabilities = 0, revision = 0;
    uint32_t count = 0, schema = 0;
    RequestManagementReply reply{};
};
RequestUidReadbackDiagnostic maplesu_request_uid_readback_diagnostic();
// Authenticated immutable image path fact. This is neither an installation
// generation nor vendor/Root/SU readiness. The wire name has no trailing NUL.
struct RequestDeploymentNamespace {
    maplesu_deployment_namespace_v3 record{};
    RequestOwnerBinding binding{};
};
// Uses this worker's existing management session, opening it without ROOT when
// needed. Failure preserves output and the full completed command receipt;
// malformed success data poisons the session instead of publishing a path.
KModErr maplesu_request_owner_deployment(RequestDeploymentNamespace& output);
struct RequestSuRuntimeStatus {
    maplesu_su_runtime_status_v3 record{};
    RequestOwnerBinding binding{};
};
struct RequestEarlyFixedResult {
    int64_t code = 0;
    int32_t native_errno = 0;
    uint32_t effects = 0;
    uint64_t values[3]{};
};
// Authenticated EarlyHelper fixed business operation. The host returns the
// original module code/raw errno/effects; missing or uncertain receipts stay
// failed and are never replayed through the legacy path.
KModErr maplesu_request_helper_fixed(uint32_t operation, uint32_t mode,
    uint32_t exploit, uint64_t value, RequestEarlyFixedResult& output);
// Real native factory/source/publication facts, never app authorization or Ready.
// A complete authenticated provider error publishes its validated diagnostics but
// still returns the original error/errno. Missing, malformed or authority-lost
// results preserve output and full wire receipts. Manager/helper only; no replay.
KModErr maplesu_request_owner_su_runtime(RequestSuRuntimeStatus& output);
// Sole R02 installation bridge. Complete errors retain original status/effects.
// An uncertain mutation is never replayed. READ publishes only after final local
// identity validation; every failure preserves the caller's previous value.
KModErr maplesu_request_owner_installation(uint64_t action,
    maplesu_installation_state_v3& value);
// Existing helper, init-user-ns Root and exact kernel-held executable inode are
// checked by the host. This never selects owner mode or claims Manager status.
// Each thread/process starts with READ, including after fork. Missing/invalid
// completion or changed identity blocks mutations until a full explicit READ;
// negative COMMITTED/PENDING receipts also require this refresh. Valid completed
// receipts survive later identity failure; failed calls preserve the old value.
KModErr maplesu_request_helper_vendor(uint64_t action, unsigned index,
    maplesu_installation_state_v3& value);
// Local preflight before modifying this helper's disk record. No READ, request,
// I/O or authority grant; matches the last successful READ/mutation host/revision
// and this thread/process identity. Fork and uncertain completion fail closed.
bool maplesu_request_helper_vendor_matches(const maplesu_installation_state_v3& value);
// Cleanup may change session/authority and must keep those changes. This lexical
// scope restores only the current thread/process diagnostic receipt and errno.
class CleanupReceiptScope {
public:
    CleanupReceiptScope() noexcept;
    ~CleanupReceiptScope() noexcept;
    CleanupReceiptScope(const CleanupReceiptScope&) = delete;
    CleanupReceiptScope& operator=(const CleanupReceiptScope&) = delete;
    CleanupReceiptScope(CleanupReceiptScope&&) = delete;
    CleanupReceiptScope& operator=(CleanupReceiptScope&&) = delete;
private:
    int saved_errno_;
    uint64_t saved_process_;
    RequestManagementReply saved_reply_;
};
KModErr maplesu_request_owner_close();
// Select the single credential transaction before any mutation. New Key
// producers advertise it through their authenticated capability query; only a
// complete old producer response permits the centralized legacy adapter.
KModErr maplesu_request_credential_channel(bool& managed, uint64_t& capabilities);
KModErr maplesu_request_owner_root();
KModErr maplesu_request_owner_caps(const maplesu_caps_v3& caps);
// Current task only; credentials and no_new_privs remain separate. A completed
// detach may survive a later error; no uncertain operation is retried.
KModErr maplesu_request_owner_task_state();
// Same authenticated gateway, current-task default procattr only. Caller bytes
// include exactly one final NUL and remain valid for this synchronous call.
// A private copy stays alive through the native writer. No file/Key fallback.
KModErr maplesu_request_owner_procattr(uint32_t attribute, const char* context, uint32_t length);
// Fixed text operation on the same gateway; no generated EXEC or legacy retry.
// The address is instruction-aligned; arbitrary byte lengths preserve the last
// word's neighboring bytes inside the producer's single text-lock transaction.
KModErr maplesu_request_owner_write_text(uint64_t address, const void* data, uint32_t size);
KModErr maplesu_request_owner_reserve_code(uint32_t size, uint64_t near_anchor, uint64_t& address);
struct RequestSharedBool {
    uint64_t id = 0, address = 0;
    maplesu_host_instance host{};
    // Creation epoch is provenance, not this Manager's mutation authority.
    // The gateway checks the current session and the object's lifetime domain.
    uint32_t epoch = 0;
};
KModErr maplesu_request_owner_shared_bool_create(bool initial, RequestSharedBool& object);
KModErr maplesu_request_owner_shared_bool_store(const RequestSharedBool& object, bool value);
// Drops only the creating session's reference; publications hold independent refs.
KModErr maplesu_request_owner_shared_bool_release(const RequestSharedBool& object);
struct RequestPublicationMember {
    uint64_t address = 0;
    uint32_t role = 0;
    RequestSharedBool shared_bool{};
};
struct RequestPublication {
    uint64_t id = 0, control_address = 0;
    maplesu_host_instance host{};
};
// Ordinary members are exact owned allocations in this worker. SHARED_BOOL
// members explicitly supply their same-host descriptor, not a guessed pointer.
// The kernel alone checks Manager-owned versus trusted runtime dependencies.
// PREPARE acquires each publication ref; PUBLISH freezes ordinary members before exposure.
KModErr maplesu_request_owner_publication_prepare(const RequestPublicationMember* members,
    uint32_t count, uint32_t gate_index, uint64_t entry, uint64_t gate_offset,
    uint32_t expected_instruction, uint64_t payload_entry, RequestPublication& publication);
KModErr maplesu_request_owner_publication_publish(const RequestPublication& publication);
KModErr maplesu_request_owner_publication_disable(const RequestPublication& publication);
KModErr maplesu_request_owner_publication_retire(const RequestPublication& publication);
// Read-only control snapshot, not qualification or permission to call its gate
// functions from userspace. The generated kernel gate is the balanced consumer.
// Its creation epoch may precede the current Manager's epoch; each operation
// still authenticates the current session and kernel lifetime binding.
KModErr maplesu_request_owner_publication_control(const RequestPublication& publication,
    maplesu_publication_control_v3& control);

// Typed storage, not persistent SU authorization or complete KSU Profile.
// Scalars in rows still require the real installation/Profile providers.
struct RequestUidController { uint64_t id = 0; maplesu_host_instance host{}; };
struct RequestUidCandidate {
    uint64_t id = 0;
    RequestUidController controller{};
};
KModErr maplesu_request_owner_uid_create(RequestUidController& controller, uint64_t& revision);
KModErr maplesu_request_owner_uid_prepare(const RequestUidController& controller,
    const maplesu_uid_record_v3* records, uint32_t count, uint64_t expected_revision,
    RequestUidCandidate& candidate);
// Completed REFERENCE_DROPPED consumes the local candidate even on a later error.
// Failed calls preserve revision/output; inspect the full receipt for committed
// effects and explicitly read back before deciding what to do next.
KModErr maplesu_request_owner_uid_commit(RequestUidCandidate& candidate, uint64_t& revision);
KModErr maplesu_request_owner_uid_cancel(RequestUidCandidate& candidate);
KModErr maplesu_request_owner_uid_readback(const RequestUidController& controller,
    uint64_t expected_revision, maplesu_uid_metadata_v3& metadata,
    maplesu_uid_record_v3* records, uint32_t capacity);
// Fixed boot-runtime mirror of SU's already committed durable v3 authority.
// These reuse UID_COMMIT/READBACK with zero handle on the same R02/session.
// No grant input, second store, Key fallback or caller-owned candidate is made.
// full_uid=0 synchronizes the complete already committed durable authority.
// Native PENDING/negative/effect receipts remain in management_reply; the HOST
// alone retains/consumes its private candidate. Missing completion is uncertain;
// no mutation is replayed and readback never clears that uncertainty.
KModErr maplesu_request_owner_runtime_uid_sync(uint32_t full_uid);
KModErr maplesu_request_owner_runtime_uid_readback(uint64_t expected_revision,
    maplesu_uid_metadata_v3& metadata, maplesu_uid_record_v3* records, uint32_t capacity);
// Unpublishes current; held readers can finish and controller tombstone stays.
KModErr maplesu_request_owner_uid_shutdown(const RequestUidController& controller);
KModErr maplesu_request_owner_execute(const uint8_t* bytes, uint32_t size, uint64_t& result);
// Key/v2 management shares the native resource owner with v3. Only a complete
// zero-effect UNSUPPORTED OPEN (or an untouched old QUERY) selects compatibility.
// Every uncertain/error completion keeps supported=true and forbids replay.
KModErr maplesu_request_key_alloc(uint32_t size, uint64_t& address, bool& supported);
KModErr maplesu_request_key_execute(const uint8_t* bytes, uint32_t size,
    uint64_t& result, bool& supported);
bool maplesu_request_managed_allocation(uint64_t address);
// Central compatibility boundary for the old Key credential operations. The
// native exact-task gateway rebinds credentials at its next authenticated BEGIN;
// keep owned resources and refresh only the matching SDK execution identity.
KModErr maplesu_execute_legacy_credential_frame(const uint8_t* bytes, uint32_t size,
    uint64_t& result);
KModErr maplesu_request_key_credential_begin();
KModErr maplesu_request_key_credential_end(KModErr execution_error);

// Query compatibility while retaining the legacy setter's original saved IDs.
// An untouched response is ambiguous: an old gateway or a failed v2 request copy.
// It proves neither legacy identity nor v2 success and is not cached as legacy.
KModErr maplesu_request_v2_probe(maplesu_response_v2& response, bool& supported);
// Call only after successful negotiation. Transport failure never retries or switches protocol.
// Command status and the full result remain separate in response.
// Each exchange authenticates with one Key/PID snapshot; observed changes discard its response.
KModErr maplesu_request_v2_exchange(uint32_t command, uint64_t arg0, uint64_t arg1,
                                 maplesu_response_v2& response);
// Supported negotiation is cached per thread, process and current module identity.
KModErr maplesu_request_v2_channel(maplesu_response_v2& response, bool& supported);
// Requires READ capability. Errors never retry through the legacy read/executor.
// All batches bind to the initial Key/PID. Failure may leave already copied bytes;
// callers must use the returned error, not partial output, as the completion result.
KModErr maplesu_request_v2_read(uint64_t source, void* destination, uint32_t size);
}
