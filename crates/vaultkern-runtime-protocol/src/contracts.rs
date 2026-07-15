//! Phase 0 contract freeze — the pinned wire formats from docs/design/000–004.
//!
//! This module is the **canonical source** of the frozen schemas (000,
//! Execution discipline #1): `CacheManifest` (002), `JournalRecord` +
//! `JournalOpKind` + `DeadLetterRecord` (003, journal contract),
//! `QuickUnlockLedgerEntry` and the platform record key (003, source of
//! truth + cross-store write-order axiom). The generated JSON Schema
//! artifacts under `schemas/` and the golden fixtures under
//! `tests/fixtures/` are CI snapshots of these types: **any wire change
//! must explicitly update the goldens**.
//!
//! Evolution rules (frozen together with the formats):
//!
//! - Changes are **additive-only** within a `SCHEMA_VERSION`: new fields must
//!   carry `#[serde(default)]` so old records still deserialize.
//! - Readers tolerate unknown fields (no `deny_unknown_fields` anywhere), so
//!   old readers accept new records.
//! - Field names on these storage contracts are `snake_case`, exactly as the
//!   wire-format blocks in 002/003 spell them (unlike the camelCase UI DTOs
//!   in the crate root — these are storage/wire contracts, and the design
//!   documents are their sole authority).
//! - No business logic lives here: merge, replay, and ledger transitions are
//!   Phase 1 work. This module only pins the shapes (and, for the passkey
//!   idempotence law, the pure decision function) those implementations
//!   must consume.

use serde::{Deserialize, Serialize};

use crate::EntryPasskeyDto;

/// 002 §"CacheManifest wire format and atomic publication".
///
/// Binds the cached vault bytes in the app group container to a
/// `vault_ref_id` and a KDF generation. The manifest is **the authority** in
/// the two-file commit: readers verify `H(bytes) == content_fingerprint` and
/// degrade to "no cache" on any mismatch (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct CacheManifest {
    /// Format version of this manifest document. Currently
    /// [`CacheManifest::SCHEMA_VERSION`].
    #[cfg_attr(
        feature = "json-schema",
        schemars(schema_with = "schema_version_const_one")
    )]
    pub schema_version: u32,
    /// The vault reference this cache belongs to. The extension refuses a
    /// cache whose `vault_ref_id` differs from the one in the envelope AAD
    /// (002 §"Envelope↔cache binding").
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub vault_ref_id: String,
    /// SHA-256 of the cached vault bytes, lowercase hex. Content-addressed:
    /// this is also the cache file's name.
    #[cfg_attr(feature = "json-schema", schemars(regex(pattern = r"^[0-9a-f]{64}$")))]
    pub content_fingerprint: String,
    /// `H(canonical(KdfParameters VariantDictionary))`, lowercase hex —
    /// 002's single authoritative formula (see `vaultkern-kdbx`'s
    /// `kdf_generation` module). Equality check, not an ordering.
    #[cfg_attr(feature = "json-schema", schemars(regex(pattern = r"^[0-9a-f]{64}$")))]
    pub kdf_generation: String,
    /// Remote identity at snapshot time; `None` for local-file vaults (the
    /// fingerprint alone is the identity).
    #[serde(default)]
    pub source_etag: Option<String>,
    /// Publication time, seconds since the Unix epoch.
    pub published_at: u64,
}

impl CacheManifest {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// 003 §"Journal contract" — one record appended by a system-extension
/// writer to its own single-writer segment file.
///
/// The binary framing around this body is frozen in the [`crate::framing`]
/// module (003 r10): `len u32 LE ‖ record_version u16 LE ‖ body ‖ crc u32
/// LE`, where the body is this document as **any schema-conforming UTF-8
/// JSON** — a writer uses its language's standard serializer, the CRC
/// covers the exact bytes that writer wrote, and no correctness property
/// depends on the body's byte shape (idempotence and dedup rest entirely
/// on `op_id`; 003 r11). [`JournalRecord::SCHEMA_VERSION`] is the
/// `record_version` the framing carries for records of this shape.
///
/// The op vocabulary is **sealed at rest** (003 r9, payload sealing):
/// `payload_sealed` is the AES-256-GCM ciphertext of the serialized
/// [`JournalOpKind`] document, under
/// `key = HKDF-SHA256(transformed, info = "vaultkern.journal.v1")`, with a
/// fresh random 12-byte nonce per record and `AAD = op_id ‖ vault_ref_id`.
/// The journal is the only on-disk location outside the vault that can hold
/// secrets (passkey private keys); container same-signature isolation
/// argues write integrity, not confidentiality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct JournalRecord {
    /// Normally monotonic within its writer's segment, but **diagnostic
    /// only — it plays no part in correctness** (003 r11): an implausible
    /// value never rejects a record, and `seq` holes from a writer crash
    /// are tolerated.
    pub seq: u64,
    /// UUIDv7 string — the idempotency identity of the mutation. Replay
    /// dedup and the applied set key off this value alone; it is also the
    /// first component of the sealing AAD.
    #[cfg_attr(
        feature = "json-schema",
        schemars(regex(
            pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ))
    )]
    pub op_id: String,
    /// Target vault, **plaintext**: routing + pre-replay validation. Lives
    /// only here (payloads do not duplicate it) and is bound into the
    /// sealing AAD, so it cannot be swapped without failing the GCM tag.
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub vault_ref_id: String,
    /// AES-256-GCM ciphertext (including the GCM tag) of the serialized
    /// [`JournalOpKind`] document, encoded as **standard base64
    /// (RFC 4648 §4, with padding)** — the encoding is part of the frozen
    /// contract. Minimum length 24 characters (the 16-byte GCM tag alone).
    #[cfg_attr(
        feature = "json-schema",
        schemars(
            length(min = 24),
            regex(pattern = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
        )
    )]
    pub payload_sealed: String,
    /// The record's fresh random 12-byte GCM nonce, encoded as **standard
    /// base64 (RFC 4648 §4, with padding)** — same pinned encoding as
    /// `payload_sealed`. 12 bytes encode to exactly 16 base64 characters
    /// (no padding).
    #[cfg_attr(
        feature = "json-schema",
        schemars(regex(pattern = r"^[A-Za-z0-9+/]{16}$"))
    )]
    pub nonce: String,
    /// Fingerprint (lowercase hex SHA-256) of the cached vault the extension
    /// saw when it appended this record. **Diagnostic only**; replay does not
    /// require a match and an implausible value never rejects a record.
    #[cfg_attr(feature = "json-schema", schemars(regex(pattern = r"^[0-9a-f]{64}$")))]
    pub base_fingerprint: String,
    /// Append time, seconds since the Unix epoch. **Diagnostic field**.
    pub created_at: u64,
}

impl JournalRecord {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// 003 §"Journal contract" (r11) — the body of a dead-letter file frame.
///
/// The dead-letter file uses the same binary framing as journal segments
/// ([`crate::framing`]); each frame's body is this document. It archives
/// the original frame's **raw bytes, verbatim** — never a
/// re-serialization: unknown fields, the writer's original serialization,
/// and even undecodable bodies survive intact, and the retry path
/// re-parses from these bytes. (Originals in their segments are never
/// edited; this is the copy.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct DeadLetterRecord {
    /// Why the record was dead-lettered. Frozen values so far (an additive
    /// vocabulary; see [`dead_letter_reason`]): `kdf_rotated`,
    /// `payload_conflict`, `user_discarded`, `unknown_kind`,
    /// `corruption_unreachable`, plus replay validation failures. Unknown
    /// reason strings are displayed verbatim and handled generically
    /// (003 r11, vocabulary evolution).
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub reason: String,
    /// When this dead-letter entry was captured, seconds since the Unix
    /// epoch.
    pub captured_at: u64,
    /// The archived raw bytes, encoded as **standard base64 (RFC 4648 §4,
    /// with padding)**. Two distinct semantics (r12):
    ///
    /// - For per-record reasons (`kdf_rotated`, `payload_conflict`,
    ///   `user_discarded`, `unknown_kind`, validation failures): one
    ///   **complete frame** — `len ‖ record_version ‖ body ‖ crc` exactly
    ///   as it appeared in the segment.
    /// - For `corruption_unreachable`: the **raw unreachable region**
    ///   (failing frame through EOF), which is *not* a well-formed frame
    ///   and can be as short as **one byte** (e.g. a tail torn inside the
    ///   length prefix itself).
    ///
    /// Hence a one-byte corruption region encodes to the four-character
    /// `AA==` minimum. At most
    /// [`DeadLetterRecord::MAX_ARCHIVED_BYTES`] raw bytes are stored
    /// here; a longer region keeps its prefix, with `region_len` and
    /// `archived_segment` recording the rest (r12).
    #[cfg_attr(
        feature = "json-schema",
        schemars(
            length(min = 4),
            regex(pattern = r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
        )
    )]
    pub frame_b64: String,
    /// Total byte length of the full original region, whether or not it
    /// was truncated to fit `frame_b64`. Additive field (r12); `0` in a
    /// pre-r12 document means "unrecorded — equal to the archived bytes".
    #[serde(default)]
    pub region_len: u64,
    /// When the region exceeded [`DeadLetterRecord::MAX_ARCHIVED_BYTES`]:
    /// the file name of the corrupt segment, renamed to `*.corrupt` and
    /// kept whole in the container — never parsed again, read directly by
    /// the support procedure. `None` when nothing was truncated. Additive
    /// field (r12).
    #[serde(default)]
    pub archived_segment: Option<String>,
}

impl DeadLetterRecord {
    pub const SCHEMA_VERSION: u32 = 1;

    /// Cap on raw bytes archived in `frame_b64`: one maximum-size journal
    /// frame, including its framing overhead. This guarantees that every
    /// legal journal frame can be archived verbatim.
    pub const MAX_ARCHIVED_BYTES: usize =
        crate::framing::MAX_RECORD_LEN as usize + crate::framing::FRAME_OVERHEAD;

    /// Assembles a dead-letter entry from a raw byte region under the
    /// production cap ([`Self::MAX_ARCHIVED_BYTES`]). Pure assembly — no
    /// I/O: renaming an over-limit segment to `*.corrupt` is the caller's
    /// act, reported here via `archived_segment`.
    pub fn archive(
        reason: impl Into<String>,
        captured_at: u64,
        region: &[u8],
        archived_segment: Option<String>,
    ) -> Self {
        Self::archive_with_limit(
            reason,
            captured_at,
            region,
            Self::MAX_ARCHIVED_BYTES,
            archived_segment,
        )
    }

    /// [`Self::archive`] with an injectable cap — the test seam that pins
    /// the truncation rule (store the prefix, record the full length);
    /// production code uses [`Self::archive`].
    pub fn archive_with_limit(
        reason: impl Into<String>,
        captured_at: u64,
        region: &[u8],
        max_archived_bytes: usize,
        archived_segment: Option<String>,
    ) -> Self {
        use base64::Engine as _;
        let stored = &region[..region.len().min(max_archived_bytes)];
        Self {
            reason: reason.into(),
            captured_at,
            frame_b64: base64::engine::general_purpose::STANDARD.encode(stored),
            region_len: region.len() as u64,
            archived_segment,
        }
    }
}

/// The frozen `DeadLetterRecord.reason` vocabulary (003 r10/r11).
/// Additive: new reasons may be added; existing strings never change
/// meaning; unknown strings are displayed verbatim and handled
/// generically.
pub mod dead_letter_reason {
    /// Sealed under a KDF generation that has been rotated away — the
    /// payload is undecryptable (003, drain-before-rotate).
    pub const KDF_ROTATED: &str = "kdf_rotated";
    /// Passkey registration whose credential UUID already exists with
    /// different data (003, three-branch idempotence law).
    pub const PAYLOAD_CONFLICT: &str = "payload_conflict";
    /// Explicitly discarded by the user during a credential-change drain
    /// (003, drain-before-rotate failure path).
    pub const USER_DISCARDED: &str = "user_discarded";
    /// The op `kind` (or a higher `record_version`) is unknown to this
    /// reader; the raw bytes are preserved so a newer app can retry
    /// (003 r11, vocabulary evolution).
    pub const UNKNOWN_KIND: &str = "unknown_kind";
    /// A sealed segment's unreachable region after a framing failure,
    /// archived byte-for-byte for manual forensics (003 r11 — truncation
    /// is accepted by design; no resync marker exists).
    pub const CORRUPTION_UNREACHABLE: &str = "corruption_unreachable";
}

/// 003 journal op vocabulary — **the plaintext content of
/// [`JournalRecord::payload_sealed`]**: this document (wire shape: sibling
/// `kind` + `payload` fields) is what sealing encrypts and unsealing
/// yields; it never appears unencrypted on disk.
///
/// **Contract law (003, fixed-point replay)**: every op kind — present and
/// future — MUST declare its idempotence and monotonicity laws and its
/// applicability predicate in its doc comment, and its implementation must
/// ship a termination property test. A new variant cannot be added without
/// them.
///
/// Increment-style ops are forbidden (003, correctness layer 1): every op
/// carries observed absolute state so re-application is a no-op.
///
/// Deliberately does **not** derive `Clone`: the passkey variant carries
/// entry-level secret material, and secret-bearing DTOs do not derive
/// Clone (D5 r11 contract rule — copies of secrets must be explicit and
/// justified, never ambient). Guarded against regression:
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<vaultkern_runtime_protocol::contracts::JournalOpKind>();
/// ```
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum JournalOpKind {
    /// A WebAuthn registration completed inside a system extension.
    ///
    /// - **Idempotence law (three-branch, 003 r10)** — frozen executably as
    ///   [`PasskeyRegistrationPayload::registration_outcome`]:
    ///   (a) an entry with the same UUID exists and its stored data, including
    ///   `entry_id`, equals this record's full canonical payload ⇒ **no-op**;
    ///   (b) same UUID but a differing payload ⇒ the record is
    ///   dead-lettered with reason `payload_conflict` — **silent overwrite
    ///   and silent keep are both forbidden**; (c) no such UUID ⇒ insert.
    ///   No passkey update semantics exist (a WebAuthn private key has no
    ///   update scenario; a re-registration arrives as a new credential
    ///   UUID).
    /// - **Monotonicity law**: insert-only under a fixed key; applying this
    ///   op never un-applies or oscillates any other op's effect, and
    ///   re-application never changes the vault again (branch (a)) or
    ///   removes the record from replay entirely (branch (b), dead-letter).
    /// - **Applicability predicate**: creation-type — applicable whenever
    ///   the record targets the vault being replayed (the record header's
    ///   plaintext `vault_ref_id` matches); it depends on no pre-existing
    ///   entry. In an extension's stale-cache overlay it synthesizes a
    ///   provisional entry so a just-registered passkey can assert
    ///   immediately.
    PasskeyRegistration(PasskeyRegistrationPayload),
    /// An observed usage-count for an existing credential/entry.
    ///
    /// - **Idempotence law**: carries the **observed value**, never an
    ///   increment (increments are forbidden by 003 layer 1); application is
    ///   `usage_count := max(current, observed)`, and `max` applied twice
    ///   equals `max` applied once.
    /// - **Monotonicity law**: `usage_count` never decreases under
    ///   application; `max` is commutative and associative, so applying this
    ///   op never un-applies or oscillates another op, and cross-segment
    ///   application order is irrelevant.
    /// - **Applicability predicate**: mutation-type — applicable iff the
    ///   target entry (`payload.entry_id`) exists in the vault being
    ///   replayed. Otherwise the record is **pending**: it stays in its
    ///   segment (blocking deletion), is retried on every future replay, and
    ///   is dead-lettered (by copy) only when its target is confirmed dead
    ///   by a newer tombstone. On a stale cache it surfaces as pending-sync
    ///   in the overlay rather than applied.
    UsageCount(UsageCountPayload),
}

/// Payload of [`JournalOpKind::PasskeyRegistration`]. The credential reuses
/// the protocol's existing vault-side passkey vocabulary (D5: protocol DTOs
/// are the single vocabulary). The target `vault_ref_id` is **not** here —
/// it lives once, in the plaintext record header, bound via the sealing
/// AAD (003 r9).
///
/// `Debug` is **hand-written and redacted** (D5 r10: entry-level secrets
/// never enter logs; Debug/Display representations are redacted) — the
/// private key renders as `[REDACTED]`. Deliberately does **not** derive
/// `Clone` (D5 r11: secret-bearing DTOs do not derive Clone; a copy of a
/// private key must be an explicit, justified operation). Guarded
/// against regression:
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<vaultkern_runtime_protocol::contracts::PasskeyRegistrationPayload>();
/// ```
#[derive(PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PasskeyRegistrationPayload {
    /// UUID of the target (or to-be-created) vault entry. The extension
    /// generates it during the ceremony and replay must preserve it.
    #[cfg_attr(
        feature = "json-schema",
        schemars(regex(
            pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        ))
    )]
    pub entry_id: String,
    /// The registered credential as it is to exist in the vault. Its
    /// `credential_id` identifies the credential, while `entry_id` identifies
    /// the entry and is part of the idempotent payload.
    pub passkey: EntryPasskeyDto,
}

impl std::fmt::Debug for PasskeyRegistrationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRegistrationPayload")
            .field("passkey", &RedactedEntryPasskey(&self.passkey))
            .finish()
    }
}

/// Debug adapter rendering an [`EntryPasskeyDto`] with its secret material
/// redacted (D5 r10).
struct RedactedEntryPasskey<'a>(&'a EntryPasskeyDto);

impl std::fmt::Debug for RedactedEntryPasskey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryPasskeyDto")
            .field("username", &self.0.username)
            .field("credential_id", &self.0.credential_id)
            .field("generated_user_id", &self.0.generated_user_id)
            .field("private_key_pem", &"[REDACTED]")
            .field("relying_party", &self.0.relying_party)
            .field("user_handle", &self.0.user_handle)
            .field("backup_eligible", &self.0.backup_eligible)
            .field("backup_state", &self.0.backup_state)
            .finish()
    }
}

/// Outcome of the three-branch passkey-registration idempotence law
/// (003 r10). See [`PasskeyRegistrationPayload::registration_outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyRegistrationOutcome {
    /// No credential with this UUID exists — insert.
    Insert,
    /// A credential with this UUID exists and equals this payload — no-op.
    NoOp,
    /// A credential with this UUID exists with **different** data — the
    /// record must be dead-lettered with reason
    /// [`dead_letter_reason::PAYLOAD_CONFLICT`]. Silent overwrite and
    /// silent keep are both forbidden; no passkey update semantics exist.
    Conflict,
}

impl PasskeyRegistrationPayload {
    /// The three-branch idempotence law of 003 r10, frozen as a pure
    /// function so the Phase 1 replay implementation and its tests share
    /// one source of truth. `existing` carries the entry UUID and credential
    /// currently held under this payload's credential UUID; equality includes
    /// both the entry UUID and full passkey payload.
    pub fn registration_outcome(
        &self,
        existing: Option<(&str, &EntryPasskeyDto)>,
    ) -> PasskeyRegistrationOutcome {
        match existing {
            None => PasskeyRegistrationOutcome::Insert,
            Some((entry_id, current)) if entry_id == self.entry_id && *current == self.passkey => {
                PasskeyRegistrationOutcome::NoOp
            }
            Some(_) => PasskeyRegistrationOutcome::Conflict,
        }
    }
}

/// Payload of [`JournalOpKind::UsageCount`]. The target `vault_ref_id` is
/// **not** here — it lives once, in the plaintext record header, bound via
/// the sealing AAD (003 r9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct UsageCountPayload {
    /// UUID of the target entry.
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub entry_id: String,
    /// The **observed** absolute usage count (001: `usage_count` merges as
    /// max; increment-style ops are forbidden).
    pub observed_usage_count: u64,
}

/// 003 §"Source of truth" — one row per vault in the per-extension-scope
/// quick unlock ledger. Records in platform secure storage are ciphertext
/// caches indexed by generation; **this row is the only source of truth**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct QuickUnlockLedgerEntry {
    /// On-disk ledger schema version. Missing values fail closed during
    /// deserialization; this is app-owned persistent storage.
    #[cfg_attr(
        feature = "json-schema",
        schemars(schema_with = "schema_version_const_one")
    )]
    pub schema_version: u32,
    /// Current state; errors drive state transitions, never record
    /// destruction (003 axiom).
    pub state: QuickUnlockState,
    /// Monotonically increasing, baked into the envelope AAD. A platform
    /// record whose generation mismatches this value is equivalent to
    /// non-existent. Disable/rotation = one atomic ledger write
    /// (`policy=false, state=Disabled, generation+1`) — the write itself is
    /// the revocation.
    pub generation: u64,
    /// User intent: quick unlock enabled or not.
    pub policy: bool,
}

impl QuickUnlockLedgerEntry {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// 003 quick unlock states. There is no `Revoked` state (generation
/// mismatch is the revocation) and no stored "cleanup pending" state (that
/// is a derived display state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuickUnlockState {
    /// Quick unlock is off for this vault.
    Disabled,
    /// A platform record at the ledger's current generation is expected to
    /// exist and be usable.
    Enrolled,
    /// The envelope is invalid; re-enrollment happens automatically at the
    /// next successful full-credential unlock (`Enrolled(gen+1)`).
    NeedsReenroll { reason: NeedsReenrollReason },
}

/// Why a vault fell into [`QuickUnlockState::NeedsReenroll`] (003 transition
/// table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum NeedsReenrollReason {
    /// The platform reported `PermanentlyInvalidated` (e.g.
    /// `biometryCurrentSet` invalidation — the biometric enrollment set
    /// changed).
    BiometryChanged,
    /// `kdf_generation` mismatch against the file header (002): a
    /// master-credential change or a third-party salt rotation.
    KdfRotated,
}

/// 003 cross-store write-order axiom, precondition: the **physical key** a
/// platform secure-storage record is stored under.
///
/// The key contains the generation, so sealing `gen+1` creates a **new**
/// record and never overwrites the current one — an overwrite-in-place
/// provider would destroy the current record before the ledger commits and
/// falsifies the axiom (the 004 provider negative test enforces this).
/// Orphaned records (seal succeeded, crash before the ledger write) are
/// inert by generation mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "json-schema", derive(schemars::JsonSchema))]
pub struct PlatformRecordKey {
    /// The extension scope this record belongs to (per-scope ledger, 003).
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub identifier_scope: String,
    /// The vault the sealed envelope unlocks.
    #[cfg_attr(feature = "json-schema", schemars(length(min = 1)))]
    pub vault_ref_id: String,
    /// The ledger generation this record was sealed at.
    pub record_generation: u64,
}

impl PlatformRecordKey {
    pub const SCHEMA_VERSION: u32 = 1;
}

/// JSON Schema for a `schema_version` field frozen at `1` (M1: the version
/// is a `const` in the schema, so a document claiming any other version is
/// rejected by validation rather than silently accepted).
#[cfg(feature = "json-schema")]
fn schema_version_const_one(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
    schemars::schema::Schema::Object(schemars::schema::SchemaObject {
        instance_type: Some(schemars::schema::InstanceType::Integer.into()),
        format: Some("uint32".to_owned()),
        const_value: Some(serde_json::json!(1)),
        ..Default::default()
    })
}
