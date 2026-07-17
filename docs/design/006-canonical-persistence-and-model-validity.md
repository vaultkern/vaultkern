# 006 — Canonical Persistence and Model Validity Invariants

Status: **Frozen — r5**. 2026-07-17. Additive operational amendment to 000 D1
and 005, frozen after the r3 contract review and the interoperability/evidence
gates in §10 passed; r5 amends the frozen text for the PR #35/#36 post-merge
review rounds (§12).

Upstream: 000 D1 (KDBX interoperability), 001 (merge consumers), and 005
(canonical entry serialization v1).

## 1. Decision and precedence

005 freezes the bytes of an entry's canonical semantic projection, but it does
not define which constructible model states are persistable, how duplicate
model representations stay consistent, or which KDBX versions the writer can
actually emit. Those missing operational rules allowed the canonical encoder,
the KDBX reader, and the KDBX writer to observe different meanings for one
`Entry`.

This document closes that gap without changing 005's byte layout or schema:

- canonical entry v1 still has exactly 27 fields, the `VKCS` framing, and
  `schema_version = 1`;
- 005 owns the byte layout and the semantic fields included in the hash. When
  005 says field 9 contains the persistent TOTP/passkey source attributes, this
  document pins that operational source as `A(e)`, not the unmaterialized
  `Entry.attributes` member;
- this document owns persistence validity, shared model projections, KDBX
  write capability, and fidelity-state transformations;
- 001 continues to own merge behavior. This document defines the stable entry
  projection that merge consumes but no winner, history, or merge decision.

No rule below adds a canonical field or includes fidelity state in the hash.
Duplicate representations fall into exactly two regimes:

1. An **authoritative value plus a derived cache** has one mutation owner. A
   stale cache is not a competing semantic fact; materialization overwrites it
   from the authoritative value. `Entry.totp` / `Entry.passkey` versus their
   persistent source attributes are in this regime while a structured
   projection is present.
2. **Co-equal replicas or aliases** have no such precedence. A disagreement is
   a semantic contradiction and is outside `P`; load or save MUST reject it.
   CustomData's map/block views and an attachment's map key/redundant name are
   in this regime.

A future duplicate representation MUST be assigned to one of these regimes by
a numbered design amendment. An implementation cannot invent precedence and
call it repair.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` have their usual RFC
2119 meanings.

## 2. State domains and required laws

Let:

- `M` be every state constructible with the public Rust model structs;
- `P` be the subset of vault states that the KDBX writer can persist without
  discarding or inventing canonical semantics or required fidelity state;
- `A(e)` be the materialized persistent-attribute map for entry `e` (§3);
- `C1(e)` be the canonical entry v1 byte stream defined by 005;
- `S_p(v)` be KDBX serialization of vault `v` with save profile `p`;
- `L(b)` be KDBX loading of bytes `b`;
- `VG(v)` be the modeled Vault/Meta/Group structural view defined below;
- `T(v)` be the map from deleted-object UUID to its latest deletion time.

A save profile is the tuple `(version, outer cipher, compression, KDF
component)`. The KDF component is optional: absent means *preserve* — the
ordinary save — while present means an explicit KDF change carrying the
requested algorithm and work-factor parameters. The composite key is an
input to serialization, not a profile property. The vault's loaded KDBX4
`KdfParameters` dictionary — the salt, version fields such as Argon2 `V`,
and any unknown `VariantDictionary` entries, verbatim — is required
vault-level fidelity state carried by `v` itself, so `S_p(v)` has a defined
state carrier for the preservation mandate instead of rebuilding from the
profile. An ordinary save MUST re-emit that retained dictionary unchanged
and therefore satisfies

```text
kdf_generation(L(S_p(v))) = kdf_generation(v)
```

by construction (002's rotation policy). This applies when the loaded vault
already carries a KDBX4 `KdfParameters` dictionary: loading a KDBX2/3 vault
and saving it under a 4.x profile is the explicit §8 format upgrade, which
constructs the KDBX4 dictionary for the first time and changes
`kdf_generation` exactly as 002 already records for that upgrade. A newly
created vault has no retained dictionary; its first save constructs one,
equivalent to an explicit KDF change with product defaults. Otherwise
only a master-credential change or an explicit KDF change (a present KDF
component) constructs a new dictionary and thereby rotates the salt;
per-save rotation would invalidate every quick-unlock envelope on every
save. Random master seeds, IVs, inner-stream keys, and block nonces are
fresh physical output on every save and are not profile properties.

`VG(v)` contains every modeled Vault/Meta field except `deleted_objects`, every
modeled Group field recursively, custom-icon content and metadata, public
custom data, and, for each Group, the ordered UUID sequence of its direct
entries and child groups. For each current Entry it also contains the ordered
sequence of its history snapshots' `C1` values. Entry bodies are otherwise
covered by `C1`; deleted objects are covered by `T`;
`raw_state`, opaque XML, and anchors are fidelity state covered by §6. Before
structural comparison, CustomData blocks retain their block/item order and
item key/value/timestamp but omit each block's `after` anchor from `VG`; §6
compares those anchors separately. `VG` applies only these KDBX semantic
defaults:

| Model spelling | `VG` value |
|---|---|
| `Group.icon_id = None` | icon ID `0` |
| `Group.times = None` | `created_at = modified_at = 0`, `expires = false`, and `expiry_time = last_accessed_at = usage_count = location_changed_at = None` |
| `Group.flags.is_expanded = None` | `true` |

All other modeled optionality is significant. In particular, an optional text
field that KDBX cannot distinguish from absence MUST use `None`, not `Some("")`,
in `P` (§9); it is not another implicit `VG` default.

The public structs MAY remain directly constructible, so `M` is intentionally
larger than `P`. The boundary rules are:

1. `C1` MUST remain deterministic for every entry it can encode. It is not the
   persistence validator; its only representation-level failures are the
   checked size/count failures needed to represent 005's `u32` length and count
   domains.
2. Every successful supported load MUST produce a state in `P`; malformed or
   contradictory input MUST return a structured error.
3. Product mutation APIs MUST preserve `P` atomically. Test fixtures and
   low-level callers that construct structs directly are responsible for
   validating before save.
4. `S_p` MUST reject a state outside `P` with a structured error. It MUST NOT
   choose one of two contradictory representations, flatten fidelity state, or
   return bytes labeled as a format it did not emit.
5. For every `v` in `P`, every supported write profile `p`, and every current
   and history entry `e` in `v`, the corresponding reloaded entry `e'` MUST
   satisfy:

   ```text
   C1(e') = C1(e), where L(S_p(v)) contains e'
   ```

   Encryption nonces, seeds, compression, XML formatting, and other physical
   file bytes are deliberately outside this equality.
6. The non-entry modeled graph MUST satisfy:

   ```text
   VG(L(S_p(v))) = VG(v)
   ```

   Thus a writer cannot satisfy this contract while dropping Meta fields,
   Group fields, graph placement, or modeled ordering merely because entries
   still hash equally.
7. Deleted objects MUST satisfy:

   ```text
   T(L(S_p(v))) = T(v)
   ```

   where duplicate source tombstones are folded as specified in §9.
8. A save failure MUST expose no partial file as a successful result. An API
   that writes to a path additionally MUST retain the existing atomic-write
   contract.

The round-trip law applies only to supported write profiles and persistence-
valid states. Rejecting an unsupported or contradictory input is correct;
silently changing its canonical projection is not.

## 3. Entry persistent attributes

### 3.1 One materialized view

`Entry.attributes`, `Entry.totp`, and `Entry.passkey` are not three independent
persistent stores. The one source consumed by both canonical field 9 and KDBX
`String` output is `A(e)`, a model-owned, transient materialized view.

There MUST be exactly one implementation of `A(e)`. The canonical encoder and
the KDBX writer MUST call it rather than carrying separate TOTP/passkey rules.
It MUST be deterministic and MUST NOT mutate `e` or retain another long-lived
copy of credential secrets. Its return type MUST bind the frozen 000 D5
entry-secret lifecycle: secret values are borrowed where possible; every owned
secret scratch buffer is zeroized on drop; and the carrier either has no
`Debug`/`Display` implementation or redacts every secret value. Canonical and
KDBX callers MUST NOT log the materialized view.

This is an operational amendment to 005's projection assumption, not a new
field. Canonical v1 has not yet shipped as a merge dependency, so `A(e)` MUST be
frozen before that first merge. After canonical v1 ships, the change rule at
the end of this section applies.

Outside a projectable credential source, `A(e)` preserves attribute keys,
values, and protection flags exactly except for the conservative secret
protection in §3.2. It performs no Unicode normalization. Parsing and
deterministically re-emitting a projectable TOTP/passkey source is one explicit
semantic normalization. Escalating the protection flag of a reserved secret is
the second. Both happen inside `A(e)`, so `C1(e)` observes the same normalized
view before and after a save; neither authorizes normalization of unrelated
attributes.

Materialization follows this precedence:

1. Start with `Entry.attributes`.
2. A present structured TOTP projection removes every key in the complete OTP
   reserved set below, then emits the canonical TOTP spelling. This prevents a
   higher-priority stale KeePass secret or an HOTP counter from surviving the
   authoritative product mutation.
3. Without a structured TOTP projection, the complete raw OTP set is parsed
   and re-emitted only when it is projectable under the lossless rules below. A
   projectable `otp` URI has precedence over the canonical discrete
   `TimeOtp-*` representation. An unprojectable set is retained verbatim except
   for §3.2 protection escalation.
4. A present structured passkey projection overrides every recognized
   `KPEX_PASSKEY_*` source attribute. Optional fields absent from the projection
   remove stale source keys.
5. Without a structured passkey projection, a projectable recognized source
   representation is parsed and re-emitted using the same writer rules.
6. Projection and backing attributes MUST never produce duplicate keys. The
   projection wins because it is authoritative and the backing attributes are
   its derived persistence cache; this is §1 regime 1, not silent resolution
   between co-equal facts.

The complete reserved OTP namespace is:

| Family | Reserved keys |
|---|---|
| URI | `otp` |
| TOTP secret | `TimeOtp-Secret`, `TimeOtp-Secret-Hex`, `TimeOtp-Secret-Base32`, `TimeOtp-Secret-Base64` |
| TOTP parameters | `TimeOtp-Algorithm`, `TimeOtp-Length`, `TimeOtp-Period` |
| HOTP | `HmacOtp-Secret`, `HmacOtp-Secret-Hex`, `HmacOtp-Secret-Base32`, `HmacOtp-Secret-Base64`, `HmacOtp-Counter` |

Every key in this table participates in structured-projection removal,
credential-clear removal, and reserved-field hiding. The secret-protection set
is `otp`, all eight `TimeOtp-Secret*` / `HmacOtp-Secret*` spellings, and
`HmacOtp-Counter`. The three non-secret TOTP parameter keys remain unprotected.
This set mirrors KeePass's secret priority and `RemoveOtpSecrets` behavior in
the pinned [`EntryUtil.cs`](https://github.com/dlech/KeePass2.x/blob/d1eec63f1bd73dc2d5273eaf94528f616b553ce5/KeePass/Util/EntryUtil.cs).

HOTP and the UTF-8/hex/base64 TOTP secret spellings are recognized for
preservation, hiding, protection, and removal, but are not projectable into the
current `TotpSpec`. A raw OTP set is convertible to a persisted structured
projection only when `otp` is a projectable TOTP URI and every other present
OTP key is one of the four canonical discrete TOTP keys emitted below.

A discrete-only set — `otp` absent, `TimeOtp-Secret-Base32` present, and the
only other OTP keys the three `TimeOtp-*` parameter keys — is recognized and
MAY back a read-only in-memory code generator, but MUST NOT be converted to
a persisted structured projection: it carries no issuer or account, so
emitting the canonical URI would require the non-exact username/title
fallback below. The set is retained verbatim, with §3.2 protection
escalation, until an explicit product TOTP edit re-enrolls it as a
structured projection with a materialized account.

Thus any HOTP key, any alternate TOTP secret spelling, an unprojectable
present `otp`, or a discrete-only set leaves the whole raw namespace
preserved verbatim. This prevents a lower-priority Base32 value from
replacing a higher-priority KeePass secret and prevents partial
normalization from discarding data. When URI and discrete
keys coexist without a structured projection, every present discrete value
MUST be semantically equivalent to the URI value after the pinned defaults;
otherwise the whole reserved namespace remains an unprojectable raw payload;
the loader MUST NOT create a structured TOTP fact or select either spelling.
If `TimeOtp-Secret-Base32` is present, the complete discrete specification,
including defaults for absent parameters, is compared to the URI; without a
discrete secret, only the parameter keys actually present are compared. Secret
equivalence is byte-for-byte equality of the stored Base32 text, including case
and padding; algorithm and numeric parameters compare as parsed model values.
URI supplies issuer/account only after that equivalence check. In a discrete-
only form, a missing algorithm, length, or period means SHA-1, 6, or 30
seconds. A present algorithm is projectable only when it is one of the three
`TimeOtp-Algorithm` spellings in the table below, ASCII-case-insensitively; a
present length or period must parse as its model integer type. Any other present
value makes the raw set malformed and unprojectable rather than silently
replacing it with a default.

A projectable URI has an ASCII-case-insensitive `otpauth://totp/` prefix, a
label followed by `?`, and exactly lower-case query names drawn from `secret`,
`issuer`, `algorithm`, `digits`, and `period`. Every query component MUST be a
`name=value` pair, every name MUST occur at most once, and `secret` MUST occur.
An unknown name, duplicate name, missing `=`, or empty component makes the URI
unprojectable so the original `otp` value and companion keys are preserved.
The decoded account MUST be non-empty after separator handling: an
empty-account label such as `Issuer:` makes the URI unprojectable and it
follows the raw-retention path, never a structured `TotpSpec` that would
violate `P`. An empty decoded issuer — whether from the label or from an
empty `issuer` query value, which likewise means no issuer — never yields
an issuer. As a final gate after every label and query rule: if the parse
result would pair no issuer with an account containing a colon, the URI is
unprojectable and follows the raw-retention path, whatever path produced
that combination. This keeps the invariant that a parsed projection never
pairs a colon-bearing account with no issuer.
Missing algorithm, digits, or period use SHA-1, 6, and 30. Present algorithm
values are limited to `SHA1`, `SHA256`, `SHA512` and their `HMAC-SHA-*`
spellings, case-insensitively; present digits and period must parse as their
model integer types. The `issuer` query parameter overrides a label issuer. The
first literal `:` separates label issuer and account; only when the label
contains no literal `:` does the first percent-encoded colon separate them —
matched hex-case-insensitively, so `%3A` and `%3a` are the same separator,
as `%HH` decoding is already case-insensitive. Otherwise the decoded
non-empty label is the account. A literal separator always takes precedence
over an encoded one, so re-parsing an emitted label — whose only literal `:`
is the separator and whose content colons are `%3A` — inverts the emission
exactly. With the encoded
separator form, leading `%20` sequences in the account are ignored. Valid
`%HH` sequences are decoded and malformed escapes stay literal. If decoding
any label or query value would produce invalid UTF-8, the URI is unprojectable;
replacement-character decoding would lose bytes and is forbidden.

For a modeled TOTP, the persistent view emits `otp`,
`TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`, `TimeOtp-Length`, and
`TimeOtp-Period`. `otp` and the secret are protected; algorithm, length, and
period are not. The spellings are fixed as follows:

| Model algorithm | URI value | `TimeOtp-Algorithm` value |
|---|---|---|
| SHA-1 | `SHA1` | `HMAC-SHA-1` |
| SHA-256 | `SHA256` | `HMAC-SHA-256` |
| SHA-512 | `SHA512` | `HMAC-SHA-512` |

URI output is exactly:

```text
otpauth://totp/<label>?secret=<secret>[&issuer=<issuer>]
  &algorithm=<algorithm>&digits=<digits>&period=<period>
```

The displayed line break is not emitted. Components are UTF-8 percent-encoded
byte by byte; only `ALPHA / DIGIT / "-" / "." / "_" / "~"` remain literal,
and hexadecimal digits are uppercase. Issuer and account are encoded as two
separate components and joined by one literal `:` byte; the separator is never
encoded as `%3A`. A `:` inside either source component is encoded as `%3A`, and
the literal-first parsing rule above makes the split unambiguous. Query
parameters occur in the shown order.

`TotpSpec.secret_base32` is a stored spelling, not decoded secret bytes. Both
the URI `secret=` value and `TimeOtp-Secret-Base32` emit that string verbatim
before ordinary percent-encoding of the URI component. Loading a projectable
URI stores the percent-decoded `secret` text verbatim; loading the discrete form
stores its field text verbatim. Case and `=` padding are therefore preserved,
and `A(e)` MUST NOT decode/re-encode, uppercase, lowercase, add, or remove
padding.

Label and issuer fallback are:

1. With an explicit issuer, label is `issuer:account`; a missing account uses
   `Entry.username`, and the issuer query parameter is emitted.
2. Without an issuer, a present non-empty account is the whole label and no
   issuer query parameter is emitted.
3. Without an issuer and with an absent or empty account, label is
   `Entry.title:Entry.username` and `Entry.title` is emitted as issuer.

Fallback 2 emits no literal separator, so a content colon in its label would
re-parse as an issuer/account split. A modeled TOTP with no issuer whose
account contains `:` therefore has no invertible URI spelling and is outside
`P`; enrollment and mutation APIs MUST reject it or require an issuer. The
parser never produces that state: a parsed account contains a colon only when
a separator preceded it, and the final projectability gate above excludes
every path that would evade this, so a parsed projection always pairs a
colon-bearing account with a non-empty issuer.

The label fallbacks that substitute `Entry.username` or `Entry.title` remain
defined so `C1` stays total over `M`, but they do not reload exactly: the
substituted values re-parse as an explicit account and issuer, and a later
username or title edit would silently change the emitted URI. `P` therefore
requires a structured TOTP projection to carry a present, non-empty
`account_name` — the otpauth label grammar itself makes the account
mandatory — and enrollment APIs materialize it at enrollment time, from
`Entry.username` when the user supplies nothing. A parsed source whose label
yields an empty account is retained as raw source rather than converted to a
structured projection, per §3.2's exact-reconstruction condition. Every
emission from a state in `P` therefore uses explicit issuer and account
values only and re-parses to itself exactly at both the URI and the model
level.

These URI rules and the parser precedence/defaults above are part of `A(e)` and
therefore part of canonical v1 behavior.

The recognized passkey keys are the eight keys in the table below. A source is
projectable when username, credential ID, private key, and relying party keys
are present; the generated user ID and user handle are optional, and absent
backup flags default to false. Presence, rather than non-empty text, defines
structural completeness; semantic validation of a newly registered credential
belongs to the registration operation. A present flag is projectable only when
it is `"0"`, `"1"`, or ASCII-case-insensitive `"false"` / `"true"`; absent
flags default to false. Materialization emits `"1"` or `"0"`. Any other present
flag keeps the complete raw passkey set unprojectable and verbatim.

For a loaded or directly supplied `PasskeyRecord`, all non-flag string values
are stored and emitted verbatim; `A(e)` does not parse and re-encode PEM,
credential IDs, or user handles. The first-write registration producer is
nevertheless pinned so implementations do not improvise incompatible
spellings:

- credential-ID bytes and user-handle bytes use RFC 4648 base64url without
  `=` padding; accepted user-handle text MUST decode and re-encode to the same
  canonical string;
- a newly generated ES256 private key is an unencrypted PKCS#8 `PrivateKeyInfo`
  encoded as strict RFC 7468 PEM with label `PRIVATE KEY`, standard padded
  base64, 64 characters on every non-final base64 line, LF line endings, and
  one final LF after `-----END PRIVATE KEY-----`;
- first write leaves `KPEX_PASSKEY_GENERATED_USER_ID` absent unless a future
  registration input explicitly supplies it under an amended contract.

This is the spelling produced by the current `URL_SAFE_NO_PAD` and
`to_pkcs8_pem(LineEnding::LF)` registration path. Accepting an interoperable
loaded key does not authorize rewriting it into this first-write profile.

For a modeled passkey, the protection matrix is:

| Source key | Model value | Protected |
|---|---|---|
| `KPEX_PASSKEY_USERNAME` | username | no |
| `KPEX_PASSKEY_CREDENTIAL_ID` | credential ID | yes |
| `KPEX_PASSKEY_GENERATED_USER_ID` | generated user ID | no |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | private key | yes |
| `KPEX_PASSKEY_RELYING_PARTY` | relying party | no |
| `KPEX_PASSKEY_USER_HANDLE` | user handle | yes |
| `KPEX_PASSKEY_FLAG_BE` | backup eligible | no |
| `KPEX_PASSKEY_FLAG_BS` | backup state | no |

An incomplete raw record is handled more conservatively as described below.

### 3.2 Incomplete or malformed credential sources

Third-party or future-version reserved attributes that do not form a
projectable current representation MUST NOT disappear merely because the
current product cannot model them.

- An incomplete or malformed TOTP source set remains persistent source data.
  Every key in the OTP secret-protection set above MUST be protected on output;
  in particular this includes all TOTP/HOTP secret spellings and
  `HmacOtp-Counter`, not only `otp` and `TimeOtp-Secret-Base32`.
- An incomplete passkey source set remains persistent source data. Credential
  ID, generated user ID, private key, and user handle MUST be protected on
  output.
- Reserved source attributes MUST remain hidden from ordinary custom-field UI,
  listing, and mutation APIs. A dedicated credential or redacted diagnostic
  path MAY inspect them. Hiding is not permission to discard the persistent
  data.
- Explicit credential-clear operations MUST remove both the structured
  projection and its recognized persistent source attributes. Merely setting
  the projection to `None` is insufficient when backing attributes exist.

Loading a projectable source representation MAY retain only its structured
projection in the long-lived model, provided `A(e)` reconstructs exactly the
writer-visible map. Loading an incomplete representation MUST retain enough
raw source data for a lossless subsequent save.

Any future change to `A(e)` that changes `C1(e)` for a state already valid
under this document is a canonical contract change and requires the 005
`schema_version` process. Refactoring without observable byte changes does not.

## 4. CustomData consistency

For any Meta, Group, Entry, or history Entry custom-data scope, define
`D(blocks)` as the string map produced by visiting every `CustomDataItem` in
document order and retaining the last value for each key.

A vault is persistence-valid only when, at every scope:

```text
D(custom_data_blocks) = custom_data
```

The two representations have different jobs:

- `custom_data` is the last-wins semantic string view and, for entries, is
  canonical field 25;
- `custom_data_blocks` owns item timestamps, duplicate occurrences, block
  boundaries, document order, and anchors; for entries, its last-wins item
  projection is canonical field 26 exactly as specified by 005.

Consequences:

1. The canonical encoder MUST derive field 26 from the actual blocks. It MUST
   NOT synthesize field 26 from `custom_data`.
2. The writer MUST reject a mismatch instead of choosing the map or blocks.
3. Mutation APIs MUST update the map and blocks as one operation. Updating an
   existing key changes its last occurrence; adding a key creates a real item;
   deleting a key removes all of its item occurrences.
4. A no-op save MUST preserve block order, duplicate occurrences, timestamps,
   empty blocks, and valid anchors. Equivalent maps do not permit flattening
   the blocks.
5. A loader MUST populate both views consistently, including duplicate-key
   last-wins behavior.

An empty block is fidelity state and remains valid. A block that becomes empty
because its final item was explicitly deleted MAY be removed, but §6 then
governs every anchor that referred to it.

## 5. Attachment identity and names

005 defines the attachment map key as canonical field 10's attachment name;
the repeated `Attachment.name` member is not another semantic field. Until the
redundant member is removed from the model, a persistence-valid Entry or
history Entry requires, for every map item `(key, attachment)`:

```text
key is non-empty AND attachment.name = key
```

The canonical encoder and KDBX writer MUST both use the map key as the name.
A mismatch is outside `P` and MUST be rejected rather than allowing canonical
field 10 and saved XML to name different attachments. Rename operations MUST
move the map item and update the redundant member atomically. A loader MUST
populate both representations consistently.

Attachment content identity remains its SHA-256 `AttachmentContentId`, and
`protect_in_memory` remains part of field 10; this section changes neither rule.

## 6. Opaque XML and anchor transformations

005 excludes `raw_state`, opaque XML, block boundaries, and anchors from the
hash because they are fidelity state, not because they may be discarded.

An anchor `(element_name, occurrence)` identifies the position immediately
after the named known-element occurrence in that scope. Occurrences are
one-based. A persistence-valid anchor is `None` or resolves to an already
preceding known node in the same scope; zero, forward, self, cross-scope, and
dangling references are invalid and MUST be rejected rather than appended at a
fallback position. A no-op load/save MUST preserve:

- the XML information content of every opaque fragment;
- the relative order of opaque fragments and known nodes;
- modeled raw string forms and known-node order where the corresponding
  `raw_state` field records them;
- CustomData block boundaries and their relative positions.

The `DeletedObjects` container is the §9.1 exception: its `DeletedObject`
children are an order-insensitive tombstone scope whose only semantics are
`T(v)`, so child order is not fidelity state and the scope admits no opaque
fragments or anchors. A loader MUST reject every unknown child element in
`DeletedObjects`; the relative-order preservation and anchor-retargeting rules
below therefore do not apply within it.

Each opaque fragment in `P` MUST parse as exactly one well-formed XML element,
and that element's root name MUST be unknown in its parent scope. A known node
cannot be smuggled through `opaque_xml`; it must use the corresponding modeled
field so the writer cannot emit contradictory duplicate known nodes.

Known-node multiplicity is fail-closed on load:

- the document has exactly one `Meta`, one `Root`, and one root `Group`, and at
  most one `DeletedObjects` container;
- a schema-singleton known child in Meta, Group, Entry, `Times`, `AutoType`, or
  any other modeled scope occurs at most once, or exactly once where KDBX
  requires it;
- repeated Entry `String` elements MUST have unique keys, including the five
  standard keys, and repeated `Binary` elements MUST have unique names;
- multiple `CustomData` blocks and duplicate item keys inside them are the
  deliberate exception governed by §4; repeated child Group/Entry elements are
  structural collections, not duplicate singleton nodes;
- current Group and Entry UUIDs are non-zero and unique across their shared
  live-object namespace; custom-icon UUIDs are non-zero and unique in the icon
  namespace. A history snapshot MUST reuse its owning Entry UUID. DeletedObject
  UUID validity and overlap with live objects are governed by §9.1.

A duplicate known singleton or duplicate `String` key MUST NOT be handled by
first-wins, last-wins, or conversion of the loser to opaque XML. The loader
returns a structured error because the model has no fidelity carrier that can
represent both. CustomData's explicitly modeled duplicate blocks/items and the
DeletedObjects rule in §9 are the only last-wins/latest-wins exceptions.

Exact encrypted bytes, insignificant XML whitespace, attribute quote style,
and namespace-prefix spelling are not fidelity requirements when the parsed XML
information is equivalent.

Any mutation that changes the count or order of an anchorable known-node kind
MUST build an old-to-new occurrence mapping before discarding the old order.
Retained keyed nodes map by semantic identity: for example, `String` by key,
`Binary` by attachment name, and child Group/Entry nodes by UUID. A removed
node maps to its recursively mapped predecessor. New nodes do not retroactively
capture opaque fragments that were anchored to an older occurrence. The
mapping is applied atomically to every fidelity anchor in the same scope.

If repeated nodes lack a stable semantic identity, fidelity state MUST retain
an internal occurrence token long enough to perform this mapping. When neither
identity nor a retained token exists, the mutation MUST fail or first upgrade
the fidelity representation; guessing from the new occurrence number is not
allowed.

For CustomData block mutations, the generic rule specializes to the following
mapping in Meta, Group, Entry, and history Entry scopes:

1. Build a mapping from every old CustomData occurrence to its new anchor.
2. A retained block maps to its renumbered CustomData occurrence.
3. A removed block maps to that block's recursively retargeted predecessor
   anchor (`block.after`).
4. Apply the same mapping atomically to both later block anchors and every
   `OpaqueXmlFragment.after` anchor.
5. Preserve the relative order of all fragments that shared an anchor.

No retained anchor may refer to a CustomData occurrence removed by the same
mutation. Falling back to the end of the parent element is not an acceptable
substitute when the predecessor mapping is known.

## 7. Typed optional XML values

Whitespace normalization belongs only to parsing the syntax of typed XML
fields. It MUST NOT alter ordinary text fields or the stored strings encoded by
005.

For every model `Option<Uuid>` persisted as KDBX XML, including custom-icon,
previous-parent, last-visible, recycle-bin, and template-group references:

- a missing element or a present element containing only XML whitespace maps
  to `None`;
- a nonblank value must be a valid encoded UUID or loading fails;
- an all-zero UUID is the KDBX sentinel for no reference and maps to `None`;
- the writer emits an optional UUID element only for a non-zero UUID.

Any optional UUID modeled as `Some(nil)` is outside `P` and MUST be rejected at
the save boundary rather than silently collapsed. 005's fields 12 and 23 can
encode `Some(nil)` for a directly constructed Entry, but the KDBX round-trip
law applies only to `P`.

The KDBX syntax also collapses empty content and absence for a small set of
modeled optional text fields. In `P`, `Vault.generator`, `Vault.description`,
`Vault.default_username`, `Vault.color`, `CustomIcon.name`, and
`Group.default_auto_type_sequence` MUST use `None` rather than `Some("")`.
Loaders map either wire spelling to `None`; mutation APIs normalize an explicit
clear to `None`; direct `Some("")` construction is rejected before save. Entry
foreground/background colors and override URL are not in this list because
their loader preserves present-empty distinctly.

For the remaining Option-typed entry fields that 005 encodes and that neither
§3, §5, nor the preceding paragraphs govern — `icon_id`, `expiry_time`,
`last_accessed_at`, `usage_count`, and `auto_type`, for current and history
entries alike — the wire spelling is pinned to the model spelling: the writer
emits the element only when the value is present, and the loader maps an
absent or whitespace-only element to `None`. Materializing a default
(`IconID` `0`, a default `AutoType` node, or any absent `Times` child) for an
absent model value is forbidden: it would change `C1` across a vaultkern
round trip and violate law 5. `Expires` is always written; `expiry_time`
alone follows the optional rule. The absent-or-whitespace-only rule applies
to typed scalar elements; the `AutoType` container itself is presence-based:
an absent `AutoType` element loads as `None`, while a present `AutoType`
element — even one with no children — loads as `Some` with each child mapped
individually, so `Some(AutoTypeConfig::default())` and `None` round-trip
distinctly. Inside a present `AutoType` element, the typed children
`Enabled` and `DataTransferObfuscation` are emitted only when modeled and
load absent or whitespace-only as `None`; `DefaultSequence` is a text child —
it is emitted whenever modeled, including empty or whitespace-only values,
and a present element loads verbatim under this section's
no-text-normalization rule. A present, non-blank typed element in these
fields or in those typed `AutoType` children whose content does not parse as
the field's type fails the load with a structured error rather than
collapsing to `None`, matching the UUID rule above.

`location_changed_at` is deliberately not in that group, because 001 decides
group membership by the newer `location_changed_at` and treats an absent
value as the epoch: an absent element that a third-party save later
materializes would manufacture a newer move fact that canonical-hash
tie-breaking cannot resolve, silently overriding a genuine move. In `P`,
every current and history entry has `location_changed_at = Some` and the
writer always emits `LocationChanged`. Entry-creation APIs set it to the
creation time and every move updates it. The loader canonicalizes an absent
or whitespace-only `LocationChanged` to the epoch (model value `0`) — exactly
the value 001 already assigns to absence, so merge semantics are unchanged
and any genuine move's present timestamp still wins — and a present,
non-parsing value fails the load. Epoch spellings therefore arise only from
loaded files that omitted the element. 001 r14 makes the location tie total:
whenever the two values are equal — and both-absent compares as the epoch —
with differing groups, the group-UUID ordering decides. Epoch-canonicalized
loads therefore take exactly the branch absence took; the canonicalization
is invisible to the merge layer, and 006 adds no merge rule of its own.

Accepted consequence, recorded deliberately: KeePass materializes these
elements unconditionally on its own saves, so a third-party save of a
vaultkern file that omitted them yields concrete values — for
`LastAccessTime`, even a third-party load-time value — where vaultkern stored
`None`, changing `C1` without a semantic edit. 001's same-second tie rule
resolves that divergence deterministically. Among these fields only
`usage_count` feeds a further 001 rule — it merges as the maximum — and a
third-party materialization of an absent value is `0`, the identity of that
maximum, so the accepted drift stays confined to the hash tie
(`location_changed_at`, which drives placement, is excluded above). Because
`None` and `Some(0)` are distinct canonical spellings, 001 r14 pins the
merged spelling of a numerically equal maximum to the present one —
`Some(0)` over `None` — so both merge directions converge on one `C1`; that
rule lives in 001, where merge decisions belong.
To keep vaultkern output KeePass-shaped, product entry-creation APIs MUST
populate the full KeePass-materialized set at creation: `icon_id`,
`auto_type`, `expiry_time` and `last_accessed_at` set to the creation time
(with `expires = false`), and `usage_count = Some(0)`, alongside the
`location_changed_at` requirement above. The `None` spellings then arise
only from third-party files that already omitted the elements, where the
drift pre-exists.

Interoperability basis: the pinned KeePass writer emits `CustomIconUUID` only
when `CustomIconUuid.IsZero` is false ([KeePass source at
`d1eec63`](https://github.com/dlech/KeePass2.x/blob/d1eec63f1bd73dc2d5273eaf94528f616b553ce5/KeePassLib/Serialization/KdbxFile.Write.cs)).

## 8. KDBX read and write capability

Read support and write support are separate capabilities. Recognizing a
legacy header does not authorize emitting that version.

The normative capability matrix is:

| KDBX version | Read | Write | Write condition |
|---|---|---|---|
| 2.0 | yes | no | reject as `UnsupportedVersion` |
| 3.0 | yes | no | reject as `UnsupportedVersion` |
| 3.1 | yes | no | reject as `UnsupportedVersion` |
| 4.0 | yes | yes | `minimum_write_version(v) <= 4.0` |
| 4.1 | yes | yes | always, subject to ordinary validation |

For this contract, `minimum_write_version(v) = 4.1` when any current or history
state contains at least one of the following:

1. a `CustomDataItem.last_modified` at Meta, Group, Entry, or history-Entry
   scope;
2. a custom-icon non-empty name or `last_modified` value;
3. a non-empty Group tag set;
4. `previous_parent` on a Group, current Entry, or history Entry;
5. `exclude_from_reports = true`, or retained `QualityCheck` known-node fidelity
   that requires emitting that element, on a current or history Entry;
6. a structured or projectable passkey source as observed through `A(e)`.

Items 1-5 are KDBX 4.1 XML features: item timestamps, custom-icon `Name` /
`LastModificationTime`, Group `Tags`, `PreviousParentGroup`, and Entry
`QualityCheck`. Their conditional emission is pinned by KeePass's
[`KdbxFile.Write.cs`](https://github.com/dlech/KeePass2.x/blob/d1eec63f1bd73dc2d5273eaf94528f616b553ce5/KeePassLib/Serialization/KdbxFile.Write.cs),
while KeePass's
[`GetMinKdbxVersion`](https://github.com/dlech/KeePass2.x/blob/d1eec63f1bd73dc2d5273eaf94528f616b553ce5/KeePassLib/Serialization/KdbxFile.cs)
independently checks Group tags, `QualityCheck`, custom-icon metadata, and Meta
CustomData timestamps. That helper is not exhaustive for vaultkern's modeled
scopes; this contract deliberately includes the other `Write.cs`-gated cases
so a forced 4.0 save cannot drop them. Item 6 is an explicit product
compatibility floor, not a claim that custom `String` nodes are physically
impossible in 4.0. Equivalent projection-backed and source-backed passkeys MUST
compute the same minimum version.

The list is exhaustive for the current model. Adding a modeled 4.1-only field
MUST update this list, the shared classifier, and the version matrix tests in
the same change. A raw-state spelling that requires a listed 4.1 element counts
even when its semantic value equals a default; fidelity cannot be dropped to
force a 4.0 save.

The writer MUST reject an unsupported version before constructing output. It
MUST NOT place a KDBX4 inner header, block stream, or XML policy under a KDBX2/3
version field. Write support also requires the version's standard timestamp,
binary-pool, protected-stream, and payload encodings; a parse-only compatibility
fallback is not a valid writer encoding.

Loading a KDBX2/3 vault and later saving it as KDBX4 is an explicit format
upgrade, not legacy write support. A future KDBX2/3 writer requires a numbered
design amendment plus format-specific header, payload, timestamp, binary-pool,
protected-stream, and external-fixture tests. Changing only the version enum or
header field can never establish support.

## 9. Validation boundary

Persistence validation MUST cover the whole vault graph before a save is
reported successful: Meta, every Group, every current Entry, and every history
Entry. At minimum it checks:

- the CustomData invariant in §4 at every scope;
- the attachment key/name invariant in §5 for current and history entries;
- every CustomData, attribute, and attachment key that KDBX requires to be
  non-empty;
- absence of `Title`, `UserName`, `Password`, `URL`, and `Notes` from
  `Entry.attributes`, because the structured fields are authoritative;
- non-empty tags containing neither `,` nor `;`, with no leading or trailing
  Unicode whitespace. KeePass splits on both delimiters and trims before
  replacing embedded separators, as pinned by
  [`StrUtil.cs`](https://github.com/dlech/KeePass2.x/blob/d1eec63f1bd73dc2d5273eaf94528f616b553ce5/KeePassLib/Utility/StrUtil.cs);
- the §3.1 structured-TOTP validity rules: `account_name` present and
  non-empty, and no `:` in the account when there is no issuer;
- `location_changed_at` present on every current and history entry (§7);
- the optional-text canonical form in §7 and every modeled UUID uniqueness /
  known-node multiplicity rule in §6;
- the requirement that a history snapshot's own `history` list is empty; KDBX
  has one history level and the writer MUST NOT discard a nested level;
- checked representability of every timestamp in the requested KDBX version's
  standard encoding; a non-standard decimal fallback is not writer support;
- other field constraints whose KDBX representation would otherwise be
  ambiguous or lossy;
- every anchor's one-based occurrence and same-scope predecessor validity,
  including references affected by an in-memory mutation;
- the requested write version and the vault's minimum required version.

The representation checks MUST have one reusable implementation shared by the
writer and focused invariant tests. Version/profile checks MAY be a KDBX-layer
extension of that result. A `ValidatedVault`-style wrapper is permitted but not
required; duplicating graph-validity rules in multiple serializers is not.

Validation MUST return a structured error and MUST NOT repair the state inside
the writer. An explicit model/core normalization operation MAY repair a state,
but it must be deterministic, visible to the caller, update every duplicate
representation atomically, and complete before canonical comparison or save.

### 9.1 DeletedObjects

001 defines a tombstone as an LWW fact. On load, duplicate `DeletedObject`
elements with the same UUID are therefore folded to the latest `deleted_at`;
an equal timestamp collapses to one fact. This is an explicit 001 semantic
normalization, not generic last-wins handling for duplicate known nodes.

A successful load and every product mutation state MUST contain exactly one
`DeletedObject` per non-zero UUID. A tombstone MAY share its UUID with a live
object because 001 compares their timestamps for delete-versus-resurrect. A
directly constructed vector with a nil or duplicate UUID is outside `P` and the
writer MUST reject it rather than silently folding it.
The writer emits exactly one element per UUID, in ascending raw UUID-byte order,
with the timestamp represented by `T(v)`. This is the explicit
order-insensitive scope from §6: child order is neither merge semantics nor
fidelity state, and a loader rejects unknown child elements rather than
preserving them as opaque XML. `T(v)`, not vector order, is the equality used
by §2 and 001.

## 10. Required verification

The implementation gate is a state matrix, not only example-based happy paths.
At minimum, tests cover:

| Dimension | Required cases |
|---|---|
| typed optional UUID | absent, empty, whitespace-only, nil sentinel, valid non-nil, malformed, direct `Some(nil)` rejection |
| optional/default model values | every `VG` default; every §7 optional-empty rejection; present-empty Entry color/URL preservation; absent↔`None` round-trip for every §7-pinned entry field and typed `AutoType` child (current and history); present-empty `AutoType` round-trip as `Some(default)`; empty and whitespace-only `DefaultSequence` preservation; malformed numeric/boolean element rejection; absent `LocationChanged` canonicalized to the epoch and always re-emitted |
| save profile | ordinary save reuses the loaded KDF salt with stable `kdf_generation`; rotation only on master-credential or explicit KDF parameter change; Argon2 `V` and unknown `KdfParameters` entries re-emitted verbatim with stable `kdf_generation`; KDBX3→4 upgrade changes `kdf_generation` per 002; product-created entry emits the full KeePass-shaped element set; two successive saves differ in master seed, outer IV, and inner random-stream key |
| TOTP | projection only; URI source only; discrete-only source retained verbatim and never projected; equivalent/conflicting projection cache; equivalent/conflicting URI plus discrete source; each alternate secret spelling; HOTP secret/counter; unknown/duplicate/malformed or invalid-UTF-8 URI query; malformed discrete parameters; lower-case and padded Base32 preservation; per-component label encoding; content-colon labels (issuer, account-with-issuer, title fallback); lowercase `%3a` separator parsing; no-issuer account-colon rejection; empty-`account_name` projection rejection with raw retention of empty-account labels; full-family clear/removal/protection/hiding |
| passkey | projection only, projectable source only, equivalent/conflicting cache, incomplete sensitive source, missing optional fields, invalid flag spelling, loaded strings verbatim, exact first-write base64url/PKCS#8 PEM profile |
| CustomData | empty, matched map/blocks, duplicate keys, timestamps, map-only mismatch, block-only mismatch, empty block |
| attachments | matched key/name, mismatched key/name rejection, rename, empty name |
| history graph | empty history, current entry with snapshots, nested-history rejection |
| known-node multiplicity | duplicate singleton, duplicate `String` key, duplicate `Binary` name, multiple CustomData blocks, live UUID collision |
| DeletedObjects | unique, duplicate earlier/later/equal timestamps on load, unknown-child rejection, input-order-independent UUID-sorted write-out, direct duplicate rejection |
| delimited/reserved fields | empty keys, reserved standard attribute names, empty tag, comma, semicolon, leading/trailing Unicode whitespace |
| timestamps | minimum, ordinary, maximum representable, below/above representable range rejection |
| anchors | retained keyed node, earlier removal/renumber, target removal, chained removal, multiple opaque fragments sharing one anchor, repeated unkeyed node token |
| opaque fragments | valid unknown element, malformed XML, known-node collision, dangling/forward anchor |
| write versions | 2.0, 3.0, 3.1 rejection; valid 4.0; each §8 item independently rejects under 4.0; equivalent passkey representations classify equally; valid 4.1 |
| secret lifecycle | materialized carrier redacts/omits `Debug` and zeroizes every owned reserved-secret copy on drop |
| non-entry graph | every Meta/Group modeled field and graph-order mutation is detected by `VG`; round-trip preserves `VG` under 4.0 and 4.1 |

The following test families are mandatory:

1. The frozen 005 minimal and fully populated byte goldens and digests under
   the discipline below.
2. Canonical determinism under different set/map construction orders.
3. `C1(load(save(entry))) = C1(entry)` for separate persistence-valid minimal
   and fully populated fixtures, credentials, duplicate CustomData items, and
   history entries under every supported write version.
4. Focused negative tests proving contradictory model states and unsupported
   write profiles fail rather than normalize silently.
5. Mutation-plus-round-trip tests for keyed repeated nodes, CustomData deletion,
   and opaque-anchor retargeting at Meta, Group, Entry, and history Entry
   scopes.
6. Real external KDBX fixtures for every claimed read version, plus mandatory
   KeePassXC CLI opening of vaultkern output for every claimed write version as
   specified below.
7. Property or model-based tests that generate valid combinations of
   projection/source, map/block, and anchor states and check the laws in §2.

Passing unit tests proves only covered cases. A release or merge gate claiming
this contract MUST report the matrix cells exercised, the external fixtures
used, and any deliberately unsupported cells.

### 10.1 Canonical golden discipline

The 005 goldens are intentionally inline in
`crates/vaultkern-model/src/canonical_serialization.rs` as
`MINIMAL_ENTRY_V1_HEX` / `MINIMAL_ENTRY_V1_SHA256_HEX` and
`FULL_ENTRY_V1_HEX` / `FULL_ENTRY_V1_SHA256_HEX`. Inline storage does not weaken
their status: they have the same never-silent-update discipline as the
`kdf_generation` fixtures. There MUST be no generic `BLESS` path. A change
requires review of the decoded full stream, the 005 versioning decision, and an
explicit contract commit.

Under `A(e)`, the current minimal golden is identical to the plain
`Entry.attributes` interpretation because it has no credential projection. The
fully populated golden is deliberately different: its 1173-byte stream and
SHA-256
`55979e79a38604f9dea969536290bdfc92864202db484614ff8c0e25ab4a54e2`
contain the materialized TOTP/passkey source map. The audited delta from the
obsolete plain-005 interpretation MUST be confined to field 9; framing and all
other 26 fields remain unchanged.
The freeze PR MUST include that decoded-stream comparison, or link to durable
evidence for it, showing byte-identical framing and byte-identical slices for
each of the other 26 fields. The checked-in
[field-9 golden audit](006-field9-golden-audit.md) and its executable
`full_entry_golden_delta_is_confined_to_field_9` test are that evidence.

The 005 goldens exercise `C1` over `M`; they are not persistence fixtures. The
minimal golden deliberately uses a nil Entry UUID. The fully populated golden
deliberately has attachment map keys that differ from redundant
`Attachment.name` values, independently populated CustomData map/block views,
and a non-resolving excluded anchor. Those states are outside `P` under this
document and MUST NOT be passed to `S_p`. Round-trip tests use separate
persistence-valid fixtures; they MUST NOT silently rewrite the canonical
goldens under the guise of making them saveable.

### 10.2 External interoperability evidence

The existing external read fixtures establish these distinct header versions:

| Claimed read version | Required external fixture | Header version |
|---|---|---|
| 2.0 | `Format200.kdbx` | `0x00020000` |
| 3.0 | `Format300.kdbx` | `0x00030000` |
| 3.1 | `SyncDatabase.kdbx` | `0x00030001` |
| 4.0 | `Format400.kdbx` | `0x00040000` |
| 4.1 | `crates/vaultkern-kdbx/tests/fixtures/keepassxc-2.7.6-kdbx4.1.kdbx` | `0x00040001` |

Thus a real 2.0 fixture exists and the 2.0 read claim is not downgraded. The 4.1
fixture was generated by KeePassXC 2.7.6 from its adjacent checked-in XML
source; that source uses group tags and `QualityCheck`, causing KeePassXC
itself to select `0x00040001`. Its provenance, public test password, generation
command, and SHA-256 are pinned in the fixture README. The external-fixture test
asserts the hash and header, decrypts the file, and checks those 4.1-only fields
plus known entry values. It is not a self-generated vaultkern substitute.

For writes, CI MUST save at least one vault under each claimed profile version
(4.0 and 4.1), then use `keepassxc-cli` to decrypt and enumerate the output
(for example with `db-info` plus an entry-read/list command). Process exit alone
is insufficient if no encrypted payload is read. The test MUST assert the
raw header version and at least one known semantic value. This gate is mandatory
on every claimed write version, not conditional on whether a "suitable fixture
harness" happens to exist. It is implemented as the `KDBX Interoperability`
workflow at `.github/workflows/kdbx-interoperability.yml`, which saves both
versions, independently checks their raw version words, then uses
`keepassxc-cli ls` and `show` to decrypt, enumerate, and assert a sentinel
username.

Freeze evidence was produced before this documentation-only freeze in
[Wave 4A PR #34](https://github.com/vaultkern/vaultkern/pull/34). The
corresponding
[`KDBX Interoperability` run](https://github.com/vaultkern/vaultkern/actions/runs/29553222382)
passed the field-9 audit, the external 4.1 read, and the KeePassXC 4.0/4.1
decrypt-and-enumerate gates. The implementation PR is sequenced after this
document PR; rebasing or merging it MUST preserve these artifacts and gates.
Until it lands, the workflow, the 4.1 fixture, and the executable audit are
not on `main`, and the §8 write-capability claims are unexercised there. An
implementation PR MUST NOT claim this contract's write capability unless
these gates are present and passing in its own tree, and the first
implementation PR to land MUST carry them.

## 11. Change procedure

- The r4 freeze commit revises 000 to r14 and expands D1 through both 001 and
  006. It revises 005 to r14 and records that field 9's operational source is
  `A(e)`, superseding 005 §4's assumption that source attributes always remain
  directly in `Entry.attributes`.
- The r4 freeze audit rechecked 001 r13 and found no equivalent
  projection/source-of-truth contradiction: 001 delegates the canonical layout
  to 005 and does not state where credential backing attributes live. No 001
  amendment was required on that axis. (001 r14, coordinated with r5, later
  totalized two tie rules — an unrelated, purely gap-filling change.)
- The checked-in external KDBX 4.1 fixture and mandatory KeePassXC 4.0/4.1
  writer-open gates described in §10.2 are permanent freeze evidence and MUST
  remain passing.
- A change to the 27 fields, primitive encoding, framing, or `A(e)` output for
  an already-valid entry follows 005's canonical `schema_version` process.
- Adding write support for a KDBX version amends the matrix in §8 and adds its
  external interoperability fixtures before the capability is advertised.
- Changing anchor-retargeting behavior or weakening fidelity preservation
  requires a numbered amendment; it is not an implementation detail.
- Implementations MUST describe a completed review as "no new findings under
  the recorded matrix and threat model", never as proof that no defect can
  exist.

## 12. Revision history

- r5 (2026-07-17): amendments for the post-merge review rounds on PR #35 and
  PR #36, plus a full-document coherence pass. Redefines the save profile as
  algorithm/work-factor parameters only and places the KDF salt lifecycle
  under 002's rotation policy (ordinary saves reuse the salt; rotation only
  on master-credential or explicit KDF change). Pins the absent↔`None` wire
  mapping for the previously ungoverned Option-typed entry fields — including
  all three optional `AutoType` children — forbids default materialization,
  makes malformed elements fail the load, and records the accepted
  third-party materialization consequence together with a normative
  creation-population rule for `icon_id` and `auto_type`. Excludes
  `location_changed_at` from that group because it drives 001's move
  decision: `P` requires it present, the loader canonicalizes absence to the
  epoch value 001 already assigns to it, and the writer always emits it. Pins
  literal-`:`-first label parsing — with hex-case-insensitive encoded
  separator matching — and places the non-invertible no-issuer content-colon
  TOTP spelling outside `P`. A third review round refined the container/text
  distinctions: present-empty `AutoType` loads as `Some` with children mapped
  individually, `DefaultSequence` text is preserved verbatim, and
  `usage_count`'s 001 max-merge rule is acknowledged with materialized
  absence as its identity element. A fourth round: ordinary saves re-emit the
  full loaded `KdfParameters` verbatim (`kdf_generation` stable by
  construction), the epoch canonicalization is recorded as merge-invisible
  via 001's own absent≡epoch equivalence, numerically equal `usage_count`
  maxima resolve to the present spelling, and 000 r15 records this amendment
  in the decision ledger. A fifth round: the `KdfParameters` stability
  mandate carves out the KDBX3→4 format upgrade (002's generation change
  stands), `P` requires a non-empty TOTP `account_name` with empty-account
  labels retained as raw source (username/title fallbacks stay defined only
  so `C1` is total over `M`), and creation populates the full
  KeePass-materialized field set. A sixth round: the retained `KdfParameters`
  dictionary becomes required vault fidelity state behind an optional profile
  KDF component with an explicit `kdf_generation` stability equation,
  discrete-only TOTP sources are retained verbatim instead of projected
  (they carry no account), and the two merge-tie spellings move into 001 r14
  where merge decisions belong. States plainly that the §10.2 workflow,
  4.1 fixture, and
  executable audit are not yet on `main` and forbids write-capability claims
  from any tree that lacks them. A seventh round restates 001's location
  comparison as normalize-absence-then-compare (honestly recording the
  degenerate absent-versus-present-epoch corner as the one changed outcome)
  and excludes empty-account URIs from projectability. The canonical byte
  layout and the frozen golden bytes are unchanged — both goldens'
  credentials are structured-projection-backed, a path r5 does not touch —
  but `A(e)` output does change relative to r4 for one class: a raw
  discrete-only TOTP source is now retained verbatim instead of being
  materialized through the canonical URI. That change rides the same
  pre-ship window as introducing `A(e)` itself (canonical v1 has no shipped
  merge consumer) and is recorded here for the §3.2-mandated review; the
  parser precedence and `LocationChanged` canonicalization likewise predate
  any shipped dependency, so the 005 `schema_version` process is not
  triggered. A closing full-document pass caught two of its own corners: an
  empty-issuer label whose account contains a colon is excluded from
  projectability, preserving the parser invariant, and a newly created
  vault's first save constructs its `KdfParameters` dictionary as an
  explicit-change equivalent. An eighth round generalizes that guard into
  one final projectability gate that also covers empty `issuer` query
  values, pins 001's group-UUID tie to the byte-wise greater UUID (005 §6's
  greater-wins direction), and mirrors the epoch-corner exception into
  000 r15.
- r4 (2026-07-17): frozen after r3 review. Records passed evidence for an
  external KeePassXC-generated KDBX 4.1 fixture, mandatory 4.0/4.1
  `keepassxc-cli` decrypt/enumerate gates, and the executable field-9-only
  golden audit; rechecks 001 r13 with no amendment required; coordinates the
  000/005 r14 annotations; and records the documentation-first merge order.
- r3 (2026-07-17): declares `DeletedObjects` an order-insensitive scope whose
  only semantics are `T(v)`, excludes opaque fragments and anchors from that
  scope, requires unknown-child rejection, cross-links §6 and §9.1, and makes
  the field-9-only golden audit evidence explicit for the freeze PR.
- r2 (2026-07-17): incorporates contract review. Expands the complete
  TOTP/HOTP reserved namespace and conservative projectability rules; pins URI,
  Base32, and first-write passkey spellings; classifies authoritative caches
  versus co-equal replicas; records both `A(e)` normalizations and its D5 secret
  lifecycle; defines save profiles, Meta/Group structural equality, known-node
  multiplicity, tag validity, DeletedObjects folding/write-out, and the
  exhaustive 4.1 minimum-version list; pins inline-golden discipline and real
  external-fixture/KeePassXC gates; and requires coordinated 000/005 freeze
  annotations after auditing 001.
- r1 (2026-07-17): initial proposal. Defines persistence-valid model states,
  the field-9 materialization adapter, credential fallback behavior,
  CustomData map/block consistency, generic and CustomData-specific anchor
  retargeting, attachment key/name consistency, optional UUID parsing,
  opaque-fragment validity, history/timestamp validation, the KDBX
  read/write capability matrix, and executable round-trip/negative-test gates.
