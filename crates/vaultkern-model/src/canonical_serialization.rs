use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    AttachmentContentId, AutoTypeConfig, CustomDataBlock, Entry, EntryFieldProtection,
    MaterializedPersistentAttributes, materialize_entry_persistent_attributes,
};

pub const CANONICAL_SERIALIZATION_MAGIC: [u8; 4] = *b"VKCS";
pub const CANONICAL_ENTRY_SCHEMA_VERSION_V1: u32 = 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CanonicalSerializationError {
    #[error("canonical byte string length {length} exceeds u32")]
    ByteLengthOverflow { length: usize },
    #[error("canonical collection count {count} exceeds u32")]
    CollectionCountOverflow { count: usize },
}

fn checked_byte_length(length: usize) -> Result<u32, CanonicalSerializationError> {
    u32::try_from(length).map_err(|_| CanonicalSerializationError::ByteLengthOverflow { length })
}

fn checked_collection_count(count: usize) -> Result<u32, CanonicalSerializationError> {
    u32::try_from(count).map_err(|_| CanonicalSerializationError::CollectionCountOverflow { count })
}

trait CanonicalByteString {
    fn byte_length(&self) -> usize;
    fn bytes(&self) -> &[u8];
}

impl CanonicalByteString for [u8] {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn bytes(&self) -> &[u8] {
        self
    }
}

impl CanonicalByteString for str {
    fn byte_length(&self) -> usize {
        self.len()
    }

    fn bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone, Copy)]
struct AttachmentReference {
    protect_in_memory: bool,
    content_id: AttachmentContentId,
}

fn collect_attachment_references<'a, V>(
    entries: impl ExactSizeIterator<Item = (&'a str, V)>,
    mut project: impl FnMut(V) -> AttachmentReference,
) -> Result<Vec<(&'a str, AttachmentReference)>, CanonicalSerializationError> {
    checked_collection_count(entries.len())?;
    Ok(entries
        .map(|(key, attachment)| (key, project(attachment)))
        .collect())
}

#[derive(Clone, Copy)]
struct CanonicalCustomDataItem<'a> {
    value: &'a str,
    last_modified: Option<i64>,
}

fn collect_custom_data_items<'a>(
    blocks: &'a [CustomDataBlock],
) -> BTreeMap<&'a str, CanonicalCustomDataItem<'a>> {
    let mut items = BTreeMap::new();
    for block in blocks {
        for item in &block.items {
            items.insert(
                item.key.as_str(),
                CanonicalCustomDataItem {
                    value: &item.value,
                    last_modified: item.last_modified,
                },
            );
        }
    }
    items
}

struct CanonicalEntryReference<'a> {
    id: &'a Uuid,
    title: &'a str,
    username: &'a str,
    password: &'a str,
    url: &'a str,
    notes: &'a str,
    field_protection: &'a EntryFieldProtection,
    tags: &'a BTreeSet<String>,
    attributes: MaterializedPersistentAttributes<'a>,
    attachments: Vec<(&'a str, AttachmentReference)>,
    icon_id: &'a Option<u32>,
    custom_icon_id: &'a Option<Uuid>,
    foreground_color: &'a Option<String>,
    background_color: &'a Option<String>,
    override_url: &'a Option<String>,
    created_at: u64,
    modified_at: u64,
    expires: bool,
    expiry_time: &'a Option<i64>,
    last_accessed_at: &'a Option<u64>,
    usage_count: &'a Option<u64>,
    location_changed_at: &'a Option<u64>,
    previous_parent: &'a Option<Uuid>,
    auto_type: &'a Option<AutoTypeConfig>,
    custom_data: &'a BTreeMap<String, String>,
    custom_data_items: BTreeMap<&'a str, CanonicalCustomDataItem<'a>>,
    exclude_from_reports: bool,
}

// This is the sole full-model boundary; the encoder only receives v1 fields and content IDs.
impl<'a> TryFrom<&'a Entry> for CanonicalEntryReference<'a> {
    type Error = CanonicalSerializationError;

    fn try_from(entry: &'a Entry) -> Result<Self, Self::Error> {
        let attributes = materialize_entry_persistent_attributes(entry);
        let Entry {
            id,
            title,
            username,
            password,
            url,
            notes,
            field_protection,
            tags,
            attributes: _,
            attachments,
            history: _,
            totp: _,
            passkey: _,
            icon_id,
            custom_icon_id,
            foreground_color,
            background_color,
            override_url,
            created_at,
            modified_at,
            expires,
            expiry_time,
            last_accessed_at,
            usage_count,
            location_changed_at,
            auto_type,
            custom_data,
            custom_data_blocks,
            previous_parent,
            exclude_from_reports,
            raw_state: _,
            opaque_xml: _,
        } = entry;
        let attachments = collect_attachment_references(
            attachments
                .iter()
                .map(|(key, attachment)| (key.as_str(), attachment)),
            |attachment| AttachmentReference {
                protect_in_memory: attachment.protect_in_memory,
                content_id: attachment.data.id(),
            },
        )?;
        let custom_data_items = collect_custom_data_items(custom_data_blocks);

        Ok(Self {
            id,
            title,
            username,
            password,
            url,
            notes,
            field_protection,
            tags,
            attributes,
            attachments,
            icon_id,
            custom_icon_id,
            foreground_color,
            background_color,
            override_url,
            created_at: *created_at,
            modified_at: *modified_at,
            expires: *expires,
            expiry_time,
            last_accessed_at,
            usage_count,
            location_changed_at,
            previous_parent,
            auto_type,
            custom_data,
            custom_data_items,
            exclude_from_reports: *exclude_from_reports,
        })
    }
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn with_v1_framing() -> Self {
        let mut encoder = Self::default();
        encoder.write_raw(&CANONICAL_SERIALIZATION_MAGIC);
        encoder.write_u32(CANONICAL_ENTRY_SCHEMA_VERSION_V1);
        encoder
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    fn write_raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn write_bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    fn write_u32(&mut self, value: u32) {
        self.write_raw(&value.to_le_bytes());
    }

    fn write_i32(&mut self, value: i32) {
        self.write_raw(&value.to_le_bytes());
    }

    fn write_u64(&mut self, value: u64) {
        self.write_raw(&value.to_le_bytes());
    }

    fn write_i64(&mut self, value: i64) {
        self.write_raw(&value.to_le_bytes());
    }

    fn write_byte_length(&mut self, length: usize) -> Result<(), CanonicalSerializationError> {
        self.write_u32(checked_byte_length(length)?);
        Ok(())
    }

    fn write_count(&mut self, count: usize) -> Result<(), CanonicalSerializationError> {
        self.write_u32(checked_collection_count(count)?);
        Ok(())
    }

    fn write_bytes<T: CanonicalByteString + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalSerializationError> {
        self.write_byte_length(value.byte_length())?;
        self.write_raw(value.bytes());
        Ok(())
    }

    fn write_text(&mut self, value: &str) -> Result<(), CanonicalSerializationError> {
        self.write_bytes(value)
    }

    fn write_uuid(&mut self, value: &Uuid) {
        self.write_raw(value.as_bytes());
    }

    fn write_option<T>(
        &mut self,
        value: Option<&T>,
        write_value: impl FnOnce(&mut Self, &T) -> Result<(), CanonicalSerializationError>,
    ) -> Result<(), CanonicalSerializationError> {
        match value {
            Some(value) => {
                self.bytes.push(1);
                write_value(self, value)
            }
            None => {
                self.bytes.push(0);
                Ok(())
            }
        }
    }

    fn write_list<'a, T: 'a>(
        &mut self,
        values: impl ExactSizeIterator<Item = &'a T>,
        mut write_value: impl FnMut(&mut Self, &T) -> Result<(), CanonicalSerializationError>,
    ) -> Result<(), CanonicalSerializationError> {
        self.write_count(values.len())?;
        for value in values {
            write_value(self, value)?;
        }
        Ok(())
    }

    fn write_set<'a, T: 'a>(
        &mut self,
        values: impl ExactSizeIterator<Item = &'a T>,
        mut write_value: impl FnMut(&mut Self, &T) -> Result<(), CanonicalSerializationError>,
    ) -> Result<(), CanonicalSerializationError> {
        let count = values.len();
        self.write_count(count)?;
        let mut encoded_values = Vec::with_capacity(count);
        for value in values {
            let mut encoded_value = Self::default();
            write_value(&mut encoded_value, value)?;
            encoded_values.push(encoded_value.into_bytes());
        }
        encoded_values.sort_unstable();
        for encoded_value in encoded_values {
            self.write_raw(&encoded_value);
        }
        Ok(())
    }

    fn write_string_map<'a, V>(
        &mut self,
        entries: impl ExactSizeIterator<Item = (&'a str, V)>,
        mut write_value: impl FnMut(&mut Self, V) -> Result<(), CanonicalSerializationError>,
    ) -> Result<(), CanonicalSerializationError> {
        let count = entries.len();
        self.write_count(count)?;
        let mut entries: Vec<_> = entries.collect();
        entries.sort_unstable_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        for (key, value) in entries {
            self.write_text(key)?;
            write_value(self, value)?;
        }
        Ok(())
    }

    fn write_attachment_map<'a>(
        &mut self,
        entries: impl ExactSizeIterator<Item = (&'a str, AttachmentReference)>,
    ) -> Result<(), CanonicalSerializationError> {
        self.write_string_map(entries, |encoder, attachment| {
            encoder.write_bool(attachment.protect_in_memory);
            encoder.write_raw(attachment.content_id.as_bytes());
            Ok(())
        })
    }
}

fn canonical_entry_reference_bytes_v1(
    entry: CanonicalEntryReference<'_>,
) -> Result<Vec<u8>, CanonicalSerializationError> {
    let mut encoder = Encoder::with_v1_framing();

    encoder.write_uuid(entry.id);
    encoder.write_text(entry.title)?;
    encoder.write_text(entry.username)?;
    encoder.write_text(entry.password)?;
    encoder.write_text(entry.url)?;
    encoder.write_text(entry.notes)?;

    encoder.write_bool(entry.field_protection.protect_title);
    encoder.write_bool(entry.field_protection.protect_username);
    encoder.write_bool(entry.field_protection.protect_password);
    encoder.write_bool(entry.field_protection.protect_url);
    encoder.write_bool(entry.field_protection.protect_notes);

    encoder.write_set(entry.tags.iter(), |encoder, tag| encoder.write_text(tag))?;
    encoder.write_string_map(entry.attributes.iter(), |encoder, field| {
        encoder.write_text(field.value())?;
        encoder.write_bool(field.protected());
        Ok(())
    })?;
    encoder.write_attachment_map(entry.attachments.into_iter())?;

    encoder.write_option(entry.icon_id.as_ref(), |encoder, value| {
        encoder.write_u32(*value);
        Ok(())
    })?;
    encoder.write_option(entry.custom_icon_id.as_ref(), |encoder, value| {
        encoder.write_uuid(value);
        Ok(())
    })?;
    encoder.write_option(entry.foreground_color.as_ref(), |encoder, value| {
        encoder.write_text(value)
    })?;
    encoder.write_option(entry.background_color.as_ref(), |encoder, value| {
        encoder.write_text(value)
    })?;
    encoder.write_option(entry.override_url.as_ref(), |encoder, value| {
        encoder.write_text(value)
    })?;

    encoder.write_u64(entry.created_at);
    encoder.write_u64(entry.modified_at);
    encoder.write_bool(entry.expires);
    encoder.write_option(entry.expiry_time.as_ref(), |encoder, value| {
        encoder.write_i64(*value);
        Ok(())
    })?;
    encoder.write_option(entry.last_accessed_at.as_ref(), |encoder, value| {
        encoder.write_u64(*value);
        Ok(())
    })?;
    encoder.write_option(entry.usage_count.as_ref(), |encoder, value| {
        encoder.write_u64(*value);
        Ok(())
    })?;
    encoder.write_option(entry.location_changed_at.as_ref(), |encoder, value| {
        encoder.write_u64(*value);
        Ok(())
    })?;
    encoder.write_option(entry.previous_parent.as_ref(), |encoder, value| {
        encoder.write_uuid(value);
        Ok(())
    })?;

    encoder.write_option(entry.auto_type.as_ref(), |encoder, auto_type| {
        encoder.write_option(auto_type.enabled.as_ref(), |encoder, value| {
            encoder.write_bool(*value);
            Ok(())
        })?;
        encoder.write_option(auto_type.obfuscation.as_ref(), |encoder, value| {
            encoder.write_i32(*value);
            Ok(())
        })?;
        encoder.write_option(auto_type.default_sequence.as_ref(), |encoder, value| {
            encoder.write_text(value)
        })?;
        encoder.write_list(auto_type.associations.iter(), |encoder, association| {
            encoder.write_text(&association.window)?;
            encoder.write_text(&association.sequence)
        })
    })?;

    encoder.write_string_map(
        entry
            .custom_data
            .iter()
            .map(|(key, value)| (key.as_str(), value)),
        |encoder, value| encoder.write_text(value),
    )?;

    encoder.write_string_map(entry.custom_data_items.into_iter(), |encoder, item| {
        encoder.write_text(item.value)?;
        encoder.write_option(item.last_modified.as_ref(), |encoder, value| {
            encoder.write_i64(*value);
            Ok(())
        })
    })?;

    encoder.write_bool(entry.exclude_from_reports);
    Ok(encoder.into_bytes())
}

pub fn canonical_entry_bytes_v1(entry: &Entry) -> Result<Vec<u8>, CanonicalSerializationError> {
    canonical_entry_reference_bytes_v1(CanonicalEntryReference::try_from(entry)?)
}

pub fn canonical_entry_content_hash_v1(
    entry: &Entry,
) -> Result<[u8; 32], CanonicalSerializationError> {
    let bytes = Zeroizing::new(canonical_entry_bytes_v1(entry)?);
    Ok(vaultkern_crypto::sha256_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    #[cfg(target_os = "windows")]
    use std::ffi::c_void;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::ffi::{c_int, c_long, c_void};
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    use std::process::{Command, Stdio};

    use data_encoding::HEXLOWER;
    use uuid::Uuid;

    use super::{
        AttachmentReference, CANONICAL_ENTRY_SCHEMA_VERSION_V1, CANONICAL_SERIALIZATION_MAGIC,
        CanonicalByteString, CanonicalEntryReference, CanonicalSerializationError, Encoder,
        canonical_entry_bytes_v1, canonical_entry_content_hash_v1,
        canonical_entry_reference_bytes_v1, collect_attachment_references,
    };
    use crate::{
        Attachment, AttachmentContent, AttachmentContentId, AutoTypeAssociation, AutoTypeConfig,
        CustomDataBlock, CustomDataItem, CustomField, Entry, EntryFieldProtection, EntryRawState,
        OpaqueXmlAnchor, OpaqueXmlFragment, PasskeyRecord, TotpAlgorithm, TotpSpec,
        materialize_entry_persistent_attributes,
    };

    const MINIMAL_ENTRY_V1_HEX: &str = concat!(
        "564b435301000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000010000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000",
    );
    const MINIMAL_ENTRY_V1_SHA256_HEX: &str =
        "6c78c2c817b6b80671503ba0ea9e29f93b5026540c9fdfd42429923f4257604c";
    const FULL_ENTRY_V1_HEX: &str = concat!(
        "564b435301000000000102030405060708090a0b0c0d0e0f05000000436166c3",
        "a906000000e794a8e688b7090000007040737377c3b672641a00000068747470",
        "733a2f2fe4be8b2e6578616d706c652fe799bbe5bd95110000006c696e65206f",
        "6e650a6c696e652074776f010001010003000000010000006202000000616102",
        "000000c3a90f0000001a0000004b5045585f504153534b45595f43524544454e",
        "5449414c5f49440a00000063726564656e7469616c01140000004b5045585f50",
        "4153534b45595f464c41475f4245010000003100140000004b5045585f504153",
        "534b45595f464c41475f42530100000030001e0000004b5045585f504153534b",
        "45595f47454e4552415445445f555345525f49440900000067656e6572617465",
        "64001c0000004b5045585f504153534b45595f505249564154455f4b45595f50",
        "454d0b000000707269766174652d6b6579011a0000004b5045585f504153534b",
        "45595f52454c59494e475f50415254590b0000006578616d706c652e636f6d00",
        "150000004b5045585f504153534b45595f555345524e414d4505000000616c69",
        "636500180000004b5045585f504153534b45595f555345525f48414e444c4506",
        "00000068616e646c65011100000054696d654f74702d416c676f726974686d0c",
        "000000484d41432d5348412d323536000e00000054696d654f74702d4c656e67",
        "74680100000038000e00000054696d654f74702d506572696f64020000003435",
        "001500000054696d654f74702d5365637265742d426173653332100000004a42",
        "5357593344504548504b3350585001030000006f74708e0000006f7470617574",
        "683a2f2f746f74702f254534254245253842253230436f72703a616c69636525",
        "324270726f642534306578616d706c652e636f6d3f7365637265743d4a425357",
        "593344504548504b33505850266973737565723d254534254245253842253230",
        "436f727026616c676f726974686d3d534841323536266469676974733d382670",
        "6572696f643d343501010000007a05000000706c61696e0002000000c3a90600",
        "0000e7a798e5af860102000000050000007a2e62696e00381be1088d25cbd5ac",
        "5a31056329ef74062114bcb70af9ab2df3a3c4707f024506000000c3a92e6269",
        "6e0134e248fa5bfa5ae571d4174848b6e188234a05006a9609ee4617b0688913",
        "e41c010403020101101112131415161718191a1b1c1d1e1f0107000000233131",
        "323233330103000000e8939d010a000000636d643a2f2f6f70656e0807060504",
        "03020118171615141312110101feffffffffffffff0128272625242322210138",
        "3736353433323101484746454443424101f0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
        "ff01010001feffffff01200000007b555345524e414d457d7b5441427d7b5041",
        "5353574f52447d7b454e5445527d0200000004000000e4be8b2a0a0000007b50",
        "415353574f52447d0500000041646d696e0a0000007b555345524e414d457d02",
        "000000010000007a040000006c61737402000000c3a906000000616363656e74",
        "0200000003000000647570040000006c617374017b0000000000000004000000",
        "6f6e6c7903000000e4b88001f9ffffffffffffff01",
    );
    const FULL_ENTRY_V1_SHA256_HEX: &str =
        "55979e79a38604f9dea969536290bdfc92864202db484614ff8c0e25ab4a54e2";
    const OBSOLETE_PLAIN_005_FULL_ENTRY_V1_HEX: &str = concat!(
        "564b435301000000000102030405060708090a0b0c0d0e0f05000000436166c3",
        "a906000000e794a8e688b7090000007040737377c3b672641a00000068747470",
        "733a2f2fe4be8b2e6578616d706c652fe799bbe5bd95110000006c696e65206f",
        "6e650a6c696e652074776f010001010003000000010000006202000000616102",
        "000000c3a902000000010000007a05000000706c61696e0002000000c3a90600",
        "0000e7a798e5af860102000000050000007a2e62696e00381be1088d25cbd5ac",
        "5a31056329ef74062114bcb70af9ab2df3a3c4707f024506000000c3a92e6269",
        "6e0134e248fa5bfa5ae571d4174848b6e188234a05006a9609ee4617b0688913",
        "e41c010403020101101112131415161718191a1b1c1d1e1f0107000000233131",
        "323233330103000000e8939d010a000000636d643a2f2f6f70656e0807060504",
        "03020118171615141312110101feffffffffffffff0128272625242322210138",
        "3736353433323101484746454443424101f0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
        "ff01010001feffffff01200000007b555345524e414d457d7b5441427d7b5041",
        "5353574f52447d7b454e5445527d0200000004000000e4be8b2a0a0000007b50",
        "415353574f52447d0500000041646d696e0a0000007b555345524e414d457d02",
        "000000010000007a040000006c61737402000000c3a906000000616363656e74",
        "0200000003000000647570040000006c617374017b0000000000000004000000",
        "6f6e6c7903000000e4b88001f9ffffffffffffff01",
    );
    const OBSOLETE_PLAIN_005_FULL_ENTRY_V1_SHA256_HEX: &str =
        "b67612dd8309382583d1b1a132b599ae734f6427332a557dd4da07261a7616e6";
    type EntryMutation = (&'static str, fn(&mut Entry));
    type PositionedEntryMutation = (&'static str, usize, fn(&mut Entry));
    type PositionedFieldProtectionMutation = (&'static str, usize, fn(&mut EntryFieldProtection));

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const GUARDED_REGION_LENGTH: usize = 64 * 1024;
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const NO_READ_CHILD_ENV: &str = "VAULTKERN_CANONICAL_NO_READ_SCENARIO";
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const NO_READ_CHILD_SUCCESS: i32 = 86;

    // No-read probes page-protect allocator-backed Vec storage inside a disposable child process.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            length: usize,
            protection: c_int,
            flags: c_int,
            descriptor: c_int,
            offset: c_long,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn allocate_guarded_region() -> *mut u8 {
        const PROT_READ: c_int = 1;
        const PROT_WRITE: c_int = 2;
        const MAP_PRIVATE: c_int = 2;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: c_int = 0x20;
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: c_int = 0x1000;

        let region = unsafe {
            mmap(
                std::ptr::null_mut(),
                GUARDED_REGION_LENGTH,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if region == (-1_isize) as *mut c_void {
            std::ptr::null_mut()
        } else {
            region.cast()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn protect_guarded_region(region: *mut u8) -> bool {
        unsafe { mprotect(region.cast(), GUARDED_REGION_LENGTH, 0) == 0 }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn release_guarded_region(region: *mut u8) {
        let _ = unsafe { munmap(region.cast(), GUARDED_REGION_LENGTH) };
    }

    #[cfg(target_os = "windows")]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "VirtualAlloc"]
        fn virtual_alloc(
            address: *mut c_void,
            size: usize,
            allocation_type: u32,
            protection: u32,
        ) -> *mut c_void;
        #[link_name = "VirtualProtect"]
        fn virtual_protect(
            address: *mut c_void,
            size: usize,
            new_protection: u32,
            old_protection: *mut u32,
        ) -> i32;
        #[link_name = "VirtualFree"]
        fn virtual_free(address: *mut c_void, size: usize, free_type: u32) -> i32;
    }

    #[cfg(target_os = "windows")]
    fn allocate_guarded_region() -> *mut u8 {
        const MEM_COMMIT_AND_RESERVE: u32 = 0x3000;
        const PAGE_READWRITE: u32 = 0x04;

        unsafe {
            virtual_alloc(
                std::ptr::null_mut(),
                GUARDED_REGION_LENGTH,
                MEM_COMMIT_AND_RESERVE,
                PAGE_READWRITE,
            )
            .cast()
        }
    }

    #[cfg(target_os = "windows")]
    fn protect_guarded_region(region: *mut u8) -> bool {
        const PAGE_NOACCESS: u32 = 0x01;
        let mut old_protection = 0;
        unsafe {
            virtual_protect(
                region.cast(),
                GUARDED_REGION_LENGTH,
                PAGE_NOACCESS,
                &mut old_protection,
            ) != 0
        }
    }

    #[cfg(target_os = "windows")]
    fn release_guarded_region(region: *mut u8) {
        const MEM_RELEASE: u32 = 0x8000;
        let _ = unsafe { virtual_free(region.cast(), 0, MEM_RELEASE) };
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[derive(Clone, Copy)]
    struct GuardedAllocationState {
        requested_size: usize,
        pointer: *mut u8,
    }

    thread_local! {
        static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
        static TRACKED_ALLOCATION_BYTES: Cell<usize> = const { Cell::new(0) };
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        static GUARDED_ALLOCATION: Cell<GuardedAllocationState> = const {
            Cell::new(GuardedAllocationState {
                requested_size: 0,
                pointer: std::ptr::null_mut(),
            })
        };
    }

    struct TrackingAllocator;

    #[global_allocator]
    static TEST_ALLOCATOR: TrackingAllocator = TrackingAllocator;

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn request_guarded_allocation(size: usize) {
        GUARDED_ALLOCATION.with(|guarded| {
            let mut state = guarded.get();
            assert!(
                state.pointer.is_null(),
                "guarded allocation is still active"
            );
            assert_eq!(state.requested_size, 0, "guarded allocation is nested");
            state.requested_size = size;
            guarded.set(state);
        });
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn try_allocate_guarded(layout: Layout) -> Option<*mut u8> {
        let requested = GUARDED_ALLOCATION
            .try_with(|guarded| {
                let mut state = guarded.get();
                if state.requested_size != layout.size() {
                    return false;
                }
                state.requested_size = 0;
                guarded.set(state);
                true
            })
            .unwrap_or(false);
        if !requested {
            return None;
        }
        if layout.size() > GUARDED_REGION_LENGTH || layout.align() > 4096 {
            return Some(std::ptr::null_mut());
        }

        let pointer = allocate_guarded_region();
        if !pointer.is_null()
            && GUARDED_ALLOCATION
                .try_with(|guarded| {
                    let mut state = guarded.get();
                    state.pointer = pointer;
                    guarded.set(state);
                })
                .is_err()
        {
            release_guarded_region(pointer);
            return Some(std::ptr::null_mut());
        }
        Some(pointer)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn guarded_allocation_pointer() -> *mut u8 {
        GUARDED_ALLOCATION
            .try_with(|guarded| guarded.get().pointer)
            .unwrap_or(std::ptr::null_mut())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn take_guarded_allocation(pointer: *mut u8) -> bool {
        GUARDED_ALLOCATION
            .try_with(|guarded| {
                let mut state = guarded.get();
                if state.pointer != pointer {
                    return false;
                }
                state.pointer = std::ptr::null_mut();
                guarded.set(state);
                true
            })
            .unwrap_or(false)
    }

    // Ordinary test allocations use the system allocator; tracking and guarded probes are thread-local.
    unsafe impl GlobalAlloc for TrackingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record_allocation(layout.size());
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            if let Some(pointer) = try_allocate_guarded(layout) {
                return pointer;
            }
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record_allocation(layout.size());
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            if let Some(pointer) = try_allocate_guarded(layout) {
                return pointer;
            }
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            if take_guarded_allocation(pointer) {
                release_guarded_region(pointer);
                return;
            }
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record_allocation(new_size);
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            if guarded_allocation_pointer() == pointer {
                let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
                    return std::ptr::null_mut();
                };
                let new_pointer = unsafe { System.alloc(new_layout) };
                if new_pointer.is_null() {
                    return new_pointer;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        pointer,
                        new_pointer,
                        layout.size().min(new_size),
                    );
                }
                let _ = take_guarded_allocation(pointer);
                release_guarded_region(pointer);
                return new_pointer;
            }
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }

    fn record_allocation(size: usize) {
        let tracking = TRACK_ALLOCATIONS
            .try_with(|tracking| tracking.get())
            .unwrap_or(false);
        if tracking {
            let _ = TRACKED_ALLOCATION_BYTES.try_with(|total| {
                total.set(total.get().saturating_add(size));
            });
        }
    }

    struct AllocationTrackingGuard;

    impl Drop for AllocationTrackingGuard {
        fn drop(&mut self) {
            let _ = TRACK_ALLOCATIONS.try_with(|tracking| tracking.set(false));
        }
    }

    fn allocated_bytes_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
        TRACKED_ALLOCATION_BYTES.with(|total| total.set(0));
        TRACK_ALLOCATIONS.with(|tracking| {
            assert!(!tracking.replace(true), "allocation tracking is not nested");
        });
        let guard = AllocationTrackingGuard;
        let result = operation();
        std::hint::black_box(&result);
        drop(guard);
        let allocated = TRACKED_ALLOCATION_BYTES.with(|total| total.get());
        (result, allocated)
    }

    fn canonical_entry_api_allocations(entry: &Entry) -> (usize, usize) {
        let (_, bytes_allocated) = allocated_bytes_during(|| {
            canonical_entry_bytes_v1(entry).expect("serialize entry while tracking allocations")
        });
        let (_, hash_allocated) = allocated_bytes_during(|| {
            canonical_entry_content_hash_v1(entry).expect("hash entry while tracking allocations")
        });
        (bytes_allocated, hash_allocated)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn guarded_vec_with_capacity<T>(capacity: usize) -> Vec<T> {
        let allocation_size = std::mem::size_of::<T>()
            .checked_mul(capacity)
            .expect("guarded allocation size");
        assert!(allocation_size > 0);
        assert!(allocation_size <= GUARDED_REGION_LENGTH);

        request_guarded_allocation(allocation_size);
        let mut values: Vec<T> = Vec::with_capacity(capacity);
        if values.as_mut_ptr().cast::<u8>() != guarded_allocation_pointer() {
            std::process::exit(70);
        }
        values
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn run_no_read_child(scenario: &str) -> ! {
        let (protect_attachment_bytes, compute_hash) = match scenario {
            "attachment-bytes" => (true, false),
            "attachment-hash" => (true, true),
            "history-bytes" => (false, false),
            "history-hash" => (false, true),
            _ => std::process::exit(71),
        };

        let mut entry = minimal_entry();
        let guarded_region = if protect_attachment_bytes {
            let mut bytes = guarded_vec_with_capacity::<u8>(GUARDED_REGION_LENGTH);
            bytes.resize(GUARDED_REGION_LENGTH, 0x5a);
            let region = bytes.as_mut_ptr();
            let content_id = AttachmentContentId::from_bytes(b"cached content id");
            entry.attachments.insert(
                "guarded.bin".into(),
                Attachment::with_content(
                    "ignored-name",
                    AttachmentContent::from_parts(content_id, bytes),
                    false,
                ),
            );
            region
        } else {
            let mut historical = minimal_entry();
            historical.notes = "the complete history entry must remain unread".into();
            let mut history = guarded_vec_with_capacity::<Entry>(1);
            history.push(historical);
            let region = history.as_mut_ptr().cast::<u8>();
            entry.history = history;
            region
        };

        if !protect_guarded_region(guarded_region) {
            std::process::exit(72);
        }
        let succeeded = if compute_hash {
            canonical_entry_content_hash_v1(&entry).is_ok()
        } else {
            canonical_entry_bytes_v1(&entry).is_ok()
        };
        // Direct exit avoids dropping Entry after its excluded storage becomes inaccessible.
        std::process::exit(if succeeded { NO_READ_CHILD_SUCCESS } else { 73 });
    }

    struct OversizedByteString {
        length: usize,
    }

    impl CanonicalByteString for OversizedByteString {
        fn byte_length(&self) -> usize {
            self.length
        }

        fn bytes(&self) -> &[u8] {
            panic!("overflowing byte strings must be rejected before reading their payload")
        }
    }

    struct OversizedExactSizeIterator<T> {
        length: usize,
        item: Option<T>,
    }

    impl<T> OversizedExactSizeIterator<T> {
        fn new(length: usize) -> Self {
            Self { length, item: None }
        }

        fn with_item(length: usize, item: T) -> Self {
            Self {
                length,
                item: Some(item),
            }
        }
    }

    impl<T> Iterator for OversizedExactSizeIterator<T> {
        type Item = T;

        fn next(&mut self) -> Option<Self::Item> {
            self.item.take()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            let remaining = usize::from(self.item.is_some());
            (remaining, Some(remaining))
        }
    }

    impl<T> ExactSizeIterator for OversizedExactSizeIterator<T> {
        fn len(&self) -> usize {
            self.length
        }
    }

    fn minimal_entry() -> Entry {
        let mut entry = Entry::new("");
        entry.id = Uuid::nil();
        entry.icon_id = None;
        entry.expiry_time = None;
        entry.last_accessed_at = None;
        entry.usage_count = None;
        entry.location_changed_at = None;
        entry.auto_type = None;
        entry
    }

    fn fully_populated_entry() -> Entry {
        let mut entry = Entry::new("Café");
        entry.id = Uuid::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);
        entry.username = "用户".into();
        entry.password = "p@sswörd".into();
        entry.url = "https://例.example/登录".into();
        entry.notes = "line one\nline two".into();
        entry.field_protection = EntryFieldProtection {
            protect_title: true,
            protect_username: false,
            protect_password: true,
            protect_url: true,
            protect_notes: false,
        };
        entry.tags = BTreeSet::from(["é".into(), "aa".into(), "b".into()]);
        entry.attributes = BTreeMap::from([
            (
                "é".into(),
                CustomField {
                    value: "秘密".into(),
                    protected: true,
                },
            ),
            (
                "z".into(),
                CustomField {
                    value: "plain".into(),
                    protected: false,
                },
            ),
        ]);
        entry.attachments.insert(
            "é.bin".into(),
            Attachment::new("ignored-accent-name", b"attachment-accent".to_vec(), true),
        );
        entry.attachments.insert(
            "z.bin".into(),
            Attachment::new("ignored-z-name", b"attachment-z".to_vec(), false),
        );
        entry.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period_seconds: 45,
            issuer: Some("例 Corp".into()),
            account_name: Some("alice+prod@example.com".into()),
        });
        entry.passkey = Some(PasskeyRecord {
            username: "alice".into(),
            credential_id: "credential".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "private-key".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        entry.icon_id = Some(0x0102_0304);
        entry.custom_icon_id = Some(Uuid::from_bytes([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]));
        entry.foreground_color = Some("#112233".into());
        entry.background_color = Some("蓝".into());
        entry.override_url = Some("cmd://open".into());
        entry.created_at = 0x0102_0304_0506_0708;
        entry.modified_at = 0x1112_1314_1516_1718;
        entry.expires = true;
        entry.expiry_time = Some(-2);
        entry.last_accessed_at = Some(0x2122_2324_2526_2728);
        entry.usage_count = Some(0x3132_3334_3536_3738);
        entry.location_changed_at = Some(0x4142_4344_4546_4748);
        entry.previous_parent = Some(Uuid::from_bytes([
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ]));
        entry.auto_type = Some(AutoTypeConfig {
            enabled: Some(false),
            obfuscation: Some(-2),
            default_sequence: Some("{USERNAME}{TAB}{PASSWORD}{ENTER}".into()),
            associations: vec![
                AutoTypeAssociation {
                    window: "例*".into(),
                    sequence: "{PASSWORD}".into(),
                },
                AutoTypeAssociation {
                    window: "Admin".into(),
                    sequence: "{USERNAME}".into(),
                },
            ],
        });
        entry.custom_data =
            BTreeMap::from([("é".into(), "accent".into()), ("z".into(), "last".into())]);
        entry.custom_data_blocks = vec![
            CustomDataBlock {
                items: vec![
                    CustomDataItem {
                        key: "dup".into(),
                        value: "first".into(),
                        last_modified: None,
                    },
                    CustomDataItem {
                        key: "only".into(),
                        value: "一".into(),
                        last_modified: Some(-7),
                    },
                ],
                after: Some(OpaqueXmlAnchor {
                    element_name: "ignored-anchor".into(),
                    occurrence: 99,
                }),
            },
            CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "dup".into(),
                    value: "last".into(),
                    last_modified: Some(123),
                }],
                after: None,
            },
        ];
        entry.exclude_from_reports = true;
        entry
    }

    fn canonical_bytes(entry: &Entry) -> Vec<u8> {
        canonical_entry_bytes_v1(entry).expect("serialize entry")
    }

    fn canonical_hash(entry: &Entry) -> [u8; 32] {
        canonical_entry_content_hash_v1(entry).expect("hash entry")
    }

    struct GoldenCursor<'a> {
        bytes: &'a [u8],
        position: usize,
    }

    impl<'a> GoldenCursor<'a> {
        fn take(&mut self, length: usize) -> &'a [u8] {
            let end = self
                .position
                .checked_add(length)
                .expect("golden cursor overflow");
            assert!(
                end <= self.bytes.len(),
                "truncated canonical golden at {} taking {length} of {} bytes",
                self.position,
                self.bytes.len()
            );
            let value = &self.bytes[self.position..end];
            self.position = end;
            value
        }

        fn byte(&mut self) -> u8 {
            self.take(1)[0]
        }

        fn boolean(&mut self) {
            assert!(matches!(self.byte(), 0 | 1), "invalid canonical bool");
        }

        fn u32(&mut self) -> u32 {
            u32::from_le_bytes(self.take(4).try_into().expect("four bytes"))
        }

        fn text(&mut self) {
            let length = usize::try_from(self.u32()).expect("u32 fits usize");
            self.take(length);
        }

        fn option(&mut self, present: impl FnOnce(&mut Self)) {
            match self.byte() {
                0 => {}
                1 => present(self),
                _ => panic!("invalid canonical option tag"),
            }
        }
    }

    fn decode_entry_v1_field_slices(bytes: &[u8]) -> (&[u8], Vec<&[u8]>) {
        assert!(bytes.len() >= 8, "canonical framing");
        assert_eq!(&bytes[..4], b"VKCS");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);

        let framing = &bytes[..8];
        let mut cursor = GoldenCursor { bytes, position: 8 };
        let mut fields = Vec::with_capacity(27);
        macro_rules! field {
            ($body:block) => {{
                let start = cursor.position;
                $body
                fields.push(&bytes[start..cursor.position]);
            }};
        }

        field!({
            cursor.take(16);
        });
        for _ in 0..5 {
            field!({
                cursor.text();
            });
        }
        field!({
            for _ in 0..5 {
                cursor.boolean();
            }
        });
        field!({
            let count = cursor.u32();
            for _ in 0..count {
                cursor.text();
            }
        });
        field!({
            let count = cursor.u32();
            for _ in 0..count {
                cursor.text();
                cursor.text();
                cursor.boolean();
            }
        });
        field!({
            let count = cursor.u32();
            for _ in 0..count {
                cursor.text();
                cursor.boolean();
                cursor.take(32);
            }
        });
        field!({
            cursor.option(|cursor| {
                cursor.take(4);
            });
        });
        field!({
            cursor.option(|cursor| {
                cursor.take(16);
            });
        });
        for _ in 0..3 {
            field!({
                cursor.option(GoldenCursor::text);
            });
        }
        for _ in 0..2 {
            field!({
                cursor.take(8);
            });
        }
        field!({
            cursor.boolean();
        });
        for _ in 0..4 {
            field!({
                cursor.option(|cursor| {
                    cursor.take(8);
                });
            });
        }
        field!({
            cursor.option(|cursor| {
                cursor.take(16);
            });
        });
        field!({
            cursor.option(|cursor| {
                cursor.option(GoldenCursor::boolean);
                cursor.option(|cursor| {
                    cursor.take(4);
                });
                cursor.option(GoldenCursor::text);
                let count = cursor.u32();
                for _ in 0..count {
                    cursor.text();
                    cursor.text();
                }
            });
        });
        field!({
            let count = cursor.u32();
            for _ in 0..count {
                cursor.text();
                cursor.text();
            }
        });
        field!({
            let count = cursor.u32();
            for _ in 0..count {
                cursor.text();
                cursor.text();
                cursor.option(|cursor| {
                    cursor.take(8);
                });
            }
        });
        field!({
            cursor.boolean();
        });

        assert_eq!(fields.len(), 27);
        assert_eq!(cursor.position, bytes.len(), "trailing canonical bytes");
        (framing, fields)
    }

    #[test]
    fn minimal_entry_has_pinned_v1_bytes_and_digest() {
        let entry = minimal_entry();

        let bytes = canonical_entry_bytes_v1(&entry).expect("serialize minimal entry");
        let expected_bytes = HEXLOWER
            .decode(MINIMAL_ENTRY_V1_HEX.as_bytes())
            .expect("decode minimal golden bytes");
        assert_eq!(bytes, expected_bytes);

        let digest = canonical_entry_content_hash_v1(&entry).expect("hash minimal entry");
        assert_eq!(HEXLOWER.encode(&digest), MINIMAL_ENTRY_V1_SHA256_HEX);
    }

    #[test]
    fn fully_populated_entry_has_pinned_v1_bytes_and_digest() {
        let entry = fully_populated_entry();

        let bytes = canonical_bytes(&entry);
        let expected_bytes = HEXLOWER
            .decode(FULL_ENTRY_V1_HEX.as_bytes())
            .expect("decode populated golden bytes");
        assert_eq!(bytes, expected_bytes);
        assert_eq!(bytes.len(), 1173);
        assert_eq!(
            HEXLOWER.encode(&canonical_hash(&entry)),
            FULL_ENTRY_V1_SHA256_HEX
        );
    }

    #[test]
    fn full_entry_golden_delta_is_confined_to_field_9() {
        let obsolete = HEXLOWER
            .decode(OBSOLETE_PLAIN_005_FULL_ENTRY_V1_HEX.as_bytes())
            .expect("decode obsolete plain-005 golden");
        let current = HEXLOWER
            .decode(FULL_ENTRY_V1_HEX.as_bytes())
            .expect("decode current golden");
        let (obsolete_framing, obsolete_fields) = decode_entry_v1_field_slices(&obsolete);
        let (current_framing, current_fields) = decode_entry_v1_field_slices(&current);

        assert_eq!(obsolete.len(), 565);
        assert_eq!(current.len(), 1173);
        assert_eq!(obsolete_fields[8].len(), 36);
        assert_eq!(current_fields[8].len(), 644);
        assert_eq!(&obsolete_fields[8][..4], &2_u32.to_le_bytes());
        assert_eq!(&current_fields[8][..4], &15_u32.to_le_bytes());
        assert_eq!(
            HEXLOWER.encode(&vaultkern_crypto::sha256_bytes(&obsolete)),
            OBSOLETE_PLAIN_005_FULL_ENTRY_V1_SHA256_HEX
        );
        assert_eq!(obsolete_framing, current_framing);
        for index in 0..27 {
            if index == 8 {
                assert_ne!(obsolete_fields[index], current_fields[index]);
            } else {
                assert_eq!(
                    obsolete_fields[index],
                    current_fields[index],
                    "canonical field {} changed outside the field-9 amendment",
                    index + 1
                );
            }
        }
    }

    #[test]
    fn every_included_entry_field_changes_bytes_and_digest() {
        let baseline = minimal_entry();
        let baseline_bytes = canonical_bytes(&baseline);
        let baseline_hash = canonical_hash(&baseline);
        let cases: [EntryMutation; 27] = [
            ("id", |entry| entry.id = Uuid::from_bytes([1; 16])),
            ("title", |entry| entry.title = "changed".into()),
            ("username", |entry| entry.username = "changed".into()),
            ("password", |entry| entry.password = "changed".into()),
            ("url", |entry| entry.url = "changed".into()),
            ("notes", |entry| entry.notes = "changed".into()),
            ("field_protection", |entry| {
                entry.field_protection.protect_title = true
            }),
            ("tags", |entry| {
                entry.tags.insert("changed".into());
            }),
            ("attributes", |entry| {
                entry.attributes.insert(
                    "key".into(),
                    CustomField {
                        value: "value".into(),
                        protected: true,
                    },
                );
            }),
            ("attachments", |entry| {
                entry.attachments.insert(
                    "file".into(),
                    Attachment::new("ignored", b"content".to_vec(), true),
                );
            }),
            ("icon_id", |entry| entry.icon_id = Some(1)),
            ("custom_icon_id", |entry| {
                entry.custom_icon_id = Some(Uuid::from_bytes([2; 16]))
            }),
            ("foreground_color", |entry| {
                entry.foreground_color = Some("foreground".into())
            }),
            ("background_color", |entry| {
                entry.background_color = Some("background".into())
            }),
            ("override_url", |entry| {
                entry.override_url = Some("override".into())
            }),
            ("created_at", |entry| entry.created_at = 1),
            ("modified_at", |entry| entry.modified_at = 1),
            ("expires", |entry| entry.expires = true),
            ("expiry_time", |entry| entry.expiry_time = Some(-1)),
            ("last_accessed_at", |entry| entry.last_accessed_at = Some(1)),
            ("usage_count", |entry| entry.usage_count = Some(1)),
            ("location_changed_at", |entry| {
                entry.location_changed_at = Some(1)
            }),
            ("previous_parent", |entry| {
                entry.previous_parent = Some(Uuid::from_bytes([3; 16]))
            }),
            ("auto_type", |entry| {
                entry.auto_type = Some(AutoTypeConfig::default())
            }),
            ("custom_data", |entry| {
                entry.custom_data.insert("key".into(), "value".into());
            }),
            ("custom_data_items", |entry| {
                entry.custom_data_blocks.push(CustomDataBlock {
                    items: vec![CustomDataItem {
                        key: "key".into(),
                        value: "value".into(),
                        last_modified: None,
                    }],
                    after: None,
                });
            }),
            ("exclude_from_reports", |entry| {
                entry.exclude_from_reports = true
            }),
        ];

        for (field, mutate) in cases {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(canonical_bytes(&changed), baseline_bytes, "field {field}");
            assert_ne!(canonical_hash(&changed), baseline_hash, "field {field}");
        }
    }

    #[test]
    fn field_protection_booleans_are_bound_to_their_v1_positions() {
        const FIELD_PROTECTION_OFFSET: usize = 44;
        let mut all_false_bytes = HEXLOWER
            .decode(MINIMAL_ENTRY_V1_HEX.as_bytes())
            .expect("decode minimal golden bytes");
        all_false_bytes[FIELD_PROTECTION_OFFSET + 2] = 0;
        let cases: [PositionedFieldProtectionMutation; 5] = [
            ("protect_title", 0, |value| value.protect_title = true),
            ("protect_username", 1, |value| value.protect_username = true),
            ("protect_password", 2, |value| value.protect_password = true),
            ("protect_url", 3, |value| value.protect_url = true),
            ("protect_notes", 4, |value| value.protect_notes = true),
        ];

        for (field, position, mutate) in cases {
            let mut entry = minimal_entry();
            entry.field_protection = EntryFieldProtection {
                protect_title: false,
                protect_username: false,
                protect_password: false,
                protect_url: false,
                protect_notes: false,
            };
            mutate(&mut entry.field_protection);
            let mut expected = all_false_bytes.clone();
            expected[FIELD_PROTECTION_OFFSET + position] = 1;

            assert_eq!(canonical_bytes(&entry), expected, "field {field}");
        }
    }

    #[test]
    fn top_level_booleans_are_bound_to_their_v1_positions() {
        const EXPIRES_OFFSET: usize = 82;
        const EXCLUDE_FROM_REPORTS_OFFSET: usize = 97;
        let baseline = HEXLOWER
            .decode(MINIMAL_ENTRY_V1_HEX.as_bytes())
            .expect("decode minimal golden bytes");
        let cases: [PositionedEntryMutation; 2] = [
            ("expires", EXPIRES_OFFSET, |entry| entry.expires = true),
            (
                "exclude_from_reports",
                EXCLUDE_FROM_REPORTS_OFFSET,
                |entry| entry.exclude_from_reports = true,
            ),
        ];

        for (field, offset, mutate) in cases {
            let mut entry = minimal_entry();
            mutate(&mut entry);
            let mut expected = baseline.clone();
            expected[offset] = 1;

            assert_eq!(canonical_bytes(&entry), expected, "field {field}");
        }
    }

    #[test]
    fn auto_type_enabled_encodes_the_stored_boolean() {
        let mut disabled = minimal_entry();
        disabled.auto_type = Some(AutoTypeConfig {
            enabled: Some(false),
            ..AutoTypeConfig::default()
        });
        let mut enabled = disabled.clone();
        enabled.auto_type.as_mut().expect("auto-type").enabled = Some(true);

        let disabled_bytes = canonical_bytes(&disabled);
        let enabled_bytes = canonical_bytes(&enabled);
        let changed_offsets: Vec<_> = disabled_bytes
            .iter()
            .zip(&enabled_bytes)
            .enumerate()
            .filter_map(|(offset, (left, right))| (left != right).then_some(offset))
            .collect();

        assert_eq!(changed_offsets.len(), 1);
        let offset = changed_offsets[0];
        assert_eq!((disabled_bytes[offset], enabled_bytes[offset]), (0, 1));
    }

    #[test]
    fn present_sentinel_options_remain_distinct_from_absent_options() {
        let baseline = minimal_entry();
        let baseline_bytes = canonical_bytes(&baseline);
        let baseline_hash = canonical_hash(&baseline);
        let cases: [EntryMutation; 13] = [
            ("icon_id_zero", |entry| entry.icon_id = Some(0)),
            ("custom_icon_id_nil", |entry| {
                entry.custom_icon_id = Some(Uuid::nil())
            }),
            ("foreground_color_empty", |entry| {
                entry.foreground_color = Some(String::new())
            }),
            ("background_color_empty", |entry| {
                entry.background_color = Some(String::new())
            }),
            ("override_url_empty", |entry| {
                entry.override_url = Some(String::new())
            }),
            ("expiry_time_zero", |entry| entry.expiry_time = Some(0)),
            ("last_accessed_at_zero", |entry| {
                entry.last_accessed_at = Some(0)
            }),
            ("usage_count_zero", |entry| entry.usage_count = Some(0)),
            ("location_changed_at_zero", |entry| {
                entry.location_changed_at = Some(0)
            }),
            ("previous_parent_nil", |entry| {
                entry.previous_parent = Some(Uuid::nil())
            }),
            ("auto_type_enabled_false", |entry| {
                entry.auto_type = Some(AutoTypeConfig {
                    enabled: Some(false),
                    ..AutoTypeConfig::default()
                })
            }),
            ("auto_type_obfuscation_zero", |entry| {
                entry.auto_type = Some(AutoTypeConfig {
                    obfuscation: Some(0),
                    ..AutoTypeConfig::default()
                })
            }),
            ("auto_type_default_sequence_empty", |entry| {
                entry.auto_type = Some(AutoTypeConfig {
                    default_sequence: Some(String::new()),
                    ..AutoTypeConfig::default()
                })
            }),
        ];

        for (field, mutate) in cases {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_ne!(canonical_bytes(&changed), baseline_bytes, "field {field}");
            assert_ne!(canonical_hash(&changed), baseline_hash, "field {field}");
        }
    }

    #[test]
    fn custom_data_item_last_modified_distinguishes_absent_from_zero() {
        let mut absent = minimal_entry();
        absent.custom_data_blocks = vec![CustomDataBlock {
            items: vec![CustomDataItem {
                key: "key".into(),
                value: "value".into(),
                last_modified: None,
            }],
            after: None,
        }];
        let mut zero = absent.clone();
        zero.custom_data_blocks[0].items[0].last_modified = Some(0);

        let absent_bytes = canonical_bytes(&absent);
        let zero_bytes = canonical_bytes(&zero);
        let absent_prefix_length = absent_bytes.len() - 2;
        let zero_prefix_length = zero_bytes.len() - 10;

        assert_eq!(
            &absent_bytes[..absent_prefix_length],
            &zero_bytes[..zero_prefix_length]
        );
        assert_eq!(&absent_bytes[absent_prefix_length..], &[0, 0]);
        assert_eq!(
            &zero_bytes[zero_prefix_length..],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_ne!(canonical_hash(&absent), canonical_hash(&zero));
    }

    #[test]
    fn totp_projection_changes_bytes_and_hash_without_timestamp_change() {
        let mut first = minimal_entry();
        first.modified_at = 42;
        first.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period_seconds: 60,
            issuer: Some("Example".into()),
            account_name: Some("alice@example.com".into()),
        });
        let mut second = first.clone();
        second.totp.as_mut().expect("TOTP projection").secret_base32 = "KRSXG5DSNFXGOIDB".into();

        assert_eq!(first.id, second.id);
        assert_eq!(first.modified_at, second.modified_at);
        assert_ne!(canonical_bytes(&first), canonical_bytes(&second));
        assert_ne!(canonical_hash(&first), canonical_hash(&second));
    }

    #[test]
    fn passkey_projection_changes_bytes_and_hash_without_timestamp_change() {
        let mut first = minimal_entry();
        first.modified_at = 42;
        first.passkey = Some(PasskeyRecord {
            username: "alice".into(),
            credential_id: "credential-one".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "private-key-one".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        });
        let mut second = first.clone();
        let second_passkey = second.passkey.as_mut().expect("passkey projection");
        second_passkey.credential_id = "credential-two".into();
        second_passkey.private_key_pem = "private-key-two".into();

        assert_eq!(first.id, second.id);
        assert_eq!(first.modified_at, second.modified_at);
        assert_ne!(canonical_bytes(&first), canonical_bytes(&second));
        assert_ne!(canonical_hash(&first), canonical_hash(&second));
    }

    #[test]
    fn projection_and_equivalent_backing_attributes_encode_each_key_once() {
        const ATTRIBUTE_COUNT_OFFSET: usize = 53;
        let passkey = PasskeyRecord {
            username: "alice".into(),
            credential_id: "credential".into(),
            generated_user_id: Some("generated".into()),
            private_key_pem: "private-key".into(),
            relying_party: "example.com".into(),
            user_handle: Some("handle".into()),
            backup_eligible: true,
            backup_state: false,
        };
        let mut projection_only = minimal_entry();
        projection_only.totp = Some(TotpSpec {
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period_seconds: 45,
            issuer: Some("Example".into()),
            account_name: Some("alice".into()),
        });
        projection_only.passkey = Some(passkey);
        let mut explicitly_backed = projection_only.clone();
        explicitly_backed.attributes =
            materialize_entry_persistent_attributes(&projection_only).to_custom_fields_for_test();

        let projection_bytes = canonical_bytes(&projection_only);
        assert_eq!(projection_bytes, canonical_bytes(&explicitly_backed));
        assert_eq!(
            canonical_hash(&projection_only),
            canonical_hash(&explicitly_backed)
        );
        assert_eq!(
            u32::from_le_bytes(
                projection_bytes[ATTRIBUTE_COUNT_OFFSET..ATTRIBUTE_COUNT_OFFSET + 4]
                    .try_into()
                    .expect("attribute count bytes")
            ),
            13
        );
    }

    #[test]
    fn projections_are_encoded_only_through_the_materialized_attributes_field() {
        let projected = fully_populated_entry();
        let mut explicitly_materialized = projected.clone();
        explicitly_materialized.attributes =
            materialize_entry_persistent_attributes(&projected).to_custom_fields_for_test();
        explicitly_materialized.totp = None;
        explicitly_materialized.passkey = None;

        assert_eq!(
            canonical_bytes(&projected),
            canonical_bytes(&explicitly_materialized)
        );
        assert_eq!(
            canonical_hash(&projected),
            canonical_hash(&explicitly_materialized)
        );
    }

    #[test]
    fn excluded_projection_history_and_fidelity_fields_do_not_change_content() {
        let baseline = minimal_entry();
        let expected_bytes = canonical_bytes(&baseline);
        let expected_hash = canonical_hash(&baseline);
        let cases: [EntryMutation; 4] = [
            ("history", |entry| {
                entry.history.push(fully_populated_entry())
            }),
            ("raw_state", |entry| {
                entry.raw_state = EntryRawState {
                    node_order: vec!["String".into()],
                    foreground_color_raw: Some("raw".into()),
                    background_color_raw: Some("raw-background".into()),
                    override_url_raw: Some("raw-override".into()),
                    tags_raw: Some("raw-tags".into()),
                    quality_check_raw: Some("raw-quality".into()),
                    has_history_node: true,
                    ..EntryRawState::default()
                };
            }),
            ("opaque_xml", |entry| {
                entry.opaque_xml.push(OpaqueXmlFragment {
                    xml: "<Unknown secret='value'/>".into(),
                    after: Some(OpaqueXmlAnchor {
                        element_name: "String".into(),
                        occurrence: 4,
                    }),
                });
            }),
            ("custom_data_block_anchor", |entry| {
                entry.custom_data_blocks.push(CustomDataBlock {
                    items: Vec::new(),
                    after: Some(OpaqueXmlAnchor {
                        element_name: "CustomData".into(),
                        occurrence: 7,
                    }),
                });
            }),
        ];

        for (field, mutate) in cases {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            assert_eq!(canonical_bytes(&changed), expected_bytes, "field {field}");
            assert_eq!(canonical_hash(&changed), expected_hash, "field {field}");
        }
    }

    #[test]
    fn set_elements_sort_by_full_encoded_bytes() {
        let mut entry = minimal_entry();
        entry.tags = BTreeSet::from(["aa".into(), "é".into(), "b".into()]);

        let bytes = canonical_bytes(&entry);
        assert_eq!(
            &bytes[49..70],
            &[
                3, 0, 0, 0, 1, 0, 0, 0, b'b', 2, 0, 0, 0, b'a', b'a', 2, 0, 0, 0, 0xc3, 0xa9,
            ]
        );
    }

    #[test]
    fn set_order_compares_little_endian_length_prefix_bytes_across_carry() {
        let values = ["b".to_owned(), "a".repeat(256)];
        let mut encoder = Encoder::default();

        encoder
            .write_set(values.iter(), |encoder, value| encoder.write_text(value))
            .expect("encode set across a length-prefix carry");

        let mut expected = vec![2, 0, 0, 0, 0, 1, 0, 0];
        expected.extend_from_slice(&[b'a'; 256]);
        expected.extend_from_slice(&[1, 0, 0, 0, b'b']);
        assert_eq!(encoder.into_bytes(), expected);
    }

    #[test]
    fn map_keys_sort_by_raw_utf8_bytes_not_encoded_key_bytes() {
        let mut entry = minimal_entry();
        entry.attributes = BTreeMap::from([
            (
                "b".into(),
                CustomField {
                    value: "b-value".into(),
                    protected: false,
                },
            ),
            (
                "aa".into(),
                CustomField {
                    value: "aa-value".into(),
                    protected: true,
                },
            ),
        ]);

        let expected_map = HEXLOWER
            .decode(
                b"020000000200000061610800000061612d76616c756501010000006207000000622d76616c756500",
            )
            .expect("decode expected map");
        let bytes = canonical_bytes(&entry);
        assert_eq!(&bytes[53..53 + expected_map.len()], expected_map);
    }

    #[test]
    fn string_map_helper_sorts_unsorted_input_by_raw_utf8_keys() {
        let aa_value = 1_u8;
        let b_value = 2_u8;
        let mut encoder = Encoder::default();

        encoder
            .write_string_map(
                [("b", &b_value), ("aa", &aa_value)].into_iter(),
                |encoder, value| {
                    encoder.write_u32(u32::from(*value));
                    Ok(())
                },
            )
            .expect("encode deliberately unsorted map");

        assert_eq!(
            encoder.into_bytes(),
            [
                2, 0, 0, 0, 2, 0, 0, 0, b'a', b'a', 1, 0, 0, 0, 1, 0, 0, 0, b'b', 2, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn map_and_set_insertion_order_does_not_change_bytes() {
        let mut first = minimal_entry();
        let mut second = minimal_entry();
        for value in ["z", "é", "aa"] {
            first.tags.insert(value.into());
        }
        for value in ["aa", "é", "z"] {
            second.tags.insert(value.into());
        }
        for (key, value) in [("z", "last"), ("é", "accent")] {
            first.custom_data.insert(key.into(), value.into());
        }
        for (key, value) in [("é", "accent"), ("z", "last")] {
            second.custom_data.insert(key.into(), value.into());
        }
        first.attributes.insert(
            "z".into(),
            CustomField {
                value: "last".into(),
                protected: false,
            },
        );
        first.attributes.insert(
            "é".into(),
            CustomField {
                value: "accent".into(),
                protected: true,
            },
        );
        second.attributes.insert(
            "é".into(),
            CustomField {
                value: "accent".into(),
                protected: true,
            },
        );
        second.attributes.insert(
            "z".into(),
            CustomField {
                value: "last".into(),
                protected: false,
            },
        );

        assert_eq!(canonical_bytes(&first), canonical_bytes(&second));
        assert_eq!(canonical_hash(&first), canonical_hash(&second));
    }

    #[test]
    fn text_is_not_unicode_normalized() {
        let mut composed = minimal_entry();
        composed.title = "é".into();
        let mut decomposed = minimal_entry();
        decomposed.title = "e\u{301}".into();

        assert_ne!(canonical_bytes(&composed), canonical_bytes(&decomposed));
        assert_ne!(canonical_hash(&composed), canonical_hash(&decomposed));
    }

    #[test]
    fn custom_data_items_are_document_order_last_wins_without_block_fidelity() {
        let mut split_blocks = minimal_entry();
        split_blocks.custom_data_blocks = vec![
            CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "dup".into(),
                    value: "first".into(),
                    last_modified: None,
                }],
                after: Some(OpaqueXmlAnchor {
                    element_name: "First".into(),
                    occurrence: 1,
                }),
            },
            CustomDataBlock {
                items: vec![
                    CustomDataItem {
                        key: "other".into(),
                        value: "kept".into(),
                        last_modified: None,
                    },
                    CustomDataItem {
                        key: "dup".into(),
                        value: "last".into(),
                        last_modified: Some(9),
                    },
                ],
                after: Some(OpaqueXmlAnchor {
                    element_name: "Second".into(),
                    occurrence: 2,
                }),
            },
        ];
        let mut flattened = minimal_entry();
        flattened.custom_data_blocks = vec![CustomDataBlock {
            items: vec![
                CustomDataItem {
                    key: "dup".into(),
                    value: "last".into(),
                    last_modified: Some(9),
                },
                CustomDataItem {
                    key: "other".into(),
                    value: "kept".into(),
                    last_modified: None,
                },
            ],
            after: None,
        }];
        let mut reversed_winner = flattened.clone();
        reversed_winner.custom_data_blocks[0]
            .items
            .push(CustomDataItem {
                key: "dup".into(),
                value: "first".into(),
                last_modified: None,
            });

        assert_eq!(canonical_bytes(&split_blocks), canonical_bytes(&flattened));
        assert_eq!(canonical_hash(&split_blocks), canonical_hash(&flattened));
        assert_ne!(
            canonical_bytes(&split_blocks),
            canonical_bytes(&reversed_winner)
        );
    }

    #[test]
    fn map_only_custom_data_does_not_synthesize_custom_data_items() {
        let mut map_only = minimal_entry();
        map_only
            .custom_data
            .insert("model-key".into(), "model-value".into());
        let mut persisted = map_only.clone();
        persisted.custom_data_blocks = vec![CustomDataBlock {
            items: vec![CustomDataItem {
                key: "model-key".into(),
                value: "model-value".into(),
                last_modified: None,
            }],
            after: None,
        }];

        assert_ne!(canonical_bytes(&map_only), canonical_bytes(&persisted));
        assert_ne!(canonical_hash(&map_only), canonical_hash(&persisted));
    }

    #[test]
    fn empty_custom_data_blocks_do_not_change_content() {
        let mut map_only = minimal_entry();
        map_only
            .custom_data
            .insert("model-key".into(), "model-value".into());

        let mut empty_fidelity_block = map_only.clone();
        empty_fidelity_block
            .custom_data_blocks
            .push(CustomDataBlock {
                items: Vec::new(),
                after: Some(OpaqueXmlAnchor {
                    element_name: "Times".into(),
                    occurrence: 1,
                }),
            });

        let expected_bytes = canonical_bytes(&map_only);
        let expected_hash = canonical_hash(&map_only);
        assert_eq!(canonical_bytes(&empty_fidelity_block), expected_bytes);
        assert_eq!(canonical_hash(&empty_fidelity_block), expected_hash);
    }

    #[test]
    fn entry_projection_flattens_custom_data_items_in_document_order() {
        let mut entry = minimal_entry();
        entry.custom_data_blocks = vec![
            CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "dup".into(),
                    value: "first".into(),
                    last_modified: Some(1),
                }],
                after: Some(OpaqueXmlAnchor {
                    element_name: "String".into(),
                    occurrence: 99,
                }),
            },
            CustomDataBlock {
                items: vec![CustomDataItem {
                    key: "dup".into(),
                    value: "last".into(),
                    last_modified: Some(2),
                }],
                after: Some(OpaqueXmlAnchor {
                    element_name: "AutoType".into(),
                    occurrence: 1,
                }),
            },
        ];

        let projected = CanonicalEntryReference::try_from(&entry).expect("project entry");
        let item = projected
            .custom_data_items
            .get("dup")
            .expect("last duplicate item");

        assert_eq!(projected.custom_data_items.len(), 1);
        assert_eq!(item.value, "last");
        assert_eq!(item.last_modified, Some(2));
    }

    #[test]
    fn attachments_encode_map_key_protection_and_content_id_only() {
        let secret = b"attachment bytes must stay outside canonical stream";
        let shared = AttachmentContent::from_bytes(secret.to_vec());
        let mut shared_entry = minimal_entry();
        shared_entry.attachments.insert(
            "map-key".into(),
            Attachment::with_content("ignored-internal-name", shared.clone(), true),
        );
        let mut history = minimal_entry();
        history.attachments.insert(
            "history-key".into(),
            Attachment::with_content("history-name", shared.clone(), false),
        );
        shared_entry.history.push(history);

        let mut independent_entry = minimal_entry();
        independent_entry.attachments.insert(
            "map-key".into(),
            Attachment::new("different-internal-name", secret.to_vec(), true),
        );

        let shared_bytes = canonical_bytes(&shared_entry);
        assert_eq!(shared_bytes, canonical_bytes(&independent_entry));
        assert!(
            !shared_bytes
                .windows(secret.len())
                .any(|window| window == secret)
        );

        let mut changed_key = independent_entry.clone();
        let attachment = changed_key
            .attachments
            .remove("map-key")
            .expect("attachment");
        changed_key
            .attachments
            .insert("other-key".into(), attachment);
        assert_ne!(shared_bytes, canonical_bytes(&changed_key));

        let mut changed_protection = independent_entry.clone();
        changed_protection
            .attachments
            .get_mut("map-key")
            .expect("attachment")
            .protect_in_memory = false;
        assert_ne!(shared_bytes, canonical_bytes(&changed_protection));

        let mut changed_content = minimal_entry();
        changed_content.attachments.insert(
            "map-key".into(),
            Attachment::new("ignored", b"different content".to_vec(), true),
        );
        assert_ne!(shared_bytes, canonical_bytes(&changed_content));
    }

    #[test]
    fn attachment_projection_uses_the_cached_content_id() {
        let cached_id = AttachmentContentId::from_bytes(b"cached-id-source");
        let backing_bytes = b"backing bytes with a deliberately different hash".to_vec();
        assert_ne!(cached_id, AttachmentContentId::from_bytes(&backing_bytes));
        let content = AttachmentContent::from_parts(cached_id, backing_bytes);
        let mut entry = minimal_entry();
        entry.attachments.insert(
            "cached.bin".into(),
            Attachment::with_content("ignored-name", content, true),
        );

        let projected = CanonicalEntryReference::try_from(&entry).expect("project entry");

        assert_eq!(projected.attachments.len(), 1);
        assert_eq!(projected.attachments[0].1.content_id, cached_id);
    }

    #[test]
    fn repeated_computation_is_stable_and_does_not_clone_attachment_handles() {
        let content = AttachmentContent::from_bytes(vec![0x5a; 1024 * 1024]);
        let mut entry = minimal_entry();
        entry.attachments.insert(
            "large.bin".into(),
            Attachment::with_content("large.bin", content.clone(), false),
        );
        let mut history = minimal_entry();
        history.attachments.insert(
            "history.bin".into(),
            Attachment::with_content("history.bin", content.clone(), true),
        );
        entry.history.push(history);
        let snapshot = entry.clone();
        let strong_count = content.strong_count();

        let first_bytes = canonical_bytes(&entry);
        let first_hash = canonical_hash(&entry);
        assert_eq!(first_bytes, canonical_bytes(&entry));
        assert_eq!(first_hash, canonical_hash(&entry));
        assert_eq!(entry, snapshot);
        assert_eq!(content.strong_count(), strong_count);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn canonical_entry_public_apis_do_not_read_excluded_storage() {
        if let Some(scenario) = std::env::var_os(NO_READ_CHILD_ENV) {
            run_no_read_child(&scenario.to_string_lossy());
        }

        let executable = std::env::current_exe().expect("current model test executable");
        let mut failures = Vec::new();
        for scenario in [
            "attachment-bytes",
            "attachment-hash",
            "history-bytes",
            "history-hash",
        ] {
            let status = Command::new(&executable)
                .arg("canonical_entry_public_apis_do_not_read_excluded_storage")
                .arg("--nocapture")
                .env(NO_READ_CHILD_ENV, scenario)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run guarded no-read child");
            if status.code() != Some(NO_READ_CHILD_SUCCESS) {
                failures.push(format!("{scenario}: {status}"));
            }
        }
        assert!(
            failures.is_empty(),
            "canonical entry APIs accessed guarded excluded storage:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn attachment_backing_bytes_do_not_change_public_output_when_content_id_matches() {
        let content_id = AttachmentContentId::from_bytes(b"stable-content-id");
        let mut empty_content = minimal_entry();
        empty_content.attachments.insert(
            "content.bin".into(),
            Attachment::with_content(
                "ignored-name",
                AttachmentContent::from_parts(content_id, Vec::new()),
                false,
            ),
        );
        let mut large_content = minimal_entry();
        large_content.attachments.insert(
            "content.bin".into(),
            Attachment::with_content(
                "ignored-name",
                AttachmentContent::from_parts(content_id, vec![0x5a; 1024 * 1024]),
                false,
            ),
        );

        assert_eq!(
            canonical_bytes(&empty_content),
            canonical_bytes(&large_content)
        );
        assert_eq!(
            canonical_hash(&empty_content),
            canonical_hash(&large_content)
        );
    }

    #[test]
    fn canonical_entry_apis_do_not_copy_attachment_bytes() {
        let content_id = AttachmentContentId::from_bytes(b"stable-content-id");
        let mut empty_content = minimal_entry();
        empty_content.attachments.insert(
            "content.bin".into(),
            Attachment::with_content(
                "ignored-name",
                AttachmentContent::from_parts(content_id, Vec::new()),
                false,
            ),
        );
        let mut large_content = minimal_entry();
        large_content.attachments.insert(
            "content.bin".into(),
            Attachment::with_content(
                "ignored-name",
                AttachmentContent::from_parts(content_id, vec![0x5a; 1024 * 1024]),
                false,
            ),
        );

        let empty_allocated = canonical_entry_api_allocations(&empty_content);
        let large_allocated = canonical_entry_api_allocations(&large_content);

        assert_eq!(large_allocated, empty_allocated);
    }

    #[test]
    fn canonical_entry_apis_do_not_clone_history() {
        let without_history = minimal_entry();
        let mut with_history = minimal_entry();
        let mut history = minimal_entry();
        history.notes = "history must remain untouched".repeat(32 * 1024);
        with_history.history.push(history);

        let without_history_allocated = canonical_entry_api_allocations(&without_history);
        let with_history_allocated = canonical_entry_api_allocations(&with_history);

        assert_eq!(with_history_allocated, without_history_allocated);
    }

    #[test]
    fn entry_projection_retains_only_current_attachment_content_ids() {
        let content = AttachmentContent::from_bytes(b"shared-content".to_vec());
        let mut entry = minimal_entry();
        entry.attachments.insert(
            "current.bin".into(),
            Attachment::with_content("ignored-current-name", content.clone(), true),
        );
        let mut history = fully_populated_entry();
        history.attachments.insert(
            "history.bin".into(),
            Attachment::with_content("ignored-history-name", content.clone(), false),
        );
        entry.history.push(history);
        let strong_count = content.strong_count();

        let projected = CanonicalEntryReference::try_from(&entry).expect("project entry");
        assert_eq!(content.strong_count(), strong_count);
        assert_eq!(projected.attachments.len(), 1);
        assert_eq!(projected.attachments[0].0, "current.bin");
        assert!(projected.attachments[0].1.protect_in_memory);
        assert_eq!(projected.attachments[0].1.content_id, content.id());

        let projected_bytes =
            canonical_entry_reference_bytes_v1(projected).expect("serialize projected entry");
        assert_eq!(projected_bytes, canonical_bytes(&entry));
        assert_eq!(content.strong_count(), strong_count);
    }

    #[test]
    fn attachment_map_encoder_only_accepts_content_references() {
        let aa_id = AttachmentContentId::from_bytes(b"aa-content");
        let b_id = AttachmentContentId::from_bytes(b"b-content");
        let mut encoder = Encoder::default();

        encoder
            .write_attachment_map(
                [
                    (
                        "b",
                        AttachmentReference {
                            protect_in_memory: false,
                            content_id: b_id,
                        },
                    ),
                    (
                        "aa",
                        AttachmentReference {
                            protect_in_memory: true,
                            content_id: aa_id,
                        },
                    ),
                ]
                .into_iter(),
            )
            .expect("encode attachment references");

        let mut expected = vec![2, 0, 0, 0, 2, 0, 0, 0, b'a', b'a', 1];
        expected.extend_from_slice(aa_id.as_bytes());
        expected.extend_from_slice(&[1, 0, 0, 0, b'b', 0]);
        expected.extend_from_slice(b_id.as_bytes());
        assert_eq!(encoder.into_bytes(), expected);
    }

    #[test]
    fn attachment_content_ids_keep_all_32_bytes_when_first_byte_is_zero() {
        let content_id = AttachmentContentId::from_bytes(b"leading-zero-182");
        assert_eq!(content_id.as_bytes()[0], 0);
        let mut encoder = Encoder::default();

        encoder
            .write_attachment_map(
                [(
                    "file",
                    AttachmentReference {
                        protect_in_memory: false,
                        content_id,
                    },
                )]
                .into_iter(),
            )
            .expect("encode leading-zero content ID");

        let mut expected = vec![1, 0, 0, 0, 4, 0, 0, 0, b'f', b'i', b'l', b'e', 0];
        expected.extend_from_slice(content_id.as_bytes());
        assert_eq!(encoder.into_bytes(), expected);
    }

    #[test]
    fn framing_uuid_integer_endianness_and_option_tags_are_exact() {
        let mut entry = minimal_entry();
        let uuid_bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        entry.id = Uuid::from_bytes(uuid_bytes);
        entry.icon_id = Some(0x0102_0304);
        entry.created_at = 0x0102_0304_0506_0708;
        entry.expiry_time = Some(-2);
        let bytes = canonical_bytes(&entry);

        assert_eq!(&bytes[0..4], &CANONICAL_SERIALIZATION_MAGIC);
        assert_eq!(
            &bytes[4..8],
            &CANONICAL_ENTRY_SCHEMA_VERSION_V1.to_le_bytes()
        );
        assert_eq!(&bytes[8..24], &uuid_bytes);
        assert_eq!(&bytes[61..66], &[1, 4, 3, 2, 1]);
        assert_eq!(&bytes[70..78], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(
            &bytes[87..96],
            &[1, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );

        let mut auto_type = minimal_entry();
        auto_type.auto_type = Some(AutoTypeConfig {
            obfuscation: Some(-2),
            ..AutoTypeConfig::default()
        });
        assert_eq!(
            &canonical_bytes(&auto_type)[88..100],
            &[1, 0, 1, 0xfe, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn byte_lengths_and_collection_counts_reject_u32_overflow() {
        let overflow = usize::try_from(u64::from(u32::MAX) + 1).expect("64-bit test target");

        let mut byte_length_encoder = Encoder::default();
        assert_eq!(
            byte_length_encoder.write_byte_length(overflow),
            Err(CanonicalSerializationError::ByteLengthOverflow { length: overflow })
        );
        assert!(byte_length_encoder.into_bytes().is_empty());

        let mut collection_count_encoder = Encoder::default();
        assert_eq!(
            collection_count_encoder.write_count(overflow),
            Err(CanonicalSerializationError::CollectionCountOverflow { count: overflow })
        );
        assert!(collection_count_encoder.into_bytes().is_empty());

        let mut byte_string_encoder = Encoder::default();
        assert_eq!(
            byte_string_encoder.write_bytes(&OversizedByteString { length: overflow }),
            Err(CanonicalSerializationError::ByteLengthOverflow { length: overflow })
        );
        assert!(byte_string_encoder.into_bytes().is_empty());

        let mut list_encoder = Encoder::default();
        assert_eq!(
            list_encoder.write_list(
                OversizedExactSizeIterator::<&'static u8>::new(overflow),
                |_, _| Ok(())
            ),
            Err(CanonicalSerializationError::CollectionCountOverflow { count: overflow })
        );
        assert!(list_encoder.into_bytes().is_empty());

        let mut set_encoder = Encoder::default();
        assert_eq!(
            set_encoder.write_set(
                OversizedExactSizeIterator::<&'static u8>::new(overflow),
                |_, _| Ok(())
            ),
            Err(CanonicalSerializationError::CollectionCountOverflow { count: overflow })
        );
        assert!(set_encoder.into_bytes().is_empty());

        let mut map_encoder = Encoder::default();
        assert_eq!(
            map_encoder.write_string_map(
                OversizedExactSizeIterator::<(&'static str, &'static u8)>::new(overflow),
                |_, _| Ok(())
            ),
            Err(CanonicalSerializationError::CollectionCountOverflow { count: overflow })
        );
        assert!(map_encoder.into_bytes().is_empty());

        let value = 1_u8;
        let attachment_projection = collect_attachment_references(
            OversizedExactSizeIterator::with_item(overflow, ("key", &value)),
            |_| panic!("overflowing attachment maps must be rejected before projection"),
        );
        assert!(matches!(
            attachment_projection,
            Err(CanonicalSerializationError::CollectionCountOverflow { count })
                if count == overflow
        ));

        let mut boundary_encoder = Encoder::default();
        boundary_encoder
            .write_byte_length(u32::MAX as usize)
            .expect("maximum byte length");
        boundary_encoder
            .write_count(u32::MAX as usize)
            .expect("maximum collection count");
        assert_eq!(
            boundary_encoder.into_bytes(),
            [u32::MAX.to_le_bytes(), u32::MAX.to_le_bytes()].concat()
        );
    }
}
