//! Storage-only implementation of the frozen 003 journal segment lifecycle.
//! Payload sealing, record applicability, dead-letter publication, and replay
//! accounting intentionally remain outside this module.

use crate::providers::durable_file::{
    DurableFileIdentity, ExclusiveFileLock, PublishError, create_dir_all_durable,
    opened_file_identity, path_file_identity, rename_missing_target_durable, sync_parent,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use vaultkern_runtime_protocol::contracts::JournalRecord;
use vaultkern_runtime_protocol::framing::{self, SEGMENT_HEADER_LEN};

const WRITER_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const ACTIVE_SNAPSHOT_ATTEMPTS: usize = 3;
const MAX_CORRUPTION_CAPTURE_LEN: usize =
    framing::MAX_RECORD_LEN as usize + framing::FRAME_OVERHEAD;
const REMOVE_LOCK_AFTER_SEGMENT_SYNC: bool = !cfg!(windows);

#[derive(Debug)]
pub(crate) struct JournalSegmentStore {
    directory: PathBuf,
    directory_anchor: File,
    directory_identity: DurableFileIdentity,
}

#[derive(Debug)]
pub(crate) struct JournalSegmentWriter {
    writer_id: Uuid,
    path: PathBuf,
    file: File,
    identity: DurableFileIdentity,
    append_failed: bool,
    _segment_lock: ExclusiveFileLock,
    _reservation_anchor: File,
    _reservation_lock: ExclusiveFileLock,
}

#[derive(Debug)]
struct CreatedReservation {
    anchor: File,
    identity: DurableFileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentState {
    Active,
    Sealed,
}

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredSegment {
    pub(crate) writer_id: Uuid,
    pub(crate) state: SegmentState,
    path: PathBuf,
    identity: DurableFileIdentity,
    anchor: Arc<File>,
    lock_path: PathBuf,
    lock_identity: DurableFileIdentity,
    lock_anchor: Arc<File>,
}

impl PartialEq for DiscoveredSegment {
    fn eq(&self, other: &Self) -> bool {
        self.writer_id == other.writer_id
            && self.state == other.state
            && self.path == other.path
            && self.identity == other.identity
            && self.lock_path == other.lock_path
            && self.lock_identity == other.lock_identity
    }
}

impl Eq for DiscoveredSegment {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawJournalFrame {
    pub(crate) offset: u64,
    pub(crate) record_version: u16,
    pub(crate) body: Vec<u8>,
    pub(crate) raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SegmentTail {
    Complete,
    Provisional {
        offset: u64,
        raw_bytes: Vec<u8>,
    },
    DefinitiveCorruption {
        offset: u64,
        region_len: u64,
        raw_bytes: Vec<u8>,
        error: framing::FramingError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SegmentRead {
    #[cfg(test)]
    pub(crate) frames: Vec<RawJournalFrame>,
    pub(crate) frame_count: usize,
    pub(crate) tail: SegmentTail,
    writer_id: Uuid,
    identity: DurableFileIdentity,
    snapshot_len: u64,
    snapshot_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppendAcknowledged {
    pub(crate) offset: u64,
    pub(crate) frame_len: u64,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendTestFault {
    AfterPartialWrite,
    BeforeFlush,
    BeforeSync,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SealOutcome {
    WriterAlive,
    Sealed(DiscoveredSegment),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchivedCorruptSegment {
    pub(crate) writer_id: Uuid,
    pub(crate) file_name: String,
}

#[derive(Debug)]
pub(crate) struct SegmentMutationError {
    pub(crate) published: bool,
    pub(crate) target_conflict: bool,
    source: io::Error,
}

impl SegmentMutationError {
    pub(crate) fn kind(&self) -> io::ErrorKind {
        if self.target_conflict {
            io::ErrorKind::AlreadyExists
        } else {
            self.source.kind()
        }
    }
}

impl std::fmt::Display for SegmentMutationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "journal mutation failed (published={}): {}",
            self.published, self.source
        )
    }
}

impl std::error::Error for SegmentMutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<io::Error> for SegmentMutationError {
    fn from(source: io::Error) -> Self {
        Self {
            published: false,
            target_conflict: source.kind() == io::ErrorKind::AlreadyExists,
            source,
        }
    }
}

impl From<PublishError> for SegmentMutationError {
    fn from(error: PublishError) -> Self {
        Self {
            published: error.published,
            target_conflict: error.target_conflict,
            source: error.source,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AllRecordsResolved {
    writer_id: Uuid,
    identity: DurableFileIdentity,
    size_bytes: u64,
    content_sha256: String,
}

#[derive(Debug)]
pub(crate) struct CorruptTailPreserved {
    writer_id: Uuid,
    identity: DurableFileIdentity,
    snapshot_len: u64,
    snapshot_sha256: String,
    offset: u64,
    region_len: u64,
}

impl CorruptTailPreserved {
    /// Call only after the exact capped tail bytes have been durably copied to
    /// dead-letter storage. The token binds that assertion to one read.
    pub(crate) fn after_durable_preservation(
        segment: &DiscoveredSegment,
        read: &SegmentRead,
    ) -> io::Result<Self> {
        if segment.state != SegmentState::Sealed
            || segment.writer_id != read.writer_id
            || segment.identity != read.identity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "corrupt tail preservation requires an exact sealed read",
            ));
        }
        let (offset, region_len, raw_len) = match &read.tail {
            SegmentTail::DefinitiveCorruption {
                offset,
                region_len,
                raw_bytes,
                ..
            } => (*offset, *region_len, raw_bytes.len() as u64),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "corrupt tail preservation requires definitive corruption",
                ));
            }
        };
        if region_len > MAX_CORRUPTION_CAPTURE_LEN as u64 || raw_len != region_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "corrupt tail preservation requires the complete capped region",
            ));
        }
        Ok(Self {
            writer_id: read.writer_id,
            identity: read.identity,
            snapshot_len: read.snapshot_len,
            snapshot_sha256: read.snapshot_sha256.clone(),
            offset,
            region_len,
        })
    }
}

impl AllRecordsResolved {
    #[cfg(test)]
    pub(crate) fn for_segment(_segment: &DiscoveredSegment) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "record resolution requires an exact read snapshot",
        ))
    }

    pub(crate) fn for_read(segment: &DiscoveredSegment, read: &SegmentRead) -> io::Result<Self> {
        if segment.state != SegmentState::Sealed
            || segment.writer_id != read.writer_id
            || segment.identity != read.identity
            || read.tail != SegmentTail::Complete
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "record resolution requires a complete sealed segment snapshot",
            ));
        }
        Ok(Self {
            writer_id: read.writer_id,
            identity: read.identity,
            size_bytes: read.snapshot_len,
            content_sha256: read.snapshot_sha256.clone(),
        })
    }

    pub(crate) fn for_read_with_preserved_corrupt_tail(
        segment: &DiscoveredSegment,
        read: &SegmentRead,
        preserved: CorruptTailPreserved,
    ) -> io::Result<Self> {
        let (offset, region_len, raw_len) = match &read.tail {
            SegmentTail::DefinitiveCorruption {
                offset,
                region_len,
                raw_bytes,
                ..
            } => (*offset, *region_len, raw_bytes.len() as u64),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "preserved tail resolution requires definitive corruption",
                ));
            }
        };
        if segment.state != SegmentState::Sealed
            || segment.writer_id != read.writer_id
            || segment.identity != read.identity
            || region_len > MAX_CORRUPTION_CAPTURE_LEN as u64
            || raw_len != region_len
            || preserved.writer_id != read.writer_id
            || preserved.identity != read.identity
            || preserved.snapshot_len != read.snapshot_len
            || preserved.snapshot_sha256 != read.snapshot_sha256
            || preserved.offset != offset
            || preserved.region_len != region_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "preserved corrupt tail does not match sealed read snapshot",
            ));
        }
        Ok(Self {
            writer_id: read.writer_id,
            identity: read.identity,
            size_bytes: read.snapshot_len,
            content_sha256: read.snapshot_sha256.clone(),
        })
    }
}

impl JournalSegmentStore {
    pub(crate) fn open(directory: impl AsRef<Path>) -> io::Result<Self> {
        let requested = directory.as_ref();
        let directory = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()?.join(requested)
        };
        create_dir_all_durable(&directory)?;
        let directory_anchor = open_directory_anchor(&directory)?;
        let directory_identity =
            opened_file_identity(&directory_anchor, &directory_anchor.metadata()?)?;
        Ok(Self {
            directory,
            directory_anchor,
            directory_identity,
        })
    }

    pub(crate) fn create_writer(&self) -> io::Result<JournalSegmentWriter> {
        self.create_writer_with_id(Uuid::new_v4())
    }

    pub(crate) fn create_writer_with_id(
        &self,
        writer_id: Uuid,
    ) -> io::Result<JournalSegmentWriter> {
        self.create_writer_inner(writer_id, WRITER_LOCK_TIMEOUT, None, None, None)
    }

    #[cfg(test)]
    fn create_writer_with_test_hook(
        &self,
        writer_id: Uuid,
        lock_timeout: Duration,
        after_reservation: &mut dyn FnMut(&Path),
    ) -> io::Result<JournalSegmentWriter> {
        self.create_writer_inner(writer_id, lock_timeout, None, Some(after_reservation), None)
    }

    #[cfg(all(test, unix))]
    fn create_writer_with_pre_reservation_test_hook(
        &self,
        writer_id: Uuid,
        before_reservation: &mut dyn FnMut(),
    ) -> io::Result<JournalSegmentWriter> {
        self.create_writer_inner(
            writer_id,
            WRITER_LOCK_TIMEOUT,
            Some(before_reservation),
            None,
            None,
        )
    }

    #[cfg(test)]
    fn create_writer_with_post_create_test_hook(
        &self,
        writer_id: Uuid,
        after_segment_create: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> io::Result<JournalSegmentWriter> {
        self.create_writer_inner(
            writer_id,
            WRITER_LOCK_TIMEOUT,
            None,
            None,
            Some(after_segment_create),
        )
    }

    fn create_writer_inner(
        &self,
        writer_id: Uuid,
        lock_timeout: Duration,
        mut before_reservation: Option<&mut dyn FnMut()>,
        mut after_reservation: Option<&mut dyn FnMut(&Path)>,
        mut after_segment_create: Option<&mut dyn FnMut(&Path) -> io::Result<()>>,
    ) -> io::Result<JournalSegmentWriter> {
        if writer_id.is_nil() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal writer id must be a fresh non-nil UUID",
            ));
        }
        self.ensure_directory()?;
        if let Some(hook) = before_reservation.as_mut() {
            hook();
        }
        let stem = writer_id.hyphenated().to_string();
        let path = self.directory.join(&stem);
        let sealed_path = self.directory.join(format!("{stem}.sealed"));
        let corrupt_path = self.directory.join(format!("{stem}.corrupt"));
        let lock_path = self.directory.join(format!("{stem}.lock"));
        let reservation = create_lock_reservation(&lock_path)?;
        let lock_identity = reservation.identity;
        let mut _segment_anchor = None;
        let mut segment_identity = None;
        let result = (|| {
            self.ensure_directory()?;
            if let Some(hook) = after_reservation.as_mut() {
                hook(&lock_path);
            }
            verify_path_identity(&lock_path, lock_identity)?;
            let started = Instant::now();
            let lock = ExclusiveFileLock::acquire_with_timeout(&lock_path, lock_timeout)?;
            verify_path_identity(&lock_path, lock_identity)?;
            for existing_path in [&sealed_path, &corrupt_path] {
                match fs::symlink_metadata(existing_path) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "journal writer id already has a sealed or archived segment",
                        ));
                    }
                }
            }

            let mut options = OpenOptions::new();
            options.create_new(true).read(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            let identity = opened_file_identity(&file, &file.metadata()?)?;
            _segment_anchor = Some(file.try_clone()?);
            verify_path_identity(&path, identity)?;
            segment_identity = Some(identity);
            if let Some(hook) = after_segment_create.as_mut() {
                hook(&path)?;
            }
            let remaining = lock_timeout.saturating_sub(started.elapsed());
            let segment_lock = ExclusiveFileLock::acquire_with_timeout(&path, remaining)?;
            file.write_all(&framing::encode_segment_header())?;
            file.flush()?;
            file.sync_all()?;
            sync_parent(&path)?;
            verify_path_identity(&path, identity)?;
            Ok(JournalSegmentWriter {
                writer_id,
                path: path.clone(),
                file,
                identity,
                append_failed: false,
                _segment_lock: segment_lock,
                _reservation_anchor: reservation.anchor,
                _reservation_lock: lock,
            })
        })();
        match result {
            Ok(writer) => Ok(writer),
            Err(source) => {
                if let Err(cleanup) =
                    rollback_writer_creation(&path, &lock_path, segment_identity, lock_identity)
                {
                    return Err(io::Error::new(
                        cleanup.kind(),
                        format!(
                            "journal writer creation failed ({source}); rollback failed ({cleanup})"
                        ),
                    ));
                }
                Err(source)
            }
        }
    }

    pub(crate) fn discover(&self) -> io::Result<Vec<DiscoveredSegment>> {
        self.ensure_directory()?;
        let mut segments = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 journal file name")
            })?;
            if let Some(writer_name) = name.strip_suffix(".corrupt") {
                parse_canonical_writer_id(writer_name)?;
                validate_regular_path(&entry.path())?;
                continue;
            }
            if let Some(writer_name) = name.strip_suffix(".lock") {
                parse_canonical_writer_id(writer_name)?;
                validate_regular_path(&entry.path())?;
                continue;
            }
            let (writer_name, state) = match name.strip_suffix(".sealed") {
                Some(writer_name) => (writer_name, SegmentState::Sealed),
                None => (name, SegmentState::Active),
            };
            let writer_id = parse_canonical_writer_id(writer_name)?;
            let corrupt_path = self
                .directory
                .join(format!("{}.corrupt", writer_id.hyphenated()));
            match fs::symlink_metadata(&corrupt_path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "active or sealed segment duplicates archived writer identity",
                    ));
                }
            }
            let path = entry.path();
            let metadata = validate_regular_path(&path)?;
            let anchor = open_segment_for_read(&path)?;
            let identity = opened_file_identity(&anchor, &anchor.metadata()?)?;
            if path_file_identity(&path, &metadata)? != identity {
                return Err(identity_changed_error());
            }
            let lock_path = self
                .directory
                .join(format!("{}.lock", writer_id.hyphenated()));
            let lock_metadata = validate_regular_path(&lock_path).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "journal segment has no corresponding writer lock",
                    )
                } else {
                    error
                }
            })?;
            let lock_anchor = open_segment_for_read(&lock_path)?;
            let lock_identity = opened_file_identity(&lock_anchor, &lock_anchor.metadata()?)?;
            if path_file_identity(&lock_path, &lock_metadata)? != lock_identity {
                return Err(identity_changed_error());
            }
            if segments.iter().any(|segment: &DiscoveredSegment| {
                segment.writer_id == writer_id
                    || segment.identity == identity
                    || segment.lock_identity == lock_identity
            }) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate journal segment logical or physical identity",
                ));
            }
            segments.push(DiscoveredSegment {
                writer_id,
                state,
                path,
                identity,
                anchor: Arc::new(anchor),
                lock_path,
                lock_identity,
                lock_anchor: Arc::new(lock_anchor),
            });
        }
        Ok(segments)
    }

    pub(crate) fn read_frames(
        &self,
        segment: &DiscoveredSegment,
        mut visit_frame: impl FnMut(RawJournalFrame) -> io::Result<()>,
    ) -> io::Result<SegmentRead> {
        self.read_inner(segment, None, None, &mut visit_frame)
    }

    #[cfg(test)]
    pub(crate) fn read(&self, segment: &DiscoveredSegment) -> io::Result<SegmentRead> {
        self.read_inner(segment, None, None, &mut |_| Ok(()))
    }

    #[cfg(test)]
    fn read_with_test_hook(
        &self,
        segment: &DiscoveredSegment,
        after_snapshot: &mut dyn FnMut(),
    ) -> io::Result<SegmentRead> {
        self.read_inner(segment, None, Some(after_snapshot), &mut |_| Ok(()))
    }

    #[cfg(test)]
    fn read_with_pre_fingerprint_hook(
        &self,
        segment: &DiscoveredSegment,
        before_fingerprint: &mut dyn FnMut(),
    ) -> io::Result<SegmentRead> {
        self.read_inner(segment, Some(before_fingerprint), None, &mut |_| Ok(()))
    }

    fn read_inner(
        &self,
        segment: &DiscoveredSegment,
        mut before_fingerprint: Option<&mut dyn FnMut()>,
        mut after_snapshot: Option<&mut dyn FnMut()>,
        visit_frame: &mut dyn FnMut(RawJournalFrame) -> io::Result<()>,
    ) -> io::Result<SegmentRead> {
        self.ensure_directory()?;
        let (mut file, before, snapshot_len, snapshot_sha256) = {
            let mut attempts = 0;
            loop {
                let mut file = open_segment_for_read(&segment.path)?;
                let before = file.metadata()?;
                let snapshot_len = before.len();
                if opened_file_identity(&file, &before)? != segment.identity {
                    return Err(identity_changed_error());
                }
                verify_path_identity(&segment.path, segment.identity)?;
                if let Some(hook) = before_fingerprint.take() {
                    hook();
                }
                match fingerprint_open_snapshot(&mut file, snapshot_len) {
                    Ok(snapshot_sha256) => {
                        break (file, before, snapshot_len, snapshot_sha256);
                    }
                    Err(error)
                        if segment.state == SegmentState::Active
                            && error.kind() == io::ErrorKind::UnexpectedEof
                            && attempts + 1 < ACTIVE_SNAPSHOT_ATTEMPTS =>
                    {
                        attempts += 1;
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        if let Some(hook) = after_snapshot.as_mut() {
            hook();
        }
        verify_read_stability(segment, &file, &before, snapshot_len)?;
        let mut parsed_hasher = Sha256::new();
        let mut header = read_up_to_hashed(
            &mut file,
            snapshot_len.min(SEGMENT_HEADER_LEN as u64) as usize,
            &mut parsed_hasher,
        )?;
        // Finish parsing and stability validation before exposing any frame to
        // a callback that may have irreversible effects.
        let mut validated_frames = Vec::new();
        let tail = if let Err(error) = framing::decode_segment_header(&header) {
            extend_corruption_capture(&mut file, &mut header, snapshot_len, &mut parsed_hasher)?;
            classify_framing_failure(segment.state, 0, snapshot_len, header, error)
        } else {
            let mut offset = SEGMENT_HEADER_LEN as u64;
            loop {
                if offset == snapshot_len {
                    break SegmentTail::Complete;
                }
                let region_len = snapshot_len - offset;
                let mut raw_bytes =
                    read_up_to_hashed(&mut file, region_len.min(4) as usize, &mut parsed_hasher)?;
                if raw_bytes.len() < 4 {
                    break classify_framing_failure(
                        segment.state,
                        offset,
                        region_len,
                        raw_bytes,
                        framing::FramingError::Truncated,
                    );
                }
                let body_len =
                    u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
                if body_len > framing::MAX_RECORD_LEN {
                    extend_corruption_capture(
                        &mut file,
                        &mut raw_bytes,
                        region_len,
                        &mut parsed_hasher,
                    )?;
                    break SegmentTail::DefinitiveCorruption {
                        offset,
                        region_len,
                        raw_bytes,
                        error: framing::FramingError::RecordTooLong(body_len),
                    };
                }
                let frame_len = framing::FRAME_OVERHEAD + body_len as usize;
                let available = region_len.min(frame_len as u64) as usize;
                raw_bytes.extend_from_slice(&read_up_to_hashed(
                    &mut file,
                    available.saturating_sub(raw_bytes.len()),
                    &mut parsed_hasher,
                )?);
                if raw_bytes.len() < frame_len {
                    break classify_framing_failure(
                        segment.state,
                        offset,
                        region_len,
                        raw_bytes,
                        framing::FramingError::Truncated,
                    );
                }
                match framing::decode_frame(&raw_bytes) {
                    Ok(decoded) => {
                        validated_frames.push(RawJournalFrame {
                            offset,
                            record_version: decoded.record_version,
                            body: decoded.body,
                            raw_bytes,
                        });
                        offset += frame_len as u64;
                    }
                    Err(error) => {
                        extend_corruption_capture(
                            &mut file,
                            &mut raw_bytes,
                            region_len,
                            &mut parsed_hasher,
                        )?;
                        break classify_framing_failure(
                            segment.state,
                            offset,
                            region_len,
                            raw_bytes,
                            error,
                        );
                    }
                }
            }
        };
        let parsed_position = file.stream_position()?;
        let parsed_snapshot_complete = hash_remaining_snapshot(
            &mut file,
            snapshot_len.saturating_sub(parsed_position),
            &mut parsed_hasher,
        )?;
        if parsed_snapshot_complete {
            let parsed_sha256: String = parsed_hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if parsed_sha256 != snapshot_sha256 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "journal segment content changed between fingerprint and parse",
                ));
            }
        } else if segment.state == SegmentState::Sealed {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sealed journal segment shrank while parsing",
            ));
        }
        verify_read_stability(segment, &file, &before, snapshot_len)?;
        let frame_count = validated_frames.len();
        #[cfg(test)]
        let frames = validated_frames.clone();
        for frame in validated_frames {
            visit_frame(frame)?;
        }
        Ok(SegmentRead {
            #[cfg(test)]
            frames,
            frame_count,
            tail,
            writer_id: segment.writer_id,
            identity: segment.identity,
            snapshot_len,
            snapshot_sha256,
        })
    }

    pub(crate) fn seal(
        &self,
        segment: &DiscoveredSegment,
        timeout: Duration,
    ) -> Result<SealOutcome, SegmentMutationError> {
        self.seal_inner(segment, timeout, None)
    }

    #[cfg(test)]
    fn seal_with_test_hook(
        &self,
        segment: &DiscoveredSegment,
        timeout: Duration,
        before_rename: &mut dyn FnMut(),
    ) -> Result<SealOutcome, SegmentMutationError> {
        self.seal_inner(segment, timeout, Some(before_rename))
    }

    fn seal_inner(
        &self,
        segment: &DiscoveredSegment,
        timeout: Duration,
        mut before_rename: Option<&mut dyn FnMut()>,
    ) -> Result<SealOutcome, SegmentMutationError> {
        self.ensure_directory()?;
        if segment.state != SegmentState::Active {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only an active journal segment can be sealed",
            )
            .into());
        }
        let stem = segment.writer_id.hyphenated().to_string();
        let lock_path = self.directory.join(format!("{stem}.lock"));
        if lock_path != segment.lock_path {
            return Err(identity_changed_error().into());
        }
        verify_path_identity(&lock_path, segment.lock_identity)?;
        let started = Instant::now();
        let lock = match ExclusiveFileLock::acquire_with_timeout(&lock_path, timeout) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(SealOutcome::WriterAlive);
            }
            Err(error) => return Err(error.into()),
        };
        verify_path_identity(&lock_path, segment.lock_identity)?;
        verify_path_identity(&segment.path, segment.identity)?;
        let remaining = timeout.saturating_sub(started.elapsed());
        let segment_lock = match ExclusiveFileLock::acquire_with_timeout(&segment.path, remaining) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Ok(SealOutcome::WriterAlive);
            }
            Err(error) => return Err(error.into()),
        };
        verify_path_identity(&segment.path, segment.identity)?;
        let sealed_path = self.directory.join(format!("{stem}.sealed"));
        match fs::symlink_metadata(&sealed_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "sealed journal segment already exists",
                )
                .into());
            }
        }
        if let Some(hook) = before_rename.as_mut() {
            hook();
        }
        rename_missing_target_durable(&segment.path, &sealed_path, segment.identity)
            .map_err(SegmentMutationError::from)?;
        drop(segment_lock);
        drop(lock);
        Ok(SealOutcome::Sealed(DiscoveredSegment {
            writer_id: segment.writer_id,
            state: SegmentState::Sealed,
            path: sealed_path,
            identity: segment.identity,
            anchor: Arc::clone(&segment.anchor),
            lock_path: segment.lock_path.clone(),
            lock_identity: segment.lock_identity,
            lock_anchor: Arc::clone(&segment.lock_anchor),
        }))
    }

    pub(crate) fn delete_resolved_segment(
        &self,
        segment: &DiscoveredSegment,
        resolved: AllRecordsResolved,
    ) -> Result<(), SegmentMutationError> {
        self.delete_resolved_segment_inner(
            segment,
            resolved,
            None,
            &mut sync_parent,
            REMOVE_LOCK_AFTER_SEGMENT_SYNC,
        )
    }

    #[cfg(test)]
    fn delete_resolved_segment_with_test_hook(
        &self,
        segment: &DiscoveredSegment,
        resolved: AllRecordsResolved,
        after_segment_sync: &mut dyn FnMut(),
    ) -> Result<(), SegmentMutationError> {
        self.delete_resolved_segment_inner(
            segment,
            resolved,
            Some(after_segment_sync),
            &mut sync_parent,
            true,
        )
    }

    #[cfg(test)]
    fn delete_resolved_segment_with_sync_hook(
        &self,
        segment: &DiscoveredSegment,
        resolved: AllRecordsResolved,
        sync_parent: &mut dyn FnMut(&Path) -> io::Result<()>,
    ) -> Result<(), SegmentMutationError> {
        self.delete_resolved_segment_inner(segment, resolved, None, sync_parent, true)
    }

    #[cfg(test)]
    fn delete_resolved_segment_without_durable_directory_sync(
        &self,
        segment: &DiscoveredSegment,
        resolved: AllRecordsResolved,
    ) -> Result<(), SegmentMutationError> {
        self.delete_resolved_segment_inner(segment, resolved, None, &mut sync_parent, false)
    }

    fn delete_resolved_segment_inner(
        &self,
        segment: &DiscoveredSegment,
        resolved: AllRecordsResolved,
        mut after_segment_sync: Option<&mut dyn FnMut()>,
        sync_parent: &mut dyn FnMut(&Path) -> io::Result<()>,
        remove_lock_after_segment_sync: bool,
    ) -> Result<(), SegmentMutationError> {
        self.ensure_directory()?;
        if segment.state != SegmentState::Sealed
            || segment.writer_id != resolved.writer_id
            || segment.identity != resolved.identity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resolution capability does not match sealed segment identity",
            )
            .into());
        }
        verify_path_identity(&segment.path, segment.identity)?;
        verify_path_identity(&segment.lock_path, segment.lock_identity)?;
        let (size_bytes, content_sha256) = sealed_content_fingerprint(segment)?;
        if size_bytes != resolved.size_bytes || content_sha256 != resolved.content_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sealed journal segment changed after records were resolved",
            )
            .into());
        }
        fs::remove_file(&segment.path)?;
        sync_parent(&segment.path).map_err(|source| SegmentMutationError {
            published: true,
            target_conflict: false,
            source,
        })?;
        if let Some(hook) = after_segment_sync.as_mut() {
            hook();
        }
        if !remove_lock_after_segment_sync {
            // Windows cannot durably order directory entry deletion. Keeping
            // the ignored lock sidecar makes a resurrected segment replayable.
            return Ok(());
        }
        fs::remove_file(&segment.lock_path).map_err(|source| SegmentMutationError {
            published: true,
            target_conflict: false,
            source,
        })?;
        sync_parent(&segment.path).map_err(|source| SegmentMutationError {
            published: true,
            target_conflict: false,
            source,
        })
    }

    pub(crate) fn archive_corrupt_segment(
        &self,
        segment: &DiscoveredSegment,
        read: &SegmentRead,
    ) -> Result<ArchivedCorruptSegment, SegmentMutationError> {
        self.ensure_directory()?;
        let region_len = match &read.tail {
            SegmentTail::DefinitiveCorruption { region_len, .. } => *region_len,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only definitive corruption can be archived",
                )
                .into());
            }
        };
        if segment.state != SegmentState::Sealed
            || segment.writer_id != read.writer_id
            || segment.identity != read.identity
            || region_len <= MAX_CORRUPTION_CAPTURE_LEN as u64
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "corruption archive requires an oversized exact sealed snapshot",
            )
            .into());
        }
        let (size_bytes, content_sha256) = sealed_content_fingerprint(segment)?;
        if size_bytes != read.snapshot_len || content_sha256 != read.snapshot_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "sealed journal segment changed after corruption was read",
            )
            .into());
        }
        let file_name = format!("{}.corrupt", segment.writer_id.hyphenated());
        let corrupt_path = self.directory.join(&file_name);
        rename_missing_target_durable(&segment.path, &corrupt_path, segment.identity)
            .map_err(SegmentMutationError::from)?;
        Ok(ArchivedCorruptSegment {
            writer_id: segment.writer_id,
            file_name,
        })
    }

    fn ensure_directory(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "journal directory path is not the opened directory",
            ));
        }
        reject_reparse_point(&metadata)?;
        let current = open_directory_anchor(&self.directory)?;
        let current_identity = opened_file_identity(&current, &current.metadata()?)?;
        let anchor_identity =
            opened_file_identity(&self.directory_anchor, &self.directory_anchor.metadata()?)?;
        if current_identity != self.directory_identity || anchor_identity != self.directory_identity
        {
            return Err(identity_changed_error());
        }
        Ok(())
    }
}

impl JournalSegmentWriter {
    pub(crate) fn append(&mut self, record: &JournalRecord) -> io::Result<AppendAcknowledged> {
        self.ensure_appendable()?;
        let body = encode_record_body(record)?;
        let frame = framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body)
            .map_err(framing_error)?;
        verify_path_identity(&self.path, self.identity)?;
        let offset = self.file.seek(SeekFrom::End(0))?;
        let result = (|| {
            self.file.write_all(&frame)?;
            self.file.flush()?;
            self.file.sync_all()?;
            verify_path_identity(&self.path, self.identity)?;
            Ok(AppendAcknowledged {
                offset,
                frame_len: frame.len() as u64,
            })
        })();
        match result {
            Ok(acknowledged) => Ok(acknowledged),
            Err(error) => self.fail_append_and_rollback(offset, error),
        }
    }

    #[cfg(test)]
    fn append_with_test_fault(
        &mut self,
        record: &JournalRecord,
        fault: AppendTestFault,
    ) -> io::Result<AppendAcknowledged> {
        self.ensure_appendable()?;
        verify_path_identity(&self.path, self.identity)?;
        let body = encode_record_body(record)?;
        let frame = framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body)
            .map_err(framing_error)?;
        let offset = self.file.seek(SeekFrom::End(0))?;
        match fault {
            AppendTestFault::AfterPartialWrite => {
                let partial_len = (frame.len() / 2).max(1);
                self.file.write_all(&frame[..partial_len])?;
                self.fail_append_and_rollback(
                    offset,
                    io::Error::other("injected journal append failure after partial write"),
                )
            }
            AppendTestFault::BeforeFlush => {
                self.file.write_all(&frame)?;
                self.fail_append_and_rollback(
                    offset,
                    io::Error::other("injected journal append failure before flush"),
                )
            }
            AppendTestFault::BeforeSync => {
                self.file.write_all(&frame)?;
                self.file.flush()?;
                self.fail_append_and_rollback(
                    offset,
                    io::Error::other("injected journal append failure before sync"),
                )
            }
        }
    }

    #[cfg(test)]
    fn append_with_test_pause(
        &mut self,
        record: &JournalRecord,
        partial_written: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    ) -> io::Result<AppendAcknowledged> {
        self.ensure_appendable()?;
        verify_path_identity(&self.path, self.identity)?;
        let body = encode_record_body(record)?;
        let frame = framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &body)
            .map_err(framing_error)?;
        let offset = self.file.seek(SeekFrom::End(0))?;
        let partial_len = (frame.len() / 2).max(1);
        self.file.write_all(&frame[..partial_len])?;
        self.file.flush()?;
        partial_written
            .send(())
            .map_err(|_| io::Error::other("append pause receiver closed"))?;
        resume
            .recv()
            .map_err(|_| io::Error::other("append pause sender closed"))?;
        self.file.write_all(&frame[partial_len..])?;
        self.file.flush()?;
        self.file.sync_all()?;
        verify_path_identity(&self.path, self.identity)?;
        Ok(AppendAcknowledged {
            offset,
            frame_len: frame.len() as u64,
        })
    }

    fn ensure_appendable(&self) -> io::Result<()> {
        if self.append_failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "journal writer is poisoned after an unacknowledged append",
            ));
        }
        Ok(())
    }

    fn fail_append_and_rollback(
        &mut self,
        offset: u64,
        source: io::Error,
    ) -> io::Result<AppendAcknowledged> {
        self.append_failed = true;
        let rollback = self
            .file
            .set_len(offset)
            .and_then(|_| self.file.flush())
            .and_then(|_| self.file.sync_all())
            .and_then(|_| verify_path_identity(&self.path, self.identity));
        match rollback {
            Ok(()) => Err(source),
            Err(rollback_error) => Err(io::Error::new(
                source.kind(),
                format!("{source}; journal append rollback failed: {rollback_error}"),
            )),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

fn rollback_writer_creation(
    path: &Path,
    lock_path: &Path,
    segment_identity: Option<DurableFileIdentity>,
    lock_identity: DurableFileIdentity,
) -> io::Result<()> {
    let mut sync = sync_parent;
    if let Some(identity) = segment_identity {
        remove_created_path(path, identity, &mut sync)?;
    }
    remove_created_path(lock_path, lock_identity, &mut sync)
}

fn create_lock_reservation(path: &Path) -> io::Result<CreatedReservation> {
    create_lock_reservation_inner(path, &mut File::sync_all, &mut sync_parent)
}

fn create_lock_reservation_inner(
    path: &Path,
    sync_file: &mut dyn FnMut(&File) -> io::Result<()>,
    sync_parent: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> io::Result<CreatedReservation> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let identity = opened_file_identity(&file, &file.metadata()?)?;
    verify_path_identity(path, identity)?;
    let result = sync_file(&file).and_then(|()| sync_parent(path));
    match result {
        Ok(()) => Ok(CreatedReservation {
            anchor: file,
            identity,
        }),
        Err(source) => match remove_created_path(path, identity, sync_parent) {
            Ok(()) => Err(source),
            Err(cleanup) => Err(io::Error::new(
                cleanup.kind(),
                format!(
                    "journal reservation creation failed ({source}); rollback failed ({cleanup})"
                ),
            )),
        },
    }
}

fn remove_created_path(
    path: &Path,
    expected_identity: DurableFileIdentity,
    sync_parent: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let metadata = match validate_regular_path(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => return Ok(()),
        Err(error) => return Err(error),
    };
    if path_file_identity(path, &metadata)? != expected_identity {
        return Ok(());
    }
    fs::remove_file(path)?;
    sync_parent(path)
}

fn encode_record_body(record: &JournalRecord) -> io::Result<Vec<u8>> {
    let mut buffer = LimitedJsonBuffer {
        bytes: Vec::new(),
        limit: framing::MAX_RECORD_LEN as usize,
        exceeded: false,
    };
    match serde_json::to_writer(&mut buffer, record) {
        Ok(()) => Ok(buffer.bytes),
        Err(_) if buffer.exceeded => Err(framing_error(framing::FramingError::RecordTooLong(
            framing::MAX_RECORD_LEN + 1,
        ))),
        Err(error) => Err(io::Error::other(error)),
    }
}

struct LimitedJsonBuffer {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for LimitedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal record JSON exceeds framing limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_canonical_writer_id(value: &str) -> io::Result<Uuid> {
    let writer_id = Uuid::parse_str(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid journal writer id"))?;
    if writer_id.is_nil() || writer_id.hyphenated().to_string() != value {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal writer id is not a canonical non-nil lowercase UUID",
        ));
    }
    Ok(writer_id)
}

fn verify_path_identity(path: &Path, expected: DurableFileIdentity) -> io::Result<()> {
    let metadata = validate_regular_path(path)?;
    if path_file_identity(path, &metadata)? != expected {
        return Err(identity_changed_error());
    }
    Ok(())
}

fn validate_regular_path(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "journal path is a hardlink alias",
            ));
        }
    }
    #[cfg(windows)]
    {
        let file = open_windows_reparse_aware(path)?;
        reject_windows_hardlinks(&file)?;
    }
    reject_reparse_point(&metadata)?;
    Ok(metadata)
}

fn open_segment_for_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "opened journal segment is not a regular file",
        ));
    }
    reject_reparse_point(&metadata)?;
    #[cfg(windows)]
    reject_windows_hardlinks(&file)?;
    Ok(file)
}

fn open_directory_anchor(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let directory = options.open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal directory anchor is not a directory",
        ));
    }
    reject_reparse_point(&metadata)?;
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_reparse_aware(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(windows)]
fn reject_windows_hardlinks(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.nNumberOfLinks != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal path is a hardlink alias",
        ));
    }
    Ok(())
}

fn read_up_to(file: &mut File, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(len);
    Read::by_ref(file)
        .take(len as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_up_to_hashed(file: &mut File, len: usize, hasher: &mut Sha256) -> io::Result<Vec<u8>> {
    let bytes = read_up_to(file, len)?;
    hasher.update(&bytes);
    Ok(bytes)
}

fn hash_remaining_snapshot(
    file: &mut File,
    mut remaining: u64,
    hasher: &mut Sha256,
) -> io::Result<bool> {
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Ok(false);
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(true)
}

fn fingerprint_open_snapshot(file: &mut File, snapshot_len: u64) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut remaining = snapshot_len;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "journal segment shrank while snapshotting",
            ));
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn extend_corruption_capture(
    file: &mut File,
    raw_bytes: &mut Vec<u8>,
    region_len: u64,
    hasher: &mut Sha256,
) -> io::Result<()> {
    let capture_len = region_len.min(MAX_CORRUPTION_CAPTURE_LEN as u64) as usize;
    if raw_bytes.len() < capture_len {
        raw_bytes.extend_from_slice(&read_up_to_hashed(
            file,
            capture_len - raw_bytes.len(),
            hasher,
        )?);
    }
    Ok(())
}

fn classify_framing_failure(
    state: SegmentState,
    offset: u64,
    region_len: u64,
    raw_bytes: Vec<u8>,
    error: framing::FramingError,
) -> SegmentTail {
    if error == framing::FramingError::Truncated && state == SegmentState::Active {
        SegmentTail::Provisional { offset, raw_bytes }
    } else {
        SegmentTail::DefinitiveCorruption {
            offset,
            region_len,
            raw_bytes,
            error,
        }
    }
}

fn verify_read_stability(
    segment: &DiscoveredSegment,
    file: &File,
    before: &fs::Metadata,
    snapshot_len: u64,
) -> io::Result<()> {
    let after = file.metadata()?;
    if opened_file_identity(file, &after)? != segment.identity {
        return Err(identity_changed_error());
    }
    if segment.state == SegmentState::Sealed
        && (after.len() != snapshot_len || after.modified().ok() != before.modified().ok())
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "sealed journal segment changed while reading",
        ));
    }
    verify_path_identity(&segment.path, segment.identity)
}

fn sealed_content_fingerprint(segment: &DiscoveredSegment) -> io::Result<(u64, String)> {
    let mut file = open_segment_for_read(&segment.path)?;
    let before = file.metadata()?;
    if opened_file_identity(&file, &before)? != segment.identity {
        return Err(identity_changed_error());
    }
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size_bytes = size_bytes.saturating_add(read as u64);
    }
    let after = file.metadata()?;
    verify_path_identity(&segment.path, segment.identity)?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || size_bytes != after.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "sealed journal segment changed while fingerprinting",
        ));
    }
    let content_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((size_bytes, content_sha256))
}

#[cfg(windows)]
fn reject_reparse_point(metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal path is a reparse point",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

fn identity_changed_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "journal segment identity changed",
    )
}

fn framing_error(error: framing::FramingError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid journal framing: {error:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AllRecordsResolved, AppendTestFault, JournalSegmentStore, SealOutcome, SegmentState,
        SegmentTail, create_lock_reservation_inner,
    };
    use crate::providers::durable_file::{ExclusiveFileLock, sync_parent};
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use vaultkern_runtime_protocol::contracts::JournalRecord;
    use vaultkern_runtime_protocol::framing::{
        self, SEGMENT_FORMAT_VERSION, SEGMENT_HEADER_LEN, SEGMENT_MAGIC,
    };

    fn record(seq: u64) -> JournalRecord {
        JournalRecord {
            seq,
            op_id: format!("01890f3e-7b00-7000-8000-{seq:012x}"),
            vault_ref_id: "vault-alpha".to_owned(),
            payload_sealed: "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            base_fingerprint: "00".repeat(32),
            created_at: 1_700_000_000 + seq,
        }
    }

    #[test]
    fn writer_pins_header_and_preserves_multiple_raw_frames() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000001").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        let first = record(1);
        let second = record(2);

        writer.append(&first).unwrap();
        writer.append(&second).unwrap();

        let bytes = fs::read(writer.path()).unwrap();
        assert_eq!(&bytes[..4], &SEGMENT_MAGIC);
        assert_eq!(
            &bytes[4..SEGMENT_HEADER_LEN],
            &SEGMENT_FORMAT_VERSION.to_le_bytes()
        );
        let expected_first = framing::encode_frame(
            JournalRecord::SCHEMA_VERSION as u16,
            &serde_json::to_vec(&first).unwrap(),
        )
        .unwrap();
        let expected_second = framing::encode_frame(
            JournalRecord::SCHEMA_VERSION as u16,
            &serde_json::to_vec(&second).unwrap(),
        )
        .unwrap();
        assert_eq!(
            &bytes[SEGMENT_HEADER_LEN..],
            [expected_first.as_slice(), expected_second.as_slice()].concat()
        );

        let segments = store.discover().unwrap();
        assert_eq!(segments.len(), 1);
        let read = store.read(&segments[0]).unwrap();
        assert_eq!(read.tail, SegmentTail::Complete);
        assert_eq!(read.frames.len(), 2);
        assert_eq!(read.frames[0].raw_bytes, expected_first);
        assert_eq!(read.frames[1].raw_bytes, expected_second);
        assert!(writer.path().exists());
        assert!(!temp.path().join(format!("{writer_id}.sealed")).exists());
    }

    #[test]
    fn production_reader_streams_frames_without_collecting_the_segment() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000002").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        writer.append(&record(2)).unwrap();
        let segment = store.discover().unwrap().pop().unwrap();
        let mut raw_frames = Vec::new();

        let read = store
            .read_frames(&segment, |frame| {
                raw_frames.push(frame.raw_bytes);
                Ok(())
            })
            .unwrap();

        assert_eq!(read.frame_count, 2);
        assert_eq!(raw_frames.len(), 2);
        assert_eq!(read.tail, SegmentTail::Complete);
    }

    #[test]
    fn writer_ids_are_single_use_and_independent_writers_do_not_share_a_lock() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let first_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000011").unwrap();
        let second_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000012").unwrap();
        let mut first = store.create_writer_with_id(first_id).unwrap();
        let mut second = store.create_writer_with_id(second_id).unwrap();

        first.append(&record(1)).unwrap();
        second.append(&record(2)).unwrap();

        assert_ne!(first.path(), second.path());
        assert_eq!(store.discover().unwrap().len(), 2);
        drop(first);
        let error = store.create_writer_with_id(first_id).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        second.append(&record(3)).unwrap();
    }

    #[test]
    fn writer_creation_uses_a_bounded_lock_acquisition() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000013").unwrap();
        let (path_tx, path_rx) = mpsc::channel::<std::path::PathBuf>();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let contender = thread::spawn(move || {
            let lock_path = path_rx.recv().unwrap();
            let lock = ExclusiveFileLock::acquire(&lock_path).unwrap();
            acquired_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(lock);
        });
        let mut after_reservation = |lock_path: &std::path::Path| {
            path_tx.send(lock_path.to_owned()).unwrap();
            acquired_rx.recv().unwrap();
        };
        let started = std::time::Instant::now();

        let error = store
            .create_writer_with_test_hook(
                writer_id,
                Duration::from_millis(30),
                &mut after_reservation,
            )
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(started.elapsed() >= Duration::from_millis(30));
        assert!(started.elapsed() < Duration::from_millis(250));
        release_tx.send(()).unwrap();
        contender.join().unwrap();
        assert!(!temp.path().join(format!("{writer_id}.lock")).exists());
        drop(store.create_writer_with_id(writer_id).unwrap());
    }

    #[test]
    fn writer_creation_rejects_replaced_reservation_without_deleting_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000016").unwrap();
        let lock_path = temp.path().join(format!("{writer_id}.lock"));
        let replacement = b"replacement reservation";
        let mut replace_reservation = |path: &Path| {
            fs::remove_file(path).unwrap();
            fs::write(path, replacement).unwrap();
        };

        let error = store
            .create_writer_with_test_hook(
                writer_id,
                Duration::from_secs(1),
                &mut replace_reservation,
            )
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(&lock_path).unwrap(), replacement);
        assert!(!temp.path().join(writer_id.to_string()).exists());
    }

    #[test]
    fn writer_creation_rolls_back_segment_after_header_setup_failure() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000014").unwrap();
        let mut fail_after_segment_create = |_: &std::path::Path| {
            Err(std::io::Error::other(
                "injected journal header setup failure",
            ))
        };

        let error = store
            .create_writer_with_post_create_test_hook(writer_id, &mut fail_after_segment_create)
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(!temp.path().join(writer_id.to_string()).exists());
        assert!(!temp.path().join(format!("{writer_id}.lock")).exists());
        drop(store.create_writer_with_id(writer_id).unwrap());
    }

    #[test]
    fn writer_creation_rollback_preserves_replacement_path() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000015").unwrap();
        let replacement = b"replacement owned by another actor";
        let mut replace_then_fail = |path: &std::path::Path| {
            fs::remove_file(path).unwrap();
            fs::write(path, replacement).unwrap();
            Err(std::io::Error::other("injected failure after replacement"))
        };

        store
            .create_writer_with_post_create_test_hook(writer_id, &mut replace_then_fail)
            .unwrap_err();

        assert_eq!(
            fs::read(temp.path().join(writer_id.to_string())).unwrap(),
            replacement
        );
        assert!(!temp.path().join(format!("{writer_id}.lock")).exists());
    }

    #[test]
    fn reservation_file_sync_failure_removes_created_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("reservation.lock");
        let mut fail_file_sync = |_: &File| Err(io::Error::other("injected file sync failure"));
        let mut parent_syncs = 0;
        let mut sync_parent = |_: &Path| {
            parent_syncs += 1;
            Ok(())
        };

        let error = create_lock_reservation_inner(&path, &mut fail_file_sync, &mut sync_parent)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(parent_syncs, 1);
        assert!(!path.exists());
    }

    #[test]
    fn reservation_parent_sync_failure_removes_and_syncs_created_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("reservation.lock");
        let mut sync_file = File::sync_all;
        let mut parent_syncs = 0;
        let mut fail_first_parent_sync = |_: &Path| {
            parent_syncs += 1;
            if parent_syncs == 1 {
                Err(io::Error::other("injected parent sync failure"))
            } else {
                Ok(())
            }
        };

        let error =
            create_lock_reservation_inner(&path, &mut sync_file, &mut fail_first_parent_sync)
                .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(parent_syncs, 2);
        assert!(!path.exists());
    }

    #[test]
    fn production_writer_generation_uses_fresh_ids() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();

        let first = store.create_writer().unwrap();
        let second = store.create_writer().unwrap();

        assert_ne!(first.writer_id, second.writer_id);
    }

    #[test]
    fn caller_supplied_writer_id_must_be_non_nil() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();

        let error = store.create_writer_with_id(uuid::Uuid::nil()).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(store.discover().unwrap().is_empty());
        let nil_name = uuid::Uuid::nil().to_string();
        fs::write(
            temp.path().join(&nil_name),
            framing::encode_segment_header(),
        )
        .unwrap();
        fs::write(temp.path().join(format!("{nil_name}.lock")), b"").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn active_eof_truncation_is_provisional_and_keeps_complete_frames() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000021").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        writer.append(&record(2)).unwrap();
        let path = writer.path().to_owned();
        drop(writer);
        let complete = fs::read(&path).unwrap();
        fs::write(&path, &complete[..complete.len() - 3]).unwrap();

        let segments = store.discover().unwrap();
        let read = store.read(&segments[0]).unwrap();

        assert_eq!(read.frames.len(), 1);
        match read.tail {
            SegmentTail::Provisional { offset, raw_bytes } => {
                assert_eq!(
                    offset,
                    (SEGMENT_HEADER_LEN + read.frames[0].raw_bytes.len()) as u64
                );
                assert_eq!(raw_bytes, complete[offset as usize..complete.len() - 3]);
            }
            other => panic!("expected provisional tail, got {other:?}"),
        }
    }

    #[test]
    fn active_snapshot_retries_when_append_rollback_shrinks_the_file() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000020").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let path = writer.path().to_owned();
        let committed_len = fs::metadata(&path).unwrap().len();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0x20, 0, 0])
            .unwrap();
        let segment = store.discover().unwrap().pop().unwrap();
        let mut roll_back = || {
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(committed_len)
                .unwrap();
        };

        let read = store
            .read_with_pre_fingerprint_hook(&segment, &mut roll_back)
            .unwrap();

        assert_eq!(read.frames.len(), 1);
        assert_eq!(read.tail, SegmentTail::Complete);
        assert_eq!(read.snapshot_len, committed_len);
    }

    #[test]
    fn active_crc_failure_is_definitive_from_failure_offset_to_eof() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000022").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        writer.append(&record(2)).unwrap();
        writer.append(&record(3)).unwrap();
        let path = writer.path().to_owned();
        drop(writer);
        let mut bytes = fs::read(&path).unwrap();
        let first = framing::decode_frame(&bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let failure_offset = SEGMENT_HEADER_LEN + first.consumed;
        let second = framing::decode_frame(&bytes[failure_offset..]).unwrap();
        let third_offset = failure_offset + second.consumed;
        bytes[failure_offset + 7] ^= 0x40;
        fs::write(&path, &bytes).unwrap();

        let segment = store.discover().unwrap().pop().unwrap();
        let read = store.read(&segment).unwrap();

        assert_eq!(read.frames.len(), 1);
        match read.tail {
            SegmentTail::DefinitiveCorruption {
                offset,
                raw_bytes,
                error,
                ..
            } => {
                assert_eq!(offset, failure_offset as u64);
                assert_eq!(raw_bytes, bytes[failure_offset..]);
                assert!(framing::decode_frame(&raw_bytes[third_offset - failure_offset..]).is_ok());
                assert_eq!(error, framing::FramingError::CrcMismatch);
            }
            other => panic!("expected definitive corruption, got {other:?}"),
        }
    }

    #[test]
    fn active_oversize_length_is_definitive_without_allocating_the_claimed_body() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000023").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let path = writer.path().to_owned();
        drop(writer);
        let mut bytes = framing::encode_segment_header().to_vec();
        bytes.extend_from_slice(&(framing::MAX_RECORD_LEN + 1).to_le_bytes());
        bytes.extend_from_slice(b"later bytes do not make an oversize frame provisional");
        fs::write(&path, &bytes).unwrap();

        let segment = store.discover().unwrap().pop().unwrap();
        let read = store.read(&segment).unwrap();

        assert!(read.frames.is_empty());
        assert!(matches!(
            read.tail,
            SegmentTail::DefinitiveCorruption {
                offset,
                error: framing::FramingError::RecordTooLong(_),
                ..
            } if offset == SEGMENT_HEADER_LEN as u64
        ));
    }

    #[test]
    fn oversized_append_is_rejected_before_write_without_poisoning_writer() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000024").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        let before = fs::metadata(writer.path()).unwrap().len();
        let mut oversized = record(1);
        oversized.payload_sealed = "A".repeat(framing::MAX_RECORD_LEN as usize + 1);

        let error = writer.append(&oversized).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(fs::metadata(writer.path()).unwrap().len(), before);
        writer.append(&record(2)).unwrap();
    }

    #[test]
    fn living_writer_blocks_bounded_seal_then_drop_allows_sealing() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000031").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();

        assert_eq!(
            ExclusiveFileLock::acquire_with_timeout(&active.path, Duration::from_millis(30))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );

        assert_eq!(
            store.seal(&active, Duration::from_millis(30)).unwrap(),
            SealOutcome::WriterAlive
        );
        assert_eq!(active.state, SegmentState::Active);
        assert!(active.path.exists());

        drop(writer);
        drop(
            ExclusiveFileLock::acquire_with_timeout(&active.path, Duration::from_secs(1)).unwrap(),
        );
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(sealed) => sealed,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        assert_eq!(sealed.state, SegmentState::Sealed);
        assert!(!active.path.exists());
        assert!(sealed.path.exists());
        assert_eq!(store.read(&sealed).unwrap().frames.len(), 1);
    }

    #[test]
    fn seal_never_clobbers_a_destination_that_appears_during_publish() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000032").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed_path = temp.path().join(format!("{writer_id}.sealed"));
        let mut create_destination = || {
            fs::write(&sealed_path, b"sentinel").unwrap();
        };

        let error = store
            .seal_with_test_hook(&active, Duration::from_secs(1), &mut create_destination)
            .unwrap_err();

        assert!(!error.published);
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&sealed_path).unwrap(), b"sentinel");
        assert!(active.path.exists());
    }

    #[test]
    fn whole_delete_requires_matching_sealed_identity_and_explicit_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let first_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000041").unwrap();
        let second_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000042").unwrap();
        let first_writer = store.create_writer_with_id(first_id).unwrap();
        let second_writer = store.create_writer_with_id(second_id).unwrap();
        let mut active = store.discover().unwrap();
        active.sort_by_key(|segment| segment.writer_id);

        assert!(AllRecordsResolved::for_segment(&active[0]).is_err());
        drop(first_writer);
        drop(second_writer);
        let first = match store.seal(&active[0], Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let second = match store.seal(&active[1], Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let first_read = store.read(&first).unwrap();
        let wrong_capability = AllRecordsResolved::for_read(&first, &first_read).unwrap();

        let error = store
            .delete_resolved_segment(&second, wrong_capability)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(first.path.exists());
        assert!(second.path.exists());

        let capability = AllRecordsResolved::for_read(&first, &first_read).unwrap();
        store.delete_resolved_segment(&first, capability).unwrap();
        assert!(!first.path.exists());
        #[cfg(windows)]
        assert!(temp.path().join(format!("{first_id}.lock")).exists());
        #[cfg(not(windows))]
        assert!(!temp.path().join(format!("{first_id}.lock")).exists());
        assert!(second.path.exists());
    }

    #[test]
    fn whole_delete_rejects_sealed_content_changed_after_resolution() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000043").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        let mut changed = fs::read(&sealed.path).unwrap();
        changed[SEGMENT_HEADER_LEN + 8] ^= 0x40;
        fs::write(&sealed.path, &changed).unwrap();
        assert_eq!(
            fs::metadata(&sealed.path).unwrap().len(),
            changed.len() as u64
        );

        let error = store
            .delete_resolved_segment(&sealed, capability)
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(sealed.path.exists());
    }

    #[test]
    fn whole_delete_reports_when_segment_removal_was_already_published() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000046").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        let lock_path = sealed.lock_path.clone();
        let mut break_lock_cleanup = || {
            fs::remove_file(&lock_path).unwrap();
            fs::create_dir(&lock_path).unwrap();
        };

        let error = store
            .delete_resolved_segment_with_test_hook(&sealed, capability, &mut break_lock_cleanup)
            .unwrap_err();

        assert!(error.published);
        assert!(!sealed.path.exists());
        assert!(lock_path.is_dir());
    }

    #[test]
    fn whole_delete_syncs_segment_removal_before_unlinking_the_lock() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000047").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        let lock_path = sealed.lock_path.clone();
        let mut lock_existed_at_first_sync = false;
        let mut fail_first_sync = |_: &std::path::Path| {
            lock_existed_at_first_sync = lock_path.exists();
            Err(std::io::Error::other("injected parent sync failure"))
        };

        let error = store
            .delete_resolved_segment_with_sync_hook(&sealed, capability, &mut fail_first_sync)
            .unwrap_err();

        assert!(error.published);
        assert!(lock_existed_at_first_sync);
        assert!(lock_path.exists());
        assert!(!sealed.path.exists());
    }

    #[test]
    fn whole_delete_preserves_lock_when_directory_sync_is_not_durable() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000049").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        let lock_path = sealed.lock_path.clone();

        store
            .delete_resolved_segment_without_durable_directory_sync(&sealed, capability)
            .unwrap();

        assert!(!sealed.path.exists());
        assert!(lock_path.exists());
        assert!(store.discover().unwrap().is_empty());
    }

    #[test]
    fn resolution_capability_cannot_be_minted_without_a_read_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000044").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };

        assert!(AllRecordsResolved::for_segment(&sealed).is_err());
        assert!(sealed.path.exists());
    }

    #[test]
    fn resolution_capability_requires_a_complete_tail() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000048").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let mut bytes = fs::read(&sealed.path).unwrap();
        bytes[SEGMENT_HEADER_LEN + 8] ^= 0x40;
        fs::write(&sealed.path, bytes).unwrap();
        let read = store.read(&sealed).unwrap();
        assert!(matches!(
            read.tail,
            SegmentTail::DefinitiveCorruption { .. }
        ));

        let error = AllRecordsResolved::for_read(&sealed, &read).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(sealed.path.exists());
    }

    #[test]
    fn preserved_capped_corrupt_tail_can_be_resolved_and_pruned() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-00000000004a").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let mut bytes = fs::read(&sealed.path).unwrap();
        bytes[SEGMENT_HEADER_LEN + 8] ^= 0x40;
        fs::write(&sealed.path, bytes).unwrap();
        let read = store.read(&sealed).unwrap();
        let raw_tail = match &read.tail {
            SegmentTail::DefinitiveCorruption {
                region_len,
                raw_bytes,
                ..
            } => {
                assert_eq!(*region_len as usize, raw_bytes.len());
                raw_bytes.clone()
            }
            other => panic!("expected definitive corruption, got {other:?}"),
        };
        let preserved_path = temp.path().join("dead-letter-copy");
        let preserved_file = File::create(&preserved_path).unwrap();
        (&preserved_file).write_all(&raw_tail).unwrap();
        preserved_file.sync_all().unwrap();
        sync_parent(&preserved_path).unwrap();
        let preserved =
            super::CorruptTailPreserved::after_durable_preservation(&sealed, &read).unwrap();
        let capability =
            AllRecordsResolved::for_read_with_preserved_corrupt_tail(&sealed, &read, preserved)
                .unwrap();

        store.delete_resolved_segment(&sealed, capability).unwrap();

        assert!(!sealed.path.exists());
        assert_eq!(fs::read(preserved_path).unwrap(), raw_tail);
    }

    #[test]
    fn resolution_capability_is_bound_to_the_exact_read_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000045").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let mut changed = fs::read(&sealed.path).unwrap();
        changed[SEGMENT_HEADER_LEN + 8] ^= 0x40;
        fs::write(&sealed.path, changed).unwrap();

        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        let error = store
            .delete_resolved_segment(&sealed, capability)
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(sealed.path.exists());
    }

    #[test]
    fn discovery_rejects_illegal_names_and_duplicate_logical_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        fs::write(temp.path().join("not-a-writer"), b"VKJS\x01\x00").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_file(temp.path().join("not-a-writer")).unwrap();

        fs::write(temp.path().join("not-a-writer.lock"), b"").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_file(temp.path().join("not-a-writer.lock")).unwrap();

        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000051").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let sealed_path = temp.path().join(format!("{writer_id}.sealed"));
        fs::write(&sealed_path, framing::encode_segment_header()).unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        drop(writer);
    }

    #[test]
    fn discovery_ignores_valid_archived_corrupt_segments_but_rejects_invalid_names() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = "01890f3e-7b00-7000-8000-00000000005b";
        fs::write(
            temp.path().join(format!("{writer_id}.corrupt")),
            b"opaque archived bytes",
        )
        .unwrap();

        assert!(store.discover().unwrap().is_empty());
        assert_eq!(
            store
                .create_writer_with_id(uuid::Uuid::parse_str(writer_id).unwrap())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert!(!temp.path().join(writer_id).exists());
        fs::write(
            temp.path().join(writer_id),
            framing::encode_segment_header(),
        )
        .unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        fs::remove_file(temp.path().join(writer_id)).unwrap();

        fs::write(temp.path().join("not-a-writer.corrupt"), b"opaque").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovery_rejects_hardlink_path_escape_and_physical_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let escaped_id = "01890f3e-7b00-7000-8000-000000000058";
        fs::hard_link(outside.path(), temp.path().join(escaped_id)).unwrap();
        fs::write(temp.path().join(format!("{escaped_id}.lock")), b"").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        fs::remove_file(temp.path().join(escaped_id)).unwrap();
        fs::remove_file(temp.path().join(format!("{escaped_id}.lock"))).unwrap();
        let first_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000059").unwrap();
        let second_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-00000000005a").unwrap();
        let writer = store.create_writer_with_id(first_id).unwrap();
        fs::hard_link(writer.path(), temp.path().join(second_id.to_string())).unwrap();
        fs::write(temp.path().join(format!("{second_id}.lock")), b"").unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn discovery_rejects_segment_and_lock_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let writer_id = "01890f3e-7b00-7000-8000-000000000052";
        symlink(outside.path(), temp.path().join(writer_id)).unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        fs::remove_file(temp.path().join(writer_id)).unwrap();
        symlink(
            outside.path(),
            temp.path().join(format!("{writer_id}.lock")),
        )
        .unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_replaced_directory_before_following_it() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let journal = temp.path().join("journal");
        let outside = temp.path().join("outside");
        let original = temp.path().join("original");
        let store = JournalSegmentStore::open(&journal).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::rename(&journal, &original).unwrap();
        symlink(&outside, &journal).unwrap();

        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            store.create_writer().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_replacement_by_another_real_directory() {
        let temp = tempfile::tempdir().unwrap();
        let journal = temp.path().join("journal");
        let original = temp.path().join("original");
        let store = JournalSegmentStore::open(&journal).unwrap();
        fs::rename(&journal, &original).unwrap();
        fs::create_dir(&journal).unwrap();

        let error = store.discover().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert!(fs::read_dir(&journal).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn writer_creation_rejects_directory_replacement_before_reservation_create() {
        let temp = tempfile::tempdir().unwrap();
        let journal = temp.path().join("journal");
        let original = temp.path().join("original");
        let replacement = temp.path().join("replacement");
        let store = JournalSegmentStore::open(&journal).unwrap();
        fs::create_dir(&replacement).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-00000000005b").unwrap();
        let mut replace_directory = || {
            fs::rename(&journal, &original).unwrap();
            fs::rename(&replacement, &journal).unwrap();
        };

        let error = store
            .create_writer_with_pre_reservation_test_hook(writer_id, &mut replace_directory)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(fs::read_dir(&journal).unwrap().next().is_none());
        assert!(fs::read_dir(&original).unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn store_rejects_replaced_directory_reparse_point_before_following_it() {
        use std::os::windows::fs::symlink_dir;

        let temp = tempfile::tempdir().unwrap();
        let journal = temp.path().join("journal");
        let outside = temp.path().join("outside");
        let original = temp.path().join("original");
        let store = JournalSegmentStore::open(&journal).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::rename(&journal, &original).unwrap();
        symlink_dir(&outside, &journal).unwrap();

        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(
            store.create_writer().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }

    #[cfg(windows)]
    #[test]
    fn discovery_rejects_segment_and_lock_reparse_points() {
        use std::os::windows::fs::symlink_file;

        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let writer_id = "01890f3e-7b00-7000-8000-000000000052";
        symlink_file(outside.path(), temp.path().join(writer_id)).unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
        fs::remove_file(temp.path().join(writer_id)).unwrap();
        symlink_file(
            outside.path(),
            temp.path().join(format!("{writer_id}.lock")),
        )
        .unwrap();
        assert_eq!(
            store.discover().unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[cfg(unix)]
    #[test]
    fn append_rejects_replaced_active_path_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000056").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        let path = writer.path().to_owned();
        fs::remove_file(&path).unwrap();
        fs::write(&path, framing::encode_segment_header()).unwrap();

        assert_eq!(
            writer.append(&record(1)).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[cfg(unix)]
    #[test]
    fn seal_rejects_replaced_writer_lock_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000057").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        let lock_path = temp.path().join(format!("{writer_id}.lock"));
        fs::remove_file(&lock_path).unwrap();
        fs::write(&lock_path, b"replacement").unwrap();

        assert_eq!(
            store
                .seal(&active, Duration::from_millis(30))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(active.path.exists());
        drop(writer);
    }

    #[test]
    fn exact_identity_blocks_read_seal_and_delete_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000053").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        fs::remove_file(&active.path).unwrap();
        fs::write(&active.path, framing::encode_segment_header()).unwrap();

        assert_eq!(
            store.read(&active).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            store
                .seal(&active, Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );

        let replacement = store.discover().unwrap().pop().unwrap();
        let sealed = match store.seal(&replacement, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &read).unwrap();
        fs::remove_file(&sealed.path).unwrap();
        fs::write(&sealed.path, framing::encode_segment_header()).unwrap();
        assert_eq!(
            store
                .delete_resolved_segment(&sealed, capability)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn unknown_segment_header_version_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000054").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let path = writer.path().to_owned();
        drop(writer);
        fs::write(&path, b"VKJS\x02\x00").unwrap();
        let segment = store.discover().unwrap().pop().unwrap();

        assert!(matches!(
            store.read(&segment).unwrap().tail,
            SegmentTail::DefinitiveCorruption {
                offset: 0,
                error: framing::FramingError::UnsupportedFormatVersion(2),
                ..
            }
        ));
    }

    #[test]
    fn active_truncated_header_is_provisional_during_creation_window() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000055").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let path = writer.path().to_owned();
        drop(writer);
        fs::write(&path, b"VKJ").unwrap();
        let segment = store.discover().unwrap().pop().unwrap();

        assert_eq!(
            store.read(&segment).unwrap().tail,
            SegmentTail::Provisional {
                offset: 0,
                raw_bytes: b"VKJ".to_vec(),
            }
        );
    }

    #[test]
    fn sealed_truncation_crc_and_oversize_are_definitive_unreachable_regions() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let ids = [
            "01890f3e-7b00-7000-8000-000000000061",
            "01890f3e-7b00-7000-8000-000000000062",
            "01890f3e-7b00-7000-8000-000000000063",
        ];
        let mut sealed = Vec::new();
        for (index, id) in ids.into_iter().enumerate() {
            let mut writer = store
                .create_writer_with_id(uuid::Uuid::parse_str(id).unwrap())
                .unwrap();
            writer.append(&record(index as u64 + 1)).unwrap();
            let active = store
                .discover()
                .unwrap()
                .into_iter()
                .find(|segment| segment.writer_id == writer.writer_id)
                .unwrap();
            drop(writer);
            sealed.push(match store.seal(&active, Duration::from_secs(1)).unwrap() {
                SealOutcome::Sealed(segment) => segment,
                other => panic!("expected sealed segment, got {other:?}"),
            });
        }

        let truncated_bytes = fs::read(&sealed[0].path).unwrap();
        fs::write(
            &sealed[0].path,
            &truncated_bytes[..truncated_bytes.len() - 1],
        )
        .unwrap();
        assert!(matches!(
            store.read(&sealed[0]).unwrap().tail,
            SegmentTail::DefinitiveCorruption {
                error: framing::FramingError::Truncated,
                ..
            }
        ));

        let mut crc_bytes = fs::read(&sealed[1].path).unwrap();
        *crc_bytes.last_mut().unwrap() ^= 1;
        fs::write(&sealed[1].path, &crc_bytes).unwrap();
        assert!(matches!(
            store.read(&sealed[1]).unwrap().tail,
            SegmentTail::DefinitiveCorruption {
                error: framing::FramingError::CrcMismatch,
                ..
            }
        ));

        let mut oversize_bytes = framing::encode_segment_header().to_vec();
        oversize_bytes.extend_from_slice(&(framing::MAX_RECORD_LEN + 1).to_le_bytes());
        fs::write(&sealed[2].path, &oversize_bytes).unwrap();
        assert!(matches!(
            store.read(&sealed[2]).unwrap().tail,
            SegmentTail::DefinitiveCorruption {
                error: framing::FramingError::RecordTooLong(_),
                ..
            }
        ));
    }

    #[test]
    fn definitive_region_reports_full_length_but_caps_captured_raw_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000064").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let capture_limit = framing::MAX_RECORD_LEN as usize + framing::FRAME_OVERHEAD;
        let mut bytes = framing::encode_segment_header().to_vec();
        bytes.extend_from_slice(&(framing::MAX_RECORD_LEN + 1).to_le_bytes());
        bytes.resize(SEGMENT_HEADER_LEN + capture_limit + 128, 0x5a);
        fs::write(&sealed.path, &bytes).unwrap();

        match store.read(&sealed).unwrap().tail {
            SegmentTail::DefinitiveCorruption {
                offset,
                region_len,
                raw_bytes,
                error: framing::FramingError::RecordTooLong(_),
            } => {
                assert_eq!(offset, SEGMENT_HEADER_LEN as u64);
                assert_eq!(region_len, (bytes.len() - SEGMENT_HEADER_LEN) as u64);
                assert_eq!(raw_bytes.len(), capture_limit);
                assert_eq!(raw_bytes, bytes[SEGMENT_HEADER_LEN..][..capture_limit]);
            }
            other => panic!("expected capped definitive region, got {other:?}"),
        }
    }

    #[test]
    fn oversized_unreachable_region_is_archived_by_whole_segment_rename() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000065").unwrap();
        let writer = store.create_writer_with_id(writer_id).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let capture_limit = framing::MAX_RECORD_LEN as usize + framing::FRAME_OVERHEAD;
        let mut bytes = framing::encode_segment_header().to_vec();
        bytes.extend_from_slice(&(framing::MAX_RECORD_LEN + 1).to_le_bytes());
        bytes.resize(SEGMENT_HEADER_LEN + capture_limit + 128, 0x5a);
        fs::write(&sealed.path, &bytes).unwrap();
        let read = store.read(&sealed).unwrap();

        let archived = store.archive_corrupt_segment(&sealed, &read).unwrap();

        assert_eq!(archived.writer_id, writer_id);
        assert_eq!(archived.file_name, format!("{writer_id}.corrupt"));
        assert!(!sealed.path.exists());
        assert_eq!(
            fs::read(temp.path().join(&archived.file_name)).unwrap(),
            bytes
        );
        assert!(store.discover().unwrap().is_empty());
    }

    #[test]
    fn partial_append_failure_rolls_back_to_the_last_acknowledged_frame() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000071").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();

        let error = writer
            .append_with_test_fault(&record(2), AppendTestFault::AfterPartialWrite)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(
            writer.append(&record(3)).unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );

        let active = store.discover().unwrap().pop().unwrap();
        let active_read = store.read(&active).unwrap();
        assert_eq!(active_read.frames.len(), 1);
        assert_eq!(active_read.tail, SegmentTail::Complete);

        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        assert_eq!(store.read(&sealed).unwrap().tail, SegmentTail::Complete);
    }

    #[test]
    fn flush_and_sync_faults_never_return_append_acknowledgement() {
        for (index, fault) in [AppendTestFault::BeforeFlush, AppendTestFault::BeforeSync]
            .into_iter()
            .enumerate()
        {
            let temp = tempfile::tempdir().unwrap();
            let store = JournalSegmentStore::open(temp.path()).unwrap();
            let writer_id =
                uuid::Uuid::parse_str(&format!("01890f3e-7b00-7000-8000-00000000008{}", index + 1))
                    .unwrap();
            let mut writer = store.create_writer_with_id(writer_id).unwrap();

            let error = writer
                .append_with_test_fault(&record(1), fault)
                .unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(
                writer.append(&record(2)).unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe
            );
            let active = store.discover().unwrap().pop().unwrap();
            let read = store.read(&active).unwrap();
            assert!(read.frames.is_empty());
            assert_eq!(read.tail, SegmentTail::Complete);
        }
    }

    #[test]
    fn concurrent_reader_treats_in_progress_append_eof_as_provisional() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000072").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        let (partial_tx, partial_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            writer
                .append_with_test_pause(&record(2), partial_tx, resume_rx)
                .unwrap();
        });
        partial_rx.recv().unwrap();

        let during = store.read(&active).unwrap();
        assert_eq!(during.frames.len(), 1);
        assert!(matches!(during.tail, SegmentTail::Provisional { .. }));

        resume_tx.send(()).unwrap();
        handle.join().unwrap();
        let after = store.read(&active).unwrap();
        assert_eq!(after.frames.len(), 2);
        assert_eq!(after.tail, SegmentTail::Complete);
    }

    #[test]
    fn active_reader_uses_a_bounded_file_snapshot_when_append_races() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000073").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        let mut append_after_snapshot = || {
            writer.append(&record(2)).unwrap();
        };

        let snapshot = store
            .read_with_test_hook(&active, &mut append_after_snapshot)
            .unwrap();

        assert_eq!(snapshot.frames.len(), 1);
        assert_eq!(snapshot.tail, SegmentTail::Complete);
        let current = store.read(&active).unwrap();
        assert_eq!(current.frames.len(), 2);
        assert_eq!(current.tail, SegmentTail::Complete);
    }

    #[test]
    fn sealed_reader_rejects_in_place_change_during_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000074").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let sealed_path = sealed.path.clone();
        let mut mutate_after_snapshot = || {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&sealed_path)
                .unwrap();
            file.write_all(b"x").unwrap();
            file.flush().unwrap();
        };
        let mut visited_frames = 0;

        let error = store
            .read_inner(&sealed, None, Some(&mut mutate_after_snapshot), &mut |_| {
                visited_frames += 1;
                Ok(())
            })
            .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(visited_frames, 0);
    }

    #[test]
    fn sealed_reader_compares_parsed_bytes_with_the_fingerprinted_snapshot() {
        use std::fs::FileTimes;
        use std::io::{Seek as _, SeekFrom};

        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000077").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        writer.append(&record(2)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let original_bytes = fs::read(&sealed.path).unwrap();
        let first = framing::decode_frame(&original_bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let second_offset = (SEGMENT_HEADER_LEN + first.consumed) as u64;
        let original_second =
            framing::decode_frame(&original_bytes[second_offset as usize..]).unwrap();
        let replacement_body = super::encode_record_body(&record(9)).unwrap();
        let replacement =
            framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &replacement_body).unwrap();
        assert_eq!(replacement.len(), original_second.consumed);
        let original_modified = fs::metadata(&sealed.path).unwrap().modified().unwrap();
        let sealed_path = sealed.path.clone();
        let mut mutate_without_changing_metadata = || {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(&sealed_path)
                .unwrap();
            file.seek(SeekFrom::Start(second_offset)).unwrap();
            file.write_all(&replacement).unwrap();
            file.sync_all().unwrap();
            file.set_times(FileTimes::new().set_modified(original_modified))
                .unwrap();
        };
        let mut visited_frames = 0;

        let error = store
            .read_inner(
                &sealed,
                None,
                Some(&mut mutate_without_changing_metadata),
                &mut |_| {
                    visited_frames += 1;
                    Ok(())
                },
            )
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(visited_frames, 0);
    }

    #[test]
    fn sealed_delete_during_callback_does_not_reject_validated_read() {
        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000075").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let resolved_read = store.read(&sealed).unwrap();
        let capability = AllRecordsResolved::for_read(&sealed, &resolved_read).unwrap();
        let (delete_tx, delete_rx) = mpsc::channel();
        let (deleted_tx, deleted_rx) = mpsc::channel();
        let mut visited_frames = 0;

        thread::scope(|scope| {
            let delete_store = &store;
            let delete_segment = &sealed;
            scope.spawn(move || {
                delete_rx.recv().unwrap();
                delete_store
                    .delete_resolved_segment(delete_segment, capability)
                    .unwrap();
                deleted_tx.send(()).unwrap();
            });

            let read = store
                .read_frames(&sealed, |_| {
                    visited_frames += 1;
                    delete_tx.send(()).unwrap();
                    deleted_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();

            assert_eq!(read.frame_count, 1);
            assert_eq!(read.tail, SegmentTail::Complete);
        });
        assert_eq!(visited_frames, 1);
        assert!(!sealed.path.exists());
    }

    #[test]
    fn sealed_reader_delivers_frames_from_the_validated_snapshot() {
        use std::io::{Seek as _, SeekFrom};

        let temp = tempfile::tempdir().unwrap();
        let store = JournalSegmentStore::open(temp.path()).unwrap();
        let writer_id = uuid::Uuid::parse_str("01890f3e-7b00-7000-8000-000000000076").unwrap();
        let mut writer = store.create_writer_with_id(writer_id).unwrap();
        writer.append(&record(1)).unwrap();
        writer.append(&record(2)).unwrap();
        let active = store.discover().unwrap().pop().unwrap();
        drop(writer);
        let sealed = match store.seal(&active, Duration::from_secs(1)).unwrap() {
            SealOutcome::Sealed(segment) => segment,
            other => panic!("expected sealed segment, got {other:?}"),
        };
        let original_bytes = fs::read(&sealed.path).unwrap();
        let first = framing::decode_frame(&original_bytes[SEGMENT_HEADER_LEN..]).unwrap();
        let second_offset = (SEGMENT_HEADER_LEN + first.consumed) as u64;
        let original_second =
            framing::decode_frame(&original_bytes[second_offset as usize..]).unwrap();
        let replacement_body = super::encode_record_body(&record(9)).unwrap();
        let replacement =
            framing::encode_frame(JournalRecord::SCHEMA_VERSION as u16, &replacement_body).unwrap();
        assert_eq!(replacement.len(), original_second.consumed);
        assert_ne!(replacement_body, original_second.body);
        let sealed_path = sealed.path.clone();
        let mut visited = Vec::new();

        store
            .read_frames(&sealed, |frame| {
                visited.push(frame.body);
                if visited.len() == 1 {
                    let mut file = fs::OpenOptions::new().write(true).open(&sealed_path)?;
                    file.seek(SeekFrom::Start(second_offset))?;
                    file.write_all(&replacement)?;
                    file.sync_all()?;
                }
                Ok(())
            })
            .unwrap();

        assert_eq!(visited.len(), 2);
        assert_eq!(visited[1], original_second.body);
    }
}
