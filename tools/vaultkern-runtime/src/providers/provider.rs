use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Format-neutral identity of observed Provider content.
///
/// This is distinct from [`ProviderRevision`]: identity detects equivalent
/// bytes across snapshots, while the opaque revision is the only token valid
/// for conditional Publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentIdentity {
    pub content_sha256: String,
    pub size_bytes: u64,
    /// Provider-defined hint that helps compare observations with matching size.
    ///
    /// The serialized name is retained for compatibility with existing cache
    /// manifests, where this value originated as a Local File modification
    /// timestamp. Other Providers may use a generation-derived marker.
    #[serde(rename = "modified_at", alias = "observation_marker")]
    pub observation_marker: Option<u64>,
}

impl ContentIdentity {
    pub(crate) fn for_bytes(bytes: &[u8], observation_marker: Option<u64>) -> Self {
        let digest = Sha256::digest(bytes);
        let mut content_sha256 = String::with_capacity(digest.len() * 2);
        for byte in digest {
            write!(&mut content_sha256, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self {
            content_sha256,
            size_bytes: bytes.len() as u64,
            observation_marker,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProviderRevision(Vec<u8>);

impl ProviderRevision {
    pub(crate) fn from_opaque_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn opaque_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ProviderRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderRevision([OPAQUE])")
    }
}

pub struct ProviderSnapshot {
    pub bytes: Vec<u8>,
    pub revision: ProviderRevision,
    pub identity: ContentIdentity,
    pub cache_validation_token: Option<String>,
}

impl fmt::Debug for ProviderSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSnapshot")
            .field("bytes", &"[OPAQUE]")
            .field("revision", &self.revision)
            .field("identity", &self.identity)
            .field(
                "has_cache_validation_token",
                &self.cache_validation_token.is_some(),
            )
            .finish()
    }
}

pub struct ProviderCommit {
    pub revision: ProviderRevision,
    pub identity: ContentIdentity,
    pub cache_validation_token: Option<String>,
    pub warnings: Vec<String>,
}

impl fmt::Debug for ProviderCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCommit")
            .field("revision", &self.revision)
            .field("identity", &self.identity)
            .field(
                "has_cache_validation_token",
                &self.cache_validation_token.is_some(),
            )
            .field("warning_count", &self.warnings.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderConflictCopy {
    pub identity: String,
    pub display_name: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    StaleRevision { message: String },
    NotFound { message: String },
    Unavailable { message: String },
    OutcomeUnknown { message: String },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleRevision { message } => {
                write!(formatter, "Provider rejected a stale revision: {message}")
            }
            Self::NotFound { message } => {
                write!(formatter, "Provider snapshot was not found: {message}")
            }
            Self::Unavailable { message } => {
                write!(formatter, "Provider is unavailable: {message}")
            }
            Self::OutcomeUnknown { message } => {
                write!(
                    formatter,
                    "Provider Publication outcome is unknown: {message}"
                )
            }
        }
    }
}

impl std::error::Error for ProviderError {}

pub trait Provider {
    fn read(&mut self) -> Result<ProviderSnapshot, ProviderError>;

    fn publish(
        &mut self,
        expected: &ProviderRevision,
        bytes: &[u8],
    ) -> Result<ProviderCommit, ProviderError>;

    fn preserve_conflict_copy(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProviderConflictCopy, ProviderError>;
}
