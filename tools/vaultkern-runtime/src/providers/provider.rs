use std::fmt;

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
}

impl fmt::Debug for ProviderSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSnapshot")
            .field("bytes", &"[OPAQUE]")
            .field("revision", &self.revision)
            .finish()
    }
}

pub struct ProviderCommit {
    pub revision: ProviderRevision,
    pub warnings: Vec<String>,
}

impl fmt::Debug for ProviderCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCommit")
            .field("revision", &self.revision)
            .field("warning_count", &self.warnings.len())
            .finish()
    }
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
}
