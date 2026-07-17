use vaultkern_crypto::KdfProfile;

use crate::{
    KDF_AES_KDBX3_UUID, KDF_AES_KDBX4_UUID, KDF_ARGON2D_UUID, KDF_ARGON2ID_UUID, KdbxError, Result,
    VariantDictionary, VariantValue,
};

pub const DESKTOP_ARGON2_CONFIRM_BYTES: u64 = 256 * 1024 * 1024;
pub const DESKTOP_ARGON2_REFUSE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MOBILE_ARGON2_REFUSE_BYTES: u64 = 128 * 1024 * 1024;
pub const DESKTOP_AES_CONFIRM_ROUNDS: u64 = 600_000_000;
pub const DESKTOP_AES_REFUSE_ROUNDS: u64 = 6_000_000_000;
pub const MOBILE_AES_REFUSE_ROUNDS: u64 = 600_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfAlgorithm {
    AesKdbx3,
    AesKdbx4,
    Argon2d,
    Argon2id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfParameter {
    Rounds,
    Iterations,
    MemoryBytes,
    Parallelism,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfResource {
    Rounds,
    MemoryBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalKdfRequest {
    pub algorithm: ExternalKdfAlgorithm,
    pub resource: ExternalKdfResource,
    pub observed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfDecision {
    Allow,
    Confirm(u64),
    Refuse(u64),
    Forbid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfConfirmation {
    Unconfirmed,
    Confirmed,
}

pub trait KdfPolicyEvaluator {
    fn evaluate(&self, request: ExternalKdfRequest) -> ExternalKdfDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKdfPolicy {
    Desktop,
    Mobile,
    Extension,
}

impl KdfPolicyEvaluator for ExternalKdfPolicy {
    fn evaluate(&self, request: ExternalKdfRequest) -> ExternalKdfDecision {
        if *self == Self::Extension {
            return ExternalKdfDecision::Forbid;
        }

        match (self, request.resource) {
            (Self::Desktop, ExternalKdfResource::MemoryBytes)
                if request.observed > DESKTOP_ARGON2_REFUSE_BYTES =>
            {
                ExternalKdfDecision::Refuse(DESKTOP_ARGON2_REFUSE_BYTES)
            }
            (Self::Desktop, ExternalKdfResource::MemoryBytes)
                if request.observed > DESKTOP_ARGON2_CONFIRM_BYTES =>
            {
                ExternalKdfDecision::Confirm(DESKTOP_ARGON2_CONFIRM_BYTES)
            }
            (Self::Mobile, ExternalKdfResource::MemoryBytes)
                if request.observed > MOBILE_ARGON2_REFUSE_BYTES =>
            {
                ExternalKdfDecision::Refuse(MOBILE_ARGON2_REFUSE_BYTES)
            }
            (Self::Desktop, ExternalKdfResource::Rounds)
                if request.observed > DESKTOP_AES_REFUSE_ROUNDS =>
            {
                ExternalKdfDecision::Refuse(DESKTOP_AES_REFUSE_ROUNDS)
            }
            (Self::Desktop, ExternalKdfResource::Rounds)
                if request.observed > DESKTOP_AES_CONFIRM_ROUNDS =>
            {
                ExternalKdfDecision::Confirm(DESKTOP_AES_CONFIRM_ROUNDS)
            }
            (Self::Mobile, ExternalKdfResource::Rounds)
                if request.observed > MOBILE_AES_REFUSE_ROUNDS =>
            {
                ExternalKdfDecision::Refuse(MOBILE_AES_REFUSE_ROUNDS)
            }
            _ => ExternalKdfDecision::Allow,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExternalKdfMaterial {
    Aes {
        rounds: u64,
        salt: [u8; 32],
    },
    Argon2 {
        iterations: u32,
        memory_kib: u32,
        parallelism: u32,
        salt: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalKdfParameters {
    algorithm: ExternalKdfAlgorithm,
    material: ExternalKdfMaterial,
}

impl ExternalKdfParameters {
    pub fn decode_kdbx4(dict: &VariantDictionary) -> Result<Self> {
        let uuid = match dict.get("$UUID") {
            Some(VariantValue::Bytes(bytes)) => {
                uuid::Uuid::from_slice(bytes).map_err(|_| KdbxError::InvalidValue)?
            }
            _ => return Err(KdbxError::UnsupportedKdf),
        };

        if uuid == KDF_AES_KDBX4_UUID || uuid == KDF_AES_KDBX3_UUID {
            let algorithm = ExternalKdfAlgorithm::AesKdbx4;
            let rounds = required_u64(dict, "R")?;
            validate_nonzero_bounded(algorithm, ExternalKdfParameter::Rounds, rounds)?;
            let salt = required_bytes(dict, "S")?
                .try_into()
                .map_err(|_| KdbxError::InvalidValue)?;
            Ok(Self {
                algorithm,
                material: ExternalKdfMaterial::Aes { rounds, salt },
            })
        } else if uuid == KDF_ARGON2D_UUID || uuid == KDF_ARGON2ID_UUID {
            let algorithm = if uuid == KDF_ARGON2D_UUID {
                ExternalKdfAlgorithm::Argon2d
            } else {
                ExternalKdfAlgorithm::Argon2id
            };
            let raw_iterations = required_u64(dict, "I")?;
            let iterations =
                checked_u32(algorithm, ExternalKdfParameter::Iterations, raw_iterations)?;
            let memory_bytes = required_u64(dict, "M")?;
            if memory_bytes == 0 || memory_bytes % 1024 != 0 {
                return Err(invalid(
                    algorithm,
                    ExternalKdfParameter::MemoryBytes,
                    memory_bytes,
                ));
            }
            let memory_kib = u32::try_from(memory_bytes / 1024)
                .map_err(|_| invalid(algorithm, ExternalKdfParameter::MemoryBytes, memory_bytes))?;
            let parallelism = match dict.get("P") {
                Some(VariantValue::UInt32(value)) if *value != 0 => *value,
                Some(VariantValue::UInt32(value)) => {
                    return Err(invalid(
                        algorithm,
                        ExternalKdfParameter::Parallelism,
                        u64::from(*value),
                    ));
                }
                _ => return Err(KdbxError::UnsupportedKdf),
            };
            let salt = required_bytes(dict, "S")?.to_vec();
            Ok(Self {
                algorithm,
                material: ExternalKdfMaterial::Argon2 {
                    iterations,
                    memory_kib,
                    parallelism,
                    salt,
                },
            })
        } else {
            Err(KdbxError::UnsupportedKdf)
        }
    }

    pub(crate) fn decode_kdbx3(rounds: u64, salt: [u8; 32]) -> Result<Self> {
        let algorithm = ExternalKdfAlgorithm::AesKdbx3;
        validate_nonzero_bounded(algorithm, ExternalKdfParameter::Rounds, rounds)?;
        Ok(Self {
            algorithm,
            material: ExternalKdfMaterial::Aes { rounds, salt },
        })
    }

    pub fn request(&self) -> ExternalKdfRequest {
        let (resource, observed) = match &self.material {
            ExternalKdfMaterial::Aes { rounds, .. } => (ExternalKdfResource::Rounds, *rounds),
            ExternalKdfMaterial::Argon2 { memory_kib, .. } => (
                ExternalKdfResource::MemoryBytes,
                u64::from(*memory_kib) * 1024,
            ),
        };
        ExternalKdfRequest {
            algorithm: self.algorithm,
            resource,
            observed,
        }
    }

    pub fn algorithm(&self) -> ExternalKdfAlgorithm {
        self.algorithm
    }

    pub fn rounds(&self) -> Option<u64> {
        match &self.material {
            ExternalKdfMaterial::Aes { rounds, .. } => Some(*rounds),
            ExternalKdfMaterial::Argon2 { .. } => None,
        }
    }

    pub fn argon2_work_factors(&self) -> Option<(u32, u32, u32)> {
        match &self.material {
            ExternalKdfMaterial::Argon2 {
                iterations,
                memory_kib,
                parallelism,
                ..
            } => Some((*iterations, *memory_kib, *parallelism)),
            ExternalKdfMaterial::Aes { .. } => None,
        }
    }

    pub(crate) fn into_profile(self) -> KdfProfile {
        match (self.algorithm, self.material) {
            (ExternalKdfAlgorithm::AesKdbx3, ExternalKdfMaterial::Aes { rounds, salt }) => {
                KdfProfile::AesKdbx3 { rounds, salt }
            }
            (ExternalKdfAlgorithm::AesKdbx4, ExternalKdfMaterial::Aes { rounds, salt }) => {
                KdfProfile::AesKdbx4 { rounds, salt }
            }
            (
                ExternalKdfAlgorithm::Argon2d,
                ExternalKdfMaterial::Argon2 {
                    iterations,
                    memory_kib,
                    parallelism,
                    salt,
                },
            ) => KdfProfile::Argon2d {
                iterations,
                memory_kib,
                parallelism,
                salt,
            },
            (
                ExternalKdfAlgorithm::Argon2id,
                ExternalKdfMaterial::Argon2 {
                    iterations,
                    memory_kib,
                    parallelism,
                    salt,
                },
            ) => KdfProfile::Argon2id {
                iterations,
                memory_kib,
                parallelism,
                salt,
            },
            _ => unreachable!("algorithm and decoded KDF material always agree"),
        }
    }

    #[cfg(test)]
    pub(crate) fn argon2_for_test(
        algorithm: ExternalKdfAlgorithm,
        iterations: u32,
        memory_bytes: u64,
        parallelism: u32,
    ) -> Self {
        Self {
            algorithm,
            material: ExternalKdfMaterial::Argon2 {
                iterations,
                memory_kib: u32::try_from(memory_bytes / 1024).expect("test memory fits"),
                parallelism,
                salt: vec![0; 32],
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn aes_for_test(algorithm: ExternalKdfAlgorithm, rounds: u64) -> Self {
        Self {
            algorithm,
            material: ExternalKdfMaterial::Aes {
                rounds,
                salt: [0; 32],
            },
        }
    }
}

pub fn enforce_external_kdf_policy(
    parameters: &ExternalKdfParameters,
    evaluator: &dyn KdfPolicyEvaluator,
    confirmation: ExternalKdfConfirmation,
) -> Result<()> {
    let request = parameters.request();
    let decision = evaluator.evaluate(request);
    match (decision, confirmation) {
        (ExternalKdfDecision::Allow, _)
        | (ExternalKdfDecision::Confirm(_), ExternalKdfConfirmation::Confirmed) => Ok(()),
        _ => Err(KdbxError::ExternalKdfPolicy {
            algorithm: request.algorithm,
            observed: request.observed,
            decision,
        }),
    }
}

fn required_u64(dict: &VariantDictionary, key: &str) -> Result<u64> {
    match dict.get(key) {
        Some(VariantValue::UInt64(value)) => Ok(*value),
        _ => Err(KdbxError::UnsupportedKdf),
    }
}

fn required_bytes<'a>(dict: &'a VariantDictionary, key: &str) -> Result<&'a [u8]> {
    match dict.get(key) {
        Some(VariantValue::Bytes(value)) => Ok(value),
        _ => Err(KdbxError::UnsupportedKdf),
    }
}

fn checked_u32(
    algorithm: ExternalKdfAlgorithm,
    parameter: ExternalKdfParameter,
    value: u64,
) -> Result<u32> {
    if value == 0 {
        return Err(invalid(algorithm, parameter, value));
    }
    u32::try_from(value).map_err(|_| invalid(algorithm, parameter, value))
}

fn validate_nonzero_bounded(
    algorithm: ExternalKdfAlgorithm,
    parameter: ExternalKdfParameter,
    value: u64,
) -> Result<()> {
    if value == 0 || value == u64::MAX {
        Err(invalid(algorithm, parameter, value))
    } else {
        Ok(())
    }
}

fn invalid(
    algorithm: ExternalKdfAlgorithm,
    parameter: ExternalKdfParameter,
    value: u64,
) -> KdbxError {
    KdbxError::InvalidKdfParameters {
        algorithm,
        parameter,
        value,
    }
}
