mod enc;
mod key;
mod km;

use core::error::Error;
use core::fmt;

pub use self::enc::*;
pub use self::key::*;
pub use self::km::*;

/// Unified error type for cryptographic operations (content encryption and key management).
#[derive(Debug)]
pub enum CipherError {
    /// An error occurred during AEAD encryption/decryption.
    Aead,
    /// An error occurred during signing.
    Sign,
    /// Signature verification failed.
    Verify,
    /// The key is invalid or corrupted.
    InvalidKey,
    /// The provided key has an invalid length for the selected algorithm.
    InvalidKeyLength,
    /// The generated or provided IV/nonce has an invalid length.
    InvalidIvLength,
    /// The provided authentication tag has an invalid length.
    InvalidTagLength,
    /// The provided PBKDF2 salt has an invalid (too short) length.
    InvalidSaltLength,
    /// The initialization vector (IV/nonce) is required but missing.
    MissingIv,
    /// The authentication tag is required but missing.
    MissingTag,
    /// The salt is required but missing.
    MissingSalt,
    /// A random number generation error occurred.
    Rng,
    /// The algorithm is not supported (feature not enabled).
    UnsupportedAlgorithm,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => f.write_str("AEAD error"),
            Self::Sign => f.write_str("signing error"),
            Self::Verify => f.write_str("verification failed"),
            Self::InvalidKey => f.write_str("invalid key"),
            Self::InvalidKeyLength => f.write_str("invalid key length"),
            Self::InvalidIvLength => f.write_str("invalid IV length"),
            Self::InvalidTagLength => f.write_str("invalid tag length"),
            Self::InvalidSaltLength => f.write_str("PBKDF2 salt too short (must be >= 8 bytes)"),
            Self::MissingIv => f.write_str("missing IV"),
            Self::MissingTag => f.write_str("missing authentication tag"),
            Self::MissingSalt => f.write_str("missing salt"),
            Self::Rng => f.write_str("random number generation error"),
            Self::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
        }
    }
}

impl Error for CipherError {}
