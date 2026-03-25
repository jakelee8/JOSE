mod aes_gcm;
mod aes_kw;
mod digest;
#[cfg(feature = "ecdsa")]
mod ecdsa;
mod hmac;
mod km;
#[cfg(feature = "rsa")]
mod rsa;
#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
mod secret;
#[cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]
mod sign;
#[cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]
mod verify;

use core::error::Error;
use core::fmt;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::*;
#[cfg(feature = "hmac")]
pub use self::hmac::*;
#[cfg(any(
    feature = "aes-kw",
    feature = "aes-gcm",
    feature = "rsa",
    feature = "ecdh",
    feature = "pbes2"
))]
pub use self::km::*;
#[cfg(feature = "rsa")]
pub use self::rsa::*;
#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
pub use self::secret::*;
#[cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]
pub use self::sign::*;
#[cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]
pub use self::verify::*;

/// Unified error type for cryptographic operations (content encryption and key management).
#[derive(Debug)]
pub enum CipherError {
    /// An error occurred during AEAD encryption/decryption.
    Aead,
    /// The provided key has an invalid length for the selected algorithm.
    InvalidKeyLength,
    /// The generated or provided IV/nonce has an invalid length.
    InvalidIvLength,
    /// The provided authentication tag has an invalid length.
    InvalidTagLength,
    /// The provided PBKDF2 salt has an invalid (too short) length.
    InvalidSaltLength,
    /// A random number generation error occurred.
    Rng,
    /// The algorithm is not supported (feature not enabled).
    UnsupportedAlgorithm,
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => f.write_str("AEAD error"),
            Self::InvalidKeyLength => f.write_str("invalid key length"),
            Self::InvalidIvLength => f.write_str("invalid IV length"),
            Self::InvalidTagLength => f.write_str("invalid tag length"),
            Self::InvalidSaltLength => f.write_str("PBKDF2 salt too short (must be >= 8 bytes)"),
            Self::Rng => f.write_str("random number generation error"),
            Self::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
        }
    }
}

impl From<::digest::InvalidLength> for CipherError {
    fn from(_err: ::digest::InvalidLength) -> Self {
        Self::InvalidKeyLength
    }
}

#[cfg(feature = "aes-gcm")]
impl From<::aes_gcm::Error> for CipherError {
    fn from(_err: ::aes_gcm::Error) -> Self {
        Self::Aead
    }
}

impl Error for CipherError {}
