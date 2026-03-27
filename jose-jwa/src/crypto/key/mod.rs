//! Concrete key types for cryptographic operations.
//!
//! This module provides concrete implementations of signing, verification,
//! encryption, and key wrapping keys that wrap RustCrypto types.

#![cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa",
    feature = "aes-gcm",
    feature = "aes-kw"
))]

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;
#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
pub mod ecdsa;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "rsa")]
pub mod rsa;

// Re-export signing/verification key types
#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
pub use self::ecdsa::{EcdsaError, EcdsaSigningKey, EcdsaVerifyingKey};

#[cfg(feature = "k256")]
pub use self::ecdsa::{Es256KSigningKey, Es256KVerifyingKey};
#[cfg(feature = "p256")]
pub use self::ecdsa::{Es256SigningKey, Es256VerifyingKey};
#[cfg(feature = "p384")]
pub use self::ecdsa::{Es384SigningKey, Es384VerifyingKey};
#[cfg(feature = "p521")]
pub use self::ecdsa::{Es512SigningKey, Es512VerifyingKey};
#[cfg(feature = "hmac")]
pub use self::hmac::{HmacError, HmacKey};
#[cfg(feature = "rsa")]
pub use self::rsa::{RsaError, RsaSigningKey, RsaVerifyingKey};

// Re-export encryption key types
#[cfg(feature = "aes-gcm")]
pub use self::aes_gcm::{Aes128GcmKey, Aes256GcmKey, AesGcmError, AesGcmKey};

// Re-export key wrapping key types
#[cfg(feature = "aes-kw")]
pub use self::aes_kw::{Aes128KwKey, Aes192KwKey, Aes256KwKey, AesKwError, AesKwKey};
