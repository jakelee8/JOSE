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
    feature = "aes-cbc-hmac",
    feature = "aes-kw"
))]

#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
pub mod ecdsa;
#[cfg(feature = "hmac")]
pub mod hmac;
#[cfg(feature = "rsa")]
pub mod rsa_pkcs1v15;
#[cfg(feature = "rsa")]
pub mod rsa_pss;

// Re-export signing/verification key types
#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
pub use self::ecdsa::{EcdsaCurveAlg, EcdsaSigningKey, EcdsaVerifyingKey};

#[cfg(feature = "k256")]
pub use self::ecdsa::{Es256KSigningKey, Es256KVerifyingKey};
#[cfg(feature = "p256")]
pub use self::ecdsa::{Es256SigningKey, Es256VerifyingKey};
#[cfg(feature = "p384")]
pub use self::ecdsa::{Es384SigningKey, Es384VerifyingKey};
#[cfg(feature = "p521")]
pub use self::ecdsa::{Es512SigningKey, Es512VerifyingKey};
#[cfg(feature = "hmac")]
pub use self::hmac::{HmacKey, HmacState};
#[cfg(feature = "rsa")]
pub use self::rsa_pkcs1v15::{
    Rs256SigningKey, Rs256VerifyingKey, Rs384SigningKey, Rs384VerifyingKey, Rs512SigningKey,
    Rs512VerifyingKey, RsaPkcs1v15SigningKey, RsaPkcs1v15VerifyingKey,
};
#[cfg(feature = "rsa")]
pub use self::rsa_pss::{
    Ps256SigningKey, Ps256VerifyingKey, Ps384SigningKey, Ps384VerifyingKey, Ps512SigningKey,
    Ps512VerifyingKey, RsaPssSigningKey, RsaPssVerifyingKey,
};
