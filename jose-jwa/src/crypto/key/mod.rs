//! Concrete key types for cryptographic operations.
//!
//! This module provides concrete implementations of signing, verification,
//! encryption, and key wrapping keys that wrap RustCrypto types.

#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
mod ecdsa;
#[cfg(feature = "hmac")]
mod hmac;
#[cfg(feature = "rsa")]
mod rsa_pkcs1v15;
#[cfg(feature = "rsa")]
mod rsa_pss;
mod sign;
mod verify;

pub use self::sign::*;
pub use self::verify::*;

#[cfg(feature = "rsa")]
use jose_b64::serde::{Bytes, Secret};

#[cfg(feature = "rsa")]
/// Trait for accessing RSA JWK components (n, e, d, p, q, dp, dq, qi).
///
/// Implemented by RSA signing and verifying keys to provide consistent
/// JWK parameter access across PKCS#1 v1.5 and PSS variants.
pub trait RsaComponents {
    /// Return the modulus (JWK `n` parameter).
    fn n(&self) -> Bytes;

    /// Return the public exponent (JWK `e` parameter).
    fn e(&self) -> Bytes;
}

#[cfg(feature = "rsa")]
/// Trait for accessing RSA private JWK components.
///
/// Implemented by RSA signing keys to provide access to private key parameters.
pub trait RsaPrivateComponents: RsaComponents {
    /// Return the private exponent (JWK `d` parameter).
    fn d(&self) -> Secret;

    /// Return the first prime factor (JWK `p` parameter).
    fn p(&self) -> Option<Secret>;

    /// Return the second prime factor (JWK `q` parameter).
    fn q(&self) -> Option<Secret>;

    /// Return the first factor CRT exponent (JWK `dp` parameter).
    fn dp(&self) -> Option<Secret>;

    /// Return the second factor CRT exponent (JWK `dq` parameter).
    fn dq(&self) -> Option<Secret>;

    /// Return the first CRT coefficient (JWK `qi` parameter).
    fn qi(&self) -> Option<Secret>;
}

#[cfg(feature = "k256")]
pub use self::ecdsa::{Es256KSigningKey, Es256KVerifyingKey};
#[cfg(feature = "p256")]
pub use self::ecdsa::{Es256SigningKey, Es256VerifyingKey};
#[cfg(feature = "p384")]
pub use self::ecdsa::{Es384SigningKey, Es384VerifyingKey};
#[cfg(feature = "p521")]
pub use self::ecdsa::{Es512SigningKey, Es512VerifyingKey};

#[cfg(feature = "hmac")]
pub use self::hmac::{
    Hs256Signer, Hs256Verify, Hs384Signer, Hs384Verify, Hs512Signer, Hs512Verify,
};

#[cfg(feature = "rsa")]
pub use self::rsa_pkcs1v15::{
    Rs256SigningKey, Rs256VerifyingKey, Rs384SigningKey, Rs384VerifyingKey, Rs512SigningKey,
    Rs512VerifyingKey,
};
#[cfg(feature = "rsa")]
pub use self::rsa_pss::{
    Ps256SigningKey, Ps256VerifyingKey, Ps384SigningKey, Ps384VerifyingKey, Ps512SigningKey,
    Ps512VerifyingKey,
};
