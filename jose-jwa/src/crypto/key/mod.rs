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
