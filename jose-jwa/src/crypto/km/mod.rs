//! JWE Key Management (Key Wrapping) Implementation
//!
//! This module provides key wrapping/unwrapping functions for JWE "alg" algorithms
//! (key wrapping, key encryption, key agreement) as defined in RFC 7518.
//!
//! CEK generation is handled by `Encryption::random_key()` in the `secret` module.
//!
//! The modules abstract:
//! - Content encryption: The key IS the CEK, encrypts content directly
//! - Key wrap: The wrapping key protects the generated/derived CEK

mod aes_gcm_kw;
mod aes_kw;
mod ecdh;
mod pbes2;
mod rsa_oaep;

use core::fmt;

use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "aes-gcm")]
pub use self::aes_gcm_kw::*;
#[cfg(feature = "aes-kw")]
pub use self::aes_kw::*;
#[cfg(feature = "ecdh")]
pub use self::ecdh::*;
#[cfg(feature = "pbes2")]
pub use self::pbes2::*;
#[cfg(feature = "rsa")]
pub use self::rsa_oaep::*;

/// Key management modes for JWE "alg" header (RFC 7518 Section 4.1).
///
/// These modes protect the Content Encryption Key (CEK).
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum KeyManagement {
    /// RSAES-PKCS1-v1_5 (VULNERABLE - DO NOT USE IN PRODUCTION)
    ///
    /// SECURITY WARNING: This algorithm is vulnerable to Bleichenbacher's
    /// Million Message Attack. Use `RsaOaep` or `RsaOaep256` instead.
    /// Only available with `legacy-rsa1_5` feature flag.
    #[cfg(feature = "legacy-rsa1_5")]
    #[deprecated(
        note = "RSA1_5 is vulnerable to Bleichenbacher's attack. Use RsaOaep or RsaOaep256 instead."
    )]
    #[serde(rename = "RSA1_5")]
    Rsa1_5,

    /// RSA-OAEP with SHA-1 (Recommended per RFC 7518)
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSA-OAEP with SHA-256 (Recommended)
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with 128-bit key (Recommended per RFC 7518)
    #[serde(rename = "A128KW")]
    A128Kw,

    /// AES Key Wrap with 192-bit key (Optional)
    #[serde(rename = "A192KW")]
    A192Kw,

    /// AES Key Wrap with 256-bit key (Recommended per RFC 7518)
    #[serde(rename = "A256KW")]
    A256Kw,

    /// Direct use of shared symmetric key (Recommended per RFC 7518)
    ///
    /// SECURITY: Only for single-recipient JWE. Key must be dedicated
    /// to this purpose.
    #[serde(rename = "dir")]
    Dir,

    /// ECDH-ES direct key agreement (Recommended per RFC 7518)
    ///
    /// SECURITY: Ephemeral public key (`epk`) MUST be in protected header.
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES with A128KW key wrapping (Recommended per RFC 7518)
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,

    /// ECDH-ES with A192KW key wrapping (Optional)
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,

    /// ECDH-ES with A256KW key wrapping (Recommended per RFC 7518)
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    /// AES GCM Key Wrap with 128-bit key (Optional)
    #[serde(rename = "A128GCMKW")]
    A128GcmKw,

    /// AES GCM Key Wrap with 192-bit key (Optional)
    #[serde(rename = "A192GCMKW")]
    A192GcmKw,

    /// AES GCM Key Wrap with 256-bit key (Optional)
    #[serde(rename = "A256GCMKW")]
    A256GcmKw,

    /// PBES2 with HMAC SHA-256 and A128KW (Optional)
    ///
    /// SECURITY: A minimum iteration count (`p2c`) of 1000 is RECOMMENDED per RFC 7518,
    /// and SHOULD be >= 10000 for production use.
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,

    /// PBES2 with HMAC SHA-384 and A192KW (Optional)
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,

    /// PBES2 with HMAC SHA-512 and A256KW (Optional)
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

impl KeyManagement {
    /// Returns the string representation of this sealing algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            #[cfg(feature = "legacy-rsa1_5")]
            #[allow(deprecated)]
            Self::Rsa1_5 => "RSA1_5",
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
            Self::Dir => "dir",
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::A128GcmKw => "A128GCMKW",
            Self::A192GcmKw => "A192GCMKW",
            Self::A256GcmKw => "A256GCMKW",
            Self::Pbes2Hs256A128Kw => "PBES2-HS256+A128KW",
            Self::Pbes2Hs384A192Kw => "PBES2-HS384+A192KW",
            Self::Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
        }
    }
}

impl fmt::Display for KeyManagement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Result of a key wrapping operation
///
/// Uses #[derive(Zeroize, ZeroizeOnDrop)] instead of Zeroizing wrapper
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct WrappedKey {
    /// The encrypted Content Encryption Key (None for direct modes like "dir")
    pub encrypted_key: Bytes,
    /// 96-bit IV for AES-GCM key wrap algorithms
    pub iv: Option<Bytes>,
    /// 128-bit authentication tag for AES-GCM key wrap algorithms
    pub tag: Option<Bytes>,
    /// Salt input for PBES2 algorithms (p2s header parameter, generated during wrap)
    pub salt: Option<Bytes>,
}

/// A trait for wrapping keys.
///
/// This trait is implemented by keys that can wrap other keys
/// using algorithms like AES-KW (RFC 3394). Unlike content encryption,
/// key wrapping does not use IV or AAD.
pub trait WrappingKey {
    /// The error type returned when wrapping fails.
    type Error;

    /// Wrap a content encryption key.
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    /// * `cek` - The content encryption key to wrap
    ///
    /// # Returns
    /// The wrapped key containing the encrypted CEK and any additional parameters
    /// (such as IV, tag, or salt) depending on the algorithm.
    fn wrap_key(
        &self,
        rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error>;
}

/// A trait for unwrapping keys.
///
/// This trait is implemented by keys that can unwrap other keys
/// using algorithms like AES-KW (RFC 3394). Unlike content decryption,
/// key unwrapping does not use IV or AAD.
pub trait UnwrappingKey {
    /// The error type returned when unwrapping fails.
    type Error;

    /// Unwrap a content encryption key.
    ///
    /// # Arguments
    /// * `wrapped_key` - The wrapped key containing the encrypted CEK
    ///
    /// # Returns
    /// The unwrapped key as a `Secret`. The caller is responsible for
    /// verifying the length of the unwrapped key.
    fn unwrap_key(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error>;
}
