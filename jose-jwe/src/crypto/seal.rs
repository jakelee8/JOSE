//! JWE Sealing (Key Management) Implementation
//!
//! This module provides traits for JWE key management algorithms
//! (key wrapping, key encryption, key agreement) as defined in RFC 7518.
//!
//! The sealing traits abstract both:
//! - Content encryption: The key IS the CEK, encrypts content directly
//! - Key wrap: The key generates/derives the CEK internally, encrypts the CEK

#![cfg(any(feature = "aes-gcm", feature = "aes-kw"))]

use alloc::vec::Vec;
use core::error::Error;

use jose_b64::stream::Update;
use zeroize::{Zeroize, Zeroizing};

/// Result of wrapping a CEK for a recipient.
///
/// Contains the encrypted CEK and algorithm-specific parameters.
/// The `alg` field is determined by the key type used for wrapping.
#[derive(Clone, Debug, Default)]
pub struct WrappedCek {
    /// The encrypted Content Encryption Key
    pub encrypted_key: Vec<u8>,
    /// Initialization vector for AES-GCMKW (CEK wrap)
    pub iv: Option<Vec<u8>>,
    /// Authentication tag for AES-GCMKW (CEK wrap)
    pub tag: Option<Vec<u8>>,
    /// Ephemeral public key for ECDH-ES (raw JWK bytes)
    pub epk: Option<Vec<u8>>,
    /// Agreement PartyUInfo for ECDH-ES
    pub apu: Option<Vec<u8>>,
    /// Agreement PartyVInfo for ECDH-ES
    pub apv: Option<Vec<u8>>,
    /// PBES2 salt
    pub p2s: Option<Vec<u8>>,
    /// PBES2 iteration count
    pub p2c: Option<u64>,
}

impl Zeroize for WrappedCek {
    fn zeroize(&mut self) {
        self.encrypted_key.zeroize();
        self.iv.zeroize();
        self.tag.zeroize();
        self.apu.zeroize();
        self.apv.zeroize();
        self.p2s.zeroize();
    }
}

/// Output from a sealing operation
///
/// Contains the data required to construct a JWE. Not all fields are populated
/// by all algorithms:
/// - Content encryption (A128GCM, A256GCM): ciphertext, iv, tag
/// - Key wrap (A128GCMKW, A256GCMKW): encrypted_key, ciphertext, iv, tag
/// - Key wrap (A128KW, A256KW): encrypted_key only
#[derive(Clone, Debug, Default)]
pub struct Sealed {
    /// The encrypted CEK (key wrap only)
    pub encrypted_key: Option<Vec<u8>>,
    /// The initialization vector/nonce
    pub iv: Option<Vec<u8>>,
    /// The encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// The authentication tag
    pub tag: Option<Vec<u8>>,
}

impl Zeroize for Sealed {
    fn zeroize(&mut self) {
        self.encrypted_key.zeroize();
        self.iv.zeroize();
        self.ciphertext.zeroize();
        self.tag.zeroize();
    }
}

/// A key for sealing (encrypting/wrapping content and keys)
///
/// This trait abstracts both content encryption and key wrap operations:
/// - Content encryption: The key IS the CEK, encrypts content directly
/// - Key wrap: The key generates/derives the CEK internally
pub trait SealingKey<'a> {
    #[allow(missing_docs)]
    type StartError: Error;

    /// The state object used during sealing.
    type Sealer: Sealer;

    /// Begin the sealing process.
    ///
    /// For key wrap algorithms, this generates/derives the CEK internally.
    fn seal(&'a self) -> Result<Self::Sealer, Self::StartError>;
}

/// A key capable of wrapping (encrypting) a CEK for a recipient.
///
/// The wrapping algorithm is determined by the key type.
/// For example:
/// - `rsa::Oaep<Sha1>` → RSA-OAEP
/// - `rsa::Oaep<Sha256>` → RSA-OAEP-256
/// - `Kek<Aes128Gcm>` → A128GCMKW
/// - `aes_kw::AesKw<Aes128>` → A128KW
pub trait WrappingKey {
    #[allow(missing_docs)]
    type Error: Error;

    /// Wrap (encrypt) the provided CEK.
    ///
    /// Returns the encrypted CEK and any algorithm-specific parameters.
    fn wrap_cek(&self, cek: &[u8]) -> Result<WrappedCek, Self::Error>;
}

/// Error type for seal operations that don't support wrapping.
#[derive(Debug, Clone, Copy)]
pub struct DirectEncryptionError;

impl core::fmt::Display for DirectEncryptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "direct encryption does not support CEK wrapping")
    }
}

impl Error for DirectEncryptionError {}

/// Sealing state
///
/// Implements `Update` for streaming plaintext data.
pub trait Sealer: Update {
    #[allow(missing_docs)]
    type FinishError: Error;

    /// Process Additional Authenticated Data (AAD)
    fn update_aad(&mut self, aad: impl AsRef<[u8]>) -> Result<(), <Self as Update>::Error>;

    /// Wrap the CEK for a recipient using the provided wrapping key.
    ///
    /// This method is only available for key-wrap algorithms. For direct
    /// encryption (dir, A128GCM, etc.), this returns an error.
    ///
    /// The wrapping algorithm is determined by the key type.
    fn wrap_cek(&self, key: &impl WrappingKey)
    -> Result<WrappedCek, <Self as Sealer>::FinishError>;

    /// Finish processing and return the sealed output.
    fn finish(self) -> Result<Sealed, Self::FinishError>;
}

/// A key for unsealing (decrypting/unwrapping content and keys)
///
/// This trait abstracts both content decryption and key unwrap operations.
pub trait UnsealingKey<'a> {
    #[allow(missing_docs)]
    type StartError: Error;

    /// The state object used during unsealing.
    type Unsealer: Unsealer;

    /// Begin the unsealing process.
    fn unseal(&'a self, input: Sealed) -> Result<Self::Unsealer, Self::StartError>;
}

/// Unsealing state
///
/// Implements `Update` for streaming ciphertext data (optional for AEAD modes
/// which require the full ciphertext for authentication tag verification).
pub trait Unsealer: Update {
    #[allow(missing_docs)]
    type FinishError: Error;

    /// Process Additional Authenticated Data (AAD)
    fn update_aad(&mut self, aad: impl AsRef<[u8]>) -> Result<(), <Self as Update>::Error>;

    /// Finish processing and return the plaintext content.
    fn finish(self) -> Result<Zeroizing<Vec<u8>>, Self::FinishError>;
}
