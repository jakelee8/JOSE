//! Content encryption implementations for JWE.
//!
//! This module provides implementations of the content encryption algorithms defined in
//! [RFC 7518 Sections 5.2 and 5.3](https://www.rfc-editor.org/rfc/rfc7518):
//!
//! - AES-CBC with HMAC-SHA2 ([Section 5.2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2))
//! - AES-GCM ([Section 5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3))

mod aes_cbc_hmac;
mod aes_gcm;

use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::EncryptionKeyInfo;

#[cfg(feature = "aes-cbc-hmac")]
pub use self::aes_cbc_hmac::*;
#[cfg(feature = "aes-gcm")]
pub use self::aes_gcm::*;

/// Trait for keys that can encrypt content.
///
/// This trait is implemented by keys that can perform content encryption
/// for JWE. Encryption is done in one shot (not streaming) since AEAD
/// algorithms require the full plaintext.
pub trait EncryptionKey: EncryptionKeyInfo {
    /// The error type returned by encryption operations.
    type Error: core::error::Error;

    /// Return the key bytes (JWK `k` parameter).
    fn k(&self) -> &Secret;

    /// Encrypt plaintext.
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Additional authenticated data (integrity-protected but not encrypted)
    ///
    /// # Returns
    /// Returns `Ok(Encrypted)` containing ciphertext, IV, and authentication tag.
    fn encrypt(
        &self,
        rng: &mut impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error>;

    /// Decrypt ciphertext.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    /// * `aad` - Additional authenticated data (must match encryption)
    /// * `tag` - The authentication tag
    /// * `iv` - The initialization vector or nonce
    ///
    /// # Returns
    /// Returns `Ok(Secret)` containing the plaintext.
    /// Returns `Err` if decryption or authentication fails.
    fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Secret, Self::Error>;
}

/// The result of an encryption operation.
///
/// Contains the encrypted data along with the parameters needed for decryption
/// and integrity verification.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encrypted {
    /// The encrypted ciphertext.
    pub ciphertext: Bytes,
    /// The initialization vector or nonce used for encryption.
    pub iv: Bytes,
    /// The authentication tag for integrity verification.
    pub tag: Bytes,
}
