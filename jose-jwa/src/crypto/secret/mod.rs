//! Content encryption implementations for JWE.
//!
//! This module provides implementations of the content encryption algorithms defined in
//! [RFC 7518 Sections 5.2 and 5.3](https://www.rfc-editor.org/rfc/rfc7518):
//!
//! - AES-CBC with HMAC-SHA2 ([Section 5.2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2))
//! - AES-GCM ([Section 5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3))

#[cfg(feature = "aes-cbc-hmac")]
mod aes_cbc_hmac;
#[cfg(feature = "aes-gcm")]
mod aes_gcm;
mod enc;

use core::error::Error;

#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
use alloc::vec::Vec;

#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
use digest::InvalidLength;
#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
use jose_b64::stream::Update;
#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
use rand_core::TryCryptoRng;
#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
pub use sha2::{Sha256, Sha384, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::CipherError;

#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
pub use self::enc::*;

/// Trait for content encryption keys used in JWE.
///
/// This trait abstracts over different content encryption algorithms,
/// providing a uniform interface for encryption and decryption operations.
pub trait SecretKey<'a> {
    /// The error type returned by encryption/decryption operations.
    type CipherError: Error;
    /// The encryptor type returned by the `encrypt` method.
    type Encryptor: Encryptor;
    /// The decryptor type returned by the `decrypt` method.
    type Decryptor: Decryptor;

    /// Encrypts plaintext using the selected encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator for IV/nonce generation
    /// * `key` - The encryption key (length depends on the algorithm)
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Additional authenticated data (AAD) that is integrity-protected but not encrypted
    ///
    /// # Returns
    ///
    /// Returns `Ok(Encrypted)` containing the ciphertext, IV/nonce, and authentication tag,
    /// or `Err(EncryptError)` if encryption fails.
    ///
    /// # Errors
    ///
    /// Returns `EncryptError::InvalidKeyLength` if the key length is incorrect for the algorithm.
    /// Returns `EncryptError::InvalidIvLength` if IV generation fails.
    /// Returns `EncryptError::Aead` for AEAD-specific errors.
    fn encrypt(
        &self,
        rng: &mut impl TryCryptoRng,
        key: impl AsRef<[u8]>,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Self::Encryptor, Self::CipherError>;

    /// Decrypts ciphertext using the selected encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - The encryption key (length depends on the algorithm)
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `aad` - Additional authenticated data (AAD) that is integrity-protected but not encrypted
    /// * `tag` - The authentication tag for integrity verification
    /// * `iv` - The initialization vector or nonce used for encryption
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the plaintext, or `Err(DecryptError)` if decryption fails.
    ///
    /// # Errors
    ///
    /// Returns `DecryptError::InvalidKeyLength` if the key length is incorrect for the algorithm.
    /// Returns `DecryptError::Authentication` if authentication tag verification fails.
    /// Returns `DecryptError::InvalidIvLength` if IV has an invalid length.
    /// Returns `DecryptError::Aead` for AEAD-specific errors.
    fn decrypt(
        &self,
        key: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Self::Decryptor, Self::CipherError>;
}

/// Trait for encryption operations.
///
/// Implementors of this trait can be used to incrementally encrypt data
/// and then finalize to obtain the encrypted result.
pub trait Encryptor: Update {
    /// The error type returned when finalizing encryption.
    type EncryptError: Error;

    /// Finalizes the encryption and returns the encrypted result.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Encrypted)` containing ciphertext, IV, and authentication tag.
    fn finish(self) -> Result<Encrypted, Self::EncryptError>;
}

/// Trait for decryption operations.
///
/// Implementors of this trait can be used to incrementally decrypt data
/// and then finalize to obtain the decrypted plaintext.
pub trait Decryptor: Update {
    /// The error type returned when finalizing decryption.
    type DecryptError: Error;

    /// Finalizes the decryption and returns the decrypted plaintext.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the plaintext.
    fn finish(self) -> Result<Vec<u8>, Self::DecryptError>;
}

/// The result of an encryption operation.
///
/// Contains the encrypted data along with the parameters needed for decryption
/// and integrity verification.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encrypted {
    /// The encrypted ciphertext.
    pub ciphertext: Vec<u8>,
    /// The encryption key used for the content encryption.
    pub cek: Vec<u8>,
    /// The initialization vector or nonce used for encryption.
    pub iv: Vec<u8>,
    /// The authentication tag for integrity verification.
    pub tag: Vec<u8>,
}
