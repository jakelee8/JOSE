//! Encryption algorithm implementations for JWE content encryption.
//!
//! This module provides the [`Encryption`] enum that dispatches to the
//! appropriate algorithm implementation based on the selected variant.

#![cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]

#[cfg(any(feature = "aes-cbc-hmac", feature = "aes-gcm"))]
use aes::{Aes128, Aes192, Aes256};
#[cfg(feature = "aes-gcm")]
use aes_gcm::AesGcm;
use alloc::vec::Vec;
#[cfg(feature = "aes-gcm")]
use digest::consts::U12;
use rand_core::TryCryptoRng;
use sha2::{Sha256, Sha384, Sha512};

#[cfg(feature = "aes-cbc-hmac")]
use super::aes_cbc_hmac::*;
#[cfg(feature = "aes-gcm")]
use super::aes_gcm::*;
use crate::{CipherError, Encrypted, Encryption};

/// AES-GCM with a 192-bit key and 96-bit nonce.
#[cfg(feature = "aes-gcm")]
pub type Aes192Gcm = AesGcm<Aes192, U12>;

impl Encryption {
    /// Encrypts plaintext using the selected encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    /// * `key` - The encryption key (size varies by algorithm)
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Additional authenticated data that is integrity-protected but not encrypted
    ///
    /// # Returns
    ///
    /// Returns `Ok(Encrypted)` containing the ciphertext, IV/nonce, and authentication tag.
    pub fn encrypt(
        &self,
        rng: &mut impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, CipherError> {
        match self {
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A128CbcHs256 => aes_cbc_hmac_encrypt::<Aes128, Sha256>(rng, plaintext, aad),
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A192CbcHs384 => aes_cbc_hmac_encrypt::<Aes192, Sha384>(rng, plaintext, aad),
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A256CbcHs512 => aes_cbc_hmac_encrypt::<Aes256, Sha512>(rng, plaintext, aad),
            #[cfg(feature = "aes-gcm")]
            Encryption::A128Gcm => aes_gcm_encrypt::<Aes128>(rng, plaintext, aad),
            #[cfg(feature = "aes-gcm")]
            Encryption::A192Gcm => aes_gcm_encrypt::<Aes192>(rng, plaintext, aad),
            #[cfg(feature = "aes-gcm")]
            Encryption::A256Gcm => aes_gcm_encrypt::<Aes256>(rng, plaintext, aad),
            #[cfg(not(feature = "aes-cbc-hmac"))]
            Encryption::A128CbcHs256 | Encryption::A192CbcHs384 | Encryption::A256CbcHs512 => {
                unreachable!("aes-cbc-hmac feature not enabled")
            }
            #[cfg(not(feature = "aes-gcm"))]
            Encryption::A128Gcm | Encryption::A192Gcm | Encryption::A256Gcm => {
                unreachable!("aes-gcm feature not enabled")
            }
        }
    }

    /// Decrypts ciphertext using the selected encryption algorithm.
    ///
    /// # Arguments
    ///
    /// * `key` - The encryption key (size varies by algorithm)
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `aad` - The additional authenticated data used during encryption
    /// * `tag` - The authentication tag for integrity verification
    /// * `iv` - The initialization vector or nonce used during encryption
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `CipherError::Aead` if authentication tag verification fails.
    pub fn decrypt(
        &self,
        key: impl AsRef<[u8]>,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, CipherError> {
        match self {
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A128CbcHs256 => {
                aes_cbc_hmac_decrypt::<Aes128, Sha256>(key, ciphertext, aad, tag, iv)
            }
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A192CbcHs384 => {
                aes_cbc_hmac_decrypt::<Aes192, Sha384>(key, ciphertext, aad, tag, iv)
            }
            #[cfg(feature = "aes-cbc-hmac")]
            Encryption::A256CbcHs512 => {
                aes_cbc_hmac_decrypt::<Aes256, Sha512>(key, ciphertext, aad, tag, iv)
            }
            #[cfg(feature = "aes-gcm")]
            Encryption::A128Gcm => aes_gcm_decrypt::<Aes128>(key, ciphertext, aad, tag, iv),
            #[cfg(feature = "aes-gcm")]
            Encryption::A192Gcm => aes_gcm_decrypt::<Aes192>(key, ciphertext, aad, tag, iv),
            #[cfg(feature = "aes-gcm")]
            Encryption::A256Gcm => aes_gcm_decrypt::<Aes256>(key, ciphertext, aad, tag, iv),
            #[cfg(not(feature = "aes-cbc-hmac"))]
            Encryption::A128CbcHs256 | Encryption::A192CbcHs384 | Encryption::A256CbcHs512 => {
                unreachable!("aes-cbc-hmac feature not enabled")
            }
            #[cfg(not(feature = "aes-gcm"))]
            Encryption::A128Gcm | Encryption::A192Gcm | Encryption::A256Gcm => {
                unreachable!("aes-gcm feature not enabled")
            }
        }
    }
}
