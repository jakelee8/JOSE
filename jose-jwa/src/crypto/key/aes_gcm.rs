//! AES-GCM content encryption key.
//!
//! This module provides [`AesGcmKey`] for AES-GCM authenticated encryption
//! as used in JWE content encryption (A128GCM, A256GCM).
//!
//! Note: A192GCM is not supported as the aes-gcm crate only provides
//! Aes128Gcm and Aes256Gcm.

#![cfg(feature = "aes-gcm")]

use alloc::vec;
use alloc::vec::Vec;

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
    aead::{AeadCore, AeadInOut, Tag},
};
use jose_b64::serde::Secret;
use rand_core::TryCryptoRng;

use crate::Encryption;
use crate::crypto::secret::{DecryptingKey, Encrypted, EncryptingKey};

/// An AES-GCM content encryption key.
///
/// This type wraps an AES-GCM key and implements [`EncryptingKey`] and
/// [`DecryptingKey`] for JWE content encryption.
pub struct AesGcmKey<const N: usize> {
    key: Secret,
    alg: Encryption,
}

impl<const N: usize> AesGcmKey<N> {
    /// Create an AES-GCM key from raw bytes.
    ///
    /// # Arguments
    /// * `k` - The key bytes (16 bytes for A128GCM, 32 for A256GCM)
    /// * `alg` - The encryption algorithm
    pub fn new(k: impl AsRef<[u8]>, alg: Encryption) -> Result<Self, AesGcmError> {
        let expected_len = match alg {
            Encryption::A128Gcm if N == 16 => 16,
            Encryption::A256Gcm if N == 32 => 32,
            _ => return Err(AesGcmError::InvalidAlgorithm),
        };

        if k.as_ref().len() != expected_len {
            return Err(AesGcmError::InvalidKeyLength);
        }

        Ok(Self {
            key: Secret::from(k.as_ref().to_vec()),
            alg,
        })
    }

    /// Generate a random key.
    pub fn random(rng: &mut impl TryCryptoRng, alg: Encryption) -> Result<Self, AesGcmError> {
        let k_len = match alg {
            Encryption::A128Gcm if N == 16 => 16,
            Encryption::A256Gcm if N == 32 => 32,
            _ => return Err(AesGcmError::InvalidAlgorithm),
        };

        let mut k = vec![0u8; k_len];
        rng.try_fill_bytes(&mut k)
            .map_err(|_| AesGcmError::RngError)?;

        Self::new(k, alg)
    }

    /// Get the encryption algorithm.
    pub fn alg(&self) -> Encryption {
        self.alg
    }

    /// Export the key bytes.
    pub fn to_bytes(&self) -> Secret {
        self.key.clone()
    }
}

impl EncryptingKey for AesGcmKey<16> {
    type Error = AesGcmError;

    fn encrypt(
        &self,
        mut rng: impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error> {
        let cipher =
            Aes128Gcm::new_from_slice(self.key.0.as_ref()).map_err(|_| AesGcmError::InvalidKey)?;

        let mut iv = [0u8; 12];
        rng.try_fill_bytes(&mut iv)
            .map_err(|_| AesGcmError::RngError)?;
        let nonce = Nonce::from_slice(&iv);

        let mut ciphertext = plaintext.as_ref().to_vec();
        let tag = cipher
            .encrypt_inout_detached(nonce, aad.as_ref(), &mut ciphertext)
            .map_err(|_| AesGcmError::EncryptionFailed)?;

        Ok(Encrypted {
            ciphertext,
            iv: iv.to_vec(),
            tag: tag.as_slice().to_vec(),
        })
    }
}

impl DecryptingKey for AesGcmKey<16> {
    type Error = AesGcmError;

    fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Secret, Self::Error> {
        let cipher =
            Aes128Gcm::new_from_slice(self.key.0.as_ref()).map_err(|_| AesGcmError::InvalidKey)?;

        let nonce = Nonce::from_slice(iv.as_ref());
        let tag_array = Tag::<<Aes128Gcm as AeadCore>::TagSize>::clone_from_slice(tag.as_ref());

        let mut plaintext = ciphertext.as_ref().to_vec();
        cipher
            .decrypt_inout_detached(nonce, aad.as_ref(), &mut plaintext, &tag_array)
            .map_err(|_| AesGcmError::DecryptionFailed)?;

        Ok(Secret::from(plaintext))
    }
}

impl EncryptingKey for AesGcmKey<32> {
    type Error = AesGcmError;

    fn encrypt(
        &self,
        mut rng: impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error> {
        let cipher =
            Aes256Gcm::new_from_slice(self.key.0.as_ref()).map_err(|_| AesGcmError::InvalidKey)?;

        let mut iv = [0u8; 12];
        rng.try_fill_bytes(&mut iv)
            .map_err(|_| AesGcmError::RngError)?;
        let nonce = Nonce::from_slice(&iv);

        let mut ciphertext = plaintext.as_ref().to_vec();
        let tag = cipher
            .encrypt_inout_detached(nonce, aad.as_ref(), &mut ciphertext)
            .map_err(|_| AesGcmError::EncryptionFailed)?;

        Ok(Encrypted {
            ciphertext,
            iv: iv.to_vec(),
            tag: tag.as_slice().to_vec(),
        })
    }
}

impl DecryptingKey for AesGcmKey<32> {
    type Error = AesGcmError;

    fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Secret, Self::Error> {
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| AesGcmError::InvalidKey)?;

        let nonce = Nonce::from_slice(iv.as_ref());
        let tag_array = Tag::<<Aes256Gcm as AeadCore>::TagSize>::clone_from_slice(tag.as_ref());

        let mut plaintext = ciphertext.as_ref().to_vec();
        cipher
            .decrypt_inout_detached(nonce, aad.as_ref(), &mut plaintext, &tag_array)
            .map_err(|_| AesGcmError::DecryptionFailed)?;

        Ok(Secret::from(plaintext))
    }
}

/// AES-GCM-specific errors.
#[derive(Debug)]
pub enum AesGcmError {
    /// Invalid key length.
    InvalidKeyLength,
    /// Invalid key format.
    InvalidKey,
    /// Invalid algorithm for key size.
    InvalidAlgorithm,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption failed.
    DecryptionFailed,
    /// Random number generation error.
    RngError,
}

impl core::fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength => f.write_str("invalid AES-GCM key length"),
            Self::InvalidKey => f.write_str("invalid AES-GCM key"),
            Self::InvalidAlgorithm => f.write_str("invalid algorithm for AES-GCM key size"),
            Self::EncryptionFailed => f.write_str("AES-GCM encryption failed"),
            Self::DecryptionFailed => f.write_str("AES-GCM decryption failed"),
            Self::RngError => f.write_str("random number generation failed"),
        }
    }
}

impl core::error::Error for AesGcmError {}

/// Type aliases for common AES-GCM key sizes.
pub type Aes128GcmKey = AesGcmKey<16>;
pub type Aes192GcmKey = AesGcmKey<24>;
pub type Aes256GcmKey = AesGcmKey<32>;
