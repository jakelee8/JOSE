//! AES-GCM Key Wrap implementation for JWE key management.
//!
//! Provides A128GCMKW, A192GCMKW, A256GCMKW algorithms.
//! Per RFC 7518 Section 4.7.
//!
//! NOTE: AES-GCM-KW is handled differently from AES-KW because it produces
//! a `WrappedKey` (with iv, tag) rather than just encrypted bytes. This module
//! provides a generic key type but does NOT implement `WrappingKey`/`UnwrappingKey`
//! traits due to the different return type requirements.

#![cfg(feature = "aes-gcm")]

use alloc::vec;

use aes::Aes192;
use aes::cipher::{Key, KeyInit};
use aes_gcm::aead::inout::InOutBuf;
use aes_gcm::{AeadCore, AeadInOut, Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use digest::consts::U12;
use jose_b64::serde::Secret;
use rand_core::TryCryptoRng;

use super::{UnwrappingKey, WrappedKey, WrappingKey};
use crate::CipherError;

/// Type alias for AES-192-GCM with 96-bit nonce (for AES-GCM-KW).
pub type Aes192Gcm = AesGcm<Aes192, U12>;

/// AES-GCM Key Wrap key type for 128-bit keys.
pub type AesGcmKwKey128 = AesGcmKwKey<Aes128Gcm>;
/// AES-GCM Key Wrap key type for 192-bit keys.
pub type AesGcmKwKey192 = AesGcmKwKey<Aes192Gcm>;
/// AES-GCM Key Wrap key type for 256-bit keys.
pub type AesGcmKwKey256 = AesGcmKwKey<Aes256Gcm>;

/// An AES-GCM Key Wrap key encryption key.
///
/// This type wraps an AES-GCM key and provides wrap/unwrap operations
/// for JWE key management per RFC 7518 Section 4.7.
///
/// NOTE: This type does NOT implement `WrappingKey`/`UnwrappingKey` because
/// AES-GCM-KW produces a `WrappedKey` (with iv, tag) rather than just
/// encrypted bytes. Use the `wrap` and `unwrap` methods directly.
pub struct AesGcmKwKey<A>
where
    A: AeadCore + KeyInit,
{
    oct: Secret,
    kw: A,
}

impl<A> AesGcmKwKey<A>
where
    A: AeadInOut + KeyInit,
{
    /// Create a new AES-GCM-KW key from raw bytes.
    pub fn from_slice(key: impl AsRef<[u8]>) -> Result<Self, CipherError> {
        let cipher = A::new_from_slice(key.as_ref()).map_err(|_| CipherError::InvalidKeyLength)?;
        Ok(Self {
            oct: key.as_ref().to_vec().into(),
            kw: cipher,
        })
    }

    /// Generate a random key with the specified size.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, CipherError> {
        let mut key = Key::<A>::default();
        rng.try_fill_bytes(&mut key).map_err(|_| CipherError::Rng)?;
        Ok(key.into())
    }

    pub fn oct(&self) -> &Secret {
        &self.oct
    }
}

impl<A> WrappingKey for AesGcmKwKey<A>
where
    A: AeadInOut + KeyInit,
{
    type Error = CipherError;

    fn wrap(
        &self,
        rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        // Generate random 96-bit IV per RFC 7518 Section 4.7
        let mut iv = [0u8; 12];
        rng.try_fill_bytes(&mut iv).map_err(|_| CipherError::Rng)?;
        let nonce = Nonce::try_from(iv.as_ref()).map_err(|_| CipherError::Aead)?;

        let cek = cek.as_ref();
        let mut ciphertext = vec![0u8; cek.len()];
        let inout = InOutBuf::new(cek, &mut ciphertext).map_err(|_| CipherError::Aead)?;

        let tag = self
            .kw
            .encrypt_inout_detached(&nonce, &[], inout)
            .map_err(|_| CipherError::Aead)?;

        Ok(WrappedKey {
            encrypted_key: ciphertext.into(),
            iv: Some(iv.to_vec().into()),
            tag: Some(tag.to_vec().into()),
            salt: None,
        })
    }
}

impl<A> UnwrappingKey for AesGcmKwKey<A>
where
    A: AeadInOut + KeyInit,
{
    type Error = CipherError;

    fn unwrap(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        let nonce = wrapped_key
            .iv
            .as_ref()
            .ok_or(CipherError::MissingIv)?
            .as_ref()
            .try_into()
            .map_err(|_| CipherError::InvalidIvLength)?;

        let tag = wrapped_key
            .tag
            .as_ref()
            .ok_or(CipherError::MissingTag)?
            .as_ref()
            .try_into()
            .map_err(|_| CipherError::InvalidTagLength)?;

        let encrypted_key = wrapped_key.encrypted_key.as_ref();
        let mut plaintext = vec![0u8; encrypted_key.len()];
        let inout = InOutBuf::new(encrypted_key, &mut plaintext).map_err(|_| CipherError::Aead)?;

        self.kw
            .decrypt_inout_detached(&nonce, &[], inout, &tag)
            .map_err(|_| CipherError::Aead)?;

        Ok(plaintext.into())
    }
}

impl<A> From<Key<A>> for AesGcmKwKey<A>
where
    A: AeadInOut + KeyInit,
{
    fn from(key: Key<A>) -> Self {
        Self {
            oct: key.to_vec().into(),
            kw: A::new(&key),
        }
    }
}

impl<A> TryFrom<Secret> for AesGcmKwKey<A>
where
    A: AeadInOut + KeyInit,
{
    type Error = CipherError;
    fn try_from(oct: Secret) -> Result<Self, Self::Error> {
        Ok(Self {
            kw: A::new_from_slice(&oct).map_err(|_| CipherError::InvalidKeyLength)?,
            oct,
        })
    }
}
