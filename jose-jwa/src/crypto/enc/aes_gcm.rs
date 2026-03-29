//! AES-GCM authenticated encryption and key type.
//!
//! This module implements AES-GCM (Galois/Counter Mode) authenticated encryption
//! with a 96-bit nonce, as defined in
//! [RFC 7518 Section 5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3).

#![cfg(feature = "aes-gcm")]

use alloc::vec;
use core::marker::PhantomData;

use aes::cipher::{InOutBuf, KeyInit};
use aes_gcm::{AeadInOut, AesGcm, KeySizeUser, Nonce};
use digest::consts::U12;
use jose_b64::serde::Secret;
use rand_core::TryCryptoRng;

use super::{DecryptingKey, Encrypted, EncryptingKey};
use crate::{Encryption, Error};

/// AES-128-GCM content encryption key (128-bit key).
///
/// Used with the `A128GCM` algorithm per RFC 7518 Section 5.3.
pub type Aes128GcmKey = AesGcmKey<aes::Aes128>;
/// AES-192-GCM content encryption key (192-bit key).
///
/// Used with the `A192GCM` algorithm per RFC 7518 Section 5.3.
pub type Aes192GcmKey = AesGcmKey<aes::Aes192>;
/// AES-256-GCM content encryption key (256-bit key).
///
/// Used with the `A256GCM` algorithm per RFC 7518 Section 5.3.
pub type Aes256GcmKey = AesGcmKey<aes::Aes256>;

/// An AES-GCM content encryption key.
pub struct AesGcmKey<A> {
    k: Secret,
    _alg: PhantomData<A>,
}

impl<A> AesGcmKey<A>
where
    A: KeySizeUser,
{
    /// Create an AES-GCM key from raw bytes.
    ///
    /// # Arguments
    /// * `k` - The key bytes (16 bytes for A128GCM, 24 for A192GCM, 32 for A256GCM)
    pub fn from_bytes(k: impl AsRef<[u8]>) -> Result<Self, Error> {
        if k.as_ref().len() != A::key_size() {
            return Err(Error::InvalidKeyLength);
        }

        Ok(Self {
            k: Secret::from(k.as_ref().to_vec()),
            _alg: PhantomData,
        })
    }

    /// Generate a random key.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, Error> {
        let mut k = vec![0u8; A::key_size()];
        rng.try_fill_bytes(&mut k).map_err(|_| Error::Rng)?;

        Ok(Self {
            k: k.into(),
            _alg: PhantomData,
        })
    }

    /// Get the content encryption algorithm.
    pub fn enc(&self) -> Encryption
    where
        A: AesGcmAlgorithm,
    {
        A::ENC
    }

    /// Return the key bytes (JWK `k` parameter).
    pub fn k(&self) -> &Secret {
        &self.k
    }
}

impl<A> EncryptingKey for AesGcmKey<A>
where
    A: KeySizeUser + AesGcmAlgorithm,
    AesGcm<A, U12>: KeyInit + AeadInOut,
{
    type Error = Error;

    fn enc(&self) -> Encryption {
        self.enc()
    }

    fn encrypt(
        &self,
        rng: &mut impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error> {
        let mut iv = [0u8; 12];
        rng.try_fill_bytes(&mut iv).map_err(|_| Error::Rng)?;

        let cipher = AesGcm::<A, U12>::new_from_slice(self.k.as_ref())?;
        let nonce = Nonce::try_from(iv.as_ref()).map_err(|_| Error::InvalidIvLength)?;

        let mut ciphertext = vec![0u8; plaintext.as_ref().len()];
        let inout =
            InOutBuf::new(plaintext.as_ref(), &mut ciphertext).map_err(|_| Error::Encryption)?;

        let tag = cipher
            .encrypt_inout_detached(&nonce, aad.as_ref(), inout)
            .map_err(|_| Error::Encryption)?
            .to_vec();

        Ok(Encrypted {
            ciphertext: ciphertext.into(),
            iv: iv.to_vec().into(),
            tag: tag.into(),
        })
    }
}

impl<A> DecryptingKey for AesGcmKey<A>
where
    AesGcm<A, U12>: KeyInit + AeadInOut,
{
    type Error = Error;

    fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Secret, Self::Error> {
        let cipher = AesGcm::<A, U12>::new_from_slice(self.k.as_ref())?;
        let nonce = Nonce::try_from(iv.as_ref()).map_err(|_| Error::InvalidIvLength)?;

        let ciphertext = ciphertext.as_ref();
        let mut plaintext = vec![0u8; ciphertext.len()];
        let inout = InOutBuf::new(ciphertext, &mut plaintext).map_err(|_| Error::Decryption)?;

        let tag = tag.as_ref().try_into().map_err(|_| Error::Decryption)?;
        cipher
            .decrypt_inout_detached(&nonce, aad.as_ref(), inout, &tag)
            .map_err(|_| Error::Decryption)?;

        Ok(Secret::from(plaintext))
    }
}

/// Private trait for compile-time AES-GCM algorithm mapping.
pub trait AesGcmAlgorithm {
    /// The content encryption algorithm identifier.
    const ENC: Encryption;
}

impl AesGcmAlgorithm for aes::Aes128 {
    const ENC: Encryption = Encryption::A128Gcm;
}

impl AesGcmAlgorithm for aes::Aes192 {
    const ENC: Encryption = Encryption::A192Gcm;
}

impl AesGcmAlgorithm for aes::Aes256 {
    const ENC: Encryption = Encryption::A256Gcm;
}
