//! AES Key Wrap (RFC 3394) implementation for JWE key management.
//!
//! Provides A128KW, A192KW, A256KW algorithms.

#![cfg(feature = "aes-kw")]

use alloc::vec;

use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser,
};
use aes_kw::{AesKw, IV_LEN};
use digest::consts::U16;
use jose_b64::serde::Secret;
use rand_core::TryCryptoRng;

use super::{UnwrappingKey, WrappedKey, WrappingKey};
use crate::Error;

/// AES-128 Key Wrap key type alias.
pub type AesKwKey128 = AesKwKey<Aes128>;
/// AES-192 Key Wrap key type alias.
pub type AesKwKey192 = AesKwKey<Aes192>;
/// AES-256 Key Wrap key type alias.
pub type AesKwKey256 = AesKwKey<Aes256>;

/// An AES Key Wrap key encryption key.
///
/// This type wraps an AES-KW key and provides wrap/unwrap operations
/// for JWE key management.
pub struct AesKwKey<C>
where
    C: KeySizeUser,
{
    k: Secret,
    kw: AesKw<C>,
}

impl<C> AesKwKey<C>
where
    C: KeyInit + KeySizeUser,
{
    /// Generate a random key.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, Error> {
        let mut key = Key::<C>::default();
        rng.try_fill_bytes(&mut key).map_err(|_| Error::Rng)?;
        Ok(key.into())
    }

    /// Return the key bytes (JWK `k` parameter).
    pub fn k(&self) -> &Secret {
        &self.k
    }
}

impl<C> From<Key<C>> for AesKwKey<C>
where
    C: KeyInit + KeySizeUser,
{
    fn from(key: Key<C>) -> Self {
        Self {
            kw: AesKw::new(&key),
            k: key.to_vec().into(),
        }
    }
}

impl<C> TryFrom<Secret> for AesKwKey<C>
where
    C: KeyInit + KeySizeUser,
{
    type Error = Error;

    fn try_from(k: Secret) -> Result<Self, Self::Error> {
        let kw = AesKw::<C>::new_from_slice(k.as_ref()).map_err(|_| Error::InvalidKeyLength)?;
        Ok(Self { k, kw })
    }
}

impl<C> WrappingKey for AesKwKey<C>
where
    C: BlockCipherEncrypt<BlockSize = U16> + BlockSizeUser + KeySizeUser,
{
    type Error = Error;

    fn wrap_key(
        &self,
        _rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        let cek = cek.as_ref();
        let mut encrypted_cek = vec![0u8; cek.len() + IV_LEN];

        self.kw
            .wrap_key(cek.as_ref(), &mut encrypted_cek)
            .map_err(|_| Error::Encryption)?;

        Ok(WrappedKey {
            encrypted_key: encrypted_cek.into(),
            iv: None,
            tag: None,
            salt: None,
        })
    }
}

impl<C> UnwrappingKey for AesKwKey<C>
where
    C: BlockCipherDecrypt<BlockSize = U16> + BlockSizeUser + KeySizeUser,
{
    type Error = Error;

    fn unwrap_key(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        let encrypted_cek = wrapped_key.encrypted_key.as_ref();
        let mut buf = vec![0u8; encrypted_cek.len().saturating_sub(IV_LEN)];

        self.kw
            .unwrap_key(encrypted_cek, &mut buf)
            .map_err(|_| Error::Decryption)?;

        Ok(buf.into())
    }
}
