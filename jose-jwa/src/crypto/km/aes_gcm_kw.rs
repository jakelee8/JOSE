//! AES-GCM Key Wrap implementation for JWE key management.
//!
//! Provides A128GCMKW, A192GCMKW, A256GCMKW algorithms.
//! Per RFC 7518 Section 4.7.

#![cfg(feature = "aes-gcm")]

use alloc::vec;
use alloc::vec::Vec;

use aes::cipher::{InOutBuf, KeyInit};
use aes_gcm::{AeadCore, AeadInOut, Aes128Gcm, Aes256Gcm, Nonce};
use rand_core::TryCryptoRng;

use crate::{Aes192Gcm, CipherError, WrappedKey};

/// Generic wrap implementation for AES-GCM-KW.
pub fn aes_gcm_kw_wrap<Aes>(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError>
where
    Aes: AeadCore + AeadInOut + KeyInit,
{
    // Generate random 96-bit IV per RFC 7518 Section 4.7
    let mut iv = [0u8; 12];
    rng.try_fill_bytes(&mut iv).map_err(|_| CipherError::Rng)?;
    let nonce = Nonce::try_from(iv.as_ref()).map_err(|_| CipherError::Aead)?;

    let cek = cek.as_ref();
    let mut ciphertext = vec![0u8; cek.len()];
    let inout = InOutBuf::new(cek, &mut ciphertext).map_err(|_| CipherError::Aead)?;

    let cipher = Aes::new_from_slice(kek.as_ref()).map_err(|_| CipherError::InvalidKeyLength)?;

    let tag = cipher
        .encrypt_inout_detached(&nonce, &[], inout)
        .map_err(|_| CipherError::Aead)?;

    Ok(WrappedKey {
        encrypted_key: Some(ciphertext),
        iv: Some(iv.to_vec()),
        tag: Some(tag.to_vec()),
        salt: None,
    })
}

/// Generic unwrap implementation for AES-GCM-KW.
pub fn aes_gcm_kw_unwrap<Aes>(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError>
where
    Aes: AeadInOut + KeyInit,
{
    let cipher = Aes::new_from_slice(kek.as_ref()).map_err(|_| CipherError::InvalidKeyLength)?;

    let nonce = iv
        .as_ref()
        .try_into()
        .map_err(|_| CipherError::InvalidIvLength)?;

    let tag = tag
        .as_ref()
        .try_into()
        .map_err(|_| CipherError::InvalidTagLength)?;

    let encrypted_cek = encrypted_cek.as_ref();
    let mut plaintext = vec![0u8; encrypted_cek.len()];
    let inout = InOutBuf::new(encrypted_cek, &mut plaintext).map_err(|_| CipherError::Aead)?;

    cipher
        .decrypt_inout_detached(&nonce, &[], inout, tag)
        .map_err(|_| CipherError::Aead)?;

    Ok(plaintext)
}

/// Wrap a CEK using AES-128-GCM-KW
pub fn aes_128_gcm_kw_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    aes_gcm_kw_wrap::<Aes128Gcm>(kek, cek, rng)
}

/// Wrap a CEK using AES-192-GCM-KW
pub fn aes_192_gcm_kw_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    aes_gcm_kw_wrap::<Aes192Gcm>(kek, cek, rng)
}

/// Wrap a CEK using AES-256-GCM-KW
pub fn aes_256_gcm_kw_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    aes_gcm_kw_wrap::<Aes256Gcm>(kek, cek, rng)
}

/// Unwrap a CEK using AES-128-GCM-KW
pub fn aes_128_gcm_kw_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_gcm_kw_unwrap::<Aes128Gcm>(kek, encrypted_cek, iv, tag)
}

/// Unwrap a CEK using AES-192-GCM-KW
pub fn aes_192_gcm_kw_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_gcm_kw_unwrap::<Aes192Gcm>(kek, encrypted_cek, iv, tag)
}

/// Unwrap a CEK using AES-256-GCM-KW
pub fn aes_256_gcm_kw_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_gcm_kw_unwrap::<Aes256Gcm>(kek, encrypted_cek, iv, tag)
}
