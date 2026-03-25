//! AES Key Wrap (RFC 3394) implementation for JWE key management.
//!
//! Provides A128KW, A192KW, A256KW algorithms.

#![cfg(feature = "aes-kw")]

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser};
use aes_gcm::KeySizeUser;
use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::KeyInit;
use aes_kw::{AesKw, IV_LEN};
use alloc::vec;
use alloc::vec::Vec;
use digest::consts::U16;

use crate::CipherError;

pub fn aes_wrap<C>(kek: impl AsRef<[u8]>, cek: impl AsRef<[u8]>) -> Result<Vec<u8>, CipherError>
where
    C: BlockCipherEncrypt<BlockSize = U16> + BlockSizeUser + KeyInit + KeySizeUser,
{
    let kek = kek
        .as_ref()
        .try_into()
        .map_err(|_| CipherError::InvalidKeyLength)?;

    let kw = AesKw::<C>::new(kek);

    let cek = cek.as_ref();
    let mut encrypted_cek = vec![0u8; cek.len() + IV_LEN];
    let encrypted_cek_len = kw
        .wrap_key(cek, &mut encrypted_cek)
        .map_err(|_| CipherError::Aead)?
        .len();
    encrypted_cek.resize(encrypted_cek_len, 0);
    Ok(encrypted_cek)
}

pub fn aes_unwrap<C>(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError>
where
    C: BlockCipherDecrypt<BlockSize = U16> + BlockSizeUser + KeyInit + KeySizeUser,
{
    let kek = kek
        .as_ref()
        .try_into()
        .map_err(|_| CipherError::InvalidKeyLength)?;

    let kw = AesKw::<C>::new(kek);

    let encrypted_cek = encrypted_cek.as_ref();
    let mut buf = vec![0u8; encrypted_cek.len().saturating_sub(IV_LEN)];
    kw.unwrap_key(encrypted_cek, &mut buf)
        .map_err(|_| CipherError::Aead)?;
    Ok(buf)
}

/// Wrap a CEK using AES-128-KW
pub fn aes_128_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_wrap::<Aes128>(kek, cek)
}

/// Wrap a CEK using AES-192-KW
pub fn aes_192_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_wrap::<Aes192>(kek, cek)
}

/// Wrap a CEK using AES-256-KW
pub fn aes_256_wrap(
    kek: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_wrap::<Aes256>(kek, cek)
}

/// Unwrap a CEK using AES-128-KW
pub fn aes_128_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_unwrap::<Aes128>(kek, encrypted_cek)
}

/// Unwrap a CEK using AES-192-KW
pub fn aes_192_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_unwrap::<Aes192>(kek, encrypted_cek)
}

/// Unwrap a CEK using AES-256-KW
pub fn aes_256_unwrap(
    kek: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    aes_unwrap::<Aes256>(kek, encrypted_cek)
}
