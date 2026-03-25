//! AES-GCM authenticated encryption.
//!
//! This module implements AES-GCM (Galois/Counter Mode) authenticated encryption
//! with a 96-bit nonce, as defined in
//! [RFC 7518 Section 5.3](https://www.rfc-editor.org/rfc/rfc7518#section-5.3).

#![cfg(feature = "aes-gcm")]

use alloc::vec;
use alloc::vec::Vec;

use aes::cipher::{InOutBuf, KeyInit};
use aes_gcm::{AeadInOut, Nonce};
use aes_gcm::{AesGcm, KeySizeUser};
use digest::consts::U12;
use rand_core::TryCryptoRng;

use super::{CipherError, Encrypted};

/// Encrypts plaintext using AES-GCM authenticated encryption.
///
/// Uses a 96-bit (12-byte) nonce generated using the provided RNG.
///
/// # Type Parameters
///
/// * `Aes` - The AES variant (e.g., `Aes128`, `Aes192`, `Aes256`)
///
/// # Arguments
///
/// * `rng` - A cryptographically secure random number generator for nonce generation
/// * `key` - The encryption key (size depends on AES variant)
/// * `plaintext` - The data to encrypt
/// * `aad` - Additional authenticated data that is integrity-protected but not encrypted
///
/// # Returns
///
/// Returns `Ok(Encrypted)` containing the ciphertext, nonce, and authentication tag.
pub fn aes_gcm_encrypt<Aes>(
    rng: &mut impl TryCryptoRng,
    plaintext: impl AsRef<[u8]>,
    aad: impl AsRef<[u8]>,
) -> Result<Encrypted, CipherError>
where
    Aes: KeySizeUser,
    AesGcm<Aes, U12>: KeyInit + AeadInOut,
{
    let key_size: usize = Aes::key_size();
    let mut cek = vec![0u8; key_size];
    rng.try_fill_bytes(&mut cek).map_err(|_| CipherError::Rng)?;

    let mut iv = [0u8; 12];
    rng.try_fill_bytes(&mut iv).map_err(|_| CipherError::Rng)?;

    let cek_key = AesGcm::<Aes, U12>::new_from_slice(cek.as_ref())?;
    let cek_nonce = Nonce::try_from(iv.as_ref()).map_err(|_| CipherError::InvalidIvLength)?;

    let mut ciphertext = Vec::new();
    ciphertext.resize(plaintext.as_ref().len(), 0);
    let inout =
        InOutBuf::new(plaintext.as_ref(), &mut ciphertext).map_err(|_| CipherError::Aead)?;

    let tag = cek_key
        .encrypt_inout_detached(&cek_nonce, aad.as_ref(), inout)?
        .to_vec();

    Ok(Encrypted {
        ciphertext,
        cek,
        iv: iv.to_vec(),
        tag,
    })
}

/// Decrypts ciphertext using AES-GCM authenticated decryption.
///
/// # Type Parameters
///
/// * `Aes` - The AES variant (e.g., `Aes128`, `Aes192`, `Aes256`)
///
/// # Arguments
///
/// * `key` - The encryption key (size depends on AES variant)
/// * `ciphertext` - The ciphertext to decrypt
/// * `aad` - The additional authenticated data used during encryption
/// * `tag` - The 128-bit authentication tag for integrity verification
/// * `iv` - The 96-bit nonce used during encryption
///
/// # Returns
///
/// Returns `Ok(Vec<u8>)` containing the decrypted plaintext.
///
/// # Errors
///
/// Returns `CipherError::Aead` if authentication tag verification fails.
pub fn aes_gcm_decrypt<Aes>(
    key: impl AsRef<[u8]>,
    ciphertext: impl AsRef<[u8]>,
    aad: impl AsRef<[u8]>,
    tag: impl AsRef<[u8]>,
    iv: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError>
where
    AesGcm<Aes, U12>: KeyInit + AeadInOut,
{
    let cek = AesGcm::<Aes, U12>::new_from_slice(key.as_ref())?;
    let cek_nonce = Nonce::try_from(iv.as_ref()).map_err(|_| CipherError::InvalidIvLength)?;

    let ciphertext = ciphertext.as_ref();
    let mut plaintext = Vec::new();
    plaintext.resize(ciphertext.len(), 0);
    let inout = InOutBuf::new(ciphertext, &mut plaintext).map_err(|_| CipherError::Aead)?;

    let tag = tag.as_ref().try_into().map_err(|_| CipherError::Aead)?;
    cek.decrypt_inout_detached(&cek_nonce, aad.as_ref(), inout, &tag)?;

    Ok(plaintext)
}
