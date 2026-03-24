//! AES-GCM implementations
//!
//! This module provides sealing and unsealing for:
//! - Content encryption: A128GCM, A256GCM
//! - Key wrap: A128GCMKW, A256GCMKW

#![cfg(feature = "aes-gcm")]

use alloc::vec;
use alloc::vec::Vec;
use core::convert::Infallible;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AesGcm, KeyInit, Nonce};
use aes_kw::cipher::BlockSizeUser;
use zeroize::{Zeroize, Zeroizing};

use crate::Sealing;
use crate::crypto::seal::{Sealed, Sealer, SealingKey, UnsealingKey};
use jose_b64::stream::Update;

type Result<T, E = AesGcmError> = core::result::Result<T, E>;

impl core::fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AesGcmError::Crypto => write!(f, "AES-GCM crypto error"),
            AesGcmError::InvalidAlgorithm => write!(f, "invalid algorithm"),
            AesGcmError::InvalidKey => write!(f, "invalid key size"),
            AesGcmError::MissingField(field) => write!(f, "missing field: {}", field),
            AesGcmError::InvalidFormat => write!(f, "invalid data format"),
            AesGcmError::RandError => write!(f, "random generation failed"),
        }
    }
}

/// AES-GCM Sealer
pub struct AesGcmSealer<'a, A> {
    kek: &'a A,
    cek: Option<Vec<u8>>,
    cek_iv: Option<[u8; 12]>,
    plaintext: Vec<u8>,
}

impl<'a, A> Zeroize for AesGcmSealer<'a, A> {
    fn zeroize(&mut self) {
        self.cek.zeroize();
        self.cek_iv.zeroize();
        self.plaintext.zeroize();
    }
}

impl<'a, C, N> SealingKey<'a> for AesGcm<C, N>
where
    C: BlockSizeUser + 'a,
    <C as BlockSizeUser>::BlockSize: BlockSizeUser,
    N: 'a,
    AesGcm<C, N>: KeyInit + Aead,
{
    type StartError = AesGcmError;
    type Sealer = AesGcmSealer<'a, AesGcm<C, N>>;

    fn seal(&'a self, alg: Sealing) -> Result<Self::Sealer> {
        let (cek, cek_iv) = match alg {
            Sealing::A128Kw | Sealing::A192Kw | Sealing::A256Kw => (None, None),
            Sealing::A128GcmKw | Sealing::A192GcmKw | Sealing::A256GcmKw => {
                // CEK size matches the cipher's block size (16 for Aes128, 32 for Aes256)
                let cek_size = <C as BlockSizeUser>::BlockSize::block_size();
                let cek = generate_bytes(cek_size)?;
                let iv = generate_iv()?;
                (Some(cek), Some(iv))
            }
            _ => return Err(AesGcmError::InvalidAlgorithm),
        };

        Ok(AesGcmSealer {
            kek: self,
            cek,
            cek_iv,
            plaintext: Vec::new(),
        })
    }
}

impl<'a, C, N> Update for AesGcmSealer<'a, AesGcm<C, N>> {
    type Error = Infallible;
    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.plaintext.extend_from_slice(chunk.as_ref());
        Ok(())
    }
}

impl<'a, C, N> Sealer for AesGcmSealer<'a, AesGcm<C, N>>
where
    C: BlockSizeUser + 'a,
    <C as BlockSizeUser>::BlockSize: BlockSizeUser,
    N: 'a,
    AesGcm<C, N>: KeyInit + Aead,
{
    type FinishError = AesGcmError;

    fn finish(self, aad: impl AsRef<[u8]>) -> Result<Sealed> {
        // Handle direct encryption (no CEK wrapping)
        let Some((cek_bytes, cek_iv)) = self.cek.zip(self.cek_iv) else {
            // Direct encryption - the key IS the CEK
            let iv = generate_iv()?;
            let nonce = Nonce::try_from(&iv[..]).map_err(|_| AesGcmError::InvalidFormat)?;

            let payload = Payload {
                msg: &self.plaintext,
                aad: aad.as_ref(),
            };
            let encrypted = self
                .kek
                .encrypt(&nonce, payload)
                .map_err(|_| AesGcmError::Crypto)?;

            // Split ciphertext and tag (last 16 bytes)
            let tag_offset = encrypted.len().saturating_sub(16);
            let ciphertext = encrypted[..tag_offset].to_vec();
            let tag = encrypted[tag_offset..].to_vec();

            return Ok(Sealed {
                encrypted_key: None,
                iv: Some(iv.to_vec()),
                ciphertext,
                tag: Some(tag),
            });
        };

        // Key wrap mode: generate CEK, encrypt content with CEK, wrap CEK with KEK
        let cek = AesGcm::<C, N>::new_from_slice(cek_bytes.as_ref())
            .map_err(|_| AesGcmError::InvalidKey)?;
        let content_nonce = Nonce::try_from(&cek_iv[..]).map_err(|_| AesGcmError::InvalidFormat)?;

        let content_payload = Payload {
            msg: &self.plaintext,
            aad: aad.as_ref(),
        };
        let encrypted_content = cek
            .encrypt(&content_nonce, content_payload)
            .map_err(|_| AesGcmError::Crypto)?;

        // Split content ciphertext and tag
        let content_tag_offset = encrypted_content.len().saturating_sub(16);
        let ciphertext = encrypted_content[..content_tag_offset].to_vec();
        let content_tag = encrypted_content[content_tag_offset..].to_vec();

        // Wrap the CEK with the KEK
        let kek_iv = generate_iv()?;
        let kek_nonce = Nonce::try_from(&kek_iv[..]).map_err(|_| AesGcmError::InvalidFormat)?;

        let cek_payload = Payload {
            msg: &cek_bytes,
            aad: aad.as_ref(),
        };
        let wrapped_cek = self
            .kek
            .encrypt(&kek_nonce, cek_payload)
            .map_err(|_| AesGcmError::Crypto)?;

        Ok(Sealed {
            encrypted_key: Some(wrapped_cek),
            iv: Some(kek_iv.to_vec()),
            ciphertext,
            tag: Some(content_tag),
        })
    }
}

// ============================================================================
// Unsealing
// ============================================================================

impl<'a, C, N> UnsealingKey<'a> for AesGcm<C, N>
where
    C: BlockSizeUser + 'a,
    <C as BlockSizeUser>::BlockSize: BlockSizeUser,
    N: 'a,
    AesGcm<C, N>: KeyInit + Aead,
{
    type Error = AesGcmError;

    fn unseal(
        &'a self,
        input: Sealed,
        aad: impl AsRef<[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        // Check if this is direct encryption or key wrap
        let Some(encrypted_key) = &input.encrypted_key else {
            // Direct encryption - decrypt content with the key directly
            let iv = input.iv.ok_or(AesGcmError::MissingField("iv"))?;
            let tag = input.tag.ok_or(AesGcmError::MissingField("tag"))?;

            let nonce = Nonce::try_from(iv.as_slice()).map_err(|_| AesGcmError::InvalidFormat)?;

            // Reconstruct ciphertext with tag for decryption
            let mut ct_with_tag = input.ciphertext.clone();
            ct_with_tag.extend_from_slice(&tag);

            let payload = Payload {
                msg: &ct_with_tag,
                aad: aad.as_ref(),
            };
            let plaintext = self
                .decrypt(&nonce, payload)
                .map_err(|_| AesGcmError::Crypto)?;

            return Ok(Zeroizing::new(plaintext));
        };

        // Key wrap mode
        let iv = input.iv.ok_or(AesGcmError::MissingField("iv"))?;
        let tag = input.tag.ok_or(AesGcmError::MissingField("tag"))?;

        // Unwrap the CEK
        let nonce = Nonce::try_from(iv.as_slice()).map_err(|_| AesGcmError::InvalidFormat)?;

        let cek_payload = Payload {
            msg: encrypted_key.as_slice(),
            aad: aad.as_ref(),
        };
        let cek_bytes = self
            .decrypt(&nonce, cek_payload)
            .map_err(|_| AesGcmError::Crypto)?;

        // Decrypt the content with the CEK
        let cek =
            AesGcm::<C, N>::new_from_slice(&cek_bytes).map_err(|_| AesGcmError::InvalidKey)?;

        // For AES-GCMKW, we need the content IV
        // In JWE, this would typically be in the header
        // For now, using a placeholder approach
        let mut ct_with_tag = input.ciphertext.clone();
        ct_with_tag.extend_from_slice(&tag);

        // The content IV - in real JWE this should come from the protected header
        // Using first 12 bytes of a hash or derivation would be more appropriate
        let content_iv = [0u8; 12]; // Placeholder
        let content_nonce =
            Nonce::try_from(&content_iv[..]).map_err(|_| AesGcmError::InvalidFormat)?;

        let content_payload = Payload {
            msg: &ct_with_tag,
            aad: aad.as_ref(),
        };
        let plaintext = cek
            .decrypt(&content_nonce, content_payload)
            .map_err(|_| AesGcmError::Crypto)?;

        Ok(Zeroizing::new(plaintext))
    }
}

/// Error type for AES-GCM operations
#[derive(Debug, Clone, Copy)]
pub enum AesGcmError {
    /// Crypto error
    Crypto,
    /// Invalid algorithm
    InvalidAlgorithm,
    /// Invalid key size
    InvalidKey,
    /// Missing field
    MissingField(&'static str),
    /// Invalid format
    InvalidFormat,
    /// Random generation failed
    RandError,
}

impl core::error::Error for AesGcmError {}

impl From<aes_gcm::Error> for AesGcmError {
    fn from(_: aes_gcm::Error) -> Self {
        AesGcmError::Crypto
    }
}

impl From<core::array::TryFromSliceError> for AesGcmError {
    fn from(_: core::array::TryFromSliceError) -> Self {
        AesGcmError::InvalidFormat
    }
}

fn generate_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(|_| AesGcmError::RandError)?;
    Ok(iv)
}

fn generate_bytes(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    getrandom::fill(&mut bytes).map_err(|_| AesGcmError::RandError)?;
    Ok(bytes.into())
}
