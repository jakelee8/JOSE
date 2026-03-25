//! RSA-OAEP key encryption for JWE key management.
//!
//! Provides RSA-OAEP (SHA-1) and RSA-OAEP-256 (SHA-256) algorithms.

#![cfg(feature = "rsa")]

use alloc::vec::Vec;
use digest::{Digest, FixedOutputReset};
use rand_core::TryCryptoRng;
use rsa::Oaep;
use rsa::traits::PaddingScheme;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;

use crate::CipherError;

/// Wrap (encrypt) a CEK using RSA-OAEP
pub fn rsa_oaep_wrap<D>(
    public_key: &RsaPublicKey,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<Vec<u8>, CipherError>
where
    D: Digest + FixedOutputReset,
    Oaep<D>: PaddingScheme,
{
    Oaep::<D>::new()
        .encrypt(rng, public_key, cek.as_ref())
        .map_err(|_| CipherError::Aead)
}

/// Unwrap (decrypt) a CEK using RSA-OAEP
pub fn rsa_oaep_unwrap<D>(
    private_key: &RsaPrivateKey,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError>
where
    D: Digest + FixedOutputReset,
{
    private_key
        .decrypt(Oaep::<D>::new(), encrypted_cek.as_ref())
        .map_err(|_| CipherError::Aead)
}

/// Wrap (encrypt) a CEK using RSA-OAEP with SHA-1
pub fn wrap_sha1(
    public_key: &RsaPublicKey,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<Vec<u8>, CipherError> {
    rsa_oaep_wrap::<Sha1>(public_key, cek, rng)
}

/// Wrap (encrypt) a CEK using RSA-OAEP with SHA-256
pub fn wrap_sha256(
    public_key: &RsaPublicKey,
    cek: impl AsRef<[u8]>,
    rng: &mut impl TryCryptoRng,
) -> Result<Vec<u8>, CipherError> {
    rsa_oaep_wrap::<Sha256>(public_key, cek, rng)
}

/// Unwrap (decrypt) a CEK using RSA-OAEP with SHA-1
pub fn unwrap_sha1(
    private_key: &RsaPrivateKey,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    rsa_oaep_unwrap::<Sha1>(private_key, encrypted_cek)
}

/// Unwrap (decrypt) a CEK using RSA-OAEP with SHA-256
pub fn unwrap_sha256(
    private_key: &RsaPrivateKey,
    encrypted_cek: impl AsRef<[u8]>,
) -> Result<Vec<u8>, CipherError> {
    rsa_oaep_unwrap::<Sha256>(private_key, encrypted_cek)
}
