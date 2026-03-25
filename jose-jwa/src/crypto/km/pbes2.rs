//! PBES2 password-based key encryption for JWE key management.
//!
//! Provides PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW algorithms.
//! Per RFC 7518 Section 4.8.
//!
//! # Algorithm Overview
//!
//! Each PBES2 algorithm derives a key encryption key (KEK) from a password using
//! PBKDF2 with a specified HMAC-SHA variant, then wraps the CEK using AES-KW:
//!
//! | Algorithm          | PRF          | KEK Size | Wrap Algorithm |
//! |--------------------|--------------|----------|----------------|
//! | PBES2-HS256+A128KW | HMAC-SHA-256 | 16 bytes | A128KW         |
//! | PBES2-HS384+A192KW | HMAC-SHA-384 | 24 bytes | A192KW         |
//! | PBES2-HS512+A256KW | HMAC-SHA-512 | 32 bytes | A256KW         |
//!
//! # Salt Construction
//!
//! Per RFC 7518 Section 4.8.1.1, the salt used for PBKDF2 is constructed as:
//! `UTF8(alg) || 0x00 || Salt Input`
//!
//! Where `alg` is the algorithm name string (e.g., "PBES2-HS256+A128KW").
//! The salt input is randomly generated during wrapping and stored in the JWE header
//! as the `p2s` parameter. It MUST be at least 8 octets per RFC 7518 Section 4.8.1.1.

#![cfg(feature = "pbes2")]

extern crate alloc;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser};
use aes_gcm::KeySizeUser;
use alloc::vec::Vec;

use aes_kw::aes::{Aes128, Aes192, Aes256};
use digest::consts::U16;
use hmac::{EagerHash, KeyInit};
use pbkdf2::pbkdf2_hmac;
use rand_core::TryCryptoRng;
use sha2::{Sha256, Sha384, Sha512};
use zeroize::Zeroize;

use super::{WrappedKey, aes_unwrap, aes_wrap};
use crate::CipherError;

/// PBES2 salt size in bytes. Must be >= 8 per RFC 7518 Section 4.8.1.1.
const SALT_SIZE: usize = 16;

/// Algorithm identifiers for PBES2
const ALG_HS256_A128: &str = "PBES2-HS256+A128KW";
const ALG_HS384_A192: &str = "PBES2-HS384+A192KW";
const ALG_HS512_A256: &str = "PBES2-HS512+A256KW";

/// Trait for PBES2 configuration
trait Pbes2Config {
    /// The AES cipher type
    type Cipher: BlockSizeUser + KeyInit + KeySizeUser;
    /// The hash digest type
    type Digest: EagerHash<Core: Sync>;
    /// The algorithm name for salt construction
    const ALG_NAME: &'static str;
    /// The KEK size in bytes
    const KEK_SIZE: usize;
}

/// Configuration for PBES2-HS256+A128KW
struct ConfigHs256A128;

impl Pbes2Config for ConfigHs256A128 {
    type Cipher = Aes128;
    type Digest = Sha256;
    const ALG_NAME: &'static str = ALG_HS256_A128;
    const KEK_SIZE: usize = 16;
}

/// Configuration for PBES2-HS384+A192KW
struct ConfigHs384A192;

impl Pbes2Config for ConfigHs384A192 {
    type Cipher = Aes192;
    type Digest = Sha384;
    const ALG_NAME: &'static str = ALG_HS384_A192;
    const KEK_SIZE: usize = 24;
}

/// Configuration for PBES2-HS512+A256KW
struct ConfigHs512A256;

impl Pbes2Config for ConfigHs512A256 {
    type Cipher = Aes256;
    type Digest = Sha512;
    const ALG_NAME: &'static str = ALG_HS512_A256;
    const KEK_SIZE: usize = 32;
}

/// Construct the PBKDF2 salt per RFC 7518 Section 4.8.1.1:
/// `UTF8(alg) || 0x00 || Salt Input`
fn build_salt(alg: &str, salt_input: &[u8]) -> Vec<u8> {
    let mut salt = Vec::with_capacity(alg.len() + 1 + salt_input.len());
    salt.extend_from_slice(alg.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(salt_input);
    salt
}

/// Generic PBES2 wrap implementation.
///
/// Generates a random [`SALT_SIZE`]-byte salt internally. The salt is returned in
/// [`WrappedKey::salt`] and must be stored in the JWE header `p2s` parameter.
fn wrap_pbes2<C>(
    password: &[u8],
    cek: &[u8],
    iteration_count: u32,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError>
where
    C: Pbes2Config,
    C::Cipher: BlockCipherEncrypt<BlockSize = U16>,
{
    // Generate a random salt input (p2s). SALT_SIZE >= 8 satisfies RFC 7518 Section 4.8.1.1.
    let mut salt_input = [0u8; SALT_SIZE];
    rng.try_fill_bytes(&mut salt_input)
        .map_err(|_| CipherError::Rng)?;

    let salt = build_salt(C::ALG_NAME, &salt_input);

    let mut kek = alloc::vec![0u8; C::KEK_SIZE];
    pbkdf2_hmac::<C::Digest>(password, &salt, iteration_count, &mut kek);

    let encrypted_key = aes_wrap::<C::Cipher>(&kek, cek)?;
    kek.zeroize();

    Ok(WrappedKey {
        encrypted_key: Some(encrypted_key),
        iv: None,
        tag: None,
        salt: Some(salt_input.to_vec()),
    })
}

/// Generic PBES2 unwrap implementation.
///
/// `salt_input` is the raw `p2s` value from the JWE header (before prepending the algorithm
/// label). It MUST be at least 8 octets per RFC 7518 Section 4.8.1.1.
fn unwrap_pbes2<C>(
    password: &[u8],
    encrypted_cek: &[u8],
    salt_input: &[u8],
    iteration_count: u32,
) -> Result<Vec<u8>, CipherError>
where
    C: Pbes2Config,
    C::Cipher: BlockCipherDecrypt<BlockSize = U16>,
{
    if salt_input.len() < 8 {
        return Err(CipherError::InvalidSaltLength);
    }

    let salt = build_salt(C::ALG_NAME, salt_input);

    let mut kek = alloc::vec![0u8; C::KEK_SIZE];
    pbkdf2_hmac::<C::Digest>(password, &salt, iteration_count, &mut kek);

    let result = aes_unwrap::<C::Cipher>(&kek, encrypted_cek);
    kek.zeroize();

    result
}

/// PBES2-HS256+A128KW wrap.
///
/// Generates a random salt internally and returns it in [`WrappedKey::salt`].
/// The salt MUST be stored in the JWE header `p2s` parameter.
///
/// Per RFC 7518, an iteration count of 1000 is RECOMMENDED; higher values provide
/// better protection against brute-force attacks.
pub fn wrap_hs_256_a128(
    password: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    iteration_count: u32,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    wrap_pbes2::<ConfigHs256A128>(password.as_ref(), cek.as_ref(), iteration_count, rng)
}

/// PBES2-HS384+A192KW wrap.
pub fn wrap_hs_384_a192(
    password: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    iteration_count: u32,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    wrap_pbes2::<ConfigHs384A192>(password.as_ref(), cek.as_ref(), iteration_count, rng)
}

/// PBES2-HS512+A256KW wrap.
pub fn wrap_hs_512_a256(
    password: impl AsRef<[u8]>,
    cek: impl AsRef<[u8]>,
    iteration_count: u32,
    rng: &mut impl TryCryptoRng,
) -> Result<WrappedKey, CipherError> {
    wrap_pbes2::<ConfigHs512A256>(password.as_ref(), cek.as_ref(), iteration_count, rng)
}

/// PBES2-HS256+A128KW unwrap.
///
/// `salt_input` is the raw `p2s` value from the JWE header. Must be >= 8 bytes.
pub fn unwrap_hs_256_a128(
    password: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    salt_input: impl AsRef<[u8]>,
    iteration_count: u32,
) -> Result<Vec<u8>, CipherError> {
    unwrap_pbes2::<ConfigHs256A128>(
        password.as_ref(),
        encrypted_cek.as_ref(),
        salt_input.as_ref(),
        iteration_count,
    )
}

/// PBES2-HS384+A192KW unwrap.
///
/// `salt_input` is the raw `p2s` value from the JWE header. Must be >= 8 bytes.
pub fn unwrap_hs_384_a192(
    password: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    salt_input: impl AsRef<[u8]>,
    iteration_count: u32,
) -> Result<Vec<u8>, CipherError> {
    unwrap_pbes2::<ConfigHs384A192>(
        password.as_ref(),
        encrypted_cek.as_ref(),
        salt_input.as_ref(),
        iteration_count,
    )
}

/// PBES2-HS512+A256KW unwrap.
///
/// `salt_input` is the raw `p2s` value from the JWE header. Must be >= 8 bytes.
pub fn unwrap_hs_512_a256(
    password: impl AsRef<[u8]>,
    encrypted_cek: impl AsRef<[u8]>,
    salt_input: impl AsRef<[u8]>,
    iteration_count: u32,
) -> Result<Vec<u8>, CipherError> {
    unwrap_pbes2::<ConfigHs512A256>(
        password.as_ref(),
        encrypted_cek.as_ref(),
        salt_input.as_ref(),
        iteration_count,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_construction() {
        let salt_input = b"test-salt-input";
        let salt = build_salt(ALG_HS256_A128, salt_input);

        let expected_len = ALG_HS256_A128.len() + 1 + salt_input.len();
        assert_eq!(salt.len(), expected_len);
        assert_eq!(&salt[..ALG_HS256_A128.len()], ALG_HS256_A128.as_bytes());
        assert_eq!(salt[ALG_HS256_A128.len()], 0x00);
        assert_eq!(&salt[ALG_HS256_A128.len() + 1..], salt_input.as_slice());
    }

    #[test]
    fn test_pbes2_hs256_a128_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let wrapped = wrap_hs_256_a128(password, cek, iteration_count, &mut rng).unwrap();
        let salt = wrapped.salt.clone().unwrap();
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();
        let unwrapped =
            unwrap_hs_256_a128(password, &encrypted_key, &salt, iteration_count).unwrap();

        assert_eq!(unwrapped, cek.as_slice());
    }

    #[test]
    fn test_pbes2_hs384_a192_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let wrapped = wrap_hs_384_a192(password, cek, iteration_count, &mut rng).unwrap();
        let salt = wrapped.salt.clone().unwrap();
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();
        let unwrapped =
            unwrap_hs_384_a192(password, &encrypted_key, &salt, iteration_count).unwrap();

        assert_eq!(unwrapped, cek.as_slice());
    }

    #[test]
    fn test_pbes2_hs512_a256_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let wrapped = wrap_hs_512_a256(password, cek, iteration_count, &mut rng).unwrap();
        let salt = wrapped.salt.clone().unwrap();
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();
        let unwrapped =
            unwrap_hs_512_a256(password, &encrypted_key, &salt, iteration_count).unwrap();

        assert_eq!(unwrapped, cek.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"correct-password";
        let wrong_password = b"wrong-password";
        let cek = b"my-content-encryption-key!!12345";

        let wrapped = wrap_hs_256_a128(password, cek, 1000, &mut rng).unwrap();
        let salt = wrapped.salt.clone().unwrap();
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();

        assert!(unwrap_hs_256_a128(wrong_password, &encrypted_key, &salt, 1000).is_err());
    }

    #[test]
    fn test_wrong_salt_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";

        let wrapped = wrap_hs_256_a128(password, cek, 1000, &mut rng).unwrap();
        let wrong_salt = b"wrong-salt-input!!";
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();

        assert!(unwrap_hs_256_a128(password, &encrypted_key, wrong_salt, 1000).is_err());
    }

    #[test]
    fn test_wrong_iteration_count_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";

        let wrapped = wrap_hs_256_a128(password, cek, 1000, &mut rng).unwrap();
        let salt = wrapped.salt.clone().unwrap();
        let encrypted_key = wrapped.encrypted_key.clone().unwrap();

        assert!(unwrap_hs_256_a128(password, &encrypted_key, &salt, 999).is_err());
    }

    #[test]
    fn test_short_salt_rejected_on_unwrap() {
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let short_salt = b"tiny"; // 4 bytes < 8

        assert!(unwrap_hs_256_a128(password, cek, short_salt, 1000).is_err());
    }
}
