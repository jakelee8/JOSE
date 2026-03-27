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

use core::marker::PhantomData;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit};
use aes_gcm::KeySizeUser;
use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::Key;
use digest::consts::U16;
use hmac::EagerHash;
use jose_b64::serde::Secret;
use pbkdf2::pbkdf2_hmac;
use rand_core::TryCryptoRng;
use sha2::{Sha256, Sha384, Sha512};

use super::{AesKwKey, UnwrappingKey, WrappedKey, WrappingKey};
use crate::crypto::CipherError;

/// PBES2-HS256+A128KW key type.
pub type Pbes2Hs256A128Key = Pbes2Key<ConfigHs256A128>;
/// PBES2-HS384+A192KW key type.
pub type Pbes2Hs384A192Key = Pbes2Key<ConfigHs384A192>;
/// PBES2-HS512+A256KW key type.
pub type Pbes2Hs512A256Key = Pbes2Key<ConfigHs512A256>;

/// PBES2 salt size in bytes. Must be >= 8 per RFC 7518 Section 4.8.1.1.
pub const SALT_SIZE: usize = 16;

/// Trait for PBES2 configuration.
///
/// This trait defines the cipher, digest, and algorithm name for a PBES2 variant.
trait Pbes2Config {
    /// The AES cipher type for key wrapping.
    type Cipher: BlockSizeUser + KeyInit + KeySizeUser;
    /// The hash digest type for PBKDF2.
    type Digest: EagerHash<Core: Sync>;
    /// The algorithm name for salt construction.
    const ALG_NAME: &'static str;
}

/// Configuration for PBES2-HS256+A128KW
pub struct ConfigHs256A128;

impl Pbes2Config for ConfigHs256A128 {
    type Cipher = Aes128;
    type Digest = Sha256;
    const ALG_NAME: &'static str = "PBES2-HS256+A128KW";
}

/// Configuration for PBES2-HS384+A192KW
pub struct ConfigHs384A192;

impl Pbes2Config for ConfigHs384A192 {
    type Cipher = Aes192;
    type Digest = Sha384;
    const ALG_NAME: &'static str = "PBES2-HS384+A192KW";
}

/// Configuration for PBES2-HS512+A256KW
pub struct ConfigHs512A256;

impl Pbes2Config for ConfigHs512A256 {
    type Cipher = Aes256;
    type Digest = Sha512;
    const ALG_NAME: &'static str = "PBES2-HS512+A256KW";
}

/// A PBES2 key encryption key.
///
/// This type wraps a password and iteration count, providing PBES2 key wrapping
/// and unwrapping operations for JWE key management per RFC 7518 Section 4.8.
///
/// Generic over the PBES2 configuration (cipher, digest, and algorithm name).
///
/// # Type Aliases
/// - `Pbes2Hs256A128Key` for PBES2-HS256+A128KW
/// - `Pbes2Hs384A192Key` for PBES2-HS384+A192KW
/// - `Pbes2Hs512A256Key` for PBES2-HS512+A256KW
///
/// # Example
/// ```
/// use jose_jwa::{Pbes2Hs256A128Key, WrappingKey, UnwrappingKey, WrappedKey};
///
/// // Create a PBES2 key with password and iteration count
/// let password = b"my-secret-password";
/// let pbes2_key = Pbes2Hs256A128Key::new(password, 1000);
///
/// // Wrap a CEK
/// // let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();
///
/// // Unwrap (iteration count is stored in the key)
/// // let unwrapped = pbes2_key.unwrap(&wrapped).unwrap();
/// ```
pub struct Pbes2Key<C> {
    password: Secret,
    iteration_count: u32,
    _config: PhantomData<C>,
}

impl<C> Pbes2Key<C> {
    /// Create a new PBES2 key with the given password and iteration count.
    ///
    /// Per RFC 7518, an iteration count of 1000 is RECOMMENDED; higher values
    /// provide better protection against brute-force attacks. For production
    /// use, iteration counts of 10000 or higher are recommended.
    pub fn new(password: impl AsRef<[u8]>, iteration_count: u32) -> Self {
        Self {
            password: password.as_ref().to_vec().into(),
            iteration_count,
            _config: PhantomData,
        }
    }

    /// Get the password as a secret.
    pub fn password(&self) -> &Secret {
        &self.password
    }

    /// Get the iteration count.
    pub fn iteration_count(&self) -> u32 {
        self.iteration_count
    }
}

impl<C> WrappingKey for Pbes2Key<C>
where
    C: Pbes2Config,
    C::Cipher: BlockCipherEncrypt<BlockSize = U16>,
{
    type Error = CipherError;

    fn wrap(
        &self,
        rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        // Generate a random salt input (p2s). SALT_SIZE >= 8 satisfies RFC 7518 Section 4.8.1.1.
        let mut salt_input = [0u8; SALT_SIZE];
        rng.try_fill_bytes(&mut salt_input)
            .map_err(|_| CipherError::Rng)?;

        // Build the full salt: UTF8(alg) || 0x00 || Salt Input
        let salt = build_salt(C::ALG_NAME, &salt_input);

        // Derive KEK using PBKDF2
        let mut kek = Key::<C::Cipher>::default();
        pbkdf2_hmac::<C::Digest>(
            self.password.as_ref(),
            &salt,
            self.iteration_count,
            &mut kek,
        );

        // Wrap the CEK using AES-KW
        let mut wrapped = AesKwKey::<C::Cipher>::from(kek).wrap(rng, cek)?;

        // Add the salt to the wrapped key
        wrapped.salt = Some(salt_input.to_vec().into());

        Ok(wrapped)
    }
}

impl<C> UnwrappingKey for Pbes2Key<C>
where
    C: Pbes2Config,
    C::Cipher: BlockCipherDecrypt<BlockSize = U16>,
{
    type Error = CipherError;

    fn unwrap(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        // Extract salt from wrapped key
        let salt_input = wrapped_key
            .salt
            .as_ref()
            .ok_or(CipherError::MissingSalt)?
            .as_ref();

        if salt_input.len() < 8 {
            return Err(CipherError::InvalidSaltLength);
        }

        // Build the full salt: UTF8(alg) || 0x00 || Salt Input
        let salt = build_salt(C::ALG_NAME, salt_input);

        // Derive KEK using PBKDF2
        let mut kek = Key::<C::Cipher>::default();
        pbkdf2_hmac::<C::Digest>(
            self.password.as_ref(),
            &salt,
            self.iteration_count,
            &mut kek,
        );

        // Unwrap the CEK using AES-KW
        AesKwKey::<C::Cipher>::from(kek).unwrap(wrapped_key)
    }
}

/// Construct the PBKDF2 salt per RFC 7518 Section 4.8.1.1:
/// `UTF8(alg) || 0x00 || Salt Input`
fn build_salt(alg: &str, salt_input: &[u8]) -> alloc::vec::Vec<u8> {
    let mut salt = alloc::vec::Vec::with_capacity(alg.len() + 1 + salt_input.len());
    salt.extend_from_slice(alg.as_bytes());
    salt.push(0x00);
    salt.extend_from_slice(salt_input);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_construction() {
        let salt_input = b"test-salt-input";
        let salt = build_salt("PBES2-HS256+A128KW", salt_input);

        let expected_len = "PBES2-HS256+A128KW".len() + 1 + salt_input.len();
        assert_eq!(salt.len(), expected_len);
        assert_eq!(
            &salt[.."PBES2-HS256+A128KW".len()],
            "PBES2-HS256+A128KW".as_bytes()
        );
        assert_eq!(salt["PBES2-HS256+A128KW".len()], 0x00);
        assert_eq!(
            &salt["PBES2-HS256+A128KW".len() + 1..],
            salt_input.as_slice()
        );
    }

    #[test]
    fn test_pbes2_hs256_a128_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let pbes2_key = Pbes2Hs256A128Key::new(password, iteration_count);
        let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();
        let unwrapped = pbes2_key.unwrap(&wrapped).unwrap();

        assert_eq!(unwrapped.as_ref(), cek);
    }

    #[test]
    fn test_pbes2_hs384_a192_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let pbes2_key = Pbes2Hs384A192Key::new(password, iteration_count);
        let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();
        let unwrapped = pbes2_key.unwrap(&wrapped).unwrap();

        assert_eq!(unwrapped.as_ref(), cek);
    }

    #[test]
    fn test_pbes2_hs512_a256_roundtrip() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";
        let iteration_count = 1000;

        let pbes2_key = Pbes2Hs512A256Key::new(password, iteration_count);
        let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();
        let unwrapped = pbes2_key.unwrap(&wrapped).unwrap();

        assert_eq!(unwrapped.as_ref(), cek);
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"correct-password";
        let wrong_password = b"wrong-password";
        let cek = b"my-content-encryption-key!!12345";

        let pbes2_key = Pbes2Hs256A128Key::new(password, 1000);
        let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();

        let wrong_key = Pbes2Hs256A128Key::new(wrong_password, 1000);
        assert!(wrong_key.unwrap(&wrapped).is_err());
    }

    #[test]
    fn test_wrong_salt_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";

        let pbes2_key = Pbes2Hs256A128Key::new(password, 1000);
        let mut wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();

        // Modify the salt
        wrapped.salt = Some(b"wrong-salt-input!!".to_vec().into());

        assert!(pbes2_key.unwrap(&wrapped).is_err());
    }

    #[test]
    fn test_wrong_iteration_count_fails() {
        let mut rng = getrandom::SysRng;
        let password = b"my-secret-password";
        let cek = b"my-content-encryption-key!!12345";

        let pbes2_key = Pbes2Hs256A128Key::new(password, 1000);
        let wrapped = pbes2_key.wrap(&mut rng, cek).unwrap();

        // Use wrong iteration count
        let wrong_key = Pbes2Hs256A128Key::new(password, 999);
        assert!(wrong_key.unwrap(&wrapped).is_err());
    }

    #[test]
    fn test_missing_salt_fails() {
        let password = b"my-secret-password";
        let pbes2_key = Pbes2Hs256A128Key::new(password, 1000);

        let wrapped = WrappedKey {
            encrypted_key: b"dummy".to_vec().into(),
            iv: None,
            tag: None,
            salt: None, // Missing salt
        };

        assert!(pbes2_key.unwrap(&wrapped).is_err());
    }
}
