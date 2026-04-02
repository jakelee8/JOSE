//! RSA-OAEP key encryption for JWE key management.
//!
//! Provides RSA-OAEP (SHA-1) and RSA-OAEP-256 (SHA-256) algorithms.

#![cfg(feature = "rsa")]

use alloc::vec::Vec;
use core::iter;
use core::marker::PhantomData;

use jose_b64::serde::{Bytes, Secret};
use rand_core::{CryptoRng, TryCryptoRng};
use rsa::traits::{PaddingScheme, PrivateKeyParts, PublicKeyParts};
use rsa::{BoxedUint, Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::Sha256;
use sha2::digest::{Digest, FixedOutputReset};

use crate::Error;
use crate::crypto::{UnwrappingKey, WrappedKey, WrappingKey};

/// RSA-OAEP with SHA-1 public key type alias.
pub type RsaOaepSha1PublicKey = RsaOaepPublicKey<Sha1>;
/// RSA-OAEP with SHA-1 private key type alias.
pub type RsaOaepSha1PrivateKey = RsaOaepPrivateKey<Sha1>;
/// RSA-OAEP with SHA-256 public key type alias.
pub type RsaOaepSha256PublicKey = RsaOaepPublicKey<Sha256>;
/// RSA-OAEP with SHA-256 private key type alias.
pub type RsaOaepSha256PrivateKey = RsaOaepPrivateKey<Sha256>;

/// Minimum RSA key size in bytes (256 bytes = 2048 bits).
pub const RSA_MIN_KEY_SIZE: usize = 256;
/// Maximum RSA key size in bytes.
pub const RSA_MAX_KEY_SIZE: usize = usize::MAX / 8;

/// RSA-OAEP private key for unwrapping (decrypting) CEKs.
pub struct RsaOaepPrivateKey<D> {
    key: RsaPrivateKey,
    _digest: PhantomData<D>,
}

impl<D> RsaOaepPrivateKey<D> {
    /// Create a new RSA-OAEP private key.
    pub fn from_components(
        n: impl AsRef<[u8]>,
        e: impl AsRef<[u8]>,
        d: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        Self::from_components_with_primes(n, e, d, iter::empty::<&[u8]>())
    }

    /// Create a new RSA-OAEP private key with CRT primes.
    pub fn from_components_with_primes(
        n: impl AsRef<[u8]>,
        e: impl AsRef<[u8]>,
        d: impl AsRef<[u8]>,
        primes: impl Iterator<Item = impl AsRef<[u8]>>,
    ) -> Result<Self, Error> {
        let n = BoxedUint::from_be_slice_vartime(n.as_ref());
        let e = BoxedUint::from_be_slice_vartime(e.as_ref());
        let d = BoxedUint::from_be_slice_vartime(d.as_ref());
        let primes = primes
            .map(|p| BoxedUint::from_be_slice_vartime(p.as_ref()))
            .collect::<Vec<_>>();

        let mut key =
            RsaPrivateKey::from_components(n, e, d, primes).map_err(|_| Error::InvalidKey)?;

        // Precompute CRT parameters for faster decryption if possible
        key.precompute().map_err(|_| Error::InvalidKey)?;

        Ok(Self {
            key,
            _digest: PhantomData,
        })
    }

    /// Generate a random RSA private key with the default key size (2048 bits).
    pub fn random(rng: &mut impl CryptoRng) -> Result<Self, Error> {
        Self::random_with_key_size(rng, RSA_MIN_KEY_SIZE)
    }

    /// Generate a random RSA private key with a specific key size (in bytes).
    pub fn random_with_key_size(rng: &mut impl CryptoRng, key_size: usize) -> Result<Self, Error> {
        if !(RSA_MIN_KEY_SIZE..=RSA_MAX_KEY_SIZE).contains(&key_size) {
            return Err(Error::InvalidKey);
        }
        RsaPrivateKey::new(rng, key_size * 8)
            .map_err(|_| Error::InvalidKey)?
            .try_into()
    }

    /// Get the modulus `n` as bytes.
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Get the public exponent `e` as bytes.
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }

    /// Get the private exponent `d` as a secret.
    pub fn d(&self) -> Secret {
        // Use constant-time encoding for private key material
        self.key.d().to_be_bytes().into()
    }

    /// Get the first prime factor `p` if available.
    pub fn p(&self) -> Option<Bytes> {
        self.key.primes().first().map(|p| p.to_be_bytes().into())
    }

    /// Get the second prime factor `q` if available.
    pub fn q(&self) -> Option<Bytes> {
        self.key.primes().get(1).map(|q| q.to_be_bytes().into())
    }

    /// Get `d mod (p-1)` (CRT coefficient) if available.
    pub fn dp(&self) -> Option<Bytes> {
        self.key.dp().map(|dp| dp.to_be_bytes().into())
    }

    /// Get `d mod (q-1)` (CRT coefficient) if available.
    pub fn dq(&self) -> Option<Bytes> {
        self.key.dq().map(|dq| dq.to_be_bytes().into())
    }

    /// Get `q^-1 mod p` (CRT coefficient) if available.
    pub fn qi(&self) -> Option<Bytes> {
        self.key.qinv().map(|qi| qi.retrieve().to_be_bytes().into())
    }
}

impl<D> TryFrom<RsaPrivateKey> for RsaOaepPrivateKey<D> {
    type Error = Error;

    fn try_from(mut key: RsaPrivateKey) -> Result<Self, Self::Error> {
        key.precompute().map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            key,
            _digest: PhantomData,
        })
    }
}

impl<D> WrappingKey for RsaOaepPrivateKey<D>
where
    D: Digest + FixedOutputReset,
    Oaep<D>: PaddingScheme,
{
    type Error = Error;

    fn wrap_key(
        &self,
        rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        let encrypted_key = Oaep::<D>::new()
            .encrypt(rng, self.key.as_public_key(), cek.as_ref())
            .map_err(|_| Error::Encryption)?;

        Ok(WrappedKey {
            encrypted_key: encrypted_key.into(),
            iv: None,
            tag: None,
            salt: None,
        })
    }
}

impl<D> UnwrappingKey for RsaOaepPrivateKey<D>
where
    D: Digest + FixedOutputReset,
    Oaep<D>: PaddingScheme,
{
    type Error = Error;

    fn unwrap_key(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        self.key
            .decrypt(Oaep::<D>::new(), wrapped_key.encrypted_key.as_ref())
            .map_err(|_| Error::Decryption)
            .map(Secret::from)
    }
}

/// RSA-OAEP public key for wrapping (encrypting) CEKs.
pub struct RsaOaepPublicKey<D> {
    key: RsaPublicKey,
    _digest: PhantomData<D>,
}

impl<D> From<RsaPublicKey> for RsaOaepPublicKey<D> {
    fn from(key: RsaPublicKey) -> Self {
        Self {
            key,
            _digest: PhantomData,
        }
    }
}

impl<D> RsaOaepPublicKey<D> {
    /// Create a new RSA-OAEP public key from unsigned big-endian octet sequence components.
    pub fn from_components(n: impl AsRef<[u8]>, e: impl AsRef<[u8]>) -> Result<Self, Error> {
        let n = BoxedUint::from_be_slice_vartime(n.as_ref());
        let e = BoxedUint::from_be_slice_vartime(e.as_ref());
        let key = RsaPublicKey::new(n, e).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            key,
            _digest: PhantomData,
        })
    }

    /// Get the modulus `n` as an unsigned big-endian octet sequence.
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Get the public exponent `e` as an unsigned big-endian octet sequence.
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }
}

impl<D> WrappingKey for RsaOaepPublicKey<D>
where
    D: Digest + FixedOutputReset,
    Oaep<D>: PaddingScheme,
{
    type Error = Error;

    fn wrap_key(
        &self,
        rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        let encrypted_key = Oaep::<D>::new()
            .encrypt(rng, &self.key, cek.as_ref())
            .map_err(|_| Error::Encryption)?;

        Ok(WrappedKey {
            encrypted_key: encrypted_key.into(),
            iv: None,
            tag: None,
            salt: None,
        })
    }
}
