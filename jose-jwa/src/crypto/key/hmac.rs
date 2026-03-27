//! HMAC signing implementations

use alloc::vec;
use core::{convert::Infallible, marker::PhantomData};
use digest::InvalidLength;
use subtle::ConstantTimeEq;

use aes_gcm::KeySizeUser;
use digest::common::{InvalidKey, TryKeyInit};
use digest::typenum::Unsigned;
use hmac::{EagerHash, Hmac};
use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use sha2::{Sha256, Sha384, Sha512};

use crate::{
    Signing,
    crypto::{CipherError, Signer, SigningKey, Update, Verifier, VerifyingKey},
};

/// HS256 (HMAC + SHA-256) signer
pub type Hs256Signer = HmacKey<Hmac<Sha256>>;
/// HS384 (HMAC + SHA-384) signer
pub type Hs384Signer = HmacKey<Hmac<Sha384>>;
/// HS512 (HMAC + SHA-512) signer
pub type Hs512Signer = HmacKey<Hmac<Sha512>>;

/// HS256 (HMAC + SHA-256) verifier
pub type Hs256Verify = HmacKey<Hmac<Sha256>>;
/// HS384 (HMAC + SHA-384) verifier
pub type Hs384Verify = HmacKey<Hmac<Sha384>>;
/// HS512 (HMAC + SHA-512) verifier
pub type Hs512Verify = HmacKey<Hmac<Sha512>>;

/// An HMAC signing/verification key.
///
/// This type wraps an HMAC key and implements both [`SigningKey`] and
/// [`VerifyingKey`] since HMAC uses the same key material for both operations.
pub struct HmacKey<D> {
    k: Secret,
    _hmac: PhantomData<D>,
}

impl<D> HmacKey<D>
where
    D: KeySizeUser,
{
    /// Create an HMAC key from raw key bytes.
    ///
    /// # Arguments
    /// * `k` - The HMAC key bytes
    pub fn from_bytes(k: impl AsRef<[u8]>) -> Result<Self, CipherError> {
        if k.as_ref().len() != D::key_size() {
            return Err(CipherError::InvalidKey);
        }

        Ok(Self {
            k: k.as_ref().to_vec().into(),
            _hmac: PhantomData,
        })
    }

    /// Generate a random key.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, CipherError> {
        let mut k = vec![0u8; D::KeySize::USIZE];
        rng.try_fill_bytes(&mut k).map_err(|_| CipherError::Rng)?;

        Ok(Self {
            k: k.into(),
            _hmac: PhantomData,
        })
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        match D::key_size() {
            32 => Signing::Hs256,
            48 => Signing::Hs384,
            64 => Signing::Hs512,
            _ => unreachable!("invalid HMAC key size"),
        }
    }

    /// Return the key bytes (JWK `k` parameter).
    pub fn k(&self) -> &Secret {
        &self.k
    }
}

impl<D> SigningKey for HmacKey<D>
where
    D: EagerHash + TryKeyInit,
{
    type Signer<'a>
        = HmacState<D>
    where
        Self: 'a;

    type Error = CipherError;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        let hmac = D::new_from_slice(&self.k)?;
        Ok(HmacState { hmac })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::Error> {
        let mut state = self.signer()?;
        state.update(data).map_err(|_| CipherError::Sign)?;
        Signer::finish(state).map_err(|_| CipherError::Sign)
    }
}

impl<D> VerifyingKey for HmacKey<D>
where
    D: EagerHash + TryKeyInit,
{
    type Verifier<'a>
        = HmacState<D>
    where
        Self: 'a;

    type Error = CipherError;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        let hmac = D::new_from_slice(&self.k)?;
        Ok(HmacState { hmac })
    }

    fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error> {
        let mut state = self.verifier()?;
        state.update(data).map_err(|_| CipherError::Sign)?;
        Verifier::finish(state, signature)
    }
}

/// HMAC state.
pub struct HmacState<D> {
    hmac: D,
}

impl<D> Update for HmacState<D>
where
    D: EagerHash,
{
    type Error = Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.hmac.update(chunk.as_ref());
        Ok(())
    }
}

impl<D> Signer for HmacState<D>
where
    D: EagerHash,
{
    type Error = Infallible;

    fn finish(self) -> Result<Bytes, <Self as Signer>::Error> {
        Ok(self.hmac.finalize().to_vec().into())
    }
}

impl<D> Verifier for HmacState<D>
where
    D: EagerHash,
{
    type Error = CipherError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error> {
        if self
            .hmac
            .finalize()
            .as_slice()
            .ct_eq(signature.as_ref())
            .into()
        {
            Ok(())
        } else {
            Err(CipherError::Verify)
        }
    }
}

impl From<InvalidKey> for CipherError {
    fn from(_: InvalidKey) -> Self {
        CipherError::InvalidKey
    }
}

impl From<InvalidLength> for CipherError {
    fn from(_: InvalidLength) -> Self {
        CipherError::InvalidKey
    }
}
