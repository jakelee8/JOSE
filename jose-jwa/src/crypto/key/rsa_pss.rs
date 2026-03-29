//! RSA-PSS signing implementations

use core::marker::PhantomData;

use digest::{Digest, FixedOutputReset, OutputSizeUser};
use jose_b64::serde::{Bytes, Secret};
use jose_b64::stream::Update;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey, pss};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::{Signer, SigningKey, Verifier, VerifyingKey};
use crate::{Error, Signing};

/// PS256 (RSA-PSS + SHA-256) signing key
pub type Ps256SigningKey = RsaPssSigningKey<Sha256>;
/// PS384 (RSA-PSS + SHA-384) signing key
pub type Ps384SigningKey = RsaPssSigningKey<Sha384>;
/// PS512 (RSA-PSS + SHA-512) signing key
pub type Ps512SigningKey = RsaPssSigningKey<Sha512>;

/// PS256 (RSA-PSS + SHA-256) verifying key
pub type Ps256VerifyingKey = RsaPssVerifyingKey<Sha256>;
/// PS384 (RSA-PSS + SHA-384) verifying key
pub type Ps384VerifyingKey = RsaPssVerifyingKey<Sha384>;
/// PS512 (RSA-PSS + SHA-512) verifying key
pub type Ps512VerifyingKey = RsaPssVerifyingKey<Sha512>;

/// RSA-PSS signing key.
///
/// This type wraps an RSA private key for PSS signing operations.
pub struct RsaPssSigningKey<D> {
    key: RsaPrivateKey,
    _digest: PhantomData<D>,
}

impl<D> RsaPssSigningKey<D>
where
    D: OutputSizeUser,
{
    /// Create a signing key from an RSA private key.
    pub fn new(key: RsaPrivateKey) -> Self {
        Self {
            key,
            _digest: PhantomData,
        }
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> RsaPssVerifyingKey<D> {
        RsaPssVerifyingKey {
            key: self.key.to_public_key(),
            _digest: PhantomData,
        }
    }

    /// Return the modulus (JWK `n` parameter).
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the public exponent (JWK `e` parameter).
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the private exponent (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        Secret::from(self.key.d().to_be_bytes().to_vec())
    }

    /// Return the first prime factor (JWK `p` parameter).
    pub fn p(&self) -> Option<Secret> {
        self.key
            .primes()
            .first()
            .map(|p| Secret::from(p.to_be_bytes().to_vec()))
    }

    /// Return the second prime factor (JWK `q` parameter).
    pub fn q(&self) -> Option<Secret> {
        self.key
            .primes()
            .get(1)
            .map(|q| Secret::from(q.to_be_bytes().to_vec()))
    }

    /// Return the first factor CRT exponent (JWK `dp` parameter).
    pub fn dp(&self) -> Option<Secret> {
        self.key
            .dp()
            .map(|dp| Secret::from(dp.to_be_bytes().to_vec()))
    }

    /// Return the second factor CRT exponent (JWK `dq` parameter).
    pub fn dq(&self) -> Option<Secret> {
        self.key
            .dq()
            .map(|dq| Secret::from(dq.to_be_bytes().to_vec()))
    }

    /// Return the first CRT coefficient (JWK `qi` parameter).
    pub fn qi(&self) -> Option<Secret> {
        self.key
            .qinv()
            .map(|qi| Secret::from(qi.retrieve().to_be_bytes().to_vec()))
    }
}

impl<D> SigningKey for RsaPssSigningKey<D>
where
    D: Digest + FixedOutputReset + RsaPssAlgorithm,
{
    type Signer<'a>
        = RsaPssSigner<'a, D>
    where
        Self: 'a;
    type SignError = Error;
    type VerifyingKey = RsaPssVerifyingKey<D>;

    fn alg(&self) -> Signing {
        D::ALG
    }

    fn signer(&self) -> Result<Self::Signer<'_>, Self::SignError> {
        Ok(RsaPssSigner {
            digest: D::new(),
            key: &self.key,
            _digest: PhantomData,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::SignError> {
        let mut signer = self.signer()?;
        signer.update(data).expect("infallible");
        signer.finish()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        RsaPssVerifyingKey {
            key: self.key.to_public_key(),
            _digest: PhantomData,
        }
    }
}

impl<D> VerifyingKey for RsaPssSigningKey<D>
where
    D: Digest + FixedOutputReset,
{
    type Verifier<'a>
        = RsaPssVerifier<D>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaPssVerifier {
            digest: D::new(),
            key: self.key.to_public_key(),
            _digest: PhantomData,
        })
    }

    fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).expect("infallible");
        verifier.finish(signature)
    }
}

/// RSA-PSS verifying key.
///
/// This type wraps an RSA public key for PSS verification operations.
pub struct RsaPssVerifyingKey<D> {
    key: RsaPublicKey,
    _digest: PhantomData<D>,
}

impl<D> RsaPssVerifyingKey<D>
where
    D: OutputSizeUser,
{
    /// Create a verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey) -> Self {
        Self {
            key,
            _digest: PhantomData,
        }
    }

    /// Return the modulus (JWK `n` parameter).
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the public exponent (JWK `e` parameter).
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }
}

impl<D> VerifyingKey for RsaPssVerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    type Verifier<'a>
        = RsaPssVerifier<D>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaPssVerifier {
            digest: D::new(),
            key: self.key.clone(),
            _digest: PhantomData,
        })
    }

    fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).expect("infallible");
        verifier.finish(signature)
    }
}

impl<D> From<RsaPssSigningKey<D>> for RsaPssVerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn from(key: RsaPssSigningKey<D>) -> Self {
        key.verifying_key()
    }
}

impl<D> From<&RsaPssSigningKey<D>> for RsaPssVerifyingKey<D>
where
    D: Digest + FixedOutputReset,
{
    fn from(key: &RsaPssSigningKey<D>) -> Self {
        key.verifying_key()
    }
}

/// RSA-PSS signing state.
pub struct RsaPssSigner<'a, D> {
    digest: D,
    key: &'a RsaPrivateKey,
    _digest: PhantomData<D>,
}

impl<'a, D> Update for RsaPssSigner<'a, D>
where
    D: Digest,
{
    type Error = core::convert::Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Digest::update(&mut self.digest, data.as_ref());
        Ok(())
    }
}

impl<'a, D> Signer for RsaPssSigner<'a, D>
where
    D: Digest + FixedOutputReset,
{
    type SignError = Error;

    fn finish(self) -> Result<Bytes, <Self as Signer>::SignError> {
        let hash = self.digest.finalize().to_vec();

        let key = pss::SigningKey::<D>::from(self.key.clone());
        let sig = key.sign_prehash(&hash).map_err(|_| Error::Sign)?;

        Ok(sig.to_bytes().as_ref().to_vec().into())
    }
}

/// RSA-PSS verification state.
pub struct RsaPssVerifier<D> {
    digest: D,
    key: RsaPublicKey,
    _digest: PhantomData<D>,
}

impl<D> Update for RsaPssVerifier<D>
where
    D: Digest,
{
    type Error = core::convert::Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Digest::update(&mut self.digest, data.as_ref());
        Ok(())
    }
}

impl<D> Verifier for RsaPssVerifier<D>
where
    D: Digest + FixedOutputReset,
{
    type VerifyError = Error;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::VerifyError> {
        let hash = self.digest.finalize().to_vec();
        let sig = signature.as_ref();

        let key = pss::VerifyingKey::<D>::from(self.key);
        let sig = pss::Signature::try_from(sig).map_err(|_| Error::InvalidKey)?;

        key.verify_prehash(&hash, &sig).map_err(|_| Error::Verify)
    }
}

/// Private trait for compile-time RSA-PSS algorithm mapping.
trait RsaPssAlgorithm {
    const ALG: Signing;
}

impl RsaPssAlgorithm for Sha256 {
    const ALG: Signing = Signing::Ps256;
}

impl RsaPssAlgorithm for Sha384 {
    const ALG: Signing = Signing::Ps384;
}

impl RsaPssAlgorithm for Sha512 {
    const ALG: Signing = Signing::Ps512;
}
