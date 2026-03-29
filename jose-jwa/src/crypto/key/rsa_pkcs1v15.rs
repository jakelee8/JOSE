//! RSA-PKCS#1 v1.5 signing implementations

use core::marker::PhantomData;

use digest::{Digest, OutputSizeUser};
use jose_b64::serde::{Bytes, Secret};
use jose_b64::stream::Update;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::{Signer, SigningKey, Verifier, VerifyingKey};
use crate::{Error, Signing};

/// RS256 (RSA-PKCS#1 v1.5 + SHA-256) signing key
pub type Rs256SigningKey = RsaPkcs1v15SigningKey<Sha256>;
/// RS384 (RSA-PKCS#1 v1.5 + SHA-384) signing key
pub type Rs384SigningKey = RsaPkcs1v15SigningKey<Sha384>;
/// RS512 (RSA-PKCS#1 v1.5 + SHA-512) signing key
pub type Rs512SigningKey = RsaPkcs1v15SigningKey<Sha512>;

/// RS256 (RSA-PKCS#1 v1.5 + SHA-256) verifying key
pub type Rs256VerifyingKey = RsaPkcs1v15VerifyingKey<Sha256>;
/// RS384 (RSA-PKCS#1 v1.5 + SHA-384) verifying key
pub type Rs384VerifyingKey = RsaPkcs1v15VerifyingKey<Sha384>;
/// RS512 (RSA-PKCS#1 v1.5 + SHA-512) verifying key
pub type Rs512VerifyingKey = RsaPkcs1v15VerifyingKey<Sha512>;

/// RSA-PKCS#1 v1.5 signing key.
///
/// This type wraps an RSA private key for PKCS#1 v1.5 signing operations.
pub struct RsaPkcs1v15SigningKey<D> {
    key: RsaPrivateKey,
    _digest: PhantomData<D>,
}

impl<D> RsaPkcs1v15SigningKey<D>
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

impl<D> SigningKey for RsaPkcs1v15SigningKey<D>
where
    D: Digest + digest::const_oid::AssociatedOid + RsaPkcs1v15Algorithm,
{
    type Signer<'a>
        = RsaPkcs1v15Signer<'a, D>
    where
        Self: 'a;
    type SignError = Error;
    type VerifyingKey = RsaPkcs1v15VerifyingKey<D>;

    fn alg(&self) -> Signing {
        D::ALG
    }

    fn signer(&self) -> Result<Self::Signer<'_>, Self::SignError> {
        Ok(RsaPkcs1v15Signer {
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
        RsaPkcs1v15VerifyingKey {
            key: self.key.to_public_key(),
            _digest: PhantomData,
        }
    }
}

impl<D> VerifyingKey for RsaPkcs1v15SigningKey<D>
where
    D: Digest + digest::const_oid::AssociatedOid,
{
    type Verifier<'a>
        = RsaPkcs1v15Verifier<D>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaPkcs1v15Verifier {
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

/// RSA-PKCS#1 v1.5 verifying key.
///
/// This type wraps an RSA public key for PKCS#1 v1.5 verification operations.
pub struct RsaPkcs1v15VerifyingKey<D> {
    key: RsaPublicKey,
    _digest: PhantomData<D>,
}

impl<D> RsaPkcs1v15VerifyingKey<D>
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

impl<D> VerifyingKey for RsaPkcs1v15VerifyingKey<D>
where
    D: Digest + digest::const_oid::AssociatedOid,
{
    type Verifier<'a>
        = RsaPkcs1v15Verifier<D>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaPkcs1v15Verifier {
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
        verifier.update(data).map_err(|_| Error::Verify)?;
        verifier.finish(signature)
    }
}

impl<D> From<RsaPkcs1v15SigningKey<D>> for RsaPkcs1v15VerifyingKey<D> {
    /// Get the corresponding verifying key.
    fn from(key: RsaPkcs1v15SigningKey<D>) -> RsaPkcs1v15VerifyingKey<D> {
        RsaPkcs1v15VerifyingKey {
            key: key.key.to_public_key(),
            _digest: PhantomData,
        }
    }
}

/// RSA-PKCS#1 v1.5 signing state.
pub struct RsaPkcs1v15Signer<'a, D> {
    digest: D,
    key: &'a RsaPrivateKey,
    _digest: PhantomData<D>,
}

impl<'a, D> Update for RsaPkcs1v15Signer<'a, D>
where
    D: Digest,
{
    type Error = core::convert::Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Digest::update(&mut self.digest, data.as_ref());
        Ok(())
    }
}

impl<'a, D> Signer for RsaPkcs1v15Signer<'a, D>
where
    D: Digest + digest::const_oid::AssociatedOid,
{
    type SignError = Error;

    fn finish(self) -> Result<Bytes, <Self as Signer>::SignError> {
        let hash = self.digest.finalize().to_vec();

        let key = pkcs1v15::SigningKey::<D>::from(self.key.clone());
        let sig = key.sign_prehash(&hash).map_err(|_| Error::Sign)?;

        Ok(sig.to_bytes().as_ref().to_vec().into())
    }
}

/// RSA-PKCS#1 v1.5 verification state.
pub struct RsaPkcs1v15Verifier<D> {
    digest: D,
    key: RsaPublicKey,
    _digest: PhantomData<D>,
}

impl<D> Update for RsaPkcs1v15Verifier<D>
where
    D: Digest,
{
    type Error = core::convert::Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Digest::update(&mut self.digest, data.as_ref());
        Ok(())
    }
}

impl<D> Verifier for RsaPkcs1v15Verifier<D>
where
    D: Digest + digest::const_oid::AssociatedOid,
{
    type VerifyError = Error;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::VerifyError> {
        let hash = self.digest.finalize().to_vec();
        let sig = signature.as_ref();

        let key = pkcs1v15::VerifyingKey::<D>::from(self.key);
        let sig = pkcs1v15::Signature::try_from(sig).map_err(|_| Error::InvalidKey)?;

        key.verify_prehash(&hash, &sig).map_err(|_| Error::Verify)
    }
}

/// Private trait for compile-time RSA-PKCS#1 v1.5 algorithm mapping.
trait RsaPkcs1v15Algorithm {
    const ALG: Signing;
}

impl RsaPkcs1v15Algorithm for Sha256 {
    const ALG: Signing = Signing::Rs256;
}

impl RsaPkcs1v15Algorithm for Sha384 {
    const ALG: Signing = Signing::Rs384;
}

impl RsaPkcs1v15Algorithm for Sha512 {
    const ALG: Signing = Signing::Rs512;
}
