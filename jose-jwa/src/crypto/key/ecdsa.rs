//! ECDSA key types for signing and verification.
//!
//! This module provides concrete key types for ECDSA operations:
//! - [`EcdsaSigningKey`] - for creating signatures
//! - [`EcdsaVerifyingKey`] - for verifying signatures
//!
//! Each key type is parameterized by the curve (P-256, P-384, P-521, secp256k1).

#![cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]

use core::convert::Infallible;

use alloc::borrow::ToOwned;
use digest::Digest;
use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ecdsa::{EcdsaCurve, Signature, SignatureSize};
use elliptic_curve::array::ArraySize;
use elliptic_curve::ops::Invert;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Scalar};
use jose_b64::serde::{Bytes, Secret};
use jose_b64::stream::Update;

use crate::Signing;
use crate::Error;
use crate::crypto::{Signer, SigningKey, Verifier, VerifyingKey};

/// ES256 (ECDSA + P-256 + SHA-256) signing key.
#[cfg(feature = "p256")]
pub type Es256SigningKey = EcdsaSigningKey<p256::NistP256>;
/// ES256 (ECDSA + P-256 + SHA-256) verifying key.
#[cfg(feature = "p256")]
pub type Es256VerifyingKey = EcdsaVerifyingKey<p256::NistP256>;

/// ES384 (ECDSA + P-384 + SHA-384) signing key.
#[cfg(feature = "p384")]
pub type Es384SigningKey = EcdsaSigningKey<p384::NistP384>;
/// ES384 (ECDSA + P-384 + SHA-384) verifying key.
#[cfg(feature = "p384")]
pub type Es384VerifyingKey = EcdsaVerifyingKey<p384::NistP384>;

/// ES512 (ECDSA + P-521 + SHA-512) signing key.
#[cfg(feature = "p521")]
pub type Es512SigningKey = EcdsaSigningKey<p521::NistP521>;
/// ES512 (ECDSA + P-521 + SHA-512) verifying key.
#[cfg(feature = "p521")]
pub type Es512VerifyingKey = EcdsaVerifyingKey<p521::NistP521>;

/// ES256K (ECDSA + secp256k1 + SHA-256) signing key.
#[cfg(feature = "k256")]
pub type Es256KSigningKey = EcdsaSigningKey<k256::Secp256k1>;
/// ES256K (ECDSA + secp256k1 + SHA-256) verifying key.
#[cfg(feature = "k256")]
pub type Es256KVerifyingKey = EcdsaVerifyingKey<k256::Secp256k1>;

/// Trait for deriving the signing algorithm from the curve type at compile time.
pub trait EcdsaCurveAlg {
    /// Returns the signing algorithm corresponding to this curve.
    fn alg() -> Signing;
}

#[cfg(feature = "p256")]
impl EcdsaCurveAlg for p256::NistP256 {
    fn alg() -> Signing {
        Signing::Es256
    }
}

#[cfg(feature = "p384")]
impl EcdsaCurveAlg for p384::NistP384 {
    fn alg() -> Signing {
        Signing::Es384
    }
}

#[cfg(feature = "p521")]
impl EcdsaCurveAlg for p521::NistP521 {
    fn alg() -> Signing {
        Signing::Es512
    }
}

#[cfg(feature = "k256")]
impl EcdsaCurveAlg for k256::Secp256k1 {
    fn alg() -> Signing {
        Signing::Es256K
    }
}

/// An ECDSA signing key for creating digital signatures.
///
/// This type wraps an ECDSA signing key and implements the [`SigningKey`] trait.
/// It supports multiple curves including P-256, P-384, P-521, and secp256k1.
pub struct EcdsaSigningKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    key: ecdsa::SigningKey<C>,
}

impl<C> EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Create a signing key from raw scalar bytes (JWK `d` parameter).
    pub fn from_bytes(d: impl AsRef<[u8]>) -> Result<Self, Error> {
        let key = ecdsa::SigningKey::<C>::from_slice(d.as_ref()).map_err(|_| Error::InvalidKey)?;
        Ok(Self { key })
    }

    /// Return the private scalar (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        self.key.to_bytes().to_vec().into()
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> EcdsaVerifyingKey<C> {
        EcdsaVerifyingKey {
            key: *self.key.verifying_key(),
        }
    }
}

impl<C> SigningKey for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    type Signer<'a>
        = EcdsaSigner<'a, C>
    where
        Self: 'a;
    type SignError = Error;
    type VerifyingKey = EcdsaVerifyingKey<C>;

    fn alg(&self) -> Signing {
        C::alg()
    }

    fn signer(&self) -> Result<Self::Signer<'_>, Self::SignError> {
        Ok(EcdsaSigner {
            digest: C::Digest::new(),
            key: &self.key,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::SignError> {
        let mut signer = self.signer()?;
        signer.update(data).expect("infallible");
        signer.finish()
    }

    fn verifying_key(&self) -> Self::VerifyingKey {
        EcdsaVerifyingKey {
            key: *self.key.verifying_key(),
        }
    }
}

impl<C> VerifyingKey for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(EcdsaVerifier {
            digest: C::Digest::new(),
            key: self.key.verifying_key(),
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

impl<C> AsRef<ecdsa::SigningKey<C>> for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    fn as_ref(&self) -> &ecdsa::SigningKey<C> {
        &self.key
    }
}

impl<C> From<ecdsa::SigningKey<C>> for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    fn from(key: ecdsa::SigningKey<C>) -> Self {
        Self { key }
    }
}

impl<C> From<&ecdsa::SigningKey<C>> for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    fn from(key: &ecdsa::SigningKey<C>) -> Self {
        Self {
            key: key.to_owned(),
        }
    }
}

impl<C> From<EcdsaSigningKey<C>> for EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(key: EcdsaSigningKey<C>) -> Self {
        key.verifying_key()
    }
}

impl<C> From<&EcdsaSigningKey<C>> for EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    fn from(key: &EcdsaSigningKey<C>) -> Self {
        key.verifying_key()
    }
}

impl<C> From<EcdsaSigningKey<C>> for ecdsa::SigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    fn from(key: EcdsaSigningKey<C>) -> Self {
        key.key
    }
}

/// An ECDSA verifying key for verifying digital signatures.
///
/// This type wraps an ECDSA verifying key and implements the [`VerifyingKey`] trait.
/// It supports multiple curves including P-256, P-384, P-521, and secp256k1.
pub struct EcdsaVerifyingKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    key: ecdsa::VerifyingKey<C>,
}

impl<C> EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Create a verifying key from SEC1-encoded point bytes.
    pub fn from_sec1_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let key = ecdsa::VerifyingKey::<C>::from_sec1_bytes(bytes.as_ref())
            .map_err(|_| Error::InvalidKey)?;
        Ok(Self { key })
    }

    /// Return the x-coordinate (JWK `x` parameter).
    pub fn x(&self) -> Bytes {
        let point = self.key.to_sec1_point(false);
        point
            .x()
            .unwrap_or_else(|| unreachable!("uncompressed SEC1 point always has x"))
            .as_slice()
            .to_vec()
            .into()
    }

    /// Return the y-coordinate (JWK `y` parameter).
    pub fn y(&self) -> Bytes {
        let point = self.key.to_sec1_point(false);
        point
            .y()
            .unwrap_or_else(|| unreachable!("uncompressed SEC1 point always has y"))
            .as_slice()
            .to_vec()
            .into()
    }
}

impl<C> VerifyingKey for EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = Error;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(EcdsaVerifier {
            digest: C::Digest::new(),
            key: &self.key,
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

/// ECDSA signing state for incremental signature creation.
///
/// This struct maintains the hash state during the signing process.
/// Data is fed incrementally via the [`Update`] trait, and the signature
/// is produced by calling [`Signer::finish`].
pub struct EcdsaSigner<'a, C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    digest: C::Digest,
    key: &'a ecdsa::SigningKey<C>,
}

impl<C> Update for EcdsaSigner<'_, C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(data.as_ref());
        Ok(())
    }
}

impl<C> Signer for EcdsaSigner<'_, C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
{
    type SignError = Error;

    fn finish(self) -> Result<Bytes, <Self as Signer>::SignError> {
        let hash = self.digest.finalize();
        let sig: Signature<C> = self
            .key
            .sign_prehash(hash.as_ref())
            .map_err(|_| Error::Sign)?;
        Ok(sig.to_bytes().as_slice().to_vec().into())
    }
}

/// ECDSA verification state for incremental signature verification.
///
/// This struct maintains the hash state during the verification process.
/// Data is fed incrementally via the [`Update`] trait, and the signature
/// is verified by calling [`Verifier::finish`].
pub struct EcdsaVerifier<'a, C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    digest: C::Digest,
    key: &'a ecdsa::VerifyingKey<C>,
}

impl<C> Update for EcdsaVerifier<'_, C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(data.as_ref());
        Ok(())
    }
}

impl<C> Verifier for EcdsaVerifier<'_, C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    type VerifyError = Error;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::VerifyError> {
        let hash = self.digest.finalize();
        let sig = Signature::<C>::from_slice(signature.as_ref()).map_err(|_| Error::InvalidKey)?;
        self.key
            .verify_prehash(hash.as_ref(), &sig)
            .map_err(|_| Error::Verify)
    }
}
