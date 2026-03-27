//! ECDSA key types for signing and verification.
//!
//! This module provides concrete key types for ECDSA operations:
//! - [`EcdsaSigningKey`] - for creating signatures
//! - [`EcdsaVerifyingKey`] - for verifying signatures
//!
//! Each key type is parameterized by the curve (P-256, P-384, P-521, secp256k1).

#![cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]

use alloc::vec::Vec;
use core::convert::Infallible;
use core::ops::Add;

use digest::Digest;
use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, SignatureSize};
use ecdsa::{SigningKey as EcdsaSigningKeyCore, VerifyingKey as EcdsaVerifyingKeyCore};
use elliptic_curve::array::ArraySize;
use elliptic_curve::ops::Invert;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, Scalar};
use jose_b64::serde::{Bytes, Secret};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use crate::Signing;
use crate::crypto::{CipherError, Signer, SigningKey, Update, Verifier, VerifyingKey as VerifyingKeyTrait};

/// Trait for deriving the signing algorithm from the curve type at compile time.
pub trait EcdsaCurveAlg {
    /// Returns the [`Signing`] algorithm corresponding to this curve.
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

/// An ECDSA signing key.
pub struct EcdsaSigningKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    key: EcdsaSigningKeyCore<C>,
}

impl<C> EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Create a signing key from raw scalar bytes (JWK `d` parameter).
    pub fn from_bytes(d: impl AsRef<[u8]>) -> Result<Self, CipherError> {
        let key = EcdsaSigningKeyCore::<C>::from_slice(d.as_ref())
            .map_err(|_| CipherError::InvalidKey)?;
        Ok(Self { key })
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        C::alg()
    }

    /// Return the private scalar (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        let bytes = self.key.to_bytes();
        Secret::from(bytes.as_slice().to_vec())
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> EcdsaVerifyingKey<C> {
        EcdsaVerifyingKey {
            key: self.key.verifying_key().clone(),
        }
    }
}

impl<C> SigningKey for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
{
    type Signer<'a>
        = EcdsaSigner<'a, C>
    where
        Self: 'a;
    type Error = CipherError;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(EcdsaSigner {
            digest: C::Digest::new(),
            key: &self.key,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data).map_err(|_| CipherError::Sign)?;
        signer.finish()
    }
}

impl<C> VerifyingKeyTrait for EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = CipherError;

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
        verifier.update(data).map_err(|_| CipherError::Verify)?;
        verifier.finish(signature)
    }
}

/// An ECDSA verifying key.
pub struct EcdsaVerifyingKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    key: EcdsaVerifyingKeyCore<C>,
}

impl<C> EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic + EcdsaCurveAlg,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    /// Create a verifying key from SEC1-encoded point bytes.
    pub fn from_sec1_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, CipherError> {
        let key = EcdsaVerifyingKeyCore::<C>::from_sec1_bytes(bytes.as_ref())
            .map_err(|_| CipherError::InvalidKey)?;
        Ok(Self { key })
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        C::alg()
    }

    /// Return the x-coordinate (JWK `x` parameter).
    pub fn x(&self) -> Bytes {
        let point = self.key.to_sec1_point(false);
        point.x().expect("uncompressed point").as_slice().to_vec().into()
    }

    /// Return the y-coordinate (JWK `y` parameter).
    pub fn y(&self) -> Bytes {
        let point = self.key.to_sec1_point(false);
        point.y().expect("uncompressed point").as_slice().to_vec().into()
    }

    /// Export the public key as SEC1-encoded bytes.
    pub fn to_sec1_bytes(&self, compress: bool) -> Vec<u8> {
        self.key.to_sec1_point(compress).as_bytes().to_vec()
    }
}

impl<C> VerifyingKeyTrait for EcdsaVerifyingKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
    SignatureSize<C>: ArraySize,
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = CipherError;

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
        verifier.update(data).map_err(|_| CipherError::Verify)?;
        verifier.finish(signature)
    }
}

/// ECDSA signing state.
pub struct EcdsaSigner<'a, C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    digest: C::Digest,
    key: &'a EcdsaSigningKeyCore<C>,
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
    type Error = CipherError;

    fn finish(self) -> Result<Bytes, <Self as Signer>::Error> {
        let hash = self.digest.finalize();
        let sig: Signature<C> = self
            .key
            .sign_prehash(hash.as_ref())
            .map_err(|_| CipherError::Sign)?;
        Ok(sig.to_bytes().as_slice().to_vec().into())
    }
}

/// ECDSA verification state.
pub struct EcdsaVerifier<'a, C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    digest: C::Digest,
    key: &'a EcdsaVerifyingKeyCore<C>,
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
    type Error = CipherError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error> {
        let hash = self.digest.finalize();
        let sig = Signature::<C>::from_slice(signature.as_ref())
            .map_err(|_| CipherError::InvalidKey)?;
        self.key
            .verify_prehash(hash.as_ref(), &sig)
            .map_err(|_| CipherError::Verify)
    }
}

// Type aliases for common curves
#[cfg(feature = "p256")]
pub type Es256SigningKey = EcdsaSigningKey<p256::NistP256>;
#[cfg(feature = "p256")]
pub type Es256VerifyingKey = EcdsaVerifyingKey<p256::NistP256>;

#[cfg(feature = "p384")]
pub type Es384SigningKey = EcdsaSigningKey<p384::NistP384>;
#[cfg(feature = "p384")]
pub type Es384VerifyingKey = EcdsaVerifyingKey<p384::NistP384>;

#[cfg(feature = "p521")]
pub type Es512SigningKey = EcdsaSigningKey<p521::NistP521>;
#[cfg(feature = "p521")]
pub type Es512VerifyingKey = EcdsaVerifyingKey<p521::NistP521>;

#[cfg(feature = "k256")]
pub type Es256KSigningKey = EcdsaSigningKey<k256::Secp256k1>;
#[cfg(feature = "k256")]
pub type Es256KVerifyingKey = EcdsaVerifyingKey<k256::Secp256k1>;
