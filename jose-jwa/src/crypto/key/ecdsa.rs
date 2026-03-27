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
use core::marker::PhantomData;

use digest::Digest;
use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, SignatureEncoding};
use elliptic_curve::{CurveArithmetic, NonZeroScalar};
use jose_b64::serde::Secret;
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::rand_core::TryCryptoRng;

use crate::Signing;
use crate::crypto::{Signer, SigningKey, Update, Verifier, VerifyingKey as VerifyingKeyTrait};

/// An ECDSA signing key.
///
/// This type wraps a RustCrypto ECDSA signing key and implements
/// the [`SigningKey`] trait for streaming sign operations.
pub struct EcdsaSigningKey<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> {
    key: ecdsa::SigningKey<C>,
    alg: Signing,
    _marker: PhantomData<C>,
}

impl<C> EcdsaSigningKey<C>
where
    C: EcdsaCurve + DigestAlgorithm + CurveArithmetic,
{
    /// Create a signing key from raw scalar bytes.
    ///
    /// # Arguments
    /// * `d` - The private key scalar as big-endian bytes
    /// * `alg` - The signing algorithm (ES256, ES384, ES512, or ES256K)
    pub fn from_bytes(d: impl AsRef<[u8]>, alg: Signing) -> Result<Self, EcdsaError> {
        let scalar = NonZeroScalar::<C>::from_be_bytes(
            d.as_ref().try_into().map_err(|_| EcdsaError::InvalidKey)?,
        )
        .map_err(|_| EcdsaError::InvalidKey)?;

        let key = edcsa::SigningKey::from(scalar);
        Ok(Self {
            key,
            alg,
            _marker: PhantomData,
        })
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        self.alg
    }

    /// Export the private key as raw scalar bytes.
    pub fn to_bytes(&self) -> Secret {
        Secret::from(self.key.to_bytes().to_vec())
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> EcdsaVerifyingKey<C> {
        EcdsaVerifyingKey {
            key: self.key.verifying_key().clone(),
            _marker: PhantomData,
        }
    }

    /// Export the public key coordinates (x, y).
    ///
    /// Returns the uncompressed SEC1 point coordinates.
    pub fn to_public_coords(&self) -> (Vec<u8>, Vec<u8>) {
        use elliptic_curve::sec1::ToSec1Point;
        let point = self.key.verifying_key().to_sec1_point(false);
        let x = point.x().expect("unreachable").to_vec();
        let y = point.y().expect("unreachable").to_vec();
        (x, y)
    }

    /// Export the private key scalar (d).
    pub fn to_private_scalar(&self) -> Secret {
        self.to_bytes()
    }
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> SigningKey
    for EcdsaSigningKey<C>
{
    type Signer<'a>
        = EcdsaSigner<'a, C>
    where
        Self: 'a;
    type Error = EcdsaError;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(EcdsaSigner {
            digest: C::Digest::new(),
            key: &self.key,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<jose_b64::serde::Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data).map_err(|_| EcdsaError::SigningFailed)?;
        signer.finish()
    }
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> VerifyingKeyTrait
    for EcdsaSigningKey<C>
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = EcdsaError;

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
        verifier
            .update(data)
            .map_err(|_| EcdsaError::VerificationFailed)?;
        verifier.finish(signature)
    }
}

/// An ECDSA verifying key.
///
/// This type wraps a RustCrypto ECDSA verifying key and implements
/// the [`VerifyingKey`] trait for streaming verify operations.
pub struct EcdsaVerifyingKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    key: edcsa::VerifyingKey<C>,
    _marker: PhantomData<C>,
}

impl<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> EcdsaVerifyingKey<C> {
    /// Create a verifying key from SEC1-encoded point bytes.
    ///
    /// # Arguments
    /// * `bytes` - The SEC1-encoded public key point
    pub fn from_sec1_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, EcdsaError> {
        let key = edcsa::VerifyingKey::from_sec1_bytes(bytes.as_ref())
            .map_err(|_| EcdsaError::InvalidKey)?;
        Ok(Self {
            key,
            _marker: PhantomData,
        })
    }

    /// Export the public key as SEC1-encoded bytes.
    pub fn to_sec1_bytes(&self, compress: bool) -> Vec<u8> {
        self.key.to_encoded_point(compress).as_bytes().to_vec()
    }

    /// Export the public key coordinates (x, y).
    ///
    /// Returns the uncompressed SEC1 point coordinates.
    pub fn to_coords(&self) -> (Vec<u8>, Vec<u8>) {
        use elliptic_curve::sec1::ToSec1Point;
        let point = self.key.to_sec1_point(false);
        let x = point.x().expect("unreachable").to_vec();
        let y = point.y().expect("unreachable").to_vec();
        (x, y)
    }
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> VerifyingKeyTrait
    for EcdsaVerifyingKey<C>
{
    type Verifier<'a>
        = EcdsaVerifier<'a, C>
    where
        Self: 'a;
    type Error = EcdsaError;

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
        verifier
            .update(data)
            .map_err(|_| EcdsaError::VerificationFailed)?;
        verifier.finish(signature)
    }
}

/// ECDSA signing state.
///
/// Accumulates data into a digest, then signs the final hash.
pub struct EcdsaSigner<'a, C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> {
    digest: C::Digest,
    key: &'a edcsa::SigningKey<C>,
}

impl<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic> Update for EcdsaSigner<'_, C> {
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(data.as_ref());
        Ok(())
    }
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> Signer
    for EcdsaSigner<'_, C>
{
    type Error = EcdsaError;

    fn finish(self) -> Result<jose_b64::serde::Bytes, <Self as Signer>::Error> {
        let hash = self.digest.finalize();
        let sig: Signature<C> = self
            .key
            .sign_prehash(&hash)
            .map_err(|_| EcdsaError::SigningFailed)?;
        Ok(sig.to_der().as_bytes().to_vec().into())
    }
}

/// ECDSA verification state.
///
/// Accumulates data into a digest, then verifies against the signature.
pub struct EcdsaVerifier<'a, C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> {
    digest: C::Digest,
    key: &'a edcsa::VerifyingKey<C>,
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> Update
    for EcdsaVerifier<'_, C>
{
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(data.as_ref());
        Ok(())
    }
}

impl<C: EcdsaCurve + DigestAlgorithm + elliptic_curve::CurveArithmetic> Verifier
    for EcdsaVerifier<'_, C>
{
    type Error = EcdsaError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error> {
        let hash = self.digest.finalize();
        let sig = Signature::<C>::from_der(signature.as_ref())
            .map_err(|_| EcdsaError::InvalidSignature)?;
        self.key
            .verify_prehash(&hash, &sig)
            .map_err(|_| EcdsaError::VerificationFailed)
    }
}

/// ECDSA-specific errors.
#[derive(Debug)]
pub enum EcdsaError {
    /// Invalid key format or length.
    InvalidKey,
    /// Invalid signature format.
    InvalidSignature,
    /// Signing operation failed.
    SigningFailed,
    /// Verification failed (signature invalid).
    VerificationFailed,
}

impl core::fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("invalid ECDSA key"),
            Self::InvalidSignature => f.write_str("invalid ECDSA signature format"),
            Self::SigningFailed => f.write_str("ECDSA signing failed"),
            Self::VerificationFailed => f.write_str("ECDSA verification failed"),
        }
    }
}

impl core::error::Error for EcdsaError {}

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
