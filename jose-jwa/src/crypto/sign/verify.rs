//! JWS Cryptographic Implementation - Verification
//!
//! This module provides verification-specific implementations.
//! The main traits are re-exported from `sign` for consistency.

#![cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]

use core::error::Error;

use jose_b64::stream::Update;

/// A signature verification key.
///
/// This trait is implemented by keys that can verify digital signatures.
/// Verification is done via a two-phase process:
/// 1. Call `verifier()` to get a `Verifier` state object
/// 2. Use `Verifier::update()` to feed data (supports streaming)
/// 3. Call `Verifier::finish()` with the signature to verify
///
/// A one-shot `verify()` method is provided for convenience.
pub trait VerifyingKey {
    /// The error type returned when creating a verifier.
    type Error: Error;

    /// The verifier state type.
    type Verifier<'a>: Verifier
    where
        Self: 'a;

    /// Begin the signature verification process.
    ///
    /// Returns a `Verifier` that can be used to incrementally feed data
    /// and then finalize to verify a signature.
    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error>;

    /// Verify a signature in one shot.
    ///
    /// This is a convenience method that creates a verifier, feeds all data,
    /// and verifies the signature in one call.
    ///
    /// # Arguments
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    fn verify(
        &self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error>;
}

/// Signature verification state.
///
/// This trait represents the state of an in-progress verification operation.
/// Data can be incrementally fed via `update()`, then `finish()` verifies
/// the signature against the accumulated data.
pub trait Verifier: Update {
    /// The error type returned when finalizing.
    type VerifyError: Error;

    /// Finish processing payload and verify the signature.
    ///
    /// Consumes the verifier and returns `Ok(())` if the signature is valid,
    /// or an error if verification fails.
    #[must_use = "the result of verification should be checked to determine if the signature is valid"]
    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), Self::VerifyError>;
}
