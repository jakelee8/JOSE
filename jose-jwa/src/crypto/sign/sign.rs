//! JWS Cryptographic Implementation
//!
//! This module provides concrete implementations of JWS signing and verification
//! algorithms as defined in RFC 7518.

use core::error::Error;

use jose_b64::serde::Bytes;
use jose_b64::stream::Update;

use crate::Signing;

use super::VerifyingKey;

/// A signature creation key.
///
/// This trait is implemented by keys that can create digital signatures.
/// Signing is done via a two-phase process:
/// 1. Call `signer()` to get a `Signer` state object
/// 2. Use `Signer::update()` to feed data (supports streaming)
/// 3. Call `Signer::finish()` to get the signature
///
/// A one-shot `sign()` method is provided for convenience.
pub trait SigningKey: VerifyingKey {
    /// The error type returned when creating a signer.
    type SignError: Error;

    /// The signer state type.
    type Signer<'a>: Signer
    where
        Self: 'a;

    /// The verifying key type.
    type VerifyingKey: VerifyingKey;

    /// Returns the signing algorithm identifier.
    fn alg(&self) -> Signing;

    /// Begin the signature creation process.
    ///
    /// Returns a `Signer` that can be used to incrementally feed data
    /// and then finalize to produce a signature.
    fn signer(&self) -> Result<Self::Signer<'_>, Self::SignError>;

    /// Sign data in one shot.
    ///
    /// This is a convenience method that creates a signer, feeds all data,
    /// and finalizes in one call.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::SignError>;

    /// Get the corresponding verifying key.
    fn verifying_key(&self) -> Self::VerifyingKey;
}

/// Signature creation state.
///
/// This trait represents the state of an in-progress signing operation.
/// Data can be incrementally fed via `update()`, then `finish()` produces
/// the final signature.
pub trait Signer: Update {
    /// The error type returned when finalizing.
    type SignError: Error;

    /// Finish processing payload and create the signature.
    ///
    /// Consumes the signer and returns the signature bytes.
    #[must_use = "the returned signature should be used (e.g., stored or transmitted)"]
    fn finish(self) -> Result<Bytes, Self::SignError>;
}
