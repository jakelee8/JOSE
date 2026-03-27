//! JWS Cryptographic Implementation
//!
//! This module provides concrete implementations of JWS signing and verification
//! algorithms as defined in RFC 7518.

#![cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]

use core::error::Error;
use jose_b64::serde::Bytes;

// Re-export Update so implementors can use it
pub use jose_b64::stream::Update;
pub use signature::rand_core::TryCryptoRng;

/// A signature creation key.
///
/// This trait is implemented by keys that can create digital signatures.
/// Signing is done via a two-phase process:
/// 1. Call `signer()` to get a `Signer` state object
/// 2. Use `Signer::update()` to feed data (supports streaming)
/// 3. Call `Signer::finish()` to get the signature
///
/// A one-shot `sign()` method is provided for convenience.
pub trait SigningKey {
    /// The error type returned when creating a signer.
    type Error: Error;

    /// The signer state type.
    type Signer<'a>: Signer
    where
        Self: 'a;

    /// Begin the signature creation process.
    ///
    /// Returns a `Signer` that can be used to incrementally feed data
    /// and then finalize to produce a signature.
    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error>;

    /// Sign data in one shot.
    ///
    /// This is a convenience method that creates a signer, feeds all data,
    /// and finalizes in one call.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    /// * `rng` - A cryptographically secure random number generator
    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::Error>;
}

/// Signature creation state.
///
/// This trait represents the state of an in-progress signing operation.
/// Data can be incrementally fed via `update()`, then `finish()` produces
/// the final signature.
pub trait Signer: Update {
    /// The error type returned when finalizing.
    type Error: Error;

    /// Finish processing payload and create the signature.
    ///
    /// Consumes the signer and returns the signature bytes.
    fn finish(self) -> Result<Bytes, <Self as Signer>::Error>;
}
