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
use jose_b64::stream::Update;

/// A signature verification key
pub trait VerifyingKey<'a> {
    #[allow(missing_docs)]
    type StartError: Error;

    /// The state object used during verification.
    type Verifier: Verifier<'a>;

    /// Begin the signature verification process.
    fn verify(&'a self) -> Result<Self::Verifier, Self::StartError>;
}

/// Signature verification state
pub trait Verifier<'a>: Update {
    #[allow(missing_docs)]
    type FinishError: Error;

    /// Finish processing payload and verify the signature.
    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), Self::FinishError>;
}
