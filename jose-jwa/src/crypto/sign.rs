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

use alloc::vec::Vec;
use core::error::Error;

use jose_b64::stream::Update;

/// A signature creation key
pub trait SigningKey<'a> {
    #[allow(missing_docs)]
    type StartError: Error;

    /// The state object used during signing.
    type Signer: Signer;

    /// Begin the signature creation process.
    fn sign(&'a self) -> Result<Self::Signer, Self::StartError>;
}

/// Signature creation state
pub trait Signer: Update {
    #[allow(missing_docs)]
    type FinishError: Error;

    /// Finish processing payload and create the signature.
    fn finish(self) -> Result<Vec<u8>, Self::FinishError>;
}
