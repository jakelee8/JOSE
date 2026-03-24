//! HMAC signing implementations

use alloc::vec::Vec;
use core::convert::Infallible;

use hmac::{EagerHash, Hmac, Mac};
use jose_b64::stream::Update;

use crate::crypto::sign::{Signer, SigningKey};
use crate::{Verifier, VerifyingKey};

/// HS256 (HMAC + SHA-256) signer
pub type Hs256Signer = HmacState<sha2::Sha256>;
/// HS384 (HMAC + SHA-384) signer
pub type Hs384Signer = HmacState<sha2::Sha384>;
/// HS512 (HMAC + SHA-512) signer
pub type Hs512Signer = HmacState<sha2::Sha512>;

/// HS256 (HMAC + SHA-256) verifier
pub type Hs256Verify = HmacState<sha2::Sha256>;
/// HS384 (HMAC + SHA-384) verifier
pub type Hs384Verify = HmacState<sha2::Sha384>;
/// HS512 (HMAC + SHA-512) verifier
pub type Hs512Verify = HmacState<sha2::Sha512>;

/// HMAC signer state
pub struct HmacState<D>
where
    D: EagerHash,
{
    hmac: Hmac<D>,
}

impl<D> HmacState<D>
where
    D: EagerHash + Clone,
{
    /// Create a new HMAC signer state with the given HMAC instance.
    pub fn new(hmac: Hmac<D>) -> Self {
        Self { hmac }
    }
}

impl<D> Update for HmacState<D>
where
    D: EagerHash + Clone,
{
    type Error = Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.hmac.update(chunk.as_ref());
        Ok(())
    }
}

impl<D> SigningKey<'_> for Hmac<D>
where
    D: EagerHash + Clone,
{
    type StartError = Infallible;
    type Signer = HmacState<D>;

    fn sign(&self) -> Result<Self::Signer, Self::StartError> {
        Ok(HmacState::new(self.clone()))
    }
}

impl<D> Signer for HmacState<D>
where
    D: EagerHash + Clone,
{
    type FinishError = Infallible;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        Ok(self.hmac.finalize().into_bytes().to_vec())
    }
}

impl<'a, D> VerifyingKey<'a> for Hmac<D>
where
    D: EagerHash + Clone,
{
    type StartError = Infallible;
    type Verifier = HmacState<D>;

    fn verify(&'a self) -> Result<Self::Verifier, Self::StartError> {
        Ok(HmacState::new(self.clone()))
    }
}

impl<'a, D> Verifier<'a> for HmacState<D>
where
    D: EagerHash + Clone,
{
    type FinishError = HmacVerifyError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), Self::FinishError> {
        if self.hmac.finalize().into_bytes().as_slice() == signature.as_ref() {
            Ok(())
        } else {
            Err(HmacVerifyError)
        }
    }
}

/// HMAC verification error
#[derive(Debug, Clone, Copy)]
pub struct HmacVerifyError;

impl core::fmt::Display for HmacVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HMAC verify error")
    }
}

impl core::error::Error for HmacVerifyError {}
