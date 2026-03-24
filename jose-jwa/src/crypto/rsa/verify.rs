//! RSA verification implementations

use core::convert::Infallible;

use digest::FixedOutputReset;
use rsa::{pkcs1v15, pss};
use sha2::{Sha256, Sha384, Sha512, digest::Digest};

use crate::crypto::digest::KeyRefDigestState;

type VerifierRs<'a, D> = KeyRefDigestState<'a, pkcs1v15::VerifyingKey<D>, D, pkcs1v15::Signature>;
type VerifierPs<'a, D> = KeyRefDigestState<'a, pss::VerifyingKey<D>, D, pss::Signature>;

/// RS256 (RSA-PKCS1-v1_5 + SHA-256) verifier
pub type Rs256Verifier<'a> = VerifierRs<'a, Sha256>;
/// RS384 (RSA-PKCS1-v1_5 + SHA-384) verifier
pub type Rs384Verifier<'a> = VerifierRs<'a, Sha384>;
/// RS512 (RSA-PKCS1-v1_5 + SHA-512) verifier
pub type Rs512Verifier<'a> = VerifierRs<'a, Sha512>;

/// PS256 (RSA-PSS + SHA-256) verifier
pub type Ps256Verifier<'a> = VerifierPs<'a, Sha256>;
/// PS384 (RSA-PSS + SHA-384) verifier
pub type Ps384Verifier<'a> = VerifierPs<'a, Sha384>;
/// PS512 (RSA-PSS + SHA-512) verifier
pub type Ps512Verifier<'a> = VerifierPs<'a, Sha512>;

impl<'a, D> crate::VerifyingKey<'a> for pkcs1v15::VerifyingKey<D>
where
    D: 'a + Digest,
{
    type StartError = Infallible;
    type Verifier = VerifierRs<'a, D>;

    fn verify(&'a self) -> Result<Self::Verifier, Self::StartError> {
        Ok(self.into())
    }
}

impl<'a, D> crate::VerifyingKey<'a> for pss::VerifyingKey<D>
where
    D: 'a + Digest + FixedOutputReset,
{
    type StartError = Infallible;
    type Verifier = VerifierPs<'a, D>;

    fn verify(&'a self) -> Result<Self::Verifier, Self::StartError> {
        Ok(self.into())
    }
}
