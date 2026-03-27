//! RSA verification implementations

use core::convert::Infallible;

use digest::{Digest, FixedOutputReset};
use rsa::{pkcs1v15, pss};
use sha2::{Sha256, Sha384, Sha512};

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

impl<D> crate::crypto::VerifyingKey for pkcs1v15::VerifyingKey<D>
where
    D: Digest,
    for<'a> VerifierRs<'a, D>: From<&'a pkcs1v15::VerifyingKey<D>>,
{
    type Verifier<'a> = VerifierRs<'a, D> where Self: 'a;
    type Error = Infallible;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(self.into())
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data)?;
        verifier.finish(signature)
    }
}

impl<D> crate::crypto::VerifyingKey for pss::VerifyingKey<D>
where
    D: Digest + FixedOutputReset,
    for<'a> VerifierPs<'a, D>: From<&'a pss::VerifyingKey<D>>,
{
    type Verifier<'a> = VerifierPs<'a, D> where Self: 'a;
    type Error = Infallible;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(self.into())
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data)?;
        verifier.finish(signature)
    }
}
