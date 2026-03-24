//! RSA signing implementations

use core::convert::Infallible;

use digest::{Digest, FixedOutputReset};
use rsa::{pkcs1v15, pss};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::digest::KeyRefDigestState;

type SignerRs<'a, D> = KeyRefDigestState<'a, pkcs1v15::SigningKey<D>, D, pkcs1v15::Signature>;
type SignerPs<'a, D> = KeyRefDigestState<'a, pss::SigningKey<D>, D, pss::Signature>;

/// RS256 (RSA-PKCS1-v1_5 + SHA-256) signer
pub type Rs256Signer<'a> = SignerRs<'a, Sha256>;
/// RS384 (RSA-PKCS1-v1_5 + SHA-384) signer
pub type Rs384Signer<'a> = SignerRs<'a, Sha384>;
/// RS512 (RSA-PKCS1-v1_5 + SHA-512) signer
pub type Rs512Signer<'a> = SignerRs<'a, Sha512>;

/// PS256 (RSA-PSS + SHA-256) signer
pub type Ps256Signer<'a> = SignerPs<'a, Sha256>;
/// PS384 (RSA-PSS + SHA-384) signer
pub type Ps384Signer<'a> = SignerPs<'a, Sha384>;
/// PS512 (RSA-PSS + SHA-512) signer
pub type Ps512Signer<'a> = SignerPs<'a, Sha512>;

impl<'a, D> crate::SigningKey<'a> for pkcs1v15::SigningKey<D>
where
    D: 'a + Digest,
{
    type StartError = Infallible;
    type Signer = SignerRs<'a, D>;

    fn sign(&'a self) -> Result<Self::Signer, Self::StartError> {
        Ok(self.into())
    }
}

impl<'a, D> crate::SigningKey<'a> for pss::SigningKey<D>
where
    D: 'a + Digest + FixedOutputReset,
{
    type StartError = Infallible;
    type Signer = SignerPs<'a, D>;

    fn sign(&'a self) -> Result<Self::Signer, Self::StartError> {
        Ok(self.into())
    }
}
