//! RSA signing implementations

use core::convert::Infallible;

use digest::{Digest, FixedOutputReset};
use rsa::{pkcs1v15, pss};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::digest::KeyRefDigestState;
use crate::crypto::sign::SigningKey;

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

impl<D> SigningKey for pkcs1v15::SigningKey<D>
where
    D: Digest,
    for<'a> SignerRs<'a, D>: From<&'a pkcs1v15::SigningKey<D>>,
{
    type Error = Infallible;
    type Signer<'a> = SignerRs<'a, D> where Self: 'a;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(self.into())
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<jose_b64::serde::Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data)?;
        signer.finish()
    }
}

impl<D> SigningKey for pss::SigningKey<D>
where
    D: Digest + FixedOutputReset,
    for<'a> SignerPs<'a, D>: From<&'a pss::SigningKey<D>>,
{
    type Error = Infallible;
    type Signer<'a> = SignerPs<'a, D> where Self: 'a;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(self.into())
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<jose_b64::serde::Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data)?;
        signer.finish()
    }
}
