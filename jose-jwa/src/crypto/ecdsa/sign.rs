use core::convert::Infallible;
use core::ops::Add;

use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, SigningKey as EcdsaSigningKeyInner};
use elliptic_curve::array::ArraySize;
use elliptic_curve::{Curve, CurveArithmetic};

use crate::crypto::digest::KeyRefDigestState;
use crate::crypto::sign::{Signer, SigningKey};
use jose_b64::stream::Update;
use jose_b64::serde::Bytes;

pub type EcdsaSigner<'a, C> =
    KeyRefDigestState<'a, EcdsaSigningKeyInner<C>, <C as DigestAlgorithm>::Digest, Signature<C>>;

impl<C> SigningKey for EcdsaSigningKeyInner<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestAlgorithm,
    for<'a> EcdsaSigner<'a, C>: From<&'a EcdsaSigningKeyInner<C>>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
{
    type Error = Infallible;
    type Signer<'a> = EcdsaSigner<'a, C> where Self: 'a;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(self.into())
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<Bytes, Self::Error> {
        use crate::crypto::Signer;
        let mut signer = self.signer()?;
        match signer.update(data) {
            Ok(()) => {}
            Err(_) => unreachable!(),
        }
        match signer.finish() {
            Ok(sig) => Ok(sig),
            Err(_) => unreachable!(),
        }
    }
}
