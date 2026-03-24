use core::convert::Infallible;
use core::ops::Add;

use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, SigningKey};
use elliptic_curve::array::ArraySize;
use elliptic_curve::{Curve, CurveArithmetic};

use crate::crypto::digest::KeyRefDigestState;

pub type EcdsaSigner<'a, C> =
    KeyRefDigestState<'a, SigningKey<C>, <C as DigestAlgorithm>::Digest, Signature<C>>;

impl<'a, C> crate::SigningKey<'a> for &'a SigningKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestAlgorithm,
    EcdsaSigner<'a, C>: From<&'a Self>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
{
    type StartError = Infallible;
    type Signer = EcdsaSigner<'a, C>;

    fn sign(&'a self) -> Result<Self::Signer, Self::StartError> {
        Ok(self.into())
    }
}
