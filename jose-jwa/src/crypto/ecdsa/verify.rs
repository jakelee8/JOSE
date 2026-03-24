use core::convert::Infallible;
use core::ops::Add;

use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, VerifyingKey};
use elliptic_curve::array::ArraySize;
use elliptic_curve::{Curve, CurveArithmetic};

use crate::crypto::digest::KeyRefDigestState;

pub type EcdsaVerifier<'a, C> =
    KeyRefDigestState<'a, VerifyingKey<C>, <C as DigestAlgorithm>::Digest, Signature<C>>;

impl<'a, C> crate::VerifyingKey<'a> for &'a VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestAlgorithm,
    EcdsaVerifier<'a, C>: From<&'a Self>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
{
    type StartError = Infallible;
    type Verifier = EcdsaVerifier<'a, C>;

    fn verify(&'a self) -> Result<Self::Verifier, Self::StartError> {
        Ok(self.into())
    }
}
