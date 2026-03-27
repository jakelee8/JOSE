use core::convert::Infallible;
use core::ops::Add;

use ecdsa::hazmat::DigestAlgorithm;
use ecdsa::{EcdsaCurve, Signature, VerifyingKey};
use elliptic_curve::array::ArraySize;
use elliptic_curve::{Curve, CurveArithmetic};

use crate::crypto::digest::KeyRefDigestState;
use crate::crypto::verify::Verifier;
use jose_b64::stream::Update;

pub type EcdsaVerifier<'a, C> =
    KeyRefDigestState<'a, VerifyingKey<C>, <C as DigestAlgorithm>::Digest, Signature<C>>;

impl<C> crate::crypto::VerifyingKey for VerifyingKey<C>
where
    C: EcdsaCurve + CurveArithmetic + DigestAlgorithm,
    for<'a> EcdsaVerifier<'a, C>: From<&'a VerifyingKey<C>>,
    <<C as Curve>::FieldBytesSize as Add>::Output: ArraySize,
{
    type Verifier<'a> = EcdsaVerifier<'a, C> where Self: 'a;
    type Error = Infallible;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(self.into())
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        match verifier.update(data) {
            Ok(()) => {}
            Err(_) => unreachable!(),
        }
        match verifier.finish(signature) {
            Ok(()) => Ok(()),
            Err(_) => unreachable!(),
        }
    }
}
