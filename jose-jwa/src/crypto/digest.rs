#![cfg(any(
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]

use core::convert::Infallible;
use core::marker::PhantomData;

use alloc::vec::Vec;
use digest::Digest;
use jose_b64::stream::Update;
use signature::SignatureEncoding;

pub struct KeyRefDigestState<'a, K, D, S> {
    pub key: &'a K,
    pub digest: D,
    pub _signature: PhantomData<S>,
}

impl<'a, K, D, S> KeyRefDigestState<'a, K, D, S>
where
    D: Digest,
{
    pub fn new(key: &'a K) -> Self {
        Self {
            key,
            digest: D::new(),
            _signature: PhantomData,
        }
    }
}

impl<'a, K, D, S> Update for KeyRefDigestState<'a, K, D, S>
where
    D: Digest,
{
    type Error = Infallible;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.digest.update(chunk.as_ref());
        Ok(())
    }
}

impl<'a, K, D, S> From<&'a K> for KeyRefDigestState<'a, K, D, S>
where
    D: Digest,
{
    fn from(key: &'a K) -> Self {
        KeyRefDigestState::new(key)
    }
}

impl<'a, K, D, S> super::Signer for KeyRefDigestState<'a, K, D, S>
where
    D: Digest,
    K: signature::hazmat::PrehashSigner<S>,
    S: SignatureEncoding,
{
    type FinishError = signature::Error;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        let sig = self.key.sign_prehash(&self.digest.finalize())?;
        Ok(sig.to_vec())
    }
}

impl<'a, K, D, S> super::Verifier<'a> for KeyRefDigestState<'a, K, D, S>
where
    D: 'a + Digest,
    K: signature::hazmat::PrehashVerifier<S>,
    S: SignatureEncoding,
{
    type FinishError = signature::Error;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), Self::FinishError> {
        let sig = signature
            .as_ref()
            .try_into()
            .map_err(|_| signature::Error::new())?;
        self.key.verify_prehash(&self.digest.finalize(), &sig)?;
        Ok(())
    }
}
