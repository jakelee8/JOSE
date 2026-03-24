#![cfg(feature = "p384")]

use p384::ecdsa;

use crate::Signing;

/// ES384 (P-384 + SHA-384) signer
pub type Es384Signer<'a> = super::EcdsaSigner<'a, ecdsa::SigningKey>;

/// ES384 (P-384 + SHA-384) verifier
pub type Es384Verifier<'a> = super::EcdsaVerifier<'a, ecdsa::SigningKey>;

impl From<p384::NistP384> for Signing {
    fn from(_alg: p384::NistP384) -> Self {
        Signing::Es384
    }
}

impl From<&p384::PublicKey> for Signing {
    fn from(_key: &p384::PublicKey) -> Self {
        Signing::Es384
    }
}

impl From<&p384::SecretKey> for Signing {
    fn from(_key: &p384::SecretKey) -> Self {
        Signing::Es384
    }
}
