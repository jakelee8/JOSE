#![cfg(feature = "p256")]

use p256::ecdsa;

use crate::Signing;

/// ES256 (P-256 + SHA-256) signer
pub type Es256Signer<'a> = super::EcdsaSigner<'a, ecdsa::SigningKey>;

/// ES256 (P-256 + SHA-256) verifier
pub type Es256Verifier<'a> = super::EcdsaVerifier<'a, ecdsa::SigningKey>;

impl From<p256::NistP256> for Signing {
    fn from(_alg: p256::NistP256) -> Self {
        Signing::Es256
    }
}

impl From<&p256::PublicKey> for Signing {
    fn from(_key: &p256::PublicKey) -> Self {
        Signing::Es256
    }
}

impl From<&p256::SecretKey> for Signing {
    fn from(_key: &p256::SecretKey) -> Self {
        Signing::Es256
    }
}
