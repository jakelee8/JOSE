#![cfg(feature = "p521")]

use p521::ecdsa;

use crate::Signing;

/// ES512 (P-521 + SHA-512) signer
pub type Es521Signer<'a> = super::EcdsaSigner<'a, ecdsa::SigningKey>;

/// ES512 (P-521 + SHA-512) verifier
pub type Es521Verifier<'a> = super::EcdsaVerifier<'a, ecdsa::SigningKey>;

impl From<p521::NistP521> for Signing {
    fn from(_alg: p521::NistP521) -> Self {
        Signing::Es512
    }
}

impl From<&p521::PublicKey> for Signing {
    fn from(_key: &p521::PublicKey) -> Self {
        Signing::Es512
    }
}

impl From<&p521::SecretKey> for Signing {
    fn from(_key: &p521::SecretKey) -> Self {
        Signing::Es512
    }
}
