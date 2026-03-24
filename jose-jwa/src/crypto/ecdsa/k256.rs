#![cfg(feature = "k256")]

use k256::ecdsa;

use crate::Signing;

/// ES256K (secp256k1 + SHA-256) signer
pub type Es256KSigner<'a> = super::EcdsaSigner<'a, ecdsa::SigningKey>;

/// ES256K (secp256k1 + SHA-256) verifier
pub type Es256KVerifier<'a> = super::EcdsaVerifier<'a, ecdsa::SigningKey>;

impl From<k256::Secp256k1> for Signing {
    fn from(_alg: k256::Secp256k1) -> Self {
        Signing::Es256K
    }
}

impl From<&k256::PublicKey> for Signing {
    fn from(_key: &k256::PublicKey) -> Self {
        Signing::Es256K
    }
}

impl From<&k256::SecretKey> for Signing {
    fn from(_key: &k256::SecretKey) -> Self {
        Signing::Es256K
    }
}
