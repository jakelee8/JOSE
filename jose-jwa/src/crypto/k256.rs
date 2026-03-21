#![cfg(feature = "k256")]

use crate::Signing;

impl From<k256::Secp256k1> for Signing {
    fn from(_alg: k256::Secp256k1) -> Self {
        Signing::Es256K
    }
}

impl From<k256::PublicKey> for Signing {
    fn from(_key: k256::PublicKey) -> Self {
        Signing::Es256K
    }
}

impl From<&k256::PublicKey> for Signing {
    fn from(_key: &k256::PublicKey) -> Self {
        Signing::Es256K
    }
}

impl From<k256::SecretKey> for Signing {
    fn from(_key: k256::SecretKey) -> Self {
        Signing::Es256K
    }
}

impl From<&k256::SecretKey> for Signing {
    fn from(_key: &k256::SecretKey) -> Self {
        Signing::Es256K
    }
}

#[cfg(test)]
mod tests {
    use crate::Signing;

    #[test]
    fn k256_converts_to_es256k() {
        assert_eq!(Signing::from(k256::Secp256k1), Signing::Es256K);
    }
}
