#![cfg(feature = "p256")]

use crate::Signing;

impl From<p256::NistP256> for Signing {
    fn from(_alg: p256::NistP256) -> Self {
        Signing::Es256
    }
}

impl From<p256::PublicKey> for Signing {
    fn from(_key: p256::PublicKey) -> Self {
        Signing::Es256
    }
}

impl From<&p256::PublicKey> for Signing {
    fn from(_key: &p256::PublicKey) -> Self {
        Signing::Es256
    }
}

impl From<p256::SecretKey> for Signing {
    fn from(_key: p256::SecretKey) -> Self {
        Signing::Es256
    }
}

impl From<&p256::SecretKey> for Signing {
    fn from(_key: &p256::SecretKey) -> Self {
        Signing::Es256
    }
}

#[cfg(test)]
mod tests {
    use crate::Signing;

    #[test]
    fn p256_converts_to_es256() {
        assert_eq!(Signing::from(p256::NistP256), Signing::Es256);
    }
}
