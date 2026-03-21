#![cfg(feature = "p521")]

use crate::Signing;

impl From<p521::NistP521> for Signing {
    fn from(_alg: p521::NistP521) -> Self {
        Signing::Es512
    }
}

impl From<p521::PublicKey> for Signing {
    fn from(_key: p521::PublicKey) -> Self {
        Signing::Es512
    }
}

impl From<&p521::PublicKey> for Signing {
    fn from(_key: &p521::PublicKey) -> Self {
        Signing::Es512
    }
}

impl From<p521::SecretKey> for Signing {
    fn from(_key: p521::SecretKey) -> Self {
        Signing::Es512
    }
}

impl From<&p521::SecretKey> for Signing {
    fn from(_key: &p521::SecretKey) -> Self {
        Signing::Es512
    }
}

#[cfg(test)]
mod tests {
    use crate::Signing;

    #[test]
    fn p521_converts_to_es512() {
        assert_eq!(Signing::from(p521::NistP521), Signing::Es512);
    }
}
