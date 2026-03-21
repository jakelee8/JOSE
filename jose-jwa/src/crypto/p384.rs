#![cfg(feature = "p384")]

use crate::Signing;

impl From<p384::NistP384> for Signing {
    fn from(_alg: p384::NistP384) -> Self {
        Signing::Es384
    }
}

impl From<p384::PublicKey> for Signing {
    fn from(_key: p384::PublicKey) -> Self {
        Signing::Es384
    }
}

impl From<&p384::PublicKey> for Signing {
    fn from(_key: &p384::PublicKey) -> Self {
        Signing::Es384
    }
}

impl From<p384::SecretKey> for Signing {
    fn from(_key: p384::SecretKey) -> Self {
        Signing::Es384
    }
}

impl From<&p384::SecretKey> for Signing {
    fn from(_key: &p384::SecretKey) -> Self {
        Signing::Es384
    }
}

#[cfg(test)]
mod tests {
    use crate::Signing;

    #[test]
    fn p384_converts_to_es384() {
        assert_eq!(Signing::from(p384::NistP384), Signing::Es384);
    }
}
