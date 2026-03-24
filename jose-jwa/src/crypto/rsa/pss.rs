use digest::Digest;
use rsa::pss;
use sha2::{Sha256, Sha384, Sha512};

use crate::{Algorithm, Signing};

impl<T> From<pss::SigningKey<T>> for Algorithm
where
    T: Digest,
    pss::SigningKey<T>: Into<Signing>,
{
    fn from(key: pss::SigningKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<pss::SigningKey<T>> for Signing
where
    T: Digest,
    for<'a> &'a pss::SigningKey<T>: Into<Signing>,
{
    fn from(key: pss::SigningKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl From<&pss::SigningKey<Sha256>> for Signing {
    fn from(_key: &pss::SigningKey<Sha256>) -> Self {
        Signing::Ps256
    }
}

impl From<&pss::SigningKey<Sha384>> for Signing {
    fn from(_key: &pss::SigningKey<Sha384>) -> Self {
        Signing::Ps384
    }
}

impl From<&pss::SigningKey<Sha512>> for Signing {
    fn from(_key: &pss::SigningKey<Sha512>) -> Self {
        Signing::Ps512
    }
}
