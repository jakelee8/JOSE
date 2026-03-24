use digest::Digest;
use rsa::pkcs1v15;
use sha2::{Sha256, Sha384, Sha512};

use crate::{Algorithm, Signing};

impl<T> From<pkcs1v15::SigningKey<T>> for Algorithm
where
    T: Digest,
    pkcs1v15::SigningKey<T>: Into<Signing>,
{
    fn from(key: pkcs1v15::SigningKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<pkcs1v15::SigningKey<T>> for Signing
where
    T: Digest,
    for<'a> &'a pkcs1v15::SigningKey<T>: Into<Signing>,
{
    fn from(key: pkcs1v15::SigningKey<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl From<&pkcs1v15::SigningKey<Sha256>> for Signing {
    fn from(_key: &pkcs1v15::SigningKey<Sha256>) -> Self {
        Signing::Rs256
    }
}

impl From<&pkcs1v15::SigningKey<Sha384>> for Signing {
    fn from(_key: &pkcs1v15::SigningKey<Sha384>) -> Self {
        Signing::Rs384
    }
}

impl From<&pkcs1v15::SigningKey<Sha512>> for Signing {
    fn from(_key: &pkcs1v15::SigningKey<Sha512>) -> Self {
        Signing::Rs512
    }
}
