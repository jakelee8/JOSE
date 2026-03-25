use rsa::Oaep;
use sha1::Sha1;
use sha2::Sha256;

use crate::{Algorithm, KeyManagement};

impl<T> From<Oaep<T>> for Algorithm
where
    Oaep<T>: Into<KeyManagement>,
{
    fn from(key: Oaep<T>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl<T> From<Oaep<T>> for KeyManagement
where
    for<'a> &'a Oaep<T>: Into<KeyManagement>,
{
    fn from(key: Oaep<T>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl From<&Oaep<Sha1>> for KeyManagement {
    fn from(_key: &Oaep<Sha1>) -> Self {
        KeyManagement::RsaOaep
    }
}

impl From<&Oaep<Sha256>> for KeyManagement {
    fn from(_key: &Oaep<Sha256>) -> Self {
        KeyManagement::RsaOaep256
    }
}
