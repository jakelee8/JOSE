use rsa::Oaep;
use sha1::Sha1;
use sha2::Sha256;

use crate::{Algorithm, Sealing};

impl<T> From<Oaep<T>> for Algorithm
where
    Oaep<T>: Into<Sealing>,
{
    fn from(key: Oaep<T>) -> Self {
        Into::<Sealing>::into(key).into()
    }
}

impl<T> From<Oaep<T>> for Sealing
where
    for<'a> &'a Oaep<T>: Into<Sealing>,
{
    fn from(key: Oaep<T>) -> Self {
        Into::<Sealing>::into(key).into()
    }
}

impl From<&Oaep<Sha1>> for Sealing {
    fn from(_key: &Oaep<Sha1>) -> Self {
        Sealing::RsaOaep
    }
}

impl From<&Oaep<Sha256>> for Sealing {
    fn from(_key: &Oaep<Sha256>) -> Self {
        Sealing::RsaOaep256
    }
}
