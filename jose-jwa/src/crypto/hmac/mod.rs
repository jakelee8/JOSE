//! HMAC signing algorithm mappings

#![cfg(feature = "hmac")]

mod state;

pub use self::state::*;

use hmac::{EagerHash, Hmac};
use sha2::{Sha256, Sha384, Sha512};

use crate::{Algorithm, Signing};

impl<T> From<Hmac<T>> for Algorithm
where
    T: EagerHash,
    Hmac<T>: Into<Signing>,
{
    fn from(key: Hmac<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl<T> From<Hmac<T>> for Signing
where
    T: EagerHash,
    for<'a> &'a Hmac<T>: Into<Signing>,
{
    fn from(key: Hmac<T>) -> Self {
        Into::<Signing>::into(key).into()
    }
}

impl From<&Hmac<Sha256>> for Signing {
    fn from(_alg: &Hmac<Sha256>) -> Self {
        Signing::Hs256
    }
}

impl From<&Hmac<Sha384>> for Signing {
    fn from(_alg: &Hmac<Sha384>) -> Self {
        Signing::Hs384
    }
}

impl From<&Hmac<Sha512>> for Signing {
    fn from(_alg: &Hmac<Sha512>) -> Self {
        Signing::Hs512
    }
}
