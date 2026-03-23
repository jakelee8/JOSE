//! HMAC signing algorithm mappings

#![cfg(feature = "hmac")]

use sha2::{Sha256, Sha384, Sha512};

use crate::Signing;

impl From<hmac::Hmac<Sha256>> for Signing {
    fn from(_alg: hmac::Hmac<Sha256>) -> Self {
        Signing::Hs256
    }
}

impl From<&hmac::Hmac<Sha256>> for Signing {
    fn from(_alg: &hmac::Hmac<Sha256>) -> Self {
        Signing::Hs256
    }
}

impl From<hmac::Hmac<Sha384>> for Signing {
    fn from(_alg: hmac::Hmac<Sha384>) -> Self {
        Signing::Hs384
    }
}

impl From<&hmac::Hmac<Sha384>> for Signing {
    fn from(_alg: &hmac::Hmac<Sha384>) -> Self {
        Signing::Hs384
    }
}

impl From<hmac::Hmac<Sha512>> for Signing {
    fn from(_alg: hmac::Hmac<Sha512>) -> Self {
        Signing::Hs512
    }
}

impl From<&hmac::Hmac<Sha512>> for Signing {
    fn from(_alg: &hmac::Hmac<Sha512>) -> Self {
        Signing::Hs512
    }
}
