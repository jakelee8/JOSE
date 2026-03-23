//! AES Key Wrap sealing algorithm mappings

#![cfg(feature = "aes-kw")]

use aes_kw::AesKw;
use aes_kw::aes::{Aes128, Aes192, Aes256};

use crate::Sealing;

impl From<AesKw<Aes128>> for Sealing {
    fn from(_alg: AesKw<Aes128>) -> Self {
        Sealing::A128Kw
    }
}

impl From<&AesKw<Aes128>> for Sealing {
    fn from(_alg: &AesKw<Aes128>) -> Self {
        Sealing::A128Kw
    }
}

impl From<AesKw<Aes192>> for Sealing {
    fn from(_alg: AesKw<Aes192>) -> Self {
        Sealing::A192Kw
    }
}

impl From<&AesKw<Aes192>> for Sealing {
    fn from(_alg: &AesKw<Aes192>) -> Self {
        Sealing::A192Kw
    }
}

impl From<AesKw<Aes256>> for Sealing {
    fn from(_alg: AesKw<Aes256>) -> Self {
        Sealing::A256Kw
    }
}

impl From<&AesKw<Aes256>> for Sealing {
    fn from(_alg: &AesKw<Aes256>) -> Self {
        Sealing::A256Kw
    }
}
