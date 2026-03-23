//! AES-GCM content encryption algorithm mappings

#![cfg(feature = "aes-gcm")]

use aes_gcm::{Aes128Gcm, Aes256Gcm};

use crate::Encryption;

impl From<Aes128Gcm> for Encryption {
    fn from(_alg: Aes128Gcm) -> Self {
        Encryption::A128Gcm
    }
}

impl From<&Aes128Gcm> for Encryption {
    fn from(_alg: &Aes128Gcm) -> Self {
        Encryption::A128Gcm
    }
}

impl From<Aes256Gcm> for Encryption {
    fn from(_alg: Aes256Gcm) -> Self {
        Encryption::A256Gcm
    }
}

impl From<&Aes256Gcm> for Encryption {
    fn from(_alg: &Aes256Gcm) -> Self {
        Encryption::A256Gcm
    }
}
