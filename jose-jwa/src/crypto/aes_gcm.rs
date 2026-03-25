//! AES-GCM content encryption algorithm mappings

#![cfg(feature = "aes-gcm")]

use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use digest::consts::U12;

use crate::{Algorithm, Encryption, KeyManagement};

type Aes192Gcm = AesGcm<Aes192, U12>;

impl<A, N> From<AesGcm<A, N>> for Algorithm
where
    AesGcm<A, N>: Into<KeyManagement>,
{
    fn from(key: AesGcm<A, N>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl<A, N> From<AesGcm<A, N>> for KeyManagement
where
    for<'a> &'a AesGcm<A, N>: Into<KeyManagement>,
{
    fn from(key: AesGcm<A, N>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl<A, N> From<AesGcm<A, N>> for Encryption
where
    for<'a> &'a AesGcm<A, N>: Into<Encryption>,
{
    fn from(key: AesGcm<A, N>) -> Self {
        Into::<Encryption>::into(key).into()
    }
}

impl From<&Aes128Gcm> for KeyManagement {
    fn from(_alg: &Aes128Gcm) -> Self {
        KeyManagement::A128GcmKw
    }
}

impl From<&Aes192Gcm> for KeyManagement {
    fn from(_alg: &Aes192Gcm) -> Self {
        KeyManagement::A192GcmKw
    }
}

impl From<&Aes256Gcm> for KeyManagement {
    fn from(_alg: &Aes256Gcm) -> Self {
        KeyManagement::A256GcmKw
    }
}

impl From<&Aes128Gcm> for Encryption {
    fn from(_alg: &Aes128Gcm) -> Self {
        Encryption::A128Gcm
    }
}

impl From<&Aes192Gcm> for Encryption {
    fn from(_alg: &Aes192Gcm) -> Self {
        Encryption::A192Gcm
    }
}

impl From<&Aes256Gcm> for Encryption {
    fn from(_alg: &Aes256Gcm) -> Self {
        Encryption::A256Gcm
    }
}
