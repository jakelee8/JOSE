//! AES Key Wrap sealing algorithm mappings

#![cfg(feature = "aes-kw")]

#[cfg(feature = "aes-gcm")]
use aes_gcm::{Aes128Gcm, Aes256Gcm};
#[cfg(feature = "aes-gcm")]
use aes_gcm::aes::Aes192;
#[cfg(feature = "aes-gcm")]
use aes_gcm::AesGcm;
use aes_kw::AesKw;
use aes_kw::aes::{Aes128, Aes192 as KwAes192, Aes256};
#[cfg(feature = "aes-gcm")]
use digest::consts::U12;

use crate::{Algorithm, Encryption, KeyManagement};

#[cfg(feature = "aes-gcm")]
type Aes192Gcm = AesGcm<Aes192, U12>;

impl<C> From<AesKw<C>> for Algorithm
where
    AesKw<C>: Into<KeyManagement>,
{
    fn from(key: AesKw<C>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl<C> From<AesKw<C>> for KeyManagement
where
    for<'a> &'a AesKw<C>: Into<KeyManagement>,
{
    fn from(key: AesKw<C>) -> Self {
        Into::<KeyManagement>::into(key).into()
    }
}

impl<C> From<AesKw<C>> for Encryption
where
    for<'a> &'a AesKw<C>: Into<Encryption>,
{
    fn from(key: AesKw<C>) -> Self {
        Into::<Encryption>::into(key).into()
    }
}

impl From<&AesKw<Aes128>> for KeyManagement {
    fn from(_alg: &AesKw<Aes128>) -> Self {
        KeyManagement::A128Kw
    }
}

impl From<&AesKw<KwAes192>> for KeyManagement {
    fn from(_alg: &AesKw<KwAes192>) -> Self {
        KeyManagement::A192Kw
    }
}

impl From<&AesKw<Aes256>> for KeyManagement {
    fn from(_alg: &AesKw<Aes256>) -> Self {
        KeyManagement::A256Kw
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&AesKw<Aes128Gcm>> for KeyManagement {
    fn from(_alg: &AesKw<Aes128Gcm>) -> Self {
        KeyManagement::A128Kw
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&AesKw<Aes192Gcm>> for KeyManagement {
    fn from(_alg: &AesKw<Aes192Gcm>) -> Self {
        KeyManagement::A192Kw
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&AesKw<Aes256Gcm>> for KeyManagement {
    fn from(_alg: &AesKw<Aes256Gcm>) -> Self {
        KeyManagement::A256Kw
    }
}
