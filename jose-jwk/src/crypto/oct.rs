// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Symmetric key conversions for JWK.
//!
//! Provides TryFrom implementations for converting JWK octet (Oct) keys
//! to jose-jwa symmetric key types (HMAC, AES-GCM, AES-KW).

#![cfg(any(feature = "hmac", feature = "aes-gcm", feature = "aes-kw"))]

#[cfg(feature = "aes-gcm")]
use jose_jwa::crypto::{Aes128GcmKey, Aes192GcmKey, Aes256GcmKey, EncryptionKey};
#[cfg(feature = "aes-kw")]
use jose_jwa::crypto::{AesKwKey128, AesKwKey192, AesKwKey256};
#[cfg(feature = "hmac")]
use jose_jwa::crypto::{Hs256Signer, Hs384Signer, Hs512Signer};

use super::Error;
use crate::Oct;

// --- HMAC conversions (feature = "hmac") ---

#[cfg(feature = "hmac")]
impl TryFrom<&Oct> for Hs256Signer {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "hmac")]
impl TryFrom<&Oct> for Hs384Signer {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "hmac")]
impl TryFrom<&Oct> for Hs512Signer {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

// --- AES-GCM conversions (feature = "aes-gcm") ---

#[cfg(feature = "aes-gcm")]
impl TryFrom<&Oct> for Aes128GcmKey {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 16 {
            return Err(Error::Invalid);
        }
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "aes-gcm")]
impl TryFrom<&Oct> for Aes192GcmKey {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 24 {
            return Err(Error::Invalid);
        }
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "aes-gcm")]
impl TryFrom<&Oct> for Aes256GcmKey {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 32 {
            return Err(Error::Invalid);
        }
        Self::from_bytes(oct.k.as_ref()).map_err(|_| Error::Invalid)
    }
}

// --- AES-KW conversions (feature = "aes-kw") ---

#[cfg(feature = "aes-kw")]
impl TryFrom<&Oct> for AesKwKey128 {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 16 {
            return Err(Error::Invalid);
        }
        Self::try_from(oct.k.clone()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "aes-kw")]
impl TryFrom<&Oct> for AesKwKey192 {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 24 {
            return Err(Error::Invalid);
        }
        Self::try_from(oct.k.clone()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "aes-kw")]
impl TryFrom<&Oct> for AesKwKey256 {
    type Error = Error;

    fn try_from(oct: &Oct) -> Result<Self, Self::Error> {
        if oct.k.as_ref().len() != 32 {
            return Err(Error::Invalid);
        }
        Self::try_from(oct.k.clone()).map_err(|_| Error::Invalid)
    }
}

// --- Reverse conversions: from jose-jwa types to JWK Oct ---

#[cfg(feature = "hmac")]
impl From<&Hs256Signer> for Oct {
    fn from(key: &Hs256Signer) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "hmac")]
impl From<&Hs384Signer> for Oct {
    fn from(key: &Hs384Signer) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "hmac")]
impl From<&Hs512Signer> for Oct {
    fn from(key: &Hs512Signer) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&Aes128GcmKey> for Oct {
    fn from(key: &Aes128GcmKey) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&Aes192GcmKey> for Oct {
    fn from(key: &Aes192GcmKey) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-gcm")]
impl From<&Aes256GcmKey> for Oct {
    fn from(key: &Aes256GcmKey) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-kw")]
impl From<&AesKwKey128> for Oct {
    fn from(key: &AesKwKey128) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-kw")]
impl From<&AesKwKey192> for Oct {
    fn from(key: &AesKwKey192) -> Self {
        Self { k: key.k().clone() }
    }
}

#[cfg(feature = "aes-kw")]
impl From<&AesKwKey256> for Oct {
    fn from(key: &AesKwKey256) -> Self {
        Self { k: key.k().clone() }
    }
}
