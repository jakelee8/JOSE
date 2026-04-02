// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p384")]

use jose_jwa::crypto::{Es384SigningKey, Es384VerifyingKey};
#[cfg(feature = "ecdh")]
use jose_jwa::crypto::{P384PublicKey, P384SecretKey};
use jose_jwa::{
    Algorithm, Algorithm::KeyManagement, Algorithm::Signing, KeyManagement::*, Signing as S,
};

use super::Error;
use super::KeyInfo;
use crate::{Ec, EcCurves};

impl KeyInfo for Es384VerifyingKey {
    fn strength(&self) -> usize {
        24
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es384)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl KeyInfo for Es384SigningKey {
    fn strength(&self) -> usize {
        24
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es384)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl From<&Es384VerifyingKey> for Ec {
    fn from(pk: &Es384VerifyingKey) -> Self {
        Self {
            crv: EcCurves::P384,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

impl From<Es384VerifyingKey> for Ec {
    fn from(pk: Es384VerifyingKey) -> Self {
        (&pk).into()
    }
}

impl TryFrom<&Ec> for Es384VerifyingKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P384 {
            return Err(Error::AlgMismatch);
        }

        // Build uncompressed SEC1 point: 0x04 || x || y
        let mut sec1 = alloc::vec::Vec::new();
        sec1.push(0x04u8);
        sec1.extend_from_slice(&value.x);
        sec1.extend_from_slice(&value.y);

        Self::from_sec1_bytes(&sec1).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<Ec> for Es384VerifyingKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&Es384SigningKey> for Ec {
    fn from(sk: &Es384SigningKey) -> Self {
        let mut key: Self = sk.verifying_key().into();
        key.d = Some(sk.d().into());
        key
    }
}

impl From<Es384SigningKey> for Ec {
    fn from(sk: Es384SigningKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for Es384SigningKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P384 {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_bytes(d.as_ref()).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Ec> for Es384SigningKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

// ECDH conversions for P-384
#[cfg(feature = "ecdh")]
impl KeyInfo for P384PublicKey {
    fn strength(&self) -> usize {
        24
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

#[cfg(feature = "ecdh")]
impl KeyInfo for P384SecretKey {
    fn strength(&self) -> usize {
        24
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

#[cfg(feature = "ecdh")]
impl From<&P384PublicKey> for Ec {
    fn from(pk: &P384PublicKey) -> Self {
        Self {
            crv: EcCurves::P384,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

#[cfg(feature = "ecdh")]
impl From<P384PublicKey> for Ec {
    fn from(pk: P384PublicKey) -> Self {
        (&pk).into()
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<&Ec> for P384PublicKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P384 {
            return Err(Error::AlgMismatch);
        }

        Self::from_components(&value.x, &value.y).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<Ec> for P384PublicKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

#[cfg(feature = "ecdh")]
impl From<&P384SecretKey> for Ec {
    fn from(sk: &P384SecretKey) -> Self {
        let public_key = sk.public_key();
        Self {
            crv: EcCurves::P384,
            x: public_key.x(),
            y: public_key.y(),
            d: Some(sk.d()),
        }
    }
}

#[cfg(feature = "ecdh")]
impl From<P384SecretKey> for Ec {
    fn from(sk: P384SecretKey) -> Self {
        (&sk).into()
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<&Ec> for P384SecretKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P384 {
            return Err(Error::AlgMismatch);
        }

        let Some(d) = value.d.as_ref() else {
            return Err(Error::NotPrivate);
        };

        Self::from_bytes(d.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<Ec> for P384SecretKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
