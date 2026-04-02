// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p256")]

use jose_jwa::crypto::{Es256SigningKey, Es256VerifyingKey};
#[cfg(feature = "ecdh")]
use jose_jwa::crypto::{P256PublicKey, P256SecretKey};
use jose_jwa::{
    Algorithm, Algorithm::KeyManagement, Algorithm::Signing, KeyManagement::*, Signing as S,
};

use super::Error;
use super::KeyInfo;
use crate::{Ec, EcCurves};

impl KeyInfo for Es256VerifyingKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es256)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl KeyInfo for Es256SigningKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es256)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl From<&Es256VerifyingKey> for Ec {
    fn from(pk: &Es256VerifyingKey) -> Self {
        Self {
            crv: EcCurves::P256,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

impl From<Es256VerifyingKey> for Ec {
    fn from(pk: Es256VerifyingKey) -> Self {
        (&pk).into()
    }
}

impl TryFrom<&Ec> for Es256VerifyingKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
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

impl TryFrom<Ec> for Es256VerifyingKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&Es256SigningKey> for Ec {
    fn from(sk: &Es256SigningKey) -> Self {
        let mut key: Self = sk.verifying_key().into();
        key.d = Some(sk.d().into());
        key
    }
}

impl From<Es256SigningKey> for Ec {
    fn from(sk: Es256SigningKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for Es256SigningKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_bytes(d.as_ref()).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Ec> for Es256SigningKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

// ECDH conversions for P-256
#[cfg(feature = "ecdh")]
impl KeyInfo for P256PublicKey {
    fn strength(&self) -> usize {
        16
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
impl KeyInfo for P256SecretKey {
    fn strength(&self) -> usize {
        16
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
impl From<&P256PublicKey> for Ec {
    fn from(pk: &P256PublicKey) -> Self {
        Self {
            crv: EcCurves::P256,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

#[cfg(feature = "ecdh")]
impl From<P256PublicKey> for Ec {
    fn from(pk: P256PublicKey) -> Self {
        (&pk).into()
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<&Ec> for P256PublicKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        Self::from_components(&value.x, &value.y).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<Ec> for P256PublicKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

#[cfg(feature = "ecdh")]
impl From<&P256SecretKey> for Ec {
    fn from(sk: &P256SecretKey) -> Self {
        let public_key = sk.public_key();
        Self {
            crv: EcCurves::P256,
            x: public_key.x(),
            y: public_key.y(),
            d: Some(sk.d()),
        }
    }
}

#[cfg(feature = "ecdh")]
impl From<P256SecretKey> for Ec {
    fn from(sk: P256SecretKey) -> Self {
        (&sk).into()
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<&Ec> for P256SecretKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        let Some(d) = value.d.as_ref() else {
            return Err(Error::NotPrivate);
        };

        Self::from_bytes(d.as_ref()).map_err(|_| Error::Invalid)
    }
}

#[cfg(feature = "ecdh")]
impl TryFrom<Ec> for P256SecretKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
