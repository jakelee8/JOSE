// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "k256")]

use jose_jwa::crypto::{Es256KSigningKey, Es256KVerifyingKey};
use jose_jwa::{
    Algorithm, Algorithm::KeyManagement, Algorithm::Signing, KeyManagement::*, Signing as S,
};

use super::Error;
use super::KeyInfo;
use crate::{Ec, EcCurves};

impl KeyInfo for Es256KVerifyingKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es256K)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl KeyInfo for Es256KSigningKey {
    fn strength(&self) -> usize {
        16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            algo,
            // Signing algorithms
            Signing(S::Es256K)
                // Sealing algorithms (ECDH)
                | KeyManagement(EcdhEs)
                | KeyManagement(EcdhEsA128Kw)
                | KeyManagement(EcdhEsA192Kw)
                | KeyManagement(EcdhEsA256Kw)
        )
    }
}

impl From<&Es256KVerifyingKey> for Ec {
    fn from(pk: &Es256KVerifyingKey) -> Self {
        Self {
            crv: EcCurves::P256K,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

impl From<Es256KVerifyingKey> for Ec {
    fn from(pk: Es256KVerifyingKey) -> Self {
        (&pk).into()
    }
}

impl TryFrom<&Ec> for Es256KVerifyingKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256K {
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

impl TryFrom<Ec> for Es256KVerifyingKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&Es256KSigningKey> for Ec {
    fn from(sk: &Es256KSigningKey) -> Self {
        let mut key: Self = sk.verifying_key().into();
        key.d = Some(sk.d().into());
        key
    }
}

impl From<Es256KSigningKey> for Ec {
    fn from(sk: Es256KSigningKey) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for Es256KSigningKey {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256K {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_bytes(d.as_ref()).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Ec> for Es256KSigningKey {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
