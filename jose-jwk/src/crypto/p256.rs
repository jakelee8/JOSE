// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "p256")]

use jose_jwa::crypto::{EcdsaSigningKey, EcdsaVerifyingKey};
use jose_jwa::{
    Algorithm, Algorithm::KeyManagement, Algorithm::Signing, KeyManagement::*, Signing as S,
};

use super::Error;
use super::KeyInfo;
use crate::{Ec, EcCurves};

impl KeyInfo for EcdsaVerifyingKey<p256::NistP256> {
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

impl KeyInfo for EcdsaSigningKey<p256::NistP256> {
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

impl From<&EcdsaVerifyingKey<p256::NistP256>> for Ec {
    fn from(pk: &EcdsaVerifyingKey<p256::NistP256>) -> Self {
        Self {
            crv: EcCurves::P256,
            x: pk.x(),
            y: pk.y(),
            d: None,
        }
    }
}

impl From<EcdsaVerifyingKey<p256::NistP256>> for Ec {
    fn from(pk: EcdsaVerifyingKey<p256::NistP256>) -> Self {
        (&pk).into()
    }
}

impl TryFrom<&Ec> for EcdsaVerifyingKey<p256::NistP256> {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        // Build uncompressed SEC1 point: 0x04 || x || y
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&value.x);
        sec1.extend_from_slice(&value.y);

        Self::from_sec1_bytes(&sec1).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<Ec> for EcdsaVerifyingKey<p256::NistP256> {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<&EcdsaSigningKey<p256::NistP256>> for Ec {
    fn from(sk: &EcdsaSigningKey<p256::NistP256>) -> Self {
        let mut key: Self = sk.verifying_key().into();
        key.d = Some(sk.d().into());
        key
    }
}

impl From<EcdsaSigningKey<p256::NistP256>> for Ec {
    fn from(sk: EcdsaSigningKey<p256::NistP256>) -> Self {
        (&sk).into()
    }
}

impl TryFrom<&Ec> for EcdsaSigningKey<p256::NistP256> {
    type Error = Error;

    fn try_from(value: &Ec) -> Result<Self, Self::Error> {
        if value.crv != EcCurves::P256 {
            return Err(Error::AlgMismatch);
        }

        if let Some(d) = value.d.as_ref() {
            return Self::from_bytes(&d.0).map_err(|_| Error::Invalid);
        }

        Err(Error::NotPrivate)
    }
}

impl TryFrom<Ec> for EcdsaSigningKey<p256::NistP256> {
    type Error = Error;

    fn try_from(value: Ec) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}
