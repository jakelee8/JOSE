// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use jose_jwa::Algorithm;

use super::KeyInfo;

#[cfg(any(feature = "p256", feature = "p384", feature = "p521", feature = "k256"))]
use jose_jwa::crypto::{EcdsaSigningKey, EcdsaVerifyingKey};

#[cfg(feature = "rsa")]
use super::key::{RsaSigningKey, RsaVerifyingKey};

/// The kind of a key (public or private).
pub enum Kind<P, S> {
    /// A public key.
    Public(P),

    /// A private key.
    Secret(S),
}

impl<P: KeyInfo, S: KeyInfo> KeyInfo for Kind<P, S> {
    fn strength(&self) -> usize {
        match self {
            Self::Public(k) => k.strength(),
            Self::Secret(k) => k.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Self::Public(k) => k.is_supported(algo),
            Self::Secret(k) => k.is_supported(algo),
        }
    }
}

#[cfg(feature = "rsa")]
impl From<&Kind<RsaVerifyingKey, RsaSigningKey>> for crate::Rsa {
    fn from(value: &Kind<RsaVerifyingKey, RsaSigningKey>) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for Kind<RsaVerifyingKey, RsaSigningKey> {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        if value.prv.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p256")]
impl From<&Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>> for crate::Ec {
    fn from(
        value: &Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>,
    ) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&crate::Ec>
    for Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>
{
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p384")]
impl From<&Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>> for crate::Ec {
    fn from(
        value: &Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>,
    ) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p384")]
impl TryFrom<&crate::Ec>
    for Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>
{
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "p521")]
impl From<&Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>> for crate::Ec {
    fn from(
        value: &Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>,
    ) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "p521")]
impl TryFrom<&crate::Ec>
    for Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>
{
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}

#[cfg(feature = "k256")]
impl From<&Kind<EcdsaVerifyingKey<k256::Secp256k1>, EcdsaSigningKey<k256::Secp256k1>>>
    for crate::Ec
{
    fn from(
        value: &Kind<EcdsaVerifyingKey<k256::Secp256k1>, EcdsaSigningKey<k256::Secp256k1>>,
    ) -> Self {
        match value {
            Kind::Public(key) => key.into(),
            Kind::Secret(key) => key.into(),
        }
    }
}

#[cfg(feature = "k256")]
impl TryFrom<&crate::Ec>
    for Kind<EcdsaVerifyingKey<k256::Secp256k1>, EcdsaSigningKey<k256::Secp256k1>>
{
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        if value.d.is_none() {
            Ok(Kind::Public(value.try_into()?))
        } else {
            Ok(Kind::Secret(value.try_into()?))
        }
    }
}
