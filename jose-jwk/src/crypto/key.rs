// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

use jose_jwa::crypto::{EcdsaSigningKey, EcdsaVerifyingKey, RsaSigningKey, RsaVerifyingKey};
use jose_jwa::Algorithm;
use zeroize::Zeroizing;

use super::KeyInfo;

/// A fully parsed Key that mimics the runtime behavior of a JWK.
///
/// A JWK is a half-parsed key. This means that it represents a parsed view of
/// the data structure on the wire. But this is not yet usable to perform
/// cryptographic operations. A Key, on the other hand, is a fully parsed key
/// ready to perform cryptographic operations.
///
/// Since RustCrypto provides strong typing and, in order to match the
/// behavior of a JWK, this structure allows us to represent the different
/// kinds of JWKs at runtime using a single object.
#[allow(clippy::large_enum_variant)]
pub enum Key {
    /// A symmetric key.
    Oct(Zeroizing<Box<[u8]>>),

    /// An RSA key.
    #[cfg(feature = "rsa")]
    Rsa(super::Kind<RsaVerifyingKey, RsaSigningKey>),

    /// A P-256 key.
    #[cfg(feature = "p256")]
    P256(super::Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>),

    /// A P-384 key.
    #[cfg(feature = "p384")]
    P384(super::Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>),

    /// A P-521 key.
    #[cfg(feature = "p521")]
    P521(super::Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>),

    /// A Secp256k1 key.
    #[cfg(feature = "k256")]
    P256K(super::Kind<EcdsaVerifyingKey<k256::Secp256k1>, EcdsaSigningKey<k256::Secp256k1>>),
}

impl KeyInfo for Key {
    fn strength(&self) -> usize {
        match self {
            Self::Oct(k) => k.strength(),

            #[cfg(feature = "rsa")]
            Self::Rsa(k) => k.strength(),

            #[cfg(feature = "p256")]
            Self::P256(k) => k.strength(),

            #[cfg(feature = "p384")]
            Self::P384(k) => k.strength(),

            #[cfg(feature = "p521")]
            Self::P521(k) => k.strength(),

            #[cfg(feature = "k256")]
            Self::P256K(k) => k.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Self::Oct(k) => k.is_supported(algo),

            #[cfg(feature = "rsa")]
            Self::Rsa(k) => k.is_supported(algo),

            #[cfg(feature = "p256")]
            Self::P256(k) => k.is_supported(algo),

            #[cfg(feature = "p384")]
            Self::P384(k) => k.is_supported(algo),

            #[cfg(feature = "p521")]
            Self::P521(k) => k.is_supported(algo),

            #[cfg(feature = "k256")]
            Key::P256K(k) => k.is_supported(algo),
        }
    }
}

impl From<Zeroizing<Box<[u8]>>> for Key {
    fn from(value: Zeroizing<Box<[u8]>>) -> Self {
        Self::Oct(value)
    }
}

#[cfg(feature = "rsa")]
impl From<super::Kind<RsaVerifyingKey, RsaSigningKey>> for Key {
    fn from(value: super::Kind<RsaVerifyingKey, RsaSigningKey>) -> Self {
        Self::Rsa(value)
    }
}

#[cfg(feature = "rsa")]
impl From<RsaVerifyingKey> for Key {
    fn from(value: RsaVerifyingKey) -> Self {
        Self::Rsa(super::Kind::Public(value))
    }
}

#[cfg(feature = "rsa")]
impl From<RsaSigningKey> for Key {
    fn from(value: RsaSigningKey) -> Self {
        Self::Rsa(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p256")]
impl From<super::Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>> for Key {
    fn from(
        value: super::Kind<EcdsaVerifyingKey<p256::NistP256>, EcdsaSigningKey<p256::NistP256>>,
    ) -> Self {
        Self::P256(value)
    }
}

#[cfg(feature = "p256")]
impl From<EcdsaVerifyingKey<p256::NistP256>> for Key {
    fn from(value: EcdsaVerifyingKey<p256::NistP256>) -> Self {
        Self::P256(super::Kind::Public(value))
    }
}

#[cfg(feature = "p256")]
impl From<EcdsaSigningKey<p256::NistP256>> for Key {
    fn from(value: EcdsaSigningKey<p256::NistP256>) -> Self {
        Self::P256(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p384")]
impl From<super::Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>> for Key {
    fn from(
        value: super::Kind<EcdsaVerifyingKey<p384::NistP384>, EcdsaSigningKey<p384::NistP384>>,
    ) -> Self {
        Self::P384(value)
    }
}

#[cfg(feature = "p384")]
impl From<EcdsaVerifyingKey<p384::NistP384>> for Key {
    fn from(value: EcdsaVerifyingKey<p384::NistP384>) -> Self {
        Self::P384(super::Kind::Public(value))
    }
}

#[cfg(feature = "p384")]
impl From<EcdsaSigningKey<p384::NistP384>> for Key {
    fn from(value: EcdsaSigningKey<p384::NistP384>) -> Self {
        Self::P384(super::Kind::Secret(value))
    }
}

#[cfg(feature = "p521")]
impl From<super::Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>> for Key {
    fn from(
        value: super::Kind<EcdsaVerifyingKey<p521::NistP521>, EcdsaSigningKey<p521::NistP521>>,
    ) -> Self {
        Self::P521(value)
    }
}

#[cfg(feature = "p521")]
impl From<EcdsaVerifyingKey<p521::NistP521>> for Key {
    fn from(value: EcdsaVerifyingKey<p521::NistP521>) -> Self {
        Self::P521(super::Kind::Public(value))
    }
}

#[cfg(feature = "p521")]
impl From<EcdsaSigningKey<p521::NistP521>> for Key {
    fn from(value: EcdsaSigningKey<p521::NistP521>) -> Self {
        Self::P521(super::Kind::Secret(value))
    }
}

impl From<&crate::Oct> for Key {
    fn from(value: &crate::Oct) -> Self {
        Self::Oct(value.k.to_vec().into_boxed_slice().into())
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        Ok(Self::Rsa(value.try_into()?))
    }
}

#[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
impl TryFrom<&crate::Ec> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Ec) -> Result<Self, Self::Error> {
        match value.crv {
            #[cfg(feature = "p256")]
            crate::EcCurves::P256 => Ok(Self::P256(value.try_into()?)),

            #[cfg(feature = "p384")]
            crate::EcCurves::P384 => Ok(Self::P384(value.try_into()?)),

            #[cfg(feature = "p521")]
            crate::EcCurves::P521 => Ok(Self::P521(value.try_into()?)),

            _ => Err(super::Error::Unsupported),
        }
    }
}

impl TryFrom<&crate::Key> for Key {
    type Error = super::Error;

    fn try_from(value: &crate::Key) -> Result<Self, Self::Error> {
        match value {
            crate::Key::Oct(oct) => Ok(oct.into()),

            #[cfg(feature = "rsa")]
            crate::Key::Rsa(rsa) => rsa.try_into(),

            #[cfg(any(feature = "p256", feature = "p384", feature = "p521"))]
            crate::Key::Ec(ec) => ec.try_into(),

            _ => Err(super::Error::Unsupported),
        }
    }
}

impl From<&Key> for crate::Key {
    fn from(value: &Key) -> Self {
        match value {
            Key::Oct(oct) => Self::Oct(crate::Oct {
                k: oct.to_vec().into(),
            }),

            #[cfg(feature = "rsa")]
            Key::Rsa(kind) => match kind {
                super::Kind::Public(public) => Self::Rsa(public.into()),
                super::Kind::Secret(secret) => Self::Rsa(secret.into()),
            },

            #[cfg(feature = "p256")]
            Key::P256(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },

            #[cfg(feature = "p384")]
            Key::P384(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },

            #[cfg(feature = "p521")]
            Key::P521(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },

            #[cfg(feature = "k256")]
            Key::P256K(kind) => match kind {
                super::Kind::Public(public) => Self::Ec(public.into()),
                super::Kind::Secret(secret) => Self::Ec(secret.into()),
            },
        }
    }
}
