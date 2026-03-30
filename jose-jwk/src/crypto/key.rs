// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;

use jose_jwa::Algorithm;
use jose_jwa::crypto::{
    EcdsaSigningKey, EcdsaVerifyingKey, Ps256SigningKey, Ps256VerifyingKey, Ps384SigningKey,
    Ps384VerifyingKey, Ps512SigningKey, Ps512VerifyingKey, Rs256SigningKey, Rs256VerifyingKey,
    Rs384SigningKey, Rs384VerifyingKey, Rs512SigningKey, Rs512VerifyingKey, RsaComponents,
};
use zeroize::Zeroizing;

use super::KeyInfo;

/// RSA signing key enum wrapping all algorithm-specific types.
#[cfg(feature = "rsa")]
pub enum RsaSigningKey {
    /// RS256 signing key
    Rs256(Rs256SigningKey),
    /// RS384 signing key
    Rs384(Rs384SigningKey),
    /// RS512 signing key
    Rs512(Rs512SigningKey),
    /// PS256 signing key
    Ps256(Ps256SigningKey),
    /// PS384 signing key
    Ps384(Ps384SigningKey),
    /// PS512 signing key
    Ps512(Ps512SigningKey),
}

#[cfg(feature = "rsa")]
impl KeyInfo for RsaSigningKey {
    fn strength(&self) -> usize {
        match self {
            Self::Rs256(k) => k.n().len() / 16,
            Self::Rs384(k) => k.n().len() / 16,
            Self::Rs512(k) => k.n().len() / 16,
            Self::Ps256(k) => k.n().len() / 16,
            Self::Ps384(k) => k.n().len() / 16,
            Self::Ps512(k) => k.n().len() / 16,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        let strength = self.strength();
        self.strength() >= 16
            && match (self, algo) {
                (Self::Rs256(_), Algorithm::Signing(jose_jwa::Signing::Rs256)) => strength >= 16,
                (Self::Rs384(_), Algorithm::Signing(jose_jwa::Signing::Rs384)) => strength >= 24,
                (Self::Rs512(_), Algorithm::Signing(jose_jwa::Signing::Rs512)) => strength >= 32,
                (Self::Ps256(_), Algorithm::Signing(jose_jwa::Signing::Ps256)) => strength >= 16,
                (Self::Ps384(_), Algorithm::Signing(jose_jwa::Signing::Ps384)) => strength >= 24,
                (Self::Ps512(_), Algorithm::Signing(jose_jwa::Signing::Ps512)) => strength >= 32,
                (_, Algorithm::KeyManagement(jose_jwa::KeyManagement::RsaOaep)) => strength >= 16,
                (_, Algorithm::KeyManagement(jose_jwa::KeyManagement::RsaOaep256)) => {
                    strength >= 16
                }
                _ => false,
            }
    }
}

#[cfg(feature = "rsa")]
impl From<&RsaSigningKey> for crate::Rsa {
    fn from(key: &RsaSigningKey) -> Self {
        use jose_jwa::crypto::RsaPrivateComponents;
        let (n, e, d, opt) = match key {
            RsaSigningKey::Rs256(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
            RsaSigningKey::Rs384(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
            RsaSigningKey::Rs512(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
            RsaSigningKey::Ps256(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
            RsaSigningKey::Ps384(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
            RsaSigningKey::Ps512(k) => {
                let opt = k.p().zip(k.q()).zip(k.dp()).zip(k.dq()).zip(k.qi()).map(
                    |((((p, q), dp), dq), qi)| crate::RsaOptional {
                        p,
                        q,
                        dp,
                        dq,
                        qi,
                        oth: alloc::vec::Vec::new(),
                    },
                );
                (k.n(), k.e(), k.d(), opt)
            }
        };
        Self {
            n: n.into(),
            e: e.into(),
            prv: Some(crate::RsaPrivate { d: d.into(), opt }),
        }
    }
}

#[cfg(feature = "rsa")]
impl From<RsaSigningKey> for crate::Rsa {
    fn from(key: RsaSigningKey) -> Self {
        (&key).into()
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for RsaSigningKey {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        use rsa::RsaPrivateKey;

        if value.prv.is_none() {
            return Err(super::Error::NotPrivate);
        }

        // Convert JWK Rsa to RsaPrivateKey
        let private_key: RsaPrivateKey = value.try_into()?;

        // Construct signing keys directly from the private key
        // We use RS256 (PKCS#1 v1.5 with SHA-256) as the default
        Ok(Self::Rs256(Rs256SigningKey::new(private_key)))
    }
}

/// RSA verifying key enum wrapping all algorithm-specific types.
#[cfg(feature = "rsa")]
pub enum RsaVerifyingKey {
    /// RS256 verifying key
    Rs256(Rs256VerifyingKey),
    /// RS384 verifying key
    Rs384(Rs384VerifyingKey),
    /// RS512 verifying key
    Rs512(Rs512VerifyingKey),
    /// PS256 verifying key
    Ps256(Ps256VerifyingKey),
    /// PS384 verifying key
    Ps384(Ps384VerifyingKey),
    /// PS512 verifying key
    Ps512(Ps512VerifyingKey),
}

#[cfg(feature = "rsa")]
impl KeyInfo for RsaVerifyingKey {
    fn strength(&self) -> usize {
        match self {
            Self::Rs256(k) => k.n().len() / 16,
            Self::Rs384(k) => k.n().len() / 16,
            Self::Rs512(k) => k.n().len() / 16,
            Self::Ps256(k) => k.n().len() / 16,
            Self::Ps384(k) => k.n().len() / 16,
            Self::Ps512(k) => k.n().len() / 16,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.strength() >= 16
            && match (self, algo) {
                (Self::Rs256(_), Algorithm::Signing(jose_jwa::Signing::Rs256)) => true,
                (Self::Rs384(_), Algorithm::Signing(jose_jwa::Signing::Rs384)) => true,
                (Self::Rs512(_), Algorithm::Signing(jose_jwa::Signing::Rs512)) => true,
                (Self::Ps256(_), Algorithm::Signing(jose_jwa::Signing::Ps256)) => true,
                (Self::Ps384(_), Algorithm::Signing(jose_jwa::Signing::Ps384)) => true,
                (Self::Ps512(_), Algorithm::Signing(jose_jwa::Signing::Ps512)) => true,
                (_, Algorithm::KeyManagement(jose_jwa::KeyManagement::RsaOaep)) => true,
                (_, Algorithm::KeyManagement(jose_jwa::KeyManagement::RsaOaep256)) => true,
                _ => false,
            }
    }
}

#[cfg(feature = "rsa")]
impl From<&RsaVerifyingKey> for crate::Rsa {
    fn from(key: &RsaVerifyingKey) -> Self {
        let (n, e) = match key {
            RsaVerifyingKey::Rs256(k) => (k.n(), k.e()),
            RsaVerifyingKey::Rs384(k) => (k.n(), k.e()),
            RsaVerifyingKey::Rs512(k) => (k.n(), k.e()),
            RsaVerifyingKey::Ps256(k) => (k.n(), k.e()),
            RsaVerifyingKey::Ps384(k) => (k.n(), k.e()),
            RsaVerifyingKey::Ps512(k) => (k.n(), k.e()),
        };
        Self {
            n: n.into(),
            e: e.into(),
            prv: None,
        }
    }
}

#[cfg(feature = "rsa")]
impl From<RsaVerifyingKey> for crate::Rsa {
    fn from(key: RsaVerifyingKey) -> Self {
        (&key).into()
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&crate::Rsa> for RsaVerifyingKey {
    type Error = super::Error;

    fn try_from(value: &crate::Rsa) -> Result<Self, Self::Error> {
        use rsa::RsaPublicKey;

        // Convert JWK Rsa to RsaPublicKey
        let public_key: RsaPublicKey = value.try_into()?;

        // Construct a verifying key directly from the public key
        // We use RS256 (PKCS#1 v1.5 with SHA-256) as the default
        Ok(Self::Rs256(Rs256VerifyingKey::new(public_key)))
    }
}

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
