// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "rsa")]

use alloc::vec::Vec;

use jose_jwa::crypto::{
    Ps256SigningKey, Ps256VerifyingKey, Ps384SigningKey, Ps384VerifyingKey, Ps512SigningKey,
    Ps512VerifyingKey, Rs256SigningKey, Rs256VerifyingKey, Rs384SigningKey, Rs384VerifyingKey,
    Rs512SigningKey, Rs512VerifyingKey, RsaComponents, RsaPrivateComponents,
};
use jose_jwa::{
    Algorithm, Algorithm::KeyManagement, Algorithm::Signing, KeyManagement::*, Signing as S,
};

use super::Error;
use super::KeyInfo;
use crate::{Rsa, RsaOptional, RsaPrivate};

// === KeyInfo implementations for RSA verifying keys ===

impl KeyInfo for Rs256VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        // RFC 7518 Section 3.3
        if self.strength() < 16 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

impl KeyInfo for Rs384VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.strength() < 24 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

impl KeyInfo for Rs512VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.strength() < 32 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

impl KeyInfo for Ps256VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.strength() < 16 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

impl KeyInfo for Ps384VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.strength() < 24 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

impl KeyInfo for Ps512VerifyingKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        if self.strength() < 32 {
            return false;
        }
        matches!(
            algo,
            Signing(S::Rs256)
                | Signing(S::Rs384)
                | Signing(S::Rs512)
                | Signing(S::Ps256)
                | Signing(S::Ps384)
                | Signing(S::Ps512)
                | KeyManagement(RsaOaep)
                | KeyManagement(RsaOaep256)
        )
    }
}

// === KeyInfo implementations for RSA signing keys ===

impl KeyInfo for Rs256SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

impl KeyInfo for Rs384SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

impl KeyInfo for Rs512SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

impl KeyInfo for Ps256SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

impl KeyInfo for Ps384SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

impl KeyInfo for Ps512SigningKey {
    fn strength(&self) -> usize {
        self.n().as_ref().len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            (Signing(S::Rs256), 16..)
                | (Signing(S::Rs384), 24..)
                | (Signing(S::Rs512), 32..)
                | (Signing(S::Ps256), 16..)
                | (Signing(S::Ps384), 24..)
                | (Signing(S::Ps512), 32..)
                | (KeyManagement(RsaOaep), 16..)
                | (KeyManagement(RsaOaep256), 16..)
        )
    }
}

// === TryFrom<&Rsa> for RSA signing keys ===

impl TryFrom<&Rsa> for Rs256SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Rs384SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Rs512SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps256SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps384SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps512SigningKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        let prv = rsa.prv.as_ref().ok_or(Error::NotPrivate)?;
        let opt = prv.opt.as_ref().ok_or(Error::Unsupported)?;

        let primes = build_primes_iter(&opt);
        Self::from_components_with_primes(&rsa.n, &rsa.e, prv.d.as_ref(), primes)
            .map_err(|_| Error::Invalid)
    }
}

// === TryFrom<&Rsa> for RSA verifying keys ===

impl TryFrom<&Rsa> for Rs256VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Rs384VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Rs512VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps256VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps384VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

impl TryFrom<&Rsa> for Ps512VerifyingKey {
    type Error = Error;

    fn try_from(rsa: &Rsa) -> Result<Self, Self::Error> {
        Self::from_components(&rsa.n, &rsa.e).map_err(|_| Error::Invalid)
    }
}

// === From<jose-jwa types> for Rsa ===

fn build_rsa_optional<T: RsaPrivateComponents>(key: &T) -> Option<RsaOptional> {
    // All CRT params must be present to construct RsaOptional
    let (p, q, dp, dq, qi) = (key.p()?, key.q()?, key.dp()?, key.dq()?, key.qi()?);
    Some(RsaOptional {
        p,
        q,
        dp,
        dq,
        qi,
        oth: Vec::new(),
    })
}

impl From<&Rs256VerifyingKey> for Rsa {
    fn from(key: &Rs256VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Rs384VerifyingKey> for Rsa {
    fn from(key: &Rs384VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Rs512VerifyingKey> for Rsa {
    fn from(key: &Rs512VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Ps256VerifyingKey> for Rsa {
    fn from(key: &Ps256VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Ps384VerifyingKey> for Rsa {
    fn from(key: &Ps384VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Ps512VerifyingKey> for Rsa {
    fn from(key: &Ps512VerifyingKey) -> Self {
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: None,
        }
    }
}

impl From<&Rs256SigningKey> for Rsa {
    fn from(key: &Rs256SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

impl From<&Rs384SigningKey> for Rsa {
    fn from(key: &Rs384SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

impl From<&Rs512SigningKey> for Rsa {
    fn from(key: &Rs512SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

impl From<&Ps256SigningKey> for Rsa {
    fn from(key: &Ps256SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

impl From<&Ps384SigningKey> for Rsa {
    fn from(key: &Ps384SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

impl From<&Ps512SigningKey> for Rsa {
    fn from(key: &Ps512SigningKey) -> Self {
        let opt = build_rsa_optional(key);
        Self {
            n: key.n().into(),
            e: key.e().into(),
            prv: Some(RsaPrivate {
                d: key.d().into(),
                opt,
            }),
        }
    }
}

/// Build an iterator over prime factors for RSA key construction.
fn build_primes_iter(opt: &RsaOptional) -> impl Iterator<Item = &[u8]> + '_ {
    core::iter::once(opt.p.as_ref())
        .chain(core::iter::once(opt.q.as_ref()))
        .chain(opt.oth.iter().map(|r| r.r.as_ref()))
}
