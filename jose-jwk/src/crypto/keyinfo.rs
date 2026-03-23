// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::ops::Deref;

use alloc::{boxed::Box, vec::Vec};
use jose_jwa::{Algorithm, Algorithm::Sealing, Algorithm::Signing, Sealing::*, Signing::*};

use crate::{Ec, EcCurves, Jwk, Key, Oct, Okp, OkpCurves, Rsa};

/// Information about a cryptographic key.
pub trait KeyInfo {
    /// Returns the strength of the key
    ///
    /// The units here is the number of bytes of a symmetric key. For
    /// example, a P-256 elliptic curve key has an approximate strength of
    /// `16` since it is comparable to a 16-byte symmetric key.
    fn strength(&self) -> usize;

    /// Tests if the provide algorithm is supported.
    fn is_supported(&self, algo: &Algorithm) -> bool;
}

impl<T: KeyInfo + ?Sized> KeyInfo for &T {
    fn strength(&self) -> usize {
        (**self).strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        (**self).is_supported(algo)
    }
}

impl<T: KeyInfo + ?Sized> KeyInfo for &mut T {
    fn strength(&self) -> usize {
        (**self).strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        (**self).is_supported(algo)
    }
}

impl<T: KeyInfo + ?Sized> KeyInfo for Box<T> {
    fn strength(&self) -> usize {
        self.deref().strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.deref().is_supported(algo)
    }
}

impl KeyInfo for Vec<u8> {
    fn strength(&self) -> usize {
        self.deref().strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.deref().is_supported(algo)
    }
}

impl KeyInfo for [u8] {
    fn strength(&self) -> usize {
        self.len()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            // Signing algorithms (HMAC)
            (Signing(Hs256), 16..)
                | (Signing(Hs384), 24..)
                | (Signing(Hs512), 32..)
                // Sealing algorithms (AES Key Wrap)
                | (Sealing(A128Kw), 16..)
                | (Sealing(A192Kw), 24..)
                | (Sealing(A256Kw), 32..)
                | (Sealing(A128GcmKw), 16..)
                | (Sealing(A192GcmKw), 24..)
                | (Sealing(A256GcmKw), 32..)
                // Direct key agreement (key is the CEK)
                | (Sealing(Dir), 1..)
        )
    }
}

impl KeyInfo for Jwk {
    fn strength(&self) -> usize {
        self.key.strength()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        self.key.is_supported(algo) && algo == self.prm.alg.as_ref().unwrap_or(algo)
    }
}

impl KeyInfo for Key {
    fn strength(&self) -> usize {
        match self {
            Key::Ec(x) => x.strength(),
            Key::Rsa(x) => x.strength(),
            Key::Oct(x) => x.strength(),
            Key::Okp(x) => x.strength(),
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        match self {
            Key::Ec(x) => x.is_supported(algo),
            Key::Rsa(x) => x.is_supported(algo),
            Key::Oct(x) => x.is_supported(algo),
            Key::Okp(x) => x.is_supported(algo),
        }
    }
}

impl KeyInfo for Ec {
    fn strength(&self) -> usize {
        match self.crv {
            EcCurves::P256 => 16,
            EcCurves::P256K => 16,
            EcCurves::P384 => 24,
            EcCurves::P521 => 32,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (self.crv, algo),
            // Signing algorithms
            (EcCurves::P256, Signing(Es256))
                | (EcCurves::P256K, Signing(Es256K))
                | (EcCurves::P384, Signing(Es384))
                | (EcCurves::P521, Signing(Es512))
                // Sealing algorithms (ECDH key agreement) - all NIST curves support ECDH
                | (EcCurves::P256, Sealing(EcdhEs))
                | (EcCurves::P256, Sealing(EcdhEsA128Kw))
                | (EcCurves::P256, Sealing(EcdhEsA192Kw))
                | (EcCurves::P256, Sealing(EcdhEsA256Kw))
                | (EcCurves::P256K, Sealing(EcdhEs))
                | (EcCurves::P256K, Sealing(EcdhEsA128Kw))
                | (EcCurves::P256K, Sealing(EcdhEsA192Kw))
                | (EcCurves::P256K, Sealing(EcdhEsA256Kw))
                | (EcCurves::P384, Sealing(EcdhEs))
                | (EcCurves::P384, Sealing(EcdhEsA128Kw))
                | (EcCurves::P384, Sealing(EcdhEsA192Kw))
                | (EcCurves::P384, Sealing(EcdhEsA256Kw))
                | (EcCurves::P521, Sealing(EcdhEs))
                | (EcCurves::P521, Sealing(EcdhEsA128Kw))
                | (EcCurves::P521, Sealing(EcdhEsA192Kw))
                | (EcCurves::P521, Sealing(EcdhEsA256Kw))
        )
    }
}

impl KeyInfo for Oct {
    fn strength(&self) -> usize {
        self.k.len()
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            // Signing algorithms (HMAC)
            (Signing(Hs256), 16..)
                | (Signing(Hs384), 24..)
                | (Signing(Hs512), 32..)
                // Sealing algorithms (AES Key Wrap)
                | (Sealing(A128Kw), 16..)
                | (Sealing(A192Kw), 24..)
                | (Sealing(A256Kw), 32..)
                | (Sealing(A128GcmKw), 16..)
                | (Sealing(A192GcmKw), 24..)
                | (Sealing(A256GcmKw), 32..)
                // Direct key agreement (key is the CEK)
                | (Sealing(Dir), 1..)
        )
    }
}

impl KeyInfo for Okp {
    fn strength(&self) -> usize {
        match self.crv {
            OkpCurves::Ed25519 => 16,
            OkpCurves::Ed448 => 24,
            OkpCurves::X25519 => 16,
            OkpCurves::X448 => 24,
        }
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (self.crv, algo),
            // Signing algorithms (EdDSA)
            (OkpCurves::Ed25519, Signing(EdDsa))
                | (OkpCurves::Ed25519, Signing(Ed25519))
                | (OkpCurves::Ed448, Signing(EdDsa))
                | (OkpCurves::Ed448, Signing(Ed448))
                // Sealing algorithms (ECDH key agreement) - X25519/X448 are for ECDH only
                | (OkpCurves::X25519, Sealing(EcdhEs))
                | (OkpCurves::X25519, Sealing(EcdhEsA128Kw))
                | (OkpCurves::X25519, Sealing(EcdhEsA192Kw))
                | (OkpCurves::X25519, Sealing(EcdhEsA256Kw))
                | (OkpCurves::X448, Sealing(EcdhEs))
                | (OkpCurves::X448, Sealing(EcdhEsA128Kw))
                | (OkpCurves::X448, Sealing(EcdhEsA192Kw))
                | (OkpCurves::X448, Sealing(EcdhEsA256Kw))
        )
    }
}

impl KeyInfo for Rsa {
    fn strength(&self) -> usize {
        self.n.len() / 16
    }

    fn is_supported(&self, algo: &Algorithm) -> bool {
        matches!(
            (algo, self.strength()),
            // Signing algorithms (RSA PKCS1 and PSS)
            (Signing(Rs256), 16..)
                | (Signing(Rs384), 24..)
                | (Signing(Rs512), 32..)
                | (Signing(Ps256), 16..)
                | (Signing(Ps384), 24..)
                | (Signing(Ps512), 32..)
                // Sealing algorithms (RSA-OAEP)
                | (Sealing(RsaOaep), 16..)
                | (Sealing(RsaOaep256), 16..)
        )
    }
}
