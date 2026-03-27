//! RSA key types for signing and verification.
//!
//! This module provides concrete key types for RSA operations:
//! - [`RsaSigningKey`] - for creating signatures
//! - [`RsaVerifyingKey`] - for verifying signatures
//!
//! Supports both PKCS#1 v1.5 and PSS padding schemes for signing.

#![cfg(feature = "rsa")]

use alloc::vec::Vec;
use core::convert::Infallible;

use digest::Digest;
use jose_b64::serde::{Bytes, Secret};
use rsa::{
    BoxedUint, RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{SigningKey as Pkcs1v15SigningKey, VerifyingKey as Pkcs1v15VerifyingKey},
    pss::{SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::SignatureEncoding;

use crate::Signing;
use crate::crypto::{CipherError, Signer, SigningKey, Update, Verifier, VerifyingKey as VerifyingKeyTrait};

/// An RSA signing key.
pub struct RsaSigningKey {
    key: RsaPrivateKey,
    alg: Signing,
}

impl RsaSigningKey {
    /// Create a signing key from an RSA private key.
    pub fn new(key: RsaPrivateKey, alg: Signing) -> Result<Self, CipherError> {
        match alg {
            Signing::Rs256
            | Signing::Rs384
            | Signing::Rs512
            | Signing::Ps256
            | Signing::Ps384
            | Signing::Ps512 => Ok(Self { key, alg }),
            _ => Err(CipherError::UnsupportedAlgorithm),
        }
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        self.alg
    }

    /// Get the corresponding verifying key.
    pub fn verifying_key(&self) -> RsaVerifyingKey {
        RsaVerifyingKey {
            key: self.key.to_public_key(),
            alg: self.alg,
        }
    }

    /// Return the modulus (JWK `n` parameter).
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the public exponent (JWK `e` parameter).
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the private exponent (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        Secret::from(self.key.d().to_be_bytes().to_vec())
    }

    /// Return the first prime factor (JWK `p` parameter).
    pub fn p(&self) -> Option<Secret> {
        self.key
            .primes()
            .first()
            .map(|p| Secret::from(p.to_be_bytes().to_vec()))
    }

    /// Return the second prime factor (JWK `q` parameter).
    pub fn q(&self) -> Option<Secret> {
        self.key
            .primes()
            .get(1)
            .map(|q| Secret::from(q.to_be_bytes().to_vec()))
    }

    /// Return the first factor CRT exponent (JWK `dp` parameter).
    pub fn dp(&self) -> Option<Secret> {
        self.key
            .dp()
            .map(|dp| Secret::from(dp.to_be_bytes().to_vec()))
    }

    /// Return the second factor CRT exponent (JWK `dq` parameter).
    pub fn dq(&self) -> Option<Secret> {
        self.key
            .dq()
            .map(|dq| Secret::from(dq.to_be_bytes().to_vec()))
    }

    /// Return the first CRT coefficient (JWK `qi` parameter).
    pub fn qi(&self) -> Option<Secret> {
        self.key
            .qinv()
            .map(|qi| Secret::from(qi.retrieve().to_be_bytes().to_vec()))
    }
}

impl SigningKey for RsaSigningKey {
    type Signer<'a>
        = RsaSigner<'a>
    where
        Self: 'a;
    type Error = CipherError;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(RsaSigner {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(CipherError::UnsupportedAlgorithm),
            },
            key: &self.key,
            alg: self.alg,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<jose_b64::serde::Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data).map_err(|_| CipherError::Sign)?;
        signer.finish()
    }
}

impl VerifyingKeyTrait for RsaSigningKey {
    type Verifier<'a>
        = RsaVerifier
    where
        Self: 'a;
    type Error = CipherError;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaVerifier {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(CipherError::UnsupportedAlgorithm),
            },
            key: self.key.to_public_key(),
            alg: self.alg,
        })
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).map_err(|_| CipherError::Verify)?;
        verifier.finish(signature)
    }
}

/// An RSA verifying key.
pub struct RsaVerifyingKey {
    key: RsaPublicKey,
    alg: Signing,
}

impl RsaVerifyingKey {
    /// Create a verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey, alg: Signing) -> Result<Self, CipherError> {
        match alg {
            Signing::Rs256
            | Signing::Rs384
            | Signing::Rs512
            | Signing::Ps256
            | Signing::Ps384
            | Signing::Ps512 => Ok(Self { key, alg }),
            _ => Err(CipherError::UnsupportedAlgorithm),
        }
    }

    /// Get the signing algorithm.
    pub fn alg(&self) -> Signing {
        self.alg
    }

    /// Return the modulus (JWK `n` parameter).
    pub fn n(&self) -> Bytes {
        self.key.n().to_be_bytes_trimmed_vartime().into()
    }

    /// Return the public exponent (JWK `e` parameter).
    pub fn e(&self) -> Bytes {
        self.key.e().to_be_bytes_trimmed_vartime().into()
    }
}

impl VerifyingKeyTrait for RsaVerifyingKey {
    type Verifier<'a>
        = RsaVerifier
    where
        Self: 'a;
    type Error = CipherError;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaVerifier {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(CipherError::UnsupportedAlgorithm),
            },
            key: self.key.clone(),
            alg: self.alg,
        })
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).map_err(|_| CipherError::Verify)?;
        verifier.finish(signature)
    }
}

/// RSA signing state.
pub struct RsaSigner<'a> {
    digest: RsaDigest,
    key: &'a RsaPrivateKey,
    alg: Signing,
}

enum RsaDigest {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl<'a> Update for RsaSigner<'a> {
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        match &mut self.digest {
            RsaDigest::Sha256(d) => d.update(data.as_ref()),
            RsaDigest::Sha384(d) => d.update(data.as_ref()),
            RsaDigest::Sha512(d) => d.update(data.as_ref()),
        };
        Ok(())
    }
}

impl<'a> Signer for RsaSigner<'a> {
    type Error = CipherError;

    fn finish(self) -> Result<jose_b64::serde::Bytes, <Self as Signer>::Error> {
        let hash = match self.digest {
            RsaDigest::Sha256(d) => d.finalize().to_vec(),
            RsaDigest::Sha384(d) => d.finalize().to_vec(),
            RsaDigest::Sha512(d) => d.finalize().to_vec(),
        };

        let sig_bytes: Vec<u8> = match self.alg {
            Signing::Rs256 => {
                let key = Pkcs1v15SigningKey::<Sha256>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            Signing::Rs384 => {
                let key = Pkcs1v15SigningKey::<Sha384>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            Signing::Rs512 => {
                let key = Pkcs1v15SigningKey::<Sha512>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            Signing::Ps256 => {
                let key = PssSigningKey::<Sha256>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            Signing::Ps384 => {
                let key = PssSigningKey::<Sha384>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            Signing::Ps512 => {
                let key = PssSigningKey::<Sha512>::from(self.key.clone());
                key.sign_prehash(&hash).map_err(|_| CipherError::Sign)?.to_bytes().as_ref().to_vec()
            }
            _ => return Err(CipherError::UnsupportedAlgorithm),
        };

        Ok(sig_bytes.into())
    }
}

/// RSA verification state.
pub struct RsaVerifier {
    digest: RsaDigest,
    key: RsaPublicKey,
    alg: Signing,
}

impl Update for RsaVerifier {
    type Error = Infallible;

    fn update(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        match &mut self.digest {
            RsaDigest::Sha256(d) => d.update(data.as_ref()),
            RsaDigest::Sha384(d) => d.update(data.as_ref()),
            RsaDigest::Sha512(d) => d.update(data.as_ref()),
        };
        Ok(())
    }
}

impl Verifier for RsaVerifier {
    type Error = CipherError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error> {
        let hash = match self.digest {
            RsaDigest::Sha256(d) => d.finalize().to_vec(),
            RsaDigest::Sha384(d) => d.finalize().to_vec(),
            RsaDigest::Sha512(d) => d.finalize().to_vec(),
        };

        let sig = signature.as_ref();

        match self.alg {
            Signing::Rs256 => {
                let key = Pkcs1v15VerifyingKey::<Sha256>::from(self.key);
                let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            Signing::Rs384 => {
                let key = Pkcs1v15VerifyingKey::<Sha384>::from(self.key);
                let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            Signing::Rs512 => {
                let key = Pkcs1v15VerifyingKey::<Sha512>::from(self.key);
                let sig = rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            Signing::Ps256 => {
                let key = PssVerifyingKey::<Sha256>::from(self.key);
                let sig = rsa::pss::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            Signing::Ps384 => {
                let key = PssVerifyingKey::<Sha384>::from(self.key);
                let sig = rsa::pss::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            Signing::Ps512 => {
                let key = PssVerifyingKey::<Sha512>::from(self.key);
                let sig = rsa::pss::Signature::try_from(sig).map_err(|_| CipherError::InvalidKey)?;
                key.verify_prehash(&hash, &sig).map_err(|_| CipherError::Verify)
            }
            _ => Err(CipherError::UnsupportedAlgorithm),
        }
    }
}
