//! RSA key types for signing, verification, and encryption.
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
    RsaPrivateKey, RsaPublicKey,
    pkcs1v15::{SigningKey as Pkcs1v15SigningKey, VerifyingKey as Pkcs1v15VerifyingKey},
    pss::{SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sha2::{Sha256, Sha384, Sha512};
use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::rand_core::TryCryptoRng;

use crate::Signing;
use crate::crypto::{Signer, SigningKey, Update, Verifier, VerifyingKey as VerifyingKeyTrait};

/// An RSA signing key.
///
/// This type wraps an RSA private key and implements [`SigningKey`]
/// for both PKCS#1 v1.5 and PSS padding schemes.
pub struct RsaSigningKey {
    key: RsaPrivateKey,
    alg: Signing,
}

impl RsaSigningKey {
    /// Create a signing key from an RSA private key.
    pub fn new(key: RsaPrivateKey, alg: Signing) -> Result<Self, RsaError> {
        match alg {
            Signing::Rs256
            | Signing::Rs384
            | Signing::Rs512
            | Signing::Ps256
            | Signing::Ps384
            | Signing::Ps512 => {}
            _ => return Err(RsaError::InvalidAlgorithm),
        }

        Ok(Self { key, alg })
    }

    /// Create from PKCS#8 DER-encoded private key.
    pub fn from_pkcs8_der(der: impl AsRef<[u8]>, alg: Signing) -> Result<Self, RsaError> {
        let key = RsaPrivateKey::from_pkcs8_der(der.as_ref()).map_err(|_| RsaError::InvalidKey)?;
        Self::new(key, alg)
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

    /// Export the public modulus (n).
    pub fn to_modulus(&self) -> Bytes {
        self.key.n().to_bytes_be().into()
    }

    /// Export the public exponent (e).
    pub fn to_public_exponent(&self) -> Bytes {
        self.key.e().to_bytes_be().into()
    }

    /// Export the private exponent (d).
    pub fn to_private_exponent(&self) -> Secret {
        Secret::from(self.key.d().to_bytes_be().to_vec())
    }

    /// Export the first prime factor (p).
    pub fn to_prime_p(&self) -> Option<Secret> {
        self.key
            .primes()
            .get(0)
            .map(|p| Secret::from(p.to_bytes_be().to_vec()))
    }

    /// Export the second prime factor (q).
    pub fn to_prime_q(&self) -> Option<Secret> {
        self.key
            .primes()
            .get(1)
            .map(|q| Secret::from(q.to_bytes_be().to_vec()))
    }

    /// Export the first factor CRT exponent (dp = d mod (p-1)).
    pub fn to_crt_dp(&self) -> Option<Secret> {
        self.key
            .dp()
            .map(|dp| Secret::from(dp.to_bytes_be().to_vec()))
    }

    /// Export the second factor CRT exponent (dq = d mod (q-1)).
    pub fn to_crt_dq(&self) -> Option<Secret> {
        self.key
            .dq()
            .map(|dq| Secret::from(dq.to_bytes_be().to_vec()))
    }

    /// Export the first CRT coefficient (qi = q⁻¹ mod p).
    pub fn to_crt_qi(&self) -> Option<Secret> {
        self.key
            .qinv()
            .map(|qi| Secret::from(qi.to_bytes_be().to_vec()))
    }
}

impl SigningKey for RsaSigningKey {
    type Signer<'a>
        = RsaSigner<'a>
    where
        Self: 'a;
    type Error = RsaError;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error> {
        Ok(RsaSigner {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(RsaError::InvalidAlgorithm),
            },
            key: &self.key,
            alg: self.alg,
        })
    }

    fn sign(&self, data: impl AsRef<[u8]>) -> Result<jose_b64::serde::Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data).map_err(|_| RsaError::SigningFailed)?;
        signer.finish()
    }
}

impl VerifyingKeyTrait for RsaSigningKey {
    type Verifier<'a>
        = RsaVerifier<'a>
    where
        Self: 'a;
    type Error = RsaError;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaVerifier {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(RsaError::InvalidAlgorithm),
            },
            key: self.key.to_public_key(),
            alg: self.alg,
        })
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).map_err(|_| RsaError::VerificationFailed)?;
        verifier.finish(signature)
    }
}

/// An RSA verifying key.
///
/// This type wraps an RSA public key and implements [`VerifyingKey`]
/// for both PKCS#1 v1.5 and PSS padding schemes.
pub struct RsaVerifyingKey {
    key: RsaPublicKey,
    alg: Signing,
}

impl RsaVerifyingKey {
    /// Create a verifying key from an RSA public key.
    pub fn new(key: RsaPublicKey, alg: Signing) -> Result<Self, RsaError> {
        match alg {
            Signing::Rs256
            | Signing::Rs384
            | Signing::Rs512
            | Signing::Ps256
            | Signing::Ps384
            | Signing::Ps512 => {}
            _ => return Err(RsaError::InvalidAlgorithm),
        }

        Ok(Self { key, alg })
    }

    /// Create from SPKI DER-encoded public key.
    pub fn from_spki_der(der: impl AsRef<[u8]>, alg: Signing) -> Result<Self, RsaError> {
        let key =
            RsaPublicKey::from_public_key_der(der.as_ref()).map_err(|_| RsaError::InvalidKey)?;
        Self::new(key, alg)
    }

    /// Export the modulus (n).
    pub fn to_modulus(&self) -> Vec<u8> {
        self.key.n().to_bytes_be().to_vec()
    }

    /// Export the public exponent (e).
    pub fn to_exponent(&self) -> Vec<u8> {
        self.key.e().to_bytes_be().to_vec()
    }
}

impl VerifyingKeyTrait for RsaVerifyingKey {
    type Verifier<'a>
        = RsaVerifier<'a>
    where
        Self: 'a;
    type Error = RsaError;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error> {
        Ok(RsaVerifier {
            digest: match self.alg {
                Signing::Rs256 | Signing::Ps256 => RsaDigest::Sha256(Sha256::new()),
                Signing::Rs384 | Signing::Ps384 => RsaDigest::Sha384(Sha384::new()),
                Signing::Rs512 | Signing::Ps512 => RsaDigest::Sha512(Sha512::new()),
                _ => return Err(RsaError::InvalidAlgorithm),
            },
            key: &self.key,
            alg: self.alg,
        })
    }

    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        let mut verifier = self.verifier()?;
        verifier.update(data).map_err(|_| RsaError::VerificationFailed)?;
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
    type Error = RsaError;

    fn finish(self) -> Result<jose_b64::serde::Bytes, <Self as Signer>::Error> {
        let hash = match self.digest {
            RsaDigest::Sha256(d) => d.finalize().to_vec(),
            RsaDigest::Sha384(d) => d.finalize().to_vec(),
            RsaDigest::Sha512(d) => d.finalize().to_vec(),
        };

        let sig = match self.alg {
            Signing::Rs256 => {
                let key = Pkcs1v15SigningKey::<Sha256>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            Signing::Rs384 => {
                let key = Pkcs1v15SigningKey::<Sha384>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            Signing::Rs512 => {
                let key = Pkcs1v15SigningKey::<Sha512>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            Signing::Ps256 => {
                let key = PssSigningKey::<Sha256>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            Signing::Ps384 => {
                let key = PssSigningKey::<Sha384>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            Signing::Ps512 => {
                let key = PssSigningKey::<Sha512>::from(self.key.clone());
                key.sign_prehash(&hash)
                    .map_err(|_| RsaError::SigningFailed)?
            }
            _ => return Err(RsaError::InvalidAlgorithm),
        };

        Ok(sig.to_vec().into())
    }
}

/// RSA verification state.
pub struct RsaVerifier<'a> {
    digest: RsaDigest,
    key: &'a RsaPublicKey,
    alg: Signing,
}

impl<'a> Update for RsaVerifier<'a> {
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

impl<'a> Verifier for RsaVerifier<'a> {
    type Error = RsaError;

    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error> {
        let hash = match self.digest {
            RsaDigest::Sha256(d) => d.finalize().to_vec(),
            RsaDigest::Sha384(d) => d.finalize().to_vec(),
            RsaDigest::Sha512(d) => d.finalize().to_vec(),
        };

        let sig = signature.as_ref();

        match self.alg {
            Signing::Rs256 => {
                let key = Pkcs1v15VerifyingKey::<Sha256>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            Signing::Rs384 => {
                let key = Pkcs1v15VerifyingKey::<Sha384>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            Signing::Rs512 => {
                let key = Pkcs1v15VerifyingKey::<Sha512>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            Signing::Ps256 => {
                let key = PssVerifyingKey::<Sha256>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            Signing::Ps384 => {
                let key = PssVerifyingKey::<Sha384>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            Signing::Ps512 => {
                let key = PssVerifyingKey::<Sha512>::from(self.key.clone());
                key.verify_prehash(&hash, sig)
                    .map_err(|_| RsaError::VerificationFailed)
            }
            _ => Err(RsaError::InvalidAlgorithm),
        }
    }
}

/// RSA-specific errors.
#[derive(Debug)]
pub enum RsaError {
    /// Invalid key format.
    InvalidKey,
    /// Invalid algorithm for RSA operation.
    InvalidAlgorithm,
    /// Signing operation failed.
    SigningFailed,
    /// Verification failed.
    VerificationFailed,
    /// Encryption failed.
    EncryptionFailed,
    /// Decryption failed.
    DecryptionFailed,
}

impl core::fmt::Display for RsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKey => f.write_str("invalid RSA key"),
            Self::InvalidAlgorithm => f.write_str("invalid algorithm for RSA"),
            Self::SigningFailed => f.write_str("RSA signing failed"),
            Self::VerificationFailed => f.write_str("RSA verification failed"),
            Self::EncryptionFailed => f.write_str("RSA encryption failed"),
            Self::DecryptionFailed => f.write_str("RSA decryption failed"),
        }
    }
}

impl core::error::Error for RsaError {}
