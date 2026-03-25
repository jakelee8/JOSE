//! JWE Header Types
//!
//! This module provides types for JWE header parameters per RFC 7516 and RFC 7518.
//!
//! # Security Considerations
//!
//! Implementations of JWE encryption/decryption MUST validate the following:
//!
//! ## ECDH Ephemeral Public Key Protection
//!
//! Per RFC 7518 Section 4.6.1.1, for ECDH key agreement algorithms
//! (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW),
//! the ephemeral public key (`epk`) MUST be integrity-protected,
//! meaning it MUST appear in the protected header.
//!
//! ## PBES2 Parameters
//!
//! Per RFC 7518 Section 4.8.1:
//! - `p2s` (salt) MUST be at least 8 octets
//! - `p2c` (iteration count) SHOULD be >= 1000, RECOMMENDED >= 10000
//!
//! ## Critical Header Parameters
//!
//! Per RFC 7516 Section 4.1.11, if a JWE contains a `crit` parameter,
//! implementations MUST verify that they understand all parameters listed.
//!
//! These validations should be performed in the concrete Encryptor/Decryptor
//! trait implementations, not at the type level, since they depend on the
//! specific cryptographic algorithm being used.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use jose_b64::base64ct::Base64;
use jose_b64::serde::Bytes;
use jose_jwa::{Encryption, KeyManagement};
use jose_jwk::{Jwk, Thumbprint};
use serde::{Deserialize, Serialize};

/// Compression Algorithms
///
/// Per RFC 7516 Section 4.1.3, the only registered value is "DEF" (deflate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Compression {
    /// Deflate compression algorithm
    #[serde(rename = "DEF")]
    Deflate,
}

/// JWE Protected Header
///
/// Contains header parameters that are integrity-protected via the AEAD tag.
/// Per RFC 7516, this is the Base64url-encoded JSON object before the first `.`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protected<U = Unprotected> {
    /// Key Management Mode (`alg`)
    ///
    /// Per RFC 7516 Section 4.1.1, this parameter identifies the cryptographic
    /// mode used to encrypt or determine the Content Encryption Key (CEK).
    /// REQUIRED and MUST be integrity-protected per RFC 8725.
    pub alg: KeyManagement,

    /// Content Encryption Algorithm (`enc`)
    ///
    /// Per RFC 7516 Section 4.1.2, this parameter identifies the content
    /// encryption algorithm used on the plaintext.
    /// REQUIRED and MUST be integrity-protected per RFC 8725.
    pub enc: Encryption,

    /// Compression Algorithm (`zip`)
    ///
    /// Per RFC 7516 Section 4.1.3. Only "DEF" (deflate) is currently registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<Compression>,

    /// Critical Header Parameters (`crit`)
    ///
    /// Per RFC 7516 Section 4.1.11, indicates header parameters that MUST
    /// be understood and processed by the implementation.
    ///
    /// # Security
    ///
    /// Per RFC 7516 Section 4.1.11, if a JWE contains a `crit` parameter,
    /// the application MUST verify that it understands all parameters listed.
    /// Failure to validate can result in security vulnerabilities if critical
    /// extensions are ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,

    /// Nonce (`nonce`)
    ///
    /// Per RFC 8555 Section 6.5.2, used for ACME and similar protocols.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Ephemeral Public Key (`epk`)
    ///
    /// Per RFC 7518 Section 4.6.1.1, REQUIRED for ECDH algorithms.
    ///
    /// # Security
    ///
    /// Per RFC 7518 Section 4.6.1.1, for ECDH key agreement algorithms
    /// (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW),
    /// the ephemeral public key (`epk`) MUST be integrity-protected,
    /// meaning it MUST appear in the protected header.
    ///
    /// This is critical because if the ephemeral public key is not integrity-protected,
    /// an attacker could modify it, causing the derived key to be compromised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Jwk>,

    /// Agreement PartyUInfo (`apu`)
    ///
    /// Per RFC 7518 Section 4.6.1.2, used in ECDH-ES Concat KDF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<Bytes>,

    /// Agreement PartyVInfo (`apv`)
    ///
    /// Per RFC 7518 Section 4.6.1.3, used in ECDH-ES Concat KDF.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<Bytes>,

    /// PBES2 Salt Input (`p2s`)
    ///
    /// Per RFC 7518 Section 4.8.1.1, REQUIRED for PBES2 algorithms.
    ///
    /// # Security
    ///
    /// Per RFC 7518 Section 4.8.1, the salt MUST be at least 8 octets.
    /// Implementations MUST validate this minimum length.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2s: Option<Bytes>,

    /// PBES2 Count (`p2c`)
    ///
    /// Per RFC 7518 Section 4.8.1.2, REQUIRED for PBES2 algorithms.
    ///
    /// # Security
    ///
    /// Per RFC 7518 Section 4.8.1, a minimum iteration count of 1000 is
    /// RECOMMENDED. Per RFC 8725 Section 3.1, higher values (typically >= 10000)
    /// are recommended for production.
    ///
    /// This is a JSON integer (`i64`). Callers MUST validate the value is positive
    /// and fits in `u32` before passing it to the PBKDF2 function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p2c: Option<i64>,

    /// Initialization Vector (`iv`)
    ///
    /// Per RFC 7518 Section 4.7.1, for AES-GCM Key Wrapping (not content encryption).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<Bytes>,

    /// Authentication Tag (`tag`)
    ///
    /// Per RFC 7518 Section 4.7.2, for AES-GCM Key Wrapping (not content encryption).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Bytes>,

    /// Extension point for additional protected header parameters.
    #[serde(flatten)]
    pub oth: U,
}

impl<U: Default> Default for Protected<U> {
    fn default() -> Self {
        Self {
            alg: KeyManagement::Dir,
            enc: Encryption::A128Gcm,
            zip: None,
            crit: None,
            nonce: None,
            epk: None,
            apu: None,
            apv: None,
            p2s: None,
            p2c: None,
            iv: None,
            tag: None,
            oth: U::default(),
        }
    }
}

impl<U> Deref for Protected<U> {
    type Target = U;

    fn deref(&self) -> &Self::Target {
        &self.oth
    }
}

impl<U> DerefMut for Protected<U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.oth
    }
}

/// JWE Unprotected Header
///
/// Contains header parameters that are NOT integrity-protected.
/// Used for per-recipient headers in JSON serialization.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Unprotected {
    /// JWK Set URL (`jku`)
    ///
    /// Per RFC 7516 Section 4.1.4, a URI that refers to a resource for a set of JWKs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// JSON Web Key (`jwk`)
    ///
    /// Per RFC 7516 Section 4.1.5. SECURITY: MUST NOT be trusted from unprotected header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// Key ID (`kid`)
    ///
    /// Per RFC 7516 Section 4.1.6, used to match a specific key in a JWK Set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// X.509 URL (`x5u`)
    ///
    /// Per RFC 7516 Section 4.1.7, a URI that refers to a resource for an X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 Certificate Chain (`x5c`)
    ///
    /// Per RFC 7516 Section 4.1.8. Note: Uses standard Base64 (not Base64url) encoding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<Bytes<Box<[u8]>, Base64>>>, // base64, not base64url

    /// X.509 Certificate Thumbprint (`x5t` / `x5t#S256`)
    ///
    /// Per RFC 7516 Section 4.1.9-10, for key identification.
    #[serde(flatten)]
    pub x5t: Thumbprint,

    /// Type (`typ`)
    ///
    /// Per RFC 7516 Section 4.1.11, used to declare the media type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content Type (`cty`)
    ///
    /// Per RFC 7516 Section 4.1.12, used to declare the media type of the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;

    use super::*;

    #[test]
    fn protected_deref() {
        let protected: Protected = Protected {
            alg: KeyManagement::Dir,
            enc: Encryption::A128Gcm,
            ..Default::default()
        };
        // Test Deref - should be able to access oth fields via Protected
        assert!(protected.jku.is_none()); // Unprotected field via Deref
        assert_eq!(protected.enc, Encryption::A128Gcm);
    }

    #[test]
    fn protected_deref_mut() {
        let mut protected: Protected = Protected::default();
        // Test DerefMut - should be able to modify oth fields via Protected
        protected.jku = Some(String::from("https://example.com/jwks"));
        assert_eq!(
            protected.jku,
            Some(String::from("https://example.com/jwks"))
        );
    }

    #[test]
    fn protected_default() {
        let protected: Protected = Protected::default();
        // alg and enc are now required, so they have default values
        assert_eq!(protected.alg, KeyManagement::Dir);
        assert_eq!(protected.enc, Encryption::A128Gcm);
        assert!(protected.zip.is_none());
        assert!(protected.crit.is_none());
        assert!(protected.epk.is_none());
        assert!(protected.jku.is_none()); // Unprotected field via Deref
    }

    #[test]
    fn unprotected_default() {
        let unprotected: Unprotected = Unprotected::default();
        assert!(unprotected.jku.is_none());
        assert!(unprotected.jwk.is_none());
        assert!(unprotected.kid.is_none());
    }
}
