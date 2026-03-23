// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Sealing (key management) algorithms for JWE "alg" header (RFC 7518 Section 4.1).
//!
//! These algorithms protect the Content Encryption Key (CEK).

use core::fmt;

use serde::{Deserialize, Serialize};

/// Sealing (key management) algorithms for JWE "alg" header (RFC 7518 Section 4.1).
///
/// These algorithms protect the Content Encryption Key (CEK).
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Sealing {
    /// RSAES-PKCS1-v1_5 (VULNERABLE - DO NOT USE IN PRODUCTION)
    ///
    /// SECURITY WARNING: This algorithm is vulnerable to Bleichenbacher's
    /// Million Message Attack. Use `RsaOaep` or `RsaOaep256` instead.
    /// Only available with `legacy-rsa1_5` feature flag.
    #[cfg(feature = "legacy-rsa1_5")]
    #[deprecated(
        note = "RSA1_5 is vulnerable to Bleichenbacher's attack. Use RsaOaep or RsaOaep256 instead."
    )]
    #[serde(rename = "RSA1_5")]
    Rsa1_5,

    /// RSA-OAEP with SHA-1 (Recommended per RFC 7518)
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,

    /// RSA-OAEP with SHA-256 (Recommended)
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with 128-bit key (Recommended per RFC 7518)
    #[serde(rename = "A128KW")]
    A128Kw,

    /// AES Key Wrap with 192-bit key (Optional)
    #[serde(rename = "A192KW")]
    A192Kw,

    /// AES Key Wrap with 256-bit key (Recommended per RFC 7518)
    #[serde(rename = "A256KW")]
    A256Kw,

    /// Direct use of shared symmetric key (Recommended per RFC 7518)
    ///
    /// SECURITY: Only for single-recipient JWE. Key must be dedicated
    /// to this purpose.
    #[serde(rename = "dir")]
    Dir,

    /// ECDH-ES direct key agreement (Recommended per RFC 7518)
    ///
    /// SECURITY: Ephemeral public key (`epk`) MUST be in protected header.
    #[serde(rename = "ECDH-ES")]
    EcdhEs,

    /// ECDH-ES with A128KW key wrapping (Recommended per RFC 7518)
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,

    /// ECDH-ES with A192KW key wrapping (Optional)
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,

    /// ECDH-ES with A256KW key wrapping (Recommended per RFC 7518)
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,

    /// AES GCM Key Wrap with 128-bit key (Optional)
    #[serde(rename = "A128GCMKW")]
    A128GcmKw,

    /// AES GCM Key Wrap with 192-bit key (Optional)
    #[serde(rename = "A192GCMKW")]
    A192GcmKw,

    /// AES GCM Key Wrap with 256-bit key (Optional)
    #[serde(rename = "A256GCMKW")]
    A256GcmKw,

    /// PBES2 with HMAC SHA-256 and A128KW (Optional)
    ///
    /// SECURITY: Iteration count (`p2c`) MUST be >= 1000, SHOULD be >= 10000.
    #[serde(rename = "PBES2-HS256+A128KW")]
    Pbes2Hs256A128Kw,

    /// PBES2 with HMAC SHA-384 and A192KW (Optional)
    #[serde(rename = "PBES2-HS384+A192KW")]
    Pbes2Hs384A192Kw,

    /// PBES2 with HMAC SHA-512 and A256KW (Optional)
    #[serde(rename = "PBES2-HS512+A256KW")]
    Pbes2Hs512A256Kw,
}

impl Sealing {
    /// Returns the string representation of this sealing algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            #[cfg(feature = "legacy-rsa1_5")]
            #[allow(deprecated)]
            Self::Rsa1_5 => "RSA1_5",
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
            Self::Dir => "dir",
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::A128GcmKw => "A128GCMKW",
            Self::A192GcmKw => "A192GCMKW",
            Self::A256GcmKw => "A256GCMKW",
            Self::Pbes2Hs256A128Kw => "PBES2-HS256+A128KW",
            Self::Pbes2Hs384A192Kw => "PBES2-HS384+A192KW",
            Self::Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
        }
    }
}

impl fmt::Display for Sealing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;
    use std::vec;

    use super::*;

    #[test]
    fn sealing_roundtrip() {
        use Sealing::*;

        let input = vec![
            RsaOaep,
            RsaOaep256,
            A128Kw,
            A192Kw,
            A256Kw,
            Dir,
            EcdhEs,
            EcdhEsA128Kw,
            EcdhEsA192Kw,
            EcdhEsA256Kw,
            A128GcmKw,
            A192GcmKw,
            A256GcmKw,
            Pbes2Hs256A128Kw,
            Pbes2Hs384A192Kw,
            Pbes2Hs512A256Kw,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["RSA-OAEP","RSA-OAEP-256","A128KW","A192KW","A256KW","dir","ECDH-ES","ECDH-ES+A128KW","ECDH-ES+A192KW","ECDH-ES+A256KW","A128GCMKW","A192GCMKW","A256GCMKW","PBES2-HS256+A128KW","PBES2-HS384+A192KW","PBES2-HS512+A256KW"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Sealing>>(&ser).expect("deserialization failed"),
            input
        );
    }
}
