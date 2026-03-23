// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Content encryption algorithms for JWE "enc" header (RFC 7518 Section 5.1).
//!
//! NOTE: This is NOT part of `Algorithm` enum. Content encryption algorithms
//! appear in the JWE "enc" header, not in JWK "alg" parameter.

use core::fmt;

use serde::{Deserialize, Serialize};

/// Content encryption algorithms for JWE "enc" header (RFC 7518 Section 5.1).
///
/// NOTE: This is NOT part of `Algorithm` enum. Content encryption algorithms
/// appear in the JWE "enc" header, not in JWK "alg" parameter.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encryption {
    /// AES CBC with HMAC SHA-256 (Required per RFC 7518)
    /// Key size: 256 bits (128 for AES, 128 for HMAC)
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,

    /// AES CBC with HMAC SHA-384 (Optional)
    /// Key size: 384 bits (192 for AES, 192 for HMAC)
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,

    /// AES CBC with HMAC SHA-512 (Required per RFC 7518)
    /// Key size: 512 bits (256 for AES, 256 for HMAC)
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,

    /// AES GCM with 128-bit key (Recommended per RFC 7518)
    #[serde(rename = "A128GCM")]
    A128Gcm,

    /// AES GCM with 192-bit key (Optional)
    #[serde(rename = "A192GCM")]
    A192Gcm,

    /// AES GCM with 256-bit key (Recommended per RFC 7518)
    #[serde(rename = "A256GCM")]
    A256Gcm,
}

impl Encryption {
    /// Returns the string representation of this encryption algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }
}

impl fmt::Display for Encryption {
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
    fn encryption_roundtrip() {
        use Encryption::*;

        let input = vec![
            A128CbcHs256,
            A192CbcHs384,
            A256CbcHs512,
            A128Gcm,
            A192Gcm,
            A256Gcm,
        ];
        let ser = serde_json::to_string(&input).expect("serialization failed");

        assert_eq!(
            ser,
            r#"["A128CBC-HS256","A192CBC-HS384","A256CBC-HS512","A128GCM","A192GCM","A256GCM"]"#
        );

        assert_eq!(
            serde_json::from_str::<Vec<Encryption>>(&ser).expect("deserialization failed"),
            input
        );
    }
}
