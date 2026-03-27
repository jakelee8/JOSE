// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::{Deserialize, Serialize};

#[cfg(any(
    feature = "aes-kw",
    feature = "aes-gcm",
    feature = "rsa",
    feature = "ecdh",
    feature = "pbes2"
))]
use crate::Signing;
#[cfg(any(
    feature = "aes-kw",
    feature = "aes-gcm",
    feature = "rsa",
    feature = "ecdh",
    feature = "pbes2"
))]
use crate::crypto::KeyManagement;

/// Possible types of algorithms that can exist in an "alg" descriptor.
///
/// Per RFC 7517 Section 4.4, the "alg" parameter indicates what a key is for:
/// - Signing algorithms: key signs/verifies data
/// - Key management modes: key encrypts/decrypts data
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// Algorithms used for digital signatures and MACs (RFC 7518 Section 3.1)
    Signing(Signing),
    /// Algorithms used for key management (RFC 7518 Section 4.1)
    #[cfg(any(
        feature = "aes-kw",
        feature = "aes-gcm",
        feature = "rsa",
        feature = "ecdh",
        feature = "pbes2"
    ))]
    KeyManagement(KeyManagement),
}

impl From<Signing> for Algorithm {
    #[inline]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

#[cfg(any(
    feature = "aes-kw",
    feature = "aes-gcm",
    feature = "rsa",
    feature = "ecdh",
    feature = "pbes2"
))]
impl From<KeyManagement> for Algorithm {
    #[inline]
    fn from(alg: KeyManagement) -> Self {
        Self::KeyManagement(alg)
    }
}
