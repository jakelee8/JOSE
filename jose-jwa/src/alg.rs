// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Algorithm type that combines signing and sealing algorithms.

use serde::{Deserialize, Serialize};

use crate::{Sealing, Signing};

/// Possible types of algorithms that can exist in an "alg" descriptor.
///
/// Per RFC 7517 Section 4.4, the "alg" parameter indicates what a key is for:
/// - Signing algorithms: key signs/verifies data
/// - Sealing algorithms: key seals/recovers CEK
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Algorithm {
    /// Algorithms used for digital signatures and MACs (RFC 7518 Section 3.1)
    Signing(Signing),
    /// Algorithms used for key management/sealing (RFC 7518 Section 4.1)
    Sealing(Sealing),
}

impl From<Signing> for Algorithm {
    #[inline]
    fn from(alg: Signing) -> Self {
        Self::Signing(alg)
    }
}

impl From<Sealing> for Algorithm {
    #[inline]
    fn from(alg: Sealing) -> Self {
        Self::Sealing(alg)
    }
}
