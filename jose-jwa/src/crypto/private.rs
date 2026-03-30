//! Private traits for compile-time algorithm mapping.
//!
//! These traits are sealed (private to the crate) to prevent external implementations.

use crate::{Encryption, Signing};

/// Private trait for encryption algorithms.
pub trait EncryptionAlgorithm {
    /// The content encryption algorithm identifier.
    const ENC: Encryption;
}

/// Private trait for signing algorithms.
pub trait SigningAlgorithm {
    /// The signing algorithm identifier.
    const ALG: Signing;
}
