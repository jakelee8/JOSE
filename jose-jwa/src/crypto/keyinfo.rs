//! Trait for querying key information.
//!
//! This module provides the [`KeyInfo`] trait which allows querying
//! algorithm and cryptographic strength information from key types.

use crate::{Encryption, Signing};

/// Trait for querying signing key information.
pub trait SigningKeyInfo {
    /// Returns the signing algorithm.
    fn sig(&self) -> Signing;
}

/// Trait for querying encryption key information.
pub trait EncryptionKeyInfo {
    /// Returns the encryption algorithm.
    fn enc(&self) -> Encryption;
}
