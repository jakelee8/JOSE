//! JWE Cryptographic Implementation
//!
//! This module provides traits for JWE encryption and decryption operations.
//!
//! # Encryption
//!
//! - [`Encryptor`]: Trait for content encryption state (encrypts plaintext)
//! - [`EncryptingKey`]: Trait for keys that can encrypt JWEs
//!
//! # Decryption
//!
//! - [`Decryptor`]: Trait for content decryption state (decrypts ciphertext)
//! - [`DecryptingKey`]: Trait for keys that can decrypt JWEs
//!
//! # Multiple Keys
//!
//! The library supports decrypting JWEs with multiple keys:
//! - `Vec<T>` where `T: Decryptor`: Tries decryptors in sequence
//! - `[T]` where `T: DecryptingKey`: Tries each key in sequence

use alloc::vec::Vec;

use jose_b64::stream::Update;
use zeroize::Zeroizing;

use crate::{Flattened, General, Jwe, Payload, Protected, Recipient, Unprotected};

/// Ciphertext creation state (content encryption with CEK)
pub trait Encryptor<U = Unprotected, P = Protected<U>>: Update {
    /// Error type for finish operations.
    type FinishError: From<Self::Error>;

    /// Process Additional Authenticated Data (AAD).
    fn update_aad(&mut self, aad: &[u8]) -> Result<(), Self::Error>;

    /// Process Additional Authenticated Data (AAD) and return self for chaining.
    fn chain_aad(mut self, aad: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        self.update_aad(aad)?;
        Ok(self)
    }

    /// Finish processing plaintext and return the encrypted payload.
    fn finish(self) -> Result<Payload, Self::FinishError>;
}

/// An encryption key (handles both key management + content encryption)
pub trait EncryptingKey<'a, U = Unprotected, P = Protected<U>> {
    /// Error type for starting encryption.
    type StartError: From<<Self::Encryptor as Update>::Error>;

    /// The state object used during encryption.
    type Encryptor: Encryptor<U, P>;

    /// Begin the encryption process.
    fn encrypt(
        &'a self,
        prot: Option<P>,
        head: Option<U>,
    ) -> Result<Self::Encryptor, Self::StartError>;
}

/// Plaintext decryption state (content decryption with CEK)
pub trait Decryptor: Update {
    /// Error type for finish operations.
    type FinishError;

    /// Finish processing ciphertext and return plaintext.
    fn finish(self) -> Result<Zeroizing<Vec<u8>>, Self::FinishError>;
}

/// Error type for Decryptor Vec implementation when all decryptors fail.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllDecryptorsFailed;

impl core::fmt::Display for AllDecryptorsFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "all decryptors failed")
    }
}

impl core::error::Error for AllDecryptorsFailed {}

/// A decryption key (handles both key management + content decryption)
pub trait DecryptingKey<'a, T> {
    /// Error type for starting decryption.
    type StartError;

    /// The state object used during decryption.
    type Decryptor: Decryptor;

    /// Begin the decryption process.
    fn decrypt(&'a self, val: T) -> Result<Self::Decryptor, Self::StartError>;
}

impl<T: Decryptor> Decryptor for Vec<T> {
    type FinishError = AllDecryptorsFailed;

    fn finish(self) -> Result<Zeroizing<Vec<u8>>, Self::FinishError> {
        for decryptor in self {
            match decryptor.finish() {
                Ok(plaintext) => return Ok(plaintext),
                Err(_) => continue,
            }
        }
        Err(AllDecryptorsFailed)
    }
}

impl<'a, A, T, V> DecryptingKey<'a, A> for [T]
where
    T: DecryptingKey<'a, A, Decryptor = V>,
    V: Decryptor,
    V: Update,
    A: Copy,
{
    type StartError = T::StartError;
    type Decryptor = Vec<V>;

    fn decrypt(&'a self, val: A) -> Result<Self::Decryptor, Self::StartError> {
        let mut all = Vec::new();
        for key in self {
            all.push(key.decrypt(val)?);
        }
        Ok(all)
    }
}

impl<'a, T, U, P> DecryptingKey<'a, &'a Flattened<U, P>> for T
where
    T: DecryptingKey<'a, &'a Recipient<U>>,
{
    type StartError = T::StartError;
    type Decryptor = T::Decryptor;

    fn decrypt(
        &'a self,
        flattened: &'a Flattened<U, P>,
    ) -> Result<Self::Decryptor, Self::StartError> {
        self.decrypt(&flattened.recipient)
    }
}

impl<'a, T, U, P> DecryptingKey<'a, &'a General<U, P>> for T
where
    T: DecryptingKey<'a, &'a Recipient<U>>,
{
    type StartError = T::StartError;
    type Decryptor = Vec<T::Decryptor>;

    fn decrypt(&'a self, general: &'a General<U, P>) -> Result<Self::Decryptor, Self::StartError> {
        general
            .recipients
            .iter()
            .map(|recipient| self.decrypt(recipient))
            .collect()
    }
}

impl<'a, T, V, E, U, P> DecryptingKey<'a, &'a Jwe<U, P>> for T
where
    T: DecryptingKey<'a, &'a Flattened<U, P>, Decryptor = V, StartError = E>,
    T: DecryptingKey<'a, &'a General<U, P>, Decryptor = Vec<V>, StartError = E>,
    V: Decryptor,
{
    type StartError = E;
    type Decryptor = Vec<V>;

    fn decrypt(&'a self, jwe: &'a Jwe<U, P>) -> Result<Self::Decryptor, Self::StartError> {
        match jwe {
            Jwe::General(general) => self.decrypt(general),
            Jwe::Flattened(flattened) => self.decrypt(flattened).map(|v| alloc::vec![v]),
        }
    }
}
