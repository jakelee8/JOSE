// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(any(
    feature = "aes-cbc-hmac",
    feature = "aes-gcm",
    feature = "aes-kw",
    feature = "ecdh",
    feature = "hmac",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "k256",
    feature = "rsa"
))]
extern crate alloc;

mod alg;
/// Cryptographic operations and key types.
///
/// This module provides concrete implementations of:
/// - Signing and verification keys
/// - Content encryption/decryption
/// - Key wrapping/unwrapping
/// - Cryptographic traits for algorithm abstraction
pub mod crypto;
mod enc;
mod error;
mod sign;

pub use self::alg::*;
#[cfg(any(
    feature = "aes-gcm",
    feature = "aes-kw",
    feature = "ecdh",
    feature = "pbes2",
    feature = "rsa"
))]
pub use self::crypto::KeyManagement;
pub use self::enc::*;
pub use self::error::Error;
pub use self::sign::*;
