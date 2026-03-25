#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
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

extern crate alloc;

pub mod crypto;

mod compact;
mod head;

pub use head::{Protected, Unprotected};

use alloc::{vec, vec::Vec};
use jose_b64::serde::{Bytes, Json};
use serde::{Deserialize, Serialize};

/// A JSON Web Encryption representation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
#[serde(untagged)]
pub enum Jwe<U = Unprotected, P = Protected<U>> {
    /// General Serialization
    General(General<U, P>),

    /// Flattened Serialization
    Flattened(Flattened<U, P>),
}

impl<U, P> From<General<U, P>> for Jwe<U, P> {
    fn from(value: General<U, P>) -> Self {
        Jwe::General(value)
    }
}

impl<U, P> From<Flattened<U, P>> for Jwe<U, P> {
    fn from(value: Flattened<U, P>) -> Self {
        Jwe::Flattened(value)
    }
}

/// General Serialization (RFC 7516 Section 7.2.1)
///
/// Allows multiple recipients with different key management.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
pub struct General<U = Unprotected, P = Protected<U>> {
    /// The shared protected header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<Json<P>>,

    /// The shared unprotected header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<U>,

    /// The encrypted payload and associated cryptographic data.
    #[serde(flatten)]
    pub payload: Payload,

    /// The recipients
    pub recipients: Vec<Recipient<U>>,
}

impl<U, P> From<Flattened<U, P>> for General<U, P> {
    fn from(value: Flattened<U, P>) -> Self {
        Self {
            protected: value.protected,
            unprotected: value.unprotected,
            payload: value.payload,
            recipients: vec![value.recipient],
        }
    }
}

/// Flattened Serialization (RFC 7516 Section 7.2.2)
///
/// Compact representation for single recipient.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>, P: serde::de::DeserializeOwned"))]
pub struct Flattened<U = Unprotected, P = Protected<U>> {
    /// The protected header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<Json<P>>,

    /// The unprotected header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<U>,

    /// The encrypted payload and associated cryptographic data.
    #[serde(flatten)]
    pub payload: Payload,

    /// The recipient information
    #[serde(flatten)]
    pub recipient: Recipient<U>,
}

/// The encrypted payload returned by `Encryptor::finish()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// The initialization vector (for AES-GCM and AES-CBC)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv: Option<Bytes>,

    /// Additional authenticated data that was processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<Bytes>,

    /// The encrypted payload
    pub ciphertext: Bytes,

    /// The authentication tag (for AES-GCM and AES-CBC+HS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<Bytes>,
}

/// A Recipient (RFC 7516 Section 7.2.1)
///
/// Contains key management information for one recipient.
/// Note: Per RFC 7516, recipients do NOT have a `protected` field - only
/// `encrypted_key` and per-recipient `header` (unprotected).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "U: Deserialize<'de>"))]
pub struct Recipient<U = Unprotected> {
    /// The per-recipient unprotected header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<U>,

    /// The encrypted Content Encryption Key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<Bytes>,
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::prelude::rust_2021::*;

    use super::*;

    #[test]
    fn flattened_roundtrip() {
        let original: Flattened<Unprotected, Protected<Unprotected>> = Flattened {
            payload: Payload {
                iv: Some(Bytes::from(vec![1, 2, 3, 4])),
                ciphertext: Bytes::from(vec![5, 6, 7, 8]),
                tag: Some(Bytes::from(vec![9, 10, 11, 12])),
                aad: None,
            },
            protected: None,
            unprotected: None::<Unprotected>,
            recipient: Recipient {
                encrypted_key: Some(Bytes::from(vec![13, 14, 15, 16])),
                header: None,
            },
        };

        let json = serde_json::to_string(&original).expect("serialization failed");
        let deserialized: Flattened = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(original.payload.ciphertext, deserialized.payload.ciphertext);
        assert_eq!(original.payload.iv, deserialized.payload.iv);
        assert_eq!(original.payload.tag, deserialized.payload.tag);
    }

    #[test]
    fn general_roundtrip() {
        let original: General<Unprotected, Protected<Unprotected>> = General {
            payload: Payload {
                iv: Some(Bytes::from(vec![1, 2, 3, 4])),
                ciphertext: Bytes::from(vec![5, 6, 7, 8]),
                tag: Some(Bytes::from(vec![9, 10, 11, 12])),
                aad: None,
            },
            protected: None,
            unprotected: None::<Unprotected>,
            recipients: vec![Recipient {
                encrypted_key: Some(Bytes::from(vec![13, 14, 15, 16])),
                header: None,
            }],
        };

        let json = serde_json::to_string(&original).expect("serialization failed");
        let deserialized: General = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(original.payload.ciphertext, deserialized.payload.ciphertext);
        assert_eq!(original.recipients.len(), deserialized.recipients.len());
    }

    #[test]
    fn flattened_to_general() {
        let flattened = Flattened {
            payload: Payload {
                iv: Some(Bytes::from(vec![1, 2, 3, 4])),
                ciphertext: Bytes::from(vec![5, 6, 7, 8]),
                tag: Some(Bytes::from(vec![9, 10, 11, 12])),
                aad: None,
            },
            protected: None,
            unprotected: None::<Unprotected>,
            recipient: Recipient {
                encrypted_key: Some(Bytes::from(vec![13, 14, 15, 16])),
                header: None,
            },
        };

        let general: General = flattened.into();
        assert_eq!(general.recipients.len(), 1);
        assert_eq!(general.payload.ciphertext, Bytes::from(vec![5, 6, 7, 8]));
    }

    #[test]
    fn jwe_enum_roundtrip() {
        let flattened = Flattened {
            payload: Payload {
                iv: Some(Bytes::from(vec![1, 2, 3, 4])),
                ciphertext: Bytes::from(vec![5, 6, 7, 8]),
                tag: Some(Bytes::from(vec![9, 10, 11, 12])),
                aad: None,
            },
            protected: None,
            unprotected: None::<Unprotected>,
            recipient: Recipient {
                encrypted_key: Some(Bytes::from(vec![13, 14, 15, 16])),
                header: None,
            },
        };

        let jwe: Jwe = flattened.into();
        let json = serde_json::to_string(&jwe).expect("serialization failed");
        let deserialized: Jwe = serde_json::from_str(&json).expect("deserialization failed");

        // Verify we got back a Flattened variant
        match deserialized {
            Jwe::Flattened(f) => {
                assert_eq!(f.payload.ciphertext, Bytes::from(vec![5, 6, 7, 8]));
            }
            _ => core::panic!("Expected Flattened variant"),
        }
    }

    #[test]
    fn compact_serialization_roundtrip() {
        // Create a JWE with minimal fields
        let original: Flattened = Flattened {
            payload: Payload {
                iv: Some(Bytes::from(vec![1, 2, 3, 4])),
                ciphertext: Bytes::from(vec![5, 6, 7, 8]),
                tag: Some(Bytes::from(vec![9, 10, 11, 12])),
                aad: None,
            },
            protected: None,
            unprotected: None::<Unprotected>,
            recipient: Recipient {
                encrypted_key: Some(Bytes::from(vec![13, 14, 15, 16])),
                header: None,
            },
        };

        // Serialize to compact format
        let compact = original.to_string();
        assert!(!compact.is_empty());
        assert!(compact.contains('.'));

        // Should have 5 parts separated by dots
        let parts: Vec<_> = compact.split('.').collect();
        assert_eq!(parts.len(), 5);
    }

    #[test]
    fn compact_deserialization() {
        // Create a valid compact JWE string
        // protected = {"alg":"A128KW","enc":"A128GCM"} base64url = eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0
        // encrypted_key = "test" base64url = dGVzdA
        // iv = "testiv" base64url = dGVzdGl2
        // ciphertext = "cipher" base64url = Y2lwaGVy
        // tag = "tag" base64url = dGFn
        let compact = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIn0.dGVzdA.dGVzdGl2.Y2lwaGVy.dGFn";

        let result: Result<Flattened, _> = compact.parse();
        assert!(
            result.is_ok(),
            "Failed to parse compact JWE: {:?}",
            result.err()
        );

        let flattened = result.unwrap();
        assert!(flattened.protected.is_some());
        assert_eq!(flattened.payload.ciphertext.as_ref(), b"cipher");
        assert_eq!(
            flattened.payload.iv.as_ref().map(|b| b.as_ref()),
            Some(&b"testiv"[..])
        );
        assert_eq!(
            flattened.payload.tag.as_ref().map(|b| b.as_ref()),
            Some(&b"tag"[..])
        );
        assert_eq!(
            flattened
                .recipient
                .encrypted_key
                .as_ref()
                .map(|b| b.as_ref()),
            Some(&b"test"[..])
        );
    }
}
