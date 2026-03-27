//! ECDH-ES key agreement for JWE key management.
//!
//! Provides ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW algorithms
//! for P-256, P-384, and P-521 curves per RFC 7518 Section 4.6.

#![cfg(feature = "ecdh")]

use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;
use digest::{FixedOutputReset, OutputSizeUser};

use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes_kw::{AesKw, IV_LEN};
use digest::consts::U16;
use digest::typenum::Unsigned;
use elliptic_curve::ecdh::diffie_hellman;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{AffinePoint, CurveArithmetic, NonZeroScalar, PublicKey, SecretKey};
use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{UnwrappingKey, WrappedKey, WrappingKey};
use crate::CipherError;

/// ECDH-ES direct key agreement
pub type EcdhEs = EcdhEsDirect;
/// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
pub type EcdhEsA128Kw = EcdhEsKeyAgreement<Aes128>;
/// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
pub type EcdhEsA192Kw = EcdhEsKeyAgreement<Aes192>;
/// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
pub type EcdhEsA256Kw = EcdhEsKeyAgreement<Aes256>;

/// ECDH-ES direct key derivation result.
pub struct EcdhEsDirect {
    // Content encryption key derived from ECDH-ES + Concat KDF
    cek: Secret,
}

pub struct EcdhEsSenderKey<C>
where
    C: CurveArithmetic,
{
    secret: SecretKey<C>,
}

impl<C> From<SecretKey<C>> for EcdhEsSenderKey<C>
where
    C: CurveArithmetic,
{
    fn from(secret: SecretKey<C>) -> Self {
        Self { secret }
    }
}

pub struct EcdhEsKeyAgreement<C, A>
where
    C: CurveArithmetic,
{
    sender: EcdhEsSenderKey<C>,
    recipient_public: PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &'static [u8],
    _aes: PhantomData<A>,
}

impl<C, A> EcdhEsKeyAgreement<C, A>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    fn derive(
        sender_private_d: impl AsRef<[u8]>,
        recipient_public_x: impl AsRef<[u8]>,
        recipient_public_y: impl AsRef<[u8]>,
        keydatalen: usize,
        algorithm_id: impl AsRef<[u8]>,
        apu: Option<impl AsRef<[u8]>>,
        apv: Option<impl AsRef<[u8]>>,
    ) -> Result<Self, CipherError> {
        let secret_key = sender_private_d.as_ref().try_into()?;

        let public_key_x = recipient_public_x.as_ref().try_into()?;
        let public_key_y = recipient_public_y.as_ref().try_into()?;
        let public_key = AffinePoint::from_coordinates(&public_key_x, &public_key_y)
            .into_option()
            .ok_or(CipherError::InvalidKey)?;

        let z = diffie_hellman::<C>(&secret_key, &public_key);

        let derived = concat_kdf(
            z.raw_secret_bytes().as_slice(),
            keydatalen,
            algorithm_id,
            apu,
            apv,
        );

        Ok(Self {})
    }

    /// Generate a new ephemeral key pair.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, CipherError> {
        let mut secret_bytes = elliptic_curve::FieldBytes::<C>::default();
        rand_core::TryRng::try_fill_bytes(rng, &mut secret_bytes).map_err(|_| CipherError::Rng)?;
        let secret = SecretKey::from_bytes(&secret_bytes).map_err(|_| CipherError::InvalidKey)?;
        Ok(Self { secret })
    }

    /// Get the x-coordinate of the public key as bytes.
    ///
    /// This is used for constructing the JWK in the JWE header `epk` field.
    pub fn x(&self) -> Bytes
    where
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        C::FieldBytesSize: ModulusSize,
    {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let x = encoded.x().expect("public key has x-coordinate");
        x.to_vec().into()
    }

    /// Get the y-coordinate of the public key as bytes.
    ///
    /// This is used for constructing the JWK in the JWE header `epk` field.
    pub fn y(&self) -> Bytes
    where
        C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
        C::FieldBytesSize: ModulusSize,
    {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let y = encoded.y().expect("public key has y-coordinate");
        y.to_vec().into()
    }

    /// Get the raw secret key bytes.
    pub fn d(&self) -> Secret {
        self.secret.to_bytes().as_slice().to_vec().into()
    }
}

/// Concatenation KDF for ECDH-ES per RFC 7518 Section 4.6.2.
///
/// Uses SHA-256 as the hash function. Derives keying material of `keydatalen` bits.
fn concat_kdf(
    z: impl AsRef<[u8]>,
    keydatalen: usize,
    algorithm_id: impl AsRef<[u8]>,
    apu: Option<impl AsRef<[u8]>>,
    apv: Option<impl AsRef<[u8]>>,
) -> Vec<u8> {
    let z = z.as_ref();

    let algorithm_id = algorithm_id.as_ref();
    let algorithm_id_len = (algorithm_id.len() as u32).to_be_bytes();

    let apu = apu.as_ref().map(|s| s.as_ref()).unwrap_or(&[]);
    let apu_len = (apu.len() as u32).to_be_bytes();

    let apv = apv.as_ref().map(|s| s.as_ref()).unwrap_or(&[]);
    let apv_len = (apv.len() as u32).to_be_bytes();

    let mut derived = vec![0u8; (keydatalen + 7) / 8];
    let mut hasher = Sha256::new();

    let mut i = 1u32;
    for chunk in derived.chunks_mut(<Sha256 as OutputSizeUser>::OutputSize::USIZE) {
        hasher.update(&(i as u32).to_be_bytes());
        hasher.update(z);
        hasher.update(&algorithm_id_len);
        hasher.update(algorithm_id);
        hasher.update(&apu_len);
        hasher.update(apu);
        hasher.update(&apv_len);
        hasher.update(apv);
        // SuppPubInfo: keydatalen in bits as a 4-byte big-endian value
        hasher.update(&(keydatalen as u32).to_be_bytes());

        chunk.copy_from_slice(&hasher.finalize_reset()[..chunk.len()]);

        i += 1;
    }

    derived
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from RFC 7518 Appendix C - Example ECDH-ES Key Agreement Computation
    #[test]
    fn ecdh_es_p256_rfc7518_appendix_c() {
        let alice_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];
        let bob_d: [u8; 32] = [
            0x54, 0x49, 0x83, 0x66, 0x90, 0xd7, 0x5c, 0xaf, 0x29, 0xf0, 0xdd, 0x02, 0x9d, 0xdb,
            0x31, 0xb3, 0xdd, 0xb8, 0xab, 0xa9, 0xd2, 0xd5, 0x15, 0xc5, 0x01, 0x24, 0x65, 0xe8,
            0x17, 0xd4, 0xa9, 0xdc,
        ];
        let expected_z: [u8; 32] = [
            0x9e, 0x56, 0xd9, 0x1d, 0x81, 0x71, 0x35, 0xd3, 0x72, 0x83, 0x42, 0x83, 0xbf, 0x84,
            0x26, 0x9c, 0xfb, 0x31, 0x6e, 0xa3, 0xda, 0x80, 0x6a, 0x48, 0xf6, 0xda, 0xa7, 0x79,
            0x8c, 0xfe, 0x90, 0xc4,
        ];
        let expected_cek: [u8; 16] = [
            0x56, 0xaa, 0x8d, 0xea, 0xf8, 0x23, 0x6d, 0x20, 0x5c, 0x22, 0x28, 0xcd, 0x71, 0xa7,
            0x10, 0x1a,
        ];

        let alice_secret = SecretKey::<p256::NistP256>::from_slice(&alice_d).unwrap();
        let bob_secret = SecretKey::<p256::NistP256>::from_slice(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();

        // Create sender key from Alice's secret
        let alice_sender: EcdhEsSenderKey<p256::NistP256> = alice_secret.into();

        // Verify direct key derivation using EcdhEsDirect
        let direct = EcdhEsP256A128Gcm::new(
            &alice_sender,
            &bob_public,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        )
        .unwrap();
        assert_eq!(
            direct.cek().as_ref(),
            expected_cek,
            "Derived CEK does not match RFC 7518 expected value"
        );

        // Verify commutativity: Bob can derive the same shared secret
        let sender_public = SecretKey::<p256::NistP256>::from_slice(&alice_d)
            .unwrap()
            .public_key();
        let bob_recipient: EcdhEsRecipientKey<p256::NistP256> = bob_secret.into();
        let direct_recipient = EcdhEsDirectRecipient::<p256::NistP256, Aes128>::new(
            &bob_recipient,
            &sender_public,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        )
        .unwrap();
        assert_eq!(direct_recipient.cek().as_ref(), expected_cek);
    }

    #[test]
    fn concat_kdf_different_algorithms() {
        let z = [0xab; 32];
        let cek_256 = concat_kdf(&z, 256, b"A256GCM", None, None);
        assert_eq!(cek_256.len(), 32);
        let cek_192 = concat_kdf(&z, 192, b"A192GCM", None, None);
        assert_eq!(cek_192.len(), 24);
        let cek_128 = concat_kdf(&z, 128, b"A128GCM", None, None);
        assert_eq!(cek_128.len(), 16);
    }

    #[test]
    fn concat_kdf_empty_party_info() {
        let z = [0xcd; 32];
        let cek_empty = concat_kdf(&z, 128, b"A128GCM", None, None);
        let cek_explicit = concat_kdf(&z, 128, b"A128GCM", Some(&[]), Some(&[]));
        assert_eq!(cek_empty.as_slice(), cek_explicit.as_slice());
    }

    #[test]
    fn ecdh_es_key_agreement_wrap_unwrap_p256() {
        // Setup: generate recipient key
        let recipient_secret =
            SecretKey::<p256::NistP256>::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let recipient_public = recipient_secret.public_key();

        // Sender generates ephemeral key and wraps a CEK
        let sender = EcdhEsSenderKey::<p256::NistP256>::generate(
            &mut p256::elliptic_curve::rand_core::OsRng,
        )
        .unwrap();
        let sender_public = sender.public_key();
        let ka = EcdhEsA128KwP256::new(sender, recipient_public, 128, b"A128KW");

        let cek = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0u8,
        ];

        let wrapped = ka
            .wrap(&mut p256::elliptic_curve::rand_core::OsRng, &cek)
            .unwrap();

        // Recipient unwraps using their private key and sender's ephemeral public key
        let recipient: EcdhEsRecipientKey<p256::NistP256> = recipient_secret.into();
        let unwrap_ctx = EcdhEsUnwrapContext::<p256::NistP256, Aes128>::new(
            recipient,
            sender_public,
            128,
            b"A128KW",
        );

        let unwrapped = unwrap_ctx.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped.as_ref(), &cek);
    }

    #[test]
    fn ecdh_es_key_agreement_wrap_unwrap_p384() {
        let recipient_secret =
            SecretKey::<p384::NistP384>::random(&mut p384::elliptic_curve::rand_core::OsRng);
        let recipient_public = recipient_secret.public_key();

        let sender = EcdhEsSenderKey::<p384::NistP384>::generate(
            &mut p384::elliptic_curve::rand_core::OsRng,
        )
        .unwrap();
        let sender_public = sender.public_key();
        let ka = EcdhEsA256KwP384::new(sender, recipient_public, 256, b"A256KW");

        let cek = [0xab; 32];
        let wrapped = ka
            .wrap(&mut p384::elliptic_curve::rand_core::OsRng, &cek)
            .unwrap();

        let recipient: EcdhEsRecipientKey<p384::NistP384> = recipient_secret.into();
        let unwrap_ctx = EcdhEsUnwrapContext::<p384::NistP384, Aes256>::new(
            recipient,
            sender_public,
            256,
            b"A256KW",
        );

        let unwrapped = unwrap_ctx.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped.as_ref(), &cek);
    }
}
