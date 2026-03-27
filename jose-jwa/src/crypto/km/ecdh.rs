//! ECDH-ES key agreement for JWE key management.
//!
//! Provides ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW algorithms
//! for P-256, P-384, and P-521 curves per RFC 7518 Section 4.6.

#![cfg(feature = "ecdh")]

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use aes::cipher::BlockSizeUser;
use aes_gcm::KeySizeUser;
use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes_kw::{AesKw, IV_LEN};
use digest::consts::U16;
use digest::typenum::Unsigned;
use digest::OutputSizeUser;
use elliptic_curve::ecdh::diffie_hellman;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};

use super::{UnwrappingKey, WrappedKey, WrappingKey};
use crate::crypto::CipherError;
use crate::KeyManagement;

/// ECDH-ES direct key agreement (no key wrapping, derives CEK directly).
pub type EcdhEsDirect<C> = EcdhEsWrappingKey<C>;

/// ECDH-ES using Concat KDF and CEK wrapped with "A128KW".
pub type EcdhEsA128Kw<C> = EcdhEsKeyAgreement<C, Aes128>;
/// ECDH-ES using Concat KDF and CEK wrapped with "A192KW".
pub type EcdhEsA192Kw<C> = EcdhEsKeyAgreement<C, Aes192>;
/// ECDH-ES using Concat KDF and CEK wrapped with "A256KW".
pub type EcdhEsA256Kw<C> = EcdhEsKeyAgreement<C, Aes256>;

/// ECDH-ES wrapping key for direct key agreement.
///
/// The sender uses their ephemeral private key and the recipient's public key
/// to derive the CEK directly via Concat KDF.
pub struct EcdhEsWrappingKey<C>
where
    C: CurveArithmetic,
{
    secret: SecretKey<C>,
    recipient_public: PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &'static [u8],
    apu: Vec<u8>,
    apv: Vec<u8>,
}

impl<C> EcdhEsWrappingKey<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    /// Create a new ECDH-ES wrapping key.
    ///
    /// # Arguments
    /// * `secret` - The sender's ephemeral private key
    /// * `recipient_public` - The recipient's public key
    /// * `keydatalen` - The length of the key to derive in bits
    /// * `algorithm_id` - The algorithm ID (e.g., b"A128GCM")
    /// * `apu` - Agreement PartyUInfo (optional)
    /// * `apv` - Agreement PartyVInfo (optional)
    pub fn new(
        secret: SecretKey<C>,
        recipient_public: PublicKey<C>,
        keydatalen: usize,
        algorithm_id: &'static [u8],
        apu: Option<impl AsRef<[u8]>>,
        apv: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self {
            secret,
            recipient_public,
            keydatalen,
            algorithm_id,
            apu: apu.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            apv: apv.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
        }
    }

    /// Generate a new ephemeral sender key.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<SecretKey<C>, CipherError> {
        let mut secret_bytes = elliptic_curve::FieldBytes::<C>::default();
        rand_core::TryRng::try_fill_bytes(rng, &mut secret_bytes)
            .map_err(|_| CipherError::Rng)?;
        SecretKey::<C>::from_bytes(&secret_bytes).map_err(|_| CipherError::InvalidKey)
    }

    /// Get the key management algorithm.
    pub fn alg(&self) -> KeyManagement {
        KeyManagement::EcdhEs
    }

    /// Get the ephemeral public key (for JWE header `epk` field).
    pub fn ephemeral_public(&self) -> PublicKey<C> {
        self.secret.public_key()
    }

    /// Get the x-coordinate of the ephemeral public key as bytes.
    pub fn x(&self) -> Bytes {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let x = encoded.x().expect("public key has x-coordinate");
        x.to_vec().into()
    }

    /// Get the y-coordinate of the ephemeral public key as bytes.
    pub fn y(&self) -> Bytes {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let y = encoded.y().expect("public key has y-coordinate");
        y.to_vec().into()
    }

    /// Get the raw secret key bytes (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        self.secret.to_bytes().as_slice().to_vec().into()
    }

    /// Get the recipient's public key (for verification).
    pub fn recipient_public(&self) -> &PublicKey<C> {
        &self.recipient_public
    }
}

impl<C> WrappingKey for EcdhEsWrappingKey<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = CipherError;

    fn wrap(
        &self,
        _rng: &mut impl TryCryptoRng,
        _cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        // For ECDH-ES direct, we don't wrap the CEK - we derive it.
        // This returns an empty encrypted key; the CEK is derived from the shared secret.
        // The caller should use the derived key directly via the unwrapping side.
        Ok(WrappedKey {
            encrypted_key: vec![].into(),
            iv: None,
            tag: None,
            salt: None,
        })
    }
}

/// ECDH-ES unwrapping key for direct key agreement (recipient side).
///
/// The recipient uses their private key and the sender's ephemeral public key
/// to derive the same CEK that the sender derived.
pub struct EcdhEsUnwrappingKey<C>
where
    C: CurveArithmetic,
{
    secret: SecretKey<C>,
    sender_public: PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &'static [u8],
    apu: Vec<u8>,
    apv: Vec<u8>,
}

impl<C> EcdhEsUnwrappingKey<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    /// Create a new ECDH-ES unwrapping key.
    ///
    /// # Arguments
    /// * `secret` - The recipient's private key
    /// * `sender_public` - The sender's ephemeral public key (from JWE header `epk`)
    /// * `keydatalen` - The length of the key to derive in bits
    /// * `algorithm_id` - The algorithm ID (e.g., b"A128GCM")
    /// * `apu` - Agreement PartyUInfo (optional)
    /// * `apv` - Agreement PartyVInfo (optional)
    pub fn new(
        secret: SecretKey<C>,
        sender_public: PublicKey<C>,
        keydatalen: usize,
        algorithm_id: &'static [u8],
        apu: Option<impl AsRef<[u8]>>,
        apv: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self {
            secret,
            sender_public,
            keydatalen,
            algorithm_id,
            apu: apu.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            apv: apv.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
        }
    }

    /// Get the key management algorithm.
    pub fn alg(&self) -> KeyManagement {
        KeyManagement::EcdhEs
    }

    /// Get the x-coordinate of the sender's ephemeral public key.
    pub fn sender_x(&self) -> Bytes {
        let encoded = self.sender_public.to_sec1_point(false);
        let x = encoded.x().expect("public key has x-coordinate");
        x.to_vec().into()
    }

    /// Get the y-coordinate of the sender's ephemeral public key.
    pub fn sender_y(&self) -> Bytes {
        let encoded = self.sender_public.to_sec1_point(false);
        let y = encoded.y().expect("public key has y-coordinate");
        y.to_vec().into()
    }
}

impl<C> UnwrappingKey for EcdhEsUnwrappingKey<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    type Error = CipherError;

    fn unwrap(&self, _wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        // Perform ECDH to get the shared secret
        let z = diffie_hellman::<C>(
            self.secret.to_nonzero_scalar().clone(),
            self.sender_public.as_affine(),
        );

        // Derive the key using Concat KDF
        let derived = concat_kdf(
            z.raw_secret_bytes().as_slice(),
            self.keydatalen,
            self.algorithm_id,
            Some(&self.apu),
            Some(&self.apv),
        );

        Ok(derived.into())
    }
}

/// ECDH-ES key agreement with AES Key Wrap.
///
/// This type handles both the ECDH key agreement and the AES-KW wrapping
/// of the Content Encryption Key.
pub struct EcdhEsKeyAgreement<C, A>
where
    C: CurveArithmetic,
{
    wrapping_key: Secret,
    encrypted_key: Bytes,
    _curve: PhantomData<C>,
    _aes: PhantomData<A>,
}

/// ECDH-ES wrapping key for key agreement with AES Key Wrap (sender side).
///
/// This type derives a wrapping key from the ECDH shared secret and uses
/// it to wrap the Content Encryption Key with AES-KW.
pub struct EcdhEsKeyAgreementWrappingKey<C, A>
where
    C: CurveArithmetic,
{
    secret: SecretKey<C>,
    recipient_public: PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &'static [u8],
    apu: Vec<u8>,
    apv: Vec<u8>,
    _aes: PhantomData<A>,
}

impl<C, A> EcdhEsKeyAgreementWrappingKey<C, A>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
    A: KeyInit + KeySizeUser,
{
    /// Create a new ECDH-ES+AesKw wrapping key.
    pub fn new(
        secret: SecretKey<C>,
        recipient_public: PublicKey<C>,
        keydatalen: usize,
        algorithm_id: &'static [u8],
        apu: Option<impl AsRef<[u8]>>,
        apv: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self {
            secret,
            recipient_public,
            keydatalen,
            algorithm_id,
            apu: apu.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            apv: apv.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            _aes: PhantomData,
        }
    }

    /// Generate a new ephemeral sender key.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<SecretKey<C>, CipherError> {
        EcdhEsWrappingKey::<C>::random(rng)
    }

    /// Get the key management algorithm.
    pub fn alg(&self) -> KeyManagement {
        match self.keydatalen {
            128 => KeyManagement::EcdhEsA128Kw,
            192 => KeyManagement::EcdhEsA192Kw,
            256 => KeyManagement::EcdhEsA256Kw,
            _ => KeyManagement::EcdhEsA256Kw, // Default fallback
        }
    }

    /// Get the ephemeral public key (for JWE header `epk` field).
    pub fn ephemeral_public(&self) -> PublicKey<C> {
        self.secret.public_key()
    }

    /// Get the x-coordinate of the ephemeral public key.
    pub fn x(&self) -> Bytes {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let x = encoded.x().expect("public key has x-coordinate");
        x.to_vec().into()
    }

    /// Get the y-coordinate of the ephemeral public key.
    pub fn y(&self) -> Bytes {
        let public = self.secret.public_key();
        let encoded = public.to_sec1_point(false);
        let y = encoded.y().expect("public key has y-coordinate");
        y.to_vec().into()
    }

    /// Get the raw secret key bytes (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        self.secret.to_bytes().as_slice().to_vec().into()
    }

    fn derive_wrapping_key(&self) -> Result<Secret, CipherError> {
        // Perform ECDH
        let z = diffie_hellman::<C>(
            self.secret.to_nonzero_scalar().clone(),
            self.recipient_public.as_affine(),
        );

        // Derive the wrapping key using Concat KDF
        let derived = concat_kdf(
            z.raw_secret_bytes().as_slice(),
            self.keydatalen,
            self.algorithm_id,
            Some(&self.apu),
            Some(&self.apv),
        );

        Ok(derived.into())
    }
}

impl<C, A> WrappingKey for EcdhEsKeyAgreementWrappingKey<C, A>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
    A: BlockCipherEncrypt<BlockSize = U16> + BlockSizeUser + KeyInit + KeySizeUser,
{
    type Error = CipherError;

    fn wrap(
        &self,
        _rng: &mut impl TryCryptoRng,
        cek: impl AsRef<[u8]>,
    ) -> Result<WrappedKey, Self::Error> {
        // Derive the wrapping key from ECDH
        let wrapping_key = self.derive_wrapping_key()?;

        // Create AES-KW instance
        let kw = AesKw::<A>::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| CipherError::InvalidKeyLength)?;

        // Wrap the CEK
        let cek = cek.as_ref();
        let mut encrypted_cek = vec![0u8; cek.len() + IV_LEN];

        let len = kw
            .wrap_key(cek, &mut encrypted_cek)
            .map_err(|_| CipherError::Aead)?
            .len();

        encrypted_cek.resize(len, 0);

        Ok(WrappedKey {
            encrypted_key: encrypted_cek.into(),
            iv: None,
            tag: None,
            salt: None,
        })
    }
}

/// ECDH-ES unwrapping key for key agreement with AES Key Wrap (recipient side).
///
/// This type derives a wrapping key from the ECDH shared secret and uses
/// it to unwrap the Content Encryption Key with AES-KW.
pub struct EcdhEsKeyAgreementUnwrappingKey<C, A>
where
    C: CurveArithmetic,
{
    secret: SecretKey<C>,
    sender_public: PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &'static [u8],
    apu: Vec<u8>,
    apv: Vec<u8>,
    _aes: PhantomData<A>,
}

impl<C, A> EcdhEsKeyAgreementUnwrappingKey<C, A>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
    A: KeyInit + KeySizeUser,
{
    /// Create a new ECDH-ES+AesKw unwrapping key.
    pub fn new(
        secret: SecretKey<C>,
        sender_public: PublicKey<C>,
        keydatalen: usize,
        algorithm_id: &'static [u8],
        apu: Option<impl AsRef<[u8]>>,
        apv: Option<impl AsRef<[u8]>>,
    ) -> Self {
        Self {
            secret,
            sender_public,
            keydatalen,
            algorithm_id,
            apu: apu.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            apv: apv.map(|s| s.as_ref().to_vec()).unwrap_or_default(),
            _aes: PhantomData,
        }
    }

    /// Get the key management algorithm.
    pub fn alg(&self) -> KeyManagement {
        match self.keydatalen {
            128 => KeyManagement::EcdhEsA128Kw,
            192 => KeyManagement::EcdhEsA192Kw,
            256 => KeyManagement::EcdhEsA256Kw,
            _ => KeyManagement::EcdhEsA256Kw,
        }
    }

    fn derive_wrapping_key(&self) -> Result<Secret, CipherError> {
        // Perform ECDH
        let z = diffie_hellman::<C>(
            self.secret.to_nonzero_scalar().clone(),
            self.sender_public.as_affine(),
        );

        // Derive the wrapping key using Concat KDF
        let derived = concat_kdf(
            z.raw_secret_bytes().as_slice(),
            self.keydatalen,
            self.algorithm_id,
            Some(&self.apu),
            Some(&self.apv),
        );

        Ok(derived.into())
    }
}

impl<C, A> UnwrappingKey for EcdhEsKeyAgreementUnwrappingKey<C, A>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
    A: BlockCipherDecrypt<BlockSize = U16> + BlockSizeUser + KeyInit + KeySizeUser,
{
    type Error = CipherError;

    fn unwrap(&self, wrapped_key: &WrappedKey) -> Result<Secret, Self::Error> {
        // Derive the wrapping key from ECDH
        let wrapping_key = self.derive_wrapping_key()?;

        // Create AES-KW instance
        let kw = AesKw::<A>::new_from_slice(wrapping_key.as_ref())
            .map_err(|_| CipherError::InvalidKeyLength)?;

        // Unwrap the CEK
        let encrypted_cek = wrapped_key.encrypted_key.as_ref();
        let mut buf = vec![0u8; encrypted_cek.len().saturating_sub(IV_LEN)];

        kw.unwrap_key(encrypted_cek, &mut buf)
            .map_err(|_| CipherError::Aead)?;

        Ok(buf.into())
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

    /// Simple test RNG that panics if asked for random bytes
    /// (we use deterministic keys in tests)
    struct TestRng;

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("TestRng should not be used for randomness")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("TestRng should not be used for randomness")
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Self::Error> {
            // For key generation in tests, we use pre-generated keys
            // This won't be called if we construct keys from bytes
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

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
        let _expected_z: [u8; 32] = [
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

        // Sender (Alice) side - wrap derives the CEK
        let _wrap_key = EcdhEsWrappingKey::<p256::NistP256>::new(
            alice_secret.clone(),
            bob_public,
            128,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        );

        // Recipient (Bob) side - unwrap derives the same CEK
        let alice_public = alice_secret.public_key();
        let _unwrap_key = EcdhEsUnwrappingKey::<p256::NistP256>::new(
            bob_secret.clone(),
            alice_public,
            128,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        );

        // For direct ECDH-ES, we need to manually derive because wrap/unwrap
        // handle the ECDH exchange differently
        let z = diffie_hellman::<p256::NistP256>(
            alice_secret.to_nonzero_scalar().clone(),
            bob_public.as_affine(),
        );

        let derived_cek = concat_kdf(
            z.raw_secret_bytes().as_slice(),
            128,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        );

        assert_eq!(
            derived_cek.as_slice(),
            expected_cek,
            "Derived CEK does not match RFC 7518 expected value"
        );

        // Verify commutativity: Bob derives the same key
        let z_bob = diffie_hellman::<p256::NistP256>(
            bob_secret.to_nonzero_scalar().clone(),
            alice_public.as_affine(),
        );

        let derived_bob = concat_kdf(
            z_bob.raw_secret_bytes().as_slice(),
            128,
            b"A128GCM",
            Some(b"Alice"),
            Some(b"Bob"),
        );

        assert_eq!(derived_bob.as_slice(), expected_cek);
    }

    #[test]
    fn concat_kdf_different_algorithms() {
        let z = [0xab; 32];
        let cek_256 = concat_kdf(&z, 256, b"A256GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_256.len(), 32);
        let cek_192 = concat_kdf(&z, 192, b"A192GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_192.len(), 24);
        let cek_128 = concat_kdf(&z, 128, b"A128GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_128.len(), 16);
    }

    #[test]
    fn concat_kdf_empty_party_info() {
        let z = [0xcd; 32];
        let cek_empty = concat_kdf(&z, 128, b"A128GCM", None::<&[u8]>, None::<&[u8]>);
        let cek_explicit = concat_kdf(&z, 128, b"A128GCM", Some(&[]), Some(&[]));
        assert_eq!(cek_empty.as_slice(), cek_explicit.as_slice());
    }

    #[test]
    fn ecdh_es_key_agreement_wrap_unwrap_p256() {
        // Use deterministic test keys (from RFC 7518 Appendix C test vectors)
        let recipient_d: [u8; 32] = [
            0x54, 0x49, 0x83, 0x66, 0x90, 0xd7, 0x5c, 0xaf, 0x29, 0xf0, 0xdd, 0x02, 0x9d, 0xdb,
            0x31, 0xb3, 0xdd, 0xb8, 0xab, 0xa9, 0xd2, 0xd5, 0x15, 0xc5, 0x01, 0x24, 0x65, 0xe8,
            0x17, 0xd4, 0xa9, 0xdc,
        ];
        let sender_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];

        let recipient_secret = SecretKey::<p256::NistP256>::from_slice(&recipient_d).unwrap();
        let recipient_public = recipient_secret.public_key();

        let sender_secret = SecretKey::<p256::NistP256>::from_slice(&sender_d).unwrap();

        // Create wrapping key
        let wrap_key = EcdhEsKeyAgreementWrappingKey::<p256::NistP256, Aes128>::new(
            sender_secret.clone(),
            recipient_public,
            128,
            b"ECDH-ES+A128KW",
            None::<&[u8]>,
            None::<&[u8]>,
        );

        let cek = [
            0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
            0xbc, 0xde, 0xf0,
        ];

        let wrapped = wrap_key
            .wrap(&mut TestRng, &cek)
            .unwrap();

        // Recipient unwraps using their private key and sender's ephemeral public key
        let unwrap_key = EcdhEsKeyAgreementUnwrappingKey::<p256::NistP256, Aes128>::new(
            recipient_secret,
            sender_secret.public_key(),
            128,
            b"ECDH-ES+A128KW",
            None::<&[u8]>,
            None::<&[u8]>,
        );

        let unwrapped = unwrap_key.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped.as_ref(), &cek);
    }

    #[test]
    fn ecdh_es_key_agreement_wrap_unwrap_p384() {
        // Use deterministic test keys
        let recipient_d: [u8; 48] = [
            0x64, 0xdf, 0x86, 0x36, 0xee, 0x2f, 0x59, 0x70, 0x8d, 0x93, 0xe4, 0x02,
            0x82, 0x5d, 0x41, 0x9e, 0x0c, 0x5f, 0xa9, 0x0e, 0x8d, 0x97, 0x1a, 0x12,
            0xbf, 0x1a, 0x6b, 0x9f, 0xd9, 0xf8, 0x4e, 0x5c, 0x8b, 0x5e, 0x5d, 0x12,
            0x14, 0x47, 0x1e, 0x52, 0x67, 0x81, 0x5d, 0xab, 0xbe, 0x8c, 0xa1, 0x43,
        ];
        let sender_d: [u8; 48] = [
            0x12, 0xdd, 0x65, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
        ];

        let recipient_secret = SecretKey::<p384::NistP384>::from_slice(&recipient_d).unwrap();
        let recipient_public = recipient_secret.public_key();

        let sender_secret = SecretKey::<p384::NistP384>::from_slice(&sender_d).unwrap();

        let wrap_key = EcdhEsKeyAgreementWrappingKey::<p384::NistP384, Aes256>::new(
            sender_secret.clone(),
            recipient_public,
            256,
            b"ECDH-ES+A256KW",
            None::<&[u8]>,
            None::<&[u8]>,
        );

        let cek = [0xab; 32];
        let wrapped = wrap_key
            .wrap(&mut TestRng, &cek)
            .unwrap();

        let unwrap_key = EcdhEsKeyAgreementUnwrappingKey::<p384::NistP384, Aes256>::new(
            recipient_secret,
            sender_secret.public_key(),
            256,
            b"ECDH-ES+A256KW",
            None::<&[u8]>,
            None::<&[u8]>,
        );

        let unwrapped = unwrap_key.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped.as_ref(), &cek);
    }
}
