//! ECDH-ES key agreement for JWE key management.
//!
//! Provides ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW algorithms
//! for P-256, P-384, and P-521 curves per RFC 7518 Section 4.6.

#![cfg(feature = "ecdh")]

use alloc::vec::Vec;

use aes_kw::aes::{Aes128, Aes192, Aes256};
use aes_kw::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes_kw::{AesKw, IV_LEN};
use digest::consts::U16;
use elliptic_curve::ecdh::diffie_hellman;
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{CipherError, WrappedKey};

/// Generic ECDH key agreement function.
///
/// Returns the shared secret Z (x-coordinate) as a zeroizing byte vector.
fn ecdh_key_agreement<C>(
    sender_secret: &SecretKey<C>,
    recipient_public: &PublicKey<C>,
) -> Zeroizing<Vec<u8>>
where
    C: CurveArithmetic,
{
    let shared_secret = diffie_hellman(
        sender_secret.to_nonzero_scalar(),
        recipient_public.as_affine(),
    );
    Zeroizing::new(shared_secret.raw_secret_bytes().as_slice().to_vec())
}

/// Concatenation KDF for ECDH-ES per RFC 7518 Section 4.6.2.
///
/// Uses SHA-256 as the hash function. Derives keying material of `keydatalen` bits.
/// Both `keydatalen` and the internal `hash_len` counter are in **bits**;
/// the output buffer is sized in bytes (bits / 8).
fn concat_kdf(
    z: &[u8],
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let apu = apu.unwrap_or(&[]);
    let apv = apv.unwrap_or(&[]);

    // Each SHA-256 round produces 256 bits (32 bytes). Compute the number of rounds.
    let hash_len_bits = 256usize;
    let reps = (keydatalen + hash_len_bits - 1) / hash_len_bits;

    let mut derived = Zeroizing::new(Vec::with_capacity(reps * 32)); // 32 bytes = 256 bits

    for i in 1..=reps {
        let mut hasher = Sha256::new();

        hasher.update(&(i as u32).to_be_bytes());
        hasher.update(z);
        hasher.update(&(algorithm_id.len() as u32).to_be_bytes());
        hasher.update(algorithm_id);
        hasher.update(&(apu.len() as u32).to_be_bytes());
        hasher.update(apu);
        hasher.update(&(apv.len() as u32).to_be_bytes());
        hasher.update(apv);
        // SuppPubInfo: keydatalen in bits as a 4-byte big-endian value
        hasher.update(&(keydatalen as u32).to_be_bytes());

        derived.extend_from_slice(&hasher.finalize());
    }

    let bytes_needed = (keydatalen + 7) / 8;
    derived.truncate(bytes_needed);

    derived
}

/// Generic ECDH-ES direct key agreement.
fn ecdh_es_derive_key_direct<C>(
    sender_secret: &SecretKey<C>,
    recipient_public: &PublicKey<C>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Zeroizing<Vec<u8>>
where
    C: CurveArithmetic,
{
    let z = ecdh_key_agreement(sender_secret, recipient_public);
    concat_kdf(&z, keydatalen, algorithm_id, apu, apv)
}

/// Generic ECDH-ES with AES-KW key wrapping.
fn ecdh_es_wrap_generic<C, A>(
    sender_secret: &SecretKey<C>,
    recipient_public: &PublicKey<C>,
    cek: impl AsRef<[u8]>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError>
where
    C: CurveArithmetic,
    A: BlockCipherEncrypt<BlockSize = U16> + KeyInit,
    AesKw<A>: KeyInit,
{
    let z = ecdh_key_agreement(sender_secret, recipient_public);
    let wrapping_key = concat_kdf(&z, keydatalen, algorithm_id, apu, apv);

    let kw = AesKw::<A>::new(
        (&wrapping_key[..])
            .try_into()
            .map_err(|_| CipherError::InvalidKeyLength)?,
    );

    let cek_slice = cek.as_ref();
    let mut encrypted_cek = alloc::vec![0u8; cek_slice.len() + IV_LEN];
    let encrypted_len = kw
        .wrap_key(cek_slice, &mut encrypted_cek)
        .map_err(|_| CipherError::Aead)?
        .len();
    encrypted_cek.truncate(encrypted_len);

    Ok(WrappedKey {
        encrypted_key: Some(encrypted_cek),
        iv: None,
        tag: None,
        salt: None,
    })
}

/// Generic ECDH-ES with AES-KW unwrap.
fn ecdh_es_unwrap_generic<C, A>(
    recipient_secret: &SecretKey<C>,
    sender_public: &PublicKey<C>,
    encrypted_cek: impl AsRef<[u8]>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError>
where
    C: CurveArithmetic,
    A: BlockCipherDecrypt<BlockSize = U16> + KeyInit,
    AesKw<A>: KeyInit,
{
    let z = ecdh_key_agreement(recipient_secret, sender_public);
    let wrapping_key = concat_kdf(&z, keydatalen, algorithm_id, apu, apv);

    let kw = AesKw::<A>::new(
        (&wrapping_key[..])
            .try_into()
            .map_err(|_| CipherError::InvalidKeyLength)?,
    );

    let encrypted_slice = encrypted_cek.as_ref();
    let mut cek = alloc::vec![0u8; encrypted_slice.len().saturating_sub(IV_LEN)];
    kw.unwrap_key(encrypted_slice, &mut cek)
        .map_err(|_| CipherError::Aead)?;

    Ok(cek)
}

// ============================================================================
// P-256 implementations (RFC 7518 Section 4.6)
// ============================================================================

/// ECDH-ES direct key agreement using P-256.
pub fn ecdh_es_p256_derive_direct(
    sender_secret: &SecretKey<p256::NistP256>,
    recipient_public: &PublicKey<p256::NistP256>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    ecdh_es_derive_key_direct(
        sender_secret,
        recipient_public,
        keydatalen,
        algorithm_id,
        apu,
        apv,
    )
}

/// ECDH-ES + AES-128-KW using P-256.
pub fn ecdh_es_p256_wrap_aes_128(
    sender_secret: &SecretKey<p256::NistP256>,
    recipient_public: &PublicKey<p256::NistP256>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p256::NistP256, Aes128>(
        sender_secret,
        recipient_public,
        cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-192-KW using P-256.
pub fn ecdh_es_p256_wrap_aes_192(
    sender_secret: &SecretKey<p256::NistP256>,
    recipient_public: &PublicKey<p256::NistP256>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p256::NistP256, Aes192>(
        sender_secret,
        recipient_public,
        cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-256-KW using P-256.
pub fn ecdh_es_p256_wrap_aes_256(
    sender_secret: &SecretKey<p256::NistP256>,
    recipient_public: &PublicKey<p256::NistP256>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p256::NistP256, Aes256>(
        sender_secret,
        recipient_public,
        cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-128-KW using P-256.
pub fn ecdh_es_p256_unwrap_aes_128(
    recipient_secret: &SecretKey<p256::NistP256>,
    sender_public: &PublicKey<p256::NistP256>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p256::NistP256, Aes128>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-192-KW using P-256.
pub fn ecdh_es_p256_unwrap_aes_192(
    recipient_secret: &SecretKey<p256::NistP256>,
    sender_public: &PublicKey<p256::NistP256>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p256::NistP256, Aes192>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-256-KW using P-256.
pub fn ecdh_es_p256_unwrap_aes_256(
    recipient_secret: &SecretKey<p256::NistP256>,
    sender_public: &PublicKey<p256::NistP256>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p256::NistP256, Aes256>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

// ============================================================================
// P-384 implementations (RFC 7518 Section 4.6)
// ============================================================================

/// ECDH-ES direct key agreement using P-384.
pub fn ecdh_es_p384_derive_direct(
    sender_secret: &SecretKey<p384::NistP384>,
    recipient_public: &PublicKey<p384::NistP384>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    ecdh_es_derive_key_direct(
        sender_secret,
        recipient_public,
        keydatalen,
        algorithm_id,
        apu,
        apv,
    )
}

/// ECDH-ES + AES-128-KW using P-384.
pub fn ecdh_es_p384_wrap_aes_128(
    sender_secret: &SecretKey<p384::NistP384>,
    recipient_public: &PublicKey<p384::NistP384>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p384::NistP384, Aes128>(
        sender_secret,
        recipient_public,
        cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-192-KW using P-384.
pub fn ecdh_es_p384_wrap_aes_192(
    sender_secret: &SecretKey<p384::NistP384>,
    recipient_public: &PublicKey<p384::NistP384>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p384::NistP384, Aes192>(
        sender_secret,
        recipient_public,
        cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-256-KW using P-384.
pub fn ecdh_es_p384_wrap_aes_256(
    sender_secret: &SecretKey<p384::NistP384>,
    recipient_public: &PublicKey<p384::NistP384>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p384::NistP384, Aes256>(
        sender_secret,
        recipient_public,
        cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-128-KW using P-384.
pub fn ecdh_es_p384_unwrap_aes_128(
    recipient_secret: &SecretKey<p384::NistP384>,
    sender_public: &PublicKey<p384::NistP384>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p384::NistP384, Aes128>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-192-KW using P-384.
pub fn ecdh_es_p384_unwrap_aes_192(
    recipient_secret: &SecretKey<p384::NistP384>,
    sender_public: &PublicKey<p384::NistP384>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p384::NistP384, Aes192>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-256-KW using P-384.
pub fn ecdh_es_p384_unwrap_aes_256(
    recipient_secret: &SecretKey<p384::NistP384>,
    sender_public: &PublicKey<p384::NistP384>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p384::NistP384, Aes256>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

// ============================================================================
// P-521 implementations (RFC 7518 Section 4.6)
// ============================================================================

/// ECDH-ES direct key agreement using P-521.
pub fn ecdh_es_p521_derive_direct(
    sender_secret: &SecretKey<p521::NistP521>,
    recipient_public: &PublicKey<p521::NistP521>,
    keydatalen: usize,
    algorithm_id: &[u8],
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    ecdh_es_derive_key_direct(
        sender_secret,
        recipient_public,
        keydatalen,
        algorithm_id,
        apu,
        apv,
    )
}

/// ECDH-ES + AES-128-KW using P-521.
pub fn ecdh_es_p521_wrap_aes_128(
    sender_secret: &SecretKey<p521::NistP521>,
    recipient_public: &PublicKey<p521::NistP521>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p521::NistP521, Aes128>(
        sender_secret,
        recipient_public,
        cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-192-KW using P-521.
pub fn ecdh_es_p521_wrap_aes_192(
    sender_secret: &SecretKey<p521::NistP521>,
    recipient_public: &PublicKey<p521::NistP521>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p521::NistP521, Aes192>(
        sender_secret,
        recipient_public,
        cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// ECDH-ES + AES-256-KW using P-521.
pub fn ecdh_es_p521_wrap_aes_256(
    sender_secret: &SecretKey<p521::NistP521>,
    recipient_public: &PublicKey<p521::NistP521>,
    cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<WrappedKey, CipherError> {
    ecdh_es_wrap_generic::<p521::NistP521, Aes256>(
        sender_secret,
        recipient_public,
        cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-128-KW using P-521.
pub fn ecdh_es_p521_unwrap_aes_128(
    recipient_secret: &SecretKey<p521::NistP521>,
    sender_public: &PublicKey<p521::NistP521>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p521::NistP521, Aes128>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        128,
        b"A128KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-192-KW using P-521.
pub fn ecdh_es_p521_unwrap_aes_192(
    recipient_secret: &SecretKey<p521::NistP521>,
    sender_public: &PublicKey<p521::NistP521>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p521::NistP521, Aes192>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        192,
        b"A192KW",
        apu,
        apv,
    )
}

/// Unwrap CEK for ECDH-ES + AES-256-KW using P-521.
pub fn ecdh_es_p521_unwrap_aes_256(
    recipient_secret: &SecretKey<p521::NistP521>,
    sender_public: &PublicKey<p521::NistP521>,
    encrypted_cek: impl AsRef<[u8]>,
    apu: Option<&[u8]>,
    apv: Option<&[u8]>,
) -> Result<Vec<u8>, CipherError> {
    ecdh_es_unwrap_generic::<p521::NistP521, Aes256>(
        recipient_secret,
        sender_public,
        encrypted_cek,
        256,
        b"A256KW",
        apu,
        apv,
    )
}

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

        let computed_z = ecdh_key_agreement(&alice_secret, &bob_public);
        assert_eq!(
            computed_z.as_slice(),
            expected_z,
            "ECDH shared secret Z does not match RFC 7518 expected value"
        );

        let algorithm_id = b"A128GCM";
        let computed_cek =
            concat_kdf(&computed_z, 128, algorithm_id, Some(b"Alice"), Some(b"Bob"));
        assert_eq!(
            computed_cek.as_slice(),
            expected_cek,
            "Derived CEK does not match RFC 7518 expected value"
        );

        // Verify commutativity: Bob can derive the same shared secret
        let alice_public = alice_secret.public_key();
        let bob_computed_z = ecdh_key_agreement(&bob_secret, &alice_public);
        assert_eq!(bob_computed_z.as_slice(), expected_z);

        let bob_computed_cek =
            concat_kdf(&bob_computed_z, 128, algorithm_id, Some(b"Alice"), Some(b"Bob"));
        assert_eq!(bob_computed_cek.as_slice(), expected_cek);
    }

    #[test]
    fn ecdh_es_p256_rfc7518_base64url_check() {
        let expected_cek: [u8; 16] = [
            0x56, 0xaa, 0x8d, 0xea, 0xf8, 0x23, 0x6d, 0x20, 0x5c, 0x22, 0x28, 0xcd, 0x71, 0xa7,
            0x10, 0x1a,
        ];
        assert_eq!(expected_cek[0], 0x56);
        assert_eq!(expected_cek[1], 0xaa);
        assert_eq!(expected_cek[2], 0x8d);
        assert_eq!(expected_cek[3], 0xea);

        let expected_z: [u8; 32] = [
            0x9e, 0x56, 0xd9, 0x1d, 0x81, 0x71, 0x35, 0xd3, 0x72, 0x83, 0x42, 0x83, 0xbf, 0x84,
            0x26, 0x9c, 0xfb, 0x31, 0x6e, 0xa3, 0xda, 0x80, 0x6a, 0x48, 0xf6, 0xda, 0xa7, 0x79,
            0x8c, 0xfe, 0x90, 0xc4,
        ];
        let computed_cek = concat_kdf(&expected_z, 128, b"A128GCM", Some(b"Alice"), Some(b"Bob"));
        assert_eq!(computed_cek.as_slice(), expected_cek);
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
}
