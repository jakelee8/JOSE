//! ECDH-ES key agreement for JWE key management.
//!
//! Provides ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW algorithms
//! for P-256, P-384, and P-521 curves per RFC 7518 Section 4.6.
//!
//! # Usage
//!
//! ## ECDH-ES Direct Key Agreement
//!
//! ```rust
//! # use jose_jwa::crypto::{EcdhPublicKey, EcdhSecretKey, EcdhDeriveParams, EcdhDerivation};
//! # fn example() -> Result<(), jose_jwa::Error> {
//! # let x = [0u8; 32];
//! # let y = [0u8; 32];
//! # let d = [0x54u8; 32];
//! # let epk_x = [0xd3u8; 32];
//! # let epk_y = [0xd3u8; 32];
//! # let mut rng = getrandom::SysRng;
//! // Sender: generate ephemeral key, derive CEK
//! let recipient_public = EcdhPublicKey::<p256::NistP256>::from_components(&x, &y)?;
//! let ephemeral = EcdhSecretKey::<p256::NistP256>::random(&mut rng)?;
//! let cek = ephemeral.derive(&recipient_public, &EcdhDeriveParams {
//!     algorithm: EcdhDerivation::A128Gcm,
//!     apu: None,
//!     apv: None,
//! });
//! // Serialize ephemeral.public_key() to JWE header as 'epk'
//!
//! // Recipient: use static key, derive same CEK
//! let static_key = EcdhSecretKey::<p256::NistP256>::from_bytes(&d)?;
//! let sender_epk = EcdhPublicKey::<p256::NistP256>::from_components(&epk_x, &epk_y)?;
//! let cek = static_key.derive(&sender_epk, &EcdhDeriveParams {
//!     algorithm: EcdhDerivation::A128Gcm,
//!     apu: None,
//!     apv: None,
//! });
//! # Ok(())
//! # }
//! ```
//!
//! ## ECDH-ES with Key Wrap (e.g., ECDH-ES+A128KW)
//!
//! ```rust,ignore
//! // Note: This example requires the "aes-kw" feature.
//! // Sender: derive KEK, wrap CEK with AES-KW
//! # use jose_jwa::crypto::{EcdhPublicKey, EcdhSecretKey, EcdhDeriveParams, EcdhDerivation};
//! # use jose_jwa::crypto::{AesKwKey128, WrappingKey, UnwrappingKey};
//! # fn example() -> Result<(), jose_jwa::Error> {
//! # let x = [0u8; 32];
//! # let y = [0u8; 32];
//! # let d = [0x54u8; 32];
//! # let epk_x = [0xd3u8; 32];
//! # let epk_y = [0xd3u8; 32];
//! # let cek = [0xabu8; 16];
//! # let mut rng = getrandom::SysRng;
//! # let ephemeral = EcdhSecretKey::<p256::NistP256>::random(&mut rng)?;
//! # let recipient_public = EcdhPublicKey::<p256::NistP256>::from_components(&x, &y)?;
//! let kek = ephemeral.derive(&recipient_public, &EcdhDeriveParams {
//!     algorithm: EcdhDerivation::EcdhEsA128Kw,
//!     apu: None,
//!     apv: None,
//! });
//! let wrapped_cek = AesKwKey128::try_from(kek)?.wrap_key(&mut rng, cek)?;
//!
//! // Recipient: derive same KEK, unwrap CEK
//! # let static_key = EcdhSecretKey::<p256::NistP256>::from_bytes(&d)?;
//! # let sender_epk = EcdhPublicKey::<p256::NistP256>::from_components(&epk_x, &epk_y)?;
//! let kek = static_key.derive(&sender_epk, &EcdhDeriveParams {
//!     algorithm: EcdhDerivation::EcdhEsA128Kw,
//!     apu: None,
//!     apv: None,
//! });
//! let unwrapped_cek = AesKwKey128::try_from(kek)?.unwrap_key(&wrapped_cek)?;
//! # Ok(())
//! # }
//! ```

#![cfg(feature = "ecdh")]

use alloc::vec;
use core::fmt;

use digest::OutputSizeUser;
use digest::typenum::Unsigned;
use elliptic_curve::ecdh::{SharedSecret, diffie_hellman};
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use elliptic_curve::{Curve, CurveArithmetic, Generate, PublicKey, SecretKey};
use jose_b64::serde::{Bytes, Secret};
use rand_core::TryCryptoRng;
use sha2::{Digest, Sha256};

use crate::Error;

/// Compile-time curve identifier trait.
///
/// Implemented by each supported curve to provide its JWK curve identifier
/// at compile time, eliminating the need for runtime field-size matching.
pub trait EcdhCurve {
    /// The JWK curve identifier for this curve.
    const CURVE: EcCurves;
}

/// Curve identifiers for ECDH operations.
///
/// This enum mirrors `jose_jwk::key::EcCurves` for use in the crypto layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EcCurves {
    /// P-256 curve
    P256,
    /// P-384 curve
    P384,
    /// P-521 curve
    P521,
}

// Compile-time curve implementations
#[cfg(feature = "p256")]
impl EcdhCurve for p256::NistP256 {
    const CURVE: EcCurves = EcCurves::P256;
}

#[cfg(feature = "p384")]
impl EcdhCurve for p384::NistP384 {
    const CURVE: EcCurves = EcCurves::P384;
}

#[cfg(feature = "p521")]
impl EcdhCurve for p521::NistP521 {
    const CURVE: EcCurves = EcCurves::P521;
}

/// Algorithm context for ECDH key derivation via concat KDF (RFC 7518 §4.6.2).
///
/// Each variant encodes the `algorithm_id` string and `keydatalen` (in bits)
/// for the concat KDF. Select the variant that matches the JWE header:
///
/// - For `alg="ECDH-ES"` (direct): choose the variant matching the `enc` value.
/// - For `alg="ECDH-ES+A*KW"` (key wrap): choose the variant matching the `alg` value.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EcdhDerivation {
    // Direct ECDH-ES: algorithm_id = enc value, keydatalen = enc algorithm key length
    /// A128CBC-HS256 content encryption (256-bit key)
    A128CbcHs256,
    /// A192CBC-HS384 content encryption (384-bit key)
    A192CbcHs384,
    /// A256CBC-HS512 content encryption (512-bit key)
    A256CbcHs512,
    /// A128GCM content encryption (128-bit key)
    A128Gcm,
    /// A192GCM content encryption (192-bit key)
    A192Gcm,
    /// A256GCM content encryption (256-bit key)
    A256Gcm,
    // Key-wrap ECDH-ES+A*KW: algorithm_id = alg value, keydatalen = KW key length
    /// ECDH-ES+A128KW key wrap (128-bit key)
    EcdhEsA128Kw,
    /// ECDH-ES+A192KW key wrap (192-bit key)
    EcdhEsA192Kw,
    /// ECDH-ES+A256KW key wrap (256-bit key)
    EcdhEsA256Kw,
}

impl EcdhDerivation {
    /// The `algorithm_id` bytes passed to the concat KDF.
    fn algorithm_id(self) -> &'static [u8] {
        match self {
            Self::A128CbcHs256 => b"A128CBC-HS256",
            Self::A192CbcHs384 => b"A192CBC-HS384",
            Self::A256CbcHs512 => b"A256CBC-HS512",
            Self::A128Gcm => b"A128GCM",
            Self::A192Gcm => b"A192GCM",
            Self::A256Gcm => b"A256GCM",
            Self::EcdhEsA128Kw => b"ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => b"ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => b"ECDH-ES+A256KW",
        }
    }

    /// The `keydatalen` in bits passed to the concat KDF.
    fn keydatalen(self) -> usize {
        match self {
            Self::A128CbcHs256 => 256,
            Self::A192CbcHs384 => 384,
            Self::A256CbcHs512 => 512,
            Self::A128Gcm | Self::EcdhEsA128Kw => 128,
            Self::A192Gcm | Self::EcdhEsA192Kw => 192,
            Self::A256Gcm | Self::EcdhEsA256Kw => 256,
        }
    }
}

/// Parameters for ECDH key derivation via concat KDF.
///
/// Pass to [`EcdhSecretKey::derive`]. Empty slices for `apu`/`apv` are
/// equivalent to absent (RFC 7518 §4.6.2).
pub struct EcdhDeriveParams {
    /// Derivation algorithm — determines `algorithm_id` and `keydatalen`.
    pub algorithm: EcdhDerivation,
    /// Agreement PartyUInfo (JWE `apu` header, base64url-decoded).
    pub apu: Option<Bytes>,
    /// Agreement PartyVInfo (JWE `apv` header, base64url-decoded).
    pub apv: Option<Bytes>,
}

/// ECDH public key.
///
/// Holds any EC public key (recipient's static key or sender's ephemeral key).
/// This type is parameterized by the curve (`C`), which should be one of:
/// - `p256::NistP256` for P-256
/// - `p384::NistP384` for P-384
/// - `p521::NistP521` for P-521
///
/// # Example
///
/// ```rust
/// # use jose_jwa::crypto::{EcdhPublicKey, EcCurves};
/// # fn example() -> Result<(), jose_jwa::Error> {
/// # let x_bytes = [0xd3u8; 32];
/// # let y_bytes = [0xd3u8; 32];
/// // Construct from JWK coordinates
/// let pk = EcdhPublicKey::<p256::NistP256>::from_components(&x_bytes, &y_bytes)?;
///
/// // Serialize back to JWK
/// let crv = pk.crv(); // EcCurves::P256
/// let x = pk.x();     // Bytes
/// let y = pk.y();     // Bytes
/// # assert_eq!(crv, EcCurves::P256);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct EcdhPublicKey<C: CurveArithmetic> {
    inner: PublicKey<C>,
}

impl<C> EcdhPublicKey<C>
where
    C: CurveArithmetic + EcdhCurve,
{
    /// Get the curve identifier (for JWK serialization).
    pub fn crv(&self) -> EcCurves {
        C::CURVE
    }
}

impl<C> EcdhPublicKey<C>
where
    C: CurveArithmetic,
    C::AffinePoint: FromSec1Point<C> + ToSec1Point<C>,
    C::FieldBytesSize: ModulusSize,
{
    /// Construct a public key from JWK `x` and `y` coordinates.
    ///
    /// # Arguments
    /// * `x` - The x-coordinate as bytes (must match curve field size)
    /// * `y` - The y-coordinate as bytes (must match curve field size)
    ///
    /// # Errors
    /// Returns `Error::InvalidKey` if the coordinates are invalid or the
    /// point is not on the curve.
    pub fn from_components(x: impl AsRef<[u8]>, y: impl AsRef<[u8]>) -> Result<Self, Error> {
        let x = x.as_ref().try_into().map_err(|_| Error::InvalidKey)?;
        let y = y.as_ref().try_into().map_err(|_| Error::InvalidKey)?;

        let point = AffineCoordinates::from_coordinates(&x, &y)
            .into_option()
            .ok_or(Error::InvalidKey)?;

        let inner = PublicKey::from_affine(point).map_err(|_| Error::InvalidKey)?;

        Ok(Self { inner })
    }

    /// Get the x-coordinate (JWK `x` parameter).
    pub fn x(&self) -> Bytes {
        let encoded = self.inner.to_sec1_point(false);
        encoded
            .x()
            .unwrap_or_else(|| unreachable!("uncompressed SEC1 point always has x"))
            .as_slice()
            .to_vec()
            .into()
    }

    /// Get the y-coordinate (JWK `y` parameter).
    pub fn y(&self) -> Bytes {
        let encoded = self.inner.to_sec1_point(false);
        encoded
            .y()
            .unwrap_or_else(|| unreachable!("uncompressed SEC1 point always has y"))
            .as_slice()
            .to_vec()
            .into()
    }
}

impl<C> From<PublicKey<C>> for EcdhPublicKey<C>
where
    C: CurveArithmetic,
{
    fn from(inner: PublicKey<C>) -> Self {
        Self { inner }
    }
}

impl<C> From<EcdhPublicKey<C>> for PublicKey<C>
where
    C: CurveArithmetic,
{
    fn from(key: EcdhPublicKey<C>) -> Self {
        key.inner
    }
}

/// ECDH secret key.
///
/// Used for static recipient keys and ephemeral sender keys. This type wraps
/// `elliptic_curve::SecretKey<C>` and provides JWK-compatible serialization.
///
/// # Security
///
/// The secret key material is automatically zeroized when this type is dropped
/// (the inner `SecretKey` type implements `ZeroizeOnDrop`).
/// This type does not implement `Clone` or `Copy` to prevent accidental key duplication.
pub struct EcdhSecretKey<C: Curve> {
    inner: SecretKey<C>,
}

impl<C: Curve> fmt::Debug for EcdhSecretKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(core::any::type_name::<Self>())
            .finish_non_exhaustive()
    }
}

impl<C> EcdhSecretKey<C>
where
    C: CurveArithmetic,
{
    /// Construct a secret key from JWK `d` scalar bytes.
    ///
    /// # Arguments
    /// * `d` - The private scalar as bytes
    ///
    /// # Errors
    /// Returns `Error::InvalidKey` if the scalar is zero or >= curve order.
    pub fn from_bytes(d: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = SecretKey::<C>::from_slice(d.as_ref()).map_err(|_| Error::InvalidKey)?;
        Ok(Self { inner })
    }

    /// Generate a new random secret key.
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Errors
    /// Returns `Error::Rng` if the RNG fails.
    pub fn random(rng: &mut impl TryCryptoRng) -> Result<Self, Error> {
        let inner = SecretKey::try_generate_from_rng(rng).map_err(|_| Error::Rng)?;
        Ok(Self { inner })
    }
}

impl<C> EcdhSecretKey<C>
where
    C: CurveArithmetic + EcdhCurve,
{
    /// Get the curve identifier (for JWK serialization).
    pub fn crv(&self) -> EcCurves {
        C::CURVE
    }

    /// Get the private scalar bytes (JWK `d` parameter).
    pub fn d(&self) -> Secret {
        self.inner.to_bytes().as_slice().to_vec().into()
    }

    /// Derive the public key from this secret key.
    pub fn public_key(&self) -> EcdhPublicKey<C> {
        self.inner.public_key().into()
    }

    /// Derive a key from ECDH key agreement and the concat KDF (RFC 7518 Section 4.6.2).
    ///
    /// Performs DH with `other`, then runs the result through the concat KDF. The
    /// `algorithm_id` and `keydatalen` are determined by `params.algorithm`.
    pub fn derive(&self, other: &EcdhPublicKey<C>, params: &EcdhDeriveParams) -> Secret {
        let z = self.agree(other);
        concat_kdf(
            z.raw_secret_bytes(),
            params.algorithm.keydatalen(),
            params.algorithm.algorithm_id(),
            params.apu.as_ref(),
            params.apv.as_ref(),
        )
    }

    fn agree(&self, other: &EcdhPublicKey<C>) -> SharedSecret<C> {
        diffie_hellman::<C>(self.inner.to_nonzero_scalar(), other.inner.as_affine())
    }
}

impl<C> From<SecretKey<C>> for EcdhSecretKey<C>
where
    C: CurveArithmetic,
{
    fn from(inner: SecretKey<C>) -> Self {
        Self { inner }
    }
}

impl<C> From<EcdhSecretKey<C>> for SecretKey<C>
where
    C: CurveArithmetic,
{
    fn from(key: EcdhSecretKey<C>) -> Self {
        key.inner
    }
}

/// Concatenation KDF per RFC 7518 Section 4.6.2 / NIST.800-56A Section 5.8.1.
///
/// Uses SHA-256 as the hash function. Derives keying material of `keydatalen` bits.
///
/// # Arguments
/// * `z` - The shared secret from ECDH key agreement
/// * `keydatalen` - The length of the key to derive in bits
/// * `algorithm_id` - The algorithm ID (e.g., b"A128GCM")
/// * `apu` - Agreement PartyUInfo (optional)
/// * `apv` - Agreement PartyVInfo (optional)
///
/// # Returns
/// The derived key as a `Secret` (zeroized on drop).
fn concat_kdf(
    z: impl AsRef<[u8]>,
    keydatalen: usize,
    algorithm_id: impl AsRef<[u8]>,
    apu: Option<impl AsRef<[u8]>>,
    apv: Option<impl AsRef<[u8]>>,
) -> Secret {
    let z = z.as_ref();

    let algorithm_id = algorithm_id.as_ref();
    let algorithm_id_len = (algorithm_id.len() as u32).to_be_bytes();

    let apu = apu.as_ref().map(|s| s.as_ref()).unwrap_or(&[]);
    let apu_len = (apu.len() as u32).to_be_bytes();

    let apv = apv.as_ref().map(|s| s.as_ref()).unwrap_or(&[]);
    let apv_len = (apv.len() as u32).to_be_bytes();

    let mut derived = vec![0u8; keydatalen.div_ceil(8)];
    let mut hasher = Sha256::new();

    let mut i = 1u32;
    for chunk in derived.chunks_mut(<Sha256 as OutputSizeUser>::OutputSize::USIZE) {
        hasher.update(i.to_be_bytes());
        hasher.update(z);
        hasher.update(algorithm_id_len);
        hasher.update(algorithm_id);
        hasher.update(apu_len);
        hasher.update(apu);
        hasher.update(apv_len);
        hasher.update(apv);
        // SuppPubInfo: keydatalen in bits as a 4-byte big-endian value
        hasher.update((keydatalen as u32).to_be_bytes());

        chunk.copy_from_slice(&hasher.finalize_reset()[..chunk.len()]);

        i += 1;
    }

    derived.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors from RFC 7518 Appendix C - Example ECDH-ES Key Agreement Computation
    #[test]
    fn ecdh_p256_rfc7518_appendix_c() {
        // Alice's ephemeral private key (sender)
        let alice_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];
        // Bob's static private key (recipient)
        let bob_d: [u8; 32] = [
            0x54, 0x49, 0x83, 0x66, 0x90, 0xd7, 0x5c, 0xaf, 0x29, 0xf0, 0xdd, 0x02, 0x9d, 0xdb,
            0x31, 0xb3, 0xdd, 0xb8, 0xab, 0xa9, 0xd2, 0xd5, 0x15, 0xc5, 0x01, 0x24, 0x65, 0xe8,
            0x17, 0xd4, 0xa9, 0xdc,
        ];
        // Expected shared secret Z
        let expected_z: [u8; 32] = [
            0x9e, 0x56, 0xd9, 0x1d, 0x81, 0x71, 0x35, 0xd3, 0x72, 0x83, 0x42, 0x83, 0xbf, 0x84,
            0x26, 0x9c, 0xfb, 0x31, 0x6e, 0xa3, 0xda, 0x80, 0x6a, 0x48, 0xf6, 0xda, 0xa7, 0x79,
            0x8c, 0xfe, 0x90, 0xc4,
        ];

        // Create keys
        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();
        let alice_public = alice_secret.public_key();

        // Both sides compute the same shared secret
        let z_alice = alice_secret.agree(&bob_public);
        let z_bob = bob_secret.agree(&alice_public);

        assert_eq!(
            z_alice.raw_secret_bytes().as_ref(),
            expected_z,
            "Alice's Z does not match expected"
        );
        assert_eq!(
            z_bob.raw_secret_bytes().as_ref(),
            expected_z,
            "Bob's Z does not match expected"
        );
        assert_eq!(
            z_alice.raw_secret_bytes(),
            z_bob.raw_secret_bytes(),
            "Shared secrets don't match"
        );
    }

    #[test]
    fn ecdh_public_key_jwk_export() {
        // Use deterministic test keys from RFC 7518
        let alice_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];

        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let alice_public = alice_secret.public_key();

        // Verify JWK export functions
        assert_eq!(alice_public.crv(), EcCurves::P256);
        assert_eq!(alice_secret.d().as_ref(), alice_d);
        assert_eq!(alice_public.x().as_ref().len(), 32);
        assert_eq!(alice_public.y().as_ref().len(), 32);
    }

    #[test]
    fn ecdh_secret_key_jwk_export() {
        let bob_d: [u8; 32] = [
            0x54, 0x49, 0x83, 0x66, 0x90, 0xd7, 0x5c, 0xaf, 0x29, 0xf0, 0xdd, 0x02, 0x9d, 0xdb,
            0x31, 0xb3, 0xdd, 0xb8, 0xab, 0xa9, 0xd2, 0xd5, 0x15, 0xc5, 0x01, 0x24, 0x65, 0xe8,
            0x17, 0xd4, 0xa9, 0xdc,
        ];

        let bob_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();

        // Verify JWK export functions
        assert_eq!(bob_secret.crv(), EcCurves::P256);
        assert_eq!(bob_secret.d().as_ref(), bob_d);
        assert_eq!(bob_public.x().as_ref().len(), 32);
        assert_eq!(bob_public.y().as_ref().len(), 32);
    }

    #[test]
    fn ecdh_public_key_from_components() {
        // Alice's ephemeral key from RFC 7518
        let alice_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];

        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let alice_public = alice_secret.public_key();

        // Get x and y
        let x = alice_public.x();
        let y = alice_public.y();

        // Reconstruct public key from components
        let reconstructed =
            EcdhPublicKey::<p256::NistP256>::from_components(x.as_ref(), y.as_ref()).unwrap();

        // Should be the same key
        assert_eq!(alice_public, reconstructed);
    }

    #[test]
    fn ecdh_roundtrip_p256() {
        // Use deterministic test keys from RFC 7518 Appendix C
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

        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();

        // Both sides agree
        let z1 = alice_secret.agree(&bob_public);
        let z2 = bob_secret.agree(&alice_secret.public_key());

        assert_eq!(z1.raw_secret_bytes(), z2.raw_secret_bytes());
    }

    #[test]
    fn ecdh_roundtrip_p384() {
        // Use deterministic test keys
        let alice_d: [u8; 48] = [
            0x64, 0xdf, 0x86, 0x36, 0xee, 0x2f, 0x59, 0x70, 0x8d, 0x93, 0xe4, 0x02, 0x82, 0x5d,
            0x41, 0x9e, 0x0c, 0x5f, 0xa9, 0x0e, 0x8d, 0x97, 0x1a, 0x12, 0xbf, 0x1a, 0x6b, 0x9f,
            0xd9, 0xf8, 0x4e, 0x5c, 0x8b, 0x5e, 0x5d, 0x12, 0x14, 0x47, 0x1e, 0x52, 0x67, 0x81,
            0x5d, 0xab, 0xbe, 0x8c, 0xa1, 0x43,
        ];
        let bob_d: [u8; 48] = [
            0x12, 0xdd, 0x65, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
            0x4f, 0x4f, 0x4f, 0x4f, 0x4f, 0x4f,
        ];

        let alice_secret = EcdhSecretKey::<p384::NistP384>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p384::NistP384>::from_bytes(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();

        // Both sides agree
        let z1 = alice_secret.agree(&bob_public);
        let z2 = bob_secret.agree(&alice_secret.public_key());

        assert_eq!(z1.raw_secret_bytes(), z2.raw_secret_bytes());
    }

    #[test]
    fn ecdh_roundtrip_p521() {
        // Use deterministic test keys (small scalars guaranteed to be valid)
        let alice_d: [u8; 66] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let bob_d: [u8; 66] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];

        let alice_secret = EcdhSecretKey::<p521::NistP521>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p521::NistP521>::from_bytes(&bob_d).unwrap();
        let bob_public = bob_secret.public_key();

        // Both sides agree
        let z1 = alice_secret.agree(&bob_public);
        let z2 = bob_secret.agree(&alice_secret.public_key());

        assert_eq!(z1.raw_secret_bytes(), z2.raw_secret_bytes());
    }

    #[test]
    fn ecdh_secret_key_from_bytes_invalid() {
        // Zero scalar should be invalid
        let zero = [0u8; 32];
        assert!(EcdhSecretKey::<p256::NistP256>::from_bytes(&zero).is_err());

        // All 0xFF should be invalid (>= curve order)
        let invalid = [0xFFu8; 32];
        assert!(EcdhSecretKey::<p256::NistP256>::from_bytes(&invalid).is_err());
    }

    #[test]
    fn ecdh_public_key_from_components_invalid() {
        // Invalid x (all zeros) - this is valid point encoding but may not be on curve
        // We just check that it returns an error for obviously wrong input
        let x = [0u8; 32];
        let y = [0u8; 32];
        assert!(EcdhPublicKey::<p256::NistP256>::from_components(&x, &y).is_err());
    }

    #[test]
    fn ecdh_curve_detection() {
        // Use valid scalars from RFC test vectors
        let p256_d: [u8; 32] = [
            0xd3, 0xf3, 0x71, 0x69, 0x13, 0xd4, 0x31, 0x0a, 0x00, 0x26, 0xde, 0x74, 0x1b, 0x3f,
            0x18, 0x89, 0x3a, 0xfc, 0x81, 0x14, 0xf0, 0xc8, 0x46, 0x82, 0xba, 0x67, 0x7e, 0x31,
            0x3a, 0x13, 0x98, 0x8a,
        ];
        let p384_d: [u8; 48] = [
            0x64, 0xdf, 0x86, 0x36, 0xee, 0x2f, 0x59, 0x70, 0x8d, 0x93, 0xe4, 0x02, 0x82, 0x5d,
            0x41, 0x9e, 0x0c, 0x5f, 0xa9, 0x0e, 0x8d, 0x97, 0x1a, 0x12, 0xbf, 0x1a, 0x6b, 0x9f,
            0xd9, 0xf8, 0x4e, 0x5c, 0x8b, 0x5e, 0x5d, 0x12, 0x14, 0x47, 0x1e, 0x52, 0x67, 0x81,
            0x5d, 0xab, 0xbe, 0x8c, 0xa1, 0x43,
        ];
        let p521_d: [u8; 66] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
        ];

        let p256_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&p256_d).unwrap();
        let p384_secret = EcdhSecretKey::<p384::NistP384>::from_bytes(&p384_d).unwrap();
        let p521_secret = EcdhSecretKey::<p521::NistP521>::from_bytes(&p521_d).unwrap();

        assert_eq!(p256_secret.crv(), EcCurves::P256);
        assert_eq!(p384_secret.crv(), EcCurves::P384);
        assert_eq!(p521_secret.crv(), EcCurves::P521);

        assert_eq!(p256_secret.public_key().crv(), EcCurves::P256);
        assert_eq!(p384_secret.public_key().crv(), EcCurves::P384);
        assert_eq!(p521_secret.public_key().crv(), EcCurves::P521);
    }

    /// Test vectors from RFC 7518 Appendix C - Example ECDH-ES Key Agreement Computation
    #[test]
    fn concat_kdf_rfc7518_appendix_c() {
        let expected_z: [u8; 32] = [
            0x9e, 0x56, 0xd9, 0x1d, 0x81, 0x71, 0x35, 0xd3, 0x72, 0x83, 0x42, 0x83, 0xbf, 0x84,
            0x26, 0x9c, 0xfb, 0x31, 0x6e, 0xa3, 0xda, 0x80, 0x6a, 0x48, 0xf6, 0xda, 0xa7, 0x79,
            0x8c, 0xfe, 0x90, 0xc4,
        ];
        let expected_cek: [u8; 16] = [
            0x56, 0xaa, 0x8d, 0xea, 0xf8, 0x23, 0x6d, 0x20, 0x5c, 0x22, 0x28, 0xcd, 0x71, 0xa7,
            0x10, 0x1a,
        ];

        let derived_cek = concat_kdf(&expected_z, 128, b"A128GCM", Some(b"Alice"), Some(b"Bob"));

        assert_eq!(
            derived_cek.as_ref(),
            expected_cek,
            "Derived CEK does not match RFC 7518 expected value"
        );
    }

    #[test]
    fn concat_kdf_different_algorithms() {
        let z = [0xab; 32];
        let cek_256 = concat_kdf(&z, 256, b"A256GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_256.as_ref().len(), 32);
        let cek_192 = concat_kdf(&z, 192, b"A192GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_192.as_ref().len(), 24);
        let cek_128 = concat_kdf(&z, 128, b"A128GCM", None::<&[u8]>, None::<&[u8]>);
        assert_eq!(cek_128.as_ref().len(), 16);
    }

    #[test]
    fn concat_kdf_empty_party_info() {
        let z = [0xcd; 32];
        let cek_empty = concat_kdf(&z, 128, b"A128GCM", None::<&[u8]>, None::<&[u8]>);
        let cek_explicit = concat_kdf(&z, 128, b"A128GCM", Some(&[]), Some(&[]));
        assert_eq!(cek_empty.as_ref(), cek_explicit.as_ref());
    }

    /// End-to-end ECDH-ES direct: both sides derive the same CEK.
    /// Uses RFC 7518 Appendix C test vectors and verifies against the expected CEK.
    #[test]
    fn ecdh_es_direct_derive_cek() {
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
        // Expected CEK from RFC 7518 Appendix C
        let expected_cek: [u8; 16] = [
            0x56, 0xaa, 0x8d, 0xea, 0xf8, 0x23, 0x6d, 0x20, 0x5c, 0x22, 0x28, 0xcd, 0x71, 0xa7,
            0x10, 0x1a,
        ];

        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&bob_d).unwrap();

        let params = EcdhDeriveParams {
            algorithm: EcdhDerivation::A128Gcm,
            apu: Some(b"Alice".to_vec().into()),
            apv: Some(b"Bob".to_vec().into()),
        };

        let cek_alice = alice_secret.derive(&bob_secret.public_key(), &params);
        let cek_bob = bob_secret.derive(&alice_secret.public_key(), &params);

        assert_eq!(
            cek_alice.as_ref(),
            expected_cek,
            "Alice's CEK does not match RFC 7518"
        );
        assert_eq!(
            cek_bob.as_ref(),
            expected_cek,
            "Bob's CEK does not match RFC 7518"
        );
        assert_eq!(
            cek_alice.as_ref(),
            cek_bob.as_ref(),
            "Both sides must derive the same CEK"
        );
    }

    /// End-to-end ECDH-ES+A128KW: sender wraps a CEK, recipient unwraps it.
    #[cfg(feature = "aes-kw")]
    #[test]
    fn ecdh_es_a128kw_wrap_unwrap() {
        use super::super::{AesKwKey128, UnwrappingKey, WrappingKey};

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
        let original_cek = [0xabu8; 16]; // fixed CEK to be wrapped

        let alice_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&alice_d).unwrap();
        let bob_secret = EcdhSecretKey::<p256::NistP256>::from_bytes(&bob_d).unwrap();

        let params = EcdhDeriveParams {
            algorithm: EcdhDerivation::EcdhEsA128Kw,
            apu: None,
            apv: None,
        };

        // Sender: derive KEK and wrap the CEK
        let kek_sender = alice_secret.derive(&bob_secret.public_key(), &params);
        let mut rng = getrandom::SysRng;
        let wrapped = AesKwKey128::try_from(kek_sender)
            .unwrap()
            .wrap_key(&mut rng, original_cek)
            .unwrap();

        // Recipient: derive the same KEK and unwrap
        let kek_recipient = bob_secret.derive(&alice_secret.public_key(), &params);
        let unwrapped = AesKwKey128::try_from(kek_recipient)
            .unwrap()
            .unwrap_key(&wrapped)
            .unwrap();

        assert_eq!(unwrapped.as_ref(), original_cek);
    }
}
