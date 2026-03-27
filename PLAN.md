# JOSE Crypto Restructuring Plan

## Overview

This plan documents the restructuring of `jose-jwa` to expose ergonomic crypto abstractions that completely hide RustCrypto implementation details. The goal is to enable `jose-jwk` to work with JWKs without direct crypto library dependencies.

## Architecture

### Design Principles

1. **Opaque Key Types**: `jose-jwa` exposes concrete key types (`SigningKey`, `VerifyingKey`, `EncryptingKey`, `DecryptingKey`) that wrap RustCrypto types
2. **Trait-Based API**: Clean traits for signing, verification, encryption, and key wrapping
3. **Streaming Support**: Signing uses two-phase process with `Update` trait for streaming
4. **One-Shot Convenience**: Convenience methods for one-shot operations
5. **Flexible Input Types**: Use `impl AsRef<[u8]>` for all data inputs
6. **Secure Defaults**: All sensitive data returns `jose_b64::serde::Secret` or `Zeroizing<Vec<u8>>`
7. **Single Error Type**: All operations return a unified `CryptoError` type (consolidated from module-specific errors)

### Module Structure

```
jose-jwa/src/crypto/
├── sign.rs          # SigningKey, Signer traits (consolidated with verify)
├── secret/
│   ├── enc.rs       # EncryptingKey, DecryptingKey traits
│   └── mod.rs       # Re-exports
├── key/             # Concrete key implementations
│   ├── ecdsa.rs     # EcdsaSigningKey, EcdsaVerifyingKey
│   ├── hmac.rs      # HmacKey (signing + verifying)
│   ├── rsa.rs       # RsaSigningKey, RsaVerifyingKey
│   ├── aes_gcm.rs   # AesGcmKey<N> for content encryption
│   ├── aes_kw.rs    # AesKwKey<N> for key wrapping
│   └── mod.rs       # Re-exports
├── mod.rs           # Re-exports from key/ module, unified CryptoError
```

## Implementation Status

### NOT Completed (Plan Status Corrected)

- [x] New trait definitions in `sign.rs`
- [ ] ~~`verify.rs`~~ - REDUNDANT, merge into `sign.rs` (Verifier/VerifyingKey re-export from sign)
- [x] `secret/enc.rs` with `EncryptingKey` and `DecryptingKey` traits
- [ ] `crypto/key/` module with concrete implementations:
  - [ ] `ecdsa.rs` - **HAS COMPILATION ERRORS** (missing CurveArithmetic bound on EcdsaSigner/EcdsaVerifier)
  - [ ] `hmac.rs` - **HAS COMPILATION ERRORS** (lifetime mismatch on Signer associated type)
  - [x] `rsa.rs` - RSA signing/verification keys
  - [ ] `aes_gcm.rs` - **INCOMPLETE** (missing EncryptingKey/DecryptingKey impl for AesGcmKey<24>)
  - [x] `aes_kw.rs` - AES key wrapping (A128KW, A192KW, A256KW)
- [x] Module exports in `crypto/key/mod.rs`
- [x] Re-exports in `crypto/mod.rs`

### In Progress

- [ ] Fix compilation errors in key implementations
- [ ] Consolidate error types into single `CryptoError` enum
- [ ] Remove old implementation files (cleanup)
- [ ] Update dependent crates (jose-jws, jose-jwe)

### Critical Issues Found

1. **Aes192Gcm Support EXISTS - Plan is Wrong**: `Aes192Gcm` IS supported and actively used:
   - Defined in `crypto/secret/enc.rs` as `pub type Aes192Gcm = AesGcm<Aes192, U12>`
   - Used in `crypto/km/aes_gcm_kw.rs` for A192GCMKW key wrapping
   - Used in `crypto/secret/enc.rs` for Encryption::A192Gcm
   - **ACTION**: Update plan to PRESERVE Aes192Gcm support, not remove it

2. **Missing CurveArithmetic Bound**: `EcdsaSigner<'a, C>` and `EcdsaVerifier<'a, C>` structs in `key/ecdsa.rs` need `C: CurveArithmetic` bound (lines 172, 202) to satisfy `ecdsa::SigningKey`/`ecdsa::VerifyingKey` requirements.

3. **HmacKey Lifetime Mismatch**: `HmacKey` implements `SigningKey` with `type Signer = HmacSigner` (line 103) but trait requires `type Signer<'a>` (GAT). Must use `type Signer<'a> = HmacSigner where Self: 'a`.

4. **Missing Aes192GcmKey Impl**: `AesGcmKey<24>` type alias exists but has NO `EncryptingKey`/`DecryptingKey` impl blocks (only `<16>` and `<32>` have impls). This is a bug.

5. **Multiple Error Types Fragmentation**: Currently ~7 different error types:
   - `EcdsaError`, `HmacError`, `RsaError`, `AesGcmError`, `AesKwError` (in key/ modules)
   - `CipherError` (in crypto/mod.rs)
   - `HmacVerifyError` (in crypto/hmac/state.rs - old)

   **ACTION**: Delete module-specific error types and use `CryptoError` directly throughout the crate

## Trait API

### SigningKey

```rust
pub trait SigningKey {
    type Error: Error;
    type Signer<'a>: Signer where Self: 'a;

    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error>;
    fn sign(&self, data: impl AsRef<[u8]>, rng: impl TryCryptoRng) -> Result<Vec<u8>, Self::Error>;
}
```

### Signer

```rust
pub trait Signer: Update {
    type Error: Error;
    fn finish(self, rng: impl TryCryptoRng) -> Result<Vec<u8>, Self::Error>;
}
```

### VerifyingKey

```rust
pub trait VerifyingKey {
    type Error: Error;
    type Verifier<'a>: Verifier where Self: 'a;

    fn verifier(&self) -> Result<Self::Verifier<'_>, Self::Error>;
    fn verify(&self, data: impl AsRef<[u8]>, signature: impl AsRef<[u8]>) -> Result<(), Self::Error>;
}
```

### Verifier

```rust
pub trait Verifier: Update {
    type Error: Error;
    fn finish(self, signature: impl AsRef<[u8]>) -> Result<(), <Self as Verifier>::Error>;
}
```

### EncryptingKey

```rust
pub trait EncryptingKey {
    type Error;
    fn encrypt(
        &self,
        rng: impl TryCryptoRng,
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error>;
}
```

### DecryptingKey

```rust
pub trait DecryptingKey {
    type Error;
    fn decrypt(
        &self,
        ciphertext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
        tag: impl AsRef<[u8]>,
        iv: impl AsRef<[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error>;
}
```

## Key Types

### ECDSA

- `EcdsaSigningKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic>`
- `EcdsaVerifyingKey<C: EcdsaCurve + DigestAlgorithm + CurveArithmetic>`
- Type aliases: `Es256SigningKey`, `Es384SigningKey`, `Es512SigningKey`, `Es256KSigningKey`
- Type aliases: `Es256VerifyingKey`, `Es384VerifyingKey`, `Es512VerifyingKey`, `Es256KVerifyingKey`

### HMAC

- `HmacKey` - single type for both signing and verification
- Implements both `SigningKey` and `VerifyingKey`
- Internal state types: `HmacSigner`, `HmacVerifier`

### RSA

- `RsaSigningKey` - RSA signing with PKCS1v15 or PSS padding
- `RsaVerifyingKey` - RSA verification with PKCS1v15 or PSS padding
- Supports RS256, RS384, RS512, PS256, PS384, PS512

### AES-GCM

- `AesGcmKey<const N: usize>` - generic over key size
- Type aliases: `Aes128GcmKey` (N=16), `Aes192GcmKey` (N=24), `Aes256GcmKey` (N=32)
- **CORRECTION**: A192GCM IS supported. The `Aes192Gcm` type exists in `secret/enc.rs` and is used in AES-GCM-KW.
- **BUG**: Missing `EncryptingKey`/`DecryptingKey` impl for `AesGcmKey<24>` (Aes192GcmKey)

### AES-KW

- `AesKwKey<const N: usize>` - generic over key size
- Type aliases: `Aes128KwKey` (N=16), `Aes192KwKey` (N=24), `Aes256KwKey` (N=32)

## Recommended Design Changes

### 1. Consolidate Error Types

**Current State**: ~7 different error types across modules:
- `EcdsaError`, `HmacError`, `RsaError`, `AesGcmError`, `AesKwError` (in key/)
- `CipherError` (in crypto/mod.rs)
- `HmacVerifyError` (in crypto/hmac/state.rs - old)

**Constraint**: DO NOT EXPOSE RustCrypto types, even error types. All errors must be wrapped in jose-jwa's own error types.

**Recommendation**: Replace ALL with single `CryptoError` enum in `crypto/mod.rs`:

```rust
#[derive(Debug)]
pub enum CryptoError {
    // Key-related
    InvalidKey,
    InvalidKeyLength,
    InvalidAlgorithm,
    // Operation-related
    SigningFailed,
    VerificationFailed,
    EncryptionFailed,
    DecryptionFailed,
    WrapFailed,
    UnwrapFailed,
    // AEAD-specific
    InvalidIvLength,
    InvalidTagLength,
    Aead,
    // RNG
    Rng,
}

impl core::fmt::Display for CryptoError { ... }
impl core::error::Error for CryptoError {}
```

Delete module-specific error types. `From` implementations are acceptable as long as the underlying RustCrypto error types are not publicly exposed:

```rust
impl From<signature::Error> for CryptoError {
    fn from(_: signature::Error) -> Self {
        CryptoError::SigningFailed
    }
}
```

**DO NOT USE thiserror** - minimize dependencies. Implement Display and Error manually.

### 2. Fix Compilation Errors

**File: `crypto/key/ecdsa.rs`**
- Add `CurveArithmetic` bound to `EcdsaSigner<'a, C>` and `EcdsaVerifier<'a, C>` (lines ~172, ~202)

**File: `crypto/key/hmac.rs`**
- Fix `type Signer<'a>` GAT to match trait definition (line ~103)

**File: `crypto/key/aes_gcm.rs`**
- Add `EncryptingKey` and `DecryptingKey` impl blocks for `AesGcmKey<24>` (Aes192GcmKey)

### 3. Module Cleanup

**Remove old implementations**:
- `crypto/hmac/state.rs` - Old HMAC trait impls (superseded by key/hmac.rs)
- `crypto/ecdsa/sign.rs` and `crypto/ecdsa/verify.rs` - Old ECDSA trait impls
- `crypto/rsa/sign.rs` and `crypto/rsa/verify.rs` - Old RSA trait impls
- `crypto/digest.rs` - May contain old digest utilities

**Keep**: `crypto/ecdsa/mod.rs`, `crypto/ecdsa/p256.rs`, etc. for curve-specific implementations

### 4. Key Trait Design

**Constraint**: DO NOT define a common `Key` trait in jose-jwa. JWK-related functionality belongs in jose-jwk, not jose-jwa.

jose-jwa is responsible for:
- Algorithm-specific key types (EcdsaSigningKey, HmacKey, RsaSigningKey, etc.)
- Cryptographic operations (sign, verify, encrypt, decrypt, wrap, unwrap)

jose-jwk is responsible for:
- JWK serialization/deserialization
- Algorithm-agnostic key management
- The common `Key` trait for JWK fields (kty, use, key_ops, alg)

Algorithm-specific key material export methods belong on concrete types:
- `EcdsaSigningKey::to_bytes(&self) -> Secret` - exports raw scalar
- `EcdsaVerifyingKey::to_sec1_bytes(&self) -> Vec<u8>` - exports SEC1 point
- `EcdsaVerifyingKey::to_coords(&self) -> (Vec<u8>, Vec<u8>)` - exports x, y coordinates
- `HmacKey::to_bytes(&self) -> Secret` - exports raw key material
- `AesGcmKey::to_bytes(&self) -> Secret` - exports raw key bytes

**Constraint**: Keys only need JWK exported fields. Review key exports to ensure they match JWK requirements.

### 5. GAT Design for Memory Efficiency

**Keep GAT-based streaming API** - It's already implemented and provides memory efficiency for RSA/ECDSA keys by holding references rather than cloning keys.

**Constraint**: RSA and ECDSA signing keys should minimize memory usage by holding references (`&'a RsaPrivateKey`) in the signer state, not cloning the entire key.

**Why not Arc?** GAT with references has zero overhead. Arc adds reference counting overhead which is unnecessary for the signer/verifier lifetime pattern.

The GAT pattern with lifetime bounds is correct:
```rust
pub trait SigningKey {
    type Signer<'a>: Signer where Self: 'a;
    fn signer(&self) -> Result<Self::Signer<'_>, Self::Error>;
}
```

For types where cloning is cheap or required because they have state (HMAC keys), owned state types are fine.

### 6. Move RNG Arguments to Type-Specific Constructors

**Current**: `Signer::finish(self, rng: impl TryCryptoRng)` and `EncryptingKey::encrypt(rng, ...)` take RNG at operation time.

**Constraint**: Move RNG into type-specific constructors or stored in the key.

**Rationale**:
- HMAC signing doesn't need RNG at all - remove RNG parameter
- ECDSA signing requires RNG - store RNG in key or signer creation
- AES-GCM encryption requires RNG for IV generation - pass RNG at encryption time

**Recommendation**:
```rust
// For deterministic operations (HMAC) - no RNG
pub trait Signer: Update {
    fn finish(self) -> Result<Bytes, Self::Error>;
}

// For randomized operations (ECDSA, RSA-PSS) - RNG at creation or stored
pub struct EcdsaSigner<'a, C> {
    digest: C::Digest,
    key: &'a EcdsaSigningKeyInner<C>,
    // RNG stored here or passed at creation
}

// For encryption (AES-GCM) - RNG at encrypt time is correct
pub trait EncryptingKey {
    fn encrypt(
        &self,
        rng: impl TryCryptoRng,  // Keep for IV generation
        plaintext: impl AsRef<[u8]>,
        aad: impl AsRef<[u8]>,
    ) -> Result<Encrypted, Self::Error>;
}
```

### 7. Add Compile-Time Verification for AesGcmKey

`AesGcmKey<const N: usize>` carries both const generic AND runtime `alg: Encryption` field. Add a compile-time check that these align, or derive the algorithm from `N`:

```rust
impl<const N: usize> AesGcmKey<N> {
    const ALGORITHM: Encryption = match N {
        16 => Encryption::A128Gcm,
        24 => Encryption::A192Gcm,
        32 => Encryption::A256Gcm,
        _ => panic!("invalid AES-GCM key size"),
    };
}
```

### 7. Update Module Exports

Ensure `crypto/mod.rs` properly re-exports from the new `key/` module:

```rust
#[cfg(feature = "hmac")]
pub use self::key::{HmacKey, CryptoError};
#[cfg(feature = "rsa")]
pub use self::key::{RsaSigningKey, RsaVerifyingKey, RsaError};
// etc.
```

## Migration Path (Blocked Until Compilation Fixes)

**STATUS**: Migration CANNOT proceed until compilation errors are fixed.

### For jose-jwk

1. Wait for `jose-jwa` compilation fixes
2. Remove direct RustCrypto dependencies
3. Use `jose-jwa::crypto::key::*` types for crypto operations
4. JWK types become pure data structures with serialization/deserialization

### For jose-jws

1. Update to use new `SigningKey` and `VerifyingKey` traits
2. Use concrete key types from `jose-jwa::crypto::key`

### For jose-jwe

1. Update to use new `EncryptingKey` and `DecryptingKey` traits
2. Use concrete key types from `jose-jwa::crypto::key`

## Summary of Critical Issues

| Issue | Location | Severity | Fix Required |
|-------|----------|----------|--------------|
| Missing `CurveArithmetic` bound | `key/ecdsa.rs` lines 172, 202 | **Blocking** | Add bound to structs |
| HmacKey lifetime mismatch | `key/hmac.rs` line 103 | **Blocking** | Fix GAT syntax: `Replace <'a> with RPITIT` |
| Missing Aes192GcmKey impl | `key/aes_gcm.rs` | **Bug** | Add impl blocks for N=24 |
| Aes192Gcm incorrectly marked removed | `PLAN.md` line 179 | Documentation | Plan incorrectly states A192GCM removed |
| Multiple error types | Various | Technical Debt | Delete `EcdsaError`, `HmacError`, etc.; use `CryptoError` directly |
| Old impl files | `hmac/state.rs`, `ecdsa/*.rs`, `rsa/*.rs` | Cleanup | Remove after confirming new impls work |
| GAT complexity | `key/hmac.rs` | Design | Use RPITIT for simpler syntax (Rust 1.75+) |

## Testing Strategy

1. Unit tests for each key type
2. Integration tests with known test vectors from RFC 7515, 7516, 7518
3. Property-based testing for round-trip operations
4. Feature flag testing (ensure each feature compiles independently)

## Future Enhancements

1. Add support for ECDH key agreement
2. Add support for PBES2 key wrapping
3. Consider adding async variants for crypto operations
4. Benchmark and optimize hot paths
