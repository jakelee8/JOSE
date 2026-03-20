# [RustCrypto]: jose-jkt

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2.0 OR MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the JWK Thumbprint component of the Javascript
Object Signing and Encryption ([JOSE]) specification as described in [RFC 7638].

A JWK Thumbprint is a hash of the required members of a JSON Web Key ([JWK]),
and provides a deterministic and unique identifier for the key.

```rust
use jose_jwk::{Jwk, Rsa};
use jose_jkt::JwkThumbprint;
use sha2::Sha512;

let jwk = Jwk {
    key: Rsa {
        e: vec![1, 0, 1].into(),
        n: vec![0xAB, 0xCD, 0xEF].into(),
        prv: None,
    }.into(),
    prm: Default::default(),
};

assert_eq!(jwk.thumbprint(), "I5r6_zYlxFlKVu1cnIWv8q0RLoX2fRe2XQ40lwJ6Rvk");
assert_eq!(
    jwk.thumbprint_with_digest::<Sha512>(),
    "uUALByNLLxO2A7sasEiV-YLOVT97AzQ8NqIRhLfj_6TZHQas2L-sGMX7y0SApYjyemE4v0wn-aeVcq3ZIUYbjg"
);
```

[Documentation][docs-link]

## License

Licensed under either of:

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # "badges"

[crate-image]: https://img.shields.io/crates/v/jose-jkt.svg
[crate-link]: https://crates.io/crates/jose-jkt
[docs-image]: https://docs.rs/jose-jkt/badge.svg
[docs-link]: https://docs.rs/jose-jkt/
[license-image]: https://img.shields.io/badge/license-Apache2.0_OR_MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.65+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/300570-formats
[build-image]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jkt.yml/badge.svg
[build-link]: https://github.com/RustCrypto/JOSE/actions/workflows/jose-jkt.yml

[//]: # "links"

[RustCrypto]: https://github.com/RustCrypto/
[JWK]: https://jose.readthedocs.io/en/latest/#jwk
[JOSE]: https://jose.readthedocs.io/
[RFC 7638]: https://datatracker.ietf.org/doc/html/rfc7638
