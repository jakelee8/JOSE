//! RSA algorithm mappings

#![cfg(feature = "rsa")]

use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{Sealing, Signing};

// RSA-OAEP with SHA-1 maps to RsaOaep
impl From<rsa::Oaep<Sha1>> for Sealing {
    fn from(_alg: rsa::Oaep<Sha1>) -> Self {
        Sealing::RsaOaep
    }
}

impl From<&rsa::Oaep<Sha1>> for Sealing {
    fn from(_alg: &rsa::Oaep<Sha1>) -> Self {
        Sealing::RsaOaep
    }
}

// RSA-OAEP with SHA-256 maps to RsaOaep256
impl From<rsa::Oaep<Sha256>> for Sealing {
    fn from(_alg: rsa::Oaep<Sha256>) -> Self {
        Sealing::RsaOaep256
    }
}

impl From<&rsa::Oaep<Sha256>> for Sealing {
    fn from(_alg: &rsa::Oaep<Sha256>) -> Self {
        Sealing::RsaOaep256
    }
}

// RSA key types for sealing (default to RSA-OAEP)
impl From<rsa::RsaPublicKey> for Sealing {
    fn from(_key: rsa::RsaPublicKey) -> Self {
        Sealing::RsaOaep
    }
}

impl From<&rsa::RsaPublicKey> for Sealing {
    fn from(_key: &rsa::RsaPublicKey) -> Self {
        Sealing::RsaOaep
    }
}

impl From<rsa::RsaPrivateKey> for Sealing {
    fn from(_key: rsa::RsaPrivateKey) -> Self {
        Sealing::RsaOaep
    }
}

impl From<&rsa::RsaPrivateKey> for Sealing {
    fn from(_key: &rsa::RsaPrivateKey) -> Self {
        Sealing::RsaOaep
    }
}

// RSASSA-PSS variants map to Signing algorithms
impl From<rsa::Pss<Sha256>> for Signing {
    fn from(_alg: rsa::Pss<Sha256>) -> Self {
        Signing::Ps256
    }
}

impl From<&rsa::Pss<Sha256>> for Signing {
    fn from(_alg: &rsa::Pss<Sha256>) -> Self {
        Signing::Ps256
    }
}

impl From<rsa::Pss<Sha384>> for Signing {
    fn from(_alg: rsa::Pss<Sha384>) -> Self {
        Signing::Ps384
    }
}

impl From<&rsa::Pss<Sha384>> for Signing {
    fn from(_alg: &rsa::Pss<Sha384>) -> Self {
        Signing::Ps384
    }
}

impl From<rsa::Pss<Sha512>> for Signing {
    fn from(_alg: rsa::Pss<Sha512>) -> Self {
        Signing::Ps512
    }
}

impl From<&rsa::Pss<Sha512>> for Signing {
    fn from(_alg: &rsa::Pss<Sha512>) -> Self {
        Signing::Ps512
    }
}

// RSASSA-PKCS1-v1_5 variants map to Signing algorithms
impl From<rsa::pkcs1v15::SigningKey<Sha256>> for Signing {
    fn from(_key: rsa::pkcs1v15::SigningKey<Sha256>) -> Self {
        Signing::Rs256
    }
}

impl From<&rsa::pkcs1v15::SigningKey<Sha256>> for Signing {
    fn from(_key: &rsa::pkcs1v15::SigningKey<Sha256>) -> Self {
        Signing::Rs256
    }
}

impl From<rsa::pkcs1v15::SigningKey<Sha384>> for Signing {
    fn from(_key: rsa::pkcs1v15::SigningKey<Sha384>) -> Self {
        Signing::Rs384
    }
}

impl From<&rsa::pkcs1v15::SigningKey<Sha384>> for Signing {
    fn from(_key: &rsa::pkcs1v15::SigningKey<Sha384>) -> Self {
        Signing::Rs384
    }
}

impl From<rsa::pkcs1v15::SigningKey<Sha512>> for Signing {
    fn from(_key: rsa::pkcs1v15::SigningKey<Sha512>) -> Self {
        Signing::Rs512
    }
}

impl From<&rsa::pkcs1v15::SigningKey<Sha512>> for Signing {
    fn from(_key: &rsa::pkcs1v15::SigningKey<Sha512>) -> Self {
        Signing::Rs512
    }
}
