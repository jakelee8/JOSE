use core::fmt::Display;
use core::str::FromStr;

use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use jose_b64::stream::Error as StreamError;

use crate::{Flattened, General, Jwe, Recipient};

impl<U, P> FromStr for Jwe<U, P>
where
    P: serde::de::DeserializeOwned,
{
    type Err = StreamError<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
}

impl<U, P> FromStr for General<U, P>
where
    P: serde::de::DeserializeOwned,
{
    type Err = StreamError<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Flattened::from_str(s)?.into())
    }
}

impl<U, P> FromStr for Flattened<U, P>
where
    P: serde::de::DeserializeOwned,
{
    type Err = StreamError<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // JWE Compact: PROTECTED.ENCRYPTED_KEY.IV.CIPHERTEXT.TAG
        // Per RFC 7516 Section 7.1
        let mut iter = s.split('.');

        let protected_str = iter.next().ok_or(StreamError::Length)?;
        let encrypted_key_str = iter.next().ok_or(StreamError::Length)?;
        let iv_str = iter.next().ok_or(StreamError::Length)?;
        let ciphertext_str = iter.next().ok_or(StreamError::Length)?;
        let tag_str = iter.next().ok_or(StreamError::Length)?;

        if iter.next().is_some() {
            return Err(StreamError::Length);
        }

        // Protected header MUST be present for JWE compact serialization.
        if protected_str.is_empty() {
            return Err(StreamError::Length);
        }

        let protected = Some(protected_str.parse()?);

        // Parse base64url-encoded fields - use map_err to convert error type
        let encrypted_key = if encrypted_key_str.is_empty() {
            None
        } else {
            Some(
                encrypted_key_str
                    .parse()
                    .map_err(|_| StreamError::<serde_json::Error>::Length)?,
            )
        };

        let iv = if iv_str.is_empty() {
            None
        } else {
            Some(
                iv_str
                    .parse()
                    .map_err(|_| StreamError::<serde_json::Error>::Length)?,
            )
        };

        let ciphertext = ciphertext_str
            .parse()
            .map_err(|_| StreamError::<serde_json::Error>::Length)?;

        let tag = if tag_str.is_empty() {
            None
        } else {
            Some(
                tag_str
                    .parse()
                    .map_err(|_| StreamError::<serde_json::Error>::Length)?,
            )
        };

        Ok(Self {
            payload: crate::Payload {
                ciphertext,
                iv,
                tag,
                aad: None,
            },
            protected,
            unprotected: None,
            recipient: Recipient {
                encrypted_key,
                header: None,
            },
        })
    }
}

impl<U, P> Display for Flattened<U, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Per RFC 7516 Section 7.1, protected header MUST be present for compact serialization.
        let prot = self
            .protected
            .as_ref()
            .map(|x| Base64UrlUnpadded::encode_string(x.as_ref()));

        let encrypted_key = self
            .recipient
            .encrypted_key
            .as_ref()
            .map(|x| Base64UrlUnpadded::encode_string(x));

        let iv = self
            .payload
            .iv
            .as_ref()
            .map(|x| Base64UrlUnpadded::encode_string(x));

        let ciphertext = Base64UrlUnpadded::encode_string(&self.payload.ciphertext);

        let tag = self
            .payload
            .tag
            .as_ref()
            .map(|x| Base64UrlUnpadded::encode_string(x));

        write!(
            f,
            "{}.{}.{}.{}.{}",
            prot.as_deref().unwrap_or(""),
            encrypted_key.as_deref().unwrap_or(""),
            iv.as_deref().unwrap_or(""),
            ciphertext,
            tag.as_deref().unwrap_or("")
        )
    }
}
