//! AES-256-GCM for TOTP secrets and passkey data at rest.
//!
//! Sealed bytes are `MAGIC || nonce || ciphertext || tag`; sealed text is `TEXT_PREFIX` followed
//! by the same bytes without `MAGIC`, base64url-encoded. A random 96-bit nonce per value is fine
//! at this scale: a handful of accounts rewrite a passkey on each use, far from the 2^32 limit.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use uuid::Uuid;

use crate::crypto::random_bytes;
use crate::error::Error;

const MAGIC: &[u8] = b"lk1\0";
const TEXT_PREFIX: &str = "lk1:";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub(crate) struct DataKey {
    cipher: Aes256Gcm,
}

/// What a stored value is bound to; a value sealed for one owner or kind does not open as
/// another.
pub(crate) enum Aad {
    Totp { user: Uuid },
    Passkey { user: Uuid, passkey: Uuid },
}

impl Aad {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Aad::Totp { user } => format!("latchkey-totp:{user}"),
            Aad::Passkey { user, passkey } => format!("latchkey-passkey:{user}:{passkey}"),
        }
        .into_bytes()
    }
}

/// How a stored value looks before it is opened.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    Sealed,
    Plaintext,
}

pub(crate) fn classify_bytes(stored: &[u8]) -> Stored {
    if stored.starts_with(MAGIC) && stored.len() >= MAGIC.len() + NONCE_LEN + TAG_LEN {
        Stored::Sealed
    } else {
        Stored::Plaintext
    }
}

pub(crate) fn classify_text(stored: &str) -> Stored {
    if stored.starts_with(TEXT_PREFIX) {
        Stored::Sealed
    } else {
        Stored::Plaintext
    }
}

impl DataKey {
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(&(*key).into()),
        }
    }

    fn seal_raw(&self, aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = Nonce::from(nonce_bytes);
        let aad = aad.bytes();
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Internal("encryption failed".into()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn open_raw(&self, aad: &Aad, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let (nonce_bytes, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
        let nonce = Nonce::try_from(nonce_bytes).ok()?;
        let aad = aad.bytes();
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .ok()
    }

    pub(crate) fn seal_bytes(&self, aad: &Aad, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let raw = self.seal_raw(aad, plaintext)?;
        let mut out = Vec::with_capacity(MAGIC.len() + raw.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// `None` when the value is plaintext, was sealed under another key, or is bound to
    /// another owner or kind.
    pub(crate) fn open_bytes(&self, aad: &Aad, stored: &[u8]) -> Option<Vec<u8>> {
        if classify_bytes(stored) != Stored::Sealed {
            return None;
        }
        self.open_raw(aad, stored.get(MAGIC.len()..)?)
    }

    pub(crate) fn seal_text(&self, aad: &Aad, plaintext: &str) -> Result<String, Error> {
        let raw = self.seal_raw(aad, plaintext.as_bytes())?;
        Ok(format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    pub(crate) fn open_text(&self, aad: &Aad, stored: &str) -> Option<String> {
        let encoded = stored.strip_prefix(TEXT_PREFIX)?;
        let raw = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        String::from_utf8(self.open_raw(aad, &raw)?).ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn totp(user: Uuid) -> Aad {
        Aad::Totp { user }
    }

    #[test]
    fn bytes_round_trip_and_hide_the_plaintext() {
        let key = DataKey::new(&[9; 32]);
        let user = Uuid::new_v4();
        let secret = [7u8; 20];
        let sealed = key.seal_bytes(&totp(user), &secret).unwrap();
        assert_eq!(classify_bytes(&sealed), Stored::Sealed);
        assert!(!sealed.windows(secret.len()).any(|w| w == secret));
        assert_eq!(key.open_bytes(&totp(user), &sealed).unwrap(), secret);
    }

    #[test]
    fn values_are_bound_to_owner_and_kind() {
        let key = DataKey::new(&[9; 32]);
        let user = Uuid::new_v4();
        let passkey = Uuid::new_v4();
        let sealed = key.seal_bytes(&totp(user), b"secret").unwrap();
        assert!(key.open_bytes(&totp(Uuid::new_v4()), &sealed).is_none());
        let text = key
            .seal_text(&Aad::Passkey { user, passkey }, "{\"cred\":1}")
            .unwrap();
        assert_eq!(classify_text(&text), Stored::Sealed);
        assert!(
            key.open_text(
                &Aad::Passkey {
                    user,
                    passkey: Uuid::new_v4()
                },
                &text
            )
            .is_none()
        );
        assert!(
            key.open_text(
                &Aad::Passkey {
                    user: Uuid::new_v4(),
                    passkey
                },
                &text
            )
            .is_none()
        );
        assert_eq!(
            key.open_text(&Aad::Passkey { user, passkey }, &text)
                .unwrap(),
            "{\"cred\":1}"
        );
    }

    #[test]
    fn another_key_or_a_flipped_bit_does_not_open() {
        let key = DataKey::new(&[9; 32]);
        let other = DataKey::new(&[8; 32]);
        let user = Uuid::new_v4();
        let mut sealed = key.seal_bytes(&totp(user), b"secret").unwrap();
        assert!(other.open_bytes(&totp(user), &sealed).is_none());
        if let Some(last) = sealed.last_mut() {
            *last ^= 1;
        }
        assert!(key.open_bytes(&totp(user), &sealed).is_none());
    }

    #[test]
    fn plaintext_is_recognised() {
        assert_eq!(classify_bytes(&[1u8; 20]), Stored::Plaintext);
        assert_eq!(classify_bytes(b"lk1\0short"), Stored::Plaintext);
        assert_eq!(classify_text("{\"cred\":{}}"), Stored::Plaintext);
        let key = DataKey::new(&[9; 32]);
        assert!(key.open_bytes(&totp(Uuid::new_v4()), &[1u8; 20]).is_none());
    }
}
