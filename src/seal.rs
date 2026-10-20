//! AES-256-GCM sealing for secrets the app stores, such as TOTP secrets and passkey data.
//!
//! Sealed bytes are `"lk1\0" || nonce || ciphertext || tag`; sealed text is `"lk1:"`
//! followed by `nonce || ciphertext || tag` in base64url. Both are the formats latchkey 0.2
//! wrote, so its stored values open unchanged. Each value is bound to its owner and kind
//! through the associated data ([`Aad`]): a value copied into another row does not open.
//!
//! A random 96-bit nonce per value is safe for well under 2^32 seals per key, which a
//! personal app never approaches.
//!
//! ```
//! use latchkey::seal::{Aad, DataKey};
//! use latchkey::UserId;
//!
//! # fn main() -> Result<(), latchkey::Error> {
//! let mut rng = latchkey::os_rng()?;
//! let key = DataKey::new(&[7; 32]);
//! let user = UserId::random(&mut rng);
//! let sealed = key.seal_bytes(&mut rng, &Aad::totp(user), b"secret")?;
//! assert_eq!(key.open_bytes(&Aad::totp(user), &sealed).as_deref(), Some(&b"secret"[..]));
//! assert!(key.open_bytes(&Aad::totp(UserId::random(&mut rng)), &sealed).is_none());
//! # Ok(())
//! # }
//! ```

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::CryptoRng;

use crate::Error;
use crate::ids::{PasskeyId, UserId};
use crate::totp::TotpSecret;

const MAGIC: &[u8] = b"lk1\0";
const TEXT_PREFIX: &str = "lk1:";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The key that seals stored secrets. Keep it apart from every other key, outside the
/// database and its backups. Zeroed on drop.
#[derive(Clone)]
pub struct DataKey {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// What a sealed value is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aad(Vec<u8>);

impl Aad {
    /// A TOTP secret (confirmed or pending) of `user`: `latchkey-totp:<user>`.
    #[must_use]
    pub fn totp(user: UserId) -> Self {
        Self(format!("latchkey-totp:{user}").into_bytes())
    }

    /// The data of one passkey: `latchkey-passkey:<user>:<passkey>`.
    #[must_use]
    pub fn passkey(user: UserId, passkey: PasskeyId) -> Self {
        Self(format!("latchkey-passkey:{user}:{passkey}").into_bytes())
    }

    /// Any other secret of the app's, bound to `context` (for example `"api-key:<row id>"`).
    /// Prefixed with `app:` so it never equals one of latchkey's own.
    #[must_use]
    pub fn app(context: &str) -> Self {
        Self(format!("app:{context}").into_bytes())
    }

    /// The associated data bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// How a stored value looks before it is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// Has the sealed format's prefix.
    Sealed,
    /// Anything else, such as a value latchkey 0.1 stored in plain text.
    Plaintext,
}

/// Whether stored bytes are sealed.
#[must_use]
pub fn classify_bytes(stored: &[u8]) -> Stored {
    if stored.starts_with(MAGIC) && stored.len() >= MAGIC.len() + NONCE_LEN + TAG_LEN {
        Stored::Sealed
    } else {
        Stored::Plaintext
    }
}

/// Whether stored text is sealed.
#[must_use]
pub fn classify_text(stored: &str) -> Stored {
    if stored.starts_with(TEXT_PREFIX) {
        Stored::Sealed
    } else {
        Stored::Plaintext
    }
}

/// Checks the start-up rule latchkey 0.2 enforced on its two keys: both non-zero and
/// different from each other.
///
/// # Errors
///
/// [`Error::Config`] naming the problem.
pub fn check_keys(secret_key: &[u8; 32], data_key: &[u8; 32]) -> Result<(), Error> {
    if secret_key == &[0u8; 32] {
        return Err(Error::Config("secret key is all zeroes"));
    }
    if data_key == &[0u8; 32] {
        return Err(Error::Config("data key is all zeroes"));
    }
    if data_key == secret_key {
        return Err(Error::Config("data key must differ from the secret key"));
    }
    Ok(())
}

impl DataKey {
    /// A key from 32 bytes.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new(&(*key).into()),
        }
    }

    fn seal_raw<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        aad: &Aad,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad.0,
                },
            )
            .map_err(|_| Error::Crypto("encryption failed"))?;
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
        self.cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad.0,
                },
            )
            .ok()
    }

    /// Seals bytes for a binary column.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when encryption fails.
    pub fn seal_bytes<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        aad: &Aad,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let raw = self.seal_raw(rng, aad, plaintext)?;
        let mut out = Vec::with_capacity(MAGIC.len() + raw.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&raw);
        Ok(out)
    }

    /// Opens sealed bytes; `None` when they are plaintext, sealed under another key, bound
    /// to another [`Aad`] or tampered with.
    #[must_use]
    pub fn open_bytes(&self, aad: &Aad, stored: &[u8]) -> Option<Vec<u8>> {
        if classify_bytes(stored) != Stored::Sealed {
            return None;
        }
        self.open_raw(aad, stored.get(MAGIC.len()..)?)
    }

    /// Seals text for a text column.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when encryption fails.
    pub fn seal_text<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        aad: &Aad,
        plaintext: &str,
    ) -> Result<String, Error> {
        let raw = self.seal_raw(rng, aad, plaintext.as_bytes())?;
        Ok(format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    /// Opens sealed text; `None` as for [`open_bytes`](Self::open_bytes).
    #[must_use]
    pub fn open_text(&self, aad: &Aad, stored: &str) -> Option<String> {
        let encoded = stored.strip_prefix(TEXT_PREFIX)?;
        let raw = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        String::from_utf8(self.open_raw(aad, &raw)?).ok()
    }

    /// Seals a TOTP secret of `user`.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when encryption fails.
    pub fn seal_totp<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        user: UserId,
        secret: &TotpSecret,
    ) -> Result<Vec<u8>, Error> {
        self.seal_bytes(rng, &Aad::totp(user), secret.expose_secret())
    }

    /// Opens a TOTP secret of `user`.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when it does not open: a wrong key, another account's value or a
    /// plaintext leftover from latchkey 0.1.
    pub fn open_totp(&self, user: UserId, stored: &[u8]) -> Result<TotpSecret, Error> {
        self.open_bytes(&Aad::totp(user), stored)
            .map(TotpSecret::from_bytes)
            .ok_or(Error::Crypto("a TOTP secret does not decrypt"))
    }

    /// Seals a passkey as JSON text.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when serialising or encryption fails.
    #[cfg(feature = "passkeys")]
    #[cfg_attr(docsrs, doc(cfg(feature = "passkeys")))]
    pub fn seal_passkey<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
        user: UserId,
        id: PasskeyId,
        passkey: &webauthn_rs::prelude::Passkey,
    ) -> Result<String, Error> {
        let json =
            serde_json::to_string(passkey).map_err(|_| Error::Crypto("passkey serialisation"))?;
        self.seal_text(rng, &Aad::passkey(user, id), &json)
    }

    /// Opens a passkey sealed with [`seal_passkey`](Self::seal_passkey).
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when it does not open or parse.
    #[cfg(feature = "passkeys")]
    #[cfg_attr(docsrs, doc(cfg(feature = "passkeys")))]
    pub fn open_passkey(
        &self,
        user: UserId,
        id: PasskeyId,
        stored: &str,
    ) -> Result<webauthn_rs::prelude::Passkey, Error> {
        let json = self
            .open_text(&Aad::passkey(user, id), stored)
            .ok_or(Error::Crypto("a passkey does not decrypt"))?;
        serde_json::from_str(&json).map_err(|_| Error::Crypto("a passkey does not parse"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_hide_the_plaintext() {
        let mut rng = crate::test_rng();
        let key = DataKey::new(&[9; 32]);
        let user = UserId::random(&mut rng);
        let secret = [7u8; 20];
        let sealed = key.seal_bytes(&mut rng, &Aad::totp(user), &secret);
        let sealed = sealed.unwrap_or_default();
        assert_eq!(classify_bytes(&sealed), Stored::Sealed);
        assert!(!sealed.windows(secret.len()).any(|w| w == secret));
        assert_eq!(
            key.open_bytes(&Aad::totp(user), &sealed),
            Some(secret.to_vec())
        );
    }

    #[test]
    fn values_are_bound_to_owner_and_kind() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let key = DataKey::new(&[9; 32]);
        let user = UserId::random(&mut rng);
        let passkey = PasskeyId::random(&mut rng);
        let sealed = key.seal_bytes(&mut rng, &Aad::totp(user), b"secret")?;
        assert!(
            key.open_bytes(&Aad::totp(UserId::random(&mut rng)), &sealed)
                .is_none()
        );
        let text = key.seal_text(&mut rng, &Aad::passkey(user, passkey), "{\"cred\":1}")?;
        assert_eq!(classify_text(&text), Stored::Sealed);
        let other_passkey = Aad::passkey(user, PasskeyId::random(&mut rng));
        assert!(key.open_text(&other_passkey, &text).is_none());
        let other_user = Aad::passkey(UserId::random(&mut rng), passkey);
        assert!(key.open_text(&other_user, &text).is_none());
        assert_eq!(
            key.open_text(&Aad::passkey(user, passkey), &text)
                .as_deref(),
            Some("{\"cred\":1}")
        );
        assert!(key.open_text(&Aad::app("x"), &text).is_none());
        Ok(())
    }

    #[test]
    fn another_key_or_a_flipped_bit_does_not_open() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let key = DataKey::new(&[9; 32]);
        let other = DataKey::new(&[8; 32]);
        let user = UserId::random(&mut rng);
        let mut sealed = key.seal_bytes(&mut rng, &Aad::totp(user), b"secret")?;
        assert!(other.open_bytes(&Aad::totp(user), &sealed).is_none());
        if let Some(last) = sealed.last_mut() {
            *last ^= 1;
        }
        assert!(key.open_bytes(&Aad::totp(user), &sealed).is_none());
        Ok(())
    }

    #[test]
    fn totp_helpers_round_trip() -> Result<(), Error> {
        let mut rng = crate::test_rng();
        let key = DataKey::new(&[9; 32]);
        let user = UserId::random(&mut rng);
        let secret = TotpSecret::random(&mut rng);
        let sealed = key.seal_totp(&mut rng, user, &secret)?;
        assert_eq!(key.open_totp(user, &sealed)?, secret);
        assert!(key.open_totp(UserId::random(&mut rng), &sealed).is_err());
        Ok(())
    }

    #[test]
    fn plaintext_is_recognised() {
        assert_eq!(classify_bytes(&[1u8; 20]), Stored::Plaintext);
        assert_eq!(classify_bytes(b"lk1\0short"), Stored::Plaintext);
        assert_eq!(classify_text("{\"cred\":{}}"), Stored::Plaintext);
        let key = DataKey::new(&[9; 32]);
        let user = UserId::random(&mut crate::test_rng());
        assert!(key.open_bytes(&Aad::totp(user), &[1u8; 20]).is_none());
    }

    #[test]
    fn keys_must_be_nonzero_and_distinct() {
        assert!(check_keys(&[0; 32], &[8; 32]).is_err());
        assert!(check_keys(&[7; 32], &[0; 32]).is_err());
        assert!(check_keys(&[7; 32], &[7; 32]).is_err());
        assert!(check_keys(&[7; 32], &[8; 32]).is_ok());
    }

    #[test]
    fn aad_strings_match_latchkey_0_2() -> Result<(), uuid::Error> {
        let user: UserId = "6f9619ff-8b86-4d01-b42d-00c04fc964ff".parse()?;
        let passkey: PasskeyId = "00000000-0000-4000-8000-000000000001".parse()?;
        assert_eq!(
            Aad::totp(user).as_bytes(),
            b"latchkey-totp:6f9619ff-8b86-4d01-b42d-00c04fc964ff"
        );
        assert_eq!(
            Aad::passkey(user, passkey).as_bytes(),
            b"latchkey-passkey:6f9619ff-8b86-4d01-b42d-00c04fc964ff:00000000-0000-4000-8000-000000000001"
        );
        Ok(())
    }
}
