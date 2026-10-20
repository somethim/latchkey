//! Random bearer tokens: session cookies, one-time links, device cookies and CSRF tokens.
//!
//! A token is 32 random bytes, base64url without padding (43 characters). The client gets the
//! [`SecretToken`]; the app stores only its [`TokenHash`] (SHA-256), so a copy of the
//! database does not hold usable tokens. Look a presented token up with [`TokenHash::of`].
//! Tokens another system issued (a session cookie or link from before the app moved to
//! latchkey, an API key) have other shapes: hash them with [`TokenHash::of_foreign`].
//!
//! ```
//! use latchkey::token::{self, TokenHash};
//!
//! # fn main() -> Result<(), latchkey::Error> {
//! let mut rng = latchkey::os_rng()?;
//! let issued = token::issue(&mut rng);
//! let stored: TokenHash = issued.hash;
//! // Later, from the cookie the client sent back:
//! let presented = issued.token.expose_secret();
//! assert_eq!(TokenHash::of(presented), Some(stored));
//! assert!(stored.verify(presented));
//! # Ok(())
//! # }
//! ```

use crate::error::InvalidRequestReason;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Random bytes in a token.
pub const TOKEN_BYTES: usize = 32;
/// The shortest token [`TokenHash::of_foreign`] accepts, in bytes: 128 bits in base64.
pub const FOREIGN_MIN_LEN: usize = 22;
/// The longest token [`TokenHash::of_foreign`] accepts, in bytes.
pub const FOREIGN_MAX_LEN: usize = 512;

/// The SHA-256 of a token: what the app stores and looks tokens up by.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// The hash of a presented token, or `None` when it is not a well-formed token. Leading
    /// and trailing whitespace is ignored.
    #[must_use]
    pub fn of(token: &str) -> Option<Self> {
        let token = token.trim();
        let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
        (decoded.len() == TOKEN_BYTES).then(|| Self(sha256(token.as_bytes())))
    }

    /// The hash of a presented token that latchkey did not issue, or `None` when it is not
    /// [`FOREIGN_MIN_LEN`] to [`FOREIGN_MAX_LEN`] bytes of printable ASCII (no spaces).
    /// Leading and trailing whitespace is ignored.
    ///
    /// The hash is the SHA-256 of the token's text, exactly as [`of`](Self::of) computes it
    /// for latchkey's own tokens, so both kinds can share one table and one look-up. This is
    /// only safe for tokens with at least 128 random bits, which latchkey cannot check: an
    /// unsalted hash of a guessable token can be reversed from a copy of the database.
    ///
    /// Porting tokens from another system:
    ///
    /// - It stored the SHA-256 of the token text: keep the rows,
    ///   [`TokenHash::from_bytes`] (or `try_from(&[u8])`, after decoding hex if it stored
    ///   hex) reads them, and `of_foreign(presented)` finds them.
    /// - It stored the tokens themselves: replace each with `of_foreign(token)` once.
    /// - It stored anything else (an HMAC, a salted or slow hash): this cannot match it.
    ///   Keep the old look-up for old tokens until they expire, or sign everyone in again.
    ///
    /// Either way, replace a foreign session token with one of latchkey's on its first use
    /// (for example with [`issue_session`](crate::flow::issue_session)) so the old shapes
    /// disappear as sessions turn over.
    ///
    /// ```
    /// use latchkey::token::TokenHash;
    ///
    /// let legacy = "3f2a9c0d8e7b6a5f4e3d2c1b0a9f8e7d";
    /// assert_eq!(TokenHash::of(legacy), None, "not latchkey's shape");
    /// let hash = TokenHash::of_foreign(legacy);
    /// assert!(hash.is_some());
    /// assert_eq!(hash, TokenHash::of_foreign(" 3f2a9c0d8e7b6a5f4e3d2c1b0a9f8e7d\n"));
    /// assert_eq!(TokenHash::of_foreign("too-short"), None);
    /// ```
    #[must_use]
    pub fn of_foreign(token: &str) -> Option<Self> {
        let token = token.trim();
        let shaped = (FOREIGN_MIN_LEN..=FOREIGN_MAX_LEN).contains(&token.len())
            && token.bytes().all(|b| b.is_ascii_graphic());
        shaped.then(|| Self(sha256(token.as_bytes())))
    }

    /// Rebuilds a hash read back from storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes to store.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `token` hashes to this value, compared in constant time.
    #[must_use]
    pub fn verify(&self, token: &str) -> bool {
        Self::of(token).is_some_and(|presented| ct_eq(&presented.0, &self.0))
    }
}

impl TryFrom<&[u8]> for TokenHash {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| crate::Error::InvalidRequest(InvalidRequestReason::TokenHashLength))
    }
}

impl AsRef<[u8]> for TokenHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for TokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TokenHash({})",
            crate::hex(self.0.get(..4).unwrap_or_default())
        )
    }
}

/// A token to hand to the client once. Its `Debug` output is redacted, it has no `Display`,
/// and it is zeroed when dropped.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SecretToken(String);

impl SecretToken {
    /// The token text, for a cookie value, a link or a response body.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Wraps a token the client presented, such as a CSRF header.
    #[must_use]
    pub fn from_presented(token: &str) -> Self {
        Self(token.trim().to_owned())
    }

    /// Its hash, as [`TokenHash::of`] computes it.
    #[must_use]
    pub fn hash(&self) -> Option<TokenHash> {
        TokenHash::of(&self.0)
    }

    /// Compares with another token in constant time.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        ct_eq(self.0.as_bytes(), presented.trim().as_bytes())
    }
}

impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretToken(<redacted>)")
    }
}

/// A freshly issued token and the hash to store for it.
#[derive(Debug, Clone)]
#[must_use = "a token is useless unless its hash is stored and the token handed out"]
pub struct IssuedToken {
    /// For the client.
    pub token: SecretToken,
    /// For storage.
    pub hash: TokenHash,
}

/// Issues a new random token.
pub fn issue<R: CryptoRng + ?Sized>(rng: &mut R) -> IssuedToken {
    let mut bytes = [0u8; TOKEN_BYTES];
    rng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    let hash = TokenHash(sha256(token.as_bytes()));
    IssuedToken {
        token: SecretToken(token),
        hash,
    }
}

/// Compares two byte strings in constant time (for equal lengths).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_round_trips_to_its_hash() {
        let issued = issue(&mut crate::test_rng());
        assert_eq!(issued.token.expose_secret().len(), 43);
        assert_eq!(issued.token.hash(), Some(issued.hash));
        assert!(issued.hash.verify(issued.token.expose_secret()));
    }

    #[test]
    fn malformed_tokens_have_no_hash() {
        assert!(TokenHash::of("short").is_none());
        assert!(TokenHash::of("!!!!").is_none());
        assert!(!TokenHash::from_bytes([0; 32]).verify("short"));
    }

    #[test]
    fn another_token_does_not_verify() {
        let mut rng = crate::test_rng();
        let a = issue(&mut rng);
        let b = issue(&mut rng);
        assert!(!a.hash.verify(b.token.expose_secret()));
        assert!(!a.token.matches(b.token.expose_secret()));
    }

    #[test]
    fn secrets_are_redacted() {
        let issued = issue(&mut crate::test_rng());
        let debug = format!("{issued:?}");
        assert!(!debug.contains(issued.token.expose_secret()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn foreign_tokens_hash_like_latchkeys_own() {
        let issued = issue(&mut crate::test_rng());
        assert_eq!(
            TokenHash::of_foreign(issued.token.expose_secret()),
            Some(issued.hash),
            "one table can hold both kinds"
        );
        let legacy = "0123456789abcdef0123456789abcdef";
        assert_eq!(TokenHash::of(legacy), None);
        assert_eq!(
            TokenHash::of_foreign(legacy).map(|hash| *hash.as_bytes()),
            Some(sha256(legacy.as_bytes()))
        );
        assert_eq!(
            TokenHash::of_foreign(&"a".repeat(FOREIGN_MIN_LEN - 1)),
            None
        );
        assert!(TokenHash::of_foreign(&"a".repeat(FOREIGN_MIN_LEN)).is_some());
        assert!(TokenHash::of_foreign(&"a".repeat(FOREIGN_MAX_LEN)).is_some());
        assert_eq!(
            TokenHash::of_foreign(&"a".repeat(FOREIGN_MAX_LEN + 1)),
            None
        );
        assert_eq!(TokenHash::of_foreign("0123456789 abcdef0123456789"), None);
        assert_eq!(TokenHash::of_foreign("0123456789abcdef0123456\u{e9}"), None);
    }

    #[test]
    fn hashes_convert_from_stored_bytes() {
        let issued = issue(&mut crate::test_rng());
        let bytes: &[u8] = issued.hash.as_ref();
        assert_eq!(TokenHash::try_from(bytes), Ok(issued.hash));
        assert!(TokenHash::try_from(&bytes[..31]).is_err());
    }
}
