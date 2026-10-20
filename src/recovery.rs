//! Single-use recovery codes such as `abcd-efgh-jkmn`.
//!
//! [`generate`] returns the codes to show once and their hashes to store. [`verify`] says which
//! stored hash a presented code matches; the app then marks that one used (atomically, so it
//! cannot be used twice). Formatting (case, spaces, dashes) does not matter.
//!
//! ```
//! use latchkey::recovery;
//!
//! # fn main() -> Result<(), latchkey::Error> {
//! let mut rng = latchkey::os_rng()?;
//! let issued = recovery::generate(&mut rng);
//! assert_eq!(issued.codes.len(), recovery::COUNT);
//!
//! let typed = issued.codes[3].expose_secret().to_uppercase().replace('-', " ");
//! let matched = recovery::verify(&typed, &issued.hashes);
//! assert_eq!(matched, Some(issued.hashes[3]));
//! # Ok(())
//! # }
//! ```

use crate::error::InvalidRequestReason;
use rand_core::CryptoRng;
use zeroize::Zeroize;

use crate::token::{ct_eq, sha256};

/// Codes per [`generate`].
pub const COUNT: usize = 10;
const ALPHABET: &[u8; 32] = b"abcdefghjkmnpqrstuvwxyz023456789";
const GROUPS: usize = 3;
const GROUP_LEN: usize = 4;
const HASH_PREFIX: &[u8] = b"latchkey-recovery:";

/// The stored form of a recovery code: SHA-256 of a fixed prefix and the normalised code,
/// the same bytes latchkey 0.2 stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct RecoveryCodeHash([u8; 32]);

impl RecoveryCodeHash {
    /// The hash of a presented code, or `None` when it cannot be a recovery code.
    #[must_use]
    pub fn of(code: &str) -> Option<Self> {
        let mut normalized = normalize(code)?;
        let mut input = HASH_PREFIX.to_vec();
        input.extend_from_slice(normalized.as_bytes());
        normalized.zeroize();
        let hash = sha256(&input);
        input.zeroize();
        Some(Self(hash))
    }

    /// Rebuilds a hash read back from storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes to store.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for RecoveryCodeHash {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| crate::Error::InvalidRequest(InvalidRequestReason::RecoveryHashLength))
    }
}

impl std::fmt::Debug for RecoveryCodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecoveryCodeHash({})",
            crate::hex(self.0.get(..4).unwrap_or_default())
        )
    }
}

/// A recovery code in plain text, to show to the user once. Redacted `Debug`, zeroed on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// The code, formatted `xxxx-xxxx-xxxx`.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(<redacted>)")
    }
}

/// A fresh set of codes: show `codes` once, store `hashes` (replacing any earlier set).
#[derive(Debug, Clone)]
#[must_use = "recovery codes must be stored and shown"]
pub struct RecoveryCodes {
    /// For the user, once.
    pub codes: Vec<RecoveryCode>,
    /// For storage, in the same order.
    pub hashes: Vec<RecoveryCodeHash>,
}

/// Generates [`COUNT`] codes of 60 random bits each.
pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> RecoveryCodes {
    let codes: Vec<RecoveryCode> = (0..COUNT).map(|_| one(rng)).collect();
    let hashes = codes
        .iter()
        .filter_map(|code| RecoveryCodeHash::of(code.expose_secret()))
        .collect();
    RecoveryCodes { codes, hashes }
}

fn one<R: CryptoRng + ?Sized>(rng: &mut R) -> RecoveryCode {
    let mut bytes = [0u8; GROUPS * GROUP_LEN];
    rng.fill_bytes(&mut bytes);
    let mut code = String::with_capacity(GROUPS * (GROUP_LEN + 1));
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 && i % GROUP_LEN == 0 {
            code.push('-');
        }
        let index = usize::from(byte & 31);
        code.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'a')));
    }
    bytes.zeroize();
    RecoveryCode(code)
}

fn normalize(code: &str) -> Option<String> {
    let cleaned: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let valid =
        cleaned.len() == GROUPS * GROUP_LEN && cleaned.bytes().all(|b| ALPHABET.contains(&b));
    valid.then_some(cleaned)
}

/// The stored hash that `code` matches, if any. Every hash is compared, in constant time, so
/// the time taken does not depend on which one matched.
#[must_use]
pub fn verify<'a, I>(code: &str, unused: I) -> Option<RecoveryCodeHash>
where
    I: IntoIterator<Item = &'a RecoveryCodeHash>,
{
    let presented = RecoveryCodeHash::of(code)?;
    let mut found = None;
    for stored in unused {
        if ct_eq(&presented.0, &stored.0) {
            found = Some(*stored);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_ten_distinct_codes_that_hash() {
        let issued = generate(&mut crate::test_rng());
        assert_eq!(issued.codes.len(), 10);
        assert_eq!(issued.hashes.len(), 10);
        let mut unique: Vec<_> = issued
            .codes
            .iter()
            .map(RecoveryCode::expose_secret)
            .collect();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 10);
        for code in &issued.codes {
            assert_eq!(code.expose_secret().len(), 14);
        }
    }

    #[test]
    fn formatting_does_not_change_the_hash() {
        let issued = generate(&mut crate::test_rng());
        let code = issued.codes[0].expose_secret();
        let shouted = code.to_uppercase().replace('-', " ");
        assert_eq!(RecoveryCodeHash::of(code), RecoveryCodeHash::of(&shouted));
    }

    #[test]
    fn verify_names_the_matching_hash_only() {
        let issued = generate(&mut crate::test_rng());
        for (code, hash) in issued.codes.iter().zip(&issued.hashes) {
            assert_eq!(verify(code.expose_secret(), &issued.hashes), Some(*hash));
        }
        let other = generate(&mut crate::test_rng());
        assert_eq!(verify(other.codes[0].expose_secret(), &issued.hashes), None);
    }

    #[test]
    fn a_used_code_no_longer_verifies() {
        let issued = generate(&mut crate::test_rng());
        let code = issued.codes[2].expose_secret();
        let used = verify(code, &issued.hashes);
        let unused: Vec<_> = issued
            .hashes
            .iter()
            .filter(|hash| Some(**hash) != used)
            .collect();
        assert_eq!(verify(code, unused), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(RecoveryCodeHash::of("123456").is_none());
        assert!(RecoveryCodeHash::of("iiii-iiii-iiii").is_none());
        assert_eq!(verify("", &[RecoveryCodeHash([0; 32])]), None);
    }

    #[test]
    fn hashes_match_latchkey_0_2() {
        // sha256("latchkey-recovery:abcdefghjkmn")
        let expected = sha256(b"latchkey-recovery:abcdefghjkmn");
        assert_eq!(
            RecoveryCodeHash::of("ABCD-efgh-jkmn"),
            Some(RecoveryCodeHash(expected))
        );
    }
}
