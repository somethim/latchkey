use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(crate) const TOKEN_BYTES: usize = 32;

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// A secret handed to a client once; only its SHA-256 is stored.
pub(crate) struct IssuedToken {
    pub(crate) token: String,
    pub(crate) hash: Vec<u8>,
}

pub(crate) fn issue_token() -> IssuedToken {
    let token = URL_SAFE_NO_PAD.encode(random_bytes::<TOKEN_BYTES>());
    let hash = sha256(token.as_bytes());
    IssuedToken { token, hash }
}

pub(crate) fn token_hash(token: &str) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(token.trim()).ok()?;
    (decoded.len() == TOKEN_BYTES).then(|| sha256(token.trim().as_bytes()))
}

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub(crate) fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return String::new();
    };
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn issued_token_round_trips_to_its_hash() {
        let issued = issue_token();
        assert_eq!(token_hash(&issued.token).unwrap(), issued.hash);
    }

    #[test]
    fn malformed_tokens_have_no_hash() {
        assert!(token_hash("short").is_none());
        assert!(token_hash("!!!!").is_none());
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
