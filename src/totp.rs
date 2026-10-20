use time::OffsetDateTime;
use totp_rs::{Algorithm, Builder, Secret, Totp};

use crate::crypto::random_bytes;
use crate::error::Error;

const DIGITS: u8 = 6;
const STEP_SECS: u64 = 30;
const SKEW: u16 = 1;

pub(crate) fn new_secret() -> Vec<u8> {
    random_bytes::<20>().to_vec()
}

fn build(secret: &[u8], issuer: &str, account: &str) -> Result<Totp, Error> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(SKEW)
        .with_step_duration(STEP_SECS)
        .with_secret(secret.to_vec())
        .with_issuer(Some(issuer.replace(':', "")))
        .with_account_name(account.replace(':', ""))
        .build()
        .map_err(Error::internal)
}

pub(crate) struct Enrolment {
    pub(crate) secret_base32: String,
    pub(crate) otpauth_url: String,
}

pub(crate) fn enrolment(secret: &[u8], issuer: &str, account: &str) -> Result<Enrolment, Error> {
    let totp = build(secret, issuer, account)?;
    Ok(Enrolment {
        secret_base32: Secret::from(secret.to_vec()).to_base32(),
        otpauth_url: totp.to_url().map_err(Error::internal)?,
    })
}

/// The matched time step, which the caller must record so it is never accepted again.
pub(crate) fn matched_step(secret: &[u8], code: &str, now: OffsetDateTime) -> Option<i64> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != usize::from(DIGITS) || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let now = u64::try_from(now.unix_timestamp()).ok()?;
    let totp = build(secret, "latchkey", "").ok()?;
    totp.check(&code, now)
        .and_then(|step| i64::try_from(step).ok())
}

pub(crate) fn looks_like_totp(code: &str) -> bool {
    let digits: Vec<char> = code.chars().filter(|c| !c.is_whitespace()).collect();
    digits.len() == usize::from(DIGITS) && digits.iter().all(char::is_ascii_digit)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn code_at(secret: &[u8], at: OffsetDateTime) -> String {
        let totp = build(secret, "t", "").unwrap();
        totp.generate(u64::try_from(at.unix_timestamp()).unwrap())
            .to_string()
    }

    #[test]
    fn accepts_current_and_adjacent_steps_only() {
        let secret = new_secret();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let step = 1_800_000_000 / 30;
        assert_eq!(
            matched_step(&secret, &code_at(&secret, now), now),
            Some(step)
        );
        let previous = now - time::Duration::seconds(30);
        assert_eq!(
            matched_step(&secret, &code_at(&secret, previous), now),
            Some(step - 1)
        );
        let old = now - time::Duration::seconds(120);
        assert_eq!(matched_step(&secret, &code_at(&secret, old), now), None);
    }

    #[test]
    fn rejects_malformed_codes() {
        let secret = new_secret();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        assert_eq!(matched_step(&secret, "12345", now), None);
        assert_eq!(matched_step(&secret, "abcdef", now), None);
    }

    #[test]
    fn enrolment_url_names_issuer_and_account() {
        let enrolment = enrolment(&new_secret(), "Home", "owner@example.com").unwrap();
        assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Home"));
        assert!(enrolment.otpauth_url.contains("owner%40example.com"));
        assert_eq!(enrolment.secret_base32.len(), 32);
    }
}
