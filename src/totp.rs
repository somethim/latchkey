//! TOTP (RFC 6238): SHA-1, 6 digits, 30-second steps, one step of skew either way.
//!
//! A code is accepted once: [`verify`] returns the matched [`TotpStep`], which the app must
//! store as the account's last used step and pass back next time. Store it with a
//! compare-and-set (`UPDATE ... WHERE last_step IS NULL OR last_step < ?`) so two requests
//! racing with the same code cannot both succeed.
//!
//! ```
//! use latchkey::totp::{self, TotpRefusal};
//! use time::OffsetDateTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = latchkey::os_rng()?;
//! let secret = totp::TotpSecret::random(&mut rng);
//! let enrolment = totp::enrolment(&secret, "Home", "owner@example.com")?;
//! assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Home"));
//!
//! let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
//! let code = secret.code_at(now)?;
//! let step = totp::verify(&secret, &code, None, now)?;
//! // The same code again is a replay.
//! assert_eq!(totp::verify(&secret, &code, Some(step), now), Err(TotpRefusal::Replayed));
//! # Ok(())
//! # }
//! ```

use crate::error::InvalidRequestReason;
use rand_core::CryptoRng;
use time::OffsetDateTime;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroize;

use crate::Error;

/// Digits in a code.
pub const DIGITS: u8 = 6;
/// Seconds per step.
pub const STEP_SECS: u64 = 30;
/// Steps accepted on either side of the current one.
pub const SKEW: u16 = 1;
/// Bytes in a secret from [`TotpSecret::random`].
pub const SECRET_BYTES: usize = 20;
/// The shortest secret latchkey verifies codes against, in bytes (128 bits, RFC 4226).
pub const MIN_SECRET_BYTES: usize = 16;

/// A TOTP shared secret. Redacted `Debug`, zeroed on drop. Seal it with
/// [`DataKey`](crate::seal::DataKey) before storing it.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    /// A new random secret of [`SECRET_BYTES`] bytes.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = vec![0u8; SECRET_BYTES];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps secret bytes read back from storage (after opening them).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Decodes a base32 secret (RFC 4648, as authenticator apps and `otpauth://` URLs carry
    /// it), for importing secrets another system enrolled. Case, spaces, dashes and `=`
    /// padding are ignored.
    ///
    /// Older systems often enrolled 80-bit secrets (16 base32 characters). latchkey does not
    /// verify codes against secrets under [`MIN_SECRET_BYTES`], so those accounts must enrol
    /// TOTP again.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `totp_secret_base32` for a character outside the
    /// base32 alphabet, or `totp_secret_too_short` for fewer than [`MIN_SECRET_BYTES`] bytes.
    ///
    /// ```
    /// use latchkey::totp::TotpSecret;
    ///
    /// let secret = TotpSecret::from_base32("jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp")?;
    /// assert_eq!(secret.expose_secret().len(), 20);
    /// assert_eq!(secret.to_base32(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
    /// assert!(TotpSecret::from_base32("JBSWY3DPEHPK3PXP").is_err()); // 80 bits
    /// # Ok::<(), latchkey::Error>(())
    /// ```
    pub fn from_base32(encoded: &str) -> Result<Self, Error> {
        let mut bytes = Vec::with_capacity(encoded.len() * 5 / 8);
        let mut buffer: u32 = 0;
        let mut bits: u32 = 0;
        let symbols = encoded
            .trim_end_matches(|c: char| c == '=' || c.is_whitespace())
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-');
        for symbol in symbols {
            let Some(value) = base32_value(symbol) else {
                bytes.zeroize();
                return Err(Error::InvalidRequest(
                    InvalidRequestReason::TotpSecretBase32,
                ));
            };
            buffer = (buffer << 5) | u32::from(value);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                bytes.push(u8::try_from((buffer >> bits) & 0xff).unwrap_or_default());
                buffer &= (1 << bits) - 1;
            }
        }
        buffer.zeroize();
        if bytes.len() < MIN_SECRET_BYTES {
            bytes.zeroize();
            return Err(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretTooShort,
            ));
        }
        Ok(Self(bytes))
    }

    /// The raw secret, to seal for storage.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// The secret in base32, for typing into an authenticator app.
    #[must_use]
    pub fn to_base32(&self) -> String {
        Secret::from(self.0.clone()).to_base32()
    }

    /// The code an authenticator shows at `at`; for tests and for showing a sample code.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] when the secret is shorter than 128 bits or `at` is before
    /// 1970.
    pub fn code_at(&self, at: OffsetDateTime) -> Result<String, Error> {
        let at = u64::try_from(at.unix_timestamp())
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TimeBeforeEpoch))?;
        Ok(build(self, "latchkey", "")?.generate(at).to_string())
    }
}

impl Drop for TotpSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSecret(<redacted>)")
    }
}

/// A time step that matched. Store it as the account's last used step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TotpStep(u64);

impl TotpStep {
    /// Rebuilds a step read back from storage.
    #[must_use]
    pub const fn new(step: u64) -> Self {
        Self(step)
    }

    /// The step number (Unix time / 30).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<i64> for TotpStep {
    type Error = Error;

    /// For the signed `last_step` column latchkey 0.2 stored.
    fn try_from(step: i64) -> Result<Self, Error> {
        u64::try_from(step)
            .map(Self)
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::NegativeTotpStep))
    }
}

impl TryFrom<TotpStep> for i64 {
    type Error = Error;

    fn try_from(step: TotpStep) -> Result<Self, Error> {
        i64::try_from(step.0)
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TotpStepOverflow))
    }
}

/// Why a code was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TotpRefusal {
    /// Not six digits.
    #[error("not a six-digit code")]
    Malformed,
    /// Six digits, but not the code for any step in the window.
    #[error("code does not match")]
    Mismatch,
    /// The code matched a step at or before the last one used.
    #[error("code already used")]
    Replayed,
}

impl From<TotpRefusal> for Error {
    fn from(_: TotpRefusal) -> Self {
        Error::SignInFailed
    }
}

/// What to show when enrolling a secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// The secret in base32, for manual entry.
    pub secret_base32: String,
    /// The `otpauth://totp/...` URL, for a QR code.
    pub otpauth_url: String,
}

impl std::fmt::Debug for Enrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrolment").finish_non_exhaustive()
    }
}

impl Drop for Enrolment {
    fn drop(&mut self) {
        self.secret_base32.zeroize();
        self.otpauth_url.zeroize();
    }
}

fn base32_value(symbol: char) -> Option<u8> {
    match symbol.to_ascii_uppercase() {
        c @ 'A'..='Z' => u8::try_from(c).ok().map(|c| c - b'A'),
        c @ '2'..='7' => u8::try_from(c).ok().map(|c| c - b'2' + 26),
        _ => None,
    }
}

fn build(secret: &TotpSecret, issuer: &str, account: &str) -> Result<Totp, Error> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(SKEW)
        .with_step_duration(STEP_SECS)
        .with_secret(secret.0.clone())
        .with_issuer(Some(issuer.replace(':', "")))
        .with_account_name(account.replace(':', ""))
        .build()
        .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TotpSecret))
}

/// The base32 secret and `otpauth://` URL for an authenticator app. Colons are removed from
/// `issuer` and `account`, which the URL format reserves.
///
/// # Errors
///
/// [`Error::InvalidRequest`] when the secret is shorter than 128 bits.
pub fn enrolment(secret: &TotpSecret, issuer: &str, account: &str) -> Result<Enrolment, Error> {
    let totp = build(secret, issuer, account)?;
    Ok(Enrolment {
        secret_base32: secret.to_base32(),
        otpauth_url: totp
            .to_url()
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TotpUrl))?,
    })
}

/// Whether `code` has the shape of a TOTP code: six digits, whitespace ignored. Recovery
/// codes never do, which is how a single "code" field tells them apart.
#[must_use]
pub fn looks_like_code(code: &str) -> bool {
    let mut digits = 0usize;
    for c in code.chars().filter(|c| !c.is_whitespace()) {
        if !c.is_ascii_digit() {
            return false;
        }
        digits += 1;
    }
    digits == usize::from(DIGITS)
}

/// Checks `code` against `secret` at `now`, refusing steps at or before `last_used_step`.
///
/// # Errors
///
/// A [`TotpRefusal`] saying why the code was not accepted.
pub fn verify(
    secret: &TotpSecret,
    code: &str,
    last_used_step: Option<TotpStep>,
    now: OffsetDateTime,
) -> Result<TotpStep, TotpRefusal> {
    if !looks_like_code(code) {
        return Err(TotpRefusal::Malformed);
    }
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let now = u64::try_from(now.unix_timestamp()).map_err(|_| TotpRefusal::Mismatch)?;
    let totp = build(secret, "latchkey", "").map_err(|_| TotpRefusal::Mismatch)?;
    let step = totp
        .check(&code, now)
        .map(TotpStep)
        .ok_or(TotpRefusal::Mismatch)?;
    match last_used_step {
        Some(last) if step <= last => Err(TotpRefusal::Replayed),
        _ => Ok(step),
    }
}

/// The `otpauth://` URL as an SVG QR code.
///
/// # Errors
///
/// [`Error::InvalidRequest`] when the URL is too long for a QR code.
#[cfg(feature = "qr")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
pub fn qr_svg(otpauth_url: &str) -> Result<String, Error> {
    use std::fmt::Write as _;
    let qr = qrcodegen::QrCode::encode_text(otpauth_url, qrcodegen::QrCodeEcc::Medium)
        .map_err(|_| Error::InvalidRequest(InvalidRequestReason::QrTooLong))?;
    let border = 4;
    let size = qr.size() + border * 2;
    let mut path = String::new();
    for y in 0..qr.size() {
        for x in 0..qr.size() {
            if qr.get_module(x, y) {
                let _ = write!(path, "M{},{}h1v1h-1z", x + border, y + border);
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#000\"/></svg>"
    ))
}

/// The `otpauth://` URL as a PNG QR code.
///
/// # Errors
///
/// [`Error::InvalidRequest`] when the URL is too long for a QR code or encoding fails.
#[cfg(feature = "qr-png")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr-png")))]
pub fn qr_png(otpauth_url: &str) -> Result<Vec<u8>, Error> {
    qrcodegen_image::draw_png(otpauth_url)
        .map_err(|_| Error::InvalidRequest(InvalidRequestReason::QrPng))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn accepts_current_and_adjacent_steps_only() -> Result<(), Error> {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        let step = TotpStep(1_800_000_000 / 30);
        assert_eq!(verify(&secret, &secret.code_at(now)?, None, now), Ok(step));
        let previous = now - Duration::seconds(30);
        assert_eq!(
            verify(&secret, &secret.code_at(previous)?, None, now),
            Ok(TotpStep(step.get() - 1))
        );
        let old = now - Duration::seconds(120);
        assert_eq!(
            verify(&secret, &secret.code_at(old)?, None, now),
            Err(TotpRefusal::Mismatch)
        );
        Ok(())
    }

    #[test]
    fn a_step_is_accepted_once_and_never_an_older_one() -> Result<(), Error> {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        let code = secret.code_at(now)?;
        let step = verify(&secret, &code, None, now)?;
        assert_eq!(
            verify(&secret, &code, Some(step), now),
            Err(TotpRefusal::Replayed)
        );
        let previous = secret.code_at(now - Duration::seconds(30))?;
        assert_eq!(
            verify(&secret, &previous, Some(step), now),
            Err(TotpRefusal::Replayed)
        );
        let next_time = now + Duration::seconds(30);
        let next = secret.code_at(next_time)?;
        assert_eq!(
            verify(&secret, &next, Some(step), next_time),
            Ok(TotpStep(step.get() + 1))
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_codes() {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        assert_eq!(
            verify(&secret, "12345", None, now),
            Err(TotpRefusal::Malformed)
        );
        assert_eq!(
            verify(&secret, "abcdef", None, now),
            Err(TotpRefusal::Malformed)
        );
        assert!(looks_like_code(" 123 456 "));
        assert!(!looks_like_code("abcd-efgh-jkmn"));
    }

    #[test]
    fn short_secrets_are_refused() {
        let secret = TotpSecret::from_bytes(vec![1; 8]);
        assert!(enrolment(&secret, "Home", "o@example.com").is_err());
        assert_eq!(
            verify(&secret, "123456", None, at(1_800_000_000)),
            Err(TotpRefusal::Mismatch)
        );
    }

    #[test]
    fn base32_secrets_import_and_round_trip() -> Result<(), Error> {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let encoded = secret.to_base32();
        assert_eq!(TotpSecret::from_base32(&encoded)?, secret);
        assert_eq!(TotpSecret::from_base32(&encoded.to_lowercase())?, secret);
        let spaced: String = encoded
            .chars()
            .enumerate()
            .flat_map(|(i, c)| (i > 0 && i % 4 == 0).then_some(' ').into_iter().chain([c]))
            .collect();
        assert_eq!(TotpSecret::from_base32(&spaced)?, secret);
        // RFC 4648 test vector, padded.
        let padded = TotpSecret::from_base32("MZXW6YTBOI======MZXW6YTBOI======");
        assert_eq!(
            padded.err(),
            Some(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretBase32
            )),
            "padding only at the end"
        );
        let foobar = TotpSecret::from_base32("MZXW6YTBOJWW6YTBOJWW6YTBOI======")?;
        assert_eq!(foobar.expose_secret(), b"foobarmobarmobar");
        // A code from an imported secret verifies like any other.
        let now = at(1_800_000_000);
        let imported = TotpSecret::from_base32(&encoded)?;
        assert!(verify(&imported, &secret.code_at(now)?, None, now).is_ok());
        Ok(())
    }

    #[test]
    fn base32_secrets_must_be_valid_and_long_enough() {
        assert_eq!(
            TotpSecret::from_base32("JBSWY3DPEHPK3PXP").err(),
            Some(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretTooShort
            ))
        );
        assert_eq!(
            TotpSecret::from_base32("JBSWY3DPEHPK3PXP1BSWY3DPEHPK3PXP").err(),
            Some(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretBase32
            ))
        );
        assert_eq!(
            TotpSecret::from_base32("").err(),
            Some(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretTooShort
            ))
        );
        assert!(TotpSecret::from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX\u{e9}").is_err());
    }

    #[test]
    fn enrolment_url_names_issuer_and_account() -> Result<(), Error> {
        let enrolment = enrolment(
            &TotpSecret::random(&mut crate::test_rng()),
            "Home",
            "owner@example.com",
        )?;
        assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Home"));
        assert!(enrolment.otpauth_url.contains("owner%40example.com"));
        assert_eq!(enrolment.secret_base32.len(), 32);
        assert!(!format!("{enrolment:?}").contains(&enrolment.secret_base32));
        Ok(())
    }

    #[test]
    fn steps_convert_from_the_old_signed_column() {
        assert_eq!(TotpStep::try_from(5i64), Ok(TotpStep(5)));
        assert!(TotpStep::try_from(-1i64).is_err());
    }

    #[cfg(feature = "qr")]
    #[test]
    fn qr_svg_is_an_svg() -> Result<(), Error> {
        let svg = qr_svg("otpauth://totp/Home:o?secret=ABC&issuer=Home")?;
        assert!(svg.starts_with("<svg"));
        assert!(svg.ends_with("</svg>"));
        Ok(())
    }

    #[cfg(feature = "qr-png")]
    #[test]
    fn qr_png_is_a_png() -> Result<(), Error> {
        let png = qr_png("otpauth://totp/Home:o?secret=ABC&issuer=Home")?;
        assert!(png.starts_with(b"\x89PNG"));
        Ok(())
    }
}
