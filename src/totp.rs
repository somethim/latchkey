//! TOTP (RFC 6238) with SHA-1. Digits, step and skew are the app's settings, carried in a
//! [`TotpParams`] ([`Config::totp_params`](crate::Config::totp_params); by default 6 digits,
//! 30-second steps and one step of skew either way).
//!
//! **Digits and step are part of every enrolment**: the authenticator app stores them with
//! the secret. latchkey stores nothing per enrolment, so enrolments made under one setting
//! keep working only while the setting stays the same; change digits or step and every
//! account must enrol again (and, for the step, have its last used step cleared). The
//! `otpauth://` URL and its QR code carry `digits` and `period` whenever they are not the
//! defaults, so authenticators pick up new enrolments' values. The skew can change freely.
//!
//! A code is accepted once: [`verify`] returns the matched [`TotpStep`], which the app must
//! store as the account's last used step and pass back next time. Store it with a
//! compare-and-set (`UPDATE ... WHERE last_step IS NULL OR last_step < ?`) so two requests
//! racing with the same code cannot both succeed.
//!
//! ```
//! use latchkey::totp::{self, TotpRefusal};
//! use latchkey::Config;
//! use time::OffsetDateTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
//! let params = config.totp_params();
//! let mut rng = latchkey::os_rng()?;
//! let secret = totp::TotpSecret::random(&mut rng);
//! let enrolment = totp::enrolment(&secret, "Home", "owner@example.com", params)?;
//! assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Home"));
//!
//! let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
//! let code = secret.code_at(now, params)?;
//! let step = totp::verify(&secret, &code, None, now, params)?;
//! // The same code again is a replay.
//! assert_eq!(
//!     totp::verify(&secret, &code, Some(step), now, params),
//!     Err(TotpRefusal::Replayed)
//! );
//! # Ok(())
//! # }
//! ```

use crate::error::InvalidRequestReason;
use rand_core::CryptoRng;
use time::OffsetDateTime;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroize;

use crate::Error;
use crate::error::ConfigReason;

/// The default digits in a code ([`ConfigBuilder::totp_digits`](crate::ConfigBuilder::totp_digits)).
pub const DEFAULT_DIGITS: u8 = 6;
/// The default seconds per step ([`ConfigBuilder::totp_step`](crate::ConfigBuilder::totp_step)).
pub const DEFAULT_STEP_SECS: u64 = 30;
/// The default steps accepted on either side of the current one
/// ([`ConfigBuilder::totp_skew`](crate::ConfigBuilder::totp_skew)).
pub const DEFAULT_SKEW: u8 = 1;
/// Bytes in a secret from [`TotpSecret::random`]. Fixed: 160 bits, the length RFC 4226
/// recommends and the one authenticator apps expect.
pub const SECRET_BYTES: usize = 20;
/// The shortest secret latchkey verifies codes against, in bytes. Fixed: 128 bits is RFC
/// 4226's floor, a security minimum rather than a preference.
pub const MIN_SECRET_BYTES: usize = 16;

/// The digits, step and skew codes are made and checked with, validated on construction.
/// Take it from [`Config::totp_params`](crate::Config::totp_params) so every call uses the
/// app's settings; [`Default`] is 6 digits, 30-second steps and a skew of 1.
///
/// See the [module docs](self) for why digits and step must not change under existing
/// enrolments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TotpParams {
    digits: u8,
    step_secs: u64,
    skew: u8,
}

impl TotpParams {
    /// `digits` (6 or 8), `step_secs` (15 to 120) and `skew` (0 to 3).
    ///
    /// # Errors
    ///
    /// [`Error::Config`] with [`ConfigReason::TotpDigits`], [`TotpStep`](ConfigReason::TotpStep)
    /// or [`TotpSkew`](ConfigReason::TotpSkew) for a value outside its bounds.
    pub fn new(digits: u8, step_secs: u64, skew: u8) -> Result<Self, Error> {
        if !matches!(digits, 6 | 8) {
            return Err(Error::Config(ConfigReason::TotpDigits));
        }
        if !(15..=120).contains(&step_secs) {
            return Err(Error::Config(ConfigReason::TotpStep));
        }
        if skew > 3 {
            return Err(Error::Config(ConfigReason::TotpSkew));
        }
        Ok(Self {
            digits,
            step_secs,
            skew,
        })
    }

    /// Digits in a code.
    #[must_use]
    pub const fn digits(self) -> u8 {
        self.digits
    }

    /// Seconds per step.
    #[must_use]
    pub const fn step_secs(self) -> u64 {
        self.step_secs
    }

    /// Steps accepted on either side of the current one.
    #[must_use]
    pub const fn skew(self) -> u8 {
        self.skew
    }
}

impl Default for TotpParams {
    fn default() -> Self {
        Self {
            digits: DEFAULT_DIGITS,
            step_secs: DEFAULT_STEP_SECS,
            skew: DEFAULT_SKEW,
        }
    }
}

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

    /// Wraps secret bytes read back from storage (after opening them) or imported.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with [`InvalidRequestReason::TotpSecretTooShort`] for fewer
    /// than [`MIN_SECRET_BYTES`] bytes, which latchkey would never accept a code for.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < MIN_SECRET_BYTES {
            bytes.zeroize();
            return Err(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretTooShort,
            ));
        }
        Ok(Self(bytes))
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
        Self::from_bytes(bytes)
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

    /// The code an authenticator set up with `params` shows at `at`; for tests and for
    /// showing a sample code.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] when the secret is shorter than 128 bits or `at` is before
    /// 1970.
    pub fn code_at(&self, at: OffsetDateTime, params: TotpParams) -> Result<String, Error> {
        let at = u64::try_from(at.unix_timestamp())
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TimeBeforeEpoch))?;
        Ok(build(self, "latchkey", "", params)?
            .generate(at)
            .to_string())
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

    /// The step number (Unix time / the step in seconds).
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
    /// Not the configured number of digits.
    #[error("not a code of the configured length")]
    Malformed,
    /// The right shape, but not the code for any step in the window.
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
#[non_exhaustive]
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

fn build(
    secret: &TotpSecret,
    issuer: &str,
    account: &str,
    params: TotpParams,
) -> Result<Totp, Error> {
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(params.digits)
        .with_skew(params.skew.into())
        .with_step_duration(params.step_secs)
        .with_secret(secret.0.clone())
        .with_issuer(Some(issuer.replace(':', "")))
        .with_account_name(account.replace(':', ""))
        .build()
        .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TotpSecret))
}

/// The base32 secret and `otpauth://` URL for an authenticator app. Colons are removed from
/// `issuer` and `account`, which the URL format reserves. The URL names `digits` and
/// `period` whenever `params` differ from 6 and 30 (authenticators assume those otherwise);
/// an app showing only the base32 secret must tell the user any non-default values.
///
/// # Errors
///
/// [`Error::InvalidRequest`] when the secret is shorter than 128 bits.
///
/// ```
/// use latchkey::totp::{self, TotpParams, TotpSecret};
///
/// # fn main() -> Result<(), latchkey::Error> {
/// let secret = TotpSecret::random(&mut latchkey::os_rng()?);
/// let params = TotpParams::new(8, 60, 1)?;
/// let enrolment = totp::enrolment(&secret, "Home", "owner@example.com", params)?;
/// assert!(enrolment.otpauth_url.contains("digits=8"));
/// assert!(enrolment.otpauth_url.contains("period=60"));
/// # Ok(())
/// # }
/// ```
pub fn enrolment(
    secret: &TotpSecret,
    issuer: &str,
    account: &str,
    params: TotpParams,
) -> Result<Enrolment, Error> {
    let totp = build(secret, issuer, account, params)?;
    Ok(Enrolment {
        secret_base32: secret.to_base32(),
        otpauth_url: totp
            .to_url()
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TotpUrl))?,
    })
}

/// Whether `code` has the shape of a TOTP code: `params.digits()` digits, whitespace
/// ignored. Recovery codes never do, which is how a single "code" field tells them apart.
#[must_use]
pub fn looks_like_code(code: &str, params: TotpParams) -> bool {
    let mut digits = 0usize;
    for c in code.chars().filter(|c| !c.is_whitespace()) {
        if !c.is_ascii_digit() {
            return false;
        }
        digits += 1;
    }
    digits == usize::from(params.digits)
}

/// Checks `code` against `secret` at `now` under `params`, refusing steps at or before
/// `last_used_step` (a step counted with the same `params`).
///
/// # Errors
///
/// A [`TotpRefusal`] saying why the code was not accepted.
pub fn verify(
    secret: &TotpSecret,
    code: &str,
    last_used_step: Option<TotpStep>,
    now: OffsetDateTime,
    params: TotpParams,
) -> Result<TotpStep, TotpRefusal> {
    if !looks_like_code(code, params) {
        return Err(TotpRefusal::Malformed);
    }
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let now = u64::try_from(now.unix_timestamp()).map_err(|_| TotpRefusal::Mismatch)?;
    let totp = build(secret, "latchkey", "", params).map_err(|_| TotpRefusal::Mismatch)?;
    let step = totp
        .check(&code, now)
        .map(TotpStep)
        .ok_or(TotpRefusal::Mismatch)?;
    match last_used_step {
        Some(last) if step <= last => Err(TotpRefusal::Replayed),
        _ => Ok(step),
    }
}

/// The `otpauth://` URL as an SVG QR code. Pass [`Enrolment::otpauth_url`]: it carries
/// non-default digits and period, so the QR code does too.
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

/// The `otpauth://` URL as a PNG QR code. Pass [`Enrolment::otpauth_url`]: it carries
/// non-default digits and period, so the QR code does too.
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

    const P: TotpParams = TotpParams {
        digits: DEFAULT_DIGITS,
        step_secs: DEFAULT_STEP_SECS,
        skew: DEFAULT_SKEW,
    };

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn accepts_current_and_adjacent_steps_only() -> Result<(), Error> {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        let step = TotpStep(1_800_000_000 / 30);
        assert_eq!(
            verify(&secret, &secret.code_at(now, P)?, None, now, P),
            Ok(step)
        );
        let previous = now - Duration::seconds(30);
        assert_eq!(
            verify(&secret, &secret.code_at(previous, P)?, None, now, P),
            Ok(TotpStep(step.get() - 1))
        );
        let old = now - Duration::seconds(120);
        assert_eq!(
            verify(&secret, &secret.code_at(old, P)?, None, now, P),
            Err(TotpRefusal::Mismatch)
        );
        Ok(())
    }

    #[test]
    fn a_step_is_accepted_once_and_never_an_older_one() -> Result<(), Error> {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        let code = secret.code_at(now, P)?;
        let step = verify(&secret, &code, None, now, P)?;
        assert_eq!(
            verify(&secret, &code, Some(step), now, P),
            Err(TotpRefusal::Replayed)
        );
        let previous = secret.code_at(now - Duration::seconds(30), P)?;
        assert_eq!(
            verify(&secret, &previous, Some(step), now, P),
            Err(TotpRefusal::Replayed)
        );
        let next_time = now + Duration::seconds(30);
        let next = secret.code_at(next_time, P)?;
        assert_eq!(
            verify(&secret, &next, Some(step), next_time, P),
            Ok(TotpStep(step.get() + 1))
        );
        Ok(())
    }

    #[test]
    fn rejects_malformed_codes() {
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        assert_eq!(
            verify(&secret, "12345", None, now, P),
            Err(TotpRefusal::Malformed)
        );
        assert_eq!(
            verify(&secret, "abcdef", None, now, P),
            Err(TotpRefusal::Malformed)
        );
        assert!(looks_like_code(" 123 456 ", P));
        assert!(!looks_like_code("abcd-efgh-jkmn", P));
    }

    #[test]
    fn short_secrets_are_refused() {
        assert_eq!(
            TotpSecret::from_bytes(vec![1; MIN_SECRET_BYTES - 1]).err(),
            Some(Error::InvalidRequest(
                InvalidRequestReason::TotpSecretTooShort
            ))
        );
        assert!(TotpSecret::from_bytes(vec![1; MIN_SECRET_BYTES]).is_ok());
        // Still refused when one is built inside the crate.
        let secret = TotpSecret(vec![1; 8]);
        assert!(enrolment(&secret, "Home", "o@example.com", P).is_err());
        assert_eq!(
            verify(&secret, "123456", None, at(1_800_000_000), P),
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
        assert!(verify(&imported, &secret.code_at(now, P)?, None, now, P).is_ok());
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
            P,
        )?;
        assert!(enrolment.otpauth_url.starts_with("otpauth://totp/Home"));
        assert!(enrolment.otpauth_url.contains("owner%40example.com"));
        assert_eq!(enrolment.secret_base32.len(), 32);
        assert!(!format!("{enrolment:?}").contains(&enrolment.secret_base32));
        Ok(())
    }

    #[test]
    fn eight_digits_and_a_sixty_second_step_take_effect_and_reach_the_url() -> Result<(), Error> {
        let params = TotpParams::new(8, 60, 1)?;
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_000);
        let code = secret.code_at(now, params)?;
        assert_eq!(code.len(), 8);
        assert_eq!(
            verify(&secret, &code, None, now, params),
            Ok(TotpStep(1_800_000_000 / 60))
        );
        // A 6-digit code is malformed under 8 digits, and an 8-digit one under the defaults.
        assert_eq!(
            verify(&secret, &secret.code_at(now, P)?, None, now, params),
            Err(TotpRefusal::Malformed)
        );
        assert_eq!(
            verify(&secret, &code, None, now, P),
            Err(TotpRefusal::Malformed)
        );
        // One 60-second step back is within the skew of 1; three steps back is not.
        let earlier = now - Duration::seconds(60);
        assert!(
            verify(
                &secret,
                &secret.code_at(earlier, params)?,
                None,
                now,
                params
            )
            .is_ok()
        );
        let too_old = now - Duration::seconds(180);
        assert_eq!(
            verify(
                &secret,
                &secret.code_at(too_old, params)?,
                None,
                now,
                params
            ),
            Err(TotpRefusal::Mismatch)
        );
        let url = enrolment(&secret, "Home", "o@example.com", params)?
            .otpauth_url
            .clone();
        assert!(url.contains("digits=8"), "{url}");
        assert!(url.contains("period=60"), "{url}");
        let default_url = enrolment(&secret, "Home", "o@example.com", P)?
            .otpauth_url
            .clone();
        assert!(!default_url.contains("digits="));
        assert!(!default_url.contains("period="));
        let only_step = enrolment(&secret, "Home", "o", TotpParams::new(6, 45, 0)?)?;
        assert!(only_step.otpauth_url.contains("period=45"));
        assert!(!only_step.otpauth_url.contains("digits="));
        Ok(())
    }

    #[test]
    fn a_skew_of_zero_accepts_only_the_current_step() -> Result<(), Error> {
        let params = TotpParams::new(6, 30, 0)?;
        let secret = TotpSecret::random(&mut crate::test_rng());
        let now = at(1_800_000_010);
        let previous = secret.code_at(now - Duration::seconds(30), params)?;
        assert_eq!(
            verify(&secret, &previous, None, now, params),
            Err(TotpRefusal::Mismatch)
        );
        let three = TotpParams::new(6, 30, 3)?;
        let old = secret.code_at(now - Duration::seconds(90), three)?;
        assert!(verify(&secret, &old, None, now, three).is_ok());
        Ok(())
    }

    #[test]
    fn params_out_of_bounds_are_refused() {
        assert_eq!(TotpParams::default(), P);
        for (digits, step, skew, reason) in [
            (7, 30, 1, ConfigReason::TotpDigits),
            (10, 30, 1, ConfigReason::TotpDigits),
            (6, 14, 1, ConfigReason::TotpStep),
            (6, 121, 1, ConfigReason::TotpStep),
            (6, 30, 4, ConfigReason::TotpSkew),
        ] {
            assert_eq!(
                TotpParams::new(digits, step, skew),
                Err(Error::Config(reason))
            );
        }
        assert!(TotpParams::new(8, 15, 0).is_ok());
        assert!(TotpParams::new(6, 120, 3).is_ok());
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
