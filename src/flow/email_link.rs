//! Email sign-in: one mail carries a single-use link **and** a numeric code
//! ([`Config::email_code_digits`], 6 by default), both valid for [`Config::link_ttl`] (5
//! minutes by default). Either one replaces the password, never the
//! second factor.
//!
//! ```text
//! Start --Request----> Requested       (answer 202 whether or not a mail went out)
//! Start --Redeem-----> SecondFactor    (the link was opened, on any device)
//! Start --RedeemCode-> SecondFactor    (the code was typed on the screen that asked)
//! ```
//!
//! `SecondFactor` holds a second-factor session, exactly as after a password: rebuild it with
//! [`SignIn::second_factor`](super::sign_in::SignIn::second_factor) and finish with
//! [`SignInEvent::Code`](super::sign_in::SignInEvent::Code) (TOTP or recovery code) or
//! [`SignInEvent::Passkey`](super::sign_in::SignInEvent::Passkey). The full session records
//! [`SignInMethod::EmailTotp`], [`EmailRecoveryCode`](SignInMethod::EmailRecoveryCode) or
//! [`EmailPasskey`](SignInMethod::EmailPasskey). Only an account that could sign in with
//! its password alone (no second factor, under
//! [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly::AllowedUntilEnrolled)) goes
//! straight to [`EmailLink::SignedIn`].
//!
//! # The code, and why 6 digits (the least allowed) are enough here
//!
//! The link carries a 256-bit token and works on any device. The code is for when the link
//! cannot be opened on the device that asked (a TV, a shared computer, mail read on a
//! phone). A 6-digit code has only a million values, so on its own it would be guessable.
//! It is safe only because of all of the following, and none of them may be dropped:
//!
//! - **It is bound to one pending request.** [`EmailLinkEvent::Request`] sets a cookie
//!   ([`Config::email_cookie_name`]) holding a random binding token on the device that asked.
//!   The request is stored under that token's hash, and the code's hash is keyed with the
//!   token itself, so a code works only together with that cookie: on the screen that asked,
//!   never on another request, and a copy of the database cannot reverse it.
//! - **It has a tiny attempt budget.** Each guess is counted before it is checked; the
//!   wrong guess that reaches [`Config::email_code_attempts`] (5 by default, at most 20)
//!   deletes the request and its link. Wrong guesses also count towards the account
//!   lockout, like wrong passwords.
//! - **It lives minutes:** [`Config::link_ttl`], 5 minutes by default; keep it short.
//! - **It is single use, and so is the link:** redeeming either one deletes both.
//! - Only its hash is stored ([`EmailCodeHash`]), and it is compared in constant time.
//!
//! The odds that guessing wins are attempts / 10^digits per mail: 5 in a million with the
//! defaults. More digits or fewer attempts lower them.
//!
//! An attacker who can make requests for someone's address gets their own binding cookie
//! and a code mailed to the victim, which they cannot read; each request costs a mail the
//! victim sees and is limited by the resend cooldown and the app's rate limits. And even a
//! right guess only replaces the password: the second factor is still required.
//!
//! # What the app stores
//!
//! - The link, as for every one-time link: [`Effect::StoreLinkToken`].
//! - The pending code, [`Effect::StoreEmailCode`]: an [`EmailCodeRequest`] under the binding
//!   token's hash (insert or replace).
//!
//! # Redeeming
//!
//! - **Link** (`?token=` posted back): delete the link by `TokenHash::of(token)` and read it
//!   in one step (`DELETE ... RETURNING`), then send [`EmailLinkEvent::Redeem`] with that
//!   hash and what was deleted. On success carry out [`Effect::DeleteEmailCode`], which kills
//!   the code mailed with it.
//! - **Code** (posted with the binding cookie): count the attempt and read the request in
//!   **one atomic statement**, `UPDATE email_codes SET attempts = attempts + 1 WHERE
//!   binding_hash = ? RETURNING ...`, and send [`EmailLinkEvent::RedeemCode`] with the
//!   updated row (or `None`). Counting first means guesses that race each still use up one
//!   attempt. On success carry out [`Effect::ConsumeEmailCode`]: delete the request **and**
//!   its link, compare-and-set, and refuse the sign-in if either was already gone (the link
//!   or another guess won the race).
//!
//! ```
//! use latchkey::flow::email_link::issue_code;
//! use latchkey::{Config, token};
//!
//! # fn main() -> Result<(), latchkey::Error> {
//! let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
//! let mut rng = latchkey::os_rng()?;
//! let binding = token::issue(&mut rng).token; // the requesting device's cookie
//! let (code, hash) = issue_code(&binding, config.email_code_digits(), &mut rng);
//! assert_eq!(code.expose_secret().len(), 6);
//! assert!(hash.verify(binding.expose_secret(), code.expose_secret()));
//! let other_device = token::issue(&mut rng).token;
//! assert!(!hash.verify(other_device.expose_secret(), code.expose_secret()));
//! assert_eq!(config.email_code_attempts(), 5);
//! # Ok(())
//! # }
//! ```

use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use zeroize::Zeroize;

use super::{
    Client, Effect, LinkKind, LinkToken, Refusal, Transition, UNEXPECTED, audit, complete_sign_in,
    failure, issue_link, start_session,
};
use crate::Error;
use crate::account::Account;
use crate::audit::AuditKind;
use crate::config::Config;
use crate::error::InvalidRequestReason;
use crate::http::SetCookie;
use crate::ids::UserId;
use crate::mail::{Mail, MailKind};
use crate::session::{Session, SignInMethod, Stage};
use crate::token::{self, SecretToken, TokenHash, sha256};

/// The default digits in an email sign-in code
/// ([`ConfigBuilder::email_code_digits`](crate::ConfigBuilder::email_code_digits)).
pub const DEFAULT_CODE_DIGITS: u8 = 6;

/// The default guesses a pending code request allows
/// ([`ConfigBuilder::email_code_attempts`](crate::ConfigBuilder::email_code_attempts)).
pub const DEFAULT_CODE_ATTEMPTS: u32 = 5;

/// The digits a code may have: [`issue_code`] clamps to them and [`EmailCodeHash::of`]
/// accepts only them, matching the setting's bounds.
const MIN_DIGITS: u8 = 6;
const MAX_DIGITS: u8 = 10;
const HASH_DOMAIN: &[u8] = b"latchkey-email-code\0";

/// A numeric sign-in code to mail once. Its `Debug` output is redacted, it has no
/// `Display`, and it is zeroed when dropped.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct EmailCode(String);

impl EmailCode {
    /// The digits, for the mail.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl Drop for EmailCode {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for EmailCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EmailCode(<redacted>)")
    }
}

/// What is stored for an [`EmailCode`]: a SHA-256 keyed with the binding token of the request
/// it belongs to. The binding token is never stored (only its own hash, as the request's
/// key), so the code cannot be recovered from the database by trying every value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct EmailCodeHash([u8; 32]);

impl EmailCodeHash {
    /// The hash of `code` for the request bound to `binding`, or `None` when `binding` is not
    /// a well-formed token or `code` is not 6 to 10 ASCII digits (spaces and dashes are
    /// ignored, so `123 456` and `123-456` are `123456`). The digits are hashed as typed, so
    /// a code of another length than the one mailed never matches.
    #[must_use]
    pub fn of(binding: &str, code: &str) -> Option<Self> {
        let binding = binding.trim();
        TokenHash::of(binding)?;
        let mut digits = normalize_code(code)?;
        let mut input = Vec::with_capacity(HASH_DOMAIN.len() + binding.len() + 1 + digits.len());
        input.extend_from_slice(HASH_DOMAIN);
        input.extend_from_slice(binding.as_bytes());
        input.push(0);
        input.extend_from_slice(digits.as_bytes());
        let hash = Self(sha256(&input));
        input.zeroize();
        digits.zeroize();
        Some(hash)
    }

    /// Whether `code`, presented with the binding cookie `binding`, hashes to this value,
    /// compared in constant time.
    #[must_use]
    pub fn verify(&self, binding: &str, code: &str) -> bool {
        Self::of(binding, code).is_some_and(|presented| presented.0.ct_eq(&self.0).into())
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
}

impl TryFrom<&[u8]> for EmailCodeHash {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::TokenHashLength))
    }
}

impl AsRef<[u8]> for EmailCodeHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for EmailCodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EmailCodeHash({})",
            crate::hex(self.0.get(..4).unwrap_or_default())
        )
    }
}

fn normalize_code(code: &str) -> Option<String> {
    let digits: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect();
    let shaped = (usize::from(MIN_DIGITS)..=usize::from(MAX_DIGITS)).contains(&digits.len())
        && digits.bytes().all(|b| b.is_ascii_digit());
    shaped.then_some(digits)
}

/// Draws a uniformly random code of `digits` digits for the request bound to `binding`, and
/// its hash. Pass [`Config::email_code_digits`]; `digits` is clamped to 6 to 10, the
/// setting's bounds.
///
/// The flow calls this itself; it is public for apps that build their own mail, and tests.
#[must_use]
pub fn issue_code<R: CryptoRng + ?Sized>(
    binding: &SecretToken,
    digits: u8,
    rng: &mut R,
) -> (EmailCode, EmailCodeHash) {
    let digits = digits.clamp(MIN_DIGITS, MAX_DIGITS);
    let space = 10u64.pow(u32::from(digits));
    // The largest multiple of `space` that fits in a u64: draws at or above it are redrawn so
    // every code is equally likely.
    let zone = u64::MAX - (u64::MAX % space);
    let value = loop {
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        let drawn = u64::from_le_bytes(bytes);
        bytes.zeroize();
        if drawn < zone {
            break drawn % space;
        }
    };
    let code = EmailCode(format!("{value:0width$}", width = usize::from(digits)));
    // `binding` may be any presented string; an ill-formed one gets a hash nothing matches.
    let hash = EmailCodeHash::of(binding.expose_secret(), code.expose_secret())
        .unwrap_or(EmailCodeHash([0; 32]));
    (code, hash)
}

/// A pending code as the app stores it, under the hash of the requesting device's binding
/// token ([`Effect::StoreEmailCode`]).
///
/// Load it for a guess with the attempt already counted (see the [module docs](self)), and
/// purge rows past `expires_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct EmailCodeRequest {
    /// Whose sign-in it is.
    pub user_id: UserId,
    /// The hash of the link mailed with the code; redeeming either deletes both.
    pub link_hash: TokenHash,
    /// The code's hash.
    pub code_hash: EmailCodeHash,
    /// When it was mailed.
    pub created_at: OffsetDateTime,
    /// When it stops working (the link's expiry).
    pub expires_at: OffsetDateTime,
    /// Guesses made so far, **including** the one being checked: the count the atomic
    /// increment returned. 0 when stored.
    pub attempts: u32,
}

impl EmailCodeRequest {
    /// A pending code read back from storage.
    #[must_use]
    pub const fn new(
        user_id: UserId,
        link_hash: TokenHash,
        code_hash: EmailCodeHash,
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        attempts: u32,
    ) -> Self {
        Self {
            user_id,
            link_hash,
            code_hash,
            created_at,
            expires_at,
            attempts,
        }
    }
}

/// Where an email sign-in is.
// States are moved once per request; boxing the large variants would only complicate
// matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EmailLink {
    /// Nothing yet.
    Start,
    /// The request was handled; answer the same way whether or not a mail went out.
    Requested,
    /// The link or code was accepted and a second-factor session started (the client got its
    /// cookie and CSRF token). Continue with
    /// [`SignIn::second_factor`](super::sign_in::SignIn::second_factor).
    SecondFactor {
        /// Whose.
        account: Account,
        /// The second-factor session.
        session: Session,
    },
    /// Signed in: only for an account whose password alone would sign it in (no second
    /// factor, under [`PasswordOnly::AllowedUntilEnrolled`](crate::PasswordOnly)).
    SignedIn {
        /// Whose.
        account: Account,
        /// The full session.
        session: Session,
    },
}

/// What happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum EmailLinkEvent {
    /// Someone asked for a sign-in mail to an address.
    Request {
        /// The account with that address, if any.
        account: Option<Account>,
        /// When the latest unexpired sign-in link to it was issued, for the resend cooldown.
        last_sent_at: Option<OffsetDateTime>,
        /// The binding cookie ([`Config::email_cookie_name`]) the client presented, if any
        /// (`SecretToken::from_presented`). A well-formed one is kept, so a code mailed
        /// earlier keeps working on this device; otherwise a new one is issued. The cookie is
        /// set either way, for known and unknown addresses alike.
        binding: Option<SecretToken>,
        /// The client.
        client: Client,
    },
    /// A link was opened and its token posted back.
    Redeem {
        /// `TokenHash::of(token)`: the hash the link was deleted by, if the token was
        /// well-formed. Kills the code mailed with it.
        token_hash: Option<TokenHash>,
        /// The link record the app deleted by that hash, if there was one.
        link: Option<LinkToken>,
        /// The account it belongs to.
        account: Option<Account>,
        /// The client.
        client: Client,
    },
    /// A code was typed on the device holding the binding cookie.
    RedeemCode {
        /// The binding cookie the client presented.
        binding: Option<SecretToken>,
        /// The code as typed.
        code: String,
        /// The pending request stored under the binding cookie's hash, as returned by the
        /// atomic attempt increment; `None` if there is none.
        request: Option<EmailCodeRequest>,
        /// The account it belongs to.
        account: Option<Account>,
        /// The client.
        client: Client,
    },
}

impl EmailLink {
    /// Applies `event`.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] with [`Error::SignInFailed`] for an unknown, used, expired or
    /// wrong-kind link, an unknown, expired, used-up or wrong code, a code without its
    /// binding cookie, or an inactive account; [`Error::TooManyAttempts`] for a code while
    /// the account is locked; [`Error::InvalidRequest`] for an event the state does not take.
    /// A wrong code's refusal counts the failure towards the lockout and, at the attempt
    /// budget, ends the request.
    pub fn advance<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        event: EmailLinkEvent,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<EmailLink>, Refusal> {
        match (self, event) {
            (
                EmailLink::Start,
                EmailLinkEvent::Request {
                    account,
                    last_sent_at,
                    binding,
                    client,
                },
            ) => {
                let binding = binding
                    .filter(|binding| binding.hash().is_some())
                    .unwrap_or_else(|| token::issue(rng).token);
                let mut effects = vec![Effect::SetCookie(SetCookie::new(
                    config.email_cookie_name().clone(),
                    &binding,
                    config.link_ttl(),
                ))];
                let cooling = last_sent_at
                    .is_some_and(|last| last.saturating_add(config.resend_cooldown()) > now);
                if let Some(account) = account.filter(|account| account.active && !cooling) {
                    effects.extend(send_sign_in_mail(
                        config, &account, &binding, &client, now, rng,
                    ));
                }
                Ok(Transition {
                    state: EmailLink::Requested,
                    effects,
                })
            }
            (
                EmailLink::Start,
                EmailLinkEvent::Redeem {
                    token_hash,
                    link,
                    account,
                    client,
                },
            ) => {
                let valid = |account: &Account| {
                    account.active
                        && link.is_some_and(|link| {
                            link.is_redeemable(LinkKind::SignIn, now) && link.user_id == account.id
                        })
                };
                let Some(account) = account.filter(valid) else {
                    return Err(Error::SignInFailed.into());
                };
                let mut effects: Vec<Effect> = token_hash
                    .map(|link_hash| Effect::DeleteEmailCode { link_hash })
                    .into_iter()
                    .collect();
                let (state, done) = first_factor_accepted(
                    config,
                    account,
                    &SignInMethod::EmailLink,
                    &client,
                    now,
                    rng,
                );
                effects.extend(done);
                Ok(Transition { state, effects })
            }
            (
                EmailLink::Start,
                EmailLinkEvent::RedeemCode {
                    binding,
                    code,
                    request,
                    account,
                    client,
                },
            ) => {
                let presented = PresentedCode {
                    binding: binding.as_ref(),
                    code: &code,
                    request,
                    account,
                };
                presented.redeem(config, &client, now, rng)
            }
            _ => Err(UNEXPECTED.into()),
        }
    }
}

struct PresentedCode<'a> {
    binding: Option<&'a SecretToken>,
    code: &'a str,
    request: Option<EmailCodeRequest>,
    account: Option<Account>,
}

impl PresentedCode<'_> {
    fn redeem<R: CryptoRng + ?Sized>(
        self,
        config: &Config,
        client: &Client,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<Transition<EmailLink>, Refusal> {
        let (Some(binding), Some(request)) = (self.binding, self.request) else {
            return Err(Error::SignInFailed.into());
        };
        let Some(binding_hash) = binding.hash() else {
            return Err(Error::SignInFailed.into());
        };
        let end = || {
            vec![
                Effect::DeleteEmailSignIn {
                    binding_hash,
                    link_hash: request.link_hash,
                },
                Effect::SetCookie(SetCookie::removal(config.email_cookie_name().clone())),
            ]
        };
        let account = self
            .account
            .filter(|account| account.active && account.id == request.user_id);
        let Some(account) = account else {
            return Err(Refusal::new(Error::SignInFailed, end()));
        };
        let budget = config.email_code_attempts();
        if request.expires_at <= now || request.attempts > budget {
            return Err(Refusal::new(Error::SignInFailed, end()));
        }
        account.lockout.check(now)?;
        if !request.code_hash.verify(binding.expose_secret(), self.code) {
            let mut effects = failure(&account, "email_code", client, now);
            if request.attempts >= budget {
                effects.extend(end());
            }
            return Err(Refusal::new(Error::SignInFailed, effects));
        }
        let mut effects = vec![
            Effect::ConsumeEmailCode {
                binding_hash,
                link_hash: request.link_hash,
            },
            Effect::SetCookie(SetCookie::removal(config.email_cookie_name().clone())),
        ];
        let (state, done) =
            first_factor_accepted(config, account, &SignInMethod::EmailCode, client, now, rng);
        effects.extend(done);
        Ok(Transition { state, effects })
    }
}

/// The link or code stood in for the password: continue to the second factor, exactly as
/// after a password.
fn first_factor_accepted<R: CryptoRng + ?Sized>(
    config: &Config,
    account: Account,
    method: &SignInMethod,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> (EmailLink, Vec<Effect>) {
    if account.factors.password_suffices(config.password_only()) {
        let (session, effects) = complete_sign_in(config, &account, method, client, None, now, rng);
        return (EmailLink::SignedIn { account, session }, effects);
    }
    let (session, effects) = start_session(
        config,
        account.id,
        Stage::SecondFactor,
        Some(method.clone()),
        client,
        None,
        now,
        rng,
    );
    (EmailLink::SecondFactor { account, session }, effects)
}

/// Issues the link and the code, stores both, and mails them together.
fn send_sign_in_mail<R: CryptoRng + ?Sized>(
    config: &Config,
    account: &Account,
    binding: &SecretToken,
    client: &Client,
    now: OffsetDateTime,
    rng: &mut R,
) -> Vec<Effect> {
    let issued = issue_link(config, account, LinkKind::SignIn, now, rng);
    let (code, code_hash) = issue_code(binding, config.email_code_digits(), rng);
    let mut effects = Vec::with_capacity(4);
    if let Some(binding_hash) = binding.hash() {
        effects.push(Effect::StoreEmailCode {
            binding_hash,
            request: EmailCodeRequest::new(
                account.id,
                issued.token_hash,
                code_hash,
                now,
                issued.link.expires_at,
                0,
            ),
        });
    }
    effects.push(Effect::StoreLinkToken {
        token_hash: issued.token_hash,
        link: issued.link,
    });
    effects.push(Effect::SendMail(
        Mail::new(
            MailKind::SignInLink,
            account.email.clone(),
            issued.url,
            Some(issued.link.expires_at),
            None,
        )
        .with_code(code),
    ));
    effects.push(Effect::Audit(audit(
        AuditKind::SignInLinkSent,
        Some(account.id),
        client,
        now,
    )));
    effects
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_six_digits_and_bound_to_their_binding() {
        let mut rng = crate::test_rng();
        let binding = token::issue(&mut rng).token;
        let other = token::issue(&mut rng).token;
        for _ in 0..200 {
            let (code, hash) = issue_code(&binding, DEFAULT_CODE_DIGITS, &mut rng);
            let digits = code.expose_secret();
            assert_eq!(digits.len(), 6);
            assert!(digits.bytes().all(|b| b.is_ascii_digit()));
            assert!(hash.verify(binding.expose_secret(), digits));
            assert!(!hash.verify(other.expose_secret(), digits));
        }
    }

    #[test]
    fn codes_have_the_digits_asked_for_within_the_bounds() {
        let mut rng = crate::test_rng();
        let binding = token::issue(&mut rng).token;
        for (asked, got) in [
            (6, 6),
            (8, 8),
            (10, 10),
            (0, 6),
            (4, 6),
            (12, 10),
            (255, 10),
        ] {
            for _ in 0..50 {
                let (code, hash) = issue_code(&binding, asked, &mut rng);
                let digits = code.expose_secret();
                assert_eq!(digits.len(), got, "asked for {asked}");
                assert!(digits.bytes().all(|b| b.is_ascii_digit()));
                assert!(hash.verify(binding.expose_secret(), digits));
            }
        }
    }

    #[test]
    fn codes_ignore_spaces_and_dashes_and_refuse_other_shapes() {
        let binding = token::issue(&mut crate::test_rng()).token;
        let b = binding.expose_secret();
        let hash = EmailCodeHash::of(b, "123456").unwrap();
        assert!(hash.verify(b, " 123 456 "));
        assert!(hash.verify(b, "123-456"));
        assert!(!hash.verify(b, "123457"));
        assert_eq!(EmailCodeHash::of(b, "12345"), None);
        assert_eq!(EmailCodeHash::of(b, "12345678901"), None);
        // Any length the setting allows hashes, but only to its own value.
        let eight = EmailCodeHash::of(b, "1234-5678").unwrap();
        assert!(eight.verify(b, "12345678"));
        assert!(!eight.verify(b, "123456"));
        assert!(!hash.verify(b, "12345600"));
        assert_eq!(EmailCodeHash::of(b, "12345a"), None);
        assert_eq!(
            EmailCodeHash::of(b, "\u{661}\u{662}\u{663}\u{664}\u{665}\u{666}"),
            None,
            "ASCII digits only"
        );
        assert_eq!(EmailCodeHash::of("not a token", "123456"), None);
    }

    #[test]
    fn codes_are_redacted_and_hashes_round_trip() {
        let mut rng = crate::test_rng();
        let binding = token::issue(&mut rng).token;
        let (code, hash) = issue_code(&binding, DEFAULT_CODE_DIGITS, &mut rng);
        assert!(!format!("{code:?}").contains(code.expose_secret()));
        let bytes: &[u8] = hash.as_ref();
        assert_eq!(EmailCodeHash::try_from(bytes), Ok(hash));
        assert_eq!(EmailCodeHash::from_bytes(*hash.as_bytes()), hash);
        assert!(EmailCodeHash::try_from(&bytes[..31]).is_err());
    }
}
