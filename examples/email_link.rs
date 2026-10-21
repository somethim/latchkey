//! Email sign-in: request a mail with a link and a code, type the code on the device that
//! asked, then give the second factor. The link dies with the code.
//!
//! Run with `cargo run --example email_link`.

use std::collections::HashMap;

use latchkey::account::{Account, Email, Factors, Role};
use latchkey::flow::email_link::{EmailCodeRequest, EmailLink, EmailLinkEvent};
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::{Client, CodeMaterial, Effect, LinkToken, TotpMaterial};
use latchkey::mail::Mail;
use latchkey::token::{SecretToken, TokenHash};
use latchkey::totp::TotpSecret;
use latchkey::{Config, UserId};
use time::{Duration, OffsetDateTime};

/// The app's storage, and the requesting device's cookie jar.
#[derive(Default)]
struct Store {
    links: HashMap<TokenHash, LinkToken>,
    codes: HashMap<TokenHash, EmailCodeRequest>,
    outbox: Vec<Mail>,
    cookies: HashMap<String, String>,
}

impl Store {
    fn apply(&mut self, effects: Vec<Effect>) -> Result<(), latchkey::Error> {
        for effect in effects {
            match effect {
                Effect::StoreLinkToken { token_hash, link } => {
                    self.links.insert(token_hash, link);
                }
                // Insert or replace, keyed by the binding cookie's hash.
                Effect::StoreEmailCode {
                    binding_hash,
                    request,
                } => {
                    self.codes.insert(binding_hash, request);
                }
                // In SQL, one transaction in which both deletes must hit a row.
                Effect::ConsumeEmailCode {
                    binding_hash,
                    link_hash,
                } => {
                    let code = self.codes.remove(&binding_hash);
                    let link = self.links.remove(&link_hash);
                    if code.is_none() || link.is_none() {
                        return Err(latchkey::Error::SignInFailed); // lost a race
                    }
                }
                Effect::DeleteEmailCode { link_hash } => {
                    self.codes
                        .retain(|_, request| request.link_hash != link_hash);
                }
                Effect::DeleteEmailSignIn {
                    binding_hash,
                    link_hash,
                } => {
                    self.codes.remove(&binding_hash);
                    self.links.remove(&link_hash);
                }
                Effect::SetCookie(cookie) => {
                    let name = cookie.name().as_str().to_owned();
                    if cookie.max_age() > Duration::ZERO {
                        self.cookies.insert(name, cookie.expose_value().to_owned());
                    } else {
                        self.cookies.remove(&name);
                    }
                }
                Effect::SendMail(mail) => {
                    println!(
                        "To: {}\nSubject: {}\n\n{}",
                        mail.to,
                        mail.subject(),
                        mail.text()
                    );
                    self.outbox.push(mail);
                }
                Effect::Audit(event) => println!("audit: {}", event.kind),
                // StoreSession, RememberDevice, UseTotpStep and the rest: see
                // examples/password_totp.rs.
                _ => {}
            }
        }
        Ok(())
    }

    /// The atomic `UPDATE email_codes SET attempts = attempts + 1 WHERE binding_hash = ?
    /// RETURNING ...`.
    fn count_attempt(&mut self, binding: Option<&SecretToken>) -> Option<EmailCodeRequest> {
        let request = self.codes.get_mut(&binding?.hash()?)?;
        request.attempts += 1;
        Some(*request)
    }

    fn binding(&self, config: &Config) -> Option<SecretToken> {
        self.cookies
            .get(config.email_cookie_name().as_str())
            .map(|value| SecretToken::from_presented(value))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
    let mut rng = latchkey::os_rng()?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let totp = TotpSecret::random(&mut rng);
    let mut account = Account::new(
        UserId::random(&mut rng),
        Email::parse("owner@example.com")?,
        Role::Owner,
    );
    account.display_name = "Owner".into();
    account.active = true;
    account.factors = Factors::new(true, true, 0);
    let mut store = Store::default();

    // POST /sign-in/email {email}: always answer 202. The cookie binds the code to this device.
    let step = EmailLink::Start
        .advance(
            &config,
            EmailLinkEvent::Request {
                account: Some(account.clone()),
                last_sent_at: None,
                binding: store.binding(&config),
                client: Client::default(),
            },
            now,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    store.apply(step.effects)?;

    // POST /sign-in/email/code {code}, with the cookie. Count the attempt first, atomically.
    let mail = store.outbox.first().ok_or("no mail")?.clone();
    let code = mail
        .code
        .as_ref()
        .ok_or("no code")?
        .expose_secret()
        .to_owned();
    let binding = store.binding(&config);
    let request = store.count_attempt(binding.as_ref());
    let step = EmailLink::Start
        .advance(
            &config,
            EmailLinkEvent::RedeemCode {
                binding,
                code,
                request,
                account: Some(account.clone()),
                client: Client::default(),
            },
            now,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    let EmailLink::SecondFactor { session, account } = step.state else {
        return Err("expected the second factor".into());
    };
    store.apply(step.effects)?;
    println!(
        "code accepted; second factor due ({})",
        session.stage.as_str()
    );

    // POST /sign-in/code {code}: the same second-factor step as after a password.
    let later = now + Duration::seconds(30);
    let material = CodeMaterial::new(Some(TotpMaterial::new(totp.clone(), None)), Vec::new());
    let step = SignIn::second_factor(session, account.clone())
        .advance(
            &config,
            SignInEvent::Code {
                code: totp.code_at(later, config.totp_params())?,
                material,
                client: Client::default(),
            },
            later,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    if let SignIn::SignedIn { session, .. } = &step.state {
        let method = session.method.as_ref().map(ToString::to_string);
        println!("signed in by {}", method.unwrap_or_default());
    }
    store.apply(step.effects)?;

    // The link from the same mail was deleted with the code: refused.
    let token = mail.link_token().ok_or("no link")?;
    let token_hash = TokenHash::of(&token);
    let link = token_hash.and_then(|hash| store.links.remove(&hash));
    let refused = EmailLink::Start
        .advance(
            &config,
            EmailLinkEvent::Redeem {
                token_hash,
                link,
                account: Some(account),
                client: Client::default(),
            },
            later,
            &mut rng,
        )
        .err()
        .map(|refusal| refusal.error);
    println!("the link after the code: {refused:?}");
    Ok(())
}
