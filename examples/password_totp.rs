//! Password + TOTP sign-in with the app's own storage (here `HashMap`s).
//!
//! Run with `cargo run --example password_totp`.

use std::collections::HashMap;

use latchkey::account::{Account, AccountKey, Email, Factors, Lockout, Role};
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::{Client, CodeMaterial, Effect, TotpMaterial};
use latchkey::limits::{RateLimiter, WrongPasswordThrottle};
use latchkey::password::{PasswordHash, PasswordHasher, PasswordParams};
use latchkey::seal::DataKey;
use latchkey::session::Session;
use latchkey::token::TokenHash;
use latchkey::totp::{TotpSecret, TotpStep};
use latchkey::{Config, Error, LockoutPolicy, UserId};
use time::OffsetDateTime;

/// One row per account.
struct UserRow {
    account: Account,
    password: PasswordHash,
    sealed_totp: Vec<u8>,
    last_step: Option<TotpStep>,
}

#[derive(Default)]
struct Store {
    users: HashMap<UserId, UserRow>,
    sessions: HashMap<TokenHash, Session>,
    audit: Vec<String>,
}

impl Store {
    fn by_email(&self, login: &str) -> Option<&UserRow> {
        let email = Email::parse(login).ok()?;
        self.users.values().find(|row| row.account.email == email)
    }

    /// Carries out the effects of a sign-in step. A real app does this in a transaction.
    fn apply(
        &mut self,
        effects: Vec<Effect>,
        throttle: &mut WrongPasswordThrottle,
        policy: &LockoutPolicy,
        now: OffsetDateTime,
    ) -> Result<(), Error> {
        for effect in effects {
            match effect {
                Effect::StoreSession { session, replaces } => {
                    if let Some(old) = replaces {
                        self.sessions.remove(&old);
                    }
                    self.sessions.insert(session.token_hash, session);
                }
                Effect::SetCookie(cookie) => println!(
                    "Set-Cookie: {}=…; Max-Age={}",
                    cookie.name(),
                    cookie.max_age().whole_seconds()
                ),
                // One atomic statement in a database:
                // UPDATE users SET failures = failures + 1 WHERE id = ? RETURNING failures
                Effect::RecordFailure {
                    user_id,
                    at,
                    ip_tag,
                } => {
                    if let Some(row) = self.users.get_mut(&user_id) {
                        row.account.lockout.failures += 1;
                        let failures = row.account.lockout.failures;
                        if let Some(until) = policy.locked_until(failures, at) {
                            row.account.lockout.locked_until = Some(until);
                        }
                        if let Some(event) = policy.lockout_event(user_id, failures, at, ip_tag) {
                            self.audit.push(event.kind.to_string());
                        }
                    }
                }
                Effect::ClearFailures { user_id } => {
                    if let Some(row) = self.users.get_mut(&user_id) {
                        row.account.lockout = Lockout::default();
                    }
                }
                Effect::RecordWrongPassword { key } => throttle.record(&key, now),
                Effect::UseTotpStep { user_id, step } => {
                    let row = self.users.get_mut(&user_id).ok_or(Error::SignInFailed)?;
                    // Compare-and-set: a step at or before the stored one loses the race.
                    if row.last_step.is_some_and(|last| last >= step) {
                        return Err(Error::SignInFailed);
                    }
                    row.last_step = Some(step);
                }
                Effect::Audit(event) => self.audit.push(event.kind.to_string()),
                Effect::SendMail(mail) => println!("mail to {}: {}", mail.to, mail.subject()),
                Effect::RememberDevice { .. } => {}
                other => println!("(not needed in this example: {other:?})"),
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)] // the two requests read best top to bottom
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("owner@example.com", "https://home.example.com")
        .password_params(PasswordParams::new(19 * 1024, 2, 1)?)
        .build()?;
    let mut rng = latchkey::os_rng()?;
    let hasher = PasswordHasher::new(config.password_params(), &mut rng)?;
    let data_key = DataKey::new(&[7; 32]); // load from your secret store
    let mut throttle = WrongPasswordThrottle::new(config.rate_limits());
    let mut per_ip = RateLimiter::per_minute(config.rate_limits().per_ip_per_minute);
    let mut store = Store::default();
    let mut now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;

    // An account that finished setup earlier.
    let id = UserId::random(&mut rng);
    let secret = TotpSecret::random(&mut rng);
    store.users.insert(
        id,
        UserRow {
            account: Account {
                id,
                email: Email::parse("owner@example.com")?,
                display_name: "Owner".into(),
                role: Role::Owner,
                active: true,
                factors: Factors {
                    password: true,
                    totp: true,
                    passkeys: 0,
                },
                lockout: Lockout::default(),
            },
            password: hasher.hash_new_password("correct horse battery staple", &mut rng)?,
            sealed_totp: data_key.seal_totp(&mut rng, id, &secret)?,
            last_step: None,
        },
    );

    // Request 1: POST /sign-in {email, password}.
    let login = "Owner@Example.com";
    per_ip.check("ip:203.0.113.9", now)?;
    let row = store.by_email(login);
    let step = SignIn::Start
        .advance(
            &config,
            SignInEvent::Password {
                login: login.into(),
                account: row.map(|row| row.account.clone()),
                wrong_passwords: throttle.window(&AccountKey::from_login(login)),
            },
            now,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    // Allowed to hash: verify against the account's hash, or the dummy for unknown accounts.
    let matched = hasher.verify("correct horse battery staple", row.map(|row| &row.password));
    let step = match step.state.advance(
        &config,
        SignInEvent::PasswordChecked {
            matched,
            client: Client::default(),
        },
        now,
        &mut rng,
    ) {
        Ok(step) => step,
        Err(refusal) => {
            store.apply(refusal.effects, &mut throttle, config.lockout(), now)?;
            return Err(refusal.error.into());
        }
    };
    store.apply(step.effects, &mut throttle, config.lockout(), now)?;
    let SignIn::SecondFactor { session, .. } = step.state else {
        unreachable!()
    };
    println!("second factor needed; CSRF token sent in the body");

    // Request 2: POST /sign-in/code {code}, with the second-factor session cookie.
    now += time::Duration::seconds(5);
    let session = store
        .sessions
        .get(&session.token_hash)
        .cloned()
        .ok_or(Error::Unauthorized)?;
    let row = store
        .users
        .get(&session.user_id)
        .ok_or(Error::Unauthorized)?;
    let material = CodeMaterial {
        totp: Some(TotpMaterial {
            secret: data_key.open_totp(row.account.id, &row.sealed_totp)?,
            last_used_step: row.last_step,
        }),
        recovery_codes: Vec::new(),
    };
    let code = secret.code_at(now)?; // what the authenticator app shows
    let step = SignIn::second_factor(session, row.account.clone())
        .advance(
            &config,
            SignInEvent::Code {
                code,
                material,
                client: Client::default(),
            },
            now,
            &mut rng,
        )
        .map_err(|refusal| refusal.error)?;
    store.apply(step.effects, &mut throttle, config.lockout(), now)?;
    if let SignIn::SignedIn { session, .. } = step.state {
        println!(
            "signed in with {:?}, session expires {}",
            session.method, session.expires_at
        );
    }
    println!("audit: {:?}", store.audit);
    Ok(())
}
