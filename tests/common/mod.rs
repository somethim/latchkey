//! An app with its storage in `HashMap`s that carries out latchkey's effects, for the
//! integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{HashMap, HashSet};

use latchkey::account::{Account, Email, Factors, Lockout, NewAccount, Role};
use latchkey::audit::{AuditEvent, AuditKind};
use latchkey::flow::email_link::{EmailLink, EmailLinkEvent};
use latchkey::flow::setup::{Setup, SetupEvent};
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::step_up::{StepUp, StepUpEvent};
use latchkey::flow::{Client, CodeMaterial, Effect, LinkKind, LinkToken, Refusal, TotpMaterial};
use latchkey::http::SetCookie;
use latchkey::limits::WrongPasswordThrottle;
use latchkey::mail::Mail;
use latchkey::password::{PasswordHash, PasswordHasher, PasswordParams};
use latchkey::recovery::{RecoveryCode, RecoveryCodeHash};
use latchkey::seal::DataKey;
use latchkey::session::Session;
use latchkey::token::{SecretToken, TokenHash};
use latchkey::totp::{self, TotpSecret, TotpStep};
use latchkey::{Config, Error, PasskeyId, UserId};
use rand::SeedableRng;
use rand::rngs::StdRng;
use time::{Duration, OffsetDateTime};

pub const ORIGIN: &str = "https://home.example.com";
pub const OWNER: &str = "owner@example.com";
pub const PASSWORD: &str = "correct horse battery staple";

#[derive(Debug, Default, Clone)]
pub struct Row {
    pub new: Option<NewAccount>,
    pub active: bool,
    pub lockout: Lockout,
    pub password: Option<PasswordHash>,
    pub totp: Option<Vec<u8>>,
    pub pending_totp: Option<Vec<u8>>,
    pub last_step: Option<TotpStep>,
    pub recovery: Vec<(RecoveryCodeHash, bool)>,
    pub passkeys: Vec<(PasskeyId, String)>,
}

pub struct App {
    pub config: Config,
    pub rng: StdRng,
    pub hasher: PasswordHasher,
    pub data_key: DataKey,
    pub now: OffsetDateTime,
    pub rows: HashMap<UserId, Row>,
    pub sessions: HashMap<TokenHash, Session>,
    pub links: HashMap<TokenHash, LinkToken>,
    pub devices: HashSet<(UserId, TokenHash)>,
    pub audit: Vec<AuditEvent>,
    pub mail: Vec<Mail>,
    pub throttle: WrongPasswordThrottle,
}

/// A browser's cookie jar.
#[derive(Debug, Default, Clone)]
pub struct Browser {
    pub cookies: HashMap<String, String>,
    pub csrf: Option<SecretToken>,
    pub user_agent: Option<String>,
}

impl Browser {
    pub fn set(&mut self, cookie: &SetCookie) {
        if cookie.max_age() <= Duration::ZERO {
            self.cookies.remove(cookie.name().as_str());
        } else {
            self.cookies.insert(
                cookie.name().as_str().to_owned(),
                cookie.expose_value().to_owned(),
            );
        }
    }

    pub fn session_cookie(&self) -> Option<&str> {
        self.cookies.get("__Host-latchkey").map(String::as_str)
    }

    pub fn device_cookie(&self) -> Option<&str> {
        self.cookies
            .get("__Host-latchkey_device")
            .map(String::as_str)
    }
}

impl App {
    pub fn new() -> Self {
        Self::with_config(Config::builder(OWNER, ORIGIN).password(cheap()))
    }

    pub fn with_config(builder: latchkey::ConfigBuilder) -> Self {
        let config = builder.build().unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let hasher = PasswordHasher::new(config.password(), &mut rng).unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let mut app = Self {
            throttle: WrongPasswordThrottle::new(config.rate_limits()),
            config,
            rng,
            hasher,
            data_key: DataKey::new(&[9; 32]),
            now,
            rows: HashMap::new(),
            sessions: HashMap::new(),
            links: HashMap::new(),
            devices: HashSet::new(),
            audit: Vec::new(),
            mail: Vec::new(),
        };
        let owner = NewAccount::owner(&app.config, now, &mut app.rng);
        app.apply(vec![Effect::CreateAccount(owner)], &mut Browser::default())
            .unwrap();
        app
    }

    pub fn advance(&mut self, by: Duration) {
        self.now += by;
    }

    pub fn owner_id(&self) -> UserId {
        self.rows
            .iter()
            .find(|(_, row)| row.new.as_ref().unwrap().role == Role::Owner)
            .map(|(id, _)| *id)
            .unwrap()
    }

    pub fn id_of(&self, email: &str) -> Option<UserId> {
        self.rows
            .iter()
            .find(|(_, row)| row.new.as_ref().unwrap().email.as_str() == email)
            .map(|(id, _)| *id)
    }

    pub fn account(&self, id: UserId) -> Option<Account> {
        let row = self.rows.get(&id)?;
        let new = row.new.as_ref()?;
        Some(Account {
            id,
            email: new.email.clone(),
            display_name: new.display_name.clone(),
            role: new.role,
            active: row.active,
            factors: Factors {
                password: row.password.is_some(),
                totp: row.totp.is_some(),
                passkeys: row.passkeys.len(),
            },
            lockout: row.lockout,
        })
    }

    pub fn account_by_email(&self, email: &str) -> Option<Account> {
        let email = Email::parse(email).ok()?;
        self.id_of(email.as_str()).and_then(|id| self.account(id))
    }

    pub fn client(&self, browser: &Browser, user: Option<UserId>) -> Client {
        let device_cookie = browser.device_cookie().map(SecretToken::from_presented);
        let device_known = match (user, device_cookie.as_ref().and_then(SecretToken::hash)) {
            (Some(user), Some(hash)) => self.devices.contains(&(user, hash)),
            _ => false,
        };
        Client {
            ip_tag: None,
            user_agent: browser.user_agent.clone(),
            device_cookie,
            device_known,
        }
    }

    pub fn material(&self, user: UserId) -> CodeMaterial {
        let row = &self.rows[&user];
        CodeMaterial {
            totp: row.totp.as_ref().map(|sealed| TotpMaterial {
                secret: self.data_key.open_totp(user, sealed).unwrap(),
                last_used_step: row.last_step,
            }),
            recovery_codes: row
                .recovery
                .iter()
                .filter(|(_, used)| !used)
                .map(|(hash, _)| *hash)
                .collect(),
        }
    }

    pub fn session_of(&self, browser: &Browser) -> Option<Session> {
        let hash = TokenHash::of(browser.session_cookie()?)?;
        self.sessions.get(&hash).cloned()
    }

    pub fn audit_count(&self, kind: AuditKind) -> usize {
        self.audit.iter().filter(|event| event.kind == kind).count()
    }

    /// Carries out effects the way a real app would, compare-and-set included.
    pub fn apply(&mut self, effects: Vec<Effect>, browser: &mut Browser) -> Result<(), Error> {
        for effect in effects {
            match effect {
                Effect::StoreSession { session, replaces } => {
                    if let Some(old) = replaces {
                        self.sessions.remove(&old);
                    }
                    browser.csrf = Some(session.csrf_token.clone());
                    self.sessions.insert(session.token_hash, session);
                }
                Effect::DeleteSession { token_hash } => {
                    self.sessions.remove(&token_hash);
                }
                Effect::SetCookie(cookie) => browser.set(&cookie),
                Effect::SaveLockout { user_id, lockout } => {
                    self.rows.get_mut(&user_id).unwrap().lockout = lockout;
                }
                Effect::RecordWrongPassword { key } => self.throttle.record(&key, self.now),
                Effect::UseTotpStep { user_id, step } => {
                    let row = self.rows.get_mut(&user_id).unwrap();
                    if row.last_step.is_some_and(|last| last >= step) {
                        return Err(Error::SignInFailed);
                    }
                    row.last_step = Some(step);
                }
                Effect::UseRecoveryCode { user_id, hash } => {
                    let row = self.rows.get_mut(&user_id).unwrap();
                    let code = row
                        .recovery
                        .iter_mut()
                        .find(|(stored, used)| *stored == hash && !used)
                        .ok_or(Error::SignInFailed)?;
                    code.1 = true;
                }
                Effect::StoreRecoveryCodes { user_id, hashes } => {
                    self.rows.get_mut(&user_id).unwrap().recovery =
                        hashes.into_iter().map(|hash| (hash, false)).collect();
                }
                Effect::StoreLinkToken { token_hash, link } => {
                    self.links.insert(token_hash, link);
                }
                Effect::SendMail(mail) => self.mail.push(mail),
                Effect::Audit(event) => self.audit.push(event),
                Effect::RememberDevice {
                    user_id,
                    device_hash,
                    ..
                } => {
                    self.devices.insert((user_id, device_hash));
                }
                Effect::CreateAccount(account) => {
                    if self.id_of(account.email.as_str()).is_some() {
                        return Err(Error::Conflict("email_taken"));
                    }
                    self.rows.insert(
                        account.id,
                        Row {
                            new: Some(account),
                            ..Row::default()
                        },
                    );
                }
                Effect::StorePassword { user_id, hash } => {
                    self.rows.get_mut(&user_id).unwrap().password = Some(hash);
                }
                Effect::ActivateAccount { user_id } => {
                    self.rows.get_mut(&user_id).unwrap().active = true;
                }
                Effect::MarkStepUp {
                    token_hash,
                    at,
                    method,
                } => {
                    if let Some(session) = self.sessions.get_mut(&token_hash) {
                        session.authenticated_at = Some(at);
                        session.method = Some(method);
                    }
                }
                _ => unreachable!("new effect"),
            }
        }
        Ok(())
    }

    /// Applies a refusal's effects and returns its error.
    pub fn refused(&mut self, refusal: Refusal, browser: &mut Browser) -> Error {
        self.apply(refusal.effects, browser).unwrap();
        refusal.error
    }

    pub fn take_link(&mut self, mail: &Mail) -> Option<LinkToken> {
        let hash = TokenHash::of(&mail.link_token()?)?;
        self.links.remove(&hash)
    }

    // ---- flows as an app would drive them ----

    pub fn request_setup(&mut self, browser: &mut Browser) {
        let owner = self.account(self.owner_id());
        let client = self.client(browser, None);
        let last = self.last_link_at(self.owner_id(), LinkKind::Setup);
        let step = Setup::Start
            .advance(
                &self.config,
                SetupEvent::RequestLink {
                    owner,
                    last_sent_at: last,
                    client,
                },
                self.now,
                &mut self.rng,
            )
            .unwrap();
        self.apply(step.effects, browser).unwrap();
    }

    pub fn last_link_at(&self, user: UserId, kind: LinkKind) -> Option<OffsetDateTime> {
        self.links
            .values()
            .filter(|link| link.user_id == user && link.kind == kind)
            .map(|link| link.created_at)
            .max()
    }

    pub fn redeem_setup(
        &mut self,
        browser: &mut Browser,
        kind: LinkKind,
        token: &str,
    ) -> Result<Setup, Error> {
        let link = TokenHash::of(token).and_then(|hash| self.links.remove(&hash));
        let account = link.and_then(|link| self.account(link.user_id));
        let client = self.client(browser, None);
        match Setup::Start.advance(
            &self.config,
            SetupEvent::Redeem {
                kind,
                link,
                account,
                client,
            },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                Ok(step.state)
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    fn setup_state(&self, browser: &Browser) -> Result<Setup, Error> {
        let session = self.session_of(browser).ok_or(Error::Unauthorized)?;
        let account = self.account(session.user_id).ok_or(Error::Unauthorized)?;
        Ok(Setup::resume(session, account))
    }

    pub fn setup_password(&mut self, browser: &mut Browser, password: &str) -> Result<(), Error> {
        let state = self.setup_state(browser)?;
        let hash = self.hasher.hash_new_password(password, &mut self.rng)?;
        let client = self.client(browser, None);
        match state.advance(
            &self.config,
            SetupEvent::PasswordSet { hash, client },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => self.apply(step.effects, browser),
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    /// Enrols TOTP directly (as the app would after `totp::verify` of the first code).
    pub fn enrol_totp(&mut self, user: UserId) -> TotpSecret {
        let secret = TotpSecret::random(&mut self.rng);
        let code = secret.code_at(self.now).unwrap();
        let step = totp::verify(&secret, &code, None, self.now).unwrap();
        let sealed = self
            .data_key
            .seal_totp(&mut self.rng, user, &secret)
            .unwrap();
        let row = self.rows.get_mut(&user).unwrap();
        row.totp = Some(sealed);
        row.last_step = Some(step);
        secret
    }

    pub fn finish_setup(&mut self, browser: &mut Browser) -> Result<Vec<RecoveryCode>, Error> {
        let state = self.setup_state(browser)?;
        let user = match &state {
            Setup::InSetup { account, .. } => account.id,
            _ => unreachable!(),
        };
        let client = self.client(browser, Some(user));
        match state.advance(
            &self.config,
            SetupEvent::Finish { client },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                match step.state {
                    Setup::Complete { recovery_codes, .. } => Ok(recovery_codes),
                    _ => unreachable!(),
                }
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    /// Sets up the owner with a password and TOTP; returns the TOTP secret and codes.
    pub fn setup_owner(&mut self, browser: &mut Browser) -> (TotpSecret, Vec<RecoveryCode>) {
        self.request_setup(browser);
        let token = self.mail.last().unwrap().link_token().unwrap();
        self.redeem_setup(browser, LinkKind::Setup, &token).unwrap();
        self.setup_password(browser, PASSWORD).unwrap();
        let secret = self.enrol_totp(self.owner_id());
        self.advance(Duration::seconds(30));
        let codes = self.finish_setup(browser).unwrap();
        (secret, codes)
    }

    /// The password step; `Ok` leaves a second-factor session in the browser.
    pub fn password_step(
        &mut self,
        browser: &mut Browser,
        email: &str,
        password: &str,
    ) -> Result<SignIn, Error> {
        let key = latchkey::account::AccountKey::from_login(email);
        let account = self.account_by_email(email);
        let step = SignIn::Start.advance(
            &self.config,
            SignInEvent::Password {
                login: email.to_owned(),
                account,
                wrong_passwords: self.throttle.window(&key),
            },
            self.now,
            &mut self.rng,
        );
        let state = match step {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                step.state
            }
            Err(refusal) => return Err(self.refused(refusal, browser)),
        };
        let stored = match &state {
            SignIn::VerifyPassword {
                account: Some(account),
                ..
            } => self.rows[&account.id].password.clone(),
            _ => None,
        };
        let matched = self.hasher.verify(password, stored.as_ref());
        let client = self.client(browser, None);
        match state.advance(
            &self.config,
            SignInEvent::PasswordChecked { matched, client },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                Ok(step.state)
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    /// The code step on the second-factor session in `browser`.
    pub fn code_step(&mut self, browser: &mut Browser, code: &str) -> Result<SignIn, Error> {
        let session = self.session_of(browser).ok_or(Error::Unauthorized)?;
        let account = self.account(session.user_id).ok_or(Error::Unauthorized)?;
        let material = self.material(account.id);
        let client = self.client(browser, Some(account.id));
        match SignIn::second_factor(session, account).advance(
            &self.config,
            SignInEvent::Code {
                code: code.to_owned(),
                material,
                client,
            },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                Ok(step.state)
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    pub fn sign_in(
        &mut self,
        browser: &mut Browser,
        email: &str,
        password: &str,
        secret: &TotpSecret,
    ) -> Result<SignIn, Error> {
        self.password_step(browser, email, password)?;
        let code = secret.code_at(self.now).unwrap();
        self.code_step(browser, &code)
    }

    pub fn request_email_link(&mut self, browser: &mut Browser, email: &str) {
        let account = self.account_by_email(email);
        let last = account
            .as_ref()
            .and_then(|account| self.last_link_at(account.id, LinkKind::SignIn));
        let client = self.client(browser, None);
        let step = EmailLink::Start
            .advance(
                &self.config,
                EmailLinkEvent::Request {
                    account,
                    last_sent_at: last,
                    client,
                },
                self.now,
                &mut self.rng,
            )
            .unwrap();
        assert!(matches!(step.state, EmailLink::Requested));
        self.apply(step.effects, browser).unwrap();
    }

    pub fn redeem_email_link(
        &mut self,
        browser: &mut Browser,
        token: &str,
    ) -> Result<EmailLink, Error> {
        let link = TokenHash::of(token).and_then(|hash| self.links.remove(&hash));
        let account = link.and_then(|link| self.account(link.user_id));
        let client = self.client(browser, account.as_ref().map(|account| account.id));
        match EmailLink::Start.advance(
            &self.config,
            EmailLinkEvent::Redeem {
                link,
                account,
                client,
            },
            self.now,
            &mut self.rng,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                Ok(step.state)
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }

    pub fn step_up_password(
        &mut self,
        browser: &mut Browser,
        password: &str,
        code: &str,
    ) -> Result<StepUp, Error> {
        let session = self.session_of(browser).ok_or(Error::Unauthorized)?;
        let account = self.account(session.user_id).ok_or(Error::Unauthorized)?;
        let key = latchkey::account::AccountKey::from(&account.email);
        let user = account.id;
        let state = match StepUp::new(account, session).advance(
            &self.config,
            StepUpEvent::Password {
                wrong_passwords: self.throttle.window(&key),
            },
            self.now,
        ) {
            Ok(step) => step.state,
            Err(refusal) => return Err(self.refused(refusal, browser)),
        };
        let stored = self.rows[&user].password.clone();
        let matched = self.hasher.verify(password, stored.as_ref());
        let material = self.material(user);
        let client = self.client(browser, Some(user));
        match state.advance(
            &self.config,
            StepUpEvent::PasswordChecked {
                matched,
                code: code.to_owned(),
                material,
                client,
            },
            self.now,
        ) {
            Ok(step) => {
                self.apply(step.effects, browser)?;
                Ok(step.state)
            }
            Err(refusal) => Err(self.refused(refusal, browser)),
        }
    }
}

pub fn cheap() -> PasswordParams {
    PasswordParams::new(64, 1, 1).unwrap()
}

pub fn mail_kinds(app: &App) -> Vec<latchkey::mail::MailKind> {
    app.mail.iter().map(|mail| mail.kind).collect()
}

pub fn code_of(codes: &[RecoveryCode], index: usize) -> String {
    codes[index].expose_secret().to_owned()
}
