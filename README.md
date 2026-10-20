# latchkey

Sign-in building blocks and sign-in policy for Rust, without I/O.

latchkey hashes passwords, checks TOTP and recovery codes, runs passkey ceremonies, issues
tokens, seals secrets, builds cookies, and decides what a sign-in flow does next. It does
**not** talk to a database, send mail, serve HTTP, read the clock or draw randomness behind
your back. Every function takes values (including `now` and an explicit `CryptoRng`) and
returns values; your app stores what it is told to store, sends what it is told to send and
answers its clients.

It was extracted from an axum sign-in service (latchkey 0.2) and keeps its behaviour and
stored formats: Argon2id (64 MiB, t=3, p=2), TOTP (SHA-1, 6 digits, 30 s, ±1 step) with a
replay guard, single-use recovery codes, passkeys with user verification, `__Host-` cookies,
Origin and CSRF checks, a doubling lockout, a wrong-password throttle, new-device mail and an
audit trail, now as pure functions and state machines.

## What is in it

| Module | What it does |
|---|---|
| `password` | `PasswordHasher`: Argon2id hash/verify, `needs_rehash` for hashes made with other parameters, a dummy hash so unknown accounts cost the same, the 12–1024 character policy |
| `totp` | `TotpSecret` (`from_base32` to import), `enrolment` (base32 + `otpauth://` URL), `verify(secret, code, last_used_step, now) -> Result<TotpStep, TotpRefusal>`, `qr_svg`/`qr_png` |
| `recovery` | `generate(rng) -> RecoveryCodes { codes, hashes }`, `verify(code, unused_hashes) -> Option<RecoveryCodeHash>` |
| `passkey` | `RelyingParty` with `start_*`/`finish_*` for registration, authentication, allow-list and discoverable sign-in; `Ceremony<S>` bound (`Ceremony::binding`) to a session and user, or before sign-in to the browser by a one-off token; 5 minutes |
| `token` | `issue(rng) -> IssuedToken { token, hash }`, `TokenHash::of(presented)`, `TokenHash::of_foreign` for tokens another system issued, constant-time compare |
| `seal` | `DataKey`: AES-256-GCM with associated data per owner and kind, compatible with 0.2's stored values |
| `http` | `SetCookie` (`__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`; a development mode for plain-HTTP localhost), `find_cookie`, `RequestHeaders::check_origin` / `check_session_request`, `client_ip`, `IpTagKey` |
| `account` | `Account`, `Email`, `Factors` (last-factor rules), `LockoutPolicy` and `Lockout` |
| `limits` | `RateLimiter` (fixed windows), `WrongPasswordThrottle` (sliding window), and their per-key states |
| `session` | `Session` records (with their step-up failure count), `Stage`, `SignInMethod`, `Session::authorize(active, Access, step_up_window, now)` |
| `flow` | `sign_in`, `email_link`, `setup`, `invite`, `step_up` as `advance(state, event, now, rng) -> Result<Transition, Refusal>`; `issue_session`, `sign_out` |
| `mail` | `Mail` with `subject()` and `text()` for setup, sign-in link, invite and new-device mail |
| `audit` | `AuditEvent` and `AuditKind` |

### Features

| Feature | Default | Adds | Pulls in |
|---|---|---|---|
| `os-rng` | yes | `latchkey::os_rng()`: a ChaCha12 generator seeded from the OS | `rand` |
| `serde` | no | `Serialize`/`Deserialize` on ids, hashes, accounts, sessions, links, mail and audit events, limiter states | `serde` |
| `passkeys` | no | the `passkey` module, `DataKey::seal_passkey`/`open_passkey`; implies `serde` | `webauthn-rs` (OpenSSL), `serde_json` |
| `qr` | no | `totp::qr_svg` | `qrcodegen` |
| `qr-png` | no | `totp::qr_png` | `qrcodegen-image`, `image` |

Without `passkeys`, nothing links OpenSSL. The flows still accept a passkey result
(`verified: bool`) from any WebAuthn library you prefer.

## How the flows work

Each flow is an enum of states. `advance` consumes the state, takes one event carrying the
facts your app loaded (the account, its factor material, the presented device cookie, a
verification result) and `now`, and returns either

- `Ok(Transition { state, effects })`: the next state and what to do, or
- `Err(Refusal { error, effects })`: the error to answer with **and** what must still be done
  (count the failure, lock the account, write the audit event).

```text
sign_in:    Start -Password-> VerifyPassword -PasswordChecked-> SecondFactor -Code|Passkey-> SignedIn
            Start -PasskeyOnly-> SignedIn
email_link: Start -Request-> Requested            Start -Redeem-> SignedIn
setup:      Start -RequestLink-> LinkRequested    Start -Redeem-> InSetup -PasswordSet-> InSetup -Finish-> Complete
invite:     Start -Send-> Sent
step_up:    Start -Password-> VerifyPassword -PasswordChecked-> Done      Start -Passkey-> Done
```

Password steps are split in two so the throttle and lockout are decided *before* the
expensive hash, and an unknown address still costs a full (dummy) hash.

Effects are values: `StoreSession { session, replaces }`, `DeleteSession`, `SetCookie`,
`RecordFailure`, `ClearFailures`, `RecordWrongPassword`, `UseTotpStep`, `UseRecoveryCode`, `StoreRecoveryCodes`,
`StoreLinkToken`, `SendMail`, `Audit`, `RememberDevice`, `CreateAccount`, `StorePassword`,
`ActivateAccount`, `MarkStepUp`, and with per-session step-up failures `RecordStepUpFailure`
and `ClearStepUpFailures`. Carry out every one, in order: storage effects ideally in one
transaction, then mail. `UseTotpStep` and `UseRecoveryCode` are compare-and-set: if the stored
step is already as new, or the code already used, the request lost a race and must be refused.
`RecordFailure` must be **one atomic statement** that increments the stored count
(`UPDATE users SET failures = failures + 1 WHERE id = ? RETURNING failures`), never a value
computed from the `Account` snapshot, so failures that race are all counted; then store
`config.lockout().locked_until(n, at)` and append `config.lockout().lockout_event(user, n, at,
ip_tag)` when they are `Some`. `ClearFailures` resets the count and the lock.

### Where wrong step-up guesses count

By default (`StepUpFailures::AccountLockout`) a wrong password or code at step-up counts like
a sign-in failure: towards the account lockout and the wrong-password throttle, and a locked
account cannot step up. That lets anyone holding a stolen session cookie lock the real owner
out, and lets anonymous sign-in guesses stop a signed-in owner from re-verifying. To count
them per session instead:

```rust
use latchkey::{Config, Error, StepUpFailures};

fn config() -> Result<Config, Error> {
    Config::builder("owner@example.com", "https://home.example.com")
        .step_up_failures(StepUpFailures::PerSession { limit: 5 })
        .build()
}
assert!(config().is_ok());
```

Then step-up neither consults nor feeds the lockout and throttle. Each wrong guess emits
`RecordStepUpFailure { token_hash }`: increment `sessions.step_up_failures` atomically in the
same transaction (`UPDATE sessions SET step_up_failures = step_up_failures + 1 WHERE
token_hash = ? RETURNING step_up_failures`). Load that column into `Session::step_up_failures`
when you rebuild the session. The guess that reaches `limit` also emits `DeleteSession`, a
cookie removal and a `session_revoked` audit event (detail `step_up_failures`), and the
refusal is `Error::SessionEnded` (`session_ended`, 401): sign in again. A session whose stored
count already reached the limit (guesses that raced) is refused and ended the same way on its
next step-up; to end it at once, check `config.step_up_failures().ends_session(n)` on the
count the increment returned. A successful step-up emits `ClearStepUpFailures` and still
`ClearFailures`, so a full proof lifts an account lock. A passkey that fails to verify is not
counted in either mode.

### Accounts with only a password

latchkey asks for a second factor after every password, and setup does not finish without
one. Accounts imported from another system with only a password, or apps that let users
enrol TOTP or a passkey later, can opt in:

```rust
use latchkey::{Config, Error, PasswordOnly};

fn config() -> Result<Config, Error> {
    Config::builder("owner@example.com", "https://home.example.com")
        .password_only(PasswordOnly::AllowedUntilEnrolled)
        .build()
}
assert!(config().is_ok());
```

Then an account with a password and no second factor signs in with the password alone
(`SignIn::VerifyPassword` goes straight to `SignedIn`, method `password_only`), steps up with
it, finishes setup and gets `issue_session`. As soon as the account has TOTP or a passkey,
that factor is required again; `Factors::password_suffices(config.password_only())` says
which case applies.

### Passkey sign-in before a session exists

Registration, a passkey second factor and step-up run inside a session, and their
ceremonies are bound to it (`Binding::Session`, finished with `into_state(session.id, user,
now)`). A passkey sign-in has no session yet: `RelyingParty::start_sign_in(user, passkeys,
now, rng)` (the user typed their address; the challenge lists their passkeys) and
`start_discoverable(now, rng)` return a third value, a one-off binding token. The ceremony
keeps only its hash (`Binding::Browser`).

```rust
#[cfg(feature = "passkeys")]
mod passkey_sign_in {
    use latchkey::http::{SetCookie, find_cookie};
    use latchkey::passkey::webauthn_rs::prelude::{
        AuthenticationResult, Passkey, PasskeyAuthentication, PublicKeyCredential,
        RequestChallengeResponse,
    };
    use latchkey::passkey::{CEREMONY_TTL, Ceremony, RelyingParty};
    use latchkey::{Config, CryptoRng, Error, UserId};
    use time::OffsetDateTime;

    /// POST /sign-in/passkey/start {email}: store the ceremony under `ceremony.id()`, answer
    /// with the challenge and that id, and send the cookie.
    pub fn start(
        config: &Config,
        rp: &RelyingParty,
        user: UserId,
        passkeys: &[Passkey],
        now: OffsetDateTime,
        rng: &mut impl CryptoRng,
    ) -> Result<(RequestChallengeResponse, Ceremony<PasskeyAuthentication>, SetCookie), Error> {
        let (challenge, ceremony, binding) = rp.start_sign_in(user, passkeys, now, rng)?;
        let cookie = SetCookie::new(config.ceremony_cookie_name().clone(), &binding, CEREMONY_TTL);
        Ok((challenge, ceremony, cookie))
    }

    /// POST /sign-in/passkey/finish {ceremony_id, credential}: `ceremony` is the one the app
    /// removed from storage by the posted id. Then `passkey::record_use` on the passkeys of
    /// the returned user, and `SignInEvent::PasskeyOnly { account, verified, client }`.
    pub fn finish(
        config: &Config,
        rp: &RelyingParty,
        ceremony: Ceremony<PasskeyAuthentication>,
        cookie_headers: &[&str],
        credential: &PublicKeyCredential,
        now: OffsetDateTime,
    ) -> Result<(UserId, AuthenticationResult), Error> {
        let user = ceremony.binding().user().ok_or(Error::SignInFailed)?;
        let name = config.ceremony_cookie_name().as_str();
        let binding = find_cookie(cookie_headers.iter().copied(), name).unwrap_or_default();
        let state = ceremony.into_browser_state(binding, now)?;
        Ok((user, rp.finish_authentication(credential, &state)?))
    }
}
```

Only the browser holding the cookie can finish the ceremony it started.

### Plain-HTTP development on localhost

Cookies are `__Host-` and `Secure`. Chrome and Firefox keep such cookies on
`http://localhost`, Safari does not. For local development over plain HTTP:

```rust
use latchkey::{Config, Error};

fn development_config() -> Result<Config, Error> {
    Config::builder("owner@example.com", "http://localhost:3000")
        .danger_insecure_localhost_cookies()
        .build()
}
let config = development_config();
assert_eq!(config.map(|c| c.cookie_name().to_string()), Ok("latchkey".into())); // no __Host-
```

`build` refuses this for any origin other than `http://localhost`, `http://127.0.0.1` or
`http://[::1]`, and a production origin must be `https`, so it cannot reach production by
accident. Read cookies by `config.cookie_name().as_str()`, not a hard-coded name.

## Example: password + TOTP with your own storage

A condensed version of `examples/password_totp.rs` (`cargo run --example password_totp`).
Storage is a `HashMap` here; use whatever you like.

```rust
use std::collections::HashMap;

use latchkey::account::{AccountKey, Lockout};
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::{Client, CodeMaterial, Effect, TotpMaterial};
use latchkey::limits::WrongPasswordThrottle;
use latchkey::password::{PasswordHash, PasswordHasher};
use latchkey::recovery::RecoveryCodeHash;
use latchkey::seal::DataKey;
use latchkey::session::Session;
use latchkey::token::TokenHash;
use latchkey::totp::TotpStep;
use latchkey::{Account, Config, CryptoRng, Email, Error, UserId};
use time::OffsetDateTime;

/// An account as the app stores it: a database row in a real app.
struct Row {
    account: Account,
    password: PasswordHash,
    sealed_totp: Vec<u8>,
    last_step: Option<TotpStep>,
    recovery: Vec<(RecoveryCodeHash, bool)>,
}

/// Built once at start-up.
struct App {
    config: Config,                  // Config::builder(owner, origin).build()?
    hasher: PasswordHasher,          // PasswordHasher::new(config.password_params(), &mut rng)?
    data_key: DataKey,               // DataKey::new(&keys.data), kept out of the database
    throttle: WrongPasswordThrottle, // WrongPasswordThrottle::new(config.rate_limits())
    users: HashMap<UserId, Row>,
    sessions: HashMap<TokenHash, Session>,
}

impl App {
    /// POST /sign-in {email, password}
    fn sign_in(
        &mut self,
        email: &str,
        password: &str,
        client: Client,
        now: OffsetDateTime,
        rng: &mut impl CryptoRng,
    ) -> Result<(), Error> {
        let address = Email::parse(email).ok();
        let row = self.users.values().find(|row| Some(&row.account.email) == address.as_ref());
        let event = SignInEvent::Password {
            login: email.to_owned(),
            account: row.map(|row| row.account.clone()),
            wrong_passwords: self.throttle.window(&AccountKey::from_login(email)),
        };
        // Throttled or locked: refused before any hashing.
        let step = SignIn::Start
            .advance(&self.config, event, now, rng)
            .map_err(|refusal| refusal.error)?;
        // On a blocking thread in a server. An unknown address (None) still costs a hash.
        let matched = self.hasher.verify(password, row.map(|row| &row.password));
        let event = SignInEvent::PasswordChecked { matched, client };
        match step.state.advance(&self.config, event, now, rng) {
            Ok(step) => self.apply(step.effects, now), // reply with the new session's CSRF token
            Err(refusal) => {
                self.apply(refusal.effects, now)?;
                Err(refusal.error)
            }
        }
    }

    /// POST /sign-in/code {code}, with the second-factor session's cookie
    fn code(
        &mut self,
        cookie: &str,
        code: String,
        client: Client,
        now: OffsetDateTime,
        rng: &mut impl CryptoRng,
    ) -> Result<(), Error> {
        let hash = TokenHash::of(cookie).ok_or(Error::Unauthorized)?;
        let session = self.sessions.get(&hash).cloned().ok_or(Error::Unauthorized)?;
        let row = self.users.get(&session.user_id).ok_or(Error::Unauthorized)?;
        let material = CodeMaterial {
            totp: Some(TotpMaterial {
                secret: self.data_key.open_totp(row.account.id, &row.sealed_totp)?,
                last_used_step: row.last_step,
            }),
            recovery_codes: row.recovery.iter().filter(|(_, used)| !used).map(|(h, _)| *h).collect(),
        };
        let event = SignInEvent::Code { code, material, client };
        match SignIn::second_factor(session, row.account.clone()).advance(&self.config, event, now, rng) {
            Ok(step) => self.apply(step.effects, now), // a full session replaces the pending one
            Err(refusal) => {
                self.apply(refusal.effects, now)?;
                Err(refusal.error)
            }
        }
    }

    /// Carries out every effect, in order: storage in one transaction, then mail.
    fn apply(&mut self, effects: Vec<Effect>, now: OffsetDateTime) -> Result<(), Error> {
        for effect in effects {
            match effect {
                Effect::StoreSession { session, replaces } => {
                    if let Some(old) = replaces {
                        self.sessions.remove(&old);
                    }
                    self.sessions.insert(session.token_hash, session);
                }
                Effect::SetCookie(cookie) => {
                    let _header = cookie.header_value(); // add to the response
                }
                Effect::RecordFailure { user_id, at, ip_tag } => {
                    // In SQL, one statement:
                    // UPDATE users SET failures = failures + 1 WHERE id = ? RETURNING failures
                    let row = self.users.get_mut(&user_id).ok_or(Error::NotFound)?;
                    let n = row.account.lockout.failures.saturating_add(1);
                    row.account.lockout.failures = n;
                    if let Some(until) = self.config.lockout().locked_until(n, at) {
                        row.account.lockout.locked_until = Some(until);
                    }
                    let _lock = self.config.lockout().lockout_event(user_id, n, at, ip_tag); // append if Some
                }
                Effect::ClearFailures { user_id } => {
                    let row = self.users.get_mut(&user_id).ok_or(Error::NotFound)?;
                    row.account.lockout = Lockout::default();
                }
                Effect::RecordWrongPassword { key } => self.throttle.record(&key, now),
                Effect::UseTotpStep { user_id, step } => {
                    // Compare-and-set: UPDATE ... SET last_step = ?
                    //   WHERE user_id = ? AND (last_step IS NULL OR last_step < ?)
                    let row = self.users.get_mut(&user_id).ok_or(Error::SignInFailed)?;
                    if row.last_step.is_some_and(|last| last >= step) {
                        return Err(Error::SignInFailed); // the code raced another request
                    }
                    row.last_step = Some(step);
                }
                Effect::UseRecoveryCode { user_id, hash } => {
                    let row = self.users.get_mut(&user_id).ok_or(Error::SignInFailed)?;
                    let code = row.recovery.iter_mut().find(|(h, used)| *h == hash && !used);
                    code.ok_or(Error::SignInFailed)?.1 = true;
                }
                Effect::SendMail(_mail) => { /* after commit: mail.to, mail.subject(), mail.text() */ }
                Effect::Audit(_event) => { /* append */ }
                // RememberDevice, RecordStepUpFailure and the effects of the other flows: see
                // the documentation of `Effect`.
                _ => {}
            }
        }
        Ok(())
    }
}
```

`examples/email_link.rs` and `examples/passkey_registration.rs` (feature `passkeys`) show
the other two common paths.

## Porting from 0.2

latchkey 0.2 was a service: an axum router, extractors, a SQLite store, a mailer and
in-memory limiters. 0.3 keeps the decisions and leaves the I/O to the app.

| 0.2 | What the app does with 0.3 |
|---|---|
| `Latchkey::new(config, store, mailer)` | Build a `Config` with `Config::builder`, a `PasswordHasher`, a `DataKey` and an `IpTagKey`; create the owner with `NewAccount::owner` if your table has none |
| `Config` public fields, `Config::new` | `Config::builder(owner_email, origin)` with setters; keys left `Config` (`DataKey::new`, `IpTagKey::new`, `seal::check_keys`) |
| `Latchkey::router()` and its endpoints | Your own routes; each calls a flow's `advance` (table below) |
| `Store` trait, `SqliteStore`, migrations | Your schema. 0.2's tables map one to one: users (`Account` + password hash), sessions (`Session`), tokens (`LinkToken` under `TokenHash`), totp (sealed secret, pending secret, `TotpStep`), passkeys (sealed JSON), recovery codes (`RecoveryCodeHash` + used flag), devices (`TokenHash` + last seen), audit (`AuditEvent`). Stored values (Argon2 PHC strings, SHA-256 hashes, `lk1` sealed values, stage/method/kind names, IP HMACs) are unchanged |
| Atomic store methods (`consume_token`, `use_totp_step`, `use_recovery_code`, `replace_session`, `add_failure`) | `DELETE ... RETURNING` for links; compare-and-set for `UseTotpStep`/`UseRecoveryCode`; one transaction for `StoreSession { replaces }`; `RecordFailure` as one atomic `failures = failures + 1` statement, then `LockoutPolicy::locked_until` on the returned count |
| `Mailer` trait, `TestMailer`, background sending | `Effect::SendMail(Mail)`; `Mail::subject()`/`text()` are unchanged; send after commit, retry if you like; `Mail::link_token()` for tests |
| `CurrentUser`, `RecentAuth` extractors | Look the session up by `TokenHash::of(find_cookie(...))`, then `session.authorize(account.active, Access::SignedIn / Access::Recent, config.step_up_window(), now)` and, for unsafe methods, `RequestHeaders::check_session_request(&config.origin_string(), &session.csrf_token)` |
| Router-wide Origin check | `RequestHeaders::check_origin` on every unsafe request |
| `CSRF_HEADER` | `http::CSRF_HEADER` |
| `Latchkey::issue_session` | `flow::issue_session(config, account, AppMethod::new("...")?, client, now, rng)` |
| `Latchkey::session_from_cookie`, `current_user_from_headers` | `TokenHash::of` + your session lookup + `Session::authorize` |
| `IssueSession::from_headers` | `http::client_ip`, `http::truncate_user_agent`, `http::find_cookie` into a `flow::Client` |
| In-memory rate limiter and wrong-password log | `limits::RateLimiter` and `limits::WrongPasswordThrottle`, owned by the app (a `Mutex`), or their per-key states persisted |
| In-memory passkey ceremonies | `passkey::Ceremony<S>` is `Serialize`: store it under `ceremony.id()`, remove it on finish, then `into_state(session, user, now)`, or for a sign-in `into_browser_state(binding_cookie, now)` |
| `Clock`, `ManualClock`, `SystemClock` | Pass `now` (`OffsetDateTime::now_utc()` in production, any value in tests) |
| `Latchkey::encrypt_plaintext_secrets` | `seal::classify_bytes`/`classify_text` find 0.1 plaintext; reseal with `DataKey::seal_bytes`/`seal_text` and `Aad::totp`/`Aad::passkey` |
| Start-up check of sealed values | Open each stored value with `DataKey::open_totp`/`open_text` at start if you want the same refusal |
| `Latchkey::reset_owner` | Delete the owner's password, factors and sessions, set it inactive, append `AuditKind::OwnerReset` |
| `Latchkey::purge_expired` | Delete sessions and links past `expires_at`, devices unseen for `config.device_ttl()` |
| `Error` with `IntoResponse` | `Error::code()`, `Error::http_status()`, `Error::detail()`, `Error::retry_after_secs()`; build the JSON body yourself |
| `async_trait`, `tokio`, `axum`, `sqlx`, `tracing` dependencies | Gone. Run `PasswordHasher` on a blocking thread with a semaphore of one, as 0.2 did |

Endpoints to flow calls:

| 0.2 endpoint | 0.3 |
|---|---|
| `POST /setup/start`, `/setup/redeem`, `/setup/password`, `/setup/complete` | `Setup`: `RequestLink`, `Redeem { kind: Setup }`, `PasswordSet`, `Finish` |
| `POST /invites`, `/invites/redeem` | `Invite::Send`, then `Setup` with `Redeem { kind: Invite }` |
| `POST /sign-in/password`, `/sign-in/code`, `/sign-in/second-factor/passkey/*`, `/sign-in/passkey/*` | `SignIn`: `Password` + `PasswordChecked`, `Code`, `Passkey`, `PasskeyOnly` |
| `POST /sign-in/email`, `/sign-in/email/redeem` | `EmailLink`: `Request`, `Redeem` |
| `POST /step-up/password`, `/step-up/passkey/*` | `StepUp`: `Password` + `PasswordChecked`, `Passkey` |
| `POST /sign-out` | `flow::sign_out` |
| `POST /password`, `/recovery-codes` | `flow::password_changed`, `flow::regenerate_recovery_codes` (after `Access::Recent`) |
| `POST /totp/enrol`, `/totp/confirm`, `DELETE /totp` | `TotpSecret::random` + `totp::enrolment` + `DataKey::seal_totp`; `totp::verify(pending, code, None, now)`; `Factors::may_remove_totp` (after `Access::Enrolling`/`Recent`) |
| `/passkeys/register/*`, `DELETE /passkeys/{id}` | `RelyingParty::start_registration`/`finish_registration`; `Factors::may_remove_passkey` |
| `GET /me`, `/sessions`, `DELETE /sessions/{id}`, `GET /audit` | Your queries; `Session::step_up_until` for `step_up_until` |

Behavioural changes: `step_up` joins the reserved method names for app-issued sessions;
`RelyingParty::finish_discoverable` takes the claimed user and refuses an assertion whose
user handle differs; the device cookie is still set on every completed sign-in.

## Security notes

- Passwords: Argon2id; an unknown account verifies against a dummy hash and fails the same
  way as a wrong password. Passwords over 4096 bytes are not hashed as given.
- Tokens (sessions, links, devices, CSRF) are 32 random bytes; only SHA-256 hashes are
  stored, except the session's CSRF token, which the client needs again. Comparisons of
  presented secrets are constant-time.
- A TOTP step is accepted once (`last_used_step`); recovery codes, links and passkey
  ceremonies are single use; passkey ceremonies are bound to the session and account that
  started them (a sign-in, which has no session yet, to the browser by a one-off cookie) and
  expire after 5 minutes; counter regressions are rejected by webauthn-rs.
- Every stage change issues a new session token (`StoreSession { replaces }`).
- The wrong-password throttle (10 per 15 minutes per address) counts unknown addresses too and
  is checked before hashing; the lockout (5 failures: 5 minutes, doubling to an hour) is
  per account. Step-up guesses count towards both unless `Config::step_up_failures` is
  `PerSession { limit }`, which bounds each session to `limit` wrong guesses and then ends it.
- Sealed values use a random 96-bit nonce and associated data `latchkey-totp:<user>` or
  `latchkey-passkey:<user>:<passkey>`; `Aad::app(context)` is for the app's own secrets.
- Secret types (`SecretToken`, `TotpSecret`, `RecoveryCode`, `PasswordHash`, `SetCookie`,
  `DataKey`, `IpTagKey`, `Mail` links) redact `Debug`, have no `Display`, and zero their
  memory on drop where they own it.
- No `unsafe`; `unwrap`, `expect`, `panic!` and indexing are denied outside tests.
- Randomness comes from the `CryptoRng` you pass, except webauthn-rs challenges, which it
  draws from OpenSSL.

Known trade-offs carried over from 0.2: a locked account answers `too_many_attempts`, which
tells someone who already made 5 wrong guesses that the address exists; the new-device check is
per browser profile; anyone with both the database and the data key can read factors.

## Testing

`cargo test --all-features` runs unit tests, property tests (`proptest`: token and cookie
parsing, the limiter against a fixed-window model, the throttle against a sliding-window
model, the lockout, TOTP replay, sealing) and integration tests that drive every flow through
an in-memory app (`tests/common`), including a software passkey.

`fuzz/` has a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target,
`untrusted_inputs`, that feeds arbitrary bytes to every parser of client input. It builds on
stable (`cargo build --manifest-path fuzz/Cargo.toml`); running it needs nightly:
`cargo +nightly fuzz run untrusted_inputs`.

The minimum supported Rust version is 1.88.

## For coding agents

The crate ships [Symposium](https://symposium.dev) skills in `skills/`: `latchkey-basics`
(how to use it correctly) and `latchkey-porting` (moving from 0.2). With the `cargo agents`
CLI, `cargo agents use latchkey` in a project that depends on latchkey installs them.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
