# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `StepUpFailures` (`flow::step_up`, re-exported at the root) and
  `ConfigBuilder::step_up_failures` / `Config::step_up_failures`: with
  `StepUpFailures::PerSession { limit }`, wrong step-up guesses count against the session
  instead of the account. Step-up then neither checks nor feeds the account lockout and the
  wrong-password throttle, and the guess that reaches `limit` ends the session. The default,
  `StepUpFailures::AccountLockout`, keeps the old behaviour.
- `Session::step_up_failures`, the per-session count the app stores and loads (`serde`
  defaults it to 0).
- `Effect::RecordStepUpFailure` (an atomic increment of the session's count) and
  `Effect::ClearStepUpFailures`, emitted only in per-session mode.
- `Error::SessionEnded` (`session_ended`, 401) for the step-up that ends its session.
- `StepUpFailures::ends_session(n)` for apps that end the session from the count their
  increment returned.
- `PasswordOnly` (`account`, re-exported at the root) and `ConfigBuilder::password_only` /
  `Config::password_only`: with `PasswordOnly::AllowedUntilEnrolled`, an account with a
  password and no second factor (imported, or not enrolled yet) finishes sign-in, step-up,
  setup and `issue_session` with its password alone. A sign-in that way records the new
  method `SignInMethod::PasswordOnly` (`password_only`). Once the account enrols TOTP or a
  passkey the second factor is required again. The default, `PasswordOnly::Refused`, keeps
  the old behaviour.
- `Factors::has_second_factor`, `Factors::are_sufficient(policy)` and
  `Factors::password_suffices(policy)`.
- `passkey::Binding` and `Ceremony::binding()`: what a ceremony is bound to, with
  `Binding::user()` naming the account whose passkeys to load before finishing.
- `RelyingParty::start_sign_in(user, passkeys, now, rng)`: a passkey sign-in with an
  allow-list before any session exists. It and `start_discoverable` bind their ceremony to
  the browser with a one-off binding token (returned as a `SecretToken`; the ceremony keeps
  only its hash), finished with `Ceremony::into_browser_state(binding_token, now)`.
- `ConfigBuilder::ceremony_cookie_name` / `Config::ceremony_cookie_name` (default
  `__Host-latchkey_ceremony`) for the binding token's cookie.
- `TokenHash::of_foreign` hashes tokens latchkey did not issue (22 to 512 bytes of
  printable ASCII, `token::FOREIGN_MIN_LEN` / `FOREIGN_MAX_LEN`) the same way as its own, for
  porting sessions, links or API keys from another system; its documentation says which
  stored forms carry over.
- `ConfigBuilder::danger_insecure_localhost_cookies` for plain-HTTP development: cookie
  names lose their `__Host-` prefix and cookies are sent without `Secure`. `build` refuses
  it unless the origin is `http://localhost`, `http://127.0.0.1` or `http://[::1]`.
  `Config::insecure_localhost_cookies` and `CookieName::is_secure` report it.
- `PasswordHasher::needs_rehash(stored)`: whether a stored hash was made with another
  algorithm, Argon2 version, cost or output length than the hasher's, for upgrading hashes
  after a successful `verify`.
- `TotpSecret::from_base32` and `totp::MIN_SECRET_BYTES` for importing TOTP secrets another
  system enrolled (80-bit secrets are refused: those accounts enrol again).

### Changed

- `Session` has a new public field, `step_up_failures`; code that builds a `Session` with a
  struct literal must set it (0 when step-up failures count against the account).
- `AuditKind::SessionRevoked` also records a session ended by the step-up limit, with detail
  `step_up_failures`.
- `Ceremony::into_state(session, user, now)` takes the session and account instead of
  `Option`s and only finishes session-bound ceremonies; `RelyingParty::start_discoverable`
  also returns the binding token, and its ceremony is finished with `into_browser_state`.
  Ceremonies stored by earlier 0.3.0-dev builds no longer deserialize (they expire after 5
  minutes anyway).
- `SignInEvent::DiscoverablePasskey` also reports allow-list passkey sign-ins
  (`SignInMethod::Passkey`).
- `ConfigBuilder::build` refuses any two equal cookie names (`Error::Config("cookie names
  must differ")`).
- An `http://127.0.0.1` or `http://[::1]` origin is accepted like `http://localhost`.
- `password_only` is reserved like latchkey's other method names: `AppMethod::new` refuses
  it, and a stored `password_only` parses as `SignInMethod::PasswordOnly`.

## [0.3.0-dev]

latchkey is now a sans-IO library: building blocks and sign-in policy as pure functions and
state machines. The app owns storage, mail, HTTP, the clock and the random number generator.
See "Porting from 0.2" in the README.

### Added

- `flow`: setup, invite, sign-in, email-link and step-up flows as enums with
  `advance(self, config, event, now, rng) -> Result<Transition<_>, Refusal>`, where
  `Transition` and `Refusal` carry `Effect` values for the app to carry out (store a session,
  set a cookie, count a failure as an atomic increment (`RecordFailure`, with
  `LockoutPolicy::locked_until` and `LockoutPolicy::lockout_event` for the lock that follows)
  or clear failures, record a wrong password, use a TOTP step or recovery code,
  store a link, send a mail, write an audit event, remember a device, create or activate an
  account, store a password, mark a step-up). `issue_session`, `sign_out`,
  `password_changed`, `regenerate_recovery_codes` and `check_code` as plain functions.
- `password::PasswordHasher` with an explicit RNG for salts, `PasswordParams::new` (validated)
  and `PasswordHash` (parsed PHC string).
- `totp::verify(secret, code, last_used_step, now) -> Result<TotpStep, TotpRefusal>`,
  `TotpSecret`, `TotpStep`, `totp::enrolment`, and `totp::qr_svg` / `totp::qr_png` behind the
  `qr` / `qr-png` features.
- `recovery::generate(rng) -> RecoveryCodes { codes, hashes }` and
  `recovery::verify(code, unused) -> Option<RecoveryCodeHash>`.
- `passkey::RelyingParty` with two-step registration, authentication and discoverable
  ceremonies; `passkey::Ceremony<S>`, serialisable, bound to a session and account and
  expiring after 5 minutes; `passkey::record_use`; behind the `passkeys` feature.
- `token`: `issue(rng) -> IssuedToken { token, hash }`, `TokenHash`, `SecretToken`, `ct_eq`.
- `seal::DataKey` with `seal_totp`/`open_totp`, `seal_passkey`/`open_passkey`, `Aad::app` for
  the app's own secrets, and `seal::check_keys`.
- `http`: `CookieName`, `SetCookie`, `find_cookie`, `RequestHeaders::check_origin` and
  `check_session_request`, `client_ip`, `truncate_user_agent`, `IpTagKey` and `IpTag`.
- `limits`: `RateLimiter`, `FixedWindow`, `FailureWindow` and `WrongPasswordThrottle` as state
  owned by the app.
- `session`: `Session`, `Stage`, `SignInMethod`, `AppMethod`, `Access` and
  `Session::authorize`, `Session::step_up_until`, `session::is_recent`.
- `account`: `Account`, `NewAccount`, `Email`, `AccountKey`, `Role`, `Factors` (with the
  last-factor rules), `Lockout` and `LockoutPolicy`.
- Id newtypes `UserId`, `SessionId`, `PasskeyId`, `CeremonyId`.
- `Config::builder` with validation; `Error::code`, `http_status`, `detail` and
  `retry_after_secs`.
- Cargo features `os-rng` (default; `latchkey::os_rng()`), `serde`, `passkeys`, `qr` and
  `qr-png`.
- Examples `password_totp`, `email_link` and `passkey_registration`.
- Symposium agent skills `latchkey-basics` and `latchkey-porting` in `skills/`.
- `deny.toml` and a GitHub Actions workflow.

### Changed

- Every function that needs the time takes `now`; every function that needs randomness takes
  a `CryptoRng` (webauthn-rs still draws its own challenges from OpenSSL).
- Secrets are newtypes with redacted `Debug`, no `Display`, zeroed on drop.
- `step_up` is reserved, like latchkey's other method names, for app-issued sessions.
- Discoverable passkey sign-in checks that the assertion's user handle is the account whose
  passkeys were loaded.
- The fuzz target is now `untrusted_inputs`, over every parser of client input.
- The minimum supported Rust version is 1.88, tested in CI.

### Removed

- The axum router, the `CurrentUser` and `RecentAuth` extractors, `Latchkey` and
  `IssueSession`/`IssuedSession`/`IssuedCookie`.
- The `Store` trait, `SqliteStore` and its migrations.
- The `Mailer` trait, `TestMailer` and background mail sending.
- `Clock`, `SystemClock` and `ManualClock`.
- In-memory global state (rate limiter, wrong-password log, passkey ceremonies).
- `Latchkey::encrypt_plaintext_secrets`, `reset_owner` and `purge_expired` (now app code over
  the `seal`, `audit` and record types).
- The dependencies `axum`, `sqlx`, `tokio`, `async-trait` and `tracing`.

## [0.2.0-dev]

### Added

- TOTP secrets (confirmed and pending) and passkey data are encrypted at rest with AES-256-GCM
  under a new `Config::data_key`, separate from `secret_key`, with associated data binding each
  value to its account and kind. `Latchkey::new` refuses to start on plaintext values or values
  that do not decrypt with the configured key.
- `Latchkey::encrypt_plaintext_secrets` encrypts the plaintext values left by 0.1, once and
  explicitly.
- New-device mail: a long-lived `__Host-latchkey_device` cookie (random, stored as SHA-256 per
  account) and a `MailKind::NewDevice` mail with `SignInDetails` when a sign-in completes on a
  device the account has not used, plus a `new_device` audit event. New `Config` fields
  `device_cookie_name`, `device_ttl` and `sessions_url`; a `latchkey_devices` table
  (store migration 2).
- A wrong-password throttle of 10 per account in any 15 minutes, for sign-in and step-up,
  in addition to the lockout and applied to unknown addresses alike
  (`RateLimits::wrong_passwords_per_account`, `RateLimits::wrong_password_window`).
- Property tests (`proptest`) for token and cookie parsing, the rate limiter, the
  wrong-password window, encryption and request bodies, and a cargo-fuzz target
  `json_bodies` in `fuzz/` behind the internal `fuzzing` feature.
- `Latchkey::issue_session(user_id, IssueSession)` starts a full session for a sign-in the app
  completed itself (such as a desktop hand-off from a signed-in browser), with the same token
  format, storage, IP HMAC, step-up window, `sign_in` audit event and new-device mail as a
  normal sign-in. It refuses locked accounts and accounts that have not finished setup, and
  methods that are latchkey's own. It returns an `IssuedSession` with the CSRF token and both
  cookies as `IssuedCookie` values with ready `Set-Cookie` headers.
- `Latchkey::session_from_cookie` and `Latchkey::current_user_from_headers` to verify a session
  outside the extractors, and `CurrentUser::csrf_token` and `CurrentUser::csrf_matches`.

### Changed

- `Config::new` takes the data key as a fourth argument, and `Config`'s `Debug` output hides
  both keys.
- `Mail::expires_at` is an `Option` (notifications do not expire) and `Mail` has a `sign_in`
  field.
- `Store` has new required methods: `all_totp`, `set_totp_secrets`, `all_passkeys`,
  `set_passkey_data`, `remember_device` and `purge_devices`.
- A stored passkey that does not decrypt or parse is an error instead of being skipped.
- `Latchkey::purge_expired` also deletes devices unused for `device_ttl`.
- The example keeps its database in memory, since it makes fresh keys on every run.

## [0.1.0]

### Added

- Password sign-in (Argon2id) that always asks for a second factor: TOTP, passkey or recovery code.
- Passkey sign-in with discoverable credentials and required user verification.
- Email sign-in links: single use, 15 minutes, sign in directly.
- TOTP enrolment and verification with a replay guard on the time step.
- Ten single-use recovery codes stored as SHA-256 hashes, with regeneration.
- First-open owner setup from a configured email address, and owner invites for family members.
- Sessions with `__Host-` cookies, rotation on every stage change, listing and revocation.
- CSRF token header and Origin check on unsafe methods.
- Step-up re-authentication with a 5-minute window, and the `CurrentUser` and `RecentAuth`
  extractors for app routes.
- Per-IP and per-account rate limits and a doubling account lockout.
- Append-only audit log with HMAC-tagged client IPs.
- `Store` trait with a SQLite implementation and its own migration table.
- `Mailer` trait and an in-memory `TestMailer`.

[Unreleased]: https://github.com/somethim/latchkey/compare/v0.1.0...HEAD
[0.3.0-dev]: https://github.com/somethim/latchkey/compare/v0.1.0...HEAD
[0.2.0-dev]: https://github.com/somethim/latchkey/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/somethim/latchkey/releases/tag/v0.1.0
