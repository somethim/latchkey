# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
[0.2.0-dev]: https://github.com/somethim/latchkey/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/somethim/latchkey/releases/tag/v0.1.0
