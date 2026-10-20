# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
[0.1.0]: https://github.com/somethim/latchkey/releases/tag/v0.1.0
