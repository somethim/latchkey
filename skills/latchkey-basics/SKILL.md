---
name: latchkey-basics
description: How to use the latchkey crate (sans-IO sign-in building blocks and policy for Rust) correctly. Use when writing or reviewing code that calls latchkey for passwords, TOTP, recovery codes, passkeys, session tokens, cookies, CSRF, lockout, rate limits, or its sign-in, setup, invite, email-link and step-up flows.
---

# Using latchkey

latchkey does no I/O. It returns values; the app stores, sends and answers. Getting the
app side right is what keeps sign-in secure.

## Inputs

- Pass `now: OffsetDateTime` to everything that asks (`OffsetDateTime::now_utc()` in
  production). Never cache one `now` across requests.
- Pass a `CryptoRng` (`latchkey::os_rng()?` with the default `os-rng` feature, or another
  CSPRNG). Never a seeded test RNG in production.
- Build `Config` once with `Config::builder(owner_email, origin).build()?`.

## Storage

- Store only hashes of tokens: `token::issue(rng)` gives `{ token, hash }`; the client gets
  `token`, the database gets `hash`. Look tokens up with `TokenHash::of(presented)`.
- Store recovery codes as `RecoveryCodeHash`es; show `RecoveryCodes::codes` once.
- Seal TOTP secrets and passkeys with `DataKey` (`seal_totp`, `seal_passkey`). The data key
  must differ from the IP-tag key (`seal::check_keys`) and live outside the database.
- Persist the TOTP last-used step. `Effect::UseTotpStep` and `Effect::UseRecoveryCode` are
  compare-and-set: update only if newer / unused, and refuse the request if the update
  touched no row.
- Apply `Effect::RecordFailure` as one atomic statement
  (`UPDATE ... SET failures = failures + 1 ... RETURNING failures`), never by writing a count
  computed from the `Account` snapshot; then set `locked_until` from
  `config.lockout().locked_until(n, at)` and append `config.lockout().lockout_event(..)` when
  `Some`. `Effect::ClearFailures` resets both.
- Step-up guesses count towards the account lockout unless the config sets
  `step_up_failures(StepUpFailures::PerSession { limit })`. Then store a
  `step_up_failures` count on each session row, load it into `Session::step_up_failures`, apply
  `Effect::RecordStepUpFailure` as an atomic `step_up_failures = step_up_failures + 1` in the
  same transaction, `Effect::ClearStepUpFailures` as a reset, and the `DeleteSession` that
  follows at the limit; answer `Error::SessionEnded` by sending the user to sign in again.
  Pass `FailureWindow::default()` as `wrong_passwords` in that mode: it is not consulted.
- Accounts with only a password (imported, or not enrolled yet) cannot sign in unless the
  config sets `password_only(PasswordOnly::AllowedUntilEnrolled)`. Then a matching password
  signs such an account in directly (`SignIn::SignedIn`, method `password_only`); enrolling
  TOTP or a passkey makes the second factor required again. Do not fake a second factor.
- Redeem links atomically (`DELETE ... RETURNING`), then pass the deleted `LinkToken` (or
  `None`) to the flow.

## Flows

- `advance` returns `Ok(Transition { state, effects })` or `Err(Refusal { error, effects })`.
  Carry out **every** effect in both cases, in order (storage in one transaction, then mail):
  refusals count failures, lock accounts and write the audit log. Mail and audit effects are
  not optional.
- Password flows have two steps. Send the `Password` event first; only if it returns
  `VerifyPassword` run `PasswordHasher::verify(password, stored_hash_or_None)` (on a blocking
  thread, limited concurrency), then send `PasswordChecked`. Never skip the hash for unknown
  accounts: pass `None`.
- Rebuild multi-request states from the stored session and the current account:
  `SignIn::second_factor(session, account)`, `Setup::resume(session, account)`,
  `StepUp::new(account, session)`.
- Fill `Client::device_known` by looking up `TokenHash::of(device_cookie)` for the account
  being signed in.

## Requests

- On every unsafe request: `RequestHeaders::check_origin(&config.origin_string())`; with a
  session also `check_session_request(..., &session.csrf_token)`.
- Authorise with `session.authorize(account.active, access, config.step_up_window(), now)`:
  `Access::SignedIn` for normal pages, `Access::Recent` for sensitive changes (password,
  recovery codes, removing factors, revoking sessions, inviting), `Access::Enrolling` for
  adding TOTP or a passkey.
- Answer refusals with `error.code()` and `error.http_status()`, and `Retry-After` from
  `error.retry_after_secs()`. Do not reveal more (an unknown address and a wrong password
  both give `sign_in_failed`; link requests always answer 202).

## Passkeys (feature `passkeys`)

- `start_*` returns the browser challenge and a `Ceremony`. Keep the ceremony server-side
  under `ceremony.id()`; remove it when the client finishes (single use), then
  `ceremony.into_state(Some(session.id), Some(user), now)?`.
- After `finish_authentication` / `finish_discoverable`, call `passkey::record_use` and
  store the updated passkey; `None` means it is not one of the account's passkeys: fail.
- For discoverable sign-in, load the passkeys of `identify_discoverable(credential)?` and
  pass that same user to `finish_discoverable`.

## Never

- Never call `flow::issue_session` with a user id the client chose; only for an account the
  app has just verified (for example the user of a full session that started a hand-off).
- Never log or `Display` secrets; secret types redact `Debug` on purpose.
- Never keep a limiter or throttle per request: they are long-lived state
  (`RateLimiter`, `WrongPasswordThrottle`) behind a lock, or persisted per key.
