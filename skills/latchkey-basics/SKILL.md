---
name: latchkey-basics
description: How to use the latchkey crate (sans-IO sign-in building blocks and policy for Rust) correctly. Use when writing or reviewing code that calls latchkey for passwords, TOTP, recovery codes, passkeys, session tokens, cookies, CSRF, lockout, rate limits, or its sign-in, setup, invite, email link and code, sign-in reset and step-up flows.
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
- Records are `#[non_exhaustive]`: build `Account`, `Session`, `Factors`, `Client`,
  `CodeMaterial` and the rest with their `new` constructors and assign the other public
  fields; flow states need a `_` arm when matched.
- Match errors by reason: `Error::InvalidRequest(InvalidRequestReason::..)`,
  `Error::Conflict(ConflictReason::..)` from `latchkey::error`; show clients
  `error.code()` and `error.detail()`.
- For plain-HTTP development only, `.danger_insecure_localhost_cookies()` drops `__Host-`
  and `Secure`; `build` refuses it unless the origin is `http://localhost`, `127.0.0.1` or
  `[::1]`. Never enable it from a request value or a production config; read cookie names
  from `config.cookie_name()` etc. rather than hard-coding `__Host-latchkey`.

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
  `None`) to the flow, with `token_hash: TokenHash::of(token)` for a sign-in link.

## Email sign-in (link and code)

- One mail carries a link and a 6-digit code (`mail.code`), both valid `config.link_ttl()`
  (5 minutes). Neither signs in: both lead to `EmailLink::SecondFactor`; continue with
  `SignIn::second_factor(session, account)` and `SignInEvent::Code` / `Passkey`. Never
  issue a full session after a link or code yourself.
- `EmailLinkEvent::Request` takes the presented `config.email_cookie_name()` cookie as
  `binding` and returns a `SetCookie` for it: carry it out for every request, known
  address or not (no oracle).
- Store `StoreEmailCode { binding_hash, request }` (insert or replace) in its own table.
  For a guess, count the attempt and read the row in **one** statement
  (`UPDATE email_codes SET attempts = attempts + 1 WHERE binding_hash = ? RETURNING ...`)
  and pass that row as `request` in `EmailLinkEvent::RedeemCode`. Never check first and
  count later: racing guesses would escape the 5-guess budget.
- `ConsumeEmailCode { binding_hash, link_hash }` deletes the request and its link in one
  transaction; if either row is already gone, refuse. `DeleteEmailCode { link_hash }` after
  a link, `DeleteEmailSignIn` when a request ends. Purge expired rows.
- The 6-digit code is safe only while it is bound to the requesting cookie, has the
  5-guess budget (wrong guesses also feed the lockout), lives minutes and still needs the
  second factor. Do not lengthen `link_ttl` much, accept codes without the cookie, or store
  the code itself.

## Sign-in reset

- "Reset sign-in" for a member who lost their second factor: `flow::reset::Reset::Start`
  with `ResetEvent::Reset { admin, session, member, remove_password, client }` from the
  owner's `Access::Recent` session. Carry out `RevokeSessions` (every session of the
  member), `RemoveFactors` (TOTP and pending TOTP, last step, passkeys, recovery codes; the
  password too when `password` is true), `DeactivateAccount`, `ClearFailures`,
  `DeletePendingLinks` (links and email codes), the invite-kind `StoreLinkToken`, the
  `MailKind::SignInReset` mail and the audit event. The member redeems the link on the
  invite page through `Setup` (`Redeem { kind: LinkKind::Invite }`) and must enrol a new
  second factor before `Finish`.

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

- `start_registration(RegistrationRequest::for_account(&account, session.id).excluding(&passkeys), now, rng)`
  and `start_authentication` return `Started { challenge, ceremony }`. Keep the ceremony
  server-side under `ceremony.id()`; remove it when the client finishes (single use), then
  `ceremony.into_state(session.id, user, now)?` for registration, second factor and step-up.
- Passkey sign-in without a session (`start_sign_in` with an allow-list, or
  `start_discoverable`) returns `SignInStarted { challenge, ceremony, binding_token }`: send
  `binding_token` as a cookie named `config.ceremony_cookie_name()` for `CEREMONY_TTL`, and
  finish with `ceremony.into_browser_state(cookie_value, now)?`. Load the passkeys of
  `ceremony.binding().user()` for an allow-list sign-in, and report the result as
  `SignInEvent::PasskeyOnly`. Never invent a session id for it.
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
