---
name: latchkey-porting
description: Porting an app from latchkey 0.2 (axum router, SqliteStore, Mailer) to latchkey 0.3 (sans-IO building blocks and flow state machines). Use when code still uses Latchkey::new, latchkey::Store, SqliteStore, Mailer, CurrentUser, RecentAuth or Latchkey::router and is being moved to latchkey 0.3.
---

# Porting from latchkey 0.2 to 0.3

0.3 removed the service (router, extractors, store, mailer, clock, in-memory limiters) and
kept the decisions. The app now owns I/O. Stored formats are unchanged, so an existing 0.2
SQLite database keeps working with the app's own queries.

## Steps

1. Replace `Config::new(owner, origin, secret_key, data_key)` with
   `Config::builder(owner, origin).build()?`, `DataKey::new(&data_key)` and
   `IpTagKey::new(&secret_key)`; keep the keys where they were. Call
   `seal::check_keys(&secret_key, &data_key)?` at start.
2. Create a `PasswordHasher::new(config.password(), &mut rng)?` once; run `verify` and
   `hash_new_password` on a blocking thread behind a semaphore of one.
3. Keep 0.2's tables (`latchkey_users`, `latchkey_sessions`, `latchkey_tokens`,
   `latchkey_totp`, `latchkey_passkeys`, `latchkey_recovery_codes`, `latchkey_devices`,
   `latchkey_audit`) and write queries for them: build `Account` from a user row (factors from
   the totp, passkey and password columns), `Session` from a session row (0.2 has no
   `step_up_failures` column: use 0, or add one if you opt into
   `StepUpFailures::PerSession`), `LinkToken` from a token row. Names (`Stage`, `SignInMethod`, `LinkKind`, `AuditKind`, `Role`) parse from and
   print to the stored strings; `TotpStep::try_from(i64)` reads `last_step`.
4. Write one `apply(effects)` function that handles every `flow::Effect` variant, with
   compare-and-set for `UseTotpStep`/`UseRecoveryCode`, an atomic `failures = failures + 1`
   for `RecordFailure` (like 0.2's `add_failure`) followed by `LockoutPolicy::locked_until`, a transaction for
   `StoreSession { replaces }`, and mail sent after commit with `Mail::subject()`/`text()`.
5. Replace each 0.2 endpoint with a route that loads data, calls the matching flow, applies
   effects and answers: `/sign-in/password` + `/sign-in/code` with `flow::sign_in`,
   `/sign-in/email*` with `flow::email_link`, `/setup/*` and `/invites/redeem` with
   `flow::setup`, `/invites` with `flow::invite`, `/step-up/*` with `flow::step_up`,
   `/sign-out` with `flow::sign_out`.
6. Replace the `CurrentUser`/`RecentAuth` extractors with an extractor of the app's own that
   reads the cookie (`http::find_cookie`), looks the session up by `TokenHash::of`, calls
   `Session::authorize` with `Access::SignedIn` or `Access::Recent`, and for unsafe methods
   `RequestHeaders::check_session_request`.
7. Hold one `RateLimiter` per IP and per account, and one `WrongPasswordThrottle`, in app
   state behind a `Mutex`; check the limiters before calling a flow.
8. Store passkey ceremonies (`passkey::Ceremony`, `Serialize`) in a table or cache with a
   5-minute TTL and remove them on use.
9. Replace `Latchkey::issue_session(user, IssueSession::from_headers(...))` with
   `flow::issue_session(&config, &account, AppMethod::new("...")?, &client, now, &mut rng)`.
10. Replace `ManualClock` in tests with explicit `now` values and `TestMailer` with the
    `SendMail` effects (`Mail::link_token()` reads the token).

## Pitfalls

- Do not drop a `Refusal`'s effects: the lockout and the audit log depend on them.
- Do not hash before the flow's first password step returns `VerifyPassword`.
- `step_up` is now a reserved method name for app-issued sessions.
