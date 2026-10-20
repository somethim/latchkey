# latchkey

Sign-in for a small [axum](https://github.com/tokio-rs/axum) app that you run for yourself and a
few people you invite. It is a library: you nest its router into your app, protect your own
routes with its extractors, and give it a database and a way to send mail.

- **Password**, always followed by a second factor (TOTP, passkey or recovery code).
- **Passkeys** with user verification required. A passkey signs in on its own.
- **Email sign-in link**, single use, valid for 15 minutes, signs in directly.
- **TOTP** (SHA-1, 6 digits, 30 s, ±1 step) with a replay guard on the time step.
- **Encryption at rest**: TOTP secrets and passkey data are sealed with AES-256-GCM under a data
  key of their own, each bound to its account and kind.
- **Recovery codes**: 10 single-use codes, stored as SHA-256 hashes.
- **First-open setup**: the owner account is created from a configured email address. Until it
  is set up, a single-use link is mailed to that address only; the owner then sets a password,
  enrols a passkey and/or TOTP, and receives recovery codes.
- **Invites**: the owner invites family members by email; they go through the same setup.
- **Sessions**: random 32-byte tokens stored as SHA-256, a new token on every stage change,
  a list of active sessions with revocation, and a 5-minute step-up window for sensitive changes.
- **Throttling**: per-IP and per-account rate limits, at most 10 wrong passwords per account in
  any 15 minutes, and an account lockout that starts at 5 minutes after 5 failures and doubles
  on every further 5 up to an hour.
- **New-device mail**: a long-lived device cookie recognises browsers; a sign-in that completes
  on one the account has not used before is mailed to the account.
- **Audit log**: append-only, with client IPs stored only as an HMAC.

The building blocks are maintained crates, not custom cryptography: `argon2`, `webauthn-rs`,
`totp-rs`, `aes-gcm`, `sha2`, `hmac`, `subtle`, `rand` and `sqlx`.

## Quick start

```toml
[dependencies]
latchkey = "0.2"
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

```rust,no_run
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Router, routing::get};
use latchkey::{
    Config, CurrentUser, Latchkey, Mail, MailError, Mailer, RecentAuth, SqliteStore, async_trait,
};

struct MyMailer;

#[async_trait]
impl Mailer for MyMailer {
    async fn send(&self, mail: Mail) -> Result<(), MailError> {
        // Hand `mail.to`, `mail.subject()` and `mail.text()` (or your own template built
        // from `mail.kind`, `mail.link` and `mail.sign_in`) to your mail provider.
        Ok(())
    }
}

async fn home(user: CurrentUser) -> String {
    format!("Hello, {}", user.display_name())
}

async fn danger(_user: RecentAuth) -> &'static str {
    "only reachable within 5 minutes of signing in or stepping up"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (secret_key, data_key): ([u8; 32], [u8; 32]) = load_keys();
    let config = Config::new("owner@example.com", "https://home.example.com", secret_key, data_key)?;
    let store = SqliteStore::connect("sqlite://auth.db").await?;
    let auth = Latchkey::new(config, Arc::new(store), Arc::new(MyMailer)).await?;

    let app = Router::new()
        .route("/", get(home))
        .route("/danger", get(danger))
        .nest("/auth", auth.router())
        .with_state(auth);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
# fn load_keys() -> ([u8; 32], [u8; 32]) { ([1; 32], [2; 32]) }
```

If your app has its own state type, implement `axum::extract::FromRef<YourState> for Latchkey`
and the extractors find it there. `examples/minimal.rs` is a runnable version that prints mail
to the terminal: `cargo run --example minimal`.

### Configuration

`Config::new(owner_email, origin, secret_key, data_key)` fills in the defaults described above;
every field is public. The ones you are most likely to change:

| Field | Default | Meaning |
|---|---|---|
| `setup_url`, `sign_in_link_url`, `invite_url` | `/setup`, `/sign-in/link`, `/invite` on the origin | Front-end pages that receive `?token=` from mailed links |
| `sessions_url` | `/settings/sessions` on the origin | Linked from the new-device mail |
| `cookie_name` | `__Host-latchkey` | Must keep the `__Host-` prefix |
| `device_cookie_name` | `__Host-latchkey_device` | Must keep the `__Host-` prefix |
| `device_ttl` | 400 days | A device unused this long counts as new again |
| `session_ttl` | 30 days | Lifetime of a signed-in session |
| `step_up_window` | 5 minutes | How long a sign-in or step-up counts as recent |
| `invite_ttl` | 3 days | Lifetime of an invite link |
| `rate_limits` | 30/min per IP, 10/min per account, 10 wrong passwords per 15 min per account | In memory; the wrong-password window slides |
| `password` | Argon2id, 64 MiB, t=3, p=2 | Hashing runs one at a time on a blocking thread |
| `trust_forwarded_for` | `false` | Use the last `X-Forwarded-For` entry as the client IP (only behind your own proxy) |

Both keys are 32 random bytes, must differ, and belong in your secret store, not the
repository or the database's backups:

- `secret_key` keys the HMAC used for IP addresses in sessions and the audit log.
- `data_key` encrypts TOTP secrets and passkey data. Losing or changing it makes every enrolled
  TOTP and passkey unreadable; `Latchkey::new` then refuses to start rather than run without
  them.

`Latchkey::reset_owner()` wipes the owner's password, factors and sessions so first-open setup
runs again, for when every factor is lost; call it from a command-line entry point of your app.
`Latchkey::purge_expired()` deletes expired sessions and links, and devices unused for
`device_ttl`.

### Upgrading from 0.1

0.1 stored TOTP secrets and passkey data in plaintext. `Latchkey::new` refuses to start while
such rows exist. Add a `data_key` to the configuration and run the migration once, before
starting:

```rust,no_run
# use latchkey::{Config, Latchkey, SqliteStore};
# async fn upgrade(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
let store = SqliteStore::connect("sqlite://auth.db").await?;
let encrypted = Latchkey::encrypt_plaintext_secrets(config, &store).await?;
println!("encrypted {encrypted} values");
# Ok(())
# }
```

Values that are already encrypted are skipped, so running it again does nothing. The store
migration adds a `latchkey_devices` table; every browser counts as new once after the upgrade.

## Sessions started by your app

Sometimes the app completes a sign-in itself, for example a desktop app that opens the
browser, where the user is already signed in, and receives a one-time code back on a loopback
redirect. `Latchkey::issue_session` then starts a latchkey session for that account, exactly
like a normal sign-in: a fresh token stored as SHA-256, `session_ttl`, the client IP as an
HMAC, `authenticated_at` set to now (the step-up window starts), failed attempts cleared, a
`sign_in` audit event with your method, and the new-device check and mail.

**It checks no factor.** Only call it for a user that latchkey has just verified, such as the
account of the browser session the hand-off started from. Never pass it a user id that a
client chose. It refuses accounts that have not finished setup (`forbidden`) and accounts
that are locked out (`too_many_attempts`), and `method` must be 1 to 32 characters from
`a-z`, `0-9` and `_`, and not one of latchkey's own (`setup`, `password`, `passkey`,
`email_link`, `totp`, `recovery_code`).

```rust,no_run
# use axum::http::HeaderMap;
# use latchkey::{Error, IssueSession, Latchkey};
# use uuid::Uuid;
// In the browser, before handing off: who is signed in? (Check the origin and the CSRF token
// with `CurrentUser::csrf_matches` yourself if this is an unsafe request.)
async fn browser_user(auth: &Latchkey, headers: &HeaderMap) -> Result<Uuid, Error> {
    Ok(auth.current_user_from_headers(headers).await?.id())
}

// Later, when the desktop app redeems the one-time code that carried that user id:
async fn desktop_session(
    auth: &Latchkey,
    user: Uuid,
    headers: &HeaderMap,
    peer: std::net::IpAddr,
) -> Result<(), Error> {
    let request = IssueSession::from_headers(auth, "desktop_bridge", headers, Some(peer));
    let issued = auth.issue_session(user, request).await?;
    let [session_cookie, device_cookie] = issued.set_cookie_headers()?;
    // Send both as `Set-Cookie` with `issued.csrf_token()` in the body, or hand
    // `issued.session_cookie().value()` to the app's keyring.
    # let _ = (session_cookie, device_cookie);
    Ok(())
}
```

- `IssueSession { method, client_ip, user_agent, device_cookie }` has public fields;
  `IssueSession::new(method)` leaves the rest empty and `IssueSession::from_headers` reads them
  the way the endpoints do (socket address or, with `trust_forwarded_for`, `X-Forwarded-For`;
  `User-Agent`; the device cookie).
- `IssuedSession` has the `user_id`, `session_id`, `csrf_token`, `authenticated_at`,
  `expires_at` and two `IssuedCookie`s, `session_cookie` and `device_cookie`, each with
  `name`, `value`, `max_age` and `set_cookie()` (`name=value; Path=/; Max-Age=…; HttpOnly;
  Secure; SameSite=Lax`). Its `Debug` output leaves out the secrets.
- `Latchkey::session_from_cookie(value)` and `Latchkey::current_user_from_headers(headers)`
  return the `CurrentUser` of a completed, unexpired session, or `unauthorized`. Unlike the
  extractor they check no origin or CSRF token; `CurrentUser::csrf_token` and
  `CurrentUser::csrf_matches` are there for that.

## Endpoints

All bodies are JSON. Responses that start a session set the cookie and include `stage` and
`csrf_token`. Errors are `{"error": "<code>"}` with a generic code such as `sign_in_failed`,
`step_up_required`, `csrf_rejected` or `too_many_attempts`.

| Method and path | Needs | Purpose |
|---|---|---|
| `GET /setup/status` | | `{"setup_required": bool}` |
| `POST /setup/start` | | Mails a setup link to the owner (always `202`) |
| `POST /setup/redeem` `{token}` | | Starts a setup session |
| `POST /setup/password` `{password}` | setup session | 12 to 1024 characters |
| `POST /setup/complete` | setup session | Needs a password and a TOTP or passkey; returns `recovery_codes` |
| `POST /invites` `{email, display_name?}` | owner, recent | Creates a member and mails an invite |
| `POST /invites/redeem` `{token}` | | Starts a setup session for the invited member |
| `GET /me` | any session | Account, stage, CSRF token, enrolled factors |
| `POST /sign-in/password` `{email, password}` | | First step; leaves a `second_factor` session |
| `POST /sign-in/code` `{code}` | second-factor session | TOTP or recovery code |
| `POST /sign-in/second-factor/passkey/start`, `/finish` | second-factor session | Passkey as the second factor |
| `POST /sign-in/passkey/start`, `/finish` `{ceremony, credential}` | | Passkey sign-in (discoverable credential) |
| `POST /sign-in/email` `{email}` | | Mails a sign-in link (always `202`) |
| `POST /sign-in/email/redeem` `{token}` | | Signs in |
| `POST /sign-out` | any session | |
| `POST /step-up/password` `{password, code}` | signed in | Refreshes the step-up window |
| `POST /step-up/passkey/start`, `/finish` | signed in | Same, with a passkey |
| `POST /password` `{password}` | recent | Changes the password |
| `POST /totp/enrol`, `POST /totp/confirm` `{code}` | setup session, or recent | |
| `DELETE /totp` | recent | Refused if it is the last factor |
| `GET /passkeys` | signed in | |
| `POST /passkeys/register/start` `{name?}`, `/finish` `{ceremony, credential}` | setup session, or recent | |
| `DELETE /passkeys/{id}` | recent | Refused if it is the last factor |
| `POST /recovery-codes` | recent | Replaces all recovery codes |
| `GET /sessions` | signed in | |
| `DELETE /sessions/{id}` | recent | |
| `GET /audit?limit=` | signed in | Owner sees everything, members see their own events |

Passkey `options` are the WebAuthn JSON for `navigator.credentials.create`/`get`; send the
browser's credential back as `credential`, base64url-encoded as `webauthn-rs` expects.

### From the browser

- Send every unsafe request (`POST`, `DELETE`, ...) with the `x-csrf-token` header set to the
  current `csrf_token` (also available from `GET /me`). The router and the `CurrentUser`
  extractor reject unsafe requests whose `Origin` is not the configured origin, or, without an
  `Origin` header, whose `Sec-Fetch-Site` is not `same-origin`.
- Links in mail point at your front-end pages; read `token` from the query string, remove it
  from the address bar, and post it to the matching `redeem` endpoint.

## Security notes

- Passwords are hashed with Argon2id. An unknown email still runs a full hash against a dummy
  value, and the response is the same as for a wrong password.
- Link requests answer `202` whether or not the address belongs to an account, and mail goes
  out on a background task so response times do not depend on it.
- Tokens, CSRF values and recovery codes come from a CSPRNG; only their SHA-256 is stored.
  CSRF tokens are compared in constant time.
- Every stage change (setup, second factor, signed in) issues a new session token and deletes
  the old one.
- A TOTP code is accepted once: the matched time step is stored and older or equal steps are
  refused, atomically.
- Links, recovery codes and passkey ceremonies are single use. Passkey ceremonies are bound to
  the session that started them and expire after 5 minutes.
- Counter regressions on a passkey (a possible cloned authenticator) are rejected by
  `webauthn-rs`.
- TOTP secrets (also while pending confirmation) and passkey data are sealed with AES-256-GCM,
  a random 96-bit nonce per write, and associated data `latchkey-totp:<user id>` or
  `latchkey-passkey:<user id>:<passkey id>`, so a value copied to another row does not decrypt.
  On start every stored value is checked: plaintext or a wrong data key stops the start.
- Wrong passwords (sign-in and step-up) are counted per normalised email address in a
  15-minute sliding window. The count is checked before the password is hashed, is not reset
  by a successful sign-in, and applies to unknown addresses the same way.
- The device cookie is a random 32-byte token, `HttpOnly`, `Secure`, `SameSite=Lax`, stored
  only as SHA-256 per account. A sign-in on an unknown device (any method except setup
  completion) writes `new_device` to the audit log and mails the account its time, method and
  browser, with a link to the sessions page. Sign-out keeps the device cookie.
- The crate forbids `unsafe` and denies `unwrap`, `expect` and `panic!` outside tests.

Known trade-offs:

- A locked account answers `too_many_attempts` instead of `sign_in_failed`, which tells an
  attacker who has already made 5 wrong guesses that the address exists. (The wrong-password
  throttle does not leak this way, since unknown addresses are throttled too.)
- Rate-limit counters, wrong-password counts and passkey ceremonies live in memory: they reset
  on restart and are not shared between several instances of the app. The lockout is stored
  and survives restarts.
- Anyone with both the database and `data_key` can read TOTP secrets and passkey data. Email
  addresses, display names, passkey names and credential IDs stay in plaintext. There is no
  key rotation yet: changing `data_key` means re-enrolling every factor.
- The new-device check is per browser profile: clearing cookies or using a private window
  counts as a new device, and someone who can read the device cookie from a known browser can
  sign in elsewhere without a mail. The mail names the browser from its `User-Agent` but not
  the IP address, which is only stored as an HMAC. Like every mail it goes out on a background
  task; a failed send is logged, not retried.

## Testing

`cargo test` runs the unit and integration tests and the property tests (`proptest`) for token
and cookie parsing, the rate limiter, the wrong-password window, encryption and request bodies.

`fuzz/` holds a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target, `json_bodies`,
that feeds arbitrary bytes to the JSON body parsing of every endpoint. It builds on stable
(`cargo build --manifest-path fuzz/Cargo.toml`); running it needs a nightly toolchain:

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run json_bodies
```

## What it does not do

- No OAuth or OpenID Connect, neither as a provider nor as a client, and no forward-auth for
  other applications.
- No self-service sign-up: accounts are the owner and the people the owner invites.
- No mail sending, templates or front-end pages; the app supplies those.
- Storage ships for SQLite only. The `Store` trait is public so another database can be added.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion
in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
