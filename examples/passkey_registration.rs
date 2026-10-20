//! Registering a passkey and signing in with it, with a software authenticator standing in
//! for the browser.
//!
//! Run with `cargo run --example passkey_registration --features passkeys`.

use std::collections::HashMap;

use latchkey::passkey::{RelyingParty, record_use};
use latchkey::seal::DataKey;
use latchkey::{CeremonyId, Config, PasskeyId, SessionId, UserId};
use time::OffsetDateTime;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("owner@example.com", "https://home.example.com").build()?;
    let rp = RelyingParty::new(&config)?;
    let mut rng = latchkey::os_rng()?;
    let data_key = DataKey::new(&[7; 32]);
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let user = UserId::random(&mut rng);
    let session = SessionId::random(&mut rng); // a setup session, or a recent full session
    let mut browser = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let origin = Url::parse("https://home.example.com")?;

    // POST /passkeys/register/start: store the ceremony server-side, send its id + challenge.
    let mut ceremonies = HashMap::new();
    let (challenge, ceremony) = rp.start_registration(
        user,
        "owner@example.com",
        "Owner",
        &[],
        session,
        now,
        &mut rng,
    )?;
    let ceremony_id: CeremonyId = ceremony.id();
    ceremonies.insert(ceremony_id, serde_json::to_string(&ceremony)?);
    println!(
        "challenge JSON: {} bytes",
        serde_json::to_string(&challenge)?.len()
    );

    // The browser runs navigator.credentials.create(challenge).
    let credential = browser.do_registration(origin.clone(), challenge)?;

    // POST /passkeys/register/finish {ceremony, credential}: take the ceremony out (single use).
    let stored = ceremonies.remove(&ceremony_id).ok_or("unknown ceremony")?;
    let ceremony: latchkey::passkey::Ceremony<
        latchkey::passkey::webauthn_rs::prelude::PasskeyRegistration,
    > = serde_json::from_str(&stored)?;
    let state = ceremony.into_state(session, user, now)?;
    let passkey = rp.finish_registration(&credential, &state, &[])?;
    let passkey_id = PasskeyId::random(&mut rng);
    let sealed = data_key.seal_passkey(&mut rng, user, passkey_id, &passkey)?;
    println!("store passkey {passkey_id} ({} sealed bytes)", sealed.len());

    // Later: verify it as a second factor or for a step-up.
    let mut passkeys = vec![data_key.open_passkey(user, passkey_id, &sealed)?];
    let (challenge, ceremony) = rp.start_authentication(user, &passkeys, session, now, &mut rng)?;
    let assertion = browser.do_authentication(origin, challenge)?;
    let state = ceremony.into_state(session, user, now)?;
    let result = rp.finish_authentication(&assertion, &state)?;
    let index = record_use(&mut passkeys, &result).ok_or("not one of the account's passkeys")?;
    println!(
        "verified with passkey #{index}; reseal and store it, then send SignInEvent::Passkey {{ verified: true }}"
    );
    Ok(())
}
