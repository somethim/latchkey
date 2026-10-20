//! Passkey ceremonies against a software authenticator, and the passkey flow events.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::{App, Browser, ORIGIN, OWNER, PASSWORD};
use latchkey::error::{ConflictReason, InvalidRequestReason};
use latchkey::flow::LinkKind;
use latchkey::flow::sign_in::{SignIn, SignInEvent};
use latchkey::flow::step_up::{StepUp, StepUpEvent};
use latchkey::passkey::webauthn_rs::prelude::{
    Passkey, PublicKeyCredential, RequestChallengeResponse,
};
use latchkey::passkey::{
    Binding, CEREMONY_TTL, RegistrationRequest, RelyingParty, SignInStarted, Started, record_use,
};
use latchkey::session::SignInMethod;
use latchkey::{Error, PasskeyId, UserId};
use time::Duration;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

struct Key {
    inner: WebauthnAuthenticator<SoftPasskey>,
    credential_id: Option<latchkey::passkey::webauthn_rs::prelude::Base64UrlSafeData>,
}

impl Key {
    fn new() -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            credential_id: None,
        }
    }

    fn origin() -> Url {
        Url::parse(ORIGIN).unwrap()
    }

    /// Registers through the relying party; returns the passkey for the app to store.
    fn register(
        &mut self,
        app: &mut App,
        rp: &RelyingParty,
        user: UserId,
        existing: &[Passkey],
    ) -> Result<Passkey, Error> {
        let session = app
            .sessions
            .values()
            .find(|s| s.user_id == user)
            .unwrap()
            .id;
        let request = RegistrationRequest::new(user, OWNER, "Owner", session).excluding(existing);
        let Started {
            challenge,
            ceremony,
            ..
        } = rp
            .start_registration(request, app.now, &mut app.rng)
            .unwrap();
        let credential = self
            .inner
            .do_registration(Self::origin(), challenge)
            .map_err(|_| Error::InvalidRequest(InvalidRequestReason::PasskeyRejected))?;
        self.credential_id = Some(credential.raw_id.clone());
        let state = ceremony.into_state(session, user, app.now)?;
        rp.finish_registration(&credential, &state, existing)
    }

    fn assert(&mut self, challenge: RequestChallengeResponse) -> PublicKeyCredential {
        self.inner
            .do_authentication(Self::origin(), challenge)
            .unwrap()
    }

    /// The soft token cannot discover its credentials, so the test supplies the allow list
    /// and the user handle a platform passkey would return.
    fn assert_discoverable(
        &mut self,
        mut challenge: RequestChallengeResponse,
        user: UserId,
    ) -> PublicKeyCredential {
        challenge.public_key.allow_credentials = vec![webauthn_rs_proto::AllowCredentials {
            type_: "public-key".into(),
            id: self.credential_id.clone().unwrap(),
            transports: None,
        }];
        let mut credential = self.assert(challenge);
        credential.response.user_handle = Some(user.as_uuid().as_bytes().to_vec().into());
        credential
    }
}

/// Sets the owner up with a password and a passkey only.
fn owner_with_passkey(
    app: &mut App,
    browser: &mut Browser,
    rp: &RelyingParty,
    key: &mut Key,
) -> Vec<Passkey> {
    app.request_setup(browser);
    let token = app.mail.last().unwrap().link_token().unwrap();
    let _ = app.redeem_setup(browser, LinkKind::Setup, &token).unwrap();
    app.setup_password(browser, PASSWORD).unwrap();
    let owner = app.owner_id();
    let passkey = key.register(app, rp, owner, &[]).unwrap();
    let id = PasskeyId::random(&mut app.rng);
    let sealed = app
        .data_key
        .seal_passkey(&mut app.rng, owner, id, &passkey)
        .unwrap();
    app.rows
        .get_mut(&owner)
        .unwrap()
        .passkeys
        .push((id, sealed));
    app.finish_setup(browser).unwrap();
    vec![passkey]
}

#[test]
fn setup_with_a_passkey_only_and_sign_in_with_it() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let mut passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();

    let SignInStarted {
        challenge,
        ceremony,
        binding_token: binding,
        ..
    } = rp.start_discoverable(app.now, &mut app.rng).unwrap();
    assert_eq!(ceremony.binding().user(), None);
    let credential = key.assert_discoverable(challenge, owner);
    let claimed = rp.identify_discoverable(&credential).unwrap();
    assert_eq!(claimed, owner);
    let state = ceremony
        .into_browser_state(binding.expose_secret(), app.now)
        .unwrap();
    let result = rp
        .finish_discoverable(&credential, state, claimed, &passkeys)
        .unwrap();
    assert_eq!(record_use(&mut passkeys, &result), Some(0));

    let mut browser = Browser::default();
    let client = app.client(&browser, Some(owner));
    let step = SignIn::Start
        .advance(
            &app.config,
            SignInEvent::PasskeyOnly {
                account: app.account(claimed),
                verified: true,
                client,
            },
            app.now,
            &mut app.rng,
        )
        .unwrap();
    app.apply(step.effects, &mut browser).unwrap();
    let SignIn::SignedIn { session, .. } = step.state else {
        panic!("not signed in");
    };
    assert_eq!(session.method, Some(SignInMethod::Passkey));
}

#[test]
fn a_ceremony_is_consumed_by_use() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let SignInStarted {
        ceremony,
        binding_token: binding,
        ..
    } = rp.start_discoverable(app.now, &mut app.rng).unwrap();
    let stored = serde_json::to_string(&ceremony).unwrap();
    assert!(!stored.contains(binding.expose_secret()));
    let state = ceremony.into_browser_state(binding.expose_secret(), app.now);
    assert!(state.is_ok());
    // `ceremony` has moved: the only way to use it again is a stored copy, which the app
    // deletes when it takes it. A copy restored from storage still works once, as here.
    let restored: latchkey::passkey::Ceremony<
        latchkey::passkey::webauthn_rs::prelude::DiscoverableAuthentication,
    > = serde_json::from_str(&stored).unwrap();
    assert!(
        restored
            .into_browser_state(binding.expose_secret(), app.now)
            .is_ok()
    );
}

#[test]
fn ceremonies_expire_and_are_bound_to_their_session_and_user() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();
    let session = latchkey::SessionId::random(&mut app.rng);
    let other = latchkey::SessionId::random(&mut app.rng);
    let start = |app: &mut App| {
        rp.start_authentication(owner, &passkeys, session, app.now, &mut app.rng)
            .unwrap()
            .ceremony
    };
    let unknown = Some(Error::InvalidRequest(InvalidRequestReason::UnknownCeremony));
    assert_eq!(
        start(&mut app).into_state(other, owner, app.now).err(),
        unknown
    );
    let stranger = UserId::random(&mut app.rng);
    assert_eq!(
        start(&mut app).into_state(session, stranger, app.now).err(),
        unknown
    );
    let ceremony = start(&mut app);
    assert_eq!(
        ceremony
            .into_state(session, owner, app.now + CEREMONY_TTL)
            .err(),
        unknown
    );
    assert!(start(&mut app).into_state(session, owner, app.now).is_ok());
}

#[test]
fn passkey_for_another_user_handle_is_rejected() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let SignInStarted {
        challenge,
        ceremony,
        binding_token: binding,
        ..
    } = rp.start_discoverable(app.now, &mut app.rng).unwrap();
    let stranger = UserId::random(&mut app.rng);
    let credential = key.assert_discoverable(challenge, stranger);
    let claimed = rp.identify_discoverable(&credential).unwrap();
    assert_eq!(claimed, stranger);
    assert!(app.account(claimed).is_none(), "the app finds no account");
    // Even against the owner's passkeys, the user handle does not match.
    let state = ceremony
        .into_browser_state(binding.expose_secret(), app.now)
        .unwrap();
    assert_eq!(
        rp.finish_discoverable(&credential, state, app.owner_id(), &passkeys)
            .err(),
        Some(Error::SignInFailed),
        "a handle that is not the account whose passkeys were loaded"
    );
    let step = SignIn::Start.advance(
        &app.config,
        SignInEvent::PasskeyOnly {
            account: None,
            verified: false,
            client: latchkey::flow::Client::default(),
        },
        app.now,
        &mut app.rng,
    );
    assert_eq!(step.err().map(|r| r.error), Some(Error::SignInFailed));
}

#[test]
fn passkey_as_second_factor_after_password() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let mut passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let mut laptop = Browser::default();
    let SignIn::SecondFactor { account, session } =
        app.password_step(&mut laptop, OWNER, PASSWORD).unwrap()
    else {
        panic!("no second factor");
    };
    let Started {
        challenge,
        ceremony,
        ..
    } = rp
        .start_authentication(account.id, &passkeys, session.id, app.now, &mut app.rng)
        .unwrap();
    let credential = key.assert(challenge);
    let state = ceremony
        .into_state(session.id, account.id, app.now)
        .unwrap();
    let result = rp.finish_authentication(&credential, &state).unwrap();
    let verified = record_use(&mut passkeys, &result).is_some();
    let client = app.client(&laptop, Some(account.id));
    let step = SignIn::second_factor(session, account)
        .advance(
            &app.config,
            SignInEvent::Passkey { verified, client },
            app.now,
            &mut app.rng,
        )
        .unwrap();
    app.apply(step.effects, &mut laptop).unwrap();
    assert_eq!(
        app.session_of(&laptop).unwrap().method,
        Some(SignInMethod::PasswordPasskey)
    );
}

#[test]
fn step_up_with_a_passkey() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let mut browser = Browser::default();
    let passkeys = owner_with_passkey(&mut app, &mut browser, &rp, &mut key);
    app.advance(Duration::minutes(6));
    let session = app.session_of(&browser).unwrap();
    let account = app.account(session.user_id).unwrap();
    let Started {
        challenge,
        ceremony,
        ..
    } = rp
        .start_authentication(account.id, &passkeys, session.id, app.now, &mut app.rng)
        .unwrap();
    let credential = key.assert(challenge);
    let state = ceremony
        .into_state(session.id, account.id, app.now)
        .unwrap();
    let verified = rp.finish_authentication(&credential, &state).is_ok();
    let client = app.client(&browser, Some(account.id));
    let step = StepUp::new(account, session)
        .advance(
            &app.config,
            StepUpEvent::Passkey { verified, client },
            app.now,
        )
        .unwrap();
    app.apply(step.effects, &mut browser).unwrap();
    let session = app.session_of(&browser).unwrap();
    assert_eq!(session.authenticated_at, Some(app.now));
}

#[test]
fn the_same_passkey_cannot_be_registered_twice() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();
    let session = latchkey::SessionId::random(&mut app.rng);
    let request = RegistrationRequest::new(owner, OWNER, "Owner", session).excluding(&passkeys);
    let Started {
        challenge,
        ceremony,
        ..
    } = rp
        .start_registration(request, app.now, &mut app.rng)
        .unwrap();
    let excluded = &challenge.public_key.exclude_credentials;
    assert_eq!(excluded.as_ref().map(Vec::len), Some(1));
    let credential = key.inner.do_registration(Key::origin(), challenge).unwrap();
    let state = ceremony.into_state(session, owner, app.now).unwrap();
    let added = rp
        .finish_registration(&credential, &state, &passkeys)
        .unwrap();
    assert_eq!(
        rp.finish_registration(&credential, &state, &[added]).err(),
        Some(Error::Conflict(ConflictReason::PasskeyExists))
    );
}

#[test]
fn sealed_passkeys_open_only_for_their_row() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();
    let id = PasskeyId::random(&mut app.rng);
    let sealed = app
        .data_key
        .seal_passkey(&mut app.rng, owner, id, &passkeys[0])
        .unwrap();
    assert!(!sealed.contains("cred"));
    let opened = app.data_key.open_passkey(owner, id, &sealed).unwrap();
    assert_eq!(opened.cred_id(), passkeys[0].cred_id());
    let other = PasskeyId::random(&mut app.rng);
    assert!(app.data_key.open_passkey(owner, other, &sealed).is_err());
}

#[test]
fn a_relying_party_must_match_the_origin() {
    assert!(RelyingParty::from_parts("other.example", "x", ORIGIN).is_err());
}

#[test]
fn ceremonies_expose_their_session_binding() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();
    let session = latchkey::SessionId::random(&mut app.rng);
    let ceremony = rp
        .start_authentication(owner, &passkeys, session, app.now, &mut app.rng)
        .unwrap()
        .ceremony;
    assert_eq!(
        *ceremony.binding(),
        Binding::Session {
            session,
            user: owner
        }
    );
    assert_eq!(ceremony.binding().user(), Some(owner));
    assert_eq!(ceremony.binding().session(), Some(session));
    let fake = latchkey::token::issue(&mut app.rng);
    assert_eq!(
        ceremony
            .into_browser_state(fake.token.expose_secret(), app.now)
            .err(),
        Some(Error::InvalidRequest(InvalidRequestReason::UnknownCeremony)),
        "a session-bound ceremony cannot be finished as a browser-bound one"
    );
}

#[test]
fn passkey_sign_in_with_an_allow_list_before_any_session() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let mut key = Key::new();
    let mut passkeys = owner_with_passkey(&mut app, &mut Browser::default(), &rp, &mut key);
    let owner = app.owner_id();

    // POST /sign-in/passkey/start {email}: no session exists yet.
    let mut browser = Browser::default();
    let SignInStarted {
        challenge,
        ceremony,
        binding_token: binding,
        ..
    } = rp
        .start_sign_in(owner, &passkeys, app.now, &mut app.rng)
        .unwrap();
    assert_eq!(challenge.public_key.allow_credentials.len(), 1);
    assert_eq!(ceremony.binding().user(), Some(owner));
    assert_eq!(ceremony.binding().session(), None);
    let cookie = latchkey::http::SetCookie::new(
        app.config.ceremony_cookie_name().clone(),
        &binding,
        CEREMONY_TTL,
    );
    browser.set(&cookie);
    let stored = serde_json::to_string(&ceremony).unwrap();
    let credential = key.assert(challenge);

    // Another browser with the ceremony id but without the binding cookie cannot finish it.
    let restore = || -> latchkey::passkey::Ceremony<
        latchkey::passkey::webauthn_rs::prelude::PasskeyAuthentication,
    > { serde_json::from_str(&stored).unwrap() };
    let other = latchkey::token::issue(&mut app.rng);
    let unknown = Some(Error::InvalidRequest(InvalidRequestReason::UnknownCeremony));
    assert_eq!(
        restore()
            .into_browser_state(other.token.expose_secret(), app.now)
            .err(),
        unknown
    );
    assert_eq!(restore().into_browser_state("", app.now).err(), unknown);
    assert_eq!(
        restore()
            .into_state(latchkey::SessionId::random(&mut app.rng), owner, app.now)
            .err(),
        unknown,
        "a browser-bound ceremony cannot be finished as a session-bound one"
    );
    assert_eq!(
        restore()
            .into_browser_state(binding.expose_secret(), app.now + CEREMONY_TTL)
            .err(),
        unknown
    );

    // POST /sign-in/passkey/finish: the binding cookie, then the account the binding names.
    let presented = browser.cookies["__Host-latchkey_ceremony"].clone();
    let ceremony = restore();
    let user = ceremony.binding().user().unwrap();
    let state = ceremony.into_browser_state(&presented, app.now).unwrap();
    let result = rp.finish_authentication(&credential, &state).unwrap();
    let verified = record_use(&mut passkeys, &result).is_some();
    let client = app.client(&browser, Some(user));
    let step = SignIn::Start
        .advance(
            &app.config,
            SignInEvent::PasskeyOnly {
                account: app.account(user),
                verified,
                client,
            },
            app.now,
            &mut app.rng,
        )
        .unwrap();
    app.apply(step.effects, &mut browser).unwrap();
    assert_eq!(
        app.session_of(&browser).unwrap().method,
        Some(SignInMethod::Passkey)
    );
}

#[test]
fn an_allow_list_sign_in_needs_passkeys() {
    let mut app = App::new();
    let rp = RelyingParty::new(&app.config).unwrap();
    let owner = app.owner_id();
    assert_eq!(
        rp.start_sign_in(owner, &[], app.now, &mut app.rng).err(),
        Some(Error::InvalidRequest(InvalidRequestReason::NoPasskey))
    );
}
