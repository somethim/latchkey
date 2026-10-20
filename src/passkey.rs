//! Passkeys through [`webauthn_rs`], with user verification required.
//!
//! Every ceremony has two steps, as in webauthn-rs: `start_*` returns the challenge JSON for
//! the browser and a [`Ceremony`] holding the server-side state; `finish_*` consumes the
//! state. Store the ceremony (it is `Serialize`) under its [`id`](Ceremony::id), hand the id
//! to the client, and on finish **remove** it before use: ceremonies are single use. A
//! ceremony expires after [`CEREMONY_TTL`] and is bound to whoever started it
//! ([`Ceremony::binding`]):
//!
//! | Started by | [`Binding`] | Finish with |
//! |---|---|---|
//! | [`start_registration`](RelyingParty::start_registration), [`start_authentication`](RelyingParty::start_authentication) (second factor, step-up) | [`Binding::Session`]: the session and account | [`Ceremony::into_state`] |
//! | [`start_sign_in`](RelyingParty::start_sign_in) (allow-list), [`start_discoverable`](RelyingParty::start_discoverable) | [`Binding::Browser`]: a one-off binding token, and the account for an allow-list | [`Ceremony::into_browser_state`] |
//!
//! A sign-in has no session yet, so its ceremony is bound to the browser instead: the start
//! also returns a binding token (a [`SecretToken`]) that the ceremony keeps only the hash
//! of. Send it as a cookie,
//! `SetCookie::new(config.ceremony_cookie_name().clone(), &token, CEREMONY_TTL)`, and on
//! finish pass the cookie's value to [`Ceremony::into_browser_state`], so only the browser
//! that started a sign-in can finish it. For an allow-list sign-in,
//! [`Binding::user`] names the account whose passkeys to load.
//!
//! webauthn-rs draws its challenges from OpenSSL's random number generator, not from an RNG
//! you pass in. This is the one place latchkey uses randomness it does not take as a
//! parameter.
//!
//! After an authentication, call [`record_use`] to update the counter of the passkey that
//! was used, then seal and store it again
//! ([`DataKey::seal_passkey`](crate::seal::DataKey::seal_passkey)).

use rand_core::CryptoRng;
use time::{Duration, OffsetDateTime};
use url::Url;
use webauthn_rs::prelude::{
    AuthenticationResult, CreationChallengeResponse, DiscoverableAuthentication, DiscoverableKey,
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::Error;
use crate::config::Config;
use crate::ids::{CeremonyId, SessionId, UserId};
use crate::token::{self, SecretToken, TokenHash};

pub use webauthn_rs;

/// How long a ceremony stays valid.
pub const CEREMONY_TTL: Duration = Duration::minutes(5);

/// What a [`Ceremony`] is bound to: the request that finishes it must prove the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Binding {
    /// Started from this session for this account: a registration, a passkey second factor
    /// or a step-up. Finish with [`Ceremony::into_state`].
    Session {
        /// The session that started it.
        session: SessionId,
        /// Its account.
        user: UserId,
    },
    /// Started before any session exists, by the browser holding the binding token whose
    /// hash this is: a sign-in with an allow-list for `user`, or a discoverable sign-in
    /// (`user` is `None`). Finish with [`Ceremony::into_browser_state`].
    Browser {
        /// The hash of the binding token the start returned.
        token_hash: TokenHash,
        /// The account whose passkeys were offered, for an allow-list sign-in.
        user: Option<UserId>,
    },
}

impl Binding {
    /// The account the ceremony is for, if it names one: load its passkeys to finish.
    #[must_use]
    pub const fn user(&self) -> Option<UserId> {
        match *self {
            Binding::Session { user, .. } => Some(user),
            Binding::Browser { user, .. } => user,
        }
    }

    /// The session that started it, for a [`Binding::Session`].
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        match *self {
            Binding::Session { session, .. } => Some(session),
            Binding::Browser { .. } => None,
        }
    }
}

/// A pending ceremony: the webauthn-rs state `S` plus what it is bound to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[must_use = "store the ceremony to finish it later"]
pub struct Ceremony<S> {
    id: CeremonyId,
    state: S,
    binding: Binding,
    expires_at: OffsetDateTime,
}

impl<S> Ceremony<S> {
    /// The id to store it under and give the client.
    #[must_use]
    pub fn id(&self) -> CeremonyId {
        self.id
    }

    /// What it is bound to: read [`Binding::user`] to know whose passkeys to load before
    /// finishing.
    #[must_use]
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// When it stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// The webauthn-rs state, if the ceremony is unexpired and was started by `session` for
    /// `user` ([`Binding::Session`]). Consumes the ceremony.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `unknown_ceremony`, also for a ceremony bound to a
    /// browser.
    pub fn into_state(
        self,
        session: SessionId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<S, Error> {
        let bound = self.binding == Binding::Session { session, user };
        if self.expires_at <= now || !bound {
            return Err(UNKNOWN);
        }
        Ok(self.state)
    }

    /// The webauthn-rs state, if the ceremony is unexpired and `binding_token` is the token
    /// its start returned ([`Binding::Browser`]), compared in constant time. Consumes the
    /// ceremony.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `unknown_ceremony`, also for a ceremony bound to a
    /// session.
    pub fn into_browser_state(self, binding_token: &str, now: OffsetDateTime) -> Result<S, Error> {
        let bound = match self.binding {
            Binding::Browser { token_hash, .. } => token_hash.verify(binding_token),
            Binding::Session { .. } => false,
        };
        if self.expires_at <= now || !bound {
            return Err(UNKNOWN);
        }
        Ok(self.state)
    }
}

const UNKNOWN: Error = Error::InvalidRequest("unknown_ceremony");

/// The relying party: the app's origin and passkey settings.
#[derive(Debug)]
pub struct RelyingParty {
    webauthn: Webauthn,
}

impl RelyingParty {
    /// From the config's relying party id, name and origin.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the id does not match the origin.
    pub fn new(config: &Config) -> Result<Self, Error> {
        Self::from_parts(config.rp_id(), config.rp_name(), config.origin())
    }

    /// From explicit parts.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when `rp_id` does not match `origin`.
    pub fn from_parts(rp_id: &str, rp_name: &str, origin: &Url) -> Result<Self, Error> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .and_then(|builder| builder.rp_name(rp_name).build())
            .map_err(|_| Error::Config("rp_id does not match the origin"))?;
        Ok(Self { webauthn })
    }

    /// Starts registering a passkey for `user`, from `session` (a setup session or a recent
    /// full session: [`Access::Enrolling`](crate::session::Access::Enrolling)). `existing`
    /// are the account's passkeys, which the authenticator is asked not to register again.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when webauthn-rs fails.
    #[allow(clippy::too_many_arguments)]
    pub fn start_registration<R: CryptoRng + ?Sized>(
        &self,
        user: UserId,
        user_name: &str,
        display_name: &str,
        existing: &[Passkey],
        session: SessionId,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<(CreationChallengeResponse, Ceremony<PasskeyRegistration>), Error> {
        let exclude = existing.iter().map(|key| key.cred_id().clone()).collect();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(user.into_uuid(), user_name, display_name, Some(exclude))
            .map_err(|_| Error::Crypto("webauthn registration start"))?;
        Ok((
            challenge,
            ceremony(state, Binding::Session { session, user }, now, rng),
        ))
    }

    /// Finishes a registration. Refuses a credential that is already among `existing` (the
    /// app should also keep credential ids unique across accounts).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `passkey_rejected`, or [`Error::Conflict`] with
    /// `passkey_exists`.
    pub fn finish_registration(
        &self,
        credential: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
        existing: &[Passkey],
    ) -> Result<Passkey, Error> {
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, state)
            .map_err(|_| Error::InvalidRequest("passkey_rejected"))?;
        if existing
            .iter()
            .any(|key| key.cred_id() == passkey.cred_id())
        {
            return Err(Error::Conflict("passkey_exists"));
        }
        Ok(passkey)
    }

    /// Starts verifying one of `user`'s passkeys: as the second factor after a password, or
    /// for a step-up. Bound to `session`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `no_passkey`, or [`Error::Crypto`].
    pub fn start_authentication<R: CryptoRng + ?Sized>(
        &self,
        user: UserId,
        passkeys: &[Passkey],
        session: SessionId,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<(RequestChallengeResponse, Ceremony<PasskeyAuthentication>), Error> {
        if passkeys.is_empty() {
            return Err(Error::InvalidRequest("no_passkey"));
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|_| Error::Crypto("webauthn authentication start"))?;
        Ok((
            challenge,
            ceremony(state, Binding::Session { session, user }, now, rng),
        ))
    }

    /// Finishes verifying. Then call [`record_use`].
    ///
    /// # Errors
    ///
    /// [`Error::SignInFailed`], including for a counter that went backwards (a possibly
    /// cloned authenticator).
    pub fn finish_authentication(
        &self,
        credential: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, Error> {
        self.webauthn
            .finish_passkey_authentication(credential, state)
            .map_err(|_| Error::SignInFailed)
    }

    /// Starts a passkey sign-in for `user` before any session exists, offering only
    /// `passkeys` (an allow-list, for when the user typed their address first). Bound to the
    /// browser: send the returned binding token as a cookie and finish with
    /// [`Ceremony::into_browser_state`], then
    /// [`finish_authentication`](Self::finish_authentication) against the passkeys of
    /// [`Binding::user`], and report the result as
    /// [`SignInEvent::DiscoverablePasskey`](crate::flow::sign_in::SignInEvent::DiscoverablePasskey).
    ///
    /// Answering differently for addresses without passkeys tells a visitor which addresses
    /// have them; prefer [`start_discoverable`](Self::start_discoverable) where browsers
    /// support it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `no_passkey`, or [`Error::Crypto`].
    #[allow(clippy::type_complexity)]
    pub fn start_sign_in<R: CryptoRng + ?Sized>(
        &self,
        user: UserId,
        passkeys: &[Passkey],
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<
        (
            RequestChallengeResponse,
            Ceremony<PasskeyAuthentication>,
            SecretToken,
        ),
        Error,
    > {
        if passkeys.is_empty() {
            return Err(Error::InvalidRequest("no_passkey"));
        }
        let (challenge, state) = self
            .webauthn
            .start_passkey_authentication(passkeys)
            .map_err(|_| Error::Crypto("webauthn authentication start"))?;
        let (ceremony, token) = browser_ceremony(state, Some(user), now, rng);
        Ok((challenge, ceremony, token))
    }

    /// Starts a passkey sign-in where the browser offers the user's discoverable passkeys.
    /// Bound to the browser like [`start_sign_in`](Self::start_sign_in): send the returned
    /// binding token as a cookie and finish with [`Ceremony::into_browser_state`].
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when webauthn-rs fails.
    #[allow(clippy::type_complexity)]
    pub fn start_discoverable<R: CryptoRng + ?Sized>(
        &self,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<
        (
            RequestChallengeResponse,
            Ceremony<DiscoverableAuthentication>,
            SecretToken,
        ),
        Error,
    > {
        let (challenge, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| Error::Crypto("webauthn discoverable start"))?;
        let (ceremony, token) = browser_ceremony(state, None, now, rng);
        Ok((challenge, ceremony, token))
    }

    /// The account a discoverable assertion claims, from its user handle. Load that
    /// account's passkeys and call [`finish_discoverable`](Self::finish_discoverable).
    ///
    /// # Errors
    ///
    /// [`Error::SignInFailed`] when it names none.
    pub fn identify_discoverable(&self, credential: &PublicKeyCredential) -> Result<UserId, Error> {
        self.webauthn
            .identify_discoverable_authentication(credential)
            .map(|(user, _)| UserId::from_uuid(user))
            .map_err(|_| Error::SignInFailed)
    }

    /// Finishes a discoverable sign-in against the passkeys of `user`, the account
    /// [`identify_discoverable`](Self::identify_discoverable) named. Then call
    /// [`record_use`].
    ///
    /// # Errors
    ///
    /// [`Error::SignInFailed`], also when the assertion's user handle is not `user`.
    pub fn finish_discoverable(
        &self,
        credential: &PublicKeyCredential,
        state: DiscoverableAuthentication,
        user: UserId,
        passkeys: &[Passkey],
    ) -> Result<AuthenticationResult, Error> {
        if self.identify_discoverable(credential)? != user {
            return Err(Error::SignInFailed);
        }
        let keys: Vec<DiscoverableKey> = passkeys.iter().map(DiscoverableKey::from).collect();
        self.webauthn
            .finish_discoverable_authentication(credential, state, &keys)
            .map_err(|_| Error::SignInFailed)
    }
}

/// Updates the passkey that `result` came from and returns its index. `None` means the
/// result is for none of `passkeys`: treat the sign-in as failed. Store the updated passkey
/// and its last-used time.
#[must_use]
pub fn record_use(passkeys: &mut [Passkey], result: &AuthenticationResult) -> Option<usize> {
    passkeys
        .iter_mut()
        .position(|passkey| passkey.update_credential(result).is_some())
}

fn ceremony<S, R: CryptoRng + ?Sized>(
    state: S,
    binding: Binding,
    now: OffsetDateTime,
    rng: &mut R,
) -> Ceremony<S> {
    Ceremony {
        id: CeremonyId::random(rng),
        state,
        binding,
        expires_at: now.saturating_add(CEREMONY_TTL),
    }
}

fn browser_ceremony<S, R: CryptoRng + ?Sized>(
    state: S,
    user: Option<UserId>,
    now: OffsetDateTime,
    rng: &mut R,
) -> (Ceremony<S>, SecretToken) {
    let issued = token::issue(rng);
    let binding = Binding::Browser {
        token_hash: issued.hash,
        user,
    };
    (ceremony(state, binding, now, rng), issued.token)
}
