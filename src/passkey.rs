//! Passkeys through [`webauthn_rs`], with user verification required.
//!
//! Every ceremony has two steps, as in webauthn-rs: `start_*` returns the challenge JSON for
//! the browser and a [`Ceremony`] holding the server-side state; `finish_*` consumes the
//! state. Store the ceremony (it is `Serialize`) under its [`id`](Ceremony::id), hand the id
//! to the client, and on finish **remove** it before use: ceremonies are single use. A
//! ceremony is bound to the session (and account) that started it and expires after
//! [`CEREMONY_TTL`]; [`Ceremony::into_state`] checks both.
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

pub use webauthn_rs;

/// How long a ceremony stays valid.
pub const CEREMONY_TTL: Duration = Duration::minutes(5);

/// A pending ceremony: the webauthn-rs state `S` plus what it is bound to.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[must_use = "store the ceremony to finish it later"]
pub struct Ceremony<S> {
    id: CeremonyId,
    state: S,
    session: Option<SessionId>,
    user: Option<UserId>,
    expires_at: OffsetDateTime,
}

impl<S> Ceremony<S> {
    /// The id to store it under and give the client.
    #[must_use]
    pub fn id(&self) -> CeremonyId {
        self.id
    }

    /// When it stops working.
    #[must_use]
    pub fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// The webauthn-rs state, if the ceremony is unexpired and was started by `session` for
    /// `user` (both `None` for discoverable sign-in). Consumes the ceremony.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRequest`] with `unknown_ceremony`.
    pub fn into_state(
        self,
        session: Option<SessionId>,
        user: Option<UserId>,
        now: OffsetDateTime,
    ) -> Result<S, Error> {
        if self.expires_at <= now || self.session != session || self.user != user {
            return Err(Error::InvalidRequest("unknown_ceremony"));
        }
        Ok(self.state)
    }
}

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
            ceremony(state, Some(session), Some(user), now, rng),
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
            ceremony(state, Some(session), Some(user), now, rng),
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

    /// Starts a passkey sign-in where the browser offers the user's discoverable passkeys.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when webauthn-rs fails.
    pub fn start_discoverable<R: CryptoRng + ?Sized>(
        &self,
        now: OffsetDateTime,
        rng: &mut R,
    ) -> Result<
        (
            RequestChallengeResponse,
            Ceremony<DiscoverableAuthentication>,
        ),
        Error,
    > {
        let (challenge, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| Error::Crypto("webauthn discoverable start"))?;
        Ok((challenge, ceremony(state, None, None, now, rng)))
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
    session: Option<SessionId>,
    user: Option<UserId>,
    now: OffsetDateTime,
    rng: &mut R,
) -> Ceremony<S> {
    Ceremony {
        id: CeremonyId::random(rng),
        state,
        session,
        user,
        expires_at: now.saturating_add(CEREMONY_TTL),
    }
}
