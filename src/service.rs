use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, DiscoverableKey, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::audit::AuditKind;
use crate::ceremony::{Ceremonies, Ceremony};
use crate::clock::{Clock, SystemClock};
use crate::config::{Config, normalize_email};
use crate::crypto::{self, hmac_hex, issue_token};
use crate::error::Error;
use crate::limiter::RateLimiter;
use crate::mail::{Mail, MailKind, Mailer};
use crate::password::{self, Hasher};
use crate::recovery;
use crate::seal::{self, Aad, DataKey, Stored};
use crate::store::{
    NewAuditEvent, OneTimeToken, PasskeyRecord, Role, Session, Stage, Store, TokenKind, User,
};
use crate::totp;

/// The sign-in service. Cheap to clone; hand it to [`Latchkey::router`] and to the app state
/// so the [`CurrentUser`](crate::CurrentUser) and [`RecentAuth`](crate::RecentAuth) extractors
/// can find it.
#[derive(Clone)]
pub struct Latchkey {
    pub(crate) inner: Arc<Inner>,
}

pub(crate) struct Inner {
    pub(crate) config: Config,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) mailer: Arc<dyn Mailer>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) hasher: Hasher,
    pub(crate) webauthn: Webauthn,
    pub(crate) ceremonies: Ceremonies,
    pub(crate) limiter: RateLimiter,
    pub(crate) data_key: DataKey,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Client {
    pub(crate) ip: Option<String>,
    pub(crate) user_agent: Option<String>,
}

pub(crate) struct Issued {
    pub(crate) token: String,
    pub(crate) session: Session,
}

pub(crate) enum SecondFactor {
    Totp,
    RecoveryCode,
}

impl std::fmt::Debug for Latchkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Latchkey")
            .field("origin", &self.inner.config.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl Latchkey {
    /// Validates the configuration and creates the owner account if there is none yet.
    pub async fn new(
        config: Config,
        store: Arc<dyn Store>,
        mailer: Arc<dyn Mailer>,
    ) -> Result<Self, Error> {
        Self::with_clock(config, store, mailer, Arc::new(SystemClock)).await
    }

    pub async fn with_clock(
        config: Config,
        store: Arc<dyn Store>,
        mailer: Arc<dyn Mailer>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.origin)
            .and_then(|builder| builder.rp_name(&config.rp_name).build())
            .map_err(|_| Error::Config("rp_id does not match the origin"))?;
        let hasher = Hasher::new(config.password).await?;
        let data_key = DataKey::new(&config.data_key);
        let latchkey = Self {
            inner: Arc::new(Inner {
                config,
                store,
                mailer,
                clock,
                hasher,
                webauthn,
                ceremonies: Ceremonies::default(),
                limiter: RateLimiter::default(),
                data_key,
            }),
        };
        check_sealed(&latchkey.inner.data_key, latchkey.inner.store.as_ref()).await?;
        latchkey.ensure_owner().await?;
        Ok(latchkey)
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.inner.store
    }

    pub(crate) fn now(&self) -> OffsetDateTime {
        self.inner.clock.now()
    }

    async fn ensure_owner(&self) -> Result<(), Error> {
        if self.inner.store.owner().await?.is_some() {
            return Ok(());
        }
        let config = &self.inner.config;
        let owner = User {
            id: Uuid::new_v4(),
            email: config.owner_email.clone(),
            display_name: config.owner_name.clone(),
            role: Role::Owner,
            password_hash: None,
            active: false,
            failed_attempts: 0,
            locked_until: None,
            created_at: self.now(),
        };
        match self.inner.store.create_user(&owner).await {
            Ok(()) | Err(crate::store::StoreError::Conflict) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Wipes the owner's password, factors and sessions so first-open setup runs again.
    /// Meant for a lost-everything recovery from a shell on the server.
    pub async fn reset_owner(&self) -> Result<(), Error> {
        let owner = self.inner.store.owner().await?.ok_or(Error::NotFound)?;
        self.inner.store.reset_user(owner.id).await?;
        self.audit(
            Some(owner.id),
            AuditKind::OwnerReset,
            None,
            &Client::default(),
        )
        .await;
        Ok(())
    }

    /// Encrypts TOTP secrets and passkeys that an earlier version stored in plaintext. Run it
    /// once, before [`Latchkey::new`], which refuses to start while plaintext rows remain.
    /// Returns how many values it encrypted; values that are already encrypted are skipped,
    /// so running it again is harmless.
    pub async fn encrypt_plaintext_secrets(
        config: &Config,
        store: &dyn Store,
    ) -> Result<usize, Error> {
        config.validate()?;
        let key = DataKey::new(&config.data_key);
        let mut encrypted = 0;
        for (user, record) in store.all_totp().await? {
            let aad = Aad::Totp { user };
            let mut changed = false;
            let mut reseal = |value: Option<Vec<u8>>| -> Result<Option<Vec<u8>>, Error> {
                match value {
                    Some(plain) if seal::classify_bytes(&plain) == Stored::Plaintext => {
                        changed = true;
                        encrypted += 1;
                        key.seal_bytes(&aad, &plain).map(Some)
                    }
                    other => Ok(other),
                }
            };
            let secret = reseal(record.secret)?;
            let pending = reseal(record.pending_secret)?;
            if changed {
                store
                    .set_totp_secrets(user, secret.as_deref(), pending.as_deref())
                    .await?;
            }
        }
        for record in store.all_passkeys().await? {
            if seal::classify_text(&record.data) == Stored::Plaintext {
                let aad = Aad::Passkey {
                    user: record.user_id,
                    passkey: record.id,
                };
                let sealed = key.seal_text(&aad, &record.data)?;
                store.set_passkey_data(record.id, &sealed).await?;
                encrypted += 1;
            }
        }
        check_sealed(&key, store).await?;
        Ok(encrypted)
    }

    /// Deletes expired sessions and links; run it now and then.
    pub async fn purge_expired(&self) -> Result<(), Error> {
        Ok(self.inner.store.purge_expired(self.now()).await?)
    }

    pub(crate) fn ip_tag(&self, client: &Client) -> Option<String> {
        client
            .ip
            .as_deref()
            .map(|ip| hmac_hex(&self.inner.config.secret_key, ip.as_bytes()))
    }

    pub(crate) async fn audit(
        &self,
        user: Option<Uuid>,
        kind: AuditKind,
        detail: Option<String>,
        client: &Client,
    ) {
        let event = NewAuditEvent {
            at: self.now(),
            user_id: user,
            kind: kind.as_str().to_owned(),
            detail,
            ip: self.ip_tag(client),
        };
        if let Err(err) = self.inner.store.append_audit(&event).await {
            tracing::error!(error = %err, kind = kind.as_str(), "audit event lost");
        }
    }

    pub(crate) fn limit_ip(&self, client: &Client) -> Result<(), Error> {
        let key = format!("ip:{}", client.ip.as_deref().unwrap_or("unknown"));
        let limit = self.inner.config.rate_limits.per_ip_per_minute;
        match self.inner.limiter.hit(&key, limit, self.now()) {
            Some(retry_after_secs) => Err(Error::TooManyAttempts { retry_after_secs }),
            None => Ok(()),
        }
    }

    pub(crate) fn limit_account(&self, account: &str) -> Result<(), Error> {
        let key = format!("account:{account}");
        let limit = self.inner.config.rate_limits.per_account_per_minute;
        match self.inner.limiter.hit(&key, limit, self.now()) {
            Some(retry_after_secs) => Err(Error::TooManyAttempts { retry_after_secs }),
            None => Ok(()),
        }
    }

    pub(crate) fn check_lock(&self, user: &User) -> Result<(), Error> {
        match user.locked_until {
            Some(until) if until > self.now() => Err(Error::TooManyAttempts {
                retry_after_secs: u64::try_from((until - self.now()).whole_seconds())
                    .unwrap_or(1)
                    .max(1),
            }),
            _ => Ok(()),
        }
    }

    pub(crate) async fn fail(&self, user: &User, method: &str, client: &Client) -> Error {
        self.audit(
            Some(user.id),
            AuditKind::SignInFailed,
            Some(method.to_owned()),
            client,
        )
        .await;
        let failures = match self.inner.store.add_failure(user.id).await {
            Ok(failures) => failures,
            Err(err) => return err.into(),
        };
        if let Some(lock) = self.inner.config.lockout.lock_for(failures) {
            let until = self.now().saturating_add(lock);
            if let Err(err) = self
                .inner
                .store
                .set_locked_until(user.id, Some(until))
                .await
            {
                return err.into();
            }
            self.audit(
                Some(user.id),
                AuditKind::Lockout,
                Some(format!("{}s", lock.whole_seconds())),
                client,
            )
            .await;
        }
        Error::SignInFailed
    }

    pub(crate) async fn start_session(
        &self,
        user: &User,
        stage: Stage,
        method: Option<&str>,
        client: &Client,
        replaces: Option<&Session>,
    ) -> Result<Issued, Error> {
        let config = &self.inner.config;
        let now = self.now();
        let ttl = match stage {
            Stage::Full => config.session_ttl,
            Stage::SecondFactor => config.pending_ttl,
            Stage::Setup => config.setup_ttl,
        };
        let issued = issue_token();
        let session = Session {
            id: Uuid::new_v4(),
            token_hash: issued.hash,
            user_id: user.id,
            stage,
            csrf_token: issue_token().token,
            method: method.map(str::to_owned),
            created_at: now,
            expires_at: now.saturating_add(ttl),
            authenticated_at: (stage == Stage::Full).then_some(now),
            ip: self.ip_tag(client),
            user_agent: client.user_agent.clone(),
        };
        match replaces {
            Some(old) => {
                self.inner
                    .store
                    .replace_session(&old.token_hash, &session)
                    .await?
            }
            None => self.inner.store.insert_session(&session).await?,
        }
        Ok(Issued {
            token: issued.token,
            session,
        })
    }

    pub(crate) async fn signed_in(
        &self,
        user: &User,
        method: &str,
        client: &Client,
        replaces: Option<&Session>,
    ) -> Result<Issued, Error> {
        self.inner.store.clear_failures(user.id).await?;
        let issued = self
            .start_session(user, Stage::Full, Some(method), client, replaces)
            .await?;
        self.audit(
            Some(user.id),
            AuditKind::SignIn,
            Some(method.to_owned()),
            client,
        )
        .await;
        Ok(issued)
    }

    /// Issues a one-time link and mails it from a background task, so the response time does
    /// not depend on the mail provider.
    pub(crate) async fn send_link(
        &self,
        user: &User,
        kind: TokenKind,
        client: &Client,
    ) -> Result<(), Error> {
        let config = &self.inner.config;
        let now = self.now();
        if kind != TokenKind::Invite
            && let Some(last) = self.inner.store.latest_token_at(user.id, kind).await?
            && last.saturating_add(config.resend_cooldown) > now
        {
            return Ok(());
        }
        let (ttl, mut link, mail_kind, audit_kind) = match kind {
            TokenKind::Setup => (
                config.link_ttl,
                config.setup_url.clone(),
                MailKind::Setup,
                AuditKind::SetupLinkSent,
            ),
            TokenKind::SignIn => (
                config.link_ttl,
                config.sign_in_link_url.clone(),
                MailKind::SignInLink,
                AuditKind::SignInLinkSent,
            ),
            TokenKind::Invite => (
                config.invite_ttl,
                config.invite_url.clone(),
                MailKind::Invite,
                AuditKind::InviteSent,
            ),
        };
        let issued = issue_token();
        let expires_at = now.saturating_add(ttl);
        self.inner
            .store
            .insert_token(&OneTimeToken {
                hash: issued.hash,
                kind,
                user_id: user.id,
                created_at: now,
                expires_at,
            })
            .await?;
        link.query_pairs_mut().append_pair("token", &issued.token);
        let mail = Mail {
            kind: mail_kind,
            to: user.email.clone(),
            link,
            expires_at,
        };
        let mailer = Arc::clone(&self.inner.mailer);
        tokio::spawn(async move {
            if let Err(err) = mailer.send(mail).await {
                tracing::error!(error = %err, "latchkey mail not sent");
            }
        });
        self.audit(Some(user.id), audit_kind, None, client).await;
        Ok(())
    }

    pub(crate) async fn redeem(&self, token: &str, kind: TokenKind) -> Result<Option<User>, Error> {
        let Some(hash) = crypto::token_hash(token) else {
            return Ok(None);
        };
        let Some(user_id) = self
            .inner
            .store
            .consume_token(&hash, kind, self.now())
            .await?
        else {
            return Ok(None);
        };
        Ok(self.inner.store.user_by_id(user_id).await?)
    }

    pub(crate) async fn find_active(&self, email: &str) -> Result<Option<User>, Error> {
        let Some(email) = normalize_email(email) else {
            return Ok(None);
        };
        Ok(self
            .inner
            .store
            .user_by_email(&email)
            .await?
            .filter(|user| user.active))
    }

    pub(crate) async fn verify_password(
        &self,
        user: Option<&User>,
        password: &str,
    ) -> Result<bool, Error> {
        let stored = user.and_then(|user| user.password_hash.as_deref());
        if password.len() > password::MAX_LEN * 4 {
            self.inner.hasher.verify("", None).await?;
            return Ok(false);
        }
        self.inner.hasher.verify(password, stored).await
    }

    pub(crate) async fn set_password(
        &self,
        user: &User,
        password: String,
        client: &Client,
    ) -> Result<(), Error> {
        password::check_policy(&password)?;
        let hash = self.inner.hasher.hash(password).await?;
        self.inner.store.set_password(user.id, &hash).await?;
        self.audit(Some(user.id), AuditKind::PasswordSet, None, client)
            .await;
        Ok(())
    }

    /// Checks a TOTP or recovery code and consumes it; `None` means it was rejected.
    pub(crate) async fn check_code(
        &self,
        user: &User,
        code: &str,
        client: &Client,
    ) -> Result<Option<SecondFactor>, Error> {
        if totp::looks_like_totp(code) {
            let Some(stored) = self
                .inner
                .store
                .totp(user.id)
                .await?
                .and_then(|record| record.secret)
            else {
                return Ok(None);
            };
            let secret = self.open_totp(user.id, &stored)?;
            let Some(step) = totp::matched_step(&secret, code, self.now()) else {
                return Ok(None);
            };
            let fresh = self.inner.store.use_totp_step(user.id, step).await?;
            return Ok(fresh.then_some(SecondFactor::Totp));
        }
        let Some(hash) = recovery::hash(code) else {
            return Ok(None);
        };
        let used = self
            .inner
            .store
            .use_recovery_code(user.id, &hash, self.now())
            .await?;
        if !used {
            return Ok(None);
        }
        self.audit(Some(user.id), AuditKind::RecoveryCodeUsed, None, client)
            .await;
        Ok(Some(SecondFactor::RecoveryCode))
    }

    pub(crate) async fn has_totp(&self, user: Uuid) -> Result<bool, Error> {
        Ok(self
            .inner
            .store
            .totp(user)
            .await?
            .is_some_and(|record| record.secret.is_some()))
    }

    pub(crate) async fn issue_recovery_codes(
        &self,
        user: &User,
        client: &Client,
    ) -> Result<Vec<String>, Error> {
        let codes = recovery::generate();
        let hashes: Vec<Vec<u8>> = codes
            .iter()
            .filter_map(|code| recovery::hash(code))
            .collect();
        self.inner
            .store
            .replace_recovery_codes(user.id, &hashes)
            .await?;
        self.audit(Some(user.id), AuditKind::RecoveryCodesIssued, None, client)
            .await;
        Ok(codes)
    }

    pub(crate) fn seal_totp(&self, user: Uuid, secret: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.data_key.seal_bytes(&Aad::Totp { user }, secret)
    }

    pub(crate) fn open_totp(&self, user: Uuid, stored: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .data_key
            .open_bytes(&Aad::Totp { user }, stored)
            .ok_or_else(|| Error::Internal("a TOTP secret does not decrypt".into()))
    }

    fn seal_passkey(&self, user: Uuid, id: Uuid, passkey: &Passkey) -> Result<String, Error> {
        let json = serde_json::to_string(passkey).map_err(Error::internal)?;
        self.inner
            .data_key
            .seal_text(&Aad::Passkey { user, passkey: id }, &json)
    }

    fn passkeys_of(&self, records: &[PasskeyRecord]) -> Result<Vec<(Uuid, Passkey)>, Error> {
        records
            .iter()
            .map(|record| {
                let aad = Aad::Passkey {
                    user: record.user_id,
                    passkey: record.id,
                };
                let json = self
                    .inner
                    .data_key
                    .open_text(&aad, &record.data)
                    .ok_or_else(|| Error::Internal("a passkey does not decrypt".into()))?;
                let passkey = serde_json::from_str::<Passkey>(&json).map_err(Error::internal)?;
                Ok((record.id, passkey))
            })
            .collect()
    }

    pub(crate) async fn start_registration(
        &self,
        user: &User,
        session: &Session,
        name: String,
    ) -> Result<(Uuid, CreationChallengeResponse), Error> {
        let existing = self.inner.store.passkeys_for(user.id).await?;
        let exclude = self
            .passkeys_of(&existing)?
            .into_iter()
            .map(|(_, passkey)| passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let (options, state) = self
            .inner
            .webauthn
            .start_passkey_registration(user.id, &user.email, &user.display_name, Some(exclude))
            .map_err(Error::internal)?;
        let ceremony = self.inner.ceremonies.insert(
            Ceremony::Register {
                session: session.id,
                user: user.id,
                name,
                state,
            },
            self.now(),
        );
        Ok((ceremony, options))
    }

    pub(crate) async fn finish_registration(
        &self,
        user: &User,
        session: &Session,
        ceremony: Uuid,
        credential: &RegisterPublicKeyCredential,
        client: &Client,
    ) -> Result<PasskeyRecord, Error> {
        let Some(Ceremony::Register {
            session: bound_session,
            user: bound_user,
            name,
            state,
        }) = self.inner.ceremonies.take(ceremony, self.now())
        else {
            return Err(Error::InvalidRequest("unknown_ceremony"));
        };
        if bound_session != session.id || bound_user != user.id {
            return Err(Error::InvalidRequest("unknown_ceremony"));
        }
        let passkey = self
            .inner
            .webauthn
            .finish_passkey_registration(credential, &state)
            .map_err(|_| Error::InvalidRequest("passkey_rejected"))?;
        let id = Uuid::new_v4();
        let record = PasskeyRecord {
            id,
            user_id: user.id,
            credential_id: passkey.cred_id().to_vec(),
            name,
            data: self.seal_passkey(user.id, id, &passkey)?,
            created_at: self.now(),
            last_used_at: None,
        };
        match self.inner.store.add_passkey(&record).await {
            Err(crate::store::StoreError::Conflict) => {
                return Err(Error::Conflict("passkey_exists"));
            }
            other => other?,
        }
        self.audit(
            Some(user.id),
            AuditKind::PasskeyAdded,
            Some(record.name.clone()),
            client,
        )
        .await;
        Ok(record)
    }

    pub(crate) async fn start_verification(
        &self,
        user: &User,
        session: &Session,
    ) -> Result<(Uuid, RequestChallengeResponse), Error> {
        let records = self.inner.store.passkeys_for(user.id).await?;
        let passkeys: Vec<Passkey> = self
            .passkeys_of(&records)?
            .into_iter()
            .map(|(_, passkey)| passkey)
            .collect();
        if passkeys.is_empty() {
            return Err(Error::InvalidRequest("no_passkey"));
        }
        let (options, state) = self
            .inner
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(Error::internal)?;
        let ceremony = self.inner.ceremonies.insert(
            Ceremony::Verify {
                session: session.id,
                user: user.id,
                state,
            },
            self.now(),
        );
        Ok((ceremony, options))
    }

    pub(crate) async fn finish_verification(
        &self,
        user: &User,
        session: &Session,
        ceremony: Uuid,
        credential: &PublicKeyCredential,
    ) -> Result<bool, Error> {
        let Some(Ceremony::Verify {
            session: bound_session,
            user: bound_user,
            state,
        }) = self.inner.ceremonies.take(ceremony, self.now())
        else {
            return Ok(false);
        };
        if bound_session != session.id || bound_user != user.id {
            return Ok(false);
        }
        let Ok(result) = self
            .inner
            .webauthn
            .finish_passkey_authentication(credential, &state)
        else {
            return Ok(false);
        };
        self.record_passkey_use(user.id, &result).await
    }

    async fn record_passkey_use(
        &self,
        user: Uuid,
        result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Result<bool, Error> {
        let records = self.inner.store.passkeys_for(user).await?;
        for (id, mut passkey) in self.passkeys_of(&records)? {
            if passkey.update_credential(result).is_some() {
                let data = self.seal_passkey(user, id, &passkey)?;
                self.inner
                    .store
                    .update_passkey(id, &data, self.now())
                    .await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn start_discoverable(&self) -> Result<(Uuid, RequestChallengeResponse), Error> {
        let (options, state) = self
            .inner
            .webauthn
            .start_discoverable_authentication()
            .map_err(Error::internal)?;
        let ceremony = self
            .inner
            .ceremonies
            .insert(Ceremony::Discoverable { state }, self.now());
        Ok((ceremony, options))
    }

    pub(crate) async fn finish_discoverable(
        &self,
        ceremony: Uuid,
        credential: &PublicKeyCredential,
    ) -> Result<Option<User>, Error> {
        let Some(Ceremony::Discoverable { state }) =
            self.inner.ceremonies.take(ceremony, self.now())
        else {
            return Ok(None);
        };
        let Ok((user_id, _)) = self
            .inner
            .webauthn
            .identify_discoverable_authentication(credential)
        else {
            return Ok(None);
        };
        let Some(user) = self
            .inner
            .store
            .user_by_id(user_id)
            .await?
            .filter(|user| user.active)
        else {
            return Ok(None);
        };
        let records = self.inner.store.passkeys_for(user.id).await?;
        let keys: Vec<DiscoverableKey> = self
            .passkeys_of(&records)?
            .iter()
            .map(|(_, passkey)| DiscoverableKey::from(passkey))
            .collect();
        let Ok(result) = self
            .inner
            .webauthn
            .finish_discoverable_authentication(credential, state, &keys)
        else {
            return Ok(None);
        };
        Ok(self
            .record_passkey_use(user.id, &result)
            .await?
            .then_some(user))
    }

    pub(crate) async fn factor_count(&self, user: Uuid) -> Result<(bool, usize), Error> {
        let totp = self.has_totp(user).await?;
        let passkeys = self.inner.store.passkeys_for(user).await?.len();
        Ok((totp, passkeys))
    }

    pub(crate) fn step_up_valid_until(&self, session: &Session) -> Option<OffsetDateTime> {
        session
            .authenticated_at
            .map(|at| at.saturating_add(self.inner.config.step_up_window))
            .filter(|until| *until > self.now())
    }
}

/// Refuses to run on plaintext factors or on factors sealed under another data key.
async fn check_sealed(key: &DataKey, store: &dyn Store) -> Result<(), Error> {
    const PLAINTEXT: Error = Error::Config(
        "the store holds unencrypted TOTP secrets or passkeys; run \
         Latchkey::encrypt_plaintext_secrets once before starting",
    );
    const WRONG_KEY: Error = Error::Config(
        "stored TOTP secrets or passkeys do not decrypt with the configured data key",
    );
    for (user, record) in store.all_totp().await? {
        let aad = Aad::Totp { user };
        for value in [record.secret, record.pending_secret].into_iter().flatten() {
            if seal::classify_bytes(&value) == Stored::Plaintext {
                return Err(PLAINTEXT);
            }
            if key.open_bytes(&aad, &value).is_none() {
                return Err(WRONG_KEY);
            }
        }
    }
    for record in store.all_passkeys().await? {
        if seal::classify_text(&record.data) == Stored::Plaintext {
            return Err(PLAINTEXT);
        }
        let aad = Aad::Passkey {
            user: record.user_id,
            passkey: record.id,
        };
        if key.open_text(&aad, &record.data).is_none() {
            return Err(WRONG_KEY);
        }
    }
    Ok(())
}
