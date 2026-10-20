use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::audit::AuditKind;
use crate::config::normalize_email;
use crate::error::Error;
use crate::extract::{AnySession, Body, CurrentUser, RecentAuth, is_unsafe, origin_ok, set_cookie};
use crate::service::{Client, Issued, Latchkey, SecondFactor};
use crate::store::{Role, Stage, TokenKind, User};
use crate::totp;

type Result<T, E = Error> = std::result::Result<T, E>;

const DEFAULT_PASSKEY_NAME: &str = "Passkey";
const MAX_NAME_LEN: usize = 100;
const MAX_AUDIT: u32 = 500;

impl Latchkey {
    /// JSON endpoints for every sign-in flow. Nest it under a prefix, e.g.
    /// `Router::new().nest("/auth", latchkey.router())`.
    pub fn router<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        Router::new()
            .route("/setup/status", get(setup_status))
            .route("/setup/start", post(setup_start))
            .route("/setup/redeem", post(setup_redeem))
            .route("/setup/password", post(setup_password))
            .route("/setup/complete", post(setup_complete))
            .route("/invites", post(invite))
            .route("/invites/redeem", post(invite_redeem))
            .route("/me", get(me))
            .route("/sign-in/password", post(sign_in_password))
            .route("/sign-in/code", post(sign_in_code))
            .route(
                "/sign-in/second-factor/passkey/start",
                post(second_factor_passkey_start),
            )
            .route(
                "/sign-in/second-factor/passkey/finish",
                post(second_factor_passkey_finish),
            )
            .route("/sign-in/passkey/start", post(passkey_sign_in_start))
            .route("/sign-in/passkey/finish", post(passkey_sign_in_finish))
            .route("/sign-in/email", post(email_link_request))
            .route("/sign-in/email/redeem", post(email_link_redeem))
            .route("/sign-out", post(sign_out))
            .route("/step-up/password", post(step_up_password))
            .route("/step-up/passkey/start", post(step_up_passkey_start))
            .route("/step-up/passkey/finish", post(step_up_passkey_finish))
            .route("/totp", delete(totp_remove))
            .route("/totp/enrol", post(totp_enrol))
            .route("/totp/confirm", post(totp_confirm))
            .route("/passkeys", get(passkeys_list))
            .route("/passkeys/{id}", delete(passkey_remove))
            .route("/passkeys/register/start", post(passkey_register_start))
            .route("/passkeys/register/finish", post(passkey_register_finish))
            .route("/password", post(password_change))
            .route("/recovery-codes", post(recovery_codes_regenerate))
            .route("/sessions", get(sessions_list))
            .route("/sessions/{id}", delete(session_revoke))
            .route("/audit", get(audit_list))
            .layer(middleware::from_fn_with_state(self.clone(), check_origin))
            .with_state(self.clone())
    }
}

async fn check_origin(State(latchkey): State<Latchkey>, request: Request, next: Next) -> Response {
    if is_unsafe(request.method()) && !origin_ok(&latchkey, request.headers()) {
        return Error::CsrfRejected.into_response();
    }
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

fn rfc3339(at: OffsetDateTime) -> String {
    at.format(&Rfc3339).unwrap_or_default()
}

fn account(user: &User) -> Value {
    json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
    })
}

fn with_session(latchkey: &Latchkey, issued: &Issued, mut body: Value) -> Response {
    if let Some(object) = body.as_object_mut() {
        object.insert("stage".into(), json!(issued.session.stage));
        object.insert("csrf_token".into(), json!(issued.session.csrf_token));
    }
    let max_age = (issued.session.expires_at - issued.session.created_at).whole_seconds();
    let mut headers = HeaderMap::new();
    if let Some(cookie) = set_cookie(latchkey, &issued.token, max_age) {
        headers.insert(header::SET_COOKIE, cookie);
    }
    (headers, Json(body)).into_response()
}

fn accepted() -> Response {
    (StatusCode::ACCEPTED, Json(json!({}))).into_response()
}

fn optional_name(raw: Option<String>) -> Result<Option<String>> {
    match raw.map(|name| name.trim().to_owned()) {
        Some(name) if name.chars().count() > MAX_NAME_LEN => {
            Err(Error::InvalidRequest("name_too_long"))
        }
        Some(name) if name.is_empty() => Ok(None),
        other => Ok(other),
    }
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

#[derive(Deserialize)]
struct EmailBody {
    email: String,
}

#[derive(Deserialize)]
struct SignInBody {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct StepUpBody {
    password: String,
    code: String,
}

#[derive(Deserialize)]
struct AssertionBody {
    ceremony: Uuid,
    credential: PublicKeyCredential,
}

#[derive(Deserialize)]
struct RegistrationBody {
    ceremony: Uuid,
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct NameBody {
    name: Option<String>,
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

async fn setup_status(State(latchkey): State<Latchkey>) -> Result<Json<Value>> {
    let owner = latchkey.store().owner().await?;
    Ok(Json(
        json!({ "setup_required": owner.is_none_or(|owner| !owner.active) }),
    ))
}

async fn setup_start(State(latchkey): State<Latchkey>, client: Client) -> Result<Response> {
    latchkey.limit_ip(&client)?;
    if let Some(owner) = latchkey.store().owner().await?
        && !owner.active
    {
        latchkey
            .send_link(&owner, TokenKind::Setup, &client)
            .await?;
    }
    Ok(accepted())
}

async fn redeem_into_setup(
    latchkey: &Latchkey,
    client: &Client,
    token: &str,
    kind: TokenKind,
) -> Result<Response> {
    latchkey.limit_ip(client)?;
    let user = latchkey
        .redeem(token, kind)
        .await?
        .filter(|user| !user.active)
        .ok_or(Error::SignInFailed)?;
    let issued = latchkey
        .start_session(&user, Stage::Setup, None, client, None)
        .await?;
    Ok(with_session(
        latchkey,
        &issued,
        json!({ "account": account(&user) }),
    ))
}

async fn setup_redeem(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<TokenBody>,
) -> Result<Response> {
    redeem_into_setup(&latchkey, &client, &body.token, TokenKind::Setup).await
}

async fn invite_redeem(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<TokenBody>,
) -> Result<Response> {
    redeem_into_setup(&latchkey, &client, &body.token, TokenKind::Invite).await
}

async fn setup_password(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
    Body(body): Body<PasswordBody>,
) -> Result<Response> {
    let AnySession { user, .. } = session.require(Stage::Setup)?;
    latchkey.set_password(&user, body.password, &client).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn setup_complete(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
) -> Result<Response> {
    let AnySession { user, session } = session.require(Stage::Setup)?;
    if user.password_hash.is_none() {
        return Err(Error::InvalidRequest("password_required"));
    }
    let (totp, passkeys) = latchkey.factor_count(user.id).await?;
    if !totp && passkeys == 0 {
        return Err(Error::InvalidRequest("second_factor_required"));
    }
    latchkey.store().set_active(user.id, true).await?;
    let codes = latchkey.issue_recovery_codes(&user, &client).await?;
    latchkey
        .audit(Some(user.id), AuditKind::SetupCompleted, None, &client)
        .await;
    let issued = latchkey
        .signed_in(&user, "setup", &client, Some(&session))
        .await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "account": account(&user), "recovery_codes": codes }),
    ))
}

async fn invite(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
    Body(body): Body<InviteBody>,
) -> Result<Response> {
    if !current.is_owner() {
        return Err(Error::Forbidden);
    }
    let email = normalize_email(&body.email).ok_or(Error::InvalidRequest("email"))?;
    let display_name = optional_name(body.display_name)?.unwrap_or_else(|| email.clone());
    let user = User {
        id: Uuid::new_v4(),
        email,
        display_name,
        role: Role::Member,
        password_hash: None,
        active: false,
        failed_attempts: 0,
        locked_until: None,
        created_at: latchkey.now(),
    };
    match latchkey.store().create_user(&user).await {
        Err(crate::store::StoreError::Conflict) => return Err(Error::Conflict("email_taken")),
        other => other?,
    }
    latchkey
        .send_link(&user, TokenKind::Invite, &client)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "account": account(&user) })),
    )
        .into_response())
}

async fn me(State(latchkey): State<Latchkey>, session: AnySession) -> Result<Json<Value>> {
    let AnySession { user, session } = session;
    let (totp, passkeys) = latchkey.factor_count(user.id).await?;
    let recovery_codes = latchkey.store().unused_recovery_codes(user.id).await?;
    Ok(Json(json!({
        "account": account(&user),
        "stage": session.stage,
        "csrf_token": session.csrf_token,
        "method": session.method,
        "step_up_until": latchkey.step_up_valid_until(&session).map(rfc3339),
        "factors": {
            "password": user.password_hash.is_some(),
            "totp": totp,
            "passkeys": passkeys,
            "recovery_codes_left": recovery_codes,
        },
    })))
}

async fn sign_in_password(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<SignInBody>,
) -> Result<Response> {
    latchkey.limit_ip(&client)?;
    latchkey.limit_account(body.email.trim().to_lowercase().as_str())?;
    let user = latchkey.find_active(&body.email).await?;
    if let Some(user) = &user {
        latchkey.check_lock(user)?;
    }
    let matched = latchkey
        .verify_password(user.as_ref(), &body.password)
        .await?;
    let Some(user) = user else {
        return Err(Error::SignInFailed);
    };
    if !matched {
        return Err(latchkey.fail(&user, "password", &client).await);
    }
    let (totp, passkeys) = latchkey.factor_count(user.id).await?;
    let issued = latchkey
        .start_session(&user, Stage::SecondFactor, Some("password"), &client, None)
        .await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "second_factor": { "totp": totp, "passkey": passkeys > 0, "recovery_code": true } }),
    ))
}

async fn sign_in_code(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
    Body(body): Body<CodeBody>,
) -> Result<Response> {
    let AnySession { user, session } = session.require(Stage::SecondFactor)?;
    latchkey.limit_ip(&client)?;
    latchkey.limit_account(&user.id.to_string())?;
    latchkey.check_lock(&user)?;
    let method = match latchkey.check_code(&user, &body.code, &client).await? {
        Some(SecondFactor::Totp) => "password+totp",
        Some(SecondFactor::RecoveryCode) => "password+recovery_code",
        None => return Err(latchkey.fail(&user, "code", &client).await),
    };
    let issued = latchkey
        .signed_in(&user, method, &client, Some(&session))
        .await?;
    let left = latchkey.store().unused_recovery_codes(user.id).await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "account": account(&user), "recovery_codes_left": left }),
    ))
}

async fn second_factor_passkey_start(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
) -> Result<Json<Value>> {
    let AnySession { user, session } = session.require(Stage::SecondFactor)?;
    latchkey.limit_ip(&client)?;
    let (ceremony, options) = latchkey.start_verification(&user, &session).await?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

async fn second_factor_passkey_finish(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
    Body(body): Body<AssertionBody>,
) -> Result<Response> {
    let AnySession { user, session } = session.require(Stage::SecondFactor)?;
    latchkey.limit_ip(&client)?;
    latchkey.check_lock(&user)?;
    if !latchkey
        .finish_verification(&user, &session, body.ceremony, &body.credential)
        .await?
    {
        return Err(Error::SignInFailed);
    }
    let issued = latchkey
        .signed_in(&user, "password+passkey", &client, Some(&session))
        .await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "account": account(&user) }),
    ))
}

async fn passkey_sign_in_start(
    State(latchkey): State<Latchkey>,
    client: Client,
) -> Result<Json<Value>> {
    latchkey.limit_ip(&client)?;
    let (ceremony, options) = latchkey.start_discoverable()?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

async fn passkey_sign_in_finish(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<AssertionBody>,
) -> Result<Response> {
    latchkey.limit_ip(&client)?;
    let user = latchkey
        .finish_discoverable(body.ceremony, &body.credential)
        .await?
        .ok_or(Error::SignInFailed)?;
    let issued = latchkey.signed_in(&user, "passkey", &client, None).await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "account": account(&user) }),
    ))
}

async fn email_link_request(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<EmailBody>,
) -> Result<Response> {
    latchkey.limit_ip(&client)?;
    latchkey.limit_account(body.email.trim().to_lowercase().as_str())?;
    if let Some(user) = latchkey.find_active(&body.email).await? {
        latchkey
            .send_link(&user, TokenKind::SignIn, &client)
            .await?;
    }
    Ok(accepted())
}

async fn email_link_redeem(
    State(latchkey): State<Latchkey>,
    client: Client,
    Body(body): Body<TokenBody>,
) -> Result<Response> {
    latchkey.limit_ip(&client)?;
    let user = latchkey
        .redeem(&body.token, TokenKind::SignIn)
        .await?
        .filter(|user| user.active)
        .ok_or(Error::SignInFailed)?;
    let issued = latchkey
        .signed_in(&user, "email_link", &client, None)
        .await?;
    Ok(with_session(
        &latchkey,
        &issued,
        json!({ "account": account(&user) }),
    ))
}

async fn sign_out(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
) -> Result<Response> {
    latchkey
        .store()
        .delete_session(&session.session.token_hash)
        .await?;
    latchkey
        .audit(Some(session.user.id), AuditKind::SignOut, None, &client)
        .await;
    let mut headers = HeaderMap::new();
    if let Some(cookie) = set_cookie(&latchkey, "", 0) {
        headers.insert(header::SET_COOKIE, cookie);
    }
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

async fn stepped_up(
    latchkey: &Latchkey,
    current: &CurrentUser,
    client: &Client,
) -> Result<Json<Value>> {
    let now = latchkey.now();
    latchkey
        .store()
        .set_session_authenticated(&current.session.token_hash, now, "step_up")
        .await?;
    latchkey
        .audit(Some(current.user.id), AuditKind::StepUp, None, client)
        .await;
    let until = now.saturating_add(latchkey.config().step_up_window);
    Ok(Json(json!({ "step_up_until": rfc3339(until) })))
}

async fn step_up_password(
    State(latchkey): State<Latchkey>,
    client: Client,
    current: CurrentUser,
    Body(body): Body<StepUpBody>,
) -> Result<Json<Value>> {
    latchkey.limit_ip(&client)?;
    latchkey.limit_account(&current.user.id.to_string())?;
    latchkey.check_lock(&current.user)?;
    if !latchkey
        .verify_password(Some(&current.user), &body.password)
        .await?
    {
        return Err(latchkey
            .fail(&current.user, "step_up_password", &client)
            .await);
    }
    if latchkey
        .check_code(&current.user, &body.code, &client)
        .await?
        .is_none()
    {
        return Err(latchkey.fail(&current.user, "step_up_code", &client).await);
    }
    latchkey.store().clear_failures(current.user.id).await?;
    stepped_up(&latchkey, &current, &client).await
}

async fn step_up_passkey_start(
    State(latchkey): State<Latchkey>,
    client: Client,
    current: CurrentUser,
) -> Result<Json<Value>> {
    latchkey.limit_ip(&client)?;
    let (ceremony, options) = latchkey
        .start_verification(&current.user, &current.session)
        .await?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

async fn step_up_passkey_finish(
    State(latchkey): State<Latchkey>,
    client: Client,
    current: CurrentUser,
    Body(body): Body<AssertionBody>,
) -> Result<Json<Value>> {
    latchkey.limit_ip(&client)?;
    if !latchkey
        .finish_verification(
            &current.user,
            &current.session,
            body.ceremony,
            &body.credential,
        )
        .await?
    {
        return Err(Error::SignInFailed);
    }
    stepped_up(&latchkey, &current, &client).await
}

async fn enrolling(latchkey: &Latchkey, session: AnySession) -> Result<AnySession> {
    match session.session.stage {
        Stage::Setup => Ok(session),
        Stage::Full if latchkey.step_up_valid_until(&session.session).is_some() => Ok(session),
        Stage::Full => Err(Error::StepUpRequired),
        Stage::SecondFactor => Err(Error::Unauthorized),
    }
}

async fn totp_enrol(State(latchkey): State<Latchkey>, session: AnySession) -> Result<Json<Value>> {
    let AnySession { user, .. } = enrolling(&latchkey, session).await?;
    let secret = totp::new_secret();
    let enrolment = totp::enrolment(&secret, &latchkey.config().rp_name, &user.email)?;
    let sealed = latchkey.seal_totp(user.id, &secret)?;
    latchkey.store().set_pending_totp(user.id, &sealed).await?;
    Ok(Json(json!({
        "secret": enrolment.secret_base32,
        "otpauth_url": enrolment.otpauth_url,
    })))
}

async fn totp_confirm(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
    Body(body): Body<CodeBody>,
) -> Result<Response> {
    let AnySession { user, .. } = enrolling(&latchkey, session).await?;
    latchkey.limit_account(&user.id.to_string())?;
    let pending = latchkey
        .store()
        .totp(user.id)
        .await?
        .and_then(|record| record.pending_secret)
        .ok_or(Error::InvalidRequest("no_pending_totp"))?;
    let pending = latchkey.open_totp(user.id, &pending)?;
    let step = totp::matched_step(&pending, &body.code, latchkey.now())
        .ok_or(Error::InvalidRequest("code_rejected"))?;
    if !latchkey.store().confirm_totp(user.id, step).await? {
        return Err(Error::InvalidRequest("no_pending_totp"));
    }
    latchkey
        .audit(Some(user.id), AuditKind::TotpEnrolled, None, &client)
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn totp_remove(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
) -> Result<Response> {
    let (totp, passkeys) = latchkey.factor_count(current.user.id).await?;
    if !totp {
        return Err(Error::NotFound);
    }
    if passkeys == 0 {
        return Err(Error::Conflict("last_factor"));
    }
    latchkey.store().delete_totp(current.user.id).await?;
    latchkey
        .audit(Some(current.user.id), AuditKind::TotpRemoved, None, &client)
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn passkeys_list(
    State(latchkey): State<Latchkey>,
    current: CurrentUser,
) -> Result<Json<Value>> {
    let passkeys = latchkey.store().passkeys_for(current.user.id).await?;
    Ok(Json(json!({
        "passkeys": passkeys.iter().map(|passkey| json!({
            "id": passkey.id,
            "name": passkey.name,
            "created_at": rfc3339(passkey.created_at),
            "last_used_at": passkey.last_used_at.map(rfc3339),
        })).collect::<Vec<_>>(),
    })))
}

async fn passkey_register_start(
    State(latchkey): State<Latchkey>,
    session: AnySession,
    Body(body): Body<NameBody>,
) -> Result<Json<Value>> {
    let AnySession { user, session } = enrolling(&latchkey, session).await?;
    let name = optional_name(body.name)?.unwrap_or_else(|| DEFAULT_PASSKEY_NAME.to_owned());
    let (ceremony, options) = latchkey.start_registration(&user, &session, name).await?;
    Ok(Json(json!({ "ceremony": ceremony, "options": options })))
}

async fn passkey_register_finish(
    State(latchkey): State<Latchkey>,
    client: Client,
    session: AnySession,
    Body(body): Body<RegistrationBody>,
) -> Result<Response> {
    let AnySession { user, session } = enrolling(&latchkey, session).await?;
    let record = latchkey
        .finish_registration(&user, &session, body.ceremony, &body.credential, &client)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": record.id, "name": record.name })),
    )
        .into_response())
}

async fn passkey_remove(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    let (totp, passkeys) = latchkey.factor_count(current.user.id).await?;
    if !totp && passkeys <= 1 {
        return Err(Error::Conflict("last_factor"));
    }
    if !latchkey.store().delete_passkey(current.user.id, id).await? {
        return Err(Error::NotFound);
    }
    latchkey
        .audit(
            Some(current.user.id),
            AuditKind::PasskeyRemoved,
            None,
            &client,
        )
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn password_change(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
    Body(body): Body<PasswordBody>,
) -> Result<Response> {
    latchkey
        .set_password(&current.user, body.password, &client)
        .await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn recovery_codes_regenerate(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
) -> Result<Json<Value>> {
    let codes = latchkey
        .issue_recovery_codes(&current.user, &client)
        .await?;
    Ok(Json(json!({ "recovery_codes": codes })))
}

async fn sessions_list(
    State(latchkey): State<Latchkey>,
    current: CurrentUser,
) -> Result<Json<Value>> {
    let sessions = latchkey
        .store()
        .sessions_for(current.user.id, latchkey.now())
        .await?;
    Ok(Json(json!({
        "sessions": sessions.iter().filter(|s| s.stage == Stage::Full).map(|session| json!({
            "id": session.id,
            "current": session.id == current.session.id,
            "method": session.method,
            "created_at": rfc3339(session.created_at),
            "expires_at": rfc3339(session.expires_at),
            "user_agent": session.user_agent,
            "ip": session.ip,
        })).collect::<Vec<_>>(),
    })))
}

async fn session_revoke(
    State(latchkey): State<Latchkey>,
    client: Client,
    RecentAuth(current): RecentAuth,
    Path(id): Path<Uuid>,
) -> Result<Response> {
    if !latchkey
        .store()
        .delete_session_by_id(current.user.id, id)
        .await?
    {
        return Err(Error::NotFound);
    }
    latchkey
        .audit(
            Some(current.user.id),
            AuditKind::SessionRevoked,
            Some(id.to_string()),
            &client,
        )
        .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn audit_list(
    State(latchkey): State<Latchkey>,
    current: CurrentUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>> {
    let limit = query.limit.unwrap_or(100).clamp(1, MAX_AUDIT);
    let scope = (!current.is_owner()).then_some(current.user.id);
    let events = latchkey.store().audit(scope, limit).await?;
    Ok(Json(json!({ "events": events })))
}
