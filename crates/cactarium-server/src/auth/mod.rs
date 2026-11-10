//! Sessions, CSRF and the user extractors.
//!
//! A session is a random 256-bit token in an HttpOnly cookie; the database keeps only its sha256.
//! Every state-changing form carries the session's CSRF token, and the CSRF middleware also checks
//! `Origin` / `Sec-Fetch-Site` on every unsafe request outside the token-authenticated API.

pub mod oauth;

use axum::extract::FromRequestParts;
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};

use crate::error::{AppError, AppResult};
use crate::state::AppState;

const IDLE: Duration = Duration::days(14);
const TOUCH_EVERY: Duration = Duration::minutes(5);

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub trusted: bool,
    pub banned: bool,
    /// The organizations the user belongs to (any role).
    pub orgs: Vec<String>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "superadmin")
    }

    pub fn is_superadmin(&self) -> bool {
        self.role == "superadmin"
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub token_hash: Vec<u8>,
    pub csrf: String,
    pub data: serde_json::Value,
    pub user: Option<User>,
}

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

pub fn cookie_name(state: &AppState) -> &'static str {
    // The __Host- prefix makes browsers refuse the cookie unless it is Secure, host-only, Path=/.
    if state.cfg.secure_cookies() { "__Host-cactarium" } else { "cactarium" }
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_owned())
        })
}

pub fn set_cookie_header(state: &AppState, token: &str) -> HeaderValue {
    let secure = if state.cfg.secure_cookies() { "; Secure" } else { "" };
    let v = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}",
        cookie_name(state),
        IDLE.whole_seconds()
    );
    HeaderValue::from_str(&v).expect("cookie is ASCII")
}

pub fn clear_cookie_header(state: &AppState) -> HeaderValue {
    let secure = if state.cfg.secure_cookies() { "; Secure" } else { "" };
    let v = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}", cookie_name(state));
    HeaderValue::from_str(&v).expect("cookie is ASCII")
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    csrf: String,
    data: serde_json::Value,
    user_id: Option<i64>,
    last_seen: OffsetDateTime,
}

pub async fn load_user(state: &AppState, id: i64) -> AppResult<Option<User>> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, role, trusted, banned,
                ARRAY(SELECT o.name FROM org_members m JOIN orgs o ON o.id = m.org_id WHERE m.user_id = users.id ORDER BY o.name) AS orgs
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

/// Reads the session named by the request's cookie, if it is live.
pub async fn current_session(state: &AppState, headers: &HeaderMap) -> AppResult<Option<Session>> {
    let Some(token) = read_cookie(headers, cookie_name(state)) else { return Ok(None) };
    let hash = sha256(&token);
    let row = sqlx::query_as::<_, SessionRow>(
        "SELECT csrf, data, user_id, last_seen FROM sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if OffsetDateTime::now_utc() - row.last_seen > TOUCH_EVERY {
        sqlx::query(
            "UPDATE sessions SET last_seen = now(), expires_at = now() + $2 WHERE token_hash = $1",
        )
        .bind(&hash)
        .bind(IDLE)
        .execute(&state.db)
        .await?;
    }
    let user = match row.user_id {
        Some(id) => load_user(state, id).await?.filter(|u| !u.banned),
        None => None,
    };
    Ok(Some(Session { token_hash: hash, csrf: row.csrf, data: row.data, user }))
}

/// Starts a fresh session (always a new token: login rotates it). Returns the cookie to set.
pub async fn create_session(
    state: &AppState,
    user_id: Option<i64>,
    data: serde_json::Value,
) -> AppResult<(Session, HeaderValue)> {
    let token = random_token();
    let hash = sha256(&token);
    let csrf = random_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf, data, expires_at) VALUES ($1, $2, $3, $4, now() + $5)",
    )
    .bind(&hash)
    .bind(user_id)
    .bind(&csrf)
    .bind(&data)
    .bind(IDLE)
    .execute(&state.db)
    .await?;
    let user = match user_id {
        Some(id) => load_user(state, id).await?,
        None => None,
    };
    Ok((Session { token_hash: hash, csrf, data, user }, set_cookie_header(state, &token)))
}

pub async fn destroy_session(state: &AppState, s: &Session) -> AppResult<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&s.token_hash)
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn set_session_data(state: &AppState, s: &Session, data: &serde_json::Value) -> AppResult<()> {
    sqlx::query("UPDATE sessions SET data = $2 WHERE token_hash = $1")
        .bind(&s.token_hash)
        .bind(data)
        .execute(&state.db)
        .await?;
    Ok(())
}

impl Session {
    /// Checks a submitted form's CSRF token in constant time.
    pub fn check_csrf(&self, submitted: &str) -> AppResult<()> {
        if bool::from(self.csrf.as_bytes().ct_eq(submitted.as_bytes())) {
            Ok(())
        } else {
            Err(AppError::bad("the form expired; reload the page and try again"))
        }
    }
}

/// The visitor's session and user, if any. Never fails for anonymous visitors.
pub struct Visitor(pub Option<Session>);

impl Visitor {
    pub fn user(&self) -> Option<&User> {
        self.0.as_ref().and_then(|s| s.user.as_ref())
    }
}

impl FromRequestParts<AppState> for Visitor {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        Ok(Visitor(current_session(state, &parts.headers).await?))
    }
}

/// A signed-in, non-banned user.
pub struct SignedIn {
    pub session: Session,
    pub user: User,
}

impl FromRequestParts<AppState> for SignedIn {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let s = current_session(state, &parts.headers).await?.ok_or(AppError::Unauthorized)?;
        let user = s.user.clone().ok_or(AppError::Unauthorized)?;
        Ok(SignedIn { session: s, user })
    }
}

/// A signed-in admin or superadmin.
pub struct Admin(pub SignedIn);

impl FromRequestParts<AppState> for Admin {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let s = SignedIn::from_request_parts(parts, state).await?;
        if !s.user.is_admin() {
            return Err(AppError::Forbidden);
        }
        Ok(Admin(s))
    }
}

/// Adds the session cookie to a response's headers.
pub fn with_cookie(mut headers: HeaderMap, cookie: HeaderValue) -> HeaderMap {
    headers.append(SET_COOKIE, cookie);
    headers
}
