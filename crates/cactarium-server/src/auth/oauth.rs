//! Sign-in: GitHub and ORCID (OAuth 2 authorization code, with state and PKCE), plus a
//! development-only login that the server refuses to enable unless it is served from localhost.

use axum::Form;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    Session, Visitor, create_session, current_session, destroy_session, random_token, set_session_data,
    with_cookie,
};
use crate::audit::audit;
use crate::error::{AppError, AppResult};
use crate::security::ClientIp;
use crate::state::AppState;
use crate::templates::{ChooseNamePage, LoginPage, PageCtx, page};
use cactup_ecosystem_common::name::Owner;

/// Who an OAuth provider (or the dev login) says the visitor is.
#[derive(Clone, Debug, serde::Serialize, Deserialize)]
pub struct Identity {
    pub provider: String,
    pub subject: String,
    pub login: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
}

fn pkce_pair() -> (String, String) {
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// The visitor's session, creating an anonymous one if needed. Returns a cookie to set when new.
async fn ensure_session(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<(Session, Option<axum::http::HeaderValue>)> {
    match current_session(state, headers).await? {
        Some(s) => Ok((s, None)),
        None => {
            let (s, c) = create_session(state, None, json!({})).await?;
            Ok((s, Some(c)))
        }
    }
}

#[derive(Deserialize)]
pub struct NextQuery {
    next: Option<String>,
}

/// Only a path on this site may be a post-login destination. Anything that, once a browser has
/// dropped control characters or folded backslashes, could leave the site falls back to the
/// dashboard.
fn safe_next(next: Option<&str>) -> String {
    let fallback = || "/dashboard".to_owned();
    let Some(n) = next else { return fallback() };
    if !n.starts_with('/') || n.chars().any(|c| c.is_control() || c == '\\') || n.starts_with("//") {
        return fallback();
    }
    let base = url::Url::parse("https://cactarium.invalid/").expect("static url");
    match base.join(n) {
        Ok(u) if u.origin() == base.origin() && !u.path().starts_with("//") => {
            let mut out = u.path().to_owned();
            if let Some(q) = u.query() {
                out.push('?');
                out.push_str(q);
            }
            out
        }
        _ => fallback(),
    }
}

pub async fn login_page(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> AppResult<Response> {
    state.limiter.check("login", ip.0, 30)?;
    let (s, cookie) = ensure_session(&state, &headers).await?;
    let ctx = PageCtx::new(&state, Some(&s));
    let body = page(&LoginPage {
        ctx,
        github: state.cfg.github.is_some(),
        orcid: state.cfg.orcid.is_some(),
        dev_login: state.cfg.dev_login,
        next: safe_next(q.next.as_deref()),
    })?;
    let mut res = body.into_response();
    if let Some(c) = cookie {
        res.headers_mut().append(axum::http::header::SET_COOKIE, c);
    }
    Ok(res)
}

async fn begin(
    state: &AppState,
    headers: &HeaderMap,
    provider: &str,
    next: Option<&str>,
) -> AppResult<Response> {
    let (s, cookie) = ensure_session(state, headers).await?;
    let oauth_state = random_token();
    let (verifier, challenge) = pkce_pair();
    let mut data = s.data.clone();
    data["oauth"] = json!({ "provider": provider, "state": oauth_state, "verifier": verifier, "next": safe_next(next) });
    set_session_data(state, &s, &data).await?;
    let redirect = state.cfg.url(&format!("/auth/{provider}/callback"));
    let url = match provider {
        "github" => {
            let app = state.cfg.github.as_ref().ok_or(AppError::NotFound)?;
            let mut u = url::Url::parse("https://github.com/login/oauth/authorize").expect("static url");
            u.query_pairs_mut()
                .append_pair("client_id", &app.client_id)
                .append_pair("redirect_uri", &redirect)
                .append_pair("scope", "read:user user:email")
                .append_pair("state", &oauth_state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("allow_signup", "true");
            u
        }
        "orcid" => {
            let app = state.cfg.orcid.as_ref().ok_or(AppError::NotFound)?;
            let mut u = state.cfg.orcid_base.join("/oauth/authorize").map_err(anyhow::Error::from)?;
            u.query_pairs_mut()
                .append_pair("client_id", &app.client_id)
                .append_pair("response_type", "code")
                .append_pair("scope", "openid")
                .append_pair("redirect_uri", &redirect)
                .append_pair("state", &oauth_state)
                .append_pair("code_challenge", &challenge)
                .append_pair("code_challenge_method", "S256");
            u
        }
        _ => return Err(AppError::NotFound),
    };
    let mut res = Redirect::to(url.as_str()).into_response();
    if let Some(c) = cookie {
        res.headers_mut().append(axum::http::header::SET_COOKIE, c);
    }
    Ok(res)
}

pub async fn github_begin(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> AppResult<Response> {
    state.limiter.check("login", ip.0, 30)?;
    begin(&state, &headers, "github", q.next.as_deref()).await
}

pub async fn orcid_begin(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Query(q): Query<NextQuery>,
) -> AppResult<Response> {
    state.limiter.check("login", ip.0, 30)?;
    begin(&state, &headers, "orcid", q.next.as_deref()).await
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Validates the callback against the session's pending flow; returns (verifier, next).
fn check_flow(s: &Session, provider: &str, cb: &Callback) -> AppResult<(String, String)> {
    if let Some(e) = &cb.error {
        return Err(AppError::bad(format!("sign-in was canceled ({e})")));
    }
    let flow = &s.data["oauth"];
    let expected = flow["state"].as_str().unwrap_or("");
    let got = cb.state.as_deref().unwrap_or("");
    if flow["provider"] != provider || expected.is_empty() || expected != got {
        return Err(AppError::bad("sign-in expired; start again"));
    }
    Ok((
        flow["verifier"].as_str().unwrap_or("").to_owned(),
        flow["next"].as_str().unwrap_or("/dashboard").to_owned(),
    ))
}

pub async fn github_callback(
    State(state): State<AppState>,
    Visitor(s): Visitor,
    headers: HeaderMap,
    Query(cb): Query<Callback>,
) -> AppResult<Response> {
    let s = s.ok_or_else(|| AppError::bad("sign-in expired; start again"))?;
    let (verifier, next) = check_flow(&s, "github", &cb)?;
    let app = state.cfg.github.as_ref().ok_or(AppError::NotFound)?;
    let code = cb.code.as_deref().ok_or_else(|| AppError::bad("no code from GitHub"))?;
    #[derive(Deserialize)]
    struct Tok {
        access_token: Option<String>,
        error_description: Option<String>,
    }
    let tok: Tok = state
        .http
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", &state.cfg.url("/auth/github/callback")),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(anyhow::Error::from)?;
    let access = tok.access_token.ok_or_else(|| {
        AppError::bad(format!(
            "GitHub refused the sign-in: {}",
            tok.error_description.unwrap_or_default()
        ))
    })?;
    #[derive(Deserialize)]
    struct GhUser {
        id: i64,
        login: String,
        name: Option<String>,
        email: Option<String>,
    }
    let u: GhUser = state
        .http
        .get("https://api.github.com/user")
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "cactarium")
        .bearer_auth(access)
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .error_for_status()
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(anyhow::Error::from)?;
    let id = Identity {
        provider: "github".into(),
        subject: u.id.to_string(),
        login: Some(u.login),
        name: u.name,
        email: u.email,
    };
    finish(&state, &headers, s, id, &next).await
}

pub async fn orcid_callback(
    State(state): State<AppState>,
    Visitor(s): Visitor,
    headers: HeaderMap,
    Query(cb): Query<Callback>,
) -> AppResult<Response> {
    let s = s.ok_or_else(|| AppError::bad("sign-in expired; start again"))?;
    let (verifier, next) = check_flow(&s, "orcid", &cb)?;
    let app = state.cfg.orcid.as_ref().ok_or(AppError::NotFound)?;
    let code = cb.code.as_deref().ok_or_else(|| AppError::bad("no code from ORCID"))?;
    #[derive(Deserialize)]
    struct Tok {
        orcid: Option<String>,
        name: Option<String>,
        error_description: Option<String>,
    }
    let token_url = state.cfg.orcid_base.join("/oauth/token").map_err(anyhow::Error::from)?;
    let tok: Tok = state
        .http
        .post(token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &state.cfg.url("/auth/orcid/callback")),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .map_err(anyhow::Error::from)?
        .json()
        .await
        .map_err(anyhow::Error::from)?;
    let orcid = tok.orcid.ok_or_else(|| {
        AppError::bad(format!(
            "ORCID refused the sign-in: {}",
            tok.error_description.unwrap_or_default()
        ))
    })?;
    let id = Identity {
        provider: "orcid".into(),
        subject: orcid.clone(),
        login: Some(orcid),
        name: tok.name,
        email: None,
    };
    finish(&state, &headers, s, id, &next).await
}

#[derive(Deserialize)]
pub struct DevLogin {
    username: String,
    next: Option<String>,
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// Local development only (refused at startup unless the site is served from localhost).
pub async fn dev_login(
    State(state): State<AppState>,
    Visitor(s): Visitor,
    headers: HeaderMap,
    Form(f): Form<DevLogin>,
) -> AppResult<Response> {
    if !state.cfg.dev_login {
        return Err(AppError::NotFound);
    }
    let s = s.ok_or_else(|| AppError::bad("the form expired; reload the page and try again"))?;
    s.check_csrf(&f.csrf)?;
    let name = f.username.trim().to_ascii_lowercase();
    let id = Identity {
        provider: "dev".into(),
        subject: name.clone(),
        login: Some(name),
        name: None,
        email: None,
    };
    let next = safe_next(f.next.as_deref());
    finish(&state, &headers, s, id, &next).await
}

/// Signs the visitor in as the user behind `id`: an existing identity, a new identity linked to
/// the already signed-in user, or a brand-new user (who may first have to choose a name).
async fn finish(
    state: &AppState,
    headers: &HeaderMap,
    s: Session,
    id: Identity,
    next: &str,
) -> AppResult<Response> {
    let existing: Option<(i64, bool)> = sqlx::query_as(
        "SELECT u.id, u.banned FROM identities i JOIN users u ON u.id = i.user_id WHERE i.provider = $1 AND i.subject = $2",
    )
    .bind(&id.provider)
    .bind(&id.subject)
    .fetch_optional(&state.db)
    .await?;
    let user_id = match (existing, &s.user) {
        (Some((_, true)), _) => return Err(AppError::Forbidden),
        (Some((uid, false)), _) => {
            sqlx::query("UPDATE identities SET login = $3, email = COALESCE($4, email) WHERE provider = $1 AND subject = $2")
                .bind(&id.provider)
                .bind(&id.subject)
                .bind(&id.login)
                .bind(&id.email)
                .execute(&state.db)
                .await?;
            uid
        }
        (None, Some(current)) => {
            // Linking another sign-in method to the signed-in account.
            insert_identity(state, current.id, &id).await?;
            audit(
                state,
                Some(current.id),
                "identity.link",
                Some(&id.provider),
                json!({ "subject": id.subject }),
                None,
            )
            .await?;
            current.id
        }
        (None, None) => {
            let suggested = id
                .login
                .as_deref()
                .map(str::to_ascii_lowercase)
                .filter(|_| id.provider != "orcid");
            match suggested {
                Some(name) if name_available(state, &name).await? => {
                    create_user(state, &name, &id).await?
                }
                _ => {
                    // Ask for a name; keep the identity in the (pre-login) session meanwhile.
                    let mut data = s.data.clone();
                    data["signup"] = serde_json::to_value(&id).map_err(anyhow::Error::from)?;
                    data["signup_next"] = json!(next);
                    data.as_object_mut().map(|o| o.remove("oauth"));
                    set_session_data(state, &s, &data).await?;
                    return Ok(Redirect::to("/auth/choose-name").into_response());
                }
            }
        }
    };
    sign_in(state, headers, s, user_id, &id, next).await
}

async fn sign_in(
    state: &AppState,
    _headers: &HeaderMap,
    old: Session,
    user_id: i64,
    id: &Identity,
    next: &str,
) -> AppResult<Response> {
    // GitHub logins can be renamed and then claimed by someone else, so GitHub accounts are
    // matched by their numeric id only; ORCID iDs and dev names are stable.
    let who =
        if id.provider == "github" { &id.subject } else { id.login.as_deref().unwrap_or(&id.subject) };
    if state.cfg.is_superadmin(&id.provider, who) {
        let changed =
            sqlx::query("UPDATE users SET role = 'superadmin' WHERE id = $1 AND role <> 'superadmin'")
                .bind(user_id)
                .execute(&state.db)
                .await?
                .rows_affected();
        if changed > 0 {
            audit(
                state,
                Some(user_id),
                "user.superadmin-bootstrap",
                Some(&id.provider),
                json!({ "who": who }),
                None,
            )
            .await?;
        }
    }
    // Rotate: the pre-login session is dropped and a new token issued.
    destroy_session(state, &old).await?;
    let (_, cookie) = create_session(state, Some(user_id), json!({})).await?;
    audit(state, Some(user_id), "login", Some(&id.provider), json!({ "who": who }), None).await?;
    Ok((with_cookie(HeaderMap::new(), cookie), Redirect::to(next)).into_response())
}

async fn name_available(state: &AppState, name: &str) -> AppResult<bool> {
    if name.parse::<Owner>().is_err() {
        return Ok(false);
    }
    // A name that already owns entries (curated ones, or transferred ones) belongs to whoever
    // they were made for, not to the first person to sign up with it.
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1) OR EXISTS (SELECT 1 FROM reserved_names WHERE name = $1)
            OR EXISTS (SELECT 1 FROM entries WHERE lower(owner) = lower($1))
            OR EXISTS (SELECT 1 FROM orgs WHERE name = $1)",
    )
    .bind(name)
    .fetch_one(&state.db)
    .await?;
    Ok(!taken)
}

async fn insert_identity(state: &AppState, user_id: i64, id: &Identity) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO identities (user_id, provider, subject, login, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(&id.provider)
    .bind(&id.subject)
    .bind(&id.login)
    .bind(&id.email)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn create_user(state: &AppState, name: &str, id: &Identity) -> AppResult<i64> {
    let mut tx = state.db.begin().await?;
    if crate::web::orgs::name_taken_locked(&mut tx, name, "orgs").await? {
        return Err(AppError::Conflict(format!("'{name}' is taken")));
    }
    let uid: i64 =
        sqlx::query_scalar("INSERT INTO users (username, display_name) VALUES ($1, $2) RETURNING id")
            .bind(name)
            .bind(&id.name)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query(
        "INSERT INTO identities (user_id, provider, subject, login, email) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(uid)
    .bind(&id.provider)
    .bind(&id.subject)
    .bind(&id.login)
    .bind(&id.email)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    audit(state, Some(uid), "user.create", Some(name), json!({ "provider": id.provider }), None).await?;
    Ok(uid)
}

pub async fn choose_name_page(
    State(state): State<AppState>,
    Visitor(s): Visitor,
) -> AppResult<Response> {
    let s = s.ok_or(AppError::Unauthorized)?;
    let id: Identity =
        serde_json::from_value(s.data["signup"].clone()).map_err(|_| AppError::Unauthorized)?;
    let suggestion = id
        .name
        .as_deref()
        .or(id.login.as_deref())
        .map(|n| n.to_ascii_lowercase().replace(' ', "-"))
        .filter(|n| n.parse::<Owner>().is_ok())
        .unwrap_or_default();
    let ctx = PageCtx::new(&state, Some(&s));
    Ok(page(&ChooseNamePage { ctx, provider: id.provider, suggestion, error: None })?.into_response())
}

#[derive(Deserialize)]
pub struct ChooseName {
    username: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn choose_name(
    State(state): State<AppState>,
    Visitor(s): Visitor,
    headers: HeaderMap,
    Form(f): Form<ChooseName>,
) -> AppResult<Response> {
    let s = s.ok_or(AppError::Unauthorized)?;
    s.check_csrf(&f.csrf)?;
    let id: Identity =
        serde_json::from_value(s.data["signup"].clone()).map_err(|_| AppError::Unauthorized)?;
    let next = s.data["signup_next"].as_str().unwrap_or("/dashboard").to_owned();
    let name = f.username.trim().to_owned();
    let problem = match name.parse::<Owner>() {
        Err(e) => Some(e.to_string()),
        Ok(_) if !name_available(&state, &name).await? => Some(format!("'{name}' is taken")),
        Ok(_) => None,
    };
    if let Some(error) = problem {
        let ctx = PageCtx::new(&state, Some(&s));
        return Ok(page(&ChooseNamePage {
            ctx,
            provider: id.provider,
            suggestion: name,
            error: Some(error),
        })?
        .into_response());
    }
    let uid = create_user(&state, &name, &id).await?;
    sign_in(&state, &headers, s, uid, &id, &safe_next(Some(&next))).await
}

#[cfg(test)]
mod tests {
    use super::safe_next;

    #[test]
    fn next_stays_on_the_site() {
        assert_eq!(safe_next(Some("/max/carpetx?tab=thorns")), "/max/carpetx?tab=thorns");
        assert_eq!(safe_next(Some("/settings")), "/settings");
        // A percent-encoded tab stays a path on this site; the decoded one (what the query
        // parameter becomes) is what browsers would drop.
        assert_eq!(safe_next(Some("/%09/evil.example")), "/%09/evil.example");
        for bad in [
            "//evil.example",
            "/\t/evil.example",
            "/\\evil.example",
            "https://evil.example",
            "/a\nb",
            "evil",
            "/\u{0}x",
        ] {
            assert_eq!(safe_next(Some(bad)), "/dashboard", "{bad:?}");
        }
    }
}

#[derive(Deserialize)]
pub struct CsrfOnly {
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn logout(
    State(state): State<AppState>,
    Visitor(s): Visitor,
    Form(f): Form<CsrfOnly>,
) -> AppResult<Response> {
    if let Some(s) = s {
        s.check_csrf(&f.csrf)?;
        destroy_session(&state, &s).await?;
    }
    let headers = with_cookie(HeaderMap::new(), super::clear_cookie_header(&state));
    Ok((headers, Redirect::to("/")).into_response())
}
