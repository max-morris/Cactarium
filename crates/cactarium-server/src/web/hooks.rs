//! Webhooks from forges: a push of a tag triggers an immediate sync instead of waiting for the poll.
//!
//! Each tracked repo has its own secret. GitHub and Bitbucket sign the body (HMAC-SHA256 in
//! `X-Hub-Signature-256` / `X-Hub-Signature`); GitLab sends the secret itself in `X-Gitlab-Token`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::{ApiResult, AppError};
use crate::model;
use crate::security::ClientIp;
use crate::state::AppState;
use crate::tracker;

fn signed(secret: &str, body: &[u8], header: Option<&str>) -> bool {
    let Some(sig) = header.and_then(|h| h.strip_prefix("sha256=")) else { return false };
    let Ok(sig) = hex::decode(sig) else { return false };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac takes any key");
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

pub async fn receive(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Path((provider, entry_id)): Path<(String, i64)>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    state.limiter.check("hook", ip.0, 60)?;
    let repo = tracker::repo_of(&state, entry_id).await?.ok_or(AppError::NotFound)?;
    let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let ok = match provider.as_str() {
        "github" => signed(&repo.webhook_secret, &body, h("x-hub-signature-256")),
        "bitbucket" => signed(&repo.webhook_secret, &body, h("x-hub-signature")),
        "gitlab" => h("x-gitlab-token")
            .is_some_and(|t| bool::from(t.as_bytes().ct_eq(repo.webhook_secret.as_bytes()))),
        _ => return Err(AppError::NotFound.into()),
    };
    if !ok {
        return Err(AppError::Forbidden.into());
    }
    // GitHub's setup ping needs no sync.
    if h("x-github-event") == Some("ping") {
        return Ok(StatusCode::NO_CONTENT);
    }
    let entry = model::entry_by_id(&state, entry_id).await?;
    tokio::spawn(async move {
        if let Err(e) = tracker::sync(&state, &entry).await {
            tracing::info!("webhook sync of {} failed: {e}", entry.slug());
        }
    });
    Ok(StatusCode::ACCEPTED)
}

#[cfg(test)]
mod tests {
    #[test]
    fn github_signatures() {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(b"{}");
        let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(super::signed("s3cret", b"{}", Some(&sig)));
        assert!(!super::signed("other", b"{}", Some(&sig)));
        assert!(!super::signed("s3cret", b"{ }", Some(&sig)));
        assert!(!super::signed("s3cret", b"{}", None));
    }
}
