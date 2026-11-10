//! Response headers, the cross-site request check, client addresses and rate limiting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::state::AppState;

/// Strict defaults on every response.
pub async fn headers(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut HeaderMap, k: header::HeaderName, v: &'static str| {
        h.entry(k).or_insert(HeaderValue::from_static(v));
    };
    set(
        h,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; \
         font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://avatars.githubusercontent.com; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com https://orcid.org https://sandbox.orcid.org",
    );
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "strict-origin-when-cross-origin");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::HeaderName::from_static("cross-origin-opener-policy"), "same-origin");
    set(
        h,
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()",
    );
    if state.cfg.secure_cookies() {
        set(h, header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    }
    res
}

/// Rejects cross-site unsafe requests to the site. The API (bearer tokens, no cookies) and the
/// webhooks (HMAC) are exempt; everything else also checks a per-form CSRF token.
pub async fn same_origin(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let path = req.uri().path();
    if safe || path.starts_with("/api/") || path.starts_with("/hooks/") {
        return next.run(req).await;
    }
    let h = req.headers();
    if let Some(site) = h.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && !matches!(site, "same-origin" | "none")
    {
        return AppError::Forbidden.into_response();
    }
    if let Some(origin) = h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let ours = state.cfg.base_url.origin().ascii_serialization();
        if origin != ours {
            return AppError::Forbidden.into_response();
        }
    }
    next.run(req).await
}

/// The client's address: the connecting peer, or behind our proxy the last X-Forwarded-For hop.
pub fn client_ip(
    state: &AppState,
    headers: &HeaderMap,
    peer: Option<&ConnectInfo<SocketAddr>>,
) -> Option<IpAddr> {
    if state.cfg.trust_proxy
        && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(last) = xff.rsplit(',').next()
        && let Ok(ip) = last.trim().parse()
    {
        return Some(ip);
    }
    peer.map(|c| c.0.ip())
}

/// The client's address as an extractor (see [`client_ip`]).
pub struct ClientIp(pub Option<IpAddr>);

impl axum::extract::FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>();
        Ok(ClientIp(client_ip(state, &parts.headers, peer)))
    }
}

/// A fixed-window limiter per (bucket, client address).
pub struct RateLimiter {
    hits: Mutex<HashMap<(&'static str, IpAddr), (Instant, u32)>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter { hits: Mutex::new(HashMap::new()) }
    }
}

impl RateLimiter {
    /// Allows `limit` requests per minute per address in `bucket`.
    pub fn check(&self, bucket: &'static str, ip: Option<IpAddr>, limit: u32) -> Result<(), AppError> {
        let Some(ip) = ip else { return Ok(()) };
        let mut hits = self.hits.lock().expect("limiter lock");
        let now = Instant::now();
        if hits.len() > 50_000 {
            hits.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let e = hits.entry((bucket, ip)).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > limit { Err(AppError::TooManyRequests) } else { Ok(()) }
    }
}
