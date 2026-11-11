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
#[derive(Clone, Copy)]
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
/// Per-minute request limits by client: a client's minute starts with its first request, and its
/// count resets once that minute is over. Clients are kept in two maps, swapped every minute, so
/// forgetting old ones costs a swap rather than a scan: a client not seen since before the last
/// swap has had its minute end, and goes with the older map. IPv6 clients are counted by their
/// /64, which one machine usually controls whole.
pub struct RateLimiter {
    windows: Mutex<Windows>,
}

type Counts = HashMap<(&'static str, IpAddr), (Instant, u32)>;

struct Windows {
    swapped: Instant,
    current: Counts,
    previous: Counts,
}

const WINDOW: Duration = Duration::from_secs(60);

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter {
            windows: Mutex::new(Windows {
                swapped: Instant::now(),
                current: HashMap::new(),
                previous: HashMap::new(),
            }),
        }
    }
}

/// The address a client is counted under: itself for IPv4, its /64 for IPv6.
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        },
    }
}

impl RateLimiter {
    /// Allows `limit` requests per minute per client in `bucket`.
    pub fn check(&self, bucket: &'static str, ip: Option<IpAddr>, limit: u32) -> Result<(), AppError> {
        let Some(ip) = ip else { return Ok(()) };
        let key = (bucket, client_key(ip));
        let mut w = self.windows.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if now.duration_since(w.swapped) >= WINDOW {
            w.previous = std::mem::take(&mut w.current);
            w.swapped = now;
        }
        let mut hit = w.current.remove(&key).or_else(|| w.previous.remove(&key)).unwrap_or((now, 0));
        if now.duration_since(hit.0) >= WINDOW {
            hit = (now, 0);
        }
        hit.1 += 1;
        let count = hit.1;
        w.current.insert(key, hit);
        if count > limit { Err(AppError::TooManyRequests) } else { Ok(()) }
    }
}

#[cfg(test)]
mod limiter_tests {
    use super::*;

    #[test]
    fn limits_per_client_and_groups_ipv6_by_64() {
        let l = RateLimiter::default();
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(l.check("x", Some(a), 2).is_ok());
        assert!(l.check("x", Some(b), 2).is_ok());
        assert!(l.check("x", Some(a), 2).is_err(), "same /64");
        assert!(l.check("x", Some(c), 2).is_ok(), "another /64");
        assert!(l.check("y", Some(a), 2).is_ok(), "another bucket");
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(l.check("x", Some(v4), 1).is_ok());
        assert!(l.check("x", Some(mapped), 1).is_err(), "a mapped v4 is the v4");
    }
}
