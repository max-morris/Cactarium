use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;

use crate::config::Config;
use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub limiter: Arc<RateLimiter>,
    /// Stack definitions read from a manifest repo's default branch, by (entry, commit): what
    /// `@head` and `@master` resolve, without cloning the repo on every request.
    pub definitions: Arc<Mutex<HashMap<(i64, String), (String, Option<String>)>>>,
    /// Packages read at their default branch's tip, by (entry, commit): what a package's `@head`
    /// and `@master` resolve.
    pub package_tips: Arc<Mutex<HashMap<(i64, String), Arc<crate::tracker::PackageTip>>>>,
}
