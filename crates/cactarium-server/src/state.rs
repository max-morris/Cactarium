use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub limiter: Arc<RateLimiter>,
}
