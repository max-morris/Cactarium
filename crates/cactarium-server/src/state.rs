use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::flights::Flights;
use crate::security::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cfg: Arc<Config>,
    pub http: reqwest::Client,
    pub limiter: Arc<RateLimiter>,
    /// Stack definitions read from a manifest repo's default branch, by (entry, commit): what
    /// `@head` and `@master` resolve, without cloning the repo on every request.
    pub definitions: Arc<Flights<(i64, String), (String, Option<String>)>>,
    /// Packages read at a commit (a tip, or one named by id), by (entry, commit, a fingerprint of
    /// what else the reading depends on: owner, repo URL, curated overlay).
    pub package_tips: Arc<Flights<(i64, String, String), Arc<crate::tracker::PackageTip>>>,
    /// Stacks resolved at their branch tips, by (entry, tip): briefly, since tips move.
    pub stack_tips: Arc<Flights<(i64, String), Arc<cactup_ecosystem_common::stack::FrozenStack>>>,
}
