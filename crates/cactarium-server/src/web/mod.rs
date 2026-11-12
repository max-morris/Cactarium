pub mod account;
pub mod admin;
pub mod api;
pub mod hooks;
pub mod orgs;
pub mod public;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::auth::oauth;
use crate::security;
use crate::state::AppState;

/// Uploads are small: a .sim is at most 1 MB.
const BODY_LIMIT: usize = 2 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/entries/{owner}/{name}", get(api::entry))
        .route("/packages/{owner}/{name}/versions", get(api::package_versions))
        .route("/packages/{owner}/{name}/versions/{tip}", get(api::package_tip))
        .route("/packages/{owner}/{name}/refresh", post(api::package_refresh))
        .route("/resolve", get(api::resolve))
        .route("/stacks/{owner}/{name}/releases", get(api::stack_releases).post(api::stack_publish))
        .route("/stacks/{owner}/{name}/releases/{version}", get(api::stack_release))
        .route("/sims/{owner}/{name}", post(api::sim_publish))
        .route("/sims/{owner}/{name}/{version}/download", get(api::sim_download))
        .fallback(api::not_found)
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(cactup_ecosystem_common::api::API_GENERATION_HEADER),
            HeaderValue::from_str(&api::generation()).expect("a number is a header value"),
        ));

    Router::new()
        .route("/", get(public::home))
        .route("/search", get(public::search))
        .route("/docs", get(public::docs))
        .route("/docs/{page}", get(public::docs_page))
        .route("/sources", get(public::sources))
        .route("/compare", get(public::compare))
        .route("/thorns/{name}", get(public::thorn_by_name))
        .route("/thorns/{arr}/{name}", get(public::thorn))
        .route("/implementations/{name}", get(public::implementation))
        .route("/auth/login", get(oauth::login_page))
        .route("/auth/github", get(oauth::github_begin))
        .route("/auth/github/callback", get(oauth::github_callback))
        .route("/auth/orcid", get(oauth::orcid_begin))
        .route("/auth/orcid/callback", get(oauth::orcid_callback))
        .route("/auth/dev", post(oauth::dev_login))
        .route("/auth/choose-name", get(oauth::choose_name_page).post(oauth::choose_name))
        .route("/auth/logout", post(oauth::logout))
        .route("/dashboard", get(account::dashboard))
        .route("/new/repo", get(account::new_repo_page).post(account::new_repo))
        .route("/new/sim", get(account::new_sim_page).post(account::new_sim))
        .route("/new/stack", get(account::new_stack_page).post(account::new_stack))
        .route("/settings", get(account::settings))
        .route("/settings/tokens", post(account::create_token))
        .route("/settings/tokens/{id}/revoke", post(account::revoke_token))
        .route("/admin", get(admin::queue))
        .route("/admin/review/{id}", post(admin::decide))
        .route("/admin/entries", get(admin::entries))
        .route("/admin/entries/{id}", post(admin::entry_action))
        .route("/admin/curated", get(admin::curated).post(admin::create_curated))
        .route("/admin/curated/{id}/version", post(admin::add_virtual))
        .route("/admin/curated/{id}/hand-over", post(admin::hand_over))
        .route("/admin/curated/{id}/reapply", post(admin::reapply))
        .route("/admin/tags", get(admin::tags))
        .route("/admin/tags/{id}/ack", post(admin::ack_tag))
        .route("/admin/users", get(admin::users))
        .route("/admin/users/{id}", post(admin::user_action))
        .route("/admin/audit", get(admin::audit_log))
        .route("/admin/site", get(admin::site_page).post(admin::site_save))
        .route("/orgs/new", get(orgs::new_page).post(orgs::create_form))
        .route("/orgs/{name}", get(orgs::manage_page))
        .route("/orgs/{name}/members", post(orgs::add_member))
        .route("/orgs/{name}/members/{uid}", post(orgs::member_action))
        .route("/orgs/{name}/trust", post(orgs::set_trust))
        .route("/hooks/{provider}/{entry_id}", post(hooks::receive))
        .nest("/api/v1", api)
        .nest_service("/static", ServeDir::new(&state.cfg.static_dir))
        .route("/{owner}", get(public::owner))
        .route("/{owner}/{name}", get(public::entry))
        .route("/{owner}/{name}/refresh", post(account::refresh))
        .route("/{owner}/{name}/yank", post(account::yank))
        .route("/{owner}/{name}/resubmit", post(account::resubmit))
        .route("/{owner}/{name}/heart", post(account::heart))
        .route("/{owner}/{name}/{version}", get(public::entry_version))
        .route("/{owner}/{name}/{version}/{file}", get(public::download))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(from_fn_with_state(state.clone(), security::same_origin))
        .layer(from_fn_with_state(state.clone(), security::headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
