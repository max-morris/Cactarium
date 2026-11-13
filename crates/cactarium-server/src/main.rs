//! The Cactarium: a registry of thorn packages, stacks and sim files for the Cactup ecosystem.

// Database rows are read as tuples; naming each one would add nothing.
#![allow(clippy::type_complexity)]

mod audit;
mod auth;
mod claims;
mod config;
mod curate;
mod deps;
mod error;
mod flights;
mod git;
mod markdown;
mod model;
mod publish;
mod security;
mod sims;
mod site;
mod stacks;
mod state;
mod templates;
mod tracker;
mod web;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;

use crate::config::Config;
use crate::state::AppState;

#[derive(Parser)]
#[command(name = "cactarium", about = "The Cactarium registry server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the site (runs pending migrations first).
    Serve,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Manage admins from the command line, for when nobody can sign in.
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Register a repo (its package, stack and/or sims) on behalf of a user; with --owner (the
    /// user must be an admin), under a namespace that is no user's, such as `et`. A repo that
    /// already has entries gets only the missing ones. Each new entry is read at its newest tag
    /// (or --tag) first; if one fails, nothing is registered.
    Register {
        username: String,
        url: String,
        #[arg(long)]
        owner: Option<String>,
        /// Read the manifests at exactly this tag, instead of each kind's newest release.
        #[arg(long)]
        tag: Option<String>,
        /// Register only the new entry with this (manifest) name; repeatable. Default: all.
        #[arg(long = "only")]
        only: Vec<String>,
    },
    /// A dry run: the preview registering URL (at TAG, if given) shows, and with a tag, how each
    /// entry already on the repo would read it. Writes nothing. With --commit, a tag that doesn't
    /// exist yet is read as if it named that commit (a branch or a full commit id).
    Check {
        url: String,
        #[arg(long)]
        tag: Option<String>,
        #[arg(long, requires = "tag")]
        commit: Option<String>,
        /// The entries' owner (default: the repo's existing owner, else the manifest's first).
        #[arg(long)]
        owner: Option<String>,
    },
    /// Re-read an invalid version of a (non-curated) repo entry at its frozen commit, as an admin:
    /// it becomes valid if it reads cleanly now (also from another tag of that version), or is
    /// removed if its tag isn't a version of the entry at all. With `--tag` instead of a version: a
    /// tag recorded as not a version of the entry is examined again under the rules as they are now.
    Reread {
        username: String,
        slug: String,
        version: Option<String>,
        #[arg(long, conflicts_with = "version")]
        tag: Option<String>,
    },
    /// Create or update curated packages from a curate.toml (see `curate.rs` for the format),
    /// as the given admin.
    Curate { username: String, file: std::path::PathBuf },
    /// Publish a .sim file on behalf of a user.
    PublishSim {
        username: String,
        file: std::path::PathBuf,
        #[arg(long)]
        name: Option<String>,
        /// The version to publish (default: the next major, 1.0.0, 2.0.0, …).
        #[arg(long)]
        version: Option<String>,
    },
    /// Manage organizations from the command line.
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Check an entry's repo for new and moved tags now.
    Sync { slug: String },
    /// Re-read the published versions of a curated package (or, without one, of every curated
    /// package) with its current manifest, as the given admin: same commits, new dependencies,
    /// claims and thorn list.
    Reapply { username: String, slug: Option<String> },
    /// Yank a version on behalf of a user who manages the entry (or an admin): it stays
    /// downloadable by exact version, but no range chooses it.
    Yank {
        username: String,
        /// owner/name
        slug: String,
        /// `1.2.0`, `track:1.2.0`, or a sim's number
        version: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Undo a yank.
    Unyank { username: String, slug: String, version: String },
    /// Point an entry, and every other entry on the same repo, at the repo's new URL (after a move
    /// such as a GitHub transfer), as the given admin; refused unless the new URL holds each one's
    /// tags at the same commits. All move together, or none does.
    MoveRepo { username: String, slug: String, url: String },
    /// Local development only: create a user who can use the development sign-in.
    DevUser { username: String },
    /// Create an API token for a user (scope "publish") and print it. It is shown only once.
    Token {
        username: String,
        #[arg(long, default_value = "cli")]
        name: String,
        #[arg(long, default_value_t = 90)]
        days: i32,
    },
}

#[derive(Subcommand)]
enum OrgAction {
    /// Create an organization with OWNER (a username) as its first owner. Reserved names such as
    /// `et` are allowed here; an organization made for a namespace with entries takes them over.
    Create {
        name: String,
        owner: String,
        #[arg(long)]
        display_name: Option<String>,
    },
    /// Add a user to an organization (or change their role).
    Add {
        name: String,
        username: String,
        /// Make them an owner, not only a member.
        #[arg(long)]
        owner: bool,
    },
    /// List organizations and their members.
    List,
}

#[derive(Subcommand)]
enum AdminAction {
    /// Make a user an admin.
    Grant { username: String },
    /// Make an admin an ordinary user.
    Revoke { username: String },
    /// Mark a user, an organization, or an entry (owner/name) trusted: new entries and releases
    /// they publish, or new releases of the entry, skip review.
    Trust { name: String },
    /// Mark a user, organization or entry untrusted again.
    Untrust { name: String },
    /// List admins and trusted users, organizations and entries.
    List,
}

async fn connect(cfg: &Config) -> anyhow::Result<sqlx::PgPool> {
    let mut last = None;
    // The database container may still be starting.
    for _ in 0..30 {
        match PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&cfg.database_url)
            .await
        {
            Ok(pool) => return Ok(pool),
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(last.map(anyhow::Error::from).unwrap_or_else(|| anyhow::anyhow!("no database")))
        .context("cannot reach the database")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();
    let cli = Cli::parse();
    let cfg = Config::from_env()?;
    let db = connect(&cfg).await?;
    // A database a newer release migrated (after a rollback to this one) still serves: newer
    // migrations keep older binaries working, and this one leaves those it doesn't know alone.
    let migrate = || async {
        let mut m = sqlx::migrate!("./migrations");
        m.set_ignore_missing(true);
        m.run(&db).await
    };
    match cli.command {
        Command::Migrate => {
            migrate().await?;
            println!("Migrations applied");
            Ok(())
        }
        Command::Admin { action } => admin(&db, action).await,
        Command::Register { username, url, owner, tag, only } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            let choice = if only.is_empty() { tracker::Choice::All } else { tracker::Choice::Names(&only) };
            let mut refused = None;
            let done = match tracker::register(&state, &user, &url, owner.as_deref(), tag.as_deref(), choice, &mut refused).await {
                Ok(done) => done,
                Err(e) => {
                    if let Some(p) = refused {
                        for l in tracker::preview_lines(&p) {
                            eprintln!("{l}");
                        }
                    }
                    anyhow::bail!("{e}");
                }
            };
            for (e, (file, tag, version)) in done.entries.iter().zip(&done.from) {
                println!("Registered {} ({}, {}) from {file} at {tag}: version {version}", e.slug(), e.kind, e.visibility);
            }
            for n in &done.notes {
                println!("Note: {n}");
            }
            Ok(())
        }
        Command::Check { url, tag, commit, owner } => {
            let state = make_state(cfg, db)?;
            let (lines, clean) = tracker::check(&state, &url, tag.as_deref(), commit.as_deref(), owner.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            for l in &lines {
                println!("{l}");
            }
            anyhow::ensure!(clean, "{} would not be read cleanly", tag.as_deref().unwrap_or("the repo"));
            Ok(())
        }
        Command::Reread { username, slug, version, tag } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            let (owner, name) = slug.split_once('/').context("give owner/name")?;
            let e = model::find_entry(&state, owner, name)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .context("no such entry")?;
            let said = match (version, tag) {
                (Some(version), None) => tracker::reread_invalid(&state, &user, &e, &version).await,
                (None, Some(tag)) => tracker::reexamine_tag(&state, &user, &e, &tag).await,
                _ => anyhow::bail!("give an invalid version, or --tag <tag>"),
            }
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{said}");
            Ok(())
        }
        Command::PublishSim { username, file, name, version } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            let bytes =
                std::fs::read(&file).with_context(|| format!("cannot read '{}'", file.display()))?;
            let checked = sims::check(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
            let (owner, name) = match name.as_deref().and_then(|n| n.split_once('/')) {
                Some((o, n)) => (Some(o.to_owned()), Some(n.to_owned())),
                None => (None, name),
            };
            let (e, n, review) = sims::publish(
                &state,
                &user,
                owner.as_deref(),
                name.as_deref(),
                version.as_deref(),
                checked,
            )
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            let shown =
                if review == "pending" { "release awaiting review" } else { e.visibility.as_str() };
            println!("Published {}@{n} ({shown})", e.slug());
            Ok(())
        }
        Command::Org { action } => {
            let state = make_state(cfg, db)?;
            let err = |e: error::AppError| anyhow::anyhow!("{e}");
            match action {
                OrgAction::Create { name, owner, display_name } => {
                    let owner = cli_user(&state, &owner).await?;
                    let org = web::orgs::create(&state, None, &name, display_name.as_deref(), &owner)
                        .await
                        .map_err(err)?;
                    println!("Created organization {} (owner {})", org.name, owner.username);
                }
                OrgAction::Add { name, username, owner } => {
                    let org = web::orgs::find_org(&state, &name)
                        .await
                        .map_err(err)?
                        .context("no such organization")?;
                    web::orgs::put_member(&state, None, &org, &username, owner).await.map_err(err)?;
                    println!(
                        "{username} is now {} of {name}",
                        if owner { "an owner" } else { "a member" }
                    );
                }
                OrgAction::List => {
                    let rows: Vec<(String, String, String)> = sqlx::query_as(
                        "SELECT o.name, u.username, m.role FROM orgs o JOIN org_members m ON m.org_id = o.id JOIN users u ON u.id = m.user_id ORDER BY o.name, m.role DESC, u.username",
                    )
                    .fetch_all(&state.db)
                    .await?;
                    for (o, u, r) in rows {
                        println!("{o}\t{u}\t{r}");
                    }
                }
            }
            Ok(())
        }
        Command::Curate { username, file } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            curate::run(&state, &user, &file).await
        }
        Command::MoveRepo { username, slug, url } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            if !user.is_admin() {
                anyhow::bail!("{username} is not an admin");
            }
            let (owner, name) = slug.split_once('/').context("give owner/name")?;
            let e = model::find_entry(&state, owner, name)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .context("no such entry")?;
            for moved in tracker::move_repo(&state, &user, &e, &url)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                println!("{} now reads {url}", moved.slug());
            }
            Ok(())
        }
        Command::Yank { username, slug, version, reason } => {
            yank_cli(cfg, db, &username, &slug, &version, true, reason.as_deref()).await
        }
        Command::Unyank { username, slug, version } => {
            yank_cli(cfg, db, &username, &slug, &version, false, None).await
        }
        Command::Sync { slug } => {
            let state = make_state(cfg, db)?;
            let (owner, name) = slug.split_once('/').context("give owner/name")?;
            let e = model::find_entry(&state, owner, name)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .context("no such entry")?;
            let n = tracker::sync(&state, &e).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{}: {n} new versions", e.slug());
            Ok(())
        }
        Command::Reapply { username, slug } => {
            let state = make_state(cfg, db)?;
            let admin = cli_user(&state, &username).await?;
            anyhow::ensure!(admin.is_admin(), "{username} is not an admin");
            let entries: Vec<model::Entry> = match slug {
                Some(s) => {
                    let (owner, name) = s.split_once('/').context("give owner/name")?;
                    vec![model::find_entry(&state, owner, name)
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?
                        .context("no such entry")?]
                }
                None => sqlx::query_as(&format!(
                    "SELECT {} FROM entries WHERE curated ORDER BY owner, name",
                    model::ENTRY_COLS
                ))
                .fetch_all(&state.db)
                .await?,
            };
            // A version can depend on a package whose own version only becomes valid later in the
            // same run (packages go in name order), so the ones left are tried again, pass after
            // pass, until a pass changes nothing.
            let mut failed = 0;
            let mut pending: Vec<&model::Entry> = entries.iter().collect();
            // Each package's notes from the last pass it was tried in.
            let mut last: std::collections::BTreeMap<String, Vec<String>> = Default::default();
            for pass in 1.. {
                let mut again: Vec<&model::Entry> = Vec::new();
                let mut progress = false;
                for e in &pending {
                    match tracker::reapply_curated(&state, &admin, e).await {
                        Ok((done, left)) => {
                            // Progress: fewer versions left than in the pass before.
                            let fewer = last.get(&e.slug()).is_some_and(|before| left.len() < before.len());
                            if pass == 1 || fewer {
                                println!("{}: {done} re-read{}", e.slug(), if pass > 1 { format!(" (pass {pass})") } else { String::new() });
                            }
                            progress |= fewer;
                            // Versions below since are left on purpose; anything else may yet fit.
                            if left.iter().any(|l| !l.contains("older than the manifest's since")) {
                                again.push(e);
                            }
                            last.insert(e.slug(), left);
                        }
                        Err(err) => {
                            failed += 1;
                            println!("{}: {err}", e.slug());
                        }
                    }
                }
                if again.is_empty() || (pass > 1 && !progress) || pass >= 5 {
                    break;
                }
                pending = again;
            }
            for (slug, left) in &last {
                for l in left {
                    println!("{slug}: left as it was: {l}");
                }
            }
            anyhow::ensure!(failed == 0, "{failed} of {} failed", entries.len());
            Ok(())
        }
        Command::Token { username, name, days } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            let token = web::account::mint_token(&state, &user, &name, days)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{token}");
            Ok(())
        }
        Command::DevUser { username } => {
            if !cfg.dev_login {
                bail!("dev-user needs CACTARIUM_DEV_LOGIN=1 (local development only)");
            }
            username
                .parse::<cactup_ecosystem_common::name::Owner>()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let role = if cfg.is_superadmin("dev", &username) { "superadmin" } else { "user" };
            let uid: i64 = sqlx::query_scalar(
                "INSERT INTO users (username, role) VALUES ($1, $2) ON CONFLICT (username) DO UPDATE SET role = EXCLUDED.role RETURNING id",
            )
            .bind(&username)
            .bind(role)
            .fetch_one(&db)
            .await?;
            sqlx::query("INSERT INTO identities (user_id, provider, subject, login) VALUES ($1, 'dev', $2, $2) ON CONFLICT DO NOTHING")
                .bind(uid)
                .bind(&username)
                .execute(&db)
                .await?;
            println!("User {username} ({role})");
            Ok(())
        }
        Command::Serve => {
            migrate().await?;
            serve(cfg, db).await
        }
    }
}

async fn admin(db: &sqlx::PgPool, action: AdminAction) -> anyhow::Result<()> {
    let set = |sql: &'static str, who: String| async move {
        let n = sqlx::query(sql).bind(&who).execute(db).await?.rows_affected();
        if n == 0 {
            bail!("no user '{who}' (or nothing to change)");
        }
        sqlx::query(
            "INSERT INTO audit_log (action, target, details) VALUES ($1, $2, '{\"via\":\"cli\"}')",
        )
        .bind(sql.split_whitespace().nth(3).unwrap_or("cli"))
        .bind(&who)
        .execute(db)
        .await?;
        println!("Done: {who}");
        Ok(())
    };
    match action {
        AdminAction::Grant { username } => {
            set("UPDATE users SET role = 'admin' WHERE username = $1 AND role = 'user'", username).await
        }
        AdminAction::Revoke { username } => {
            set("UPDATE users SET role = 'user' WHERE username = $1 AND role = 'admin'", username).await
        }
        AdminAction::Trust { name } => set_trust(db, &name, true).await,
        AdminAction::Untrust { name } => set_trust(db, &name, false).await,
        AdminAction::List => {
            let rows: Vec<(String, String, bool)> =
                sqlx::query_as("SELECT username, role, trusted FROM users WHERE role <> 'user' OR trusted ORDER BY role DESC, username")
                    .fetch_all(db)
                    .await?;
            for (u, r, t) in rows {
                println!("{u}\t{r}{}", if t { "\ttrusted" } else { "" });
            }
            let orgs: Vec<String> =
                sqlx::query_scalar("SELECT name FROM orgs WHERE trusted ORDER BY name")
                    .fetch_all(db)
                    .await?;
            for o in orgs {
                println!("{o}\torganization\ttrusted");
            }
            let entries: Vec<String> = sqlx::query_scalar(
                "SELECT owner || '/' || name FROM entries WHERE trusted ORDER BY owner, name",
            )
            .fetch_all(db)
            .await?;
            for e in entries {
                println!("{e}\tentry\ttrusted");
            }
            Ok(())
        }
    }
}

async fn yank_cli(
    cfg: Config,
    db: sqlx::PgPool,
    username: &str,
    slug: &str,
    version: &str,
    yank: bool,
    reason: Option<&str>,
) -> anyhow::Result<()> {
    let state = make_state(cfg, db)?;
    let user = cli_user(&state, username).await?;
    let err = |e: error::AppError| anyhow::anyhow!("{e}");
    let (owner, name) = slug.split_once('/').context("give owner/name")?;
    let e = model::find_entry(&state, owner, name)
        .await
        .map_err(err)?
        .context("no such entry")?;
    let v = model::any_version_by_label(&state, e.id, version)
        .await
        .map_err(err)?
        .with_context(|| format!("{slug} has no version {version}"))?;
    publish::set_yanked(&state, &user, &e, v.id, yank, reason, "cli")
        .await
        .map_err(|err| match err {
            error::AppError::Forbidden => anyhow::anyhow!("{username} doesn't manage {slug}"),
            other => anyhow::anyhow!("{other}"),
        })?;
    println!("{} {slug}@{}", if yank { "Yanked" } else { "Unyanked" }, v.label());
    Ok(())
}

/// Trusts or untrusts `name`: an entry if it is `owner/name`, else the user or organization of
/// that name (they share one namespace).
async fn set_trust(db: &sqlx::PgPool, name: &str, trusted: bool) -> anyhow::Result<()> {
    let (sql, kind) = if name.contains('/') {
        ("UPDATE entries SET trusted = $2 WHERE owner || '/' || name = $1", "entry")
    } else if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM orgs WHERE name = $1)")
        .bind(name)
        .fetch_one(db)
        .await?
    {
        ("UPDATE orgs SET trusted = $2 WHERE name = $1", "org")
    } else {
        ("UPDATE users SET trusted = $2 WHERE username = $1", "user")
    };
    let n = sqlx::query(sql).bind(name).bind(trusted).execute(db).await?.rows_affected();
    if n == 0 {
        bail!("no user, organization or entry '{name}'");
    }
    let action = format!("{kind}.{}", if trusted { "trust" } else { "untrust" });
    sqlx::query("INSERT INTO audit_log (action, target, details) VALUES ($1, $2, '{\"via\":\"cli\"}')")
        .bind(&action)
        .bind(name)
        .execute(db)
        .await?;
    println!("{} {kind} {name}", if trusted { "Trusted" } else { "Untrusted" });
    Ok(())
}

fn make_state(cfg: Config, db: sqlx::PgPool) -> anyhow::Result<AppState> {
    Ok(AppState {
        db,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("cactarium")
            .build()?,
        limiter: Arc::new(security::RateLimiter::default()),
        definitions: Arc::new(flights::Flights::new(None, 512)),
        package_tips: Arc::new(flights::Flights::new(None, 512)),
        // Branch tips move; a stack's resolved tips are reused only briefly.
        stack_tips: Arc::new(flights::Flights::new(Some(Duration::from_secs(30)), 256)),
        cfg: Arc::new(cfg),
    })
}

async fn cli_user(state: &AppState, username: &str) -> anyhow::Result<auth::User> {
    let id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(&state.db)
        .await?
        .with_context(|| format!("no user '{username}'"))?;
    auth::load_user(state, id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("no such user")
}

async fn serve(cfg: Config, db: sqlx::PgPool) -> anyhow::Result<()> {
    if cfg.dev_login {
        tracing::warn!(
            "development sign-in is enabled (CACTARIUM_DEV_LOGIN); never use this on a public server"
        );
    }
    let state = make_state(cfg, db)?;
    if let Err(e) = tracker::backfill_built_thorns(&state).await {
        tracing::warn!("backfilling the thorn index failed: {e}");
    }
    // The poller is restarted if it ever panics, rather than polling silently stopping.
    let poller = state.clone();
    tokio::spawn(async move {
        loop {
            match tokio::spawn(tracker::poll_forever(poller.clone())).await {
                Err(e) if e.is_panic() => tracing::error!("the poller panicked; restarting it in a minute"),
                _ => tracing::error!("the poller stopped; restarting it in a minute"),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&sweeper.db)
                .await;
            // Registration previews' temporary mirrors left by a process that died.
            let _ = tokio::task::spawn_blocking(git::sweep_temp_mirrors).await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let bind = state.cfg.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("cannot listen on {bind}"))?;
    tracing::info!("listening on {bind}, serving {}", state.cfg.base_url);
    axum::serve(listener, web::router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Ctrl-C, or SIGTERM: what `docker stop` sends. As PID 1 in its container, the server gets no
/// default handling of SIGTERM, so without this every stop would wait out the grace period and
/// end in SIGKILL.
async fn shutdown_signal() {
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::warn!("cannot listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
}
