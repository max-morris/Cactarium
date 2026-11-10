//! The Cactarium: a registry of thorn packages, stacks and sim files for the Cactup ecosystem.

// Database rows are read as tuples; naming each one would add nothing.
#![allow(clippy::type_complexity)]

mod audit;
mod auth;
mod config;
mod error;
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
    /// Register a repo (package and/or stack) on behalf of a user; with --owner (the user must be
    /// an admin), under a namespace that is no user's, such as `et`.
    Register {
        username: String,
        url: String,
        #[arg(long)]
        owner: Option<String>,
    },
    /// Publish a .sim file on behalf of a user.
    PublishSim {
        username: String,
        file: std::path::PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Manage organizations from the command line.
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    /// Check an entry's repo for new and moved tags now.
    Sync { slug: String },
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
    /// Mark a user trusted (their submissions skip review).
    Trust { username: String },
    /// Mark a user untrusted again.
    Untrust { username: String },
    /// List admins and trusted users.
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
    let migrate = || sqlx::migrate!("./migrations").run(&db);
    match cli.command {
        Command::Migrate => {
            migrate().await?;
            println!("Migrations applied");
            Ok(())
        }
        Command::Admin { action } => admin(&db, action).await,
        Command::Register { username, url, owner } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            for e in tracker::register(&state, &user, &url, owner.as_deref())
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                println!("Registered {} ({}, {})", e.slug(), e.kind, e.visibility);
            }
            Ok(())
        }
        Command::PublishSim { username, file, name } => {
            let state = make_state(cfg, db)?;
            let user = cli_user(&state, &username).await?;
            let bytes =
                std::fs::read(&file).with_context(|| format!("cannot read '{}'", file.display()))?;
            let checked = sims::check(&bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
            let (owner, name) = match name.as_deref().and_then(|n| n.split_once('/')) {
                Some((o, n)) => (Some(o.to_owned()), Some(n.to_owned())),
                None => (None, name),
            };
            let (e, n) = sims::publish(&state, &user, owner.as_deref(), name.as_deref(), checked)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Published {}@{n} ({})", e.slug(), e.visibility);
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
        AdminAction::Trust { username } => {
            set("UPDATE users SET trusted = TRUE WHERE username = $1", username).await
        }
        AdminAction::Untrust { username } => {
            set("UPDATE users SET trusted = FALSE WHERE username = $1", username).await
        }
        AdminAction::List => {
            let rows: Vec<(String, String, bool)> =
                sqlx::query_as("SELECT username, role, trusted FROM users WHERE role <> 'user' OR trusted ORDER BY role DESC, username")
                    .fetch_all(db)
                    .await?;
            for (u, r, t) in rows {
                println!("{u}\t{r}{}", if t { "\ttrusted" } else { "" });
            }
            Ok(())
        }
    }
}

fn make_state(cfg: Config, db: sqlx::PgPool) -> anyhow::Result<AppState> {
    Ok(AppState {
        db,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("cactarium")
            .build()?,
        limiter: Arc::new(security::RateLimiter::default()),
        definitions: Arc::default(),
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
    tokio::spawn(tracker::poll_forever(state.clone()));
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            let _ = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
                .execute(&sweeper.db)
                .await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let bind = state.cfg.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("cannot listen on {bind}"))?;
    tracing::info!("listening on {bind}, serving {}", state.cfg.base_url);
    axum::serve(listener, web::router(state).into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
