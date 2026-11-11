//! Settings, all from the environment (see deploy/.env.example).

use anyhow::{Context, bail};
use url::Url;

#[derive(Clone, Debug)]
pub struct OAuthApp {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    /// The public origin, e.g. `https://cactarium.cct.lsu.edu` or `http://localhost:8000`.
    pub base_url: Url,
    pub bind: String,
    /// Identities that are always superadmin: `github:<numeric account id>` (a login could be
    /// renamed and claimed by someone else), `orcid:<iD>`, or `dev:<name>`.
    pub superadmins: Vec<(String, String)>,
    pub github: Option<OAuthApp>,
    pub orcid: Option<OAuthApp>,
    /// `https://orcid.org`, or `https://sandbox.orcid.org` for testing.
    pub orcid_base: Url,
    /// Local development only: sign in as any name without OAuth.
    pub dev_login: bool,
    /// Local development only: let the tracker read `file://` repos and private hosts.
    pub allow_local_repos: bool,
    /// Read the client address from X-Forwarded-For (set when behind the Apache proxy).
    pub trust_proxy: bool,
    /// Seconds between polls of every tracked repo for new tags.
    pub poll_interval: u64,
    /// Where the static files are.
    pub static_dir: String,
    /// The base URL of CactUp's own documentation (its CLI and the `.sim` format), which the
    /// site's docs link to instead of repeating it. No trailing slash.
    pub cactup_docs_url: String,
}

/// Where CactUp's docs are published (from its master branch), unless `CACTUP_DOCS_URL` says
/// otherwise.
const DEFAULT_CACTUP_DOCS_URL: &str = "https://max-morris.github.io/Cactup";

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn flag(name: &str) -> bool {
    matches!(var(name).as_deref(), Some("1" | "true" | "yes"))
}

fn oauth(prefix: &str) -> Option<OAuthApp> {
    Some(OAuthApp {
        client_id: var(&format!("{prefix}_CLIENT_ID"))?,
        client_secret: var(&format!("{prefix}_CLIENT_SECRET"))?,
    })
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let base_url: Url = var("CACTARIUM_BASE_URL")
            .unwrap_or_else(|| "http://localhost:8000".into())
            .parse()
            .context("CACTARIUM_BASE_URL is not a URL")?;
        let superadmins = var("CACTARIUM_SUPERADMIN")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| match s.split_once(':') {
                Some(("github", id)) if !id.chars().all(|c| c.is_ascii_digit()) => {
                    bail!("CACTARIUM_SUPERADMIN: give the GitHub account's numeric id, not its login ('{id}'); `gh api users/{id} -q .id` prints it")
                }
                Some((p, who)) if ["github", "orcid", "dev"].contains(&p) => {
                    Ok((p.to_owned(), who.to_ascii_lowercase()))
                }
                _ => bail!("CACTARIUM_SUPERADMIN entry '{s}' must be github:<login>, orcid:<iD> or dev:<name>"),
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let cfg = Config {
            database_url: var("DATABASE_URL").context("DATABASE_URL is not set")?,
            bind: var("CACTARIUM_BIND").unwrap_or_else(|| "127.0.0.1:8000".into()),
            superadmins,
            github: oauth("GITHUB"),
            orcid: oauth("ORCID"),
            orcid_base: var("ORCID_BASE_URL")
                .unwrap_or_else(|| "https://orcid.org".into())
                .parse()
                .context("ORCID_BASE_URL is not a URL")?,
            dev_login: flag("CACTARIUM_DEV_LOGIN"),
            allow_local_repos: flag("CACTARIUM_ALLOW_LOCAL_REPOS"),
            trust_proxy: flag("CACTARIUM_TRUST_PROXY"),
            poll_interval: var("CACTARIUM_POLL_SECONDS")
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(4 * 3600),
            static_dir: var("CACTARIUM_STATIC_DIR").unwrap_or_else(|| "static".into()),
            cactup_docs_url: var("CACTUP_DOCS_URL")
                .unwrap_or_else(|| DEFAULT_CACTUP_DOCS_URL.into())
                .parse::<Url>()
                .context("CACTUP_DOCS_URL is not a URL")?
                .as_str()
                .trim_end_matches('/')
                .to_owned(),
            base_url,
        };
        if (cfg.dev_login || cfg.allow_local_repos) && !cfg.is_local() {
            bail!(
                "CACTARIUM_DEV_LOGIN and CACTARIUM_ALLOW_LOCAL_REPOS are for local development only, \
                 but CACTARIUM_BASE_URL is {}",
                cfg.base_url
            );
        }
        Ok(cfg)
    }

    /// Whether the site is served from this machine only (http://localhost or 127.0.0.1).
    pub fn is_local(&self) -> bool {
        matches!(self.base_url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    }

    /// Cookies are `Secure` whenever the public origin is https.
    pub fn secure_cookies(&self) -> bool {
        self.base_url.scheme() == "https"
    }

    pub fn url(&self, path: &str) -> String {
        let base = self.base_url.as_str().trim_end_matches('/');
        format!("{base}{path}")
    }

    pub fn is_superadmin(&self, provider: &str, who: &str) -> bool {
        let who = who.to_ascii_lowercase();
        self.superadmins.iter().any(|(p, w)| p == provider && *w == who)
    }
}
