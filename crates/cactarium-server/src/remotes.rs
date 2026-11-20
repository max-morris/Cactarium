//! Repo URLs in what the Cactarium publishes: the shared rule
//! ([`cactup_ecosystem_common::url::shareability`]) that `cactup sim export` applies too, so both
//! refuse the same URLs. A registered repo's URL goes through [`crate::git::check_url`], which
//! also turns an ssh URL into its https equivalent when that answers anonymously; URLs written in
//! content (a stack's thornlist and overrides, a `.sim`'s thornlist and pins, downloads) are
//! checked here.

use cactup_ecosystem_common::crl::{self, ComponentType};
use cactup_ecosystem_common::url::{Redacted, Shareability, download_shareability, shareability};

/// What is wrong with a git remote written in published content, if anything: the shared rule,
/// except that an ssh URL is refused even when its https equivalent answers, since the Cactarium
/// can't rewrite a file someone else committed or uploaded; the message names the https URL to
/// use. Local paths pass when local repos are allowed (development and tests).
pub fn remote_problem(url: &str, allow_local: bool) -> Option<String> {
    match shareability(url) {
        Shareability::Shareable => None,
        Shareability::Local if allow_local => None,
        Shareability::Ssh { https: Some(https) } => Some(format!(
            "{} is an ssh URL, which needs an account on the host; publish its https URL ({https}) \
             instead, if anyone can fetch that",
            Redacted(url)
        )),
        s => s.refusal(url),
    }
}

/// What is wrong with a URL that names a file to download (a tarball component, a sim's input, a
/// `.sim` pin by sha256, a submitted download), if anything: the crate's rule for downloads
/// ([`download_shareability`]), the same one `cactup sim export` applies. A query string is fine
/// unless a key looks like a credential (`private_token`, `X-Amz-Signature`, …). Local paths pass
/// when local repos are allowed (development and tests).
pub fn download_problem(url: &str, allow_local: bool) -> Option<String> {
    match download_shareability(url) {
        Shareability::Local if allow_local => None,
        s => s.download_refusal(url),
    }
}

/// What is wrong with a URL meant for people with access (a thornlist's `!AUTH_URL`, often ssh) or
/// only informational (a `[[stack.pin]] url`): only credentials in it, by the shared rule.
pub fn credentials_problem(url: &str) -> Option<String> {
    match shareability(url) {
        s @ Shareability::Credentials => s.refusal(url),
        _ => None,
    }
}

/// What is wrong with the URL of one thornlist component, labeled by its repo: a git remote by
/// [`remote_problem`], a download by [`download_problem`], and any `!AUTH_URL` by
/// [`credentials_problem`] (an ssh one is fine there: it's for people with access).
pub fn component_problems(c: &crl::Component, allow_local: bool, out: &mut Vec<String>) {
    let label = |p: String| format!("repo '{}': {p}", c.repo);
    match (&c.ty, c.url.as_deref().filter(|u| !u.trim().is_empty())) {
        (ComponentType::Git, Some(u)) => out.extend(remote_problem(u, allow_local).map(label)),
        (ComponentType::Http | ComponentType::Https | ComponentType::Ftp, Some(u)) => {
            out.extend(download_problem(u, allow_local).map(label))
        }
        _ => {}
    }
    if let Some(a) = c.auth_url.as_deref() {
        out.extend(credentials_problem(a).map(|p| label(format!("its !AUTH_URL {p}"))));
    }
}

/// Every stored URL the rules above would refuse now, one line each, labeled by where it is
/// (`owner/name`, a version, a download): repos' URLs, the pins of stack releases and sims, the
/// URLs written in their thornlists (`!AUTH_URL` included) and sims' inputs, and downloads.
/// Read-only; for an admin deciding what to fix (`cactarium check-urls`).
pub async fn stored_problems(db: &sqlx::PgPool, allow_local: bool) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let repos: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT e.owner, e.name, r.url FROM entry_repos r JOIN entries e ON e.id = r.entry_id ORDER BY e.owner, e.name",
    )
    .fetch_all(db)
    .await?;
    for (owner, name, url) in repos {
        out.extend(remote_problem(&url, allow_local).map(|e| format!("{owner}/{name}: its repo: {e}")));
    }
    let pins: Vec<(String, String, String, String, String, String, bool)> = sqlx::query_as(
        "SELECT e.owner, e.name, v.version, p.sim, p.repo, p.url, p.commit IS NOT NULL
         FROM source_pins p JOIN versions v ON v.id = p.version_id JOIN entries e ON e.id = v.entry_id
         ORDER BY e.owner, e.name, v.sort_key, p.sim, p.repo",
    )
    .fetch_all(db)
    .await?;
    for (owner, name, version, sim, repo, url, git) in pins {
        let problem = if git { remote_problem(&url, allow_local) } else { download_problem(&url, allow_local) };
        let at = if sim.is_empty() { format!("{owner}/{name}@{version}") } else { format!("{owner}/{name}/{sim}@{version}") };
        out.extend(problem.map(|e| format!("{at}: pin '{repo}': {e}")));
    }
    let lists: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT e.owner, e.name, v.version, s.own_thornlist
         FROM stack_releases s JOIN versions v ON v.id = s.version_id JOIN entries e ON e.id = v.entry_id
         WHERE s.own_thornlist IS NOT NULL ORDER BY e.owner, e.name, v.sort_key",
    )
    .fetch_all(db)
    .await?;
    for (owner, name, version, text) in lists {
        out.extend(thornlist_problems(&text, allow_local).into_iter().map(|e| format!("{owner}/{name}@{version}: thornlist: {e}")));
    }
    let sims: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT e.owner, e.name, v.version, f.name, f.content
         FROM sim_files f JOIN versions v ON v.id = f.version_id JOIN entries e ON e.id = v.entry_id
         ORDER BY e.owner, e.name, v.sort_key, f.name",
    )
    .fetch_all(db)
    .await?;
    for (owner, name, version, sim, content) in sims {
        let Ok(file) = cactup_ecosystem_common::sim::SimFile::from_toml(&content) else { continue };
        let at = if sim.is_empty() { format!("{owner}/{name}@{version}") } else { format!("{owner}/{name}/{sim}@{version}") };
        out.extend(thornlist_problems(&file.thornlist.text, allow_local).into_iter().map(|e| format!("{at}: thornlist: {e}")));
        for i in &file.inputs {
            if let Some(u) = &i.url {
                out.extend(download_problem(u, allow_local).map(|e| format!("{at}: input {}: {e}", i.knob)));
            }
        }
    }
    let downloads: Vec<(String, String)> = sqlx::query_as("SELECT url, review FROM downloads ORDER BY url").fetch_all(db).await?;
    for (url, review) in downloads {
        out.extend(download_problem(&url, allow_local).map(|e| format!("download ({review}): {e}")));
    }
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|l| seen.insert(l.clone()));
    Ok(out)
}

/// [`component_problems`] for every component of a thornlist's text (none if it doesn't parse).
fn thornlist_problems(text: &str, allow_local: bool) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(list) = crl::parse(text) {
        for c in list.components().iter().filter(|c| c.ty != ComponentType::Ignore) {
            component_problems(c, allow_local, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes_in_content() {
        assert_eq!(remote_problem("https://github.com/x/y", false), None);
        assert_eq!(remote_problem("/srv/x", true), None, "development");
        assert!(remote_problem("/srv/x", false).unwrap().contains("local path"));
        let ssh = remote_problem("git@github.com:x/y.git", false).unwrap();
        assert!(ssh.contains("https://github.com/x/y.git") && ssh.contains("instead"), "{ssh}");
        let tok = remote_problem("https://s3cret@github.com/x/y", false).unwrap();
        assert!(!tok.contains("s3cret") && tok.contains("remove them"), "{tok}");
        assert!(remote_problem("https://github.com/x/y?private_token=s3cret", false).is_some());
    }

    #[test]
    fn downloads_and_auth_urls() {
        assert_eq!(download_problem("https://zenodo.org/records/1/files/x.h5?download=1", false), None);
        assert!(download_problem("https://u:s3cret@host/x.tgz", false).is_some_and(|p| !p.contains("s3cret")));
        assert!(download_problem("https://host/x?private_token=s3cret", false).is_some_and(|p| !p.contains("s3cret")));
        assert!(download_problem("https://b.s3.amazonaws.com/x?X-Amz-Signature=s3cret", false).is_some());
        assert!(download_problem("svn+ssh://host/x", false).is_some());
        assert_eq!(download_problem("/data/x.h5", true), None, "development");
        assert!(download_problem("/data/x.h5", false).is_some());
        // An !AUTH_URL: an ssh user name is fine, a password or token isn't.
        assert_eq!(credentials_problem("git@github.com:x/y"), None);
        assert!(credentials_problem("git:s3cret@host:x").is_some());
        assert!(credentials_problem("https://s3cret@host/x").is_some());
    }

}
