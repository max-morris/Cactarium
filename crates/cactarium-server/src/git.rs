//! Reading other people's git repos, carefully.
//!
//! The registry only ever lists refs and fetches single commits into throwaway directories; it
//! never runs anything from a repo. Every git call:
//! - accepts only https URLs (plus `file://` and private hosts when local repos are allowed, for
//!   development and tests), and refuses hosts that resolve to private, loopback or link-local
//!   addresses;
//! - runs with no system or user config, no credential prompts, no hooks, no submodules, no LFS;
//! - has a time limit, and fetched trees have a size limit.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use tokio::process::Command;

const TIMEOUT: Duration = Duration::from_secs(120);
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct GitPolicy {
    pub allow_local: bool,
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64 // 100.64/10, shared address space
        }
        IpAddr::V6(v) => {
            v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (v.segments()[0] & 0xffc0) == 0xfe80 // link local
                || v.to_ipv4_mapped().is_some_and(|m| private(IpAddr::V4(m)))
        }
    }
}

/// Checks a repo URL against the policy. Returns it normalized (no trailing slash, no userinfo).
pub async fn check_url(policy: GitPolicy, raw: &str) -> anyhow::Result<String> {
    let url = url::Url::parse(raw.trim()).with_context(|| format!("'{raw}' is not a URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("repo URLs must not contain credentials");
    }
    match url.scheme() {
        "https" => {}
        "file" if policy.allow_local => return Ok(url.to_string()),
        "http" if policy.allow_local => {}
        _ => bail!("repo URLs must be https://"),
    }
    let host = url.host_str().ok_or_else(|| anyhow!("'{raw}' has no host"))?.to_owned();
    if !policy.allow_local {
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .with_context(|| format!("cannot resolve '{host}'"))?
            .collect();
        if addrs.is_empty() || addrs.iter().any(|a| private(a.ip())) {
            bail!("'{host}' is not a public host");
        }
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn git(policy: GitPolicy, home: &Path) -> Command {
    let mut c = Command::new("git");
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .env("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
        .env("GIT_HTTP_LOW_SPEED_TIME", "30")
        .args(["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"])
        .args(["-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "-c", "credential.helper="])
        .args(["-c", "http.followRedirects=initial"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if policy.allow_local {
        c.args(["-c", "protocol.file.allow=always", "-c", "protocol.http.allow=always"]);
        // Development repos are bind-mounted and owned by another user. Git reads safe.directory
        // only from global or system config (not -c, for the upload-pack it spawns), so give
        // this call a global config of its own.
        let global = home.join("dev.gitconfig");
        if std::fs::write(&global, "[safe]\n\tdirectory = *\n").is_ok() {
            c.env("GIT_CONFIG_GLOBAL", global);
        }
    }
    c
}

async fn run(mut cmd: Command, what: &str) -> anyhow::Result<String> {
    let out = tokio::time::timeout(TIMEOUT, cmd.output())
        .await
        .map_err(|_| anyhow!("{what} timed out"))?
        .with_context(|| format!("{what}: cannot run git"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim();
        bail!("{what} failed: {line}");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A ref and the commit it names (tags peeled to their commit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRef {
    pub name: String,
    pub commit: String,
}

fn parse_ls_remote(out: &str, prefix: &str) -> Vec<RemoteRef> {
    let mut refs: Vec<RemoteRef> = Vec::new();
    for line in out.lines() {
        let Some((sha, name)) = line.split_once('\t') else { continue };
        let Some(short) = name.strip_prefix(prefix) else { continue };
        match short.strip_suffix("^{}") {
            // An annotated tag: the peeled line names the commit and wins.
            Some(tag) => match refs.iter_mut().find(|r| r.name == tag) {
                Some(r) => r.commit = sha.to_owned(),
                None => refs.push(RemoteRef { name: tag.to_owned(), commit: sha.to_owned() }),
            },
            None => {
                if !refs.iter().any(|r| r.name == short) {
                    refs.push(RemoteRef { name: short.to_owned(), commit: sha.to_owned() });
                }
            }
        }
    }
    refs
}

pub async fn ls_tags(policy: GitPolicy, url: &str) -> anyhow::Result<Vec<RemoteRef>> {
    let url = check_url(policy, url).await?;
    let home = tempfile::tempdir()?;
    let mut c = git(policy, home.path());
    c.args(["ls-remote", "--tags", "--", &url]);
    Ok(parse_ls_remote(&run(c, "listing tags").await?, "refs/tags/"))
}

/// The commit a branch (or tag) currently names, or the default branch's when `git_ref` is None.
pub async fn resolve_ref(policy: GitPolicy, url: &str, git_ref: Option<&str>) -> anyhow::Result<String> {
    let url = check_url(policy, url).await?;
    let home = tempfile::tempdir()?;
    let mut c = git(policy, home.path());
    c.args(["ls-remote", "--", &url]);
    let out = run(c, "listing refs").await?;
    let want: Vec<String> = match git_ref {
        None => vec!["HEAD".into()],
        Some(r) => vec![format!("refs/heads/{r}"), format!("refs/tags/{r}^{{}}"), format!("refs/tags/{r}")],
    };
    for w in &want {
        if let Some(line) = out.lines().find(|l| l.split_once('\t').is_some_and(|(_, n)| n == w)) {
            return Ok(line.split('\t').next().unwrap_or_default().to_owned());
        }
    }
    bail!("{url} has no {}", git_ref.map(|r| format!("branch or tag '{r}'")).unwrap_or_else(|| "default branch".into()))
}

/// A commit checked out into a temporary directory, removed when dropped.
pub struct Checkout {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    pub tree: String,
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.filter_map(Result::ok)
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// Fetches exactly `commit` (depth 1) and checks it out. Falls back to fetching `via` (a branch or
/// tag) when the server refuses to serve an unadvertised commit.
pub async fn checkout(policy: GitPolicy, url: &str, commit: &str, via: Option<&str>) -> anyhow::Result<Checkout> {
    let url = check_url(policy, url).await?;
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let path = dir.path().join("src");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&path)?;
    let g = |args: &[&str]| {
        let mut c = git(policy, &home);
        c.current_dir(&path).args(args);
        c
    };
    run(g(&["init", "-q"]), "git init").await?;
    let direct = run(g(&["fetch", "-q", "--depth", "1", "--no-tags", "--", &url, commit]), "fetching the commit").await;
    if let Err(e) = direct {
        let Some(via) = via else { return Err(e) };
        run(g(&["fetch", "-q", "--no-tags", "--", &url, via]), "fetching the commit").await?;
    }
    run(g(&["-c", "advice.detachedHead=false", "checkout", "-q", commit]), "checking out the commit").await?;
    let tree = run(g(&["rev-parse", &format!("{commit}^{{tree}}")]), "reading the tree").await?.trim().to_owned();
    let size = dir_size(&path);
    if size > MAX_TREE_BYTES {
        bail!("the repo is too large to index ({} MB)", size / (1024 * 1024));
    }
    Ok(Checkout { _dir: dir, path, tree })
}

/// Reads a file inside a checkout, refusing paths that escape it (`..`, absolute, symlinks out).
pub fn read_in(co: &Checkout, rel: &str) -> anyhow::Result<Option<String>> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() || rel_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bail!("'{rel}' must be a path inside the repo");
    }
    let p = co.path.join(rel_path);
    let Ok(real) = p.canonicalize() else { return Ok(None) };
    let root = co.path.canonicalize()?;
    if !real.starts_with(&root) {
        bail!("'{rel}' points outside the repo");
    }
    if std::fs::metadata(&real)?.len() > 4 * 1024 * 1024 {
        bail!("'{rel}' is larger than 4 MB");
    }
    Ok(Some(std::fs::read_to_string(&real).with_context(|| format!("'{rel}' is not UTF-8 text"))?))
}

/// A URL in canonical form for matching (scheme-less, no `.git`, no trailing slash, lowercase host).
pub fn normalize_url(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    let u = u.strip_suffix(".git").unwrap_or(u);
    let u = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    match u.split_once('/') {
        Some((host, path)) => format!("{}/{}", host.to_ascii_lowercase(), path),
        None => u.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_remote_peels_annotated_tags() {
        let out = "aaa\trefs/tags/v1.0.0\nbbb\trefs/tags/v1.0.0^{}\nccc\trefs/tags/v1.1.0\nddd\trefs/heads/master\n";
        let r = parse_ls_remote(out, "refs/tags/");
        assert_eq!(
            r,
            [
                RemoteRef { name: "v1.0.0".into(), commit: "bbb".into() },
                RemoteRef { name: "v1.1.0".into(), commit: "ccc".into() }
            ]
        );
    }

    #[test]
    fn private_addresses() {
        for a in ["10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"] {
            assert!(private(a.parse().unwrap()), "{a}");
        }
        for a in ["140.82.112.3", "2606:50c0:8000::153"] {
            assert!(!private(a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn url_normalization() {
        assert_eq!(normalize_url("https://GitHub.com/max-morris/CarpetX.git/"), "github.com/max-morris/CarpetX");
        assert_eq!(normalize_url("https://github.com/max-morris/CarpetX"), "github.com/max-morris/CarpetX");
    }

    #[tokio::test]
    async fn url_policy() {
        let strict = GitPolicy { allow_local: false };
        assert!(check_url(strict, "file:///etc").await.is_err());
        assert!(check_url(strict, "ssh://github.com/x").await.is_err());
        assert!(check_url(strict, "https://user:pw@github.com/x").await.is_err());
        assert!(check_url(strict, "https://127.0.0.1/x").await.is_err());
        assert!(check_url(strict, "https://localhost/x").await.is_err());
        let dev = GitPolicy { allow_local: true };
        assert!(check_url(dev, "file:///tmp/repo").await.is_ok());
    }
}
