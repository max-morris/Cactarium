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

/// Addresses the registry must never fetch from: anything not globally routable.
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()
                || v.is_multicast() || v.is_documentation()
                || o[0] == 0                                   // 0/8
                || o[0] == 100 && (o[1] & 0xc0) == 64          // 100.64/10, shared address space
                || o[0] == 192 && o[1] == 0 && o[2] == 0       // 192.0.0/24, protocol assignments
                || o[0] == 198 && (o[1] & 0xfe) == 18          // 198.18/15, benchmarking
                || o[0] >= 240 // 240/4, reserved
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00                   // unique local
                || (s[0] & 0xffc0) == 0xfe80                   // link local
                || s[0] == 0x0064 && s[1] == 0xff9b            // 64:ff9b::/96 and /48, NAT64
                || s[0] == 0x2001 && s[1] == 0x0db8            // documentation
                || v.to_ipv4_mapped().is_some_and(|m| private(IpAddr::V4(m)))
                || v.to_ipv4().is_some_and(|m| private(IpAddr::V4(m)))
        }
    }
}

/// A repo URL that passed the policy, and the address git must connect to.
#[derive(Clone, Debug)]
pub struct Target {
    pub url: String,
    /// `host:port:address` for curl's resolve list: git connects to the address that was checked,
    /// not to whatever the name resolves to a moment later (DNS rebinding).
    resolve: Option<String>,
}

/// Checks a repo URL against the policy. Returns it normalized (no trailing slash, no userinfo).
pub async fn check_url(policy: GitPolicy, raw: &str) -> anyhow::Result<String> {
    Ok(check(policy, raw).await?.url)
}

async fn check(policy: GitPolicy, raw: &str) -> anyhow::Result<Target> {
    let url = url::Url::parse(raw.trim()).with_context(|| format!("'{raw}' is not a URL"))?;
    if url.scheme() == "file" && policy.allow_local {
        return Ok(Target { url: url.to_string(), resolve: None });
    }
    let (url, address) = vet(policy, url, "repo URLs").await?;
    let normalized = url.as_str().trim_end_matches('/').to_owned();
    Ok(Target {
        url: normalized,
        resolve: address.map(|(host, addr)| {
            let ip = match addr.ip() {
                IpAddr::V4(v) => v.to_string(),
                IpAddr::V6(v) => format!("[{v}]"),
            };
            format!("{host}:{}:{ip}", addr.port())
        }),
    })
}

/// The outbound-fetch policy every URL the server reads goes through: https only (plus http, and
/// private hosts, when local repos are allowed, for development and tests), no credentials, and a
/// host that resolves only to public addresses. Returns the URL and, unless local repos are
/// allowed, the host (without brackets) and the checked address to connect to, so the fetch can't
/// be sent elsewhere by a second lookup (DNS rebinding). `what` names the URLs in messages.
async fn vet(policy: GitPolicy, url: url::Url, what: &str) -> anyhow::Result<(url::Url, Option<(String, std::net::SocketAddr)>)> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{what} must not contain credentials");
    }
    match url.scheme() {
        "https" => {}
        "http" if policy.allow_local => {}
        _ => bail!("{what} must be https://"),
    }
    let host = url.host_str().ok_or_else(|| anyhow!("'{url}' has no host"))?.to_owned();
    if policy.allow_local {
        return Ok((url, None));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("cannot resolve '{host}'"))?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| private(a.ip())) {
        bail!("'{host}' is not a public host");
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    Ok((url, Some((bare, addrs[0]))))
}

/// What fetching a download read: its content's sha256 (hex) and size.
#[derive(Debug)]
pub struct Fetched {
    pub sha256: String,
    pub size: u64,
}

/// Fetches `raw` once, under the outbound-fetch policy ([`vet`], applied again to every redirect,
/// at most 5), hashing the body as it streams and stopping past `max_bytes`. Nothing is kept.
pub async fn fetch_and_hash(policy: GitPolicy, raw: &str, max_bytes: u64, time_limit: Duration) -> anyhow::Result<Fetched> {
    use sha2::Digest;
    let mut url = url::Url::parse(raw.trim()).with_context(|| format!("'{raw}' is not a URL"))?;
    let started = std::time::Instant::now();
    for _ in 0..=5 {
        let (checked, address) = vet(policy, url, "download URLs").await?;
        let mut client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(20))
            .read_timeout(Duration::from_secs(60))
            .user_agent("cactarium");
        if let Some((host, addr)) = &address {
            client = client.resolve(host, *addr);
        }
        let client = client.build()?;
        let left = time_limit.saturating_sub(started.elapsed());
        let mut resp = tokio::time::timeout(left, client.get(checked.clone()).send())
            .await
            .map_err(|_| anyhow!("it took over {} minutes", time_limit.as_secs() / 60))??;
        if resp.status().is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|l| l.to_str().ok())
                .ok_or_else(|| anyhow!("a redirect without a location"))?;
            url = checked.join(to).with_context(|| format!("a redirect to '{to}'"))?;
            continue;
        }
        if !resp.status().is_success() {
            bail!("the server answered {}", resp.status());
        }
        if let Some(n) = resp.content_length()
            && n > max_bytes
        {
            bail!("it is {n} bytes, more than the {max_bytes} the Cactarium reads");
        }
        let mut h = sha2::Sha256::new();
        let mut size: u64 = 0;
        loop {
            let left = time_limit.saturating_sub(started.elapsed());
            let chunk = tokio::time::timeout(left, resp.chunk())
                .await
                .map_err(|_| anyhow!("it took over {} minutes", time_limit.as_secs() / 60))??;
            let Some(chunk) = chunk else { break };
            size += chunk.len() as u64;
            if size > max_bytes {
                bail!("it is more than the {max_bytes} bytes the Cactarium reads");
            }
            h.update(&chunk);
        }
        return Ok(Fetched { sha256: hex::encode(h.finalize()), size });
    }
    bail!("more than 5 redirects")
}

fn git_to(policy: GitPolicy, home: &Path, target: &Target) -> Command {
    let mut c = git(policy, home);
    if let Some(r) = &target.resolve {
        c.args(["-c", &format!("http.curloptResolve={r}")]);
    }
    c
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
        // Each transport pinned by name: a repo's own config can enable a protocol by name, which
        // beats the general `protocol.allow`, but not a `-c` setting of the same name.
        .args(["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"])
        .args([
            "-c",
            "protocol.ext.allow=never",
            "-c",
            "protocol.fd.allow=never",
            "-c",
            "protocol.file.allow=never",
        ])
        .args([
            "-c",
            "protocol.git.allow=never",
            "-c",
            "protocol.ssh.allow=never",
            "-c",
            "protocol.http.allow=never",
        ])
        // No detached gc or maintenance outliving the call (and its time limit and locks).
        .args(["-c", "gc.auto=0", "-c", "maintenance.auto=false"])
        // A missing object in a partial clone is an error, never a quiet fetch from the network.
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "submodule.recurse=false",
            "-c",
            "credential.helper=",
        ])
        // A redirect could point anywhere, including inside our own network.
        .args(["-c", "http.followRedirects=false"])
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

async fn run(cmd: Command, what: &str) -> anyhow::Result<String> {
    exec(cmd, None, what, TIMEOUT, None).await
}


/// [`run`], with `input` written to the command's stdin.
async fn run_with_input(cmd: Command, input: String, what: &str) -> anyhow::Result<String> {
    exec(cmd, Some(input), what, TIMEOUT, None).await
}

/// The most a git command may print. Listings of an honest repo are far smaller; a hostile server
/// could otherwise stream refs until the server runs out of memory.
const MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// How much of stderr is kept: the end, where git puts the reason it failed.
const STDERR_TAIL: usize = 64 * 1024;

/// Runs a git command within `limit`, with its output capped. With `watch`, the directory is
/// checked every couple of seconds and the command stopped once it holds more than the given
/// bytes: git has no size limit on what a fetch downloads. However the command ends early (a time
/// limit, a cap, the caller going away), git is killed.
async fn exec(
    cmd: Command,
    input: Option<String>,
    what: &str,
    limit: Duration,
    watch: Option<(&Path, u64)>,
) -> anyhow::Result<String> {
    exec_raw(cmd, input, what, limit, watch).await.map(|out| String::from_utf8_lossy(&out).into_owned())
}

/// [`exec`], with the output as git printed it (bytes, not text).
async fn exec_raw(
    mut cmd: Command,
    input: Option<String>,
    what: &str,
    limit: Duration,
    watch: Option<(&Path, u64)>,
) -> anyhow::Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let work = async {
        let mut child = cmd.spawn().with_context(|| format!("{what}: cannot run git"))?;
        let stdin = child.stdin.take();
        let mut stdout = child.stdout.take().context("no stdout")?;
        let mut stderr = child.stderr.take().context("no stderr")?;
        // All three pipes at once, so none can fill up and stall git.
        let write = async move {
            match (stdin, input) {
                (Some(mut w), Some(i)) => {
                    let r = w.write_all(i.as_bytes()).await;
                    drop(w);
                    r
                }
                _ => Ok(()),
            }
        };
        let read_out = async {
            let mut buf = Vec::new();
            (&mut stdout).take(MAX_OUTPUT as u64 + 1).read_to_end(&mut buf).await?;
            if buf.len() > MAX_OUTPUT {
                // Only a huge repo makes git print this much (a tree of hundreds of thousands of
                // files): a fact about the commit, as the size checks are.
                return Err(TooLarge(format!(
                    "the repo is too large to index ({what}: git printed more than {} MB)",
                    MAX_OUTPUT / (1024 * 1024)
                ))
                .into());
            }
            anyhow::Ok(buf)
        };
        let read_err = async {
            let (mut tail, mut chunk) = (Vec::new(), [0u8; 8192]);
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        tail.extend_from_slice(&chunk[..n]);
                        if tail.len() > 2 * STDERR_TAIL {
                            tail.drain(..tail.len() - STDERR_TAIL);
                        }
                    }
                }
            }
            tail
        };
        // Hitting the output cap ends the wait at once (git, blocked on a full pipe, would never
        // close stderr); a write error is kept for later, since it matters only if git succeeded.
        let (written, out, err) =
            tokio::try_join!(async { anyhow::Ok(write.await) }, read_out, async {
                anyhow::Ok(read_err.await)
            })?;
        let status = child.wait().await.with_context(|| format!("{what}: cannot run git"))?;
        if !status.success() {
            let err = String::from_utf8_lossy(&err);
            let line = err.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim();
            bail!("{what} failed: {line}");
        }
        // A write error (a closed pipe) matters only if git otherwise succeeded.
        written.with_context(|| format!("{what}: cannot write to git"))?;
        anyhow::Ok(out)
    };
    let watched = async {
        let Some((dir, max)) = watch else { return std::future::pending().await };
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let d = dir.to_path_buf();
            let size = tokio::task::spawn_blocking(move || dir_size(&d)).await.unwrap_or(0);
            if size > max {
                return anyhow::Error::new(TooLarge(format!(
                    "{what}: the download passed {} MB and was stopped",
                    max / (1024 * 1024)
                )));
            }
        }
    };
    tokio::time::timeout(limit, async {
        tokio::select! {
            r = work => r,
            e = watched => Err(e),
        }
    })
    .await
    .map_err(|_| anyhow!("{what} timed out"))?
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
    let t = check(policy, url).await?;
    let home = tempfile::tempdir()?;
    let mut c = git_to(policy, home.path(), &t);
    c.args(["ls-remote", "--tags", "--", &t.url]);
    Ok(parse_ls_remote(&run(c, "listing tags").await?, "refs/tags/"))
}

/// The commit a branch (or tag) currently names, or the default branch's when `git_ref` is None.
pub async fn resolve_ref(policy: GitPolicy, url: &str, git_ref: Option<&str>) -> anyhow::Result<String> {
    let t = check(policy, url).await?;
    let url = t.url.clone();
    let home = tempfile::tempdir()?;
    let mut c = git_to(policy, home.path(), &t);
    c.args(["ls-remote", "--", &url]);
    let out = run(c, "listing refs").await?;
    let want: Vec<String> = match git_ref {
        None => vec!["HEAD".into()],
        Some(r) => {
            vec![format!("refs/heads/{r}"), format!("refs/tags/{r}^{{}}"), format!("refs/tags/{r}")]
        }
    };
    for w in &want {
        if let Some(line) = out.lines().find(|l| l.split_once('\t').is_some_and(|(_, n)| n == w)) {
            return Ok(line.split('\t').next().unwrap_or_default().to_owned());
        }
    }
    Err(Missing(format!(
        "{url} has no {}",
        git_ref
            .map(|r| format!("branch or tag '{r}'"))
            .unwrap_or_else(|| "default branch".into())
    ))
    .into())
}

/// A ref the repo answered it doesn't have: a fact about the repo now, unlike a failure to reach it.
#[derive(Debug)]
pub struct Missing(pub String);

impl std::fmt::Display for Missing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Missing {}

/// The commit a tag names (peeled, for an annotated tag), or None when the repo has no such tag.
pub async fn resolve_tag(policy: GitPolicy, url: &str, tag: &str) -> anyhow::Result<Option<String>> {
    let t = check(policy, url).await?;
    let home = tempfile::tempdir()?;
    let mut c = git_to(policy, home.path(), &t);
    // The pattern also brings the peeled `^{}` line of an annotated tag, which parse_ls_remote prefers.
    c.args(["ls-remote", "--tags", "--", &t.url, &format!("refs/tags/{tag}")]);
    let out = run(c, "listing tags").await?;
    Ok(parse_ls_remote(&out, "refs/tags/")
        .into_iter()
        .find(|r| r.name == tag)
        .map(|r| r.commit))
}

/// What an abbreviated commit id matches in a repo's history.
pub enum PrefixMatch {
    One(String),
    None,
    /// More than one commit starts with it: the full ids.
    Many(Vec<String>),
}

/// Where the history-only mirrors live: `CACTARIUM_MIRRORS`, else a folder in the temp dir. They
/// are a cache; deleting one only costs a clone.
fn mirror_root() -> PathBuf {
    std::env::var_os("CACTARIUM_MIRRORS")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("cactarium-mirrors"))
}

/// The mirror root, checked once: created if missing, and refused unless this process owns it and
/// nobody else can write it. Git reads each mirror's own config, so whoever could write there could
/// make git run commands.
async fn private_root() -> anyhow::Result<PathBuf> {
    static ROOT: tokio::sync::OnceCell<Result<PathBuf, String>> = tokio::sync::OnceCell::const_new();
    let checked = ROOT
        .get_or_init(|| async {
            let root = mirror_root();
            let r = root.clone();
            tokio::task::spawn_blocking(move || check_private_dir(&r))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r.map_err(|e| format!("{e:#}")))
                .map(|()| root)
        })
        .await;
    checked.clone().map_err(|e| anyhow!("{e}"))
}

fn check_private_dir(root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .with_context(|| format!("cannot create '{}'", root.display()))?;
    // Who we are, as the file system sees it: the owner of a file we just made there.
    let probe =
        tempfile::tempfile_in(root).with_context(|| format!("cannot write in '{}'", root.display()))?;
    let me = probe.metadata()?.uid();
    let meta = std::fs::metadata(root)?;
    if meta.uid() != me {
        bail!(
            "'{}' belongs to another user; set CACTARIUM_MIRRORS to a directory of our own",
            root.display()
        );
    }
    if meta.mode() & 0o077 != 0 {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot make '{}' private", root.display()))?;
    }
    Ok(())
}

/// How long after an update a miss may start another. A prefix that matches nothing would otherwise
/// cost a fetch per request; within this window it is answered from the mirror as it is. A commit
/// pushed just after an update is found once the window has passed.
const MIRROR_REFRESH: Duration =
    if cfg!(test) { Duration::from_secs(1) } else { Duration::from_secs(60) };

/// A first clone gets longer than other git calls: big histories take a while even without blobs.
const CLONE_TIMEOUT: Duration = Duration::from_secs(600);

/// Scratch clones older than this are leftovers of a server that died mid-clone.
const STALE_CLONE: Duration = Duration::from_secs(3600);

/// At most this many mirrors are cloned or fetched at once, whatever the requests ask for.
static MIRROR_UPDATES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(3);

/// Lookups (`POST /lookup`, anonymous) update kept mirrors one at a time, on a slot of their own:
/// however many lookups arrive, they never take one of the slots syncing uses.
static LOOKUP_UPDATES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Registration previews' temporary mirrors are cloned one at a time, on their own slot: a preview
/// never takes one of the slots syncing uses.
static PREVIEW_UPDATES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// The most a registration preview's temporary mirror may download (it has no file contents, only
/// commits and trees): a clone that outgrows it is stopped. Kept mirrors, of registered repos, have
/// no such limit, beyond the clone's time limit.
const MAX_PREVIEW_MIRROR_BYTES: u64 = 1024 * 1024 * 1024;

/// Temporary mirror roots are named so; one older than this is a leftover of a process that died.
const TEMP_MIRROR_PREFIX: &str = "cactarium-preview-";
const STALE_TEMP_MIRROR: Duration = Duration::from_secs(3600);

/// Removes temporary preview mirrors left behind by a process that died before dropping them (at
/// startup, and now and then). Only old ones: a younger one may be a running preview's, here or in
/// another process (`just cli check`). Blocking work.
pub fn sweep_temp_mirrors() {
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else { return };
    for e in rd.flatten() {
        let stale = e.file_name().to_string_lossy().starts_with(TEMP_MIRROR_PREFIX)
            && e.file_type().is_ok_and(|t| t.is_dir())
            && e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age > STALE_TEMP_MIRROR);
        if stale {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Where a repo's history mirror lives: with the others, kept and reused, or for a registration
/// preview of a repo nobody registered yet, in a temporary directory of its own, deleted once the
/// last holder lets go (the request, or a clone it started that is still running after the request
/// went away), so a preview leaves nothing behind.
#[derive(Clone)]
pub enum Mirrors {
    Shared,
    Temp(std::sync::Arc<TempMirrors>),
}

/// A temporary mirror root, removed when dropped.
pub struct TempMirrors {
    root: Option<tempfile::TempDir>,
}

impl Mirrors {
    /// A new temporary mirror root, private to this process.
    pub fn temp() -> anyhow::Result<Mirrors> {
        let root = tempfile::Builder::new().prefix(TEMP_MIRROR_PREFIX).tempdir()?;
        Ok(Mirrors::Temp(std::sync::Arc::new(TempMirrors { root: Some(root) })))
    }

    /// The temporary root's path, if this is one.
    pub fn temp_path(&self) -> Option<PathBuf> {
        match self {
            Mirrors::Shared => None,
            Mirrors::Temp(t) => t.root.as_ref().map(|r| r.path().to_path_buf()),
        }
    }
}

impl Drop for TempMirrors {
    fn drop(&mut self) {
        let Some(root) = self.root.take() else { return };
        let base = root.path().to_path_buf();
        MIRRORS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|dir, _| !dir.starts_with(&base));
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => drop(rt.spawn_blocking(move || drop(root))),
            Err(_) => drop(root),
        }
    }
}

/// One mirror's writer state. Its lock is held while the mirror is cloned or fetched, so updates of
/// one mirror never overlap (git would refuse the second, not corrupt anything) and different
/// repos never wait on each other. Lookups don't take it: git readers are safe beside a writer.
#[derive(Default)]
struct MirrorState {
    /// When the last clone or fetch ended, successful or not.
    finished: Option<std::time::Instant>,
    /// Why it failed, if it did: repeated to every request in the window.
    error: Option<String>,
    /// Git couldn't read it ([`flag_broken`]): the next update moves it aside and clones it again.
    broken: bool,
}

/// One entry per mirror this process has updated; bounded by the registered repos.
type MirrorLocks = std::collections::HashMap<PathBuf, std::sync::Arc<tokio::sync::Mutex<MirrorState>>>;
static MIRRORS: std::sync::LazyLock<std::sync::Mutex<MirrorLocks>> =
    std::sync::LazyLock::new(Default::default);

fn mirror_lock(dir: &Path) -> std::sync::Arc<tokio::sync::Mutex<MirrorState>> {
    let mut locks = MIRRORS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.entry(dir.to_path_buf()).or_default().clone()
}

/// A mirror is complete once its directory has a HEAD: clones are renamed into place whole.
async fn mirror_complete(dir: &Path) -> bool {
    tokio::fs::try_exists(dir.join("HEAD")).await.unwrap_or(false)
}

/// Resolves an abbreviated commit id against the repo's history, kept in a bare, blobless mirror
/// (commits and trees, no file contents): cloned on first use, fetched again when the prefix isn't
/// found, at most once per [`MIRROR_REFRESH`]. A full id is returned as it is; whether it exists is
/// for the checkout to find out.
///
/// The mirror has every branch and tag, so a commit is found if a branch or tag reaches it, or
/// reached it when the mirror last fetched. Commits reachable only from other refs (pull requests)
/// aren't; their full ids still work. A prefix unique in the mirror is taken as unique, even if
/// the repo has since gained another commit sharing it: the answer always names the full id.
pub async fn resolve_commit_prefix(
    policy: GitPolicy,
    url: &str,
    prefix: &str,
) -> anyhow::Result<PrefixMatch> {
    if !cactup_ecosystem_common::slug::is_commit_prefix(prefix) {
        bail!("'{prefix}' is not an abbreviated commit id");
    }
    if prefix.len() == 40 || prefix.len() == 64 {
        return Ok(PrefixMatch::One(prefix.to_owned()));
    }
    let (root, key, dir) = mirror_of(url).await?;
    let home = tempfile::tempdir()?;
    let mut broken = false;
    if mirror_complete(&dir).await {
        match lookup_commits(policy, home.path(), &dir, prefix).await {
            Ok(found) if !found.is_empty() => return Ok(classify(found)),
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("mirror of {key} unreadable ({e:#}); it will be cloned again");
                broken = true;
            }
        }
    }
    let error = update_mirror(policy, key.to_owned(), root, dir.clone(), broken).await;
    // Looked up again even when this request didn't update: another one may have, while it waited.
    if !mirror_complete(&dir).await {
        bail!("{}", error.unwrap_or_else(|| "the repo's history isn't available yet".into()));
    }
    let found = lookup_commits(policy, home.path(), &dir, prefix).await?;
    match error {
        // The mirror may be stale, so "no such commit" would be a guess.
        Some(e) if found.is_empty() => bail!("{e}"),
        _ => Ok(classify(found)),
    }
}

/// The mirror root, a repo's key and its mirror's directory. Keyed by the stored URL (normalized
/// when the repo was registered), so a lookup the mirror can answer needs no DNS; the URL is checked
/// when an update goes out to the network.
async fn mirror_of(url: &str) -> anyhow::Result<(PathBuf, String, PathBuf)> {
    mirror_in(&Mirrors::Shared, url).await
}

/// [`mirror_of`], among `mirrors`.
async fn mirror_in(mirrors: &Mirrors, url: &str) -> anyhow::Result<(PathBuf, String, PathBuf)> {
    let root = match mirrors.temp_path() {
        Some(p) => p,
        None => private_root().await?,
    };
    let key = url.trim().trim_end_matches('/').to_owned();
    let dir = root.join(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(key.as_bytes())));
    Ok((root, key, dir))
}

/// What the mirror holds for each of `commits` (after peeling, as `ls-remote` gives them): its
/// object type ("commit", "tree", ...), or `None` when it is missing (or the mirror is).
async fn object_types(policy: GitPolicy, dir: &Path, commits: &[String]) -> Vec<Option<String>> {
    if !mirror_complete(dir).await {
        return vec![None; commits.len()];
    }
    let Ok(home) = tempfile::tempdir() else { return vec![None; commits.len()] };
    let mut c = git(policy, home.path());
    c.arg("-C").arg(dir).args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]);
    let input: String = commits.iter().map(|c| format!("{c}\n")).collect();
    let Ok(out) = run_with_input(c, input, "looking up the tagged commits").await else { return vec![None; commits.len()] };
    // One line per input, in order: "<id> <type>", or "<input> missing".
    out.lines()
        .map(|l| {
            let mut p = l.split_whitespace();
            match (p.next(), p.next()) {
                (Some(_), Some("missing")) | (_, None) => None,
                (Some(_), Some(kind)) => Some(kind.to_owned()),
                _ => None,
            }
        })
        .chain(std::iter::repeat(None))
        .take(commits.len())
        .collect()
}

/// Whether the mirror is missing (or lacks any of) `commits`.
async fn lacks_commits(policy: GitPolicy, dir: &Path, commits: &[String]) -> bool {
    object_types(policy, dir, commits).await.iter().any(Option::is_none)
}

/// What a kept mirror says of some commits ([`mirror_has_commits`]).
pub struct MirrorAnswer {
    /// For each commit asked: `Some(true)` when the mirror has it, `Some(false)` when it doesn't
    /// after an update this call waited for, `None` when it can't tell just now (the update failed,
    /// none was allowed, or the last one was too recent for another).
    pub has: Vec<Option<bool>>,
    /// Whether an update was asked for (whether or not one ran: the window may have answered).
    pub updated: bool,
}

/// Whether the repo's kept history mirror has each of `commits` (full ids), as commits. `None`
/// when no mirror is kept for the repo yet: this never clones one. A mirror that lacks some is
/// brought up to date first when `refresh` allows it (asked only then), at most once per
/// [`MIRROR_REFRESH`], on the lookups' own slot ([`LOOKUP_UPDATES`]).
pub async fn mirror_has_commits(policy: GitPolicy, url: &str, commits: &[String], refresh: impl FnOnce() -> bool) -> Option<MirrorAnswer> {
    let (root, key, dir) = mirror_of(url).await.ok()?;
    if !mirror_complete(&dir).await {
        return None;
    }
    let is_commit = |types: Vec<Option<String>>| types.into_iter().map(|t| t.as_deref() == Some("commit")).collect::<Vec<bool>>();
    let first = is_commit(object_types(policy, &dir, commits).await);
    if first.iter().all(|&b| b) {
        return Some(MirrorAnswer { has: first.into_iter().map(Some).collect(), updated: false });
    }
    if !refresh() {
        return Some(MirrorAnswer { has: first.into_iter().map(|b| b.then_some(true)).collect(), updated: false });
    }
    // Never queued: a lookup that finds the slot busy says "can't tell" for what the mirror lacks.
    // So does one the refresh window answered without fetching: a commit pushed since the last
    // update would be missing, though the repo has it.
    let before = mirror_lock(&dir).lock().await.finished;
    let error = update_mirror_in(policy, &Mirrors::Shared, key, root, dir.clone(), false, None, &LOOKUP_UPDATES, Wait::Never).await;
    let fetched = mirror_lock(&dir).lock().await.finished != before;
    let after = is_commit(object_types(policy, &dir, commits).await);
    let has = after
        .into_iter()
        .map(|b| if b { Some(true) } else if error.is_none() && fetched { Some(false) } else { None })
        .collect();
    Some(MirrorAnswer { has, updated: true })
}

/// A file as a commit has it.
#[derive(Clone, Debug)]
pub enum FileAt {
    /// The commit has no such file (or it is a folder or a submodule).
    Absent,
    /// Larger than [`MAX_FILE_AT`] (its size, when known before downloading it).
    TooLarge(Option<u64>),
    Content(Vec<u8>),
    /// Not a plain file in the mirror (a symbolic link, which a checkout follows inside the repo),
    /// or its content couldn't be fetched by id: read it from a checkout (`read_in`) instead.
    NeedsCheckout,
    /// The tag names a tree or a blob, not a commit: a fact about the tag.
    NotCommit,
    /// The commit isn't in the repo's history (as far as the mirror knows): try again later.
    Unavailable,
}

/// The largest file [`read_files_in`] returns, like [`read_in`].
pub const MAX_FILE_AT: u64 = 4 * 1024 * 1024;

/// Reads files at commits from the repo's history mirror, without checking anything out: the
/// mirror is fetched when a commit isn't in it, and each blob it lacks (it is blobless) is fetched
/// by id on its own, the download stopped once it outgrows [`MAX_FILE_AT`]. Each file's outcome
/// stands alone ([`FileAt`]); an error means the repo couldn't be read at all right now (the mirror
/// couldn't be updated), and says nothing about any tag.
/// The mirror is among `mirrors` (the shared ones, or a preview's temporary root).
pub async fn read_files_in(policy: GitPolicy, mirrors: &Mirrors, url: &str, wants: &[(String, String)]) -> anyhow::Result<Vec<FileAt>> {
    if wants.is_empty() {
        return Ok(Vec::new());
    }
    let (root, key, dir) = mirror_in(mirrors, url).await?;
    let home = tempfile::tempdir()?;
    let mut commits: Vec<String> = wants.iter().map(|(c, _)| c.clone()).collect();
    commits.sort_unstable();
    commits.dedup();
    let mut types = object_types(policy, &dir, &commits).await;
    if types.iter().any(Option::is_none) {
        let slots = match mirrors {
            Mirrors::Shared => &MIRROR_UPDATES,
            Mirrors::Temp(_) => &PREVIEW_UPDATES,
        };
        let error = update_mirror_in(policy, mirrors, key.clone(), root, dir.clone(), false, Some(commits.clone()), slots, Wait::Queue).await;
        if let Some(e) = error {
            bail!("{e}");
        }
        if !mirror_complete(&dir).await {
            bail!("the repo's history isn't available yet");
        }
        types = object_types(policy, &dir, &commits).await;
    }
    let kind_of: std::collections::HashMap<&str, Option<&str>> =
        commits.iter().map(String::as_str).zip(types.iter().map(Option::as_deref)).collect();
    // Each file: its blob id, or what it is instead.
    let mut out: Vec<FileAt> = Vec::with_capacity(wants.len());
    let mut blob_of: Vec<Option<String>> = Vec::with_capacity(wants.len());
    for (commit, path) in wants {
        match kind_of.get(commit.as_str()).copied().flatten() {
            None => {
                out.push(FileAt::Unavailable);
                blob_of.push(None);
                continue;
            }
            Some("commit") => {}
            Some(_) => {
                out.push(FileAt::NotCommit);
                blob_of.push(None);
                continue;
            }
        }
        let mut c = git(policy, home.path());
        c.arg("-C").arg(&dir).args(["ls-tree", commit, "--", path]);
        let listed = run(c, "listing the commit's files").await?;
        let entry = listed.lines().find_map(|l| {
            let (meta, _) = l.split_once('\t')?;
            let mut parts = meta.split_whitespace();
            Some((parts.next()?.to_owned(), parts.next()?.to_owned(), parts.next()?.to_owned()))
        });
        match entry {
            Some((mode, kind, oid)) if kind == "blob" && (mode == "100644" || mode == "100755") => {
                out.push(FileAt::Absent); // replaced below
                blob_of.push(Some(oid));
            }
            // A symbolic link (or another kind of blob): a checkout reads it as master did.
            Some((_, kind, _)) if kind == "blob" => {
                out.push(FileAt::NeedsCheckout);
                blob_of.push(None);
            }
            _ => {
                out.push(FileAt::Absent);
                blob_of.push(None);
            }
        }
    }
    // The blobs' contents, each fetched on its own (with its download bounded) when the mirror
    // lacks it.
    let mut contents: std::collections::HashMap<String, FileAt> = std::collections::HashMap::new();
    for oid in blob_of.iter().flatten() {
        if contents.contains_key(oid) {
            continue;
        }
        let got = read_blob(policy, home.path(), &key, &dir, oid).await;
        contents.insert(oid.clone(), got);
    }
    for (i, oid) in blob_of.into_iter().enumerate() {
        if let Some(oid) = oid {
            out[i] = contents.get(&oid).cloned().unwrap_or(FileAt::NeedsCheckout);
        }
    }
    Ok(out)
}

/// One blob's content from the mirror, fetching it by id first when the mirror lacks it. A fetch
/// that fails (the host refuses wants by id, say) answers [`FileAt::NeedsCheckout`]; one that
/// grows past [`MAX_FILE_AT`] is stopped and answers [`FileAt::TooLarge`].
async fn read_blob(policy: GitPolicy, home: &Path, key: &str, dir: &Path, oid: &str) -> FileAt {
    let size = |home: &Path| {
        let mut c = git(policy, home);
        c.arg("-C").arg(dir).args(["cat-file", "-s", oid]);
        c
    };
    let known = run(size(home), "sizing a file").await.ok().and_then(|s| s.trim().parse::<u64>().ok());
    if known.is_none() {
        // Into a scratch repo that borrows the mirror's objects, so the download can be watched
        // on its own and dropped whatever happens.
        let Ok(t) = check(policy, key).await else { return FileAt::NeedsCheckout };
        let Ok(scratch) = tempfile::tempdir() else { return FileAt::NeedsCheckout };
        let repo = scratch.path().join("r.git");
        let mut c = git(policy, home);
        c.args(["init", "-q", "--bare"]).arg(&repo);
        if run(c, "preparing a fetch").await.is_err() {
            return FileAt::NeedsCheckout;
        }
        let alternates = repo.join("objects/info/alternates");
        if std::fs::write(&alternates, format!("{}\n", dir.join("objects").display())).is_err() {
            return FileAt::NeedsCheckout;
        }
        let mut c = git_to(policy, home, &t);
        c.arg("-C").arg(&repo).args(["fetch", "--quiet", "--no-write-fetch-head", "--", &t.url, oid]);
        let fetched = exec(c, None, "fetching a file", TIMEOUT, Some((repo.as_path(), MAX_FILE_AT + 1024 * 1024))).await;
        if let Err(e) = fetched {
            if e.to_string().contains("was stopped") || dir_size(&repo) > MAX_FILE_AT {
                return FileAt::TooLarge(None);
            }
            return FileAt::NeedsCheckout;
        }
        let mut c = git(policy, home);
        c.arg("-C").arg(&repo).args(["cat-file", "-s", oid]);
        let Some(n) = run(c, "sizing a file").await.ok().and_then(|s| s.trim().parse::<u64>().ok()) else {
            return FileAt::NeedsCheckout;
        };
        if n > MAX_FILE_AT {
            return FileAt::TooLarge(Some(n));
        }
        let mut c = git(policy, home);
        c.arg("-C").arg(&repo).args(["cat-file", "blob", oid]);
        return match exec_raw(c, None, "reading a file", TIMEOUT, None).await {
            Ok(bytes) => {
                keep_blob(policy, home, dir, oid, &bytes, scratch.path()).await;
                FileAt::Content(bytes)
            }
            Err(_) => FileAt::NeedsCheckout,
        };
    }
    if known.is_some_and(|n| n > MAX_FILE_AT) {
        return FileAt::TooLarge(known);
    }
    let mut c = git(policy, home);
    c.arg("-C").arg(dir).args(["cat-file", "blob", oid]);
    match exec_raw(c, None, "reading a file", TIMEOUT, None).await {
        Ok(bytes) => FileAt::Content(bytes),
        Err(_) => FileAt::NeedsCheckout,
    }
}

/// Keeps a blob fetched by id (and within [`MAX_FILE_AT`]) in the mirror, so later reads of it
/// (a sibling's, a re-read) are local. Written by content, so only a blob with exactly this id is
/// kept; under the mirror's lock, so never into a mirror being replaced. Best effort: a blob not
/// kept is only fetched again.
async fn keep_blob(policy: GitPolicy, home: &Path, dir: &Path, oid: &str, bytes: &[u8], scratch: &Path) {
    let file = scratch.join("blob");
    if std::fs::write(&file, bytes).is_err() {
        return;
    }
    let lock = mirror_lock(dir);
    let _held = lock.lock().await;
    if !mirror_complete(dir).await {
        return;
    }
    let mut c = git(policy, home);
    c.arg("-C").arg(dir).args(["hash-object", "-w", "--no-filters", "-t", "blob", "--"]).arg(&file);
    match run(c, "keeping a file").await {
        Ok(id) if id.trim() == oid => {}
        Ok(id) => tracing::warn!("keeping blob {oid} in a mirror wrote {}", id.trim()),
        Err(e) => tracing::warn!("keeping blob {oid} in a mirror: {e:#}"),
    }
}

fn classify(mut found: Vec<String>) -> PrefixMatch {
    match found.len() {
        0 => PrefixMatch::None,
        1 => PrefixMatch::One(found.remove(0)),
        _ => PrefixMatch::Many(found),
    }
}

/// Brings a mirror up to date unless it was within the window, and returns the last update's error.
/// The update runs as a task of its own: a request that goes away (a client disconnecting) only
/// stops waiting, and never cuts a clone or fetch short, so the recorded state is always the
/// outcome of a finished update.
async fn update_mirror(
    policy: GitPolicy,
    url: String,
    root: PathBuf,
    dir: PathBuf,
    broken: bool,
) -> Option<String> {
    update_mirror_in(policy, &Mirrors::Shared, url, root, dir, broken, None, &MIRROR_UPDATES, Wait::Queue).await
}

/// [`update_mirror`]; with `needed`, the update skips the window when those commits (which the repo
/// just listed, so they exist) aren't in the mirror yet, once the lock is held: a tag pushed a
/// moment after the last update is read at once, and concurrent callers fetch once.
/// The update waits for one of `slots` ([`MIRROR_UPDATES`] for syncing, [`PREVIEW_UPDATES`] for a
/// temporary mirror, [`LOOKUP_UPDATES`] for lookups). The update of a temporary mirror holds its
/// root, so it is deleted only after the update ends. Once no request holds it anymore (the
/// client went away), the update is given up: a queued one never takes the slot, and a running
/// clone is stopped (its git killed).
#[allow(clippy::too_many_arguments)]
async fn update_mirror_in(
    policy: GitPolicy,
    mirrors: &Mirrors,
    url: String,
    root: PathBuf,
    dir: PathBuf,
    broken: bool,
    needed: Option<Vec<String>>,
    slots: &'static tokio::sync::Semaphore,
    wait: Wait,
) -> Option<String> {
    let lock = mirror_lock(&dir);
    let held = mirrors.clone();
    let task = tokio::spawn(async move {
        // Up to date (or updated by another request within the window): answered without a slot.
        let fresh = |state: &MirrorState, lacking: bool| {
            !lacking && !state.broken && state.finished.is_some_and(|at| at.elapsed() < MIRROR_REFRESH)
        };
        let lacking = || async {
            match &needed {
                Some(commits) => lacks_commits(policy, &dir, commits).await,
                None => false,
            }
        };
        {
            let state = lock.lock().await;
            if fresh(&state, lacking().await) {
                return state.error.clone();
            }
        }
        // Only this task holds a temporary mirror once its requests are gone.
        let watched = match &held {
            Mirrors::Shared => None,
            Mirrors::Temp(t) => Some(std::sync::Arc::downgrade(t)),
        };
        let abandoned = || {
            let watched = watched.clone();
            async move {
                let Some(w) = watched else { return std::future::pending().await };
                while w.strong_count() > 1 {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        };
        // A slot first, and only then the repo's lock: nobody holds a repo's lock while waiting
        // for a slot, so syncs and lookups of a repo never wait behind a queue of other repos.
        let _permit = match wait {
            Wait::Queue | Wait::Quietly => tokio::select! {
                p = slots.acquire() => match p {
                    Ok(p) => p,
                    Err(e) => return Some(format!("updating the mirror failed: {e}")),
                },
                () = abandoned() => return Some("the preview this mirror was for went away".to_owned()),
            },
            Wait::Never => match slots.try_acquire() {
                Ok(p) => p,
                Err(_) => return Some(SLOT_BUSY.to_owned()),
            },
        };
        let mut state = lock.clone().lock_owned().await;
        if fresh(&state, lacking().await) {
            return state.error.clone();
        }
        let limit = match &held {
            Mirrors::Shared => None,
            Mirrors::Temp(_) => Some(MAX_PREVIEW_MIRROR_BYTES),
        };
        let discard = broken || state.broken;
        let work = async {
            let t = check(policy, &url).await?;
            let home = tempfile::tempdir()?;
            if discard {
                discard_mirror(&root, &dir).await?;
            }
            if mirror_complete(&dir).await {
                fetch_mirror(policy, home.path(), &t, &dir).await.map(|()| false)
            } else {
                clone_mirror(policy, home.path(), &t, &root, &dir, limit).await.map(|()| true)
            }
        };
        let result = tokio::select! {
            r = work => r,
            () = abandoned() => Err(anyhow!("the preview this mirror was for went away")),
        };
        // A kept mirror just cloned has no file contents: warmed at its default branch's tip.
        if matches!(result, Ok(true)) && matches!(held, Mirrors::Shared) {
            warm_soon(policy, &url);
        }
        if result.is_ok() {
            state.broken = false;
        }
        let error = result.err().map(|e| {
            tracing::warn!("updating the mirror of {url} failed: {e:#}");
            format!("{e:#}")
        });
        // Warming's updates leave the window as it was: a commit pushed just after one is still
        // fetched by the next request that misses it.
        if wait != Wait::Quietly {
            state.finished = Some(std::time::Instant::now());
            state.error = error.clone();
        }
        drop(state);
        drop(held);
        error
    });
    task.await.unwrap_or_else(|e| Some(format!("updating the mirror failed: {e}")))
}

/// Whether an update waits for a slot ([`Wait::Queue`]) or gives up when none is free
/// ([`Wait::Never`], for lookups: the answer is then "can't tell just now").
#[derive(Clone, Copy, PartialEq)]
enum Wait {
    Queue,
    Never,
    /// As [`Wait::Queue`], for warming in the background: the update doesn't start a new
    /// [`MIRROR_REFRESH`] window, so it never keeps a request from fetching what it misses.
    Quietly,
}

/// What an update that gave up for want of a slot answers.
const SLOT_BUSY: &str = "no slot is free to update the repo's history just now";

/// Fetches every branch and tag, by URL with explicit refspecs: a bare clone has no fetch refspec,
/// and the stored remote isn't consulted, so the mirror's config can't redirect the fetch.
async fn fetch_mirror(policy: GitPolicy, home: &Path, t: &Target, dir: &Path) -> anyhow::Result<()> {
    clear_stale_locks(dir).await;
    let mut c = git_to(policy, home, t);
    c.arg("-C")
        .arg(dir)
        .args(["fetch", "--quiet", "--prune", "--no-write-fetch-head", "--", &t.url]);
    c.args(["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"]);
    run(c, "updating the repo's history").await.map(drop)
}

/// Removes ref lock files left by a git that was killed (a timeout, a server stopping): git never
/// expires them, and one would fail every later fetch. Only old ones: the caller holds this
/// process's lock, and a lock younger than a git call's time limit may be another process's.
async fn clear_stale_locks(dir: &Path) {
    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => walk(&path, out),
                Ok(t) if t.is_file() && path.extension().is_some_and(|x| x == "lock") => {
                    let old =
                        e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|m| m.elapsed().ok());
                    if old.is_some_and(|age| age > 2 * TIMEOUT) {
                        out.push(path);
                    }
                }
                _ => {}
            }
        }
    }
    let dir = dir.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        let mut stale = Vec::new();
        for top in ["packed-refs.lock", "shallow.lock", "config.lock", "HEAD.lock"] {
            let p = dir.join(top);
            if std::fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age > 2 * TIMEOUT)
            {
                stale.push(p);
            }
        }
        walk(&dir.join("refs"), &mut stale);
        for p in stale {
            let _ = std::fs::remove_file(p);
        }
    })
    .await;
}

/// Moves an unreadable mirror out of the way (atomically) and deletes it off the async threads.
async fn discard_mirror(root: &Path, dir: &Path) -> anyhow::Result<()> {
    let (root, dir) = (root.to_path_buf(), dir.to_path_buf());
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let trash = tempfile::Builder::new().prefix(".clone-").tempdir_in(&root)?;
        std::fs::rename(&dir, trash.path().join("old"))
            .with_context(|| format!("cannot move '{}' aside", dir.display()))?;
        drop(trash);
        Ok(())
    })
    .await?
}

/// Clones into a scratch directory beside the mirrors and renames it into place, so a clone cut
/// short (a timeout, a crash) never leaves a half-made mirror where lookups would trust it.
async fn clone_mirror(
    policy: GitPolicy,
    home: &Path,
    t: &Target,
    root: &Path,
    dir: &Path,
    limit: Option<u64>,
) -> anyhow::Result<()> {
    let r = root.to_path_buf();
    let scratch = tokio::task::spawn_blocking(move || {
        sweep_stale_clones(&r);
        tempfile::Builder::new()
            .prefix(".clone-")
            .tempdir_in(&r)
            .with_context(|| format!("cannot create a directory in '{}'", r.display()))
    })
    .await??;
    let repo = scratch.path().join("repo.git");
    let mut c = git_to(policy, home, t);
    c.args(["clone", "--quiet", "--bare", "--filter=blob:none", "--", &t.url])
        .arg(&repo);
    // With a limit (a preview's temporary mirror), the download is watched, like a checkout's: a
    // history that outgrows it is stopped.
    let cloned = exec(c, None, "mirroring the repo's history", CLONE_TIMEOUT, limit.map(|l| (scratch.path(), l))).await;
    // The rename and the scratch directory's removal happen together, off the async threads.
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let placed = cloned.and_then(|_| match std::fs::rename(&repo, &dir) {
            Ok(()) => Ok(()),
            // Another server process finished the same clone first; its mirror is as good.
            Err(_) if dir.join("HEAD").exists() => Ok(()),
            Err(e) => Err(e).with_context(|| format!("cannot move the mirror into '{}'", dir.display())),
        });
        drop(scratch);
        placed
    })
    .await?
}

/// Removes scratch clones left behind by a process that died before it could clean up.
fn sweep_stale_clones(root: &Path) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let stale = e.file_name().to_string_lossy().starts_with(".clone-")
            && e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|age| age > STALE_CLONE);
        if stale {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// The commits in the mirror whose ids start with `prefix`. `rev-parse --disambiguate` lists every
/// object with that prefix (trees too, and nothing at all when none match); one `cat-file
/// --batch-check` keeps the commits. Git ignores digits past an object id's length, so ids that
/// don't really start with `prefix` are dropped too.
async fn lookup_commits(
    policy: GitPolicy,
    home: &Path,
    dir: &Path,
    prefix: &str,
) -> anyhow::Result<Vec<String>> {
    let mut c = git(policy, home);
    c.arg("-C").arg(dir).args(["rev-parse", &format!("--disambiguate={prefix}")]);
    let listed = run(c, "looking up the commit").await?;
    if listed.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut c = git(policy, home);
    c.arg("-C")
        .arg(dir)
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]);
    let typed = run_with_input(c, listed, "reading the objects' types").await?;
    Ok(typed
        .lines()
        .filter_map(|l| l.split_once(' '))
        .filter(|(id, kind)| *kind == "commit" && id.starts_with(prefix))
        .map(|(id, _)| id.to_owned())
        .collect())
}

/// A commit refused for its size: a fact about the content, unlike a fetch that failed for the
/// network's or the host's reasons, which is worth trying again.
#[derive(Debug)]
pub struct TooLarge(pub String);

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TooLarge {}

/// A commit checked out into a temporary directory, removed when dropped.
pub struct Checkout {
    dir: Option<tempfile::TempDir>,
    pub path: PathBuf,
    pub tree: String,
}

/// Deleting a checkout (up to [`MAX_TREE_BYTES`] of files) is blocking work: it's handed to the
/// blocking pool when there is a runtime, rather than stalling an async worker.
impl Drop for Checkout {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else { return };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => drop(rt.spawn_blocking(move || drop(dir))),
            Err(_) => drop(dir),
        }
    }
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
pub async fn checkout(
    policy: GitPolicy,
    url: &str,
    commit: &str,
    via: Option<&str>,
) -> anyhow::Result<Checkout> {
    let t = check(policy, url).await?;
    let url = t.url.clone();
    let dir = tempfile::tempdir()?;
    let home = dir.path().join("home");
    let path = dir.path().join("src");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&path)?;
    let g = |args: &[&str]| {
        let mut c = git_to(policy, &home, &t);
        c.current_dir(&path).args(args);
        c
    };
    run(g(&["init", "-q"]), "git init").await?;
    // The download is watched: what it may hold is bounded like the tree it unpacks to.
    let fetch = |what: &str| {
        exec(
            g(&["fetch", "-q", "--depth", "1", "--no-tags", "--", &url, what]),
            None,
            "fetching the commit",
            TIMEOUT,
            Some((path.as_path(), MAX_TREE_BYTES)),
        )
    };
    if let Err(e) = fetch(commit).await {
        let Some(via) = via else { return Err(e) };
        fetch(via).await?;
    }
    // Refuse before writing the tree out: a small, highly compressed download can expand to
    // gigabytes on disk.
    let listing = run(g(&["ls-tree", "-r", "-l", "--", commit]), "listing the tree").await?;
    let total: u64 = listing
        .lines()
        .filter_map(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok())
        .sum();
    if total > MAX_TREE_BYTES {
        return Err(TooLarge(format!("the repo is too large to index ({} MB at this commit)", total / (1024 * 1024))).into());
    }
    run(g(&["-c", "advice.detachedHead=false", "checkout", "-q", commit]), "checking out the commit")
        .await?;
    let tree = run(g(&["rev-parse", &format!("{commit}^{{tree}}")]), "reading the tree")
        .await?
        .trim()
        .to_owned();
    let p = path.clone();
    let size = tokio::task::spawn_blocking(move || dir_size(&p)).await?;
    if size > MAX_TREE_BYTES {
        return Err(TooLarge(format!("the repo is too large to index ({} MB)", size / (1024 * 1024))).into());
    }
    Ok(Checkout { dir: Some(dir), path, tree })
}

/// Reads a file inside a checkout, refusing paths that escape it (`..`, absolute, symlinks out).
pub fn read_in(co: &Checkout, rel: &str) -> anyhow::Result<Option<String>> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute()
        || rel_path.components().any(|c| matches!(c, std::path::Component::ParentDir))
    {
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

/// How many batch read items (`POST /packages/read`) may use the network at once, across all
/// requests: each takes a slot when it first needs one (a mirror update, the commit's files, a
/// checkout), never waiting; with none free it isn't read this time. [`set_read_network_slots`]
/// changes it at startup (a development knob).
pub const READ_NETWORK_SLOTS: usize = 16;
static READ_SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();

/// Sets how many [`READ_NETWORK_SLOTS`] there are; only before the first read takes one.
pub fn set_read_network_slots(n: usize) {
    let _ = READ_SLOTS.set(tokio::sync::Semaphore::new(n));
}

fn read_slots() -> &'static tokio::sync::Semaphore {
    READ_SLOTS.get_or_init(|| tokio::sync::Semaphore::new(READ_NETWORK_SLOTS))
}

/// The mirror updates batch reads ask for wait on slots of their own, never syncing's, lookups' or
/// warming's. As many as the reads' network slots, so an item holding one of those finds one.
static READ_UPDATES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(READ_NETWORK_SLOTS);

/// Commits written out from mirrors at once (each a whole tree on disk), whoever asks: waited for.
pub const MATERIALIZATIONS: usize = 8;
static MATERIALIZING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MATERIALIZATIONS);

/// Files fetched into a mirror are kept there only while its objects take less than this...
const MAX_KEPT_MIRROR_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// ... and the file system the mirrors are on has at least this much free.
const MIN_FREE_FOR_KEEPING: u64 = 10 * 1024 * 1024 * 1024;
/// A file being written into a mirror's packs is named so; one older than this is a leftover.
const KEEP_PREFIX: &str = "tmp_keep_";
const STALE_KEEP: Duration = Duration::from_secs(3600);

/// Who reads a commit from a mirror: a batch read, or the warming of mirrors at their default
/// branches' tips ([`warm_soon`]).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Read,
    Warm,
}

/// An item's leave to use the network. A read takes one of the [`READ_NETWORK_SLOTS`] when it first
/// needs it, never waiting; warming runs one at a time on its own slot and always may.
pub struct Leave {
    mode: Mode,
    taken: bool,
    slot: Option<tokio::sync::SemaphorePermit<'static>>,
    /// How many times leave was taken (tests ask whether an item used the network).
    uses: u32,
    /// Tests: never any leave.
    #[cfg(test)]
    deny: bool,
}

impl Leave {
    pub fn new(mode: Mode) -> Leave {
        Leave {
            mode,
            taken: false,
            slot: None,
            uses: 0,
            #[cfg(test)]
            deny: false,
        }
    }

    #[cfg(test)]
    fn denied() -> Leave {
        Leave { deny: true, ..Leave::new(Mode::Read) }
    }

    /// Leave to use the network now (kept until [`Leave::release`]), or why not.
    pub fn take(&mut self) -> Result<(), &'static str> {
        if self.taken {
            return Ok(());
        }
        #[cfg(test)]
        if self.deny {
            return Err("denied");
        }
        if self.mode == Mode::Read {
            self.slot = Some(read_slots().try_acquire().map_err(|_| "no slot was free to fetch from repo hosts just then")?);
        }
        self.taken = true;
        self.uses += 1;
        Ok(())
    }

    /// Done with the network: the slot is free for another item.
    pub fn release(&mut self) {
        self.slot = None;
        self.taken = false;
    }
}

/// What reading a commit from the repo's history mirror came to ([`checkout_from_mirror`]).
pub enum FromMirror {
    /// The commit's whole tree, written out by `git checkout` as [`checkout`] writes it.
    Read(Checkout),
    /// Warming only: the mirror already had every file of the commit; nothing was written out.
    Complete,
    /// The mirror can't serve it (it lacks the commit even after an update, or no branch or tag
    /// reaches it anymore, or the update failed, or the host wouldn't send the files by id, or the
    /// mirror couldn't be read): read it with [`checkout`], which decides, as the single read does.
    Elsewhere(String),
    /// Not read: it needed the network and got no [`Leave`].
    NotRead(&'static str),
    /// What a [`checkout`] failing so would have failed with: the commit's files are too large
    /// ([`TooLarge`]), or the host didn't send them in time. Neither needs the network to answer.
    Failed(anyhow::Error),
}

/// Reads `commit` of the repo at `url` from the repo's kept history mirror rather than fetching it
/// afresh: the commit's whole tree, written out by `git checkout` (so files, modes, symbolic links
/// and submodule folders are exactly what [`checkout`] makes) in a scratch repo that borrows the
/// mirror's objects. The mirror is blobless: the files it lacks are fetched by id, all in one
/// request, and once the tree is written out, exactly those files are packed anew and kept in the
/// mirror ([`keep_blobs`]), so a later commit of the same repo fetches only what changed. Bounded
/// as [`checkout`] is: the download is watched and stopped past [`MAX_TREE_BYTES`], and a tree
/// larger than that is refused before it is written out; and at most [`MATERIALIZATIONS`] trees
/// are written out at once.
///
/// The commit is read from the mirror only when one of the mirror's branches or tags reaches it: a
/// commit force-pushed away is left to a checkout, so the answer is the repo's now, never the
/// mirror's memory of it. The network is used only with `leave`: to update the mirror (on the
/// batch reads' own slots without waiting, or warming's) and to fetch files. Nothing else fetches:
/// every git call runs with `GIT_NO_LAZY_FETCH`, and the scratch repo isn't a partial clone.
///
/// Mirrors are never pruned or repacked (every git call disables gc and maintenance), so the
/// objects read here stay put while an update fetches beside them. A mirror git can't read is
/// flagged broken (the next update clones it again) and the commit left to a checkout.
pub async fn checkout_from_mirror(
    policy: GitPolicy,
    url: &str,
    commit: &str,
    mode: Mode,
    leave: &mut Leave,
) -> anyhow::Result<FromMirror> {
    let (root, key, dir) = mirror_of(url).await?;
    let usable = || async {
        object_types(policy, &dir, &[commit.to_owned()]).await[0].as_deref() == Some("commit")
            && reachable(policy, &dir, commit).await
    };
    if !usable().await {
        if let Err(why) = leave.take() {
            return Ok(FromMirror::NotRead(why));
        }
        // Updated at most once per window (and cloned, for a repo with no mirror yet). A commit
        // the update doesn't bring (not on a branch or tag) is for a checkout to find.
        let (slots, wait) = match mode {
            Mode::Read => (&READ_UPDATES, Wait::Never),
            Mode::Warm => (&WARM_UPDATES, Wait::Quietly),
        };
        let error = update_mirror_in(policy, &Mirrors::Shared, key.clone(), root, dir.clone(), false, None, slots, wait).await;
        match error {
            Some(e) if e == SLOT_BUSY => return Ok(FromMirror::NotRead("no slot was free to update the repo's history just then")),
            Some(e) => return Ok(FromMirror::Elsewhere(format!("the mirror couldn't be updated: {e}"))),
            None if !usable().await => return Ok(FromMirror::Elsewhere("no branch or tag of the mirror reaches the commit".into())),
            None => {}
        }
    }
    // From here, a git failure is the mirror's: flagged, and the commit left to a checkout.
    let broken = |e: anyhow::Error| {
        if e.downcast_ref::<TooLarge>().is_some() {
            return FromMirror::Failed(e);
        }
        tracing::warn!("reading {commit} from the mirror of {key}: {e:#}; it will be cloned again");
        flag_broken(&dir);
        FromMirror::Elsewhere(format!("the mirror couldn't be read: {e:#}"))
    };
    macro_rules! local {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return Ok(broken(e)),
            }
        };
    }
    let tmp = tempfile::tempdir()?;
    let home = tmp.path().join("home");
    let path = tmp.path().join("src");
    std::fs::create_dir_all(&home)?;
    std::fs::create_dir_all(&path)?;
    // Deleted off the async threads however this ends.
    let mut co = Checkout { dir: Some(tmp), path: path.clone(), tree: String::new() };
    let g = |args: &[&str]| {
        let mut c = git(policy, &home);
        c.current_dir(&path).args(args);
        c
    };
    // The scratch repo has the mirror's object format (SHA-1 or SHA-256), and borrows its objects
    // by an absolute path.
    let mut c = git(policy, &home);
    c.arg("-C").arg(&dir).args(["rev-parse", "--show-object-format"]);
    let format = local!(run(c, "reading the mirror's object format").await).trim().to_owned();
    local!(run(g(&["init", "-q", &format!("--object-format={format}")]), "git init").await);
    let objects = path.join(".git/objects");
    let borrowed = std::path::absolute(dir.join("objects"))?;
    std::fs::write(objects.join("info/alternates"), format!("{}\n", borrowed.display()))?;
    // Every blob of the tree (files and symbolic links; a submodule is a commit id, not fetched).
    let listed = local!(exec_raw(g(&["ls-tree", "-r", "-z", "--", commit]), None, "listing the tree", TIMEOUT, None).await);
    let mut blobs: Vec<String> = listed
        .split(|&b| b == 0)
        .filter_map(|entry| {
            let meta = std::str::from_utf8(entry.split(|&b| b == b'\t').next()?).ok()?;
            let mut p = meta.split(' ');
            let (_mode, kind, oid) = (p.next()?, p.next()?, p.next()?);
            (kind == "blob").then(|| oid.to_owned())
        })
        .collect();
    blobs.sort_unstable();
    blobs.dedup();
    let missing = local!(missing_objects(&g, &blobs).await);
    if missing.is_empty() && mode == Mode::Warm {
        return Ok(FromMirror::Complete);
    }
    if !missing.is_empty() {
        if let Err(why) = leave.take() {
            return Ok(FromMirror::NotRead(why));
        }
        let t = match check(policy, &key).await {
            Ok(t) => t,
            Err(e) => return Ok(FromMirror::Elsewhere(format!("{e:#}"))),
        };
        let who = if mode == Mode::Warm { "warming" } else { "reading" };
        tracing::info!("{who}: fetching {} of {} files of {commit} that the mirror of {key} lacks", missing.len(), blobs.len());
        // One request for them all, as a partial clone's own fetch of missing objects asks: no
        // negotiation (the wants are blobs), kept as one pack in the scratch repo.
        let mut c = git_to(policy, &home, &t);
        c.current_dir(&path)
            .args(["-c", "fetch.negotiationAlgorithm=noop", "-c", "fetch.unpackLimit=1", "-c", "transfer.unpackLimit=1"])
            .args(["fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no", "--stdin", "--", &t.url]);
        let wants: String = missing.iter().map(|o| format!("{o}\n")).collect();
        let watched = co.dir.as_ref().map(|d| d.path().to_path_buf()).unwrap_or_else(|| path.clone());
        if let Err(e) = exec(c, Some(wants), "fetching the commit's files", TIMEOUT, Some((&watched, MAX_TREE_BYTES))).await {
            let said = format!("{e:#}");
            if e.is::<TooLarge>() || said.contains("timed out") {
                return Ok(FromMirror::Failed(e));
            }
            return Ok(FromMirror::Elsewhere(said));
        }
        if !local!(missing_objects(&g, &missing).await).is_empty() {
            return Ok(FromMirror::Elsewhere("the host didn't send every file asked for".into()));
        }
        // The network part is over: the slot is free for another item.
        leave.release();
    }
    // From here on as checkout does it, with every object local.
    let listing = local!(run(g(&["ls-tree", "-r", "-l", "--", commit]), "listing the tree").await);
    let total: u64 = listing.lines().filter_map(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok()).sum();
    if total > MAX_TREE_BYTES {
        return Ok(FromMirror::Failed(
            TooLarge(format!("the repo is too large to index ({} MB at this commit)", total / (1024 * 1024))).into(),
        ));
    }
    let writing = MATERIALIZING.acquire().await?;
    local!(run(g(&["-c", "advice.detachedHead=false", "checkout", "-q", commit]), "checking out the commit").await);
    co.tree = local!(run(g(&["rev-parse", &format!("{commit}^{{tree}}")]), "reading the tree").await).trim().to_owned();
    let p = path.clone();
    let size = tokio::task::spawn_blocking(move || dir_size(&p)).await?;
    drop(writing);
    if size > MAX_TREE_BYTES {
        return Ok(FromMirror::Failed(TooLarge(format!("the repo is too large to index ({} MB)", size / (1024 * 1024))).into()));
    }
    if !missing.is_empty() {
        keep_blobs(&g, &path.join(".git/keep"), &dir, &missing).await;
    }
    Ok(FromMirror::Read(co))
}

/// Whether one of the mirror's branches or tags reaches `commit`.
async fn reachable(policy: GitPolicy, dir: &Path, commit: &str) -> bool {
    let Ok(home) = tempfile::tempdir() else { return false };
    let mut c = git(policy, home.path());
    c.arg("-C").arg(dir).args(["for-each-ref", "--count=1", "--format=%(refname)", "--contains", commit, "refs/heads", "refs/tags"]);
    run(c, "finding the branches that have the commit").await.is_ok_and(|out| !out.trim().is_empty())
}

/// Marks a mirror git couldn't read: its next update moves it aside and clones it again.
fn flag_broken(dir: &Path) {
    let lock = mirror_lock(dir);
    tokio::spawn(async move {
        let mut state = lock.lock().await;
        state.broken = true;
        state.finished = None;
    });
}

/// The objects among `oids` the repo `g` runs git in lacks (it never fetches them).
async fn missing_objects(g: &impl Fn(&[&str]) -> Command, oids: &[String]) -> anyhow::Result<Vec<String>> {
    if oids.is_empty() {
        return Ok(Vec::new());
    }
    let input: String = oids.iter().map(|o| format!("{o}\n")).collect();
    let out = run_with_input(g(&["cat-file", "--batch-check=%(objectname) %(objecttype)", "--buffer"]), input, "looking up the files").await?;
    // "<id> <type>", or "<id> missing".
    Ok(out.lines().filter_map(|l| l.strip_suffix(" missing")).map(str::to_owned).collect())
}

/// How long keeping fetched files waits for the mirror's lock before giving up.
const KEEP_LOCK_WAIT: Duration = Duration::from_secs(10);

/// Keeps `oids` (files a scratch repo fetched, and wrote out) in the mirror in `dir`: packed anew
/// from exactly those objects (never the pack the host sent, which could hold anything), then
/// added under the mirror's lock, so never into one being cloned or replaced. Each file is written
/// under a temporary name, synced and renamed into place, the index last (git uses a pack only once
/// its index is there), then the folder synced. Best effort, and skipped (logged) when the lock is
/// busy, the mirror's objects already take [`MAX_KEPT_MIRROR_BYTES`], or the file system has less
/// than [`MIN_FREE_FOR_KEEPING`] free: a file not kept is only fetched again.
async fn keep_blobs(g: &impl Fn(&[&str]) -> Command, out: &Path, dir: &Path, oids: &[String]) {
    let base = out.join("pack");
    let packed = async {
        std::fs::create_dir_all(out)?;
        let input: String = oids.iter().map(|o| format!("{o}\n")).collect();
        let mut c = g(&["pack-objects", "--quiet"]);
        c.arg(&base);
        anyhow::Ok(run_with_input(c, input, "packing the fetched files").await?.trim().to_owned())
    };
    let hash = match packed.await {
        Ok(h) if !h.is_empty() => h,
        Ok(_) => return,
        Err(e) => {
            tracing::warn!("packing files to keep in a mirror: {e:#}");
            return;
        }
    };
    // Only cold reads keep files, and they hold no network slot by now: waiting a while for an
    // update (warming's, a sync's) to finish is cheaper than fetching the files again later. An
    // item still waiting at the batch's deadline goes on detached.
    let Ok(guard) = tokio::time::timeout(KEEP_LOCK_WAIT, mirror_lock(dir).lock_owned()).await else {
        tracing::info!("not keeping {} files in the mirror {}: it is being updated", oids.len(), dir.display());
        return;
    };
    if !mirror_complete(dir).await {
        return;
    }
    let (dir, out) = (dir.to_path_buf(), out.to_path_buf());
    let count = oids.len();
    // The copy runs to its end even if the request goes away, holding the lock till then.
    let kept = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        use std::os::unix::fs::PermissionsExt;
        let _guard = guard;
        let to = dir.join("objects/pack");
        sweep_stale_keeps(&to);
        let used = dir_size(&dir.join("objects"));
        if used > MAX_KEPT_MIRROR_BYTES {
            tracing::info!("not keeping {count} files in {}: its objects take {} MB already", dir.display(), used / (1024 * 1024));
            return Ok(false);
        }
        let free = free_bytes(&dir).unwrap_or(0);
        if free < MIN_FREE_FOR_KEEPING {
            tracing::warn!("not keeping {count} files in {}: only {} MB free", dir.display(), free / (1024 * 1024));
            return Ok(false);
        }
        let stem = format!("pack-{hash}");
        if to.join(format!("{stem}.idx")).exists() {
            return Ok(true);
        }
        for ext in ["pack", "rev", "idx"] {
            let src = out.join(format!("{stem}.{ext}"));
            if !src.exists() {
                continue;
            }
            let mut tmp = tempfile::Builder::new().prefix(KEEP_PREFIX).tempfile_in(&to)?;
            std::io::copy(&mut std::fs::File::open(&src)?, tmp.as_file_mut())?;
            tmp.as_file().sync_all()?;
            tmp.as_file().set_permissions(std::fs::Permissions::from_mode(0o444))?;
            tmp.persist(to.join(format!("{stem}.{ext}")))?;
        }
        std::fs::File::open(&to)?.sync_all()?;
        Ok(true)
    })
    .await;
    match kept {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!("keeping fetched files in a mirror: {e:#}"),
        Err(e) => tracing::warn!("keeping fetched files in a mirror: {e}"),
    }
}

/// Removes files a keeping left half-written (a process that died mid-copy). Blocking work.
fn sweep_stale_keeps(pack_dir: &Path) {
    let Ok(rd) = std::fs::read_dir(pack_dir) else { return };
    for e in rd.flatten() {
        let stale = e.file_name().to_string_lossy().starts_with(KEEP_PREFIX)
            && e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|m| m.elapsed().ok()).is_some_and(|age| age > STALE_KEEP);
        if stale {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The bytes free to this process on the file system holding `p`.
fn free_bytes(p: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid C string and `s` a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some(s.f_bavail as u64 * s.f_frsize as u64)
}

/// Warming runs one repo at a time, and updates mirrors on a slot of its own: it never takes one
/// of the slots syncing, lookups or reads use.
static WARM_RUNS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
static WARM_UPDATES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
/// Repos with a warming queued or running.
static WARMING: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(Default::default);
/// Off until the server turns it on ([`enable_warming`]): a command-line run or a test has no
/// business leaving background fetches behind.
static WARMING_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Lets [`warm_soon`] warm mirrors (the server, at startup).
pub fn enable_warming() {
    WARMING_ON.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Warms the repo's kept mirror in the background, soon: updated (or cloned), then every file of
/// its default branch's tip fetched and kept ([`warm`]), so batch reads at that commit, or at one
/// near it, need no network. Asked again while one is queued or running, it adds nothing. Only
/// once the server enabled it.
pub fn warm_soon(policy: GitPolicy, url: &str) {
    if !WARMING_ON.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let url = url.trim().trim_end_matches('/').to_owned();
    if !WARMING.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(url.clone()) {
        return;
    }
    tokio::spawn(async move {
        let _one = WARM_RUNS.acquire().await;
        if let Err(e) = warm(policy, &url).await {
            tracing::info!("warming the mirror of {url}: {e:#}");
        }
        WARMING.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&url);
    });
}

/// [`warm_soon`]'s work, now: the mirror updated (within its window) or cloned, and the files of
/// the commit its HEAD names (the default branch, as of the clone) fetched and kept.
pub async fn warm(policy: GitPolicy, url: &str) -> anyhow::Result<()> {
    let (root, key, dir) = mirror_of(url).await?;
    if let Some(e) = update_mirror_in(policy, &Mirrors::Shared, key, root, dir.clone(), false, None, &WARM_UPDATES, Wait::Quietly).await {
        bail!("{e}");
    }
    let home = tempfile::tempdir()?;
    let mut c = git(policy, home.path());
    c.arg("-C").arg(&dir).args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]);
    let head = run(c, "reading the default branch").await?.trim().to_owned();
    match Box::pin(checkout_from_mirror(policy, url, &head, Mode::Warm, &mut Leave::new(Mode::Warm))).await? {
        FromMirror::Read(_) | FromMirror::Complete => Ok(()),
        FromMirror::Elsewhere(why) => bail!("{why}"),
        FromMirror::NotRead(why) => bail!("{why}"),
        FromMirror::Failed(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A commit made without touching the upstream's HEAD (as a push to another branch would be).
    fn commit_on(up: &Path, branch: &str, msg: &str) -> String {
        let tree = sh(up, &["rev-parse", "HEAD^{tree}"]);
        let parent = sh(up, &["rev-parse", "HEAD"]);
        let c = sh(up, &["commit-tree", "-m", msg, "-p", &parent, &tree]);
        sh(up, &["branch", "-f", branch, &c]);
        c
    }

    #[tokio::test]
    async fn prefixes_resolve_against_every_branch() {
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        std::fs::write(up.join("f"), "x").unwrap();
        sh(&up, &["add", "f"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let first = sh(&up, &["rev-parse", "HEAD"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        let one = |m: PrefixMatch| match m {
            PrefixMatch::One(c) => c,
            PrefixMatch::None => panic!("none"),
            PrefixMatch::Many(m) => panic!("many: {m:?}"),
        };

        assert_eq!(one(resolve_commit_prefix(policy, &url, &first[..7]).await.unwrap()), first);
        // A commit on another branch, pushed after the mirror was made: found once a fetch may run.
        let feat = commit_on(&up, "feat", "feature");
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        assert_eq!(one(resolve_commit_prefix(policy, &url, &feat[..9]).await.unwrap()), feat);
        // A tree's id isn't a commit's.
        let tree = sh(&up, &["rev-parse", "HEAD^{tree}"]);
        assert!(matches!(
            resolve_commit_prefix(policy, &url, &tree[..12]).await.unwrap(),
            PrefixMatch::None
        ));
        // Digits past the id's length aren't ignored.
        let long = format!("{first}0");
        assert!(matches!(resolve_commit_prefix(policy, &url, &long).await.unwrap(), PrefixMatch::None));
        assert!(resolve_commit_prefix(policy, &url, "beef").await.is_err(), "too short");
        // Many misses at once all get an answer.
        let misses: Vec<_> = (0..8)
            .map(|_| {
                let url = url.clone();
                tokio::spawn(async move { resolve_commit_prefix(policy, &url, "0000000").await })
            })
            .collect();
        for m in misses {
            assert!(matches!(m.await.unwrap().unwrap(), PrefixMatch::None));
        }
    }

    /// A download is fetched once and hashed as it streams: redirects are followed (each checked
    /// again), a server error and an oversized body are refused, and so is anything but https
    /// outside development.
    #[tokio::test]
    async fn downloads_are_fetched_and_hashed() {
        use sha2::Digest;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let body = b"tarball bytes".repeat(100);
        let served = body.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let served = served.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let head = |status: &str, extra: &str, len: usize| format!("HTTP/1.1 {status}\r\n{extra}content-length: {len}\r\nconnection: close\r\n\r\n");
                    let reply: Vec<u8> = match path.as_str() {
                        "/file" => [head("200 OK", "", served.len()).into_bytes(), served].concat(),
                        "/moved" => head("302 Found", "location: /file\r\n", 0).into_bytes(),
                        _ => head("404 Not Found", "", 0).into_bytes(),
                    };
                    let _ = s.write_all(&reply).await;
                });
            }
        });
        let dev = GitPolicy { allow_local: true };
        let limit = Duration::from_secs(30);
        let got = fetch_and_hash(dev, &format!("http://{addr}/file"), 1 << 20, limit).await.unwrap();
        assert_eq!((got.sha256, got.size), (hex::encode(sha2::Sha256::digest(&body)), body.len() as u64));
        let moved = fetch_and_hash(dev, &format!("http://{addr}/moved"), 1 << 20, limit).await.unwrap();
        assert_eq!(moved.size, body.len() as u64);
        let e = fetch_and_hash(dev, &format!("http://{addr}/gone"), 1 << 20, limit).await.unwrap_err();
        assert!(format!("{e:#}").contains("404"), "{e:#}");
        let e = fetch_and_hash(dev, &format!("http://{addr}/file"), 100, limit).await.unwrap_err();
        assert!(format!("{e:#}").contains("more than the 100"), "{e:#}");
        let strict = GitPolicy { allow_local: false };
        for bad in [format!("http://{addr}/file"), "https://127.0.0.1/x".to_owned(), "https://u:p@example.org/x".to_owned(), "file:///etc/hostname".to_owned()] {
            assert!(fetch_and_hash(strict, &bad, 1 << 20, limit).await.is_err(), "{bad}");
        }
    }

    /// The tests that use the lookups' only slot run one at a time.
    static LOOKUP_SLOT_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Nobody holds a repo's lock while waiting for a slot: a queued update leaves the repo's
    /// lock free, and a lookup that finds its slot busy answers "can't tell" at once.
    #[tokio::test]
    async fn slots_are_taken_before_locks() {
        let _one = LOOKUP_SLOT_TESTS.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        std::fs::write(up.join("f"), "x").unwrap();
        sh(&up, &["add", "f"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let first = sh(&up, &["rev-parse", "HEAD"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        resolve_commit_prefix(policy, &url, &first[..7]).await.unwrap();
        let (_, _, dir) = mirror_of(&url).await.unwrap();
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        // The lookups' only slot is busy: a lookup lacking a commit can't tell, and doesn't wait.
        let busy = LOOKUP_UPDATES.acquire().await.unwrap();
        let none = "0".repeat(40);
        let a = tokio::time::timeout(Duration::from_secs(5), mirror_has_commits(policy, &url, std::slice::from_ref(&none), || true))
            .await
            .expect("answered at once")
            .unwrap();
        assert_eq!(a.has, vec![None]);
        drop(busy);
        // Every syncing slot busy: an update waits for one without the repo's lock.
        let all = MIRROR_UPDATES.acquire_many(3).await.unwrap();
        let queued = {
            let url = url.clone();
            tokio::spawn(async move { resolve_commit_prefix(policy, &url, "0000000").await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(mirror_lock(&dir).try_lock().is_ok(), "the repo's lock is free while the update waits for a slot");
        drop(all);
        assert!(matches!(queued.await.unwrap().unwrap(), PrefixMatch::None));
    }

    /// What a kept mirror says of commits: nothing before one exists (it never clones one), then
    /// the commits it has; one pushed since is found once an update may run; a tree is no commit.
    #[tokio::test]
    async fn mirrors_answer_whether_they_have_commits() {
        let _one = LOOKUP_SLOT_TESTS.lock().await;
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        std::fs::write(up.join("f"), "x").unwrap();
        sh(&up, &["add", "f"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let first = sh(&up, &["rev-parse", "HEAD"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        assert!(mirror_has_commits(policy, &url, std::slice::from_ref(&first), || true).await.is_none(), "no mirror kept yet");
        resolve_commit_prefix(policy, &url, &first[..7]).await.unwrap();
        let none = "0".repeat(40);
        let a = mirror_has_commits(policy, &url, &[first.clone(), none.clone()], || false).await.unwrap();
        assert_eq!((a.has, a.updated), (vec![Some(true), None], false), "without an update, a miss can't tell");
        let later = commit_on(&up, "later", "later");
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        let asked = std::cell::Cell::new(false);
        let a = mirror_has_commits(policy, &url, &[later.clone(), none], || {
            asked.set(true);
            true
        })
        .await
        .unwrap();
        assert!(asked.get(), "asked, since the mirror lacked them");
        assert_eq!((a.has, a.updated), (vec![Some(true), Some(false)], true));
        // Within the window the last update opened, a miss can't tell: a commit pushed since would
        // be missing too. After it, an update runs and a miss is a no.
        let tree = sh(&up, &["rev-parse", "HEAD^{tree}"]);
        assert_eq!(mirror_has_commits(policy, &url, std::slice::from_ref(&tree), || true).await.unwrap().has, vec![None]);
        let pushed = commit_on(&up, "pushed", "pushed");
        assert_eq!(mirror_has_commits(policy, &url, std::slice::from_ref(&pushed), || true).await.unwrap().has, vec![None], "pushed in the window");
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        let a = mirror_has_commits(policy, &url, &[tree, pushed], || true).await.unwrap();
        assert_eq!(a.has, vec![Some(false), Some(true)], "a tree is no commit; the pushed one is fetched");
        // A mirror that has every commit asked never asks for an update.
        let a = mirror_has_commits(policy, &url, &[first], || panic!("no update needed")).await.unwrap();
        assert_eq!((a.has, a.updated), (vec![Some(true)], false));
    }

    /// Files at commits from a blobless mirror: blobs fetched by id, a symbolic link left to a
    /// checkout, a file over the limit refused, a tree that a tag might name told apart.
    #[tokio::test]
    async fn files_at_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        std::fs::write(up.join("cactarium.toml"), "format = 1\n").unwrap();
        std::fs::write(up.join("big.bin"), vec![b'x'; (MAX_FILE_AT + 1) as usize]).unwrap();
        std::os::unix::fs::symlink("cactarium.toml", up.join("link.toml")).unwrap();
        sh(&up, &["add", "-A"]);
        sh(&up, &["commit", "-q", "-m", "files"]);
        let c = sh(&up, &["rev-parse", "HEAD"]);
        let tree = sh(&up, &["rev-parse", "HEAD^{tree}"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        let wants: Vec<(String, String)> = ["cactarium.toml", "missing.toml", "link.toml", "big.bin"]
            .iter()
            .map(|f| (c.clone(), f.to_string()))
            .chain(std::iter::once((tree.clone(), "cactarium.toml".to_owned())))
            .collect();
        let got = read_files_in(policy, &Mirrors::Shared, &url, &wants).await.unwrap();
        assert!(matches!(&got[0], FileAt::Content(b) if b.as_slice() == b"format = 1\n"), "{:?}", got[0]);
        assert!(matches!(got[1], FileAt::Absent));
        assert!(matches!(got[2], FileAt::NeedsCheckout), "{:?}", got[2]);
        assert!(matches!(got[3], FileAt::TooLarge(_)), "{:?}", got[3]);
        assert!(matches!(got[4], FileAt::NotCommit), "{:?}", got[4]);
        // The blob fetched by id was kept in the mirror: read again with the repo gone, it is local.
        let (_, _, dir) = mirror_of(&url).await.unwrap();
        let oid = sh(&up, &["rev-parse", "HEAD:cactarium.toml"]);
        let other = sh(&up, &["rev-parse", "HEAD:big.bin"]);
        let has = |id: &str| {
            let mut c = std::process::Command::new("git");
            c.env("GIT_NO_LAZY_FETCH", "1").arg("-C").arg(&dir).args(["cat-file", "-e", id]);
            c.status().unwrap().success()
        };
        assert!(has(&oid), "the blob is kept");
        assert!(!has(&other), "the large blob isn't kept");
        std::fs::remove_dir_all(&up).unwrap();
        let again = read_files_in(policy, &Mirrors::Shared, &url, &wants[..1]).await.unwrap();
        assert!(matches!(&again[0], FileAt::Content(b) if b.as_slice() == b"format = 1\n"), "{:?}", again[0]);
    }

    /// Everything a checkout wrote, but its `.git`: each path with what it is (a folder, a file
    /// with its permissions and content, a symbolic link and where it points).
    fn tree_of(root: &Path) -> Vec<(String, String)> {
        use std::os::unix::fs::PermissionsExt;
        fn walk(root: &Path, at: &Path, out: &mut Vec<(String, String)>) {
            for e in std::fs::read_dir(at).unwrap().flatten() {
                let p = e.path();
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                if rel == ".git" {
                    continue;
                }
                let meta = std::fs::symlink_metadata(&p).unwrap();
                let what = if meta.file_type().is_symlink() {
                    format!("link -> {}", std::fs::read_link(&p).unwrap().display())
                } else if meta.is_dir() {
                    walk(root, &p, out);
                    format!("dir {:o}", meta.permissions().mode() & 0o777)
                } else {
                    format!("file {:o} {}", meta.permissions().mode() & 0o777, String::from_utf8_lossy(&std::fs::read(&p).unwrap()))
                };
                out.push((rel, what));
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    /// An upstream with `uploadpack.allowFilter`, so mirrors of it are blobless as forges' are.
    fn upstream(tmp: &Path) -> (PathBuf, String) {
        let up = tmp.join("up");
        std::fs::create_dir_all(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        let url = format!("file://{}", up.display());
        (up, url)
    }

    /// Reads `commit` from the mirror with leave for the network or none: what came of it, and
    /// whether it took leave.
    async fn mirror_read(url: &str, commit: &str, allow: bool) -> (FromMirror, bool) {
        let mut leave = if allow { Leave::new(Mode::Read) } else { Leave::denied() };
        let policy = GitPolicy { allow_local: true };
        let r = Box::pin(checkout_from_mirror(policy, url, commit, Mode::Read, &mut leave)).await.unwrap();
        (r, leave.uses > 0)
    }

    /// The blob ids in each of the mirror's packs.
    fn pack_blobs(dir: &Path) -> Vec<Vec<String>> {
        let mut all: Vec<Vec<String>> = std::fs::read_dir(dir.join("objects/pack"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".idx"))
            .map(|e| {
                let out = std::process::Command::new("git").arg("verify-pack").arg("-v").arg(e.path()).output().unwrap();
                let mut b: Vec<String> =
                    String::from_utf8(out.stdout).unwrap().lines().filter(|l| l.contains(" blob ")).map(|l| l[..40].to_owned()).collect();
                b.sort();
                b
            })
            .collect();
        all.sort();
        all
    }

    /// Commits read from the blobless mirror come out exactly as a checkout writes them (modes,
    /// symbolic links, a submodule's empty folder), fetching the files the mirror lacks in one go
    /// and keeping exactly them: a later commit fetches only what changed, and one whose files are
    /// all kept needs no network at all. A commit the mirror lacks brings an update; one the repo
    /// doesn't have is left to a checkout; no leave for the network, no read.
    #[tokio::test]
    async fn commits_are_read_from_mirrors_as_checked_out() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (up, url) = upstream(tmp.path());
        std::fs::create_dir_all(up.join("Arr/Thorn/src")).unwrap();
        std::fs::write(up.join("cactarium.toml"), "format = 1\n").unwrap();
        std::fs::write(up.join("Arr/Thorn/interface.ccl"), "implements: thorn\n").unwrap();
        std::fs::write(up.join("Arr/Thorn/src/a.c"), "#include \"b.h\"\n").unwrap();
        std::fs::write(up.join("Arr/Thorn/src/same.c"), "#include \"b.h\"\n").unwrap();
        std::fs::write(up.join("run.sh"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(up.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(up.join("with space.txt"), "x\n").unwrap();
        std::os::unix::fs::symlink("Arr/Thorn/src/a.c", up.join("link.c")).unwrap();
        std::os::unix::fs::symlink("../nowhere", up.join("dangling")).unwrap();
        sh(&up, &["add", "-A"]);
        // A submodule: a commit id in the tree, which a checkout leaves as an empty folder.
        sh(&up, &["update-index", "--add", "--cacheinfo", &format!("160000,{},ExternalLibs/sub", "1".repeat(40))]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let first = sh(&up, &["rev-parse", "HEAD"]);
        std::fs::write(up.join("Arr/Thorn/src/a.c"), "int a;\n").unwrap();
        sh(&up, &["commit", "-q", "-am", "second"]);
        let second = sh(&up, &["rev-parse", "HEAD"]);
        let policy = GitPolicy { allow_local: true };
        resolve_commit_prefix(policy, &url, &first[..7]).await.unwrap();
        let (_, _, dir) = mirror_of(&url).await.unwrap();
        let before = pack_blobs(&dir);
        assert!(before.iter().all(Vec::is_empty), "blobless: {before:?}");

        let classic = checkout(policy, &url, &first, None).await.unwrap();
        let (FromMirror::Read(got), used) = mirror_read(&url, &first, true).await else { panic!("not read") };
        assert!(used, "the files were fetched");
        assert_eq!(tree_of(&got.path), tree_of(&classic.path));
        assert_eq!(got.tree, classic.tree);
        assert!(tree_of(&got.path).iter().any(|(p, w)| p == "ExternalLibs/sub" && w.starts_with("dir")), "{:?}", tree_of(&got.path));
        let blobs_of = |c: &str| {
            let mut b: Vec<String> = sh(&up, &["ls-tree", "-r", c]).lines().filter(|l| l.contains(" blob ")).map(|l| l.split_whitespace().nth(2).unwrap().to_owned()).collect();
            b.sort();
            b.dedup();
            b
        };
        let kept: Vec<Vec<String>> = pack_blobs(&dir).into_iter().filter(|b| !b.is_empty()).collect();
        assert_eq!(kept, vec![blobs_of(&first)], "kept as one pack of exactly its files");

        // Kept: read again with no leave for the network at all.
        let (r, used) = mirror_read(&url, &first, false).await;
        assert!(matches!(r, FromMirror::Read(ref co) if tree_of(&co.path) == tree_of(&classic.path)) && !used);

        // A later commit the blobless clone had: only the changed file is fetched and kept.
        let (FromMirror::Read(got), _) = mirror_read(&url, &second, true).await else { panic!("not read") };
        let classic2 = checkout(policy, &url, &second, None).await.unwrap();
        assert_eq!(tree_of(&got.path), tree_of(&classic2.path));
        let changed = sh(&up, &["rev-parse", &format!("{second}:Arr/Thorn/src/a.c")]);
        let kept: Vec<Vec<String>> = pack_blobs(&dir).into_iter().filter(|b| !b.is_empty()).collect();
        assert!(kept.len() == 2 && kept.contains(&vec![changed]), "{kept:?}");

        // A commit pushed since, on another branch: the mirror is updated (an update by URL brings
        // the new commits' files too), with leave for the network only.
        std::fs::write(up.join("run.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        sh(&up, &["commit", "-q", "-am", "third"]);
        let third = sh(&up, &["rev-parse", "HEAD"]);
        sh(&up, &["branch", "-f", "other", &third]);
        sh(&up, &["reset", "-q", "--hard", &second]);
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        let (r, _) = mirror_read(&url, &third, false).await;
        assert!(matches!(r, FromMirror::NotRead(_)), "no leave, no update");
        let (r, used) = mirror_read(&url, &third, true).await;
        let FromMirror::Read(got) = r else { panic!("not read") };
        let classic3 = checkout(policy, &url, &third, None).await.unwrap();
        assert!(used);
        assert_eq!(tree_of(&got.path), tree_of(&classic3.path));

        // A commit the repo doesn't have: left to a checkout, which says so.
        let (r, _) = mirror_read(&url, &"ab".repeat(20), true).await;
        assert!(matches!(r, FromMirror::Elsewhere(_)));
    }

    /// A commit the mirror still has but no branch or tag reaches anymore (force-pushed away) is
    /// never read from the mirror: it is left to a checkout, which answers as the repo does now.
    #[tokio::test]
    async fn commits_no_branch_reaches_are_left_to_a_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let (up, url) = upstream(tmp.path());
        std::fs::write(up.join("f"), "x").unwrap();
        sh(&up, &["add", "f"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let gone = commit_on(&up, "gone", "pushed, then force-pushed away");
        let policy = GitPolicy { allow_local: true };
        resolve_commit_prefix(policy, &url, &gone[..7]).await.unwrap();
        let (FromMirror::Read(_), _) = mirror_read(&url, &gone, true).await else { panic!("read while a branch has it") };
        sh(&up, &["branch", "-D", "gone"]);
        tokio::time::sleep(MIRROR_REFRESH + Duration::from_millis(100)).await;
        resolve_commit_prefix(policy, &url, "0000000").await.unwrap();
        let (_, _, dir) = mirror_of(&url).await.unwrap();
        assert_eq!(object_types(policy, &dir, std::slice::from_ref(&gone)).await, vec![Some("commit".to_owned())], "the mirror still has it");
        let (r, _) = mirror_read(&url, &gone, false).await;
        assert!(matches!(r, FromMirror::NotRead(_)), "it would need the network");
        let (r, used) = mirror_read(&url, &gone, true).await;
        assert!(matches!(r, FromMirror::Elsewhere(ref why) if why.contains("no branch or tag")) && used);
    }

    /// Keeping packs exactly the files asked anew: whatever else the scratch repo holds (a host
    /// padding its pack with more) never reaches the mirror.
    #[tokio::test]
    async fn kept_packs_hold_exactly_the_wanted_files() {
        let tmp = tempfile::tempdir().unwrap();
        let (up, url) = upstream(tmp.path());
        std::fs::write(up.join("f"), "x").unwrap();
        sh(&up, &["add", "f"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let policy = GitPolicy { allow_local: true };
        resolve_commit_prefix(policy, &url, &sh(&up, &["rev-parse", "HEAD"])[..7]).await.unwrap();
        let (_, _, dir) = mirror_of(&url).await.unwrap();
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir(&scratch).unwrap();
        sh(&scratch, &["init", "-q"]);
        let mut ids: Vec<String> = ["wanted one", "wanted two", "padding", "more padding"]
            .iter()
            .map(|t| {
                std::fs::write(scratch.join("b"), t).unwrap();
                sh(&scratch, &["hash-object", "-w", "b"])
            })
            .collect();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let g = |args: &[&str]| {
            let mut c = git(policy, &home);
            c.current_dir(&scratch).args(args);
            c
        };
        ids.truncate(2);
        ids.sort();
        keep_blobs(&g, &scratch.join(".git/keep"), &dir, &ids).await;
        let kept: Vec<Vec<String>> = pack_blobs(&dir).into_iter().filter(|b| !b.is_empty()).collect();
        assert_eq!(kept, vec![ids]);
        assert!(!std::fs::read_dir(dir.join("objects/pack")).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with(KEEP_PREFIX)));
    }

    /// Warming a mirror (as a clone, a sync and startup do) keeps the files of its default branch's
    /// tip: a read there then needs no network.
    #[tokio::test]
    async fn warmed_mirrors_read_their_tips_without_the_network() {
        let tmp = tempfile::tempdir().unwrap();
        let (up, url) = upstream(tmp.path());
        std::fs::create_dir_all(up.join("Arr/T")).unwrap();
        std::fs::write(up.join("Arr/T/interface.ccl"), "implements: t\n").unwrap();
        sh(&up, &["add", "-A"]);
        sh(&up, &["commit", "-q", "-m", "first"]);
        let head = sh(&up, &["rev-parse", "HEAD"]);
        let policy = GitPolicy { allow_local: true };
        warm(policy, &url).await.unwrap();
        let (r, used) = mirror_read(&url, &head, false).await;
        assert!(matches!(r, FromMirror::Read(_)) && !used);
        // Warm already: warming again fetches nothing.
        warm(policy, &url).await.unwrap();
    }

    /// A preview's temporary mirror is read like a shared one, and gone once dropped.
    #[tokio::test]
    async fn temporary_mirrors_go() {
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        sh(&up, &["config", "uploadpack.allowFilter", "true"]);
        std::fs::write(up.join("cactarium.toml"), "format = 1\n").unwrap();
        sh(&up, &["add", "-A"]);
        sh(&up, &["commit", "-q", "-m", "files"]);
        let c = sh(&up, &["rev-parse", "HEAD"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        let mirrors = Mirrors::temp().unwrap();
        let root = mirrors.temp_path().unwrap();
        let got = read_files_in(policy, &mirrors, &url, &[(c, "cactarium.toml".to_owned())]).await.unwrap();
        assert!(matches!(&got[0], FileAt::Content(b) if b.as_slice() == b"format = 1\n"), "{:?}", got[0]);
        assert!(std::fs::read_dir(&root).unwrap().next().is_some(), "the mirror was made there");
        drop(mirrors);
        for _ in 0..50 {
            if !root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!root.exists(), "the temporary mirror is gone");
    }

    /// A preview's clone queued for the slot is given up once its request goes away: the temporary
    /// mirror is deleted while the slot is still taken, without waiting for it.
    #[tokio::test]
    async fn abandoned_previews_give_up_their_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let up = tmp.path().join("up");
        std::fs::create_dir(&up).unwrap();
        sh(&up, &["init", "-q", "-b", "master"]);
        std::fs::write(up.join("cactarium.toml"), "format = 1\n").unwrap();
        sh(&up, &["add", "-A"]);
        sh(&up, &["commit", "-q", "-m", "files"]);
        let c = sh(&up, &["rev-parse", "HEAD"]);
        let url = format!("file://{}", up.display());
        let policy = GitPolicy { allow_local: true };
        let busy = PREVIEW_UPDATES.acquire().await.unwrap();
        let mirrors = Mirrors::temp().unwrap();
        let root = mirrors.temp_path().unwrap();
        let request = {
            let m = mirrors.clone();
            tokio::spawn(async move { read_files_in(policy, &m, &url, &[(c, "cactarium.toml".to_owned())]).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        request.abort();
        drop(mirrors);
        for _ in 0..100 {
            if !root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(!root.exists(), "the abandoned preview's mirror is gone while the slot is still busy");
        drop(busy);
    }

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
        for a in [
            "10.0.0.1",
            "127.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.1.2.3",
            "198.18.0.1",
            "240.0.0.1",
            "224.0.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "ff02::1",
        ] {
            assert!(private(a.parse().unwrap()), "{a}");
        }
        for a in ["140.82.112.3", "2606:50c0:8000::153"] {
            assert!(!private(a.parse().unwrap()), "{a}");
        }
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
