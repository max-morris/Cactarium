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
    if !url.username().is_empty() || url.password().is_some() {
        bail!("repo URLs must not contain credentials");
    }
    match url.scheme() {
        "https" => {}
        "file" if policy.allow_local => return Ok(Target { url: url.to_string(), resolve: None }),
        "http" if policy.allow_local => {}
        _ => bail!("repo URLs must be https://"),
    }
    let host = url.host_str().ok_or_else(|| anyhow!("'{raw}' has no host"))?.to_owned();
    let normalized = url.as_str().trim_end_matches('/').to_owned();
    if policy.allow_local {
        return Ok(Target { url: normalized, resolve: None });
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("cannot resolve '{host}'"))?
        .collect();
    if addrs.is_empty() || addrs.iter().any(|a| private(a.ip())) {
        bail!("'{host}' is not a public host");
    }
    let ip = match addrs[0].ip() {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    Ok(Target { url: normalized, resolve: Some(format!("{bare}:{port}:{ip}")) })
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
                bail!("{what}: git printed more than {} MB", MAX_OUTPUT / (1024 * 1024));
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
        let error = update_mirror_in(policy, mirrors, key.clone(), root, dir.clone(), false, Some(commits.clone())).await;
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
    update_mirror_in(policy, &Mirrors::Shared, url, root, dir, broken, None).await
}

/// [`update_mirror`]; with `needed`, the update skips the window when those commits (which the repo
/// just listed, so they exist) aren't in the mirror yet, once the lock is held: a tag pushed a
/// moment after the last update is read at once, and concurrent callers fetch once.
/// Among `mirrors`: a temporary mirror is updated on [`PREVIEW_UPDATES`], and the update holds its
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
) -> Option<String> {
    let lock = mirror_lock(&dir);
    let held = mirrors.clone();
    let task = tokio::spawn(async move {
        let slots = match &held {
            Mirrors::Shared => &MIRROR_UPDATES,
            Mirrors::Temp(_) => &PREVIEW_UPDATES,
        };
        let mut state = lock.lock_owned().await;
        let lacking = match &needed {
            Some(commits) => lacks_commits(policy, &dir, commits).await,
            None => false,
        };
        if !lacking && state.finished.is_some_and(|at| at.elapsed() < MIRROR_REFRESH) {
            return state.error.clone();
        }
        let limit = match &held {
            Mirrors::Shared => None,
            Mirrors::Temp(_) => Some(MAX_PREVIEW_MIRROR_BYTES),
        };
        let work = async {
            let _permit = slots.acquire().await?;
            let t = check(policy, &url).await?;
            let home = tempfile::tempdir()?;
            if broken {
                discard_mirror(&root, &dir).await?;
            }
            if mirror_complete(&dir).await {
                fetch_mirror(policy, home.path(), &t, &dir).await
            } else {
                clone_mirror(policy, home.path(), &t, &root, &dir, limit).await
            }
        };
        // Only this task holds a temporary mirror once its requests are gone.
        let watched = match &held {
            Mirrors::Shared => None,
            Mirrors::Temp(t) => Some(std::sync::Arc::downgrade(t)),
        };
        let abandoned = async move {
            let Some(w) = watched else { return std::future::pending().await };
            while w.strong_count() > 1 {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        };
        let result = tokio::select! {
            r = work => r,
            () = abandoned => Err(anyhow!("the preview this mirror was for went away")),
        };
        state.finished = Some(std::time::Instant::now());
        state.error = result.err().map(|e| {
            tracing::warn!("updating the mirror of {url} failed: {e:#}");
            format!("{e:#}")
        });
        let error = state.error.clone();
        drop(state);
        drop(held);
        error
    });
    task.await.unwrap_or_else(|e| Some(format!("updating the mirror failed: {e}")))
}

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

    #[test]
    fn url_normalization() {
        assert_eq!(
            normalize_url("https://GitHub.com/max-morris/CarpetX.git/"),
            "github.com/max-morris/CarpetX"
        );
        assert_eq!(
            normalize_url("https://github.com/max-morris/CarpetX"),
            "github.com/max-morris/CarpetX"
        );
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
