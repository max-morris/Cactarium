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

async fn run_for(cmd: Command, what: &str, limit: Duration) -> anyhow::Result<String> {
    exec(cmd, None, what, limit, None).await
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
    let root = private_root().await?;
    let key = url.trim().trim_end_matches('/').to_owned();
    let dir = root.join(hex::encode(<sha2::Sha256 as sha2::Digest>::digest(key.as_bytes())));
    Ok((root, key, dir))
}

/// Whether the mirror is missing (or lacks any of) `commits`.
async fn lacks_commits(policy: GitPolicy, dir: &Path, commits: &[String]) -> bool {
    if !mirror_complete(dir).await {
        return true;
    }
    let Ok(home) = tempfile::tempdir() else { return true };
    let mut c = git(policy, home.path());
    c.arg("-C").arg(dir).args(["cat-file", "--batch-check=%(objecttype)"]);
    let input: String = commits.iter().map(|c| format!("{c}\n")).collect();
    match run_with_input(c, input, "looking up the tagged commits").await {
        Ok(out) => out.lines().any(|l| l.trim() != "commit"),
        Err(_) => true,
    }
}

/// A file as a commit has it.
pub enum FileAt {
    /// The commit has no such file.
    Absent,
    /// Larger than [`MAX_FILE_AT`]: its size.
    TooLarge(u64),
    Content(Vec<u8>),
}

/// The largest file [`read_files_at`] returns, like [`read_in`].
pub const MAX_FILE_AT: u64 = 4 * 1024 * 1024;

/// Reads files at commits from the repo's history mirror, without checking anything out: the
/// mirror is fetched when a commit isn't in it (at most once per [`MIRROR_REFRESH`]), and the
/// blobs it lacks (it is blobless) are fetched by id, together, from the repo. For deciding what a
/// tag is before reading it in full. An error means the repo couldn't be read right now.
pub async fn read_files_at(policy: GitPolicy, url: &str, wants: &[(String, String)]) -> anyhow::Result<Vec<FileAt>> {
    if wants.is_empty() {
        return Ok(Vec::new());
    }
    let (root, key, dir) = mirror_of(url).await?;
    let home = tempfile::tempdir()?;
    let mut commits: Vec<String> = wants.iter().map(|(c, _)| c.clone()).collect();
    commits.sort_unstable();
    commits.dedup();
    if lacks_commits(policy, &dir, &commits).await {
        let error = update_mirror_if(policy, key.clone(), root, dir.clone(), false, Some(commits.clone())).await;
        if lacks_commits(policy, &dir, &commits).await {
            bail!("{}", error.unwrap_or_else(|| "the tagged commits aren't in the repo's history yet".into()));
        }
    }
    // Each file's blob id, or none.
    let mut oids: Vec<Option<String>> = Vec::with_capacity(wants.len());
    for (commit, path) in wants {
        let mut c = git(policy, home.path());
        c.arg("-C").arg(&dir).args(["ls-tree", commit, "--", path]);
        let out = run(c, "listing the commit's files").await?;
        oids.push(out.lines().find_map(|l| {
            let (meta, _) = l.split_once('\t')?;
            let mut parts = meta.split_whitespace();
            let (_, kind, oid) = (parts.next()?, parts.next()?, parts.next()?);
            (kind == "blob").then(|| oid.to_owned())
        }));
    }
    let mut unique: Vec<&str> = oids.iter().flatten().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    let sizes = |dir: PathBuf, unique: Vec<String>| {
        let home = home.path().to_path_buf();
        async move {
            let mut c = git(policy, &home);
            c.arg("-C").arg(&dir).args(["cat-file", "--batch-check=%(objectname) %(objectsize)"]);
            let input: String = unique.iter().map(|o| format!("{o}\n")).collect();
            let out = run_with_input(c, input, "looking up the files").await?;
            let mut found = std::collections::HashMap::new();
            for l in out.lines() {
                let mut p = l.split_whitespace();
                if let (Some(oid), Some(size)) = (p.next(), p.next())
                    && let Ok(n) = size.parse::<u64>()
                {
                    found.insert(oid.to_owned(), n);
                }
            }
            Ok::<_, anyhow::Error>(found)
        }
    };
    let unique: Vec<String> = unique.into_iter().map(str::to_owned).collect();
    let mut found = sizes(dir.clone(), unique.clone()).await?;
    let absent: Vec<&String> = unique.iter().filter(|o| !found.contains_key(*o)).collect();
    if !absent.is_empty() {
        let t = check(policy, &key).await?;
        for chunk in absent.chunks(200) {
            let mut c = git_to(policy, home.path(), &t);
            c.arg("-C").arg(&dir).args(["fetch", "--quiet", "--no-write-fetch-head", "--", &t.url]);
            c.args(chunk.iter().map(|o| o.as_str()));
            run(c, "fetching the files").await?;
        }
        found = sizes(dir.clone(), unique.clone()).await?;
    }
    let mut out = Vec::with_capacity(wants.len());
    for oid in oids {
        let Some(oid) = oid else {
            out.push(FileAt::Absent);
            continue;
        };
        let size = *found.get(&oid).ok_or_else(|| anyhow!("the repo didn't send file {oid}"))?;
        if size > MAX_FILE_AT {
            out.push(FileAt::TooLarge(size));
            continue;
        }
        let mut c = git(policy, home.path());
        c.arg("-C").arg(&dir).args(["cat-file", "blob", &oid]);
        out.push(FileAt::Content(exec_raw(c, None, "reading a file", TIMEOUT, None).await?));
    }
    Ok(out)
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
    update_mirror_if(policy, url, root, dir, broken, None).await
}

/// [`update_mirror`]; with `needed`, the update skips the window when those commits (which the repo
/// just listed, so they exist) aren't in the mirror yet, once the lock is held: a tag pushed a
/// moment after the last update is read at once, and concurrent callers fetch once.
async fn update_mirror_if(
    policy: GitPolicy,
    url: String,
    root: PathBuf,
    dir: PathBuf,
    broken: bool,
    needed: Option<Vec<String>>,
) -> Option<String> {
    let lock = mirror_lock(&dir);
    let task = tokio::spawn(async move {
        let mut state = lock.lock_owned().await;
        let lacking = match &needed {
            Some(commits) => lacks_commits(policy, &dir, commits).await,
            None => false,
        };
        if !lacking && state.finished.is_some_and(|at| at.elapsed() < MIRROR_REFRESH) {
            return state.error.clone();
        }
        let result = async {
            let _permit = MIRROR_UPDATES.acquire().await?;
            let t = check(policy, &url).await?;
            let home = tempfile::tempdir()?;
            if broken {
                discard_mirror(&root, &dir).await?;
            }
            if mirror_complete(&dir).await {
                fetch_mirror(policy, home.path(), &t, &dir).await
            } else {
                clone_mirror(policy, home.path(), &t, &root, &dir).await
            }
        }
        .await;
        state.finished = Some(std::time::Instant::now());
        state.error = result.err().map(|e| {
            tracing::warn!("updating the mirror of {url} failed: {e:#}");
            format!("{e:#}")
        });
        state.error.clone()
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
    let cloned = run_for(c, "mirroring the repo's history", CLONE_TIMEOUT).await;
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
