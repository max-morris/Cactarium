//! Entries and versions: queries, visibility and ordering.

use cactup_ecosystem_common::version::TrackedVersion;
use time::OffsetDateTime;

use crate::auth::User;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(dead_code)] // the full row, for callers to come
pub struct Entry {
    pub id: i64,
    pub kind: String,
    pub owner: String,
    pub name: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub visibility: String,
    pub verified: bool,
    /// New releases publish without review (see `publish::release_review`).
    pub trusted: bool,
    pub curated: bool,
    pub created_by: Option<i64>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub const ENTRY_COLS: &str = "id, kind, owner, name, summary, description, visibility, verified, trusted, curated, created_by, created_at, updated_at";

impl Entry {
    pub fn slug(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    pub fn url(&self) -> String {
        format!("/{}/{}", self.owner, self.name)
    }

    /// Whether `user` manages this entry: its owner namespace is theirs or an organization they
    /// belong to, or they are an admin.
    pub fn manageable_by(&self, user: Option<&User>) -> bool {
        user.is_some_and(|u| u.is_admin() || u.username == self.owner || u.orgs.contains(&self.owner))
    }

    pub fn visible_to(&self, user: Option<&User>) -> bool {
        self.visibility == "public" || self.manageable_by(user)
    }
}

#[derive(Clone, Debug, sqlx::FromRow)]
#[allow(dead_code)] // the full row, for callers to come
pub struct Version {
    pub id: i64,
    pub entry_id: i64,
    pub track: String,
    pub version: String,
    pub sort_key: String,
    pub tag: Option<String>,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub is_virtual: bool,
    pub state: String,
    pub invalid_reason: Option<String>,
    pub yanked: bool,
    pub yank_reason: Option<String>,
    /// `approved`, or `pending`/`rejected` in review (seen only by the entry's managers).
    pub review: String,
    pub manifest: Option<serde_json::Value>,
    pub readme_html: Option<String>,
    pub created_at: OffsetDateTime,
}

pub const VERSION_COLS: &str = "id, entry_id, track, version, sort_key, tag, commit, tree, is_virtual, state, \
     invalid_reason, yanked, yank_reason, review, manifest, readme_html, created_at";

impl Version {
    /// `1.2.3`, `mixed-precision:1.2.3`, or a sim's `3`.
    pub fn label(&self) -> String {
        if self.track.is_empty() {
            self.version.clone()
        } else {
            format!("{}:{}", self.track, self.version)
        }
    }

    pub fn short_commit(&self) -> String {
        self.commit.as_deref().map(|c| c.chars().take(10).collect()).unwrap_or_default()
    }

    pub fn approved(&self) -> bool {
        self.review == "approved"
    }

    /// Not invalid: neither marked so nor carrying a reason it was found invalid (a row that was
    /// invalid stays unservable whatever later happens to its tag).
    pub fn valid(&self) -> bool {
        self.state != "invalid" && self.invalid_reason.is_none()
    }

    pub fn usable(&self) -> bool {
        self.approved() && !self.yanked && self.valid()
    }
}

/// A key that sorts versions within a track by semver precedence (release after its pre-releases).
pub fn semver_sort_key(v: &semver::Version) -> String {
    let pre = if v.pre.is_empty() { "~".to_owned() } else { format!("-{}", v.pre) };
    format!("{:010}.{:010}.{:010}{pre}", v.major, v.minor, v.patch)
}

pub fn tracked(v: &Version) -> Option<TrackedVersion> {
    v.label().parse().ok()
}

pub async fn find_entry(state: &AppState, owner: &str, name: &str) -> AppResult<Option<Entry>> {
    Ok(sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE owner = $1 AND name = $2"
    ))
    .bind(owner)
    .bind(name)
    .fetch_optional(&state.db)
    .await?)
}

/// The entry, if `user` may see it; NotFound otherwise (hidden entries are indistinguishable from
/// missing ones).
pub async fn visible_entry(
    state: &AppState,
    owner: &str,
    name: &str,
    user: Option<&User>,
) -> AppResult<Entry> {
    match find_entry(state, owner, name).await? {
        Some(e) if e.visible_to(user) => Ok(e),
        _ => Err(AppError::NotFound),
    }
}

pub async fn entry_by_id(state: &AppState, id: i64) -> AppResult<Entry> {
    sqlx::query_as::<_, Entry>(&format!("SELECT {ENTRY_COLS} FROM entries WHERE id = $1"))
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)
}

/// The published (review-approved) versions, newest first within each track; the default track
/// first. This is what everyone sees and what resolution uses.
pub async fn versions(state: &AppState, entry_id: i64) -> AppResult<Vec<Version>> {
    Ok(all_versions(state, entry_id)
        .await?
        .into_iter()
        .filter(Version::approved)
        .collect())
}

/// Every version, including those pending or rejected in review: for managers and admins only.
pub async fn all_versions(state: &AppState, entry_id: i64) -> AppResult<Vec<Version>> {
    Ok(sqlx::query_as::<_, Version>(&format!(
        "SELECT {VERSION_COLS} FROM versions WHERE entry_id = $1 ORDER BY track, sort_key DESC"
    ))
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?)
}

/// The versions `user` may see: all of them for the entry's managers, the published ones otherwise.
pub async fn versions_for(state: &AppState, e: &Entry, user: Option<&User>) -> AppResult<Vec<Version>> {
    if e.manageable_by(user) { all_versions(state, e.id).await } else { versions(state, e.id).await }
}

/// A published version by label (`1.2.3`, `track:1.2.3`, a sim's `3`).
pub async fn version_by_label(
    state: &AppState,
    entry_id: i64,
    label: &str,
) -> AppResult<Option<Version>> {
    Ok(any_version_by_label(state, entry_id, label).await?.filter(Version::approved))
}

/// A version by label whatever its review state: callers check who may see it.
pub async fn any_version_by_label(
    state: &AppState,
    entry_id: i64,
    label: &str,
) -> AppResult<Option<Version>> {
    let (track, version) = match label.split_once(':') {
        Some((t, v)) => (t, v),
        None => ("", label),
    };
    Ok(sqlx::query_as::<_, Version>(&format!(
        "SELECT {VERSION_COLS} FROM versions WHERE entry_id = $1 AND track = $2 AND version = $3"
    ))
    .bind(entry_id)
    .bind(track)
    .bind(version)
    .fetch_optional(&state.db)
    .await?)
}

/// The tracks in display order: the manifest's default track first, then the unprefixed one.
pub fn tracks_of(versions: &[Version], default_track: Option<&str>) -> Vec<String> {
    let mut tracks: Vec<String> = Vec::new();
    for v in versions {
        if !tracks.contains(&v.track) {
            tracks.push(v.track.clone());
        }
    }
    let first = default_track.map(|d| if d == "default" { "" } else { d });
    if let Some(d) = first
        && let Some(i) = tracks.iter().position(|t| t == d)
    {
        let t = tracks.remove(i);
        tracks.insert(0, t);
    }
    tracks
}

/// The newest usable version on a track (falling back to the newest of any state).
pub fn latest_on<'a>(versions: &'a [Version], track: &str) -> Option<&'a Version> {
    let on: Vec<&Version> = versions.iter().filter(|v| v.track == track).collect();
    on.iter().find(|v| v.usable()).or(on.first()).copied()
}

/// A git URL as a page a person can open: `https://host/x/y.git` → `https://host/x/y`.
pub fn repo_page(url: &str) -> String {
    let u = url.trim_end_matches('/');
    u.strip_suffix(".git").unwrap_or(u).to_owned()
}

/// The contact a manifest declares (`[package]`, `[stack]` or `[sim]` contact).
pub fn manifest_contact(manifest: Option<&serde_json::Value>) -> Option<String> {
    let m = manifest?;
    ["package", "stack", "sim"]
        .iter()
        .find_map(|k| m[k]["contact"].as_str().map(str::to_owned))
}

/// The sims a version of a sim entry holds, by name: `[""]` for an entry's only sim (a `file`
/// manifest, or an upload), else each `[sim.files]` name.
pub async fn sim_names(state: &AppState, version_id: i64) -> AppResult<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT name FROM sim_files WHERE version_id = $1 ORDER BY name")
        .bind(version_id)
        .fetch_all(&state.db)
        .await?)
}

/// Whether a sim entry publishes named sims (`[sim.files]`): then every sim is addressed
/// `owner/name/sim`, whatever the count. The form is fixed per entry (a version can't switch it).
pub async fn multi_sim(state: &AppState, entry_id: i64) -> AppResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sim_files s JOIN versions v ON v.id = s.version_id WHERE v.entry_id = $1 AND s.name <> '')",
    )
    .bind(entry_id)
    .fetch_one(&state.db)
    .await?)
}

/// Where to go for help with an entry: the newest usable version's declared contact (for a sim,
/// the one in its file: `sim`'s, for one sim of a multi-sim entry), else its repo.
pub async fn entry_contact(
    state: &AppState,
    e: &Entry,
    repo_url: Option<&str>,
    sim: Option<&str>,
) -> AppResult<Option<String>> {
    // A sim published from its repo: its cactarium-sim.toml's contact wins over the file's.
    let from_manifest = if e.kind == "sim" {
        let m: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND review = 'approved' ORDER BY sort_key DESC LIMIT 1",
        )
        .bind(e.id)
        .fetch_optional(&state.db)
        .await?
        .flatten();
        manifest_contact(m.as_ref())
    } else {
        None
    };
    let declared = if let Some(c) = from_manifest {
        Some(c)
    } else if e.kind == "sim" {
        // That sim's file in the newest version holding it; with no sim named, the newest version's
        // first sim (its only one, unless the entry is multi-sim).
        let content: Option<String> = sqlx::query_scalar(
            "SELECT s.content FROM sim_files s JOIN versions v ON v.id = s.version_id
             WHERE v.entry_id = $1 AND v.review = 'approved' AND ($2::text IS NULL OR s.name = $2)
             ORDER BY v.sort_key DESC, s.name LIMIT 1",
        )
        .bind(e.id)
        .bind(sim)
        .fetch_optional(&state.db)
        .await?;
        content
            .and_then(|c| cactup_ecosystem_common::sim::SimFile::from_toml(&c).ok())
            .and_then(|s| s.sim.contact)
    } else {
        let m: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND NOT yanked AND state <> 'invalid' AND review = 'approved' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(e.id)
        .fetch_optional(&state.db)
        .await?
        .flatten();
        manifest_contact(m.as_ref())
    };
    Ok(declared.or_else(|| repo_url.map(repo_page)))
}

pub async fn heart_count(state: &AppState, entry_id: i64) -> AppResult<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM hearts WHERE entry_id = $1")
        .bind(entry_id)
        .fetch_one(&state.db)
        .await?)
}

pub fn fmt_date(t: OffsetDateTime) -> String {
    t.format(time::macros::format_description!("[year]-[month]-[day]"))
        .unwrap_or_default()
}

pub fn fmt_time(t: OffsetDateTime) -> String {
    t.format(time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row that was found invalid is never usable, whatever its state says now.
    #[test]
    fn a_reason_for_invalid_makes_a_version_unusable() {
        let v = Version {
            id: 1,
            entry_id: 1,
            track: String::new(),
            version: "1.1.0".into(),
            sort_key: semver_sort_key(&semver::Version::new(1, 1, 0)),
            tag: Some("v1.1.0".into()),
            commit: None,
            tree: None,
            is_virtual: false,
            state: "tag-moved".into(),
            invalid_reason: Some("the manifest names 'x', not 'y'".into()),
            yanked: false,
            yank_reason: None,
            review: "approved".into(),
            manifest: None,
            readme_html: None,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert!(!v.valid() && !v.usable());
        let ok = Version { state: "tag-moved".into(), invalid_reason: None, ..v };
        assert!(ok.valid() && ok.usable());
    }

    #[test]
    fn semver_keys_order_prereleases_first() {
        let k = |s: &str| semver_sort_key(&semver::Version::parse(s).unwrap());
        assert!(k("1.2.3-rc.1") < k("1.2.3"));
        assert!(k("1.2.3") < k("1.10.0"));
        assert!(k("2026.5.0") > k("2025.11.0"));
    }
}
