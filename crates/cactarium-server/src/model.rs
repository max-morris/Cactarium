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
    pub curated: bool,
    pub created_by: Option<i64>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub const ENTRY_COLS: &str = "id, kind, owner, name, summary, description, visibility, verified, curated, created_by, created_at, updated_at";

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
    pub manifest: Option<serde_json::Value>,
    pub readme_html: Option<String>,
    pub created_at: OffsetDateTime,
}

pub const VERSION_COLS: &str = "id, entry_id, track, version, sort_key, tag, commit, tree, is_virtual, state, \
     invalid_reason, yanked, yank_reason, manifest, readme_html, created_at";

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

    pub fn usable(&self) -> bool {
        !self.yanked && self.state != "invalid"
    }
}

/// A key that sorts versions within a track by semver precedence (release after its pre-releases).
pub fn semver_sort_key(v: &semver::Version) -> String {
    let pre = if v.pre.is_empty() { "~".to_owned() } else { format!("-{}", v.pre) };
    format!("{:010}.{:010}.{:010}{pre}", v.major, v.minor, v.patch)
}

pub fn number_sort_key(n: u32) -> String {
    format!("{n:010}")
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

/// All versions, newest first within each track; the default track first.
pub async fn versions(state: &AppState, entry_id: i64) -> AppResult<Vec<Version>> {
    Ok(sqlx::query_as::<_, Version>(&format!(
        "SELECT {VERSION_COLS} FROM versions WHERE entry_id = $1 ORDER BY track, sort_key DESC"
    ))
    .bind(entry_id)
    .fetch_all(&state.db)
    .await?)
}

pub async fn version_by_label(
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

/// The contact a manifest declares (`[package] contact` or `[stack] contact`).
pub fn manifest_contact(manifest: Option<&serde_json::Value>) -> Option<String> {
    let m = manifest?;
    ["package", "stack"]
        .iter()
        .find_map(|k| m[k]["contact"].as_str().map(str::to_owned))
}

/// Where to go for help with an entry: the newest usable version's declared contact (for a sim,
/// the one in its file), else its repo.
pub async fn entry_contact(
    state: &AppState,
    e: &Entry,
    repo_url: Option<&str>,
) -> AppResult<Option<String>> {
    let declared = if e.kind == "sim" {
        let content: Option<String> = sqlx::query_scalar(
            "SELECT s.content FROM sim_files s JOIN versions v ON v.id = s.version_id WHERE v.entry_id = $1 ORDER BY v.sort_key DESC LIMIT 1",
        )
        .bind(e.id)
        .fetch_optional(&state.db)
        .await?;
        content
            .and_then(|c| cactup_ecosystem_common::sim::SimFile::from_toml(&c).ok())
            .and_then(|s| s.sim.contact)
    } else {
        let m: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT manifest FROM versions WHERE entry_id = $1 AND manifest IS NOT NULL AND NOT yanked AND state <> 'invalid' ORDER BY created_at DESC LIMIT 1",
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

    #[test]
    fn semver_keys_order_prereleases_first() {
        let k = |s: &str| semver_sort_key(&semver::Version::parse(s).unwrap());
        assert!(k("1.2.3-rc.1") < k("1.2.3"));
        assert!(k("1.2.3") < k("1.10.0"));
        assert!(k("2026.5.0") > k("2025.11.0"));
    }
}
