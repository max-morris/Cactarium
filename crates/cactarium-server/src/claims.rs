//! A version's dependencies and claims, as the `claims` table stores them: one row per
//! `[[dependency]]`, `[[fork-of]]`, `[[works-with]]` and `[[incompatible-with]]` in its manifest.

use cactup_ecosystem_common::api::ClaimInfo;
use cactup_ecosystem_common::manifest::Manifest;
use cactup_ecosystem_common::slug::Slug;

use crate::error::AppResult;
use crate::templates::ClaimRow;

#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRec {
    /// `dependency`, `fork-of`, `works-with` or `incompatible-with`.
    pub kind: String,
    pub owner: String,
    pub name: String,
    /// What followed `@` in the target.
    pub range: Option<String>,
    /// What followed `#` in the target.
    pub sha: Option<String>,
    /// A dependency's thorns of the target.
    pub needs: Vec<String>,
    /// A dependency's thorns of this package; empty means every thorn.
    pub needed_by: Vec<String>,
    pub note: Option<String>,
}

const COLS: &str = "kind, target_owner, target_name, range, sha, needs, needed_by, note";

type Row = (String, String, String, Option<String>, Option<String>, Vec<String>, Vec<String>, Option<String>);

impl ClaimRec {
    fn new(kind: &str, target: &Slug, note: &Option<String>) -> ClaimRec {
        ClaimRec {
            kind: kind.to_owned(),
            owner: target.owner.as_str().to_owned(),
            name: target.name.as_str().to_owned(),
            range: target.at.clone(),
            sha: target.sha.clone(),
            needs: vec![],
            needed_by: vec![],
            note: note.clone(),
        }
    }

    /// Every dependency and claim a manifest declares, in the order the manifest gives them.
    pub fn of_manifest(m: &Manifest) -> Vec<ClaimRec> {
        let mut out = Vec::new();
        for d in &m.dependencies {
            out.push(ClaimRec {
                needs: d.needs.clone(),
                needed_by: d.needed_by.clone(),
                ..ClaimRec::new("dependency", &d.target, &d.note)
            });
        }
        for f in &m.fork_of {
            out.push(ClaimRec::new("fork-of", &f.target, &f.note));
        }
        for (kind, list) in [("works-with", &m.works_with), ("incompatible-with", &m.incompatible_with)] {
            for c in list {
                out.push(ClaimRec::new(kind, &c.target, &c.note));
            }
        }
        out
    }

    pub fn target(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }

    pub async fn insert(&self, db: &mut sqlx::PgConnection, version_id: i64) -> AppResult<()> {
        sqlx::query(&format!(
            "INSERT INTO claims (version_id, {COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        ))
        .bind(version_id)
        .bind(&self.kind)
        .bind(&self.owner)
        .bind(&self.name)
        .bind(&self.range)
        .bind(&self.sha)
        .bind(&self.needs)
        .bind(&self.needed_by)
        .bind(&self.note)
        .execute(db)
        .await?;
        Ok(())
    }

    /// A version's claims: dependencies first, then the rest by kind, each by target.
    pub async fn of_version<'e>(db: impl sqlx::PgExecutor<'e>, version_id: i64) -> AppResult<Vec<ClaimRec>> {
        let rows: Vec<Row> = sqlx::query_as(&format!(
            "SELECT {COLS} FROM claims WHERE version_id = $1
             ORDER BY kind <> 'dependency', kind, target_owner, target_name, id"
        ))
        .bind(version_id)
        .fetch_all(db)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(kind, owner, name, range, sha, needs, needed_by, note)| ClaimRec {
                kind,
                owner,
                name,
                range,
                sha,
                needs,
                needed_by,
                note,
            })
            .collect())
    }

    pub fn info(&self) -> ClaimInfo {
        ClaimInfo {
            kind: self.kind.clone(),
            target: self.target(),
            range: self.range.clone(),
            sha: self.sha.clone(),
            needs: self.needs.clone(),
            needed_by: self.needed_by.clone(),
            note: self.note.clone(),
        }
    }

    /// For a fork-of: the upstream thorns this fork lacks, against the upstream's newest
    /// published version within the fork's range (or at its commit), as (that version's label,
    /// the missing thorns). None when it isn't a fork-of, or no such upstream version is here.
    pub async fn fork_gap(&self, db: &sqlx::PgPool, own: &[String]) -> AppResult<Option<(String, Vec<String>)>> {
        if self.kind != "fork-of" {
            return Ok(None);
        }
        let covers: Option<cactup_ecosystem_common::version::TrackedReq> = match (&self.range, &self.sha) {
            (_, Some(_)) => None,
            (Some(r), None) => match r.parse() {
                Ok(req) => Some(req),
                Err(_) => return Ok(None),
            },
            (None, None) => Some(cactup_ecosystem_common::version::TrackedReq::any()),
        };
        let upstream: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
            "SELECT v.id, v.track, v.version, v.commit FROM versions v JOIN entries e ON e.id = v.entry_id
             WHERE e.owner = $1 AND e.name = $2 AND e.kind = 'package' AND v.review = 'approved' AND v.state <> 'invalid'
             ORDER BY v.sort_key DESC",
        )
        .bind(&self.owner)
        .bind(&self.name)
        .fetch_all(db)
        .await?;
        let chosen = upstream.into_iter().find(|(_, track, version, commit)| match (&covers, &self.sha) {
            (_, Some(sha)) => commit.as_deref().is_some_and(|c| c.starts_with(sha.as_str())),
            (Some(req), None) => {
                let label = if track.is_empty() { version.clone() } else { format!("{track}:{version}") };
                label.parse().is_ok_and(|v| req.matches(&v))
            }
            (None, None) => false,
        });
        let Some((vid, track, version, _)) = chosen else { return Ok(None) };
        let theirs: Vec<String> = sqlx::query_scalar("SELECT name FROM thorns WHERE version_id = $1 ORDER BY name")
            .bind(vid)
            .fetch_all(db)
            .await?;
        let missing: Vec<String> = theirs.into_iter().filter(|t| !own.contains(t)).collect();
        let label = if track.is_empty() { version } else { format!("{track}:{version}") };
        Ok(Some((format!("{}@{label}", self.target()), missing)))
    }

    pub fn row(&self) -> ClaimRow {
        let at = match (&self.range, &self.sha) {
            (Some(r), _) => format!("@{r}"),
            (None, Some(h)) => format!("#{h}"),
            (None, None) => String::new(),
        };
        ClaimRow {
            kind: match self.kind.as_str() {
                "dependency" => "depends on".to_owned(),
                k => k.replace('-', " "),
            },
            target: self.target(),
            target_url: format!("/{}/{}", self.owner, self.name),
            range: at,
            needs: self.needs.join(", "),
            needed_by: self.needed_by.join(", "),
            note: self.note.clone().unwrap_or_default(),
        }
    }
}
