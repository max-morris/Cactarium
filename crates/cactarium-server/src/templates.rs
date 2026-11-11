//! Page view models. Templates live in `templates/`; all formatting decisions are made here so
//! the templates stay plain markup that is easy to restyle.

use askama::Template;
use axum::response::Html;

use crate::auth::Session;
use crate::error::{AppError, AppResult};
use crate::state::AppState;

#[derive(Clone, Debug, Default)]
pub struct UserView {
    pub username: String,
    pub is_admin: bool,
    pub is_superadmin: bool,
    /// Organizations the user belongs to, which they can publish under.
    pub orgs: Vec<String>,
}

/// What every page's layout needs.
#[derive(Clone, Debug, Default)]
pub struct PageCtx {
    pub user: Option<UserView>,
    pub csrf: String,
    pub dev_banner: bool,
    pub flash: Option<String>,
}

impl PageCtx {
    pub fn anonymous() -> PageCtx {
        PageCtx::default()
    }

    pub fn new(state: &AppState, s: Option<&Session>) -> PageCtx {
        PageCtx {
            user: s.and_then(|s| s.user.as_ref()).map(|u| UserView {
                username: u.username.clone(),
                is_admin: u.is_admin(),
                is_superadmin: u.is_superadmin(),
                orgs: u.orgs.clone(),
            }),
            csrf: s.map(|s| s.csrf.clone()).unwrap_or_default(),
            dev_banner: state.cfg.dev_login,
            flash: None,
        }
    }

    pub fn is_superadmin(&self) -> bool {
        self.user.as_ref().is_some_and(|u| u.is_superadmin)
    }

    /// Whether the user can publish under a namespace other than their own name.
    pub fn has_namespaces(&self) -> bool {
        self.user.as_ref().is_some_and(|u| u.is_admin || !u.orgs.is_empty())
    }
}

pub fn render<T: Template>(t: &T) -> AppResult<String> {
    t.render().map_err(|e| AppError::Internal(anyhow::anyhow!("template: {e}")))
}

pub fn page<T: Template>(t: &T) -> AppResult<Html<String>> {
    Ok(Html(render(t)?))
}

// ---------- shared rows ----------

#[derive(Clone, Debug)]
pub struct EntryRow {
    pub slug: String,
    pub url: String,
    pub kind: String,
    pub latest: String,
    pub summary: String,
    pub visibility: String,
    pub verified: bool,
    pub curated: bool,
    pub hearts: i64,
}

#[derive(Clone, Debug)]
pub struct VersionRow {
    pub label: String,
    pub url: String,
    pub tag: String,
    pub commit: String,
    pub status: String,
    pub current: bool,
    pub date: String,
    pub id: i64,
    pub yanked: bool,
    /// Waiting in review: seen only by the entry's managers and admins.
    pub pending: bool,
}

/// A sim input as its page shows it: what an import asks for or fetches.
#[derive(Clone, Debug)]
pub struct InputRow {
    pub knob: String,
    pub description: String,
    pub url: String,
    pub sha256: String,
    /// A file in the sim's own repo, at the version's commit.
    pub repo_file: String,
    pub unpack: bool,
    /// The file in the unpacked archive the knob is set to (empty: the folder itself).
    pub path: String,
    /// (file, replace, with)
    pub fixups: Vec<(String, String, String)>,
}

#[derive(Clone, Debug)]
pub struct ClaimRow {
    pub kind: String,
    pub target: String,
    pub target_url: String,
    pub range: String,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct PinRow {
    pub repo: String,
    pub url: String,
    pub git_ref: String,
    pub commit: String,
    pub registered: Option<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct Tab {
    pub label: String,
    pub url: String,
    pub selected: bool,
}

#[derive(Clone, Debug)]
pub struct EntryHead {
    pub slug: String,
    pub url: String,
    pub kind: String,
    pub summary: String,
    pub description_html: String,
    pub visibility: String,
    pub verified: bool,
    pub curated: bool,
    pub can_manage: bool,
    pub repo_url: String,
    pub review_note: String,
    pub review_status: String,
    /// Where to go for help or to report problems.
    pub contact: String,
    pub hearts: i64,
    /// The visitor saved it (always false when signed out).
    pub hearted: bool,
    pub signed_in: bool,
}

// ---------- pages ----------

#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub ctx: PageCtx,
    pub status: u16,
    pub message: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub ctx: PageCtx,
    pub github: bool,
    pub orcid: bool,
    pub dev_login: bool,
    pub next: String,
}

#[derive(Template)]
#[template(path = "choose_name.html")]
pub struct ChooseNamePage {
    pub ctx: PageCtx,
    pub provider: String,
    pub suggestion: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "home.html")]
pub struct HomePage {
    pub ctx: PageCtx,
    pub recent: Vec<EntryRow>,
    pub packages: i64,
    pub stacks: i64,
    pub sims: i64,
}

#[derive(Clone, Debug)]
pub struct ThornHit {
    pub thorn: String,
    pub implements: String,
    pub package: String,
    pub package_url: String,
    pub version: String,
}

#[derive(Template)]
#[template(path = "search.html")]
pub struct SearchPage {
    pub ctx: PageCtx,
    pub q: String,
    pub kind: String,
    pub results: Vec<EntryRow>,
    pub thorns: Vec<ThornHit>,
    pub title: String,
}

#[derive(Clone, Debug)]
pub struct ThornRow {
    pub name: String,
    pub implements: String,
    pub requires: String,
    pub inherits: String,
    pub caveat: String,
}

#[derive(Clone, Debug)]
pub struct TrackTab {
    pub name: String,
    pub url: String,
    pub selected: bool,
    pub description: String,
}

#[derive(Template)]
#[template(path = "package.html")]
pub struct PackagePage {
    pub ctx: PageCtx,
    pub e: EntryHead,
    pub tracks: Vec<TrackTab>,
    pub version: Option<VersionRow>,
    pub version_note: String,
    pub add_cmd: String,
    pub readme_html: String,
    pub thorns: Vec<ThornRow>,
    pub claims: Vec<ClaimRow>,
    pub caveats: Vec<(String, String)>,
    pub versions: Vec<VersionRow>,
    pub used_by: Vec<EntryRow>,
    pub tabs: Vec<Tab>,
    pub tab: String,
    /// For the entry's managers: its repo's controls (refresh, last error, webhooks).
    pub repo: Option<RepoManage>,
    /// Packages that declare themselves forks of this one.
    pub forks: Vec<EntryRow>,
    /// (upstream slug, compare URL) for each package this one forks.
    pub upstreams: Vec<(String, String)>,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct MoveRow {
    pub repo: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Template)]
#[template(path = "stack.html")]
pub struct StackPage {
    pub ctx: PageCtx,
    pub e: EntryHead,
    pub version: Option<VersionRow>,
    pub releases: Vec<VersionRow>,
    pub how: String,
    pub install_cmd: String,
    pub tip_cmd: String,
    pub master_cmd: String,
    /// How `@head`/`@master` are served: `trusted`, `allow` (untrusted, with a warning) or `refuse`.
    pub tip_policy: String,
    pub frozen_text: String,
    pub pins: Vec<PinRow>,
    pub diff: Vec<MoveRow>,
    pub recipe: String,
    pub extends: Vec<(String, String)>,
    pub claims: Vec<ClaimRow>,
    pub used_by: Vec<EntryRow>,
    /// For the entry's managers when it is released from a repo: the repo's controls.
    pub repo: Option<RepoManage>,
}

#[derive(Template)]
#[template(path = "sim.html")]
pub struct SimPage {
    pub ctx: PageCtx,
    pub e: EntryHead,
    pub versions: Vec<VersionRow>,
    pub tabs: Vec<Tab>,
    pub tab: String,
    pub thornlist_name: String,
    pub thornlist: String,
    pub parfile_name: String,
    pub parfile: String,
    pub pins: Vec<PinRow>,
    pub inputs: Vec<InputRow>,
    pub run: Vec<(String, String)>,
    pub provenance: Vec<(String, String)>,
    pub warnings: Vec<String>,
    pub import_cmd: String,
    pub download_url: String,
    pub authors: String,
    pub license: String,
    /// For the entry's managers when it is published from a repo: the repo's controls.
    pub repo: Option<RepoManage>,
}

/// A repo-backed entry's controls for its managers: check for tags now, the last check's error,
/// and the webhook (one payload URL per forge, all checked against the same secret).
#[derive(Clone, Debug)]
pub struct RepoManage {
    pub entry_url: String,
    pub poll_error: String,
    /// `<base>/hooks`, to which the template appends `/<forge>/<entry id>`.
    pub webhook_base: String,
    pub entry_id: i64,
    pub secret: String,
}

#[derive(Template)]
#[template(path = "owner.html")]
pub struct OwnerPage {
    pub ctx: PageCtx,
    pub owner: String,
    pub display: String,
    pub entries: Vec<EntryRow>,
    pub is_org: bool,
    /// For an organization: (username, role).
    pub members: Vec<(String, String)>,
    /// For a user: the organizations they belong to.
    pub orgs: Vec<String>,
    pub can_manage_org: bool,
}

#[derive(Clone, Debug)]
pub struct AlertRow {
    pub id: i64,
    pub entry: String,
    pub entry_url: String,
    pub tag: String,
    pub frozen: String,
    pub now: String,
    pub when: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub ctx: PageCtx,
    pub entries: Vec<EntryRow>,
    /// (name, display name, my role)
    pub orgs: Vec<(String, String, String)>,
    pub saved: Vec<EntryRow>,
    pub reviews: Vec<(String, String, String, String)>,
    pub alerts: Vec<AlertRow>,
}

#[derive(Template)]
#[template(path = "new_repo.html")]
pub struct NewRepoPage {
    pub ctx: PageCtx,
    pub url: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "new_sim.html")]
pub struct NewSimPage {
    pub ctx: PageCtx,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "new_stack.html")]
pub struct NewStackPage {
    pub ctx: PageCtx,
    pub error: Option<String>,
    pub definition: String,
    pub thornlist: String,
    pub version: String,
    /// `owner/name` when uploading a new release of an existing uploaded stack; empty otherwise.
    pub release_of: String,
}

#[derive(Clone, Debug)]
pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub prefix: String,
    pub scopes: String,
    pub created: String,
    pub expires: String,
    pub last_used: String,
}

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsPage {
    pub ctx: PageCtx,
    pub identities: Vec<(String, String)>,
    pub tokens: Vec<TokenRow>,
    pub new_token: Option<String>,
    pub can_link_github: bool,
    pub can_link_orcid: bool,
}

#[derive(Clone, Debug, Default)]
pub struct CompareSide {
    pub slug: String,
    pub url: String,
    pub summary: String,
    pub version: String,
    pub tracks: String,
    pub repo: String,
    pub contact: String,
    pub claims: Vec<ClaimRow>,
}

#[derive(Template)]
#[template(path = "compare.html")]
pub struct ComparePage {
    pub ctx: PageCtx,
    pub a: CompareSide,
    pub b: CompareSide,
    pub sides: Vec<CompareSide>,
    pub only_a: Vec<String>,
    pub only_b: Vec<String>,
    pub both: Vec<String>,
}

// ---------- docs ----------

/// The docs pages in sidebar order: (path under `/docs`, title, one-line summary). The empty path
/// is `/docs` itself.
pub const DOC_PAGES: &[(&str, &str, &str)] = &[
    ("", "Overview", "What the Cactarium holds, accounts, and how CactUp uses it."),
    (
        "publishing",
        "Publishing",
        "Registering a repo, uploading, publishing under an organization, the dashboard.",
    ),
    (
        "packages",
        "Packages: cactarium.toml",
        "Every field of the package manifest, claims, caveats and repo layouts.",
    ),
    (
        "stacks",
        "Stacks: cactarium-stack.toml",
        "Flat, recipe and combined stacks, overrides, pins, releases, @head and @master.",
    ),
    (
        "sims",
        "Sims",
        "Publishing .sim files by upload or from a repo, the checks, warnings and versions.",
    ),
    (
        "versions",
        "Versions and tracks",
        "Semver, tags, tracks and ranges, tag patterns, frozen commits, yanking.",
    ),
    ("review", "Review and trust", "What is reviewed, what pending means, and who is trusted."),
    (
        "organizations",
        "Organizations",
        "Shared namespaces: owners, members, publishing under one, trust.",
    ),
    (
        "curated",
        "Curated packages",
        "Manifests kept on the Cactarium for repos without one, and handing them over.",
    ),
    ("finding", "Finding things", "Search, thorn pages, forks and comparisons, saves."),
    ("api", "HTTP API", "Every endpoint under /api/v1, its headers, and API tokens."),
];

#[derive(Clone, Debug)]
pub struct DocLink {
    pub url: String,
    pub title: &'static str,
    pub summary: &'static str,
    pub current: bool,
}

/// What every docs page needs: the sidebar, the neighboring pages, and the links out.
#[derive(Clone, Debug)]
pub struct DocsCtx {
    pub title: &'static str,
    pub pages: Vec<DocLink>,
    pub prev: Option<DocLink>,
    pub next: Option<DocLink>,
    /// The site's public origin without a trailing slash, for examples.
    pub base_url: String,
    cactup_docs: String,
}

impl DocsCtx {
    /// The page at `/docs/{path}` (`""` for `/docs`), or `None` if there is no such page.
    pub fn new(path: &str, base_url: String, cactup_docs: String) -> Option<DocsCtx> {
        let i = DOC_PAGES.iter().position(|p| p.0 == path)?;
        let link = |j: usize| {
            let (p, title, summary) = DOC_PAGES[j];
            DocLink {
                url: if p.is_empty() { "/docs".into() } else { format!("/docs/{p}") },
                title,
                summary,
                current: j == i,
            }
        };
        Some(DocsCtx {
            title: DOC_PAGES[i].1,
            pages: (0..DOC_PAGES.len()).map(link).collect(),
            prev: i.checked_sub(1).map(link),
            next: (i + 1 < DOC_PAGES.len()).then(|| link(i + 1)),
            base_url,
            cactup_docs,
        })
    }

    /// A link into CactUp's own docs (`CACTUP_DOCS_URL`) on `topic`: `cli`, `sim-format`,
    /// `inputs` or `publishing`.
    pub fn cactup(&self, topic: &str) -> String {
        let page = match topic {
            "cli" => "reference/cli.html",
            "sim-format" => "reference/sim-format.html",
            "inputs" | "publishing" => "users/sharing-simulations.html",
            _ => "",
        };
        format!("{}/{page}", self.cactup_docs)
    }
}

macro_rules! doc_page {
    ($ty:ident, $path:literal) => {
        #[derive(Template)]
        #[template(path = $path)]
        pub struct $ty {
            pub ctx: PageCtx,
            pub doc: DocsCtx,
        }
    };
}

doc_page!(DocsOverviewPage, "docs/index.html");
doc_page!(DocsPublishingPage, "docs/publishing.html");
doc_page!(DocsPackagesPage, "docs/packages.html");
doc_page!(DocsStacksPage, "docs/stacks.html");
doc_page!(DocsSimsPage, "docs/sims.html");
doc_page!(DocsVersionsPage, "docs/versions.html");
doc_page!(DocsReviewPage, "docs/review.html");
doc_page!(DocsOrganizationsPage, "docs/organizations.html");
doc_page!(DocsCuratedPage, "docs/curated.html");
doc_page!(DocsFindingPage, "docs/finding.html");
doc_page!(DocsApiPage, "docs/api.html");

/// Renders the docs page at `/docs/{path}` (`""` for `/docs`), or `None` if there is no such page.
pub fn docs_page(
    path: &str,
    ctx: PageCtx,
    base_url: String,
    cactup_docs: String,
) -> Option<AppResult<Html<String>>> {
    let doc = DocsCtx::new(path, base_url, cactup_docs)?;
    Some(match path {
        "" => page(&DocsOverviewPage { ctx, doc }),
        "publishing" => page(&DocsPublishingPage { ctx, doc }),
        "packages" => page(&DocsPackagesPage { ctx, doc }),
        "stacks" => page(&DocsStacksPage { ctx, doc }),
        "sims" => page(&DocsSimsPage { ctx, doc }),
        "versions" => page(&DocsVersionsPage { ctx, doc }),
        "review" => page(&DocsReviewPage { ctx, doc }),
        "organizations" => page(&DocsOrganizationsPage { ctx, doc }),
        "curated" => page(&DocsCuratedPage { ctx, doc }),
        "finding" => page(&DocsFindingPage { ctx, doc }),
        "api" => page(&DocsApiPage { ctx, doc }),
        _ => return None,
    })
}

// ---------- admin ----------

#[derive(Clone, Debug)]
pub struct SubRow {
    pub id: i64,
    pub entry: String,
    /// A new release of a public entry, not a new entry.
    pub release: bool,
    pub kind: String,
    pub status: String,
    pub submitter: String,
    pub when: String,
    pub selected: bool,
}

#[derive(Clone, Debug)]
pub struct ReviewView {
    pub id: i64,
    /// The release under review (`1.2.0`), or empty for a new entry.
    pub release: String,
    pub entry_trusted: bool,
    pub owner: String,
    pub entry: String,
    pub entry_url: String,
    pub kind: String,
    pub status: String,
    pub submitter: String,
    pub submitter_trusted: bool,
    pub summary: String,
    pub versions: Vec<VersionRow>,
    pub thorns: Vec<ThornRow>,
    pub claims: Vec<ClaimRow>,
    pub warnings: Vec<String>,
    pub readme_html: String,
    pub detail: String,
    pub note: String,
    pub checklist: Vec<(String, String, bool)>,
}

#[derive(Template)]
#[template(path = "admin_queue.html")]
pub struct AdminQueuePage {
    pub ctx: PageCtx,
    pub nav: String,
    pub open: Vec<SubRow>,
    pub review: Option<ReviewView>,
    pub can_trust: bool,
}

#[derive(Clone, Debug)]
pub struct AdminEntryRow {
    pub id: i64,
    pub slug: String,
    pub url: String,
    pub kind: String,
    pub visibility: String,
    pub verified: bool,
    pub trusted: bool,
    pub curated: bool,
    /// How a curated package's upstream tags become versions; empty otherwise.
    pub tag_rule: String,
    /// The repo it is read from; empty for entries without one (sims, uploaded stacks).
    pub repo_url: String,
    pub versions: Vec<VersionRow>,
}

#[derive(Template)]
#[template(path = "admin_entries.html")]
pub struct AdminEntriesPage {
    pub ctx: PageCtx,
    pub nav: String,
    pub q: String,
    pub entries: Vec<AdminEntryRow>,
    pub can_trust: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AdminUserRow {
    pub id: i64,
    pub username: String,
    pub display: String,
    pub role: String,
    pub trusted: bool,
    pub banned: bool,
    pub identities: String,
    pub created: String,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
pub struct AdminUsersPage {
    pub ctx: PageCtx,
    pub nav: String,
    pub q: String,
    pub users: Vec<AdminUserRow>,
    pub can_trust: bool,
}

#[derive(Clone, Debug)]
pub struct AuditRow {
    pub when: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: String,
}

#[derive(Template)]
#[template(path = "admin_audit.html")]
pub struct AdminAuditPage {
    pub ctx: PageCtx,
    pub nav: String,
    pub rows: Vec<AuditRow>,
}

#[derive(Template)]
#[template(path = "admin_tags.html")]
pub struct AdminTagsPage {
    pub ctx: PageCtx,
    pub nav: String,
    pub alerts: Vec<AlertRow>,
}

#[derive(Template)]
#[template(path = "admin_curated.html")]
pub struct AdminCuratedPage {
    pub ctx: PageCtx,
    pub nav: String,
    pub curated: Vec<AdminEntryRow>,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "new_org.html")]
pub struct NewOrgPage {
    pub ctx: PageCtx,
    pub name: String,
    pub display: String,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "org.html")]
pub struct OrgPage {
    pub ctx: PageCtx,
    pub name: String,
    pub display: String,
    pub my_role: String,
    pub can_manage: bool,
    pub can_trust: bool,
    pub trusted: bool,
    /// (user id, username, role, added)
    pub members: Vec<(i64, String, String, String)>,
    pub entries: Vec<EntryRow>,
}

#[derive(Template)]
#[template(path = "admin_site.html")]
pub struct AdminSitePage {
    pub ctx: PageCtx,
    pub nav: String,
    pub trust_granted_by: String,
    pub untrusted_tips: String,
    /// (name, display name, members, trusted)
    pub orgs: Vec<(String, String, i64, bool)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_docs_page_renders() {
        for (path, title, _) in DOC_PAGES {
            let html = docs_page(
                path,
                PageCtx::anonymous(),
                "https://cactarium.example.org".into(),
                "https://cactup.example.org/docs".into(),
            )
            .unwrap_or_else(|| panic!("/docs/{path} has no template"))
            .unwrap_or_else(|e| panic!("/docs/{path} doesn't render: {e}"))
            .0;
            assert!(html.contains(&format!("<title>{title} · Cactarium docs</title>")), "/docs/{path}");
            assert!(html.contains(r#"aria-current="page""#), "/docs/{path}");
        }
        let any = |p: &str| docs_page(p, PageCtx::anonymous(), String::new(), String::new()).is_some();
        assert!(!any("nonsense") && !any("index"));
    }
}
