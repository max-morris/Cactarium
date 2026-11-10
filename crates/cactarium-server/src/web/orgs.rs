//! Organizations: namespaces shared by their members.
//!
//! Anyone signed in can create one and becomes its owner. Owners add and remove members and make
//! other owners; every member publishes under the organization and manages its entries. An
//! organization always keeps at least one owner. Admins can manage any organization, and can create
//! one under a reserved name or a namespace that already has entries (it then adopts them, as for
//! `et`).

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use cactup_ecosystem_common::name::Owner;
use serde::Deserialize;
use serde_json::json;

use crate::audit::audit;
use crate::auth::{SignedIn, User};
use crate::error::{AppError, AppResult};
use crate::model::{ENTRY_COLS, Entry, fmt_date};
use crate::state::AppState;
use crate::templates::*;
use crate::web::public::entry_rows;

#[derive(sqlx::FromRow)]
pub struct Org {
    pub id: i64,
    pub name: String,
    pub display_name: Option<String>,
}

pub async fn find_org(state: &AppState, name: &str) -> AppResult<Option<Org>> {
    Ok(sqlx::query_as::<_, Org>("SELECT id, name, display_name FROM orgs WHERE name = $1")
        .bind(name)
        .fetch_optional(&state.db)
        .await?)
}

/// (user id, username, role, added), owners first.
pub async fn members(state: &AppState, org_id: i64) -> AppResult<Vec<(i64, String, String, String)>> {
    let rows: Vec<(i64, String, String, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT u.id, u.username, m.role, m.added_at FROM org_members m JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1 ORDER BY (m.role = 'owner') DESC, u.username",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(id, u, r, at)| (id, u, r, fmt_date(at))).collect())
}

async fn role_of(state: &AppState, org_id: i64, user_id: i64) -> AppResult<Option<String>> {
    Ok(sqlx::query_scalar("SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2")
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?)
}

/// Whether `user` manages the organization's membership: one of its owners, or an admin.
pub async fn manages(state: &AppState, org: &Org, user: &User) -> AppResult<bool> {
    Ok(user.is_admin() || role_of(state, org.id, user.id).await?.as_deref() == Some("owner"))
}

/// Creates an organization with `owner` as its first owner. Everyone may take a free name; admins
/// (and the command line, `by` = None) may also take a reserved name, or one that already has
/// entries (the org then owns them).
pub async fn create(
    state: &AppState,
    by: Option<&User>,
    name: &str,
    display: Option<&str>,
    owner: &User,
) -> AppResult<Org> {
    name.parse::<Owner>().map_err(AppError::bad)?;
    let (is_user, is_org, reserved, has_entries): (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM users WHERE username = $1), EXISTS (SELECT 1 FROM orgs WHERE name = $1),
                EXISTS (SELECT 1 FROM reserved_names WHERE name = $1), EXISTS (SELECT 1 FROM entries WHERE lower(owner) = lower($1))",
    )
    .bind(name)
    .fetch_one(&state.db)
    .await?;
    if is_user || is_org {
        return Err(AppError::Conflict(format!("'{name}' is taken")));
    }
    if (reserved || has_entries) && !by.is_none_or(User::is_admin) {
        return Err(AppError::Conflict(format!("'{name}' is reserved; ask an admin")));
    }
    let display = display.map(str::trim).filter(|d| !d.is_empty());
    let mut tx = state.db.begin().await?;
    let org = sqlx::query_as::<_, Org>("INSERT INTO orgs (name, display_name, created_by) VALUES ($1, $2, $3) RETURNING id, name, display_name")
        .bind(name)
        .bind(display)
        .bind(by.map(|b| b.id))
        .fetch_one(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(org.id)
        .bind(owner.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        state,
        by.map(|b| b.id),
        "org.create",
        Some(name),
        json!({ "owner": owner.username, "adopted_entries": has_entries }),
        None,
    )
    .await?;
    Ok(org)
}

pub async fn new_page(State(state): State<AppState>, s: SignedIn) -> AppResult<Response> {
    Ok(page(&NewOrgPage {
        ctx: PageCtx::new(&state, Some(&s.session)),
        name: String::new(),
        display: String::new(),
        error: None,
    })?
    .into_response())
}

#[derive(Deserialize)]
pub struct NewOrgForm {
    name: String,
    #[serde(default)]
    display_name: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn create_form(
    State(state): State<AppState>,
    s: SignedIn,
    Form(f): Form<NewOrgForm>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let name = f.name.trim().to_owned();
    match create(&state, Some(&s.user), &name, Some(&f.display_name), &s.user).await {
        Ok(org) => Ok(Redirect::to(&format!("/orgs/{}", org.name)).into_response()),
        Err(AppError::BadRequest(m) | AppError::Conflict(m) | AppError::Denied(m)) => {
            Ok(page(&NewOrgPage {
                ctx: PageCtx::new(&state, Some(&s.session)),
                name,
                display: f.display_name,
                error: Some(m),
            })?
            .into_response())
        }
        Err(e) => Err(e),
    }
}

pub async fn manage_page(
    State(state): State<AppState>,
    s: SignedIn,
    Path(name): Path<String>,
) -> AppResult<Response> {
    let org = find_org(&state, &name).await?.ok_or(AppError::NotFound)?;
    let role = role_of(&state, org.id, s.user.id).await?;
    if role.is_none() && !s.user.is_admin() {
        return Err(AppError::Forbidden);
    }
    let entries = sqlx::query_as::<_, Entry>(&format!(
        "SELECT {ENTRY_COLS} FROM entries WHERE owner = $1 ORDER BY kind, name"
    ))
    .bind(&org.name)
    .fetch_all(&state.db)
    .await?;
    let p = OrgPage {
        ctx: PageCtx::new(&state, Some(&s.session)),
        can_manage: manages(&state, &org, &s.user).await?,
        my_role: role.unwrap_or_default(),
        members: members(&state, org.id).await?,
        entries: entry_rows(&state, entries).await?,
        display: org.display_name.clone().unwrap_or_default(),
        name: org.name,
    };
    Ok(page(&p)?.into_response())
}

#[derive(Deserialize)]
pub struct AddMember {
    username: String,
    #[serde(default)]
    role: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn add_member(
    State(state): State<AppState>,
    s: SignedIn,
    Path(name): Path<String>,
    Form(f): Form<AddMember>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let org = find_org(&state, &name).await?.ok_or(AppError::NotFound)?;
    if !manages(&state, &org, &s.user).await? {
        return Err(AppError::Forbidden);
    }
    put_member(&state, Some(&s.user), &org, f.username.trim(), f.role == "owner").await?;
    Ok(Redirect::to(&format!("/orgs/{}", org.name)).into_response())
}

/// Adds `username` to the organization, or changes their role if they are already a member.
pub async fn put_member(
    state: &AppState,
    by: Option<&User>,
    org: &Org,
    username: &str,
    owner: bool,
) -> AppResult<()> {
    let role = if owner { "owner" } else { "member" };
    let uid: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE username = $1 AND NOT banned")
        .bind(username)
        .fetch_optional(&state.db)
        .await?;
    let uid = uid.ok_or_else(|| AppError::bad(format!("no user '{username}'")))?;
    sqlx::query("INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role")
        .bind(org.id)
        .bind(uid)
        .bind(role)
        .execute(&state.db)
        .await?;
    audit(
        state,
        by.map(|b| b.id),
        "org.member-add",
        Some(&org.name),
        json!({ "user": username, "role": role }),
        None,
    )
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct MemberAction {
    action: String,
    #[serde(rename = "_csrf")]
    csrf: String,
}

pub async fn member_action(
    State(state): State<AppState>,
    s: SignedIn,
    Path((name, uid)): Path<(String, i64)>,
    Form(f): Form<MemberAction>,
) -> AppResult<Response> {
    s.session.check_csrf(&f.csrf)?;
    let org = find_org(&state, &name).await?.ok_or(AppError::NotFound)?;
    let leaving = uid == s.user.id && f.action == "remove";
    if !leaving && !manages(&state, &org, &s.user).await? {
        return Err(AppError::Forbidden);
    }
    let owners: i64 =
        sqlx::query_scalar("SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'owner'")
            .bind(org.id)
            .fetch_one(&state.db)
            .await?;
    let target_is_owner = role_of(&state, org.id, uid).await?.as_deref() == Some("owner");
    if target_is_owner && owners == 1 && f.action != "owner" {
        return Err(AppError::bad(
            "an organization needs at least one owner; make someone else an owner first",
        ));
    }
    let sql = match f.action.as_str() {
        "remove" => "DELETE FROM org_members WHERE org_id = $1 AND user_id = $2",
        "owner" => "UPDATE org_members SET role = 'owner' WHERE org_id = $1 AND user_id = $2",
        "member" => "UPDATE org_members SET role = 'member' WHERE org_id = $1 AND user_id = $2",
        _ => return Err(AppError::bad("unknown action")),
    };
    sqlx::query(sql).bind(org.id).bind(uid).execute(&state.db).await?;
    audit(
        &state,
        Some(s.user.id),
        &format!("org.member-{}", f.action),
        Some(&org.name),
        json!({ "user_id": uid }),
        None,
    )
    .await?;
    let back = if leaving { "/settings".to_owned() } else { format!("/orgs/{}", org.name) };
    Ok(Redirect::to(&back).into_response())
}
