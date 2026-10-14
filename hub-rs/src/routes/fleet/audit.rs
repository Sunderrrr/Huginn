//! Audit log routes (`app/api/routes/audit.py`) + the chained append every
//! audited fleet action uses.
//!
//! `record()` is the only supported way to write to `audit_log`: it appends one
//! immutable entry extending the tamper-evident hash chain
//! (`row_hash = sha256(prev_hash || canonical(fields))`), serialized by the
//! transaction-level advisory lock exactly like `app/core/audit.record`.
//! `GET /api/audit/verify` recomputes the whole chain with
//! `security::audit::verify_chain`.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::DbError;
use crate::error::ApiError;
use crate::models::audit::{self, AuditLog, AuditNew};
use crate::models::enums::ActorType;
use crate::security::audit::{compute_row_hash, verify_chain as verify_entries, AuditEntry};

use super::{
    client_ip, db_err, map_path_rejection, require_admin, require_operator, ts, FleetState,
    RouteError,
};

/// Append one audit entry, extending the hash chain.
///
/// The hash is computed inside `models::audit::append_chained`'s advisory-lock
/// transaction, so concurrent appends cannot fork the chain (parity with
/// `app/core/audit.record`).
pub async fn record(pool: &sqlx::PgPool, new: AuditNew) -> Result<AuditLog, DbError> {
    audit::append_chained(pool, new, |entry, prev_hash| {
        (
            prev_hash.to_owned(),
            compute_row_hash(prev_hash, &entry.hash_fields()),
        )
    })
    .await
}

/// Recompute every row hash over the persisted chain and report whether it is
/// intact (`audit_core.verify_chain`).
pub async fn verify_chain(pool: &sqlx::PgPool) -> Result<bool, DbError> {
    let rows = audit::get_all_ordered(pool).await?;
    let entries: Vec<AuditEntry> = rows
        .iter()
        .map(|row| AuditEntry {
            prev_hash: row.prev_hash.clone(),
            row_hash: row.row_hash.clone(),
            fields: hash_fields_of(row),
        })
        .collect();
    Ok(verify_entries(&entries))
}

/// The exact dict a row commits to — the same fields `AuditNew::hash_fields`
/// hashes at write time.
fn hash_fields_of(row: &AuditLog) -> serde_json::Value {
    AuditNew {
        actor_type: row.actor_type,
        actor_id: row.actor_id.clone(),
        event_type: row.event_type.clone(),
        vm_id: row.vm_id,
        action_name: row.action_name.clone(),
        command: row.command.clone(),
        result_status: row.result_status.clone(),
        exit_code: row.exit_code,
        detail: row.detail.clone(),
        source_ip: row.source_ip.clone(),
    }
    .hash_fields()
}

// ---------------------------------------------------------------------------
// Wire shape (app/schemas/audit.py)
// ---------------------------------------------------------------------------

/// `AuditEntryOut`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntryOut {
    pub id: i64,
    #[serde(with = "ts")]
    pub ts: DateTime<Utc>,
    pub actor_type: ActorType,
    pub actor_id: String,
    /// Human-friendly actor: username for users, "mcp · <username>" for the
    /// agent, else the raw id.
    pub actor_label: Option<String>,
    pub event_type: String,
    pub vm_id: Option<Uuid>,
    pub action_name: Option<String>,
    pub command: Option<String>,
    pub result_status: Option<String>,
    pub exit_code: Option<i32>,
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
}

/// `audit._label_for` — human-friendly actor label for an audit row.
fn label_for(row: &AuditLog, usernames: &HashMap<Uuid, String>) -> String {
    match row.actor_type {
        // MCP on-behalf-of: actor_id is the user's UUID → "mcp · <username>".
        ActorType::Agent => match Uuid::parse_str(&row.actor_id)
            .ok()
            .and_then(|id| usernames.get(&id))
        {
            Some(username) => format!("mcp · {username}"),
            None => "mcp".to_owned(),
        },
        ActorType::User => Uuid::parse_str(&row.actor_id)
            .ok()
            .and_then(|id| usernames.get(&id))
            .cloned()
            .unwrap_or_else(|| row.actor_id.clone()),
        // System events: login_failed records the attempted username as actor_id.
        ActorType::System => row.actor_id.clone(),
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `/api/audit` router.
pub fn router(state: FleetState) -> Router {
    Router::new()
        .route("/api/audit", get(list_audit))
        .route("/api/audit/verify", get(verify_audit))
        .with_state(state)
}

/// Query for `GET /api/audit`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListAuditQuery {
    #[serde(default)]
    pub vm_id: Option<Uuid>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

async fn list_audit(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: super::Peer,
    query: Result<Query<ListAuditQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, super::peer_addr(peer));
    let _principal = require_operator(&state, &headers, ip.as_deref()).await?;
    let Query(query) = query.map_err(map_path_rejection)?;
    if !(1..=1000).contains(&query.limit) {
        return Err(ApiError::unprocessable_entity("limit must be between 1 and 1000").into());
    }

    let rows = audit::list_filtered(
        &state.pool,
        query.vm_id,
        query.event_type.as_deref(),
        query.limit,
    )
    .await
    .map_err(db_err)?;

    // Resolve user actor_ids to usernames. Agent rows whose actor_id is a UUID
    // are MCP-on-behalf-of actions — resolved too, so the label can show
    // "mcp · <username>".
    let mut ids: Vec<Uuid> = rows
        .iter()
        .filter(|row| matches!(row.actor_type, ActorType::User | ActorType::Agent))
        .filter_map(|row| Uuid::parse_str(&row.actor_id).ok())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut usernames: HashMap<Uuid, String> = HashMap::new();
    for id in ids {
        match crate::models::user::get_by_id(&state.pool, id).await {
            Ok(Some(user)) => {
                usernames.insert(id, user.username);
            }
            Ok(None) => {}
            Err(e) => return Err(db_err(e)),
        }
    }

    let out: Vec<AuditEntryOut> = rows
        .iter()
        .map(|row| AuditEntryOut {
            id: row.id,
            ts: row.ts,
            actor_type: row.actor_type,
            actor_id: row.actor_id.clone(),
            actor_label: Some(label_for(row, &usernames)),
            event_type: row.event_type.clone(),
            vm_id: row.vm_id,
            action_name: row.action_name.clone(),
            command: row.command.clone(),
            result_status: row.result_status.clone(),
            exit_code: row.exit_code,
            detail: row.detail.clone(),
            source_ip: row.source_ip.clone(),
        })
        .collect();
    Ok(Json(out))
}

async fn verify_audit(
    State(state): State<FleetState>,
    headers: HeaderMap,
    peer: super::Peer,
) -> Result<impl IntoResponse, RouteError> {
    let ip = client_ip(&headers, &state.config, super::peer_addr(peer));
    let _principal = require_admin(&state, &headers, ip.as_deref()).await?;
    let intact = verify_chain(&state.pool).await.map_err(db_err)?;
    Ok(Json(serde_json::json!({ "intact": intact })))
}

/// Convenience builder used by the audited fleet actions.
pub fn entry(actor_type: ActorType, actor_id: &str, event_type: &str) -> AuditNew {
    AuditNew::new(actor_type, actor_id, event_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::audit::verify_chain;

    fn sample_row(event_type: &str) -> AuditNew {
        let mut new = entry(
            ActorType::User,
            "00000000-0000-0000-0000-0000000000aa",
            event_type,
        );
        new.vm_id = Some(Uuid::nil());
        new.action_name = Some("restart_service".into());
        new.detail = serde_json::json!({"service": "nginx"});
        new.source_ip = Some("10.89.19.1".into());
        new
    }

    /// Build the chained (prev_hash, row_hash) pair the writer commits to.
    fn chain(entries: &[AuditNew]) -> Vec<AuditEntry> {
        let mut prev = crate::security::audit::GENESIS_HASH.to_owned();
        entries
            .iter()
            .map(|new| {
                let row_hash = compute_row_hash(&prev, &new.hash_fields());
                let entry = AuditEntry {
                    prev_hash: prev.clone(),
                    row_hash: row_hash.clone(),
                    fields: new.hash_fields(),
                };
                prev = row_hash;
                entry
            })
            .collect()
    }

    #[test]
    fn written_chain_verifies() {
        let entries = chain(&[sample_row("approve"), sample_row("execute_action")]);
        assert!(verify_chain(&entries));
    }

    #[test]
    fn tampering_is_detected() {
        let entries = chain(&[sample_row("approve"), sample_row("execute_action")]);

        let mut rewritten = entries.clone();
        rewritten[1].fields["event_type"] = serde_json::json!("tampered");
        assert!(!verify_chain(&rewritten), "edited detail breaks the hash");

        let mut relinked = entries.clone();
        relinked[1].prev_hash = "1".repeat(64);
        assert!(!verify_chain(&relinked), "unlinked rows break the chain");

        let mut dropped = entries.clone();
        dropped.remove(0);
        assert!(
            !verify_chain(&dropped),
            "dropping the head breaks the chain"
        );
    }

    #[test]
    fn row_hash_of_a_loaded_row_matches_its_write_time_hash() {
        // `verify_chain` rebuilds the hashed dict from a persisted row: it must
        // be byte-identical to the one `record()` hashed.
        let new = sample_row("execute_command");
        let mut row = AuditLog {
            id: 7,
            ts: Utc::now(),
            actor_type: new.actor_type,
            actor_id: new.actor_id.clone(),
            event_type: new.event_type.clone(),
            vm_id: new.vm_id,
            action_name: new.action_name.clone(),
            command: None,
            result_status: None,
            exit_code: None,
            detail: new.detail.clone(),
            source_ip: new.source_ip.clone(),
            prev_hash: crate::security::audit::GENESIS_HASH.into(),
            row_hash: String::new(),
        };
        row.row_hash = compute_row_hash(&row.prev_hash, &hash_fields_of(&row));
        assert_eq!(
            row.row_hash,
            compute_row_hash(crate::security::audit::GENESIS_HASH, &new.hash_fields())
        );
    }

    #[test]
    fn entry_out_matches_the_python_schema() {
        let new = sample_row("approve");
        let row = AuditLog {
            id: 2,
            ts: Utc::now(),
            actor_type: new.actor_type,
            actor_id: new.actor_id.clone(),
            event_type: new.event_type.clone(),
            vm_id: new.vm_id,
            action_name: new.action_name.clone(),
            command: None,
            result_status: None,
            exit_code: None,
            detail: new.detail.clone(),
            source_ip: new.source_ip.clone(),
            prev_hash: crate::security::audit::GENESIS_HASH.into(),
            row_hash: "f".repeat(64),
        };
        let mut usernames = HashMap::new();
        usernames.insert(Uuid::parse_str(&row.actor_id).unwrap(), "admin".to_owned());
        let out = AuditEntryOut {
            id: row.id,
            ts: row.ts,
            actor_type: row.actor_type,
            actor_id: row.actor_id.clone(),
            actor_label: Some(label_for(&row, &usernames)),
            event_type: row.event_type.clone(),
            vm_id: row.vm_id,
            action_name: row.action_name.clone(),
            command: row.command.clone(),
            result_status: row.result_status.clone(),
            exit_code: row.exit_code,
            detail: row.detail.clone(),
            source_ip: row.source_ip.clone(),
        };
        let value = serde_json::to_value(&out).unwrap();
        assert_eq!(value["id"], 2);
        assert_eq!(value["actor_type"], "user");
        assert_eq!(value["actor_label"], "admin");
        assert_eq!(value["event_type"], "approve");
        assert_eq!(value["detail"]["service"], "nginx");
        assert!(value["command"].is_null());
        assert!(
            value.get("prev_hash").is_none(),
            "chain internals stay private"
        );
    }

    #[test]
    fn actor_labels_match_python() {
        let mut usernames = HashMap::new();
        let user_id = Uuid::new_v4();
        usernames.insert(user_id, "alice".to_owned());

        let mut row = AuditLog {
            id: 1,
            ts: Utc::now(),
            actor_type: ActorType::User,
            actor_id: user_id.to_string(),
            event_type: "login".into(),
            vm_id: None,
            action_name: None,
            command: None,
            result_status: None,
            exit_code: None,
            detail: serde_json::json!({}),
            source_ip: None,
            prev_hash: String::new(),
            row_hash: String::new(),
        };
        assert_eq!(label_for(&row, &usernames), "alice");

        row.actor_type = ActorType::Agent;
        assert_eq!(label_for(&row, &usernames), "mcp · alice");
        row.actor_id = Uuid::new_v4().to_string();
        assert_eq!(label_for(&row, &usernames), "mcp");
        row.actor_id = "hermes".into();
        assert_eq!(label_for(&row, &usernames), "mcp");

        row.actor_type = ActorType::System;
        row.actor_id = "someone".into();
        assert_eq!(label_for(&row, &usernames), "someone");

        row.actor_type = ActorType::User;
        assert_eq!(
            label_for(&row, &usernames),
            "someone",
            "unknown user keeps the id"
        );
    }
}
