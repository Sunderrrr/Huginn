//! `/api/actions` — port of `hub/app/api/routes/custom_actions.py` +
//! `app/services/custom_actions.py` and the built-in action catalog of
//! `app/core/actions.py`.
//!
//! A custom action is an ordered list of fixed argv vectors (one per command
//! line), each run with **no shell**. Lines are parsed/validated here
//! (`parse_command_lines`, shlex tokenization) so a definition can never carry
//! a shell or a malformed element. Names are `^[a-z0-9][a-z0-9_-]{1,63}$` and
//! may not collide with a built-in action name; `tag_ids` is the explicit
//! scope (an action with no tags runs nowhere).
//!
//! Anyone authenticated may *list* the catalog (to run it / show it in the
//! UI); only admins may create, edit or delete. Every mutation is audited.

use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use uuid::Uuid;

use super::{
    audit_record, authenticate, enforce_body_size, json_body, path_uuid, peer_addr, py_repr,
    AdminState, RouteError,
};
use crate::models::custom_action::{CustomAction, CustomActionNew, CustomActionPatch};

// ---------------------------------------------------------------------------
// Built-in action catalog (app/core/actions.py)
// ---------------------------------------------------------------------------

/// The hub-side catalog of whitelisted actions (`ACTION_CATALOG`). Only
/// `restart_service` takes a parameter (`service`, a safe unit name).
pub const ACTION_CATALOG: [(&str, &[&str]); 6] = [
    ("status", &[]),
    ("metrics", &[]),
    ("restart_service", &["service"]),
    ("list_upgradable_packages", &[]),
    ("apt_upgrade", &[]),
    ("update_worker", &[]),
];

/// `actions._SAFE_NAME` — `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`.
fn safe_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.chars().count() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

/// Is `name` a built-in action name? (Custom actions may not shadow them.)
pub fn is_builtin_action(name: &str) -> bool {
    ACTION_CATALOG.iter().any(|(n, _)| *n == name)
}

fn py_str_list(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|v| py_repr(v))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// `actions.validate_action` — validate an action request (name known, params
/// well-formed) before a task is created. Returns `Err` with the exact
/// `ActionError` message otherwise.
pub fn validate_action(name: &str, params: &BTreeMap<String, String>) -> Result<(), String> {
    let Some((_, allowed)) = ACTION_CATALOG.iter().find(|(n, _)| *n == name) else {
        return Err(format!("unknown action: {}", py_repr(name)));
    };
    let mut extra: Vec<String> = params
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()))
        .cloned()
        .collect();
    extra.sort();
    if !extra.is_empty() {
        return Err(format!(
            "unknown parameter(s) for {}: {}",
            py_repr(name),
            py_str_list(&extra)
        ));
    }
    for param in *allowed {
        match params.get(*param) {
            None => {
                return Err(format!(
                    "missing required parameter {} for {}",
                    py_repr(param),
                    py_repr(name)
                ))
            }
            Some(value) => {
                if !safe_name(value) {
                    return Err(format!("invalid value for parameter {}", py_repr(param)));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shlex (services/custom_actions.py tokenization — never a shell)
// ---------------------------------------------------------------------------

/// `shlex.split` (POSIX mode, `comments=False`): quoting is honoured (`echo "a
/// b"` → two tokens) but nothing is ever executed through a shell.
///
/// Ported state machine for `shlex.shlex.read_token` with `whitespace_split`:
/// outside quotes a backslash escapes any character (dropping the backslash);
/// inside `'…'` everything is literal; inside `"…"` only `\"` and `\\` are
/// escapes — any other `\x` keeps the backslash, exactly like CPython.
pub fn shlex_split(input: &str) -> Result<Vec<String>, String> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Space,
        Word,
        SingleQuote,
        DoubleQuote,
        /// Backslash escape: `return` is the state to resume after it.
        Escape {
            in_double_quotes: bool,
        },
    }

    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut state = State::Space;
    let mut chars = input.chars();

    loop {
        let next = chars.next();
        match state {
            State::Escape { in_double_quotes } => {
                let Some(c) = next else {
                    return Err("No escaped character".to_owned());
                };
                if in_double_quotes && c != '\\' && c != '"' {
                    // "only the quote itself or the escape character may be
                    // escaped within quotes" — the backslash stays.
                    token.push('\\');
                }
                token.push(c);
                state = if in_double_quotes {
                    State::DoubleQuote
                } else {
                    State::Word
                };
            }
            State::SingleQuote | State::DoubleQuote => {
                let quote = if state == State::SingleQuote {
                    '\''
                } else {
                    '"'
                };
                let Some(c) = next else {
                    return Err("No closing quotation".to_owned());
                };
                if c == quote {
                    state = State::Word;
                } else if c == '\\' && quote == '"' {
                    state = State::Escape {
                        in_double_quotes: true,
                    };
                } else {
                    token.push(c);
                }
            }
            State::Space => match next {
                None => break,
                Some(c) if c.is_whitespace() => continue,
                Some('\'') => {
                    quoted = true;
                    state = State::SingleQuote;
                }
                Some('"') => {
                    quoted = true;
                    state = State::DoubleQuote;
                }
                Some('\\') => {
                    state = State::Escape {
                        in_double_quotes: false,
                    }
                }
                Some(c) => {
                    token.push(c);
                    state = State::Word;
                }
            },
            State::Word => match next {
                None => break,
                Some(c) if c.is_whitespace() => {
                    tokens.push(std::mem::take(&mut token));
                    quoted = false;
                    state = State::Space;
                }
                Some('\'') => {
                    quoted = true;
                    state = State::SingleQuote;
                }
                Some('"') => {
                    quoted = true;
                    state = State::DoubleQuote;
                }
                Some('\\') => {
                    state = State::Escape {
                        in_double_quotes: false,
                    }
                }
                Some(c) => token.push(c),
            },
        }
    }

    // `echo ""` emits an empty token (quoted=True); a trailing word break does
    // not emit a spurious empty one.
    if !token.is_empty() || quoted {
        tokens.push(token);
    }
    Ok(tokens)
}

/// `shlex.quote` — the safe character set of CPython's `_find_unsafe`
/// (`[^\w@%+=:,./-]`, ASCII) decides between verbatim and `'…'`.
pub fn shlex_quote(value: &str) -> String {
    let unsafe_ = value.chars().any(|c| {
        !(c.is_ascii_alphanumeric()
            || matches!(c, '_' | '@' | '%' | '+' | '=' | ':' | ',' | '.' | '/' | '-'))
    });
    if !value.is_empty() && !unsafe_ {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// `shlex.join` — the canonical display form of an argv vector.
pub fn shlex_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shlex_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Command-line parsing (services/custom_actions.py)
// ---------------------------------------------------------------------------

const MAX_COMMANDS: usize = 32;
const MAX_ARGV: usize = 64;
const MAX_ELEM: usize = 1024;

/// `custom_actions.parse_command_lines` — parse command lines into argv
/// vectors (shlex tokenization, no shell). Each non-blank line becomes one
/// argv vector. Raises the exact Python `ValueError` messages otherwise.
pub fn parse_command_lines(lines: &[String]) -> Result<Vec<Vec<String>>, String> {
    let mut commands: Vec<Vec<String>> = Vec::new();
    for raw in lines {
        if raw.trim().is_empty() {
            continue; // skip blank lines
        }
        let argv = shlex_split(raw)
            .map_err(|e| format!("could not parse command {}: {}", py_repr(raw), e))?;
        if argv.is_empty() {
            continue;
        }
        if argv.len() > MAX_ARGV {
            return Err(format!("command has too many tokens (max {MAX_ARGV})"));
        }
        for elem in &argv {
            if elem.contains('\0') || elem.chars().count() > MAX_ELEM {
                return Err("command token contains a null byte or is too long".to_owned());
            }
        }
        commands.push(argv);
    }
    if commands.is_empty() {
        return Err("at least one command is required".to_owned());
    }
    if commands.len() > MAX_COMMANDS {
        return Err(format!("too many commands (max {MAX_COMMANDS})"));
    }
    Ok(commands)
}

/// `custom_actions.lines_of` — stored argv vectors back to canonical command
/// lines (for display).
pub fn lines_of(commands: &[Vec<String>]) -> Vec<String> {
    commands.iter().map(|argv| shlex_join(argv)).collect()
}

// ---------------------------------------------------------------------------
// Wire schemas (app/schemas/custom_action.py)
// ---------------------------------------------------------------------------

/// `CustomActionCreate`.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomActionCreate {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub commands: Vec<String>,
    pub tag_ids: Vec<Uuid>,
}

impl CustomActionCreate {
    pub fn validate(&self) -> Result<(), RouteError> {
        check_name(&self.name)?;
        check_len("description", &Some(self.description.as_str()), 255)?;
        if self.commands.is_empty() {
            return Err(RouteError::unprocessable_entity(
                "commands must contain at least 1 item",
            ));
        }
        if self.tag_ids.is_empty() {
            return Err(RouteError::unprocessable_entity(
                "tag_ids must contain at least 1 item",
            ));
        }
        Ok(())
    }
}

/// `CustomActionUpdate` — partial; `None` (absent or null) leaves the column
/// untouched (the service only applies non-null values).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CustomActionUpdate {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub commands: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub tag_ids: Option<Vec<Uuid>>,
}

impl CustomActionUpdate {
    pub fn validate(&self) -> Result<(), RouteError> {
        if let Some(description) = &self.description {
            check_len("description", &Some(description.as_str()), 255)?;
        }
        if let Some(commands) = &self.commands {
            if commands.is_empty() {
                return Err(RouteError::unprocessable_entity(
                    "commands must contain at least 1 item",
                ));
            }
        }
        if let Some(tag_ids) = &self.tag_ids {
            if tag_ids.is_empty() {
                return Err(RouteError::unprocessable_entity(
                    "tag_ids must contain at least 1 item",
                ));
            }
        }
        Ok(())
    }
}

/// `CustomActionOut`.
#[derive(Debug, Clone, Serialize)]
pub struct CustomActionOut {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// Canonical command lines (display form).
    pub commands: Vec<String>,
    /// Parsed argv vectors (what actually runs).
    pub argv: Vec<Vec<String>>,
    pub enabled: bool,
    pub tag_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl CustomActionOut {
    fn from_row(action: &CustomAction, tag_ids: Vec<Uuid>) -> Self {
        let argv = action.command_argv();
        Self {
            id: action.id,
            name: action.name.clone(),
            description: action.description.clone(),
            commands: lines_of(&argv),
            argv,
            enabled: action.enabled,
            tag_ids,
            created_at: action.created_at,
        }
    }
}

/// `schemas/custom_action.py:_check_name`.
fn check_name(name: &str) -> Result<(), RouteError> {
    let first_ok = name
        .bytes()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = name
        .chars()
        .skip(1)
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    let len_ok = (2..=64).contains(&name.chars().count());
    if !(first_ok && rest_ok && len_ok) {
        return Err(RouteError::unprocessable_entity(
            "name must be lowercase letters, digits, '-' or '_' (2-64 chars)",
        ));
    }
    if is_builtin_action(name) {
        return Err(RouteError::unprocessable_entity(format!(
            "{} is a built-in action name",
            py_repr(name)
        )));
    }
    Ok(())
}

fn check_len(field: &str, value: &Option<&str>, max: usize) -> Result<(), RouteError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.chars().count() > max {
        return Err(RouteError::unprocessable_entity(format!(
            "{field} must be at most {max} characters"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The `/api/actions` router (prefix included).
pub fn routes() -> Router<AdminState> {
    Router::new()
        .route("/api/actions", get(list_actions))
        .route("/api/actions", post(create_action))
        .route("/api/actions/{action_id}", patch(update_action))
        .route("/api/actions/{action_id}", delete(delete_action))
}

/// `GET /api/actions` — the catalog, for every authenticated principal.
async fn list_actions(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    authenticate(&state, &headers, peer_addr(peer)).await?;
    let actions = state.store.list_actions().await?;
    let mut out = Vec::with_capacity(actions.len());
    for action in &actions {
        let tag_ids = state.store.action_tag_ids(action.id).await?;
        out.push(CustomActionOut::from_row(action, tag_ids));
    }
    Ok(Json(out))
}

/// `POST /api/actions` — admin only (201).
async fn create_action(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    body: Result<Json<CustomActionCreate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let body = json_body(body)?;
    body.validate()?;
    // Service-layer parsing errors are 400 in the Python route.
    let commands = parse_command_lines(&body.commands).map_err(RouteError::bad_request)?;

    let action = state
        .store
        .create_action(CustomActionNew {
            name: body.name.clone(),
            description: body.description.clone(),
            commands: commands.clone(),
            created_by: Some(caller.principal.actor_id.clone()),
            tag_ids: body.tag_ids.clone(),
        })
        .await?;
    audit_record(
        &state,
        &caller,
        "custom_action_created",
        serde_json::json!({
            "name": action.name,
            "commands": commands,
        }),
    )
    .await?;
    let tag_ids = state.store.action_tag_ids(action.id).await?;
    Ok((
        StatusCode::CREATED,
        Json(CustomActionOut::from_row(&action, tag_ids)),
    ))
}

/// `PATCH /api/actions/{action_id}` — admin only.
async fn update_action(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(action_id): Path<String>,
    body: Result<Json<CustomActionUpdate>, axum::extract::rejection::JsonRejection>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let action_id = path_uuid(&action_id, "action id")?;
    let body = json_body(body)?;
    body.validate()?;
    let commands = match &body.commands {
        Some(lines) => Some(parse_command_lines(lines).map_err(RouteError::bad_request)?),
        None => None,
    };

    let action = state
        .store
        .update_action(
            action_id,
            CustomActionPatch {
                description: body.description.clone(),
                commands: commands.clone(),
                enabled: body.enabled,
                tag_ids: body.tag_ids.clone(),
            },
        )
        .await?;
    let Some(action) = action else {
        return Err(RouteError::not_found("action not found"));
    };
    audit_record(
        &state,
        &caller,
        "custom_action_updated",
        serde_json::json!({
            "name": action.name,
            "commands": action.command_argv(),
            "enabled": action.enabled,
        }),
    )
    .await?;
    let tag_ids = state.store.action_tag_ids(action.id).await?;
    Ok(Json(CustomActionOut::from_row(&action, tag_ids)))
}

/// `DELETE /api/actions/{action_id}` — admin only (204).
async fn delete_action(
    State(state): State<AdminState>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(action_id): Path<String>,
) -> Result<impl IntoResponse, RouteError> {
    enforce_body_size(&headers, state.global_body_cap())?;
    let caller = authenticate(&state, &headers, peer_addr(peer)).await?;
    caller.require_admin()?;
    let action_id = path_uuid(&action_id, "action id")?;

    let action = state.store.get_action(action_id).await?;
    let Some(action) = action else {
        return Err(RouteError::not_found("action not found"));
    };
    if !state.store.remove_action(action_id).await? {
        return Err(RouteError::not_found("action not found"));
    }
    audit_record(
        &state,
        &caller,
        "custom_action_deleted",
        serde_json::json!({"name": action.name}),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;

    use super::super::router;
    use super::super::testing::*;
    use super::*;
    use crate::models::user::User;
    use crate::models::UserRole;

    fn setup() -> (Arc<MockStore>, AdminState, User) {
        let store = Arc::new(MockStore::default());
        let state = test_state(store.clone());
        let admin = seed_user(&store, make_user("admin", UserRole::Admin));
        (store, state, admin)
    }

    fn auth(state: &AdminState, user: &User) -> (&'static str, String) {
        ("authorization", format!("Bearer {}", bearer(state, user)))
    }

    #[test]
    fn shlex_split_matches_cpython() {
        assert_eq!(shlex_split(r#"echo "a b""#).unwrap(), ["echo", "a b"]);
        assert_eq!(shlex_split(r"echo a\ b").unwrap(), ["echo", "a b"]);
        assert_eq!(shlex_split("echo 'it is'").unwrap(), ["echo", "it is"]);
        assert_eq!(shlex_split(r#"echo "a\tb""#).unwrap(), ["echo", r"a\tb"]);
        assert_eq!(shlex_split(r#"echo a\"b"#).unwrap(), ["echo", "a\"b"]);
        assert_eq!(shlex_split("echo ''").unwrap(), ["echo", ""]);
        assert_eq!(
            shlex_split("echo  spaced   out ").unwrap(),
            ["echo", "spaced", "out"]
        );
        assert_eq!(shlex_split("a\"b c\"d").unwrap(), ["ab cd"]);
        assert_eq!(
            shlex_split(r#"echo "back\\slash""#).unwrap(),
            ["echo", r"back\slash"]
        );
        assert!(shlex_split("").unwrap().is_empty());
        assert!(shlex_split("   ").unwrap().is_empty());

        assert_eq!(
            shlex_split("echo 'unbal").unwrap_err(),
            "No closing quotation"
        );
        assert_eq!(
            shlex_split("echo \"unbal").unwrap_err(),
            "No closing quotation"
        );
        assert_eq!(
            shlex_split("echo tail\\").unwrap_err(),
            "No escaped character"
        );
    }

    #[test]
    fn shlex_quote_and_join_match_cpython() {
        assert_eq!(shlex_quote("plain"), "plain");
        assert_eq!(shlex_quote("under_score"), "under_score");
        assert_eq!(shlex_quote("a-b_c.d,e/f@g%h+i=j"), "a-b_c.d,e/f@g%h+i=j");
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shlex_quote("a\"b"), "'a\"b'");
        assert_eq!(
            shlex_join(&["echo".into(), "a b".into(), "it's".into()]),
            "echo 'a b' 'it'\"'\"'s'"
        );
    }

    #[test]
    fn parse_command_lines_matches_the_python_service() {
        let lines = vec![
            "systemctl restart nginx".to_owned(),
            "echo \"a b\"".to_owned(),
        ];
        assert_eq!(
            parse_command_lines(&lines).unwrap(),
            vec![vec!["systemctl", "restart", "nginx"], vec!["echo", "a b"]]
        );
        // Blank lines are skipped.
        assert_eq!(
            parse_command_lines(&["  ".to_owned(), "uptime".to_owned()]).unwrap(),
            vec![vec!["uptime"]]
        );
        // Errors carry the exact Python messages.
        assert_eq!(
            parse_command_lines(&["echo 'oops".to_owned()]).unwrap_err(),
            "could not parse command \"echo 'oops\": No closing quotation"
        );
        assert_eq!(
            parse_command_lines(&["".to_owned()]).unwrap_err(),
            "at least one command is required"
        );
        let too_many = vec!["true".to_owned(); 33];
        assert_eq!(
            parse_command_lines(&too_many).unwrap_err(),
            "too many commands (max 32)"
        );
        let huge_line = vec![format!("echo {}", "x".repeat(1025))];
        assert_eq!(
            parse_command_lines(&huge_line).unwrap_err(),
            "command token contains a null byte or is too long"
        );
        // lines_of round-trips the display form.
        let commands = parse_command_lines(&["echo \"a b\"".to_owned()]).unwrap();
        assert_eq!(lines_of(&commands), vec!["echo 'a b'"]);
    }

    #[test]
    fn validate_action_matches_the_catalog() {
        let no_params = BTreeMap::new();
        assert!(validate_action("status", &no_params).is_ok());
        assert_eq!(
            validate_action("reboot", &no_params).unwrap_err(),
            "unknown action: 'reboot'"
        );

        let mut params = BTreeMap::new();
        params.insert("service".to_owned(), "nginx.service".to_owned());
        assert!(validate_action("restart_service", &params).is_ok());
        assert_eq!(
            validate_action("restart_service", &no_params).unwrap_err(),
            "missing required parameter 'service' for 'restart_service'"
        );
        params.insert("extra".to_owned(), "x".to_owned());
        assert_eq!(
            validate_action("restart_service", &params).unwrap_err(),
            "unknown parameter(s) for 'restart_service': ['extra']"
        );
        let mut bad = BTreeMap::new();
        bad.insert("service".to_owned(), "nginx; rm -rf /".to_owned());
        assert_eq!(
            validate_action("restart_service", &bad).unwrap_err(),
            "invalid value for parameter 'service'"
        );
        // Built-in names are reserved for the built-ins.
        assert!(is_builtin_action("status"));
        assert!(!is_builtin_action("restart-nginx"));
    }

    #[tokio::test]
    async fn action_lifecycle_create_list_update_delete() {
        let (store, state, admin) = setup();
        let cred = auth(&state, &admin);
        let tag_id = Uuid::new_v4();

        // Create → 201 with both display lines and argv.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/actions",
            json!({
                "name": "restart-nginx",
                "description": "restart nginx",
                "commands": ["systemctl restart nginx", "echo \"done fast\""],
                "tag_ids": [tag_id]
            }),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = body_json(response).await;
        assert_eq!(
            created["commands"],
            json!(["systemctl restart nginx", "echo 'done fast'"])
        );
        assert_eq!(
            created["argv"],
            json!([["systemctl", "restart", "nginx"], ["echo", "done fast"]])
        );
        assert_eq!(created["enabled"], json!(true));
        assert_eq!(created["tag_ids"], json!([tag_id]));
        let id = created["id"].as_str().unwrap().to_owned();

        // List (any authenticated principal) → the action.
        let app = router(state.clone());
        let request = json_request_with(
            "GET",
            "/api/actions",
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await.as_array().unwrap().len(), 1);

        // Update → disabled + new tag scope.
        let tag_id2 = Uuid::new_v4();
        let app = router(state.clone());
        let request = json_request_with(
            "PATCH",
            &format!("/api/actions/{id}"),
            json!({"enabled": false, "tag_ids": [tag_id2]}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let updated = body_json(response).await;
        assert_eq!(updated["enabled"], json!(false));
        assert_eq!(updated["tag_ids"], json!([tag_id2]));
        assert_eq!(
            updated["commands"],
            json!(["systemctl restart nginx", "echo 'done fast'"]),
            "untouched fields are preserved"
        );

        // Delete → 204, then 404.
        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/actions/{id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let app = router(state.clone());
        let request = json_request_with(
            "DELETE",
            &format!("/api/actions/{id}"),
            serde_json::Value::Null,
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "action not found"})
        );

        let db = store.db.lock().unwrap();
        let events: Vec<&str> = db.audit.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            events,
            vec![
                "custom_action_created",
                "custom_action_updated",
                "custom_action_deleted"
            ]
        );
    }

    #[tokio::test]
    async fn name_validation_rejects_bad_and_builtin_names() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);
        for (name, detail) in [
            (
                "x",
                "name must be lowercase letters, digits, '-' or '_' (2-64 chars)",
            ),
            (
                "UPPER",
                "name must be lowercase letters, digits, '-' or '_' (2-64 chars)",
            ),
            (
                "-lead",
                "name must be lowercase letters, digits, '-' or '_' (2-64 chars)",
            ),
            (
                "has space",
                "name must be lowercase letters, digits, '-' or '_' (2-64 chars)",
            ),
            ("status", "'status' is a built-in action name"),
            ("update_worker", "'update_worker' is a built-in action name"),
        ] {
            let app = router(state.clone());
            let request = json_request_with(
                "POST",
                "/api/actions",
                json!({
                    "name": name,
                    "commands": ["uptime"],
                    "tag_ids": [Uuid::new_v4()]
                }),
                std::slice::from_ref(&cred),
            );
            let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{name}"
            );
            assert_eq!(
                body_json(response).await,
                json!({"detail": detail}),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn create_requires_tags_and_valid_lines() {
        let (_store, state, admin) = setup();
        let cred = auth(&state, &admin);

        // Explicit scope: no tags → 422 (runs nowhere by design).
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/actions",
            json!({"name": "restart-nginx", "commands": ["uptime"], "tag_ids": []}),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // A malformed command line is a service error → 400.
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/actions",
            json!({
                "name": "restart-nginx",
                "commands": ["echo 'unbalanced"],
                "tag_ids": [Uuid::new_v4()]
            }),
            std::slice::from_ref(&cred),
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "could not parse command \"echo 'unbalanced\": No closing quotation"})
        );
    }

    #[tokio::test]
    async fn mutations_are_admin_only() {
        let (store, state, _admin) = setup();
        let operator = seed_user(&store, make_user("op", UserRole::Operator));
        let app = router(state.clone());
        let request = json_request_with(
            "POST",
            "/api/actions",
            json!({
                "name": "restart-nginx",
                "commands": ["uptime"],
                "tag_ids": [Uuid::new_v4()]
            }),
            &[auth(&state, &operator)],
        );
        let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_json(response).await,
            json!({"detail": "admin role required"})
        );
    }
}
