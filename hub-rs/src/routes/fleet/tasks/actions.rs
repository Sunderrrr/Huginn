//! Action catalog (`app/core/actions.py`): the built-in actions, their
//! parameters, and the input validation shared by every task-creating route.

use std::collections::BTreeMap;

use super::super::{py_repr, py_repr_list};

// ---------------------------------------------------------------------------
// Action catalog (app/core/actions.py)
// ---------------------------------------------------------------------------

/// A conservative identifier for things like systemd unit names: letters,
/// digits and a few separators. Prevents smuggling shell metacharacters
/// through params (`actions._SAFE_NAME`).
pub fn safe_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphanumeric()) {
        return false;
    }
    value.len() <= 128
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

/// One declared action parameter (`actions.ActionParam`).
#[derive(Debug, Clone, Copy)]
pub struct ActionParam {
    pub name: &'static str,
    pub required: bool,
}

/// One whitelisted action (`actions.ActionSpec`).
#[derive(Debug, Clone, Copy)]
pub struct ActionSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub params: &'static [ActionParam],
}

const RESTART_SERVICE_PARAMS: &[ActionParam] = &[ActionParam {
    name: "service",
    required: true,
}];

/// Server-side catalog of whitelisted actions. The worker holds the
/// authoritative name → argv mapping; the hub never ships a shell string.
pub const ACTION_CATALOG: &[ActionSpec] = &[
    ActionSpec {
        name: "status",
        description: "Report worker and host status.",
        params: &[],
    },
    ActionSpec {
        name: "metrics",
        description: "Report basic host metrics (cpu/mem/disk).",
        params: &[],
    },
    ActionSpec {
        name: "restart_service",
        description: "Restart a systemd service by name.",
        params: RESTART_SERVICE_PARAMS,
    },
    ActionSpec {
        name: "list_upgradable_packages",
        description: "List packages with available upgrades.",
        params: &[],
    },
    ActionSpec {
        name: "apt_upgrade",
        description: "Apply available apt package upgrades.",
        params: &[],
    },
    ActionSpec {
        name: "update_worker",
        description: "Update the worker to the target version.",
        params: &[],
    },
];

/// Look an action up in the built-in catalog.
pub fn action_spec(name: &str) -> Option<&'static ActionSpec> {
    ACTION_CATALOG.iter().find(|spec| spec.name == name)
}

/// `actions.validate_action` — validate an action request and return the
/// normalized params. `Err` carries the exact `ActionError` message.
pub fn validate_action(
    name: &str,
    params: &BTreeMap<String, String>,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let Some(spec) = action_spec(name) else {
        return Err(format!("unknown action: {}", py_repr(name)));
    };

    let mut extra: Vec<String> = params
        .keys()
        .filter(|key| !spec.params.iter().any(|p| p.name == **key))
        .cloned()
        .collect();
    if !extra.is_empty() {
        extra.sort();
        return Err(format!(
            "unknown parameter(s) for {}: {}",
            py_repr(name),
            py_repr_list(&extra)
        ));
    }

    let mut normalized = serde_json::Map::new();
    for param in spec.params {
        let Some(value) = params.get(param.name) else {
            if param.required {
                return Err(format!(
                    "missing required parameter {} for {}",
                    py_repr(param.name),
                    py_repr(name)
                ));
            }
            continue;
        };
        if !safe_name(value) {
            return Err(format!(
                "invalid value for parameter {}",
                py_repr(param.name)
            ));
        }
        normalized.insert(
            param.name.to_owned(),
            serde_json::Value::String(value.clone()),
        );
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_action_normalizes_known_actions() {
        assert!(validate_action("status", &params(&[])).unwrap().is_empty());
        assert_eq!(
            serde_json::Value::Object(
                validate_action("restart_service", &params(&[("service", "nginx")])).unwrap()
            ),
            json!({"service": "nginx"})
        );
    }

    #[test]
    fn validate_action_error_messages_match_python() {
        assert_eq!(
            validate_action("nope", &params(&[])).unwrap_err(),
            "unknown action: 'nope'"
        );
        assert_eq!(
            validate_action("status", &params(&[("extra", "x"), ("other", "y")])).unwrap_err(),
            "unknown parameter(s) for 'status': ['extra', 'other']"
        );
        assert_eq!(
            validate_action("restart_service", &params(&[])).unwrap_err(),
            "missing required parameter 'service' for 'restart_service'"
        );
        assert_eq!(
            validate_action(
                "restart_service",
                &params(&[("service", "nginx; rm -rf /")])
            )
            .unwrap_err(),
            "invalid value for parameter 'service'"
        );
        assert_eq!(
            validate_action("restart_service", &params(&[("service", "")])).unwrap_err(),
            "invalid value for parameter 'service'"
        );
    }

    #[test]
    fn safe_name_rejects_shell_metacharacters() {
        assert!(safe_name("nginx"));
        assert!(safe_name("systemd-resolved.service"));
        assert!(safe_name("user@100.service"));
        assert!(!safe_name("-leading"));
        assert!(!safe_name("has space"));
        assert!(!safe_name("has;semicolon"));
        assert!(!safe_name(""));
        assert!(!safe_name(&"x".repeat(129)));
    }
}
