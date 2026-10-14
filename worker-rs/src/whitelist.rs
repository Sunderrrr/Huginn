//! Maps named actions to fixed argv vectors. Parameters are re-validated here
//! (defense in depth) and only ever placed into a separate argv slot — never
//! concatenated into a command string. Mirrors Go `internal/whitelist`.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Mirrors the hub-side validation: a conservative identifier with no shell
/// metacharacters, suitable for things like systemd unit names.
static SAFE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$").unwrap());

#[derive(Debug, PartialEq, Eq)]
pub enum WhitelistError {
    UnknownAction(String),
    InvalidParam(&'static str),
}

impl std::fmt::Display for WhitelistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAction(a) => write!(f, "unknown action: \"{a}\""),
            Self::InvalidParam(p) => write!(f, "invalid parameter: {p}"),
        }
    }
}
impl std::error::Error for WhitelistError {}

fn build_argv(
    action: &str,
    params: &HashMap<String, String>,
) -> Option<Result<Vec<String>, WhitelistError>> {
    let argv = match action {
        "status" => Some(Ok(vec!["uname".into(), "-a".into()])),
        "metrics" => Some(Ok(vec!["cat".into(), "/proc/loadavg".into()])),
        "list_upgradable_packages" => {
            Some(Ok(vec!["apt".into(), "list".into(), "--upgradable".into()]))
        }
        "apt_upgrade" => Some(Ok(vec!["apt-get".into(), "-y".into(), "upgrade".into()])),
        "restart_service" => match params.get("service") {
            // A single, validated argv element can never break out into
            // another command.
            Some(s) if SAFE_NAME.is_match(s) => {
                Some(Ok(vec!["systemctl".into(), "restart".into(), s.clone()]))
            }
            _ => Some(Err(WhitelistError::InvalidParam("service"))),
        },
        _ => None,
    };
    argv
}

/// Returns the argv for a whitelisted action, or an error if the action is
/// unknown or its parameters are invalid.
pub fn build_argv_checked(
    action: &str,
    params: &HashMap<String, String>,
) -> Result<Vec<String>, WhitelistError> {
    match build_argv(action, params) {
        Some(r) => r,
        None => Err(WhitelistError::UnknownAction(action.to_string())),
    }
}

/// Whether an action name is whitelisted.
pub fn known(action: &str) -> bool {
    build_argv(action, &HashMap::new()).is_some()
}

/// Whether an action is safe to retry automatically: read-only actions only.
/// Mutating actions (apt_upgrade, restart_service) and free commands are
/// deliberately excluded — retrying them could double-apply a side effect.
pub fn idempotent(action: &str) -> bool {
    matches!(action, "status" | "metrics" | "list_upgradable_packages")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn known_actions_build_argv() {
        let argv = build_argv_checked("status", &HashMap::new()).unwrap();
        assert!(!argv.is_empty());
    }

    #[test]
    fn unknown_action_rejected() {
        let err = build_argv_checked("rm_rf_root", &HashMap::new()).unwrap_err();
        assert_eq!(err, WhitelistError::UnknownAction("rm_rf_root".into()));
    }

    #[test]
    fn restart_service_builds_expected_argv() {
        let argv = build_argv_checked("restart_service", &map(&[("service", "nginx")])).unwrap();
        assert_eq!(argv, vec!["systemctl", "restart", "nginx"]);
    }

    #[test]
    fn restart_service_rejects_injection() {
        for evil in [
            "nginx; reboot",
            "a b",
            "$(reboot)",
            "x`id`",
            "../../etc",
            "a|b",
            "",
            "a&b",
        ] {
            let res = build_argv_checked("restart_service", &map(&[("service", evil)]));
            assert!(res.is_err(), "expected rejection for service={evil:?}");
        }
    }

    #[test]
    fn restart_service_requires_param() {
        let err = build_argv_checked("restart_service", &HashMap::new()).unwrap_err();
        assert_eq!(err, WhitelistError::InvalidParam("service"));
    }

    #[test]
    fn known_lookup() {
        assert!(known("metrics"));
        assert!(!known("nope"));
    }
}
