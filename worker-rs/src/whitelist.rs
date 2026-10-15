//! Maps named actions to fixed argv vectors. Parameters are re-validated here
//! (defense in depth) and only ever placed into a separate argv slot — never
//! concatenated into a command string. Mirrors Go `internal/whitelist`.
//!
//! The hub sends the same action names on every platform; the worker picks
//! this OS's argv (uname/systemctl on Linux, PowerShell on Windows). A few
//! Linux-only actions (apt-based) have no Windows equivalent and are refused
//! with a task failure — never silently mapped to something else.

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Mirrors the hub-side validation: a conservative identifier with no shell
/// (or PowerShell) metacharacters, suitable for things like systemd unit
/// names and Windows service names.
static SAFE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$").unwrap());

#[derive(Debug, PartialEq, Eq)]
pub enum WhitelistError {
    UnknownAction(String),
    InvalidParam(&'static str),
    /// The action exists but has no equivalent on this OS (e.g. apt_upgrade
    /// on Windows). Reported as a task failure — unlike an unknown action,
    /// which is treated as a hub-defined custom command.
    /// (Only constructed on the platform whose argv builders refuse it.)
    #[cfg_attr(unix, allow(dead_code))]
    UnsupportedOnOs(&'static str),
}

impl std::fmt::Display for WhitelistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAction(a) => write!(f, "unknown action: \"{a}\""),
            Self::InvalidParam(p) => write!(f, "invalid parameter: {p}"),
            Self::UnsupportedOnOs(a) => write!(f, "action \"{a}\" is not supported on this OS"),
        }
    }
}
impl std::error::Error for WhitelistError {}

fn build_argv(
    action: &str,
    params: &HashMap<String, String>,
) -> Option<Result<Vec<String>, WhitelistError>> {
    let argv = match action {
        "status" => Some(Ok(status_argv())),
        "metrics" => Some(Ok(metrics_argv())),
        "list_upgradable_packages" => Some(list_upgradable_packages_argv()),
        "apt_upgrade" => Some(apt_upgrade_argv()),
        "restart_service" => match params.get("service") {
            // A single, validated argv element can never break out into
            // another command.
            Some(s) if SAFE_NAME.is_match(s) => Some(Ok(restart_service_argv(s))),
            _ => Some(Err(WhitelistError::InvalidParam("service"))),
        },
        _ => None,
    };
    argv
}

// --- per-OS argv builders --------------------------------------------------

#[cfg(unix)]
fn status_argv() -> Vec<String> {
    vec!["uname".into(), "-a".into()]
}

#[cfg(windows)]
fn status_argv() -> Vec<String> {
    powershell_argv("Get-ComputerInfo | Select-Object WindowsVersion, OsArchitecture | Format-List")
}

#[cfg(unix)]
fn metrics_argv() -> Vec<String> {
    vec!["cat".into(), "/proc/loadavg".into()]
}

#[cfg(windows)]
fn metrics_argv() -> Vec<String> {
    powershell_argv("(Get-CimInstance Win32_Processor).LoadPercentage")
}

#[cfg(unix)]
fn list_upgradable_packages_argv() -> Result<Vec<String>, WhitelistError> {
    Ok(vec!["apt".into(), "list".into(), "--upgradable".into()])
}

#[cfg(windows)]
fn list_upgradable_packages_argv() -> Result<Vec<String>, WhitelistError> {
    // No system package manager is guaranteed present (winget is a
    // per-user Store app and may not exist); a deterministic refusal beats
    // a maybe-broken `winget upgrade`.
    Err(WhitelistError::UnsupportedOnOs("list_upgradable_packages"))
}

#[cfg(unix)]
fn apt_upgrade_argv() -> Result<Vec<String>, WhitelistError> {
    Ok(vec!["apt-get".into(), "-y".into(), "upgrade".into()])
}

#[cfg(windows)]
fn apt_upgrade_argv() -> Result<Vec<String>, WhitelistError> {
    Err(WhitelistError::UnsupportedOnOs("apt_upgrade"))
}

#[cfg(unix)]
fn restart_service_argv(service: &str) -> Vec<String> {
    vec!["systemctl".into(), "restart".into(), service.into()]
}

#[cfg(windows)]
fn restart_service_argv(service: &str) -> Vec<String> {
    // SAFE_NAME already rejected every PowerShell metacharacter (spaces,
    // ; | $ ( ) ` & …), and the command rides in a single argv element.
    powershell_argv(&format!("Restart-Service -Name {service}"))
}

#[cfg(windows)]
fn powershell_argv(command: &str) -> Vec<String> {
    // Windows PowerShell 5.1 ships with every supported Windows release, so
    // the whitelist does not depend on pwsh being installed.
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        command.into(),
    ]
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
        assert!(
            argv[0]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
            "program must be a plain binary name: {:?}",
            argv[0]
        );
    }

    #[test]
    fn unknown_action_rejected() {
        let err = build_argv_checked("rm_rf_root", &HashMap::new()).unwrap_err();
        assert_eq!(err, WhitelistError::UnknownAction("rm_rf_root".into()));
    }

    #[test]
    fn restart_service_builds_expected_argv() {
        let argv = build_argv_checked("restart_service", &map(&[("service", "nginx")])).unwrap();
        assert_eq!(argv, restart_service_argv("nginx"));
        assert!(argv.contains(&"nginx".to_string()), "service name present");
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
            "nginx;Start-Process calc",
            "a$(calc)b",
            "'quoted'",
            "\"quoted\"",
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

    // OS-support must be reported as an execution failure, NOT as "unknown
    // action" — an unknown action would fall through to hub-defined custom
    // commands.
    #[test]
    fn linux_only_actions_are_known_but_may_be_refused() {
        assert!(known("list_upgradable_packages"));
        assert!(known("apt_upgrade"));
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    #[test]
    fn status_is_uname() {
        assert_eq!(
            build_argv_checked("status", &Default::default()).unwrap(),
            vec!["uname", "-a"]
        );
    }

    #[test]
    fn metrics_is_proc_loadavg() {
        assert_eq!(
            build_argv_checked("metrics", &Default::default()).unwrap(),
            vec!["cat", "/proc/loadavg"]
        );
    }

    #[test]
    fn list_upgradable_is_apt() {
        assert_eq!(
            build_argv_checked("list_upgradable_packages", &Default::default()).unwrap(),
            vec!["apt", "list", "--upgradable"]
        );
    }

    #[test]
    fn apt_upgrade_is_apt_get() {
        assert_eq!(
            build_argv_checked("apt_upgrade", &Default::default()).unwrap(),
            vec!["apt-get", "-y", "upgrade"]
        );
    }

    #[test]
    fn restart_service_is_systemctl() {
        let argv = build_argv_checked(
            "restart_service",
            &[("service".to_string(), "nginx".to_string())]
                .into_iter()
                .collect(),
        )
        .unwrap();
        assert_eq!(argv, vec!["systemctl", "restart", "nginx"]);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn none() -> HashMap<String, String> {
        HashMap::new()
    }

    #[test]
    fn status_is_powershell_computer_info() {
        assert_eq!(
            build_argv_checked("status", &none()).unwrap(),
            vec![
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-ComputerInfo | Select-Object WindowsVersion, OsArchitecture | Format-List"
            ]
        );
    }

    #[test]
    fn metrics_is_powershell_cpu_load() {
        assert_eq!(
            build_argv_checked("metrics", &none()).unwrap(),
            vec![
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor).LoadPercentage"
            ]
        );
    }

    #[test]
    fn restart_service_is_powershell_restart_service() {
        let mut params = HashMap::new();
        params.insert("service".to_string(), "Spooler".to_string());
        assert_eq!(
            build_argv_checked("restart_service", &params).unwrap(),
            vec![
                "powershell",
                "-NoProfile",
                "-Command",
                "Restart-Service -Name Spooler"
            ]
        );
    }

    #[test]
    fn apt_actions_are_unsupported_on_windows() {
        assert_eq!(
            build_argv_checked("list_upgradable_packages", &none()).unwrap_err(),
            WhitelistError::UnsupportedOnOs("list_upgradable_packages")
        );
        assert_eq!(
            build_argv_checked("apt_upgrade", &none()).unwrap_err(),
            WhitelistError::UnsupportedOnOs("apt_upgrade")
        );
    }
}
