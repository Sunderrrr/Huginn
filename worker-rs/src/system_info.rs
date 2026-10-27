//! Small, dependency-free operating-system identity report for fleet display.

use serde_json::{json, Value};

#[cfg(target_os = "linux")]
fn system_label() -> Option<String> {
    let contents = std::fs::read_to_string("/etc/os-release").ok()?;
    parse_os_release(&contents)
}

#[cfg(windows)]
fn system_label() -> Option<String> {
    use std::process::Command;

    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let reg = std::path::Path::new(&system_root)
        .join("System32")
        .join("reg.exe");
    let output = Command::new(reg)
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let values = parse_registry_values(&String::from_utf8_lossy(&output.stdout));
    format_windows_label(
        values.get("ProductName")?,
        values.get("DisplayVersion").map(String::as_str),
        values.get("CurrentBuildNumber").map(String::as_str),
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
fn system_label() -> Option<String> {
    None
}

/// Returns stable OS family fields plus a human-readable system designation.
pub fn collect() -> Value {
    let os = crate::os_name();
    let mut info = json!({"os": os, "arch": crate::goarch()});
    if let Some(label) = system_label() {
        info["system"] = Value::String(label);
    }
    info
}

#[cfg(target_os = "linux")]
fn parse_os_release(contents: &str) -> Option<String> {
    contents
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == "PRETTY_NAME").then(|| unquote_os_release(value.trim()))
        })
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn unquote_os_release(value: &str) -> String {
    let unquoted = value
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(value);
    unquoted.replace("\\\"", "\"").replace("\\\\", "\\")
}

#[cfg(windows)]
fn parse_registry_values(output: &str) -> std::collections::HashMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let kind = fields.next()?;
            if !kind.starts_with("REG_") {
                return None;
            }
            Some((key.to_owned(), fields.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

#[cfg(windows)]
fn format_windows_label(
    product: &str,
    display_version: Option<&str>,
    build: Option<&str>,
) -> Option<String> {
    let product = product.trim();
    if product.is_empty() {
        return None;
    }
    let product = if product.starts_with("Windows 10")
        && build
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|n| n >= 22_000)
    {
        product.replacen("Windows 10", "Windows 11", 1)
    } else {
        product.to_owned()
    };
    let version = display_version.filter(|v| !v.trim().is_empty());
    let build = build.filter(|v| !v.trim().is_empty());
    match (version, build) {
        (Some(version), Some(build)) => Some(format!("{product} · {version} (build {build})")),
        (Some(version), None) => Some(format!("{product} · {version}")),
        (None, Some(build)) => Some(format!("{product} (build {build})")),
        (None, None) => Some(product),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pretty_name_is_read_from_os_release() {
        assert_eq!(
            parse_os_release("NAME=Ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\n"),
            Some("Ubuntu 24.04.2 LTS".into())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn missing_or_blank_linux_pretty_name_is_omitted() {
        assert_eq!(parse_os_release("NAME=Debian\n"), None);
        assert_eq!(parse_os_release("PRETTY_NAME=\"\""), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_registry_values_produce_windows_11_or_server_labels() {
        let values = parse_registry_values("ProductName    REG_SZ    Windows 10 Pro\r\nDisplayVersion    REG_SZ    24H2\r\nCurrentBuildNumber    REG_SZ    26100\r\n");
        assert_eq!(
            format_windows_label(
                &values["ProductName"],
                Some(&values["DisplayVersion"]),
                Some(&values["CurrentBuildNumber"])
            ),
            Some("Windows 11 Pro · 24H2 (build 26100)".into())
        );
        assert_eq!(
            format_windows_label(
                "Windows Server 2022 Datacenter",
                Some("21H2"),
                Some("20348")
            ),
            Some("Windows Server 2022 Datacenter · 21H2 (build 20348)".into())
        );
    }
}
