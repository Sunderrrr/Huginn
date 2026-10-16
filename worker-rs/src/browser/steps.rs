//! Step parsing: worker-side re-validation of the hub's `browser` task
//! payload. Even though the hub validated the same rules on the create path,
//! every field is checked again here — a hostile hub must not be able to
//! smuggle a step field past the worker.

use serde_json::Value;
use std::time::Duration;

use super::{
    DEFAULT_JPEG_QUALITY, DEFAULT_TIMEOUT_SECONDS, MAX_SELECTOR, MAX_STEPS, MAX_STEP_JS,
    MAX_TIMEOUT_SECONDS, MAX_TYPE_TEXT, MAX_URL_CHARS, MAX_WAIT_FOR_MS,
};

/// Screenshot encoding requested by a `screenshot` step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenshotFormat {
    Jpeg,
    Png,
}

/// One validated browser step.
#[derive(Debug, Clone, PartialEq)]
pub enum BrowserStep {
    Navigate {
        url: String,
    },
    Click {
        selector: String,
    },
    Type {
        selector: String,
        text: String,
    },
    Eval {
        js: String,
    },
    Screenshot {
        format: ScreenshotFormat,
        quality: u8,
    },
    GetText,
    GetHtml,
    WaitFor {
        selector: String,
        timeout_ms: u64,
    },
}

impl BrowserStep {
    /// The step's `action` label (used in output lines and error messages).
    pub fn action(&self) -> &'static str {
        match self {
            BrowserStep::Navigate { .. } => "navigate",
            BrowserStep::Click { .. } => "click",
            BrowserStep::Type { .. } => "type",
            BrowserStep::Eval { .. } => "eval",
            BrowserStep::Screenshot { .. } => "screenshot",
            BrowserStep::GetText => "get_text",
            BrowserStep::GetHtml => "get_html",
            BrowserStep::WaitFor { .. } => "wait_for",
        }
    }
}

/// http(s):// only, printable ASCII, non-empty remainder, ≤
/// [`MAX_URL_CHARS`] — the same gate the hub applies; `file://` and
/// `javascript://` die here even if a hostile hub skipped its check.
pub fn navigate_url_allowed(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    if rest.is_empty() {
        return false; // scheme-only ("https://") navigates nowhere
    }
    let printable = url.chars().all(|c| ('\x21'..='\x7e').contains(&c));
    printable && url.chars().count() <= MAX_URL_CHARS
}

/// Parse and validate one step object (0-based `idx` for error messages).
fn parse_step(idx: usize, step: &Value) -> Result<BrowserStep, String> {
    let position = idx + 1;
    let obj = step
        .as_object()
        .ok_or_else(|| format!("step {position} must be a JSON object"))?;
    let action = obj
        .get("action")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| format!("step {position} has no action"))?;

    let field_str = |name: &str| obj.get(name).and_then(Value::as_str);
    let require_len = |name: &str, value: &str, max: usize| -> Result<(), String> {
        if value.is_empty() {
            Err(format!("step {position} {action} requires {name}"))
        } else if value.len() > max {
            Err(format!(
                "step {position} {action} {name} exceeds {max} bytes"
            ))
        } else {
            Ok(())
        }
    };

    match action {
        "navigate" => {
            let url = field_str("url").unwrap_or("");
            if url.is_empty() {
                return Err(format!("step {position} navigate requires url"));
            }
            if !navigate_url_allowed(url) {
                return Err(format!(
                    "step {position} navigate url must be http(s):// and at most {MAX_URL_CHARS} characters"
                ));
            }
            Ok(BrowserStep::Navigate { url: url.to_owned() })
        }
        "click" => {
            let selector = field_str("selector").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            Ok(BrowserStep::Click {
                selector: selector.to_owned(),
            })
        }
        "type" => {
            let selector = field_str("selector").unwrap_or("");
            let text = field_str("text").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            if text.len() > MAX_TYPE_TEXT {
                return Err(format!(
                    "step {position} type text exceeds {MAX_TYPE_TEXT} bytes"
                ));
            }
            Ok(BrowserStep::Type {
                selector: selector.to_owned(),
                text: text.to_owned(),
            })
        }
        "eval" => {
            let js = field_str("js").unwrap_or("");
            require_len("js", js, MAX_STEP_JS)?;
            Ok(BrowserStep::Eval { js: js.to_owned() })
        }
        "screenshot" => {
            let format = match field_str("format").unwrap_or("jpeg") {
                "jpeg" => ScreenshotFormat::Jpeg,
                "png" => ScreenshotFormat::Png,
                other => {
                    return Err(format!(
                        "step {position} screenshot format must be jpeg or png (got {other:?})"
                    ))
                }
            };
            let quality = obj
                .get("quality")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_JPEG_QUALITY as u64)
                .min(100) as u8;
            Ok(BrowserStep::Screenshot { format, quality })
        }
        "get_text" => Ok(BrowserStep::GetText),
        "get_html" => Ok(BrowserStep::GetHtml),
        "wait_for" => {
            let selector = field_str("selector").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            let timeout_ms = obj
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(5_000)
                .min(MAX_WAIT_FOR_MS);
            Ok(BrowserStep::WaitFor {
                selector: selector.to_owned(),
                timeout_ms,
            })
        }
        other => Err(format!(
            "step {position} unknown action {other:?} (expected navigate, click, type, eval, screenshot, get_text, get_html or wait_for)"
        )),
    }
}

/// Parse the whole task payload: `{"steps": [...], "timeout": s}`. Validates
/// the step count (1..=MAX_STEPS) and every step (see [`parse_step`]), and
/// clamps the global timeout to 1..=[`MAX_TIMEOUT_SECONDS`] (default
/// [`DEFAULT_TIMEOUT_SECONDS`]).
pub fn parse_steps(
    payload: &serde_json::Map<String, Value>,
) -> Result<(Vec<BrowserStep>, Duration), String> {
    let steps_value = payload
        .get("steps")
        .ok_or_else(|| "browser task has no steps".to_owned())?;
    let items = steps_value
        .as_array()
        .ok_or_else(|| "steps must be a JSON array".to_owned())?;
    if items.is_empty() {
        return Err("steps must contain at least one step".into());
    }
    if items.len() > MAX_STEPS {
        return Err(format!("steps must have at most {MAX_STEPS} items"));
    }
    let steps: Vec<BrowserStep> = items
        .iter()
        .enumerate()
        .map(|(idx, step)| parse_step(idx, step))
        .collect::<Result<_, _>>()?;
    let timeout = payload
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&timeout) {
        return Err(format!(
            "timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        ));
    }
    Ok((steps, Duration::from_secs(timeout)))
}
