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

/// Where a `scroll` step goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollTarget {
    Top,
    Bottom,
}

/// One cookie of a `set_cookies` step.
#[derive(Debug, Clone, PartialEq)]
pub struct CookieSpec {
    pub name: String,
    pub value: String,
    /// The URL whose domain/path the cookie is scoped to (CDP `setCookie`
    /// takes a url or a domain — the url form is the least surprising).
    pub url: String,
}

/// PDF rendering options of a `pdf` step (all defaulted).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PdfOptions {
    pub landscape: bool,
    pub print_background: bool,
    /// Paper size in inches (A4 by default).
    pub paper_width: f64,
    pub paper_height: f64,
}

impl Default for PdfOptions {
    fn default() -> Self {
        Self {
            landscape: false,
            print_background: true,
            paper_width: 8.27,
            paper_height: 11.69,
        }
    }
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
    /// Press one control key (enter, tab, escape, arrows…) or a single
    /// printable character — `Input.dispatchKeyEvent`.
    PressKey {
        key: String,
    },
    /// Move the mouse over the element (`Input.dispatchMouseEvent`).
    Hover {
        selector: String,
    },
    /// Scroll the page: `selector` scrolls that element into view, `to`
    /// jumps to the top/bottom.
    Scroll {
        selector: Option<String>,
        to: Option<ScrollTarget>,
    },
    Eval {
        js: String,
    },
    /// Set the page viewport (`Emulation.setDeviceMetricsOverride`).
    SetViewport {
        width: u64,
        height: u64,
    },
    Screenshot {
        format: ScreenshotFormat,
        quality: u8,
        /// Full-page capture (`captureBeyondViewport`) — includes content
        /// below the fold.
        full_page: bool,
    },
    /// Export the page as a PDF (`Page.printToPDF`) — base64 `data:` tag.
    Pdf {
        options: PdfOptions,
    },
    GetText,
    GetHtml,
    /// The page's title (`document.title`).
    Title,
    WaitFor {
        selector: String,
        timeout_ms: u64,
    },
    /// Wait until `text` appears in the page's inner text.
    WaitForText {
        text: String,
        timeout_ms: u64,
    },
    /// List the page's cookies (`Network.getCookies`).
    GetCookies,
    /// Set cookies before/after a navigation (`Network.setCookie`).
    SetCookies {
        cookies: Vec<CookieSpec>,
    },
}

impl BrowserStep {
    /// The step's `action` label (used in output lines and error messages).
    pub fn action(&self) -> &'static str {
        match self {
            BrowserStep::Navigate { .. } => "navigate",
            BrowserStep::Click { .. } => "click",
            BrowserStep::Type { .. } => "type",
            BrowserStep::PressKey { .. } => "press_key",
            BrowserStep::Hover { .. } => "hover",
            BrowserStep::Scroll { .. } => "scroll",
            BrowserStep::Eval { .. } => "eval",
            BrowserStep::SetViewport { .. } => "set_viewport",
            BrowserStep::Screenshot { .. } => "screenshot",
            BrowserStep::Pdf { .. } => "pdf",
            BrowserStep::GetText => "get_text",
            BrowserStep::GetHtml => "get_html",
            BrowserStep::Title => "title",
            BrowserStep::WaitFor { .. } => "wait_for",
            BrowserStep::WaitForText { .. } => "wait_for_text",
            BrowserStep::GetCookies => "get_cookies",
            BrowserStep::SetCookies { .. } => "set_cookies",
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

/// Named control keys a `press_key` step accepts: (normalized name, Chrome
/// `key` name, `windowsVirtualKeyCode`) — plus a single printable ASCII
/// character, which maps to its own upper-case code point. Verified against
/// Obscura's `Input.dispatchKeyEvent`.
pub(crate) const KEY_NAMES: [(&str, &str, u16); 13] = [
    ("enter", "Enter", 13),
    ("tab", "Tab", 9),
    ("escape", "Escape", 27),
    ("backspace", "Backspace", 8),
    ("delete", "Delete", 46),
    ("home", "Home", 36),
    ("end", "End", 35),
    ("pageup", "PageUp", 33),
    ("pagedown", "PageDown", 34),
    ("arrowup", "ArrowUp", 38),
    ("arrowdown", "ArrowDown", 40),
    ("arrowleft", "ArrowLeft", 37),
    ("arrowright", "ArrowRight", 39),
];

/// Normalize + validate a `press_key` name: one of [`KEY_NAMES`], or a
/// single printable ASCII character. Returns (normalized name, Chrome key
/// name, Windows virtual-key code).
pub(crate) fn key_spec(raw: &str) -> Option<(String, String, u16)> {
    let lower = raw.to_lowercase();
    for (name, chrome, code) in KEY_NAMES {
        if lower == name {
            return Some((name.to_owned(), chrome.to_owned(), code));
        }
    }
    // A single printable ASCII character.
    let bytes = raw.as_bytes();
    if bytes.len() == 1 && (0x20..=0x7e).contains(&bytes[0]) {
        let ch = bytes[0] as char;
        let upper = ch.to_ascii_uppercase();
        return Some((ch.to_string(), ch.to_string(), upper as u16));
    }
    None
}

/// A `wait_for_text` needle is small (it is polled against innerText).
pub const MAX_WAIT_TEXT: usize = 512;
/// `set_cookies` caps: cookie count, name length, value length, and the
/// whole serialized spec (the task payload itself is capped far lower).
pub const MAX_COOKIES: usize = 20;
pub const MAX_COOKIE_NAME: usize = 256;
pub const MAX_COOKIE_VALUE: usize = 4 * 1024;
/// Viewport bounds (`Emulation.setDeviceMetricsOverride` refuses 0 anyway;
/// sane browser window sizes only).
pub const MIN_VIEWPORT: u64 = 200;
pub const MAX_VIEWPORT: u64 = 5000;
/// PDF paper size bounds (inches).
pub const MIN_PAPER: f64 = 1.0;
pub const MAX_PAPER: f64 = 100.0;

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
    let opt_len = |name: &str, value: &str, max: usize| -> Result<(), String> {
        if value.len() > max {
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
        "press_key" => {
            let key = field_str("key").unwrap_or("");
            if key.is_empty() {
                return Err(format!("step {position} press_key requires key"));
            }
            if key_spec(key).is_none() {
                return Err(format!(
                    "step {position} press_key key must be a named key \
                     (enter, tab, escape, arrows…) or a single ASCII character"
                ));
            }
            Ok(BrowserStep::PressKey { key: key.to_owned() })
        }
        "hover" => {
            let selector = field_str("selector").unwrap_or("");
            require_len("selector", selector, MAX_SELECTOR)?;
            Ok(BrowserStep::Hover {
                selector: selector.to_owned(),
            })
        }
        "scroll" => {
            let selector = field_str("selector");
            let to = field_str("to");
            // Exactly one of `selector` (into view) or `to` (top/bottom).
            match (selector, to) {
                (Some(sel), None) => {
                    opt_len("selector", sel, MAX_SELECTOR)?;
                    Ok(BrowserStep::Scroll {
                        selector: Some(sel.to_owned()),
                        to: None,
                    })
                }
                (None, Some(target)) => match target {
                    "top" => Ok(BrowserStep::Scroll {
                        selector: None,
                        to: Some(ScrollTarget::Top),
                    }),
                    "bottom" => Ok(BrowserStep::Scroll {
                        selector: None,
                        to: Some(ScrollTarget::Bottom),
                    }),
                    other => Err(format!(
                        "step {position} scroll to must be \"top\" or \"bottom\" (got {other:?})"
                    )),
                },
                (None, None) => Err(format!(
                    "step {position} scroll requires selector or to"
                )),
                (Some(_), Some(_)) => Err(format!(
                    "step {position} scroll takes either selector or to, not both"
                )),
            }
        }
        "eval" => {
            let js = field_str("js").unwrap_or("");
            require_len("js", js, MAX_STEP_JS)?;
            Ok(BrowserStep::Eval { js: js.to_owned() })
        }
        "set_viewport" => {
            let width = obj
                .get("width")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("step {position} set_viewport requires width"))?;
            let height = obj
                .get("height")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("step {position} set_viewport requires height"))?;
            if !(MIN_VIEWPORT..=MAX_VIEWPORT).contains(&width)
                || !(MIN_VIEWPORT..=MAX_VIEWPORT).contains(&height)
            {
                return Err(format!(
                    "step {position} set_viewport dimensions must be {MIN_VIEWPORT}-{MAX_VIEWPORT} pixels"
                ));
            }
            Ok(BrowserStep::SetViewport { width, height })
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
            let full_page = obj
                .get("full_page")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Ok(BrowserStep::Screenshot {
                format,
                quality,
                full_page,
            })
        }
        "pdf" => {
            let mut options = PdfOptions::default();
            if let Some(v) = obj.get("landscape").and_then(Value::as_bool) {
                options.landscape = v;
            }
            if let Some(v) = obj.get("print_background").and_then(Value::as_bool) {
                options.print_background = v;
            }
            if let Some(v) = obj.get("paper_width").and_then(Value::as_f64) {
                if !(MIN_PAPER..=MAX_PAPER).contains(&v) {
                    return Err(format!(
                        "step {position} pdf paper_width must be {MIN_PAPER}-{MAX_PAPER} inches"
                    ));
                }
                options.paper_width = v;
            }
            if let Some(v) = obj.get("paper_height").and_then(Value::as_f64) {
                if !(MIN_PAPER..=MAX_PAPER).contains(&v) {
                    return Err(format!(
                        "step {position} pdf paper_height must be {MIN_PAPER}-{MAX_PAPER} inches"
                    ));
                }
                options.paper_height = v;
            }
            Ok(BrowserStep::Pdf { options })
        }
        "get_text" => Ok(BrowserStep::GetText),
        "get_html" => Ok(BrowserStep::GetHtml),
        "title" => Ok(BrowserStep::Title),
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
        "wait_for_text" => {
            let text = field_str("text").unwrap_or("");
            require_len("text", text, MAX_WAIT_TEXT)?;
            let timeout_ms = obj
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(5_000)
                .min(MAX_WAIT_FOR_MS);
            Ok(BrowserStep::WaitForText {
                text: text.to_owned(),
                timeout_ms,
            })
        }
        "get_cookies" => Ok(BrowserStep::GetCookies),
        "set_cookies" => {
            let list = obj
                .get("cookies")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("step {position} set_cookies requires a cookies array"))?;
            if list.is_empty() || list.len() > MAX_COOKIES {
                return Err(format!(
                    "step {position} set_cookies takes 1-{MAX_COOKIES} cookies"
                ));
            }
            let mut cookies = Vec::with_capacity(list.len());
            for (ci, spec) in list.iter().enumerate() {
                let c = spec.as_object().ok_or_else(|| {
                    format!("step {position} set_cookies cookie {} must be an object", ci + 1)
                })?;
                let name = c.get("name").and_then(Value::as_str).unwrap_or("");
                let value = c.get("value").and_then(Value::as_str).unwrap_or("");
                let url = c.get("url").and_then(Value::as_str).unwrap_or("");
                require_len("name", name, MAX_COOKIE_NAME)?;
                opt_len("value", value, MAX_COOKIE_VALUE)?;
                if !navigate_url_allowed(url) {
                    return Err(format!(
                        "step {position} set_cookies cookie {} url must be http(s)://",
                        ci + 1
                    ));
                }
                cookies.push(CookieSpec {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    url: url.to_owned(),
                });
            }
            Ok(BrowserStep::SetCookies { cookies })
        }
        other => Err(format!(
            "step {position} unknown action {other:?} (expected navigate, click, type, press_key, hover, scroll, eval, set_viewport, screenshot, pdf, get_text, get_html, title, wait_for, wait_for_text, get_cookies or set_cookies)"
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
