//! Minimal CDP (Chrome DevTools Protocol) client: one loopback WebSocket,
//! JSON-RPC with auto ids, one attached target. No SDK — the whole protocol
//! surface used here is ~8 methods, all verified against a real Obscura.

use std::time::Duration;

use base64::Engine as _;
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async_tls_with_config;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::steps::ScreenshotFormat;
use super::{truncate_chars, MAX_SCREENSHOT_B64};
use tokio::net::TcpStream;

/// Per-CDP-command timeouts.
const CMD_TIMEOUT: Duration = Duration::from_secs(30);
const NAVIGATE_TIMEOUT: Duration = Duration::from_secs(60);
const EVAL_TIMEOUT: Duration = Duration::from_secs(45);
const SCREENSHOT_TIMEOUT: Duration = Duration::from_secs(60);
/// Extra wait for the load event after `Page.navigate` answered.
const LOAD_EVENT_GRACE: Duration = Duration::from_secs(10);

/// One decoded CDP WebSocket frame: either a JSON-RPC response (matched by
/// id) or an event. Pure function over the wire bytes — unit-testable without
/// a browser.
#[derive(Debug, Clone, PartialEq)]
pub enum CdpFrame {
    Response {
        id: u64,
        result: Option<Value>,
        error: Option<String>,
    },
    Event {
        method: String,
    },
    /// Not JSON, or neither an id-carrying response nor a method-carrying
    /// event.
    Malformed,
}

/// Classify one raw CDP WebSocket text frame.
pub fn classify_cdp_frame(text: &str) -> CdpFrame {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return CdpFrame::Malformed;
    };
    if let Some(id) = value.get("id").and_then(Value::as_u64) {
        let result = value.get("result").cloned();
        let error = value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        return CdpFrame::Response { id, result, error };
    }
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return CdpFrame::Event {
            method: method.to_owned(),
        };
    }
    CdpFrame::Malformed
}

/// Minimal CDP client: one WebSocket, JSON-RPC with auto ids, one attached
/// target. No SDK — the whole protocol surface used here is ~8 methods.
pub struct CdpClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    target_id: String,
    session_id: String,
    /// Set when a `Page.loadEventFired` event was seen since the last
    /// navigation started.
    load_fired: bool,
}

impl CdpClient {
    /// Open the browser-level WebSocket, authenticating with the bearer
    /// token. The token travels in a request header and never enters an
    /// error string (tungstenite errors quote the URL, never the headers).
    pub async fn connect(url: &str, token: &str) -> Result<Self, String> {
        let mut request = url
            .into_client_request()
            .map_err(|e| format!("cdp url: {e}"))?;
        let bearer = format!("Bearer {token}");
        request
            .headers_mut()
            .insert("authorization", bearer.parse().map_err(|_| "cdp header")?);
        let (ws, _response) = connect_async_tls_with_config(request, None, true, None)
            .await
            .map_err(|e| format!("cdp connect failed: {e}"))?;
        Ok(Self {
            ws,
            next_id: 0,
            target_id: String::new(),
            session_id: String::new(),
            load_fired: false,
        })
    }

    /// Read one frame with a deadline.
    async fn read_frame(&mut self, deadline: tokio::time::Instant) -> Result<Message, String> {
        let frame = tokio::time::timeout_at(deadline, self.ws.next())
            .await
            .map_err(|_| "cdp command timed out".to_owned())?;
        match frame {
            None => Err("cdp connection closed".into()),
            Some(Ok(message)) => Ok(message),
            Some(Err(e)) => Err(format!("cdp connection error: {e}")),
        }
    }

    /// Send one browser-level command (no session) and await its response.
    async fn send_browser(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.send_raw(method, params, false, timeout).await
    }

    /// Send one session-bound command and await its response. Events seen
    /// while waiting update `load_fired`; everything else is ignored.
    async fn send_session(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.send_raw(method, params, true, timeout).await
    }

    async fn send_raw(
        &mut self,
        method: &str,
        params: Value,
        with_session: bool,
        timeout: Duration,
    ) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({ "id": id, "method": method, "params": params });
        if with_session && !self.session_id.is_empty() {
            message["sessionId"] = json!(self.session_id);
        }
        self.ws
            .send(Message::Text(message.to_string()))
            .await
            .map_err(|e| format!("cdp send failed: {e}"))?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.read_frame(deadline).await? {
                Message::Text(text) => match classify_cdp_frame(&text) {
                    CdpFrame::Response {
                        id: rid,
                        result,
                        error,
                    } if rid == id => {
                        return match error {
                            Some(error) => Err(format!("cdp {method} failed: {error}")),
                            None => Ok(result.unwrap_or(Value::Null)),
                        };
                    }
                    CdpFrame::Event { method: ref event } if event == "Page.loadEventFired" => {
                        self.load_fired = true;
                    }
                    _ => {}
                },
                Message::Close(_) => return Err("cdp connection closed".into()),
                // Pings are answered by tungstenite on the next read/write;
                // binary frames never occur on this connection.
                _ => {}
            }
        }
    }

    /// `Target.createTarget` + `Target.attachToTarget` + `Page.enable`: open
    /// a tab and bind this client to it. `url` is normally `about:blank`; the
    /// real page is reached with an explicit [`CdpClient::navigate`] step so
    /// the load event is observable.
    pub async fn create_target(&mut self, url: &str) -> Result<(), String> {
        let res = self
            .send_browser("Target.createTarget", json!({ "url": url }), CMD_TIMEOUT)
            .await?;
        self.target_id = res
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp createTarget: missing targetId".to_owned())?
            .to_owned();
        let res = self
            .send_browser(
                "Target.attachToTarget",
                json!({ "targetId": self.target_id, "flatten": true }),
                CMD_TIMEOUT,
            )
            .await?;
        self.session_id = res
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp attachToTarget: missing sessionId".to_owned())?
            .to_owned();
        // Page.enable makes the initial about:blank load events flow; they
        // are consumed (and flag `load_fired`) by the response wait.
        self.send_session("Page.enable", json!({}), CMD_TIMEOUT)
            .await?;
        Ok(())
    }

    /// `Page.navigate` + wait for the load event. Obscura only answers the
    /// navigate command after the navigation settles, so the response and
    /// the load event arrive back to back (either order).
    pub async fn navigate(&mut self, url: &str) -> Result<(), String> {
        self.load_fired = false;
        self.send_session("Page.navigate", json!({ "url": url }), NAVIGATE_TIMEOUT)
            .await?;
        let deadline = tokio::time::Instant::now() + LOAD_EVENT_GRACE;
        while !self.load_fired {
            match self.read_frame(deadline).await? {
                Message::Text(text) => match classify_cdp_frame(&text) {
                    CdpFrame::Event { method } if method == "Page.loadEventFired" => {
                        self.load_fired = true;
                    }
                    _ => {}
                },
                Message::Close(_) => return Err("cdp connection closed".into()),
                _ => {}
            }
        }
        Ok(())
    }

    /// `Runtime.evaluate` with `returnByValue`. A thrown exception becomes an
    /// error carrying the (truncated) exception text.
    pub async fn eval(&mut self, js: &str) -> Result<Value, String> {
        let res = self
            .send_session(
                "Runtime.evaluate",
                json!({ "expression": js, "returnByValue": true }),
                EVAL_TIMEOUT,
            )
            .await?;
        if let Some(details) = res.get("exceptionDetails") {
            return Err(format!("eval threw: {}", exception_text(details)));
        }
        Ok(res
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null))
    }

    /// `Page.captureScreenshot`. Obscura encodes JPEG natively (`format`
    /// jpeg/png + `quality`), so no PNG→JPEG conversion happens here; the
    /// base64 payload is validated (decodes, right magic, non-empty) and
    /// capped at [`MAX_SCREENSHOT_B64`].
    pub async fn screenshot(
        &mut self,
        format: ScreenshotFormat,
        quality: u8,
    ) -> Result<String, String> {
        let fmt = match format {
            ScreenshotFormat::Jpeg => "jpeg",
            ScreenshotFormat::Png => "png",
        };
        let mut params = json!({ "format": fmt });
        if format == ScreenshotFormat::Jpeg {
            params["quality"] = json!(quality);
        }
        let res = self
            .send_session("Page.captureScreenshot", params, SCREENSHOT_TIMEOUT)
            .await?;
        let data = res
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "cdp captureScreenshot: missing data".to_owned())?
            .to_owned();
        if data.len() > MAX_SCREENSHOT_B64 {
            return Err(format!(
                "screenshot too large ({} KiB base64, cap {} KiB)",
                data.len() / 1024,
                MAX_SCREENSHOT_B64 / 1024
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&data)
            .map_err(|e| format!("screenshot decode failed: {e}"))?;
        let ok = match format {
            ScreenshotFormat::Jpeg => bytes.starts_with(&[0xFF, 0xD8]),
            ScreenshotFormat::Png => bytes.starts_with(b"\x89PNG"),
        };
        if !ok || bytes.is_empty() {
            return Err("screenshot is not a valid image".into());
        }
        Ok(data)
    }

    /// Click the first element matching `selector` (via `Runtime.evaluate`).
    pub async fn click_selector(&mut self, selector: &str) -> Result<(), String> {
        let js = format!(
            "(function(){{var el=document.querySelector({});\
             if(!el){{return 'not-found'}};el.click();return 'ok'}})()",
            js_string(selector)
        );
        selector_result(self.eval(&js).await, selector, "click")
    }

    /// Focus `selector` and insert `text` through `Input.insertText` (the
    /// text never enters a JS string — Obscura handles the escaping).
    pub async fn type_selector(&mut self, selector: &str, text: &str) -> Result<(), String> {
        let js = format!(
            "(function(){{var el=document.querySelector({});\
             if(!el){{return 'not-found'}};el.focus();return 'ok'}})()",
            js_string(selector)
        );
        selector_result(self.eval(&js).await, selector, "focus")?;
        self.send_session("Input.insertText", json!({ "text": text }), CMD_TIMEOUT)
            .await?;
        Ok(())
    }

    /// `document.body.innerText`.
    pub async fn get_text(&mut self) -> Result<String, String> {
        self.eval("document.body ? document.body.innerText : ''")
            .await
            .and_then(value_to_string)
    }

    /// `document.documentElement.outerHTML`.
    pub async fn get_html(&mut self) -> Result<String, String> {
        self.eval("document.documentElement ? document.documentElement.outerHTML : ''")
            .await
            .and_then(value_to_string)
    }

    /// Poll `document.querySelector(sel)` every 100 ms until it exists or
    /// `timeout` elapses.
    pub async fn wait_for_selector(
        &mut self,
        selector: &str,
        timeout: Duration,
    ) -> Result<(), String> {
        let js = format!("document.querySelector({}) !== null", js_string(selector));
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.eval(&js).await? == Value::Bool(true) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!(
                    "timeout waiting for selector {}",
                    js_string(selector)
                ));
            }
            tokio::time::sleep(super::POLL_INTERVAL).await;
        }
    }

    /// `Target.closeTarget` — best effort; the process dies with the task.
    pub async fn close_target(&mut self) {
        if !self.target_id.is_empty() {
            let _ = self
                .send_browser(
                    "Target.closeTarget",
                    json!({ "targetId": self.target_id }),
                    CMD_TIMEOUT,
                )
                .await;
        }
    }
}

/// Map an eval'd `'ok' | 'not-found'` sentinel to a step result.
fn selector_result(
    value: Result<Value, String>,
    selector: &str,
    action: &str,
) -> Result<(), String> {
    match value {
        Ok(Value::String(s)) if s == "ok" => Ok(()),
        Ok(Value::String(s)) if s == "not-found" => Err(format!(
            "selector not found for {action}: {}",
            truncate_chars(selector, 120)
        )),
        Ok(_) => Err(format!("{action} failed")),
        Err(e) => Err(e),
    }
}

fn value_to_string(value: Value) -> Result<String, String> {
    match value {
        Value::String(s) => Ok(s),
        Value::Null => Ok(String::new()),
        other => Ok(other.to_string()),
    }
}

/// The exception description of a `Runtime.evaluate` failure, truncated.
fn exception_text(details: &Value) -> String {
    let text = details
        .get("exception")
        .and_then(|e| e.get("description"))
        .or_else(|| details.get("exception").and_then(|e| e.get("value")))
        .and_then(Value::as_str)
        .or_else(|| details.get("text").and_then(Value::as_str))
        .unwrap_or("unknown error");
    truncate_chars(text, 512)
}

/// Encode `s` as a JavaScript string literal. JSON string encoding is a
/// valid JS literal on every engine Obscura ships (ES2019+), and it cannot
/// be escaped out of by selector content.
pub(crate) fn js_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}
