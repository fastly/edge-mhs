//! Forwarding a validated `tools/call` to the MHS driver backend.
//!
//! Building the outbound request is pure and host-testable; actually sending
//! it is a `fastly::Request` host call, gated behind `#[cfg(target_arch =
//! "wasm32")]` like the rest of this crate's real bindings.

use serde_json::{json, Value};

/// A backend-agnostic representation of the outbound proxy call — built
/// without touching the network, so it's host-testable independent of the
/// `fastly::Request` machinery that actually sends it.
pub struct ProxyRequest {
    /// The Fastly backend name to send through (declared in `fastly.toml`).
    pub backend: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

/// Build the request that forwards one validated `tools/call` to the MHS
/// driver backend. `arguments` travels unchanged — everything upstream
/// (schema validation, safety-policy, quota) has already run by this point.
pub fn build_request(
    backend_name: &str,
    device_id: &str,
    tool: &str,
    arguments: &Value,
    correlation_id: &str,
) -> ProxyRequest {
    let body = json!({
        "device_id": device_id,
        "tool": tool,
        "arguments": arguments,
    });
    ProxyRequest {
        backend: backend_name.to_string(),
        body: serde_json::to_vec(&body).unwrap_or_default(),
        headers: vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Correlation-Id".to_string(), correlation_id.to_string()),
        ],
    }
}

#[derive(Debug, Clone)]
pub struct ProxyResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyError(pub String);

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend proxy error: {}", self.0)
    }
}

pub trait BackendProxy {
    fn forward(&self, request: &ProxyRequest) -> Result<ProxyResponse, ProxyError>;
}

/// Hard cap on a backend response body, mirroring `mcp-fastly`'s JWKS-fetch
/// size guard: bound untrusted response bodies before reading them into
/// memory, whatever the driver backend claims via `Content-Length`.
#[cfg(target_arch = "wasm32")]
const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// The real Fastly-backed proxy: a thin adapter with no independent logic —
/// what's testable ([`build_request`]) is covered above. Keep the backend's
/// connect/first-byte timeout tight at the service level so a hung driver
/// can't stall the edge request indefinitely (same guidance edge-mcp gives
/// for its `issuer_jwks` backend).
#[cfg(target_arch = "wasm32")]
pub struct FastlyBackendProxy {
    /// Absolute base URL for the MHS driver's tool-call endpoint (e.g.
    /// `https://mhs-driver.internal.example.com` in production, or
    /// `http://127.0.0.1:PORT` against a local mock under Viceroy). Kept
    /// separate from the backend *name* (`request.backend`, used for
    /// `.send()` routing) exactly like `mcp-fastly`'s `jwks_uri`/
    /// `jwks_backend` split.
    base_url: String,
}

#[cfg(target_arch = "wasm32")]
impl FastlyBackendProxy {
    pub fn new(base_url: impl Into<String>) -> Self {
        FastlyBackendProxy { base_url: base_url.into() }
    }
}

#[cfg(target_arch = "wasm32")]
impl BackendProxy for FastlyBackendProxy {
    fn forward(&self, request: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
        use std::io::Read;

        let mut out = fastly::Request::post(format!("{}/mhs/tool-call", self.base_url));
        for (k, v) in &request.headers {
            out.set_header(k.as_str(), v.as_str());
        }
        out.set_body(request.body.clone());

        let resp = out
            .send(&request.backend)
            .map_err(|e| ProxyError(format!("backend send failed: {e}")))?;
        let status = resp.get_status().as_u16();

        let mut body = Vec::new();
        resp.into_body()
            .take((MAX_RESPONSE_BYTES as u64) + 1)
            .read_to_end(&mut body)
            .map_err(|e| ProxyError(format!("backend response read failed: {e}")))?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ProxyError("backend response exceeds size cap".to_string()));
        }

        Ok(ProxyResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_targets_the_configured_backend() {
        let req = build_request("mhs_driver", "qpcr-1", "set_temperature", &json!({"celsius": 37}), "corr-1");
        assert_eq!(req.backend, "mhs_driver");
    }

    #[test]
    fn body_carries_device_tool_and_arguments_unchanged() {
        let args = json!({"celsius": 37, "nested": {"a": [1, 2, 3]}});
        let req = build_request("mhs_driver", "qpcr-1", "set_temperature", &args, "corr-1");
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["device_id"], "qpcr-1");
        assert_eq!(body["tool"], "set_temperature");
        assert_eq!(body["arguments"], args);
    }

    #[test]
    fn correlation_id_header_is_present() {
        let req = build_request("mhs_driver", "qpcr-1", "set_temperature", &json!({}), "corr-42");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "X-Correlation-Id" && v == "corr-42"));
    }

    #[test]
    fn content_type_header_is_json() {
        let req = build_request("mhs_driver", "qpcr-1", "set_temperature", &json!({}), "corr-1");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"));
    }
}
