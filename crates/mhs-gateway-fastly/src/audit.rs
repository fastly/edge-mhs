//! Structured audit events for MHS tool calls.
//!
//! Per edge-mcp's own SECURITY.md guidance (never log bearer tokens, raw
//! claims, full tool arguments, or secrets), an [`AuditEvent`] carries only a
//! hashed principal id and coarse-grained decision data — never the raw
//! subject, the tool arguments, or anything from the backend response.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// A one-way, deterministic stand-in for a principal's identity in logs.
/// Not a security boundary by itself — an operator with log access and the
/// (issuer, subject) pair could recompute it — but it keeps raw subjects out
/// of the log stream and out of any downstream system that ingests it.
pub fn hash_principal(issuer: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(issuer.as_bytes());
    hasher.update(b"|");
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();
    // Truncated: this is a log correlation id, not a security token — the
    // full 32 bytes would just bloat every log line for no benefit here.
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    /// Recorded before the proxy call, once safety and quota checks have
    /// passed — a write-ahead record that the command is about to reach the
    /// driver, independent of what the driver's response turns out to be.
    Dispatched,
    Allowed,
    DeniedSafety { field: String },
    DeniedQuota,
    /// The driver responded, but not with 2xx — distinct from [`ProxyError`](AuditDecision::ProxyError):
    /// the driver was reachable and answered, it just rejected the command.
    DeviceRejected { status: u16 },
    /// No response was obtained at all (send failure, connection reset,
    /// timeout) — whether the driver received and acted on the command
    /// before the failure is unknown.
    ProxyError,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub correlation_id: String,
    pub principal_hash: String,
    pub device_id: String,
    pub tool: String,
    pub decision: AuditDecision,
}

/// Render one audit event as a single JSON log line.
pub fn format_line(event: &AuditEvent) -> String {
    serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditError(pub String);

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit logging error: {}", self.0)
    }
}

/// Emits one audit event, reporting whether the write actually succeeded.
/// Most callers treat a failure as best-effort (an audit-pipeline outage on
/// a deny path or a post-hoc outcome record should not itself become a
/// hardware availability outage) — but the pre-dispatch `Dispatched` event is
/// the one exception: if the caller can't prove the intent to actuate was
/// logged, it must not proceed to actuate. See `DeviceToolHandler::call`.
pub trait AuditLogger {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// The real Fastly-backed logger: a named real-time log endpoint (see the
/// gateway's `fastly.toml`). A thin adapter with no independent logic — the
/// formatting it depends on ([`format_line`]) is fully covered above.
#[cfg(target_arch = "wasm32")]
pub struct FastlyLogAuditLogger {
    endpoint: fastly::log::Endpoint,
}

#[cfg(target_arch = "wasm32")]
impl FastlyLogAuditLogger {
    pub fn open(endpoint_name: &str) -> Result<Self, fastly::log::LogError> {
        Ok(FastlyLogAuditLogger { endpoint: fastly::log::Endpoint::try_from_name(endpoint_name)? })
    }
}

#[cfg(target_arch = "wasm32")]
impl AuditLogger for FastlyLogAuditLogger {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        use std::io::Write;
        // Endpoint::write emits one log line per call; clone for an owned,
        // independently writable handle (cheap — just the host handle + name).
        let mut endpoint = self.endpoint.clone();
        writeln!(endpoint, "{}", format_line(event)).map_err(|e| AuditError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn hash_principal_is_deterministic() {
        assert_eq!(hash_principal("iss", "user-1"), hash_principal("iss", "user-1"));
    }

    #[test]
    fn hash_principal_differs_for_different_subjects() {
        assert_ne!(hash_principal("iss", "user-1"), hash_principal("iss", "user-2"));
    }

    #[test]
    fn hash_principal_differs_for_different_issuers() {
        assert_ne!(hash_principal("iss-a", "user-1"), hash_principal("iss-b", "user-1"));
    }

    #[test]
    fn hash_principal_never_echoes_the_raw_subject() {
        let hashed = hash_principal("https://issuer.example.com", "user-1");
        assert_ne!(hashed, "user-1");
        assert!(!hashed.contains("user-1"));
    }

    #[test]
    fn format_line_is_valid_json_with_only_the_allowed_fields() {
        let event = AuditEvent {
            correlation_id: "corr-1".into(),
            principal_hash: hash_principal("iss", "user-1"),
            device_id: "qpcr-1".into(),
            tool: "set_temperature".into(),
            decision: AuditDecision::Allowed,
        };
        let line = format_line(&event);
        let v: Value = serde_json::from_str(&line).expect("must be valid JSON");
        let obj = v.as_object().expect("must be a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, vec!["correlation_id", "decision", "device_id", "principal_hash", "tool"]);
    }

    #[test]
    fn format_line_never_contains_a_raw_arguments_field() {
        // A regression guard: if a future edit adds "arguments" or "token" to
        // AuditEvent, this test fails the moment that field is serialized.
        let event = AuditEvent {
            correlation_id: "corr-1".into(),
            principal_hash: "deadbeef".into(),
            device_id: "qpcr-1".into(),
            tool: "set_temperature".into(),
            decision: AuditDecision::DeniedSafety { field: "celsius".into() },
        };
        let line = format_line(&event);
        assert!(!line.contains("\"arguments\""));
        assert!(!line.contains("\"token\""));
        assert!(!line.contains("\"bearer\""));
    }

    #[test]
    fn decision_variants_are_distinguishable_in_the_serialized_output() {
        let base = |d: AuditDecision| AuditEvent {
            correlation_id: "c".into(),
            principal_hash: "h".into(),
            device_id: "d".into(),
            tool: "t".into(),
            decision: d,
        };
        let dispatched = format_line(&base(AuditDecision::Dispatched));
        let allowed = format_line(&base(AuditDecision::Allowed));
        let quota = format_line(&base(AuditDecision::DeniedQuota));
        let proxy_error = format_line(&base(AuditDecision::ProxyError));
        let device_rejected = format_line(&base(AuditDecision::DeviceRejected { status: 500 }));
        let safety = format_line(&base(AuditDecision::DeniedSafety { field: "celsius".into() }));
        let all = [&dispatched, &allowed, &quota, &proxy_error, &device_rejected, &safety];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "distinct decisions must serialize distinctly");
                }
            }
        }
        assert!(safety.contains("celsius"));
    }
}
