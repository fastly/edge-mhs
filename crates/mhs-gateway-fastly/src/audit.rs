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
    Allowed,
    DeniedSafety { field: String },
    DeniedQuota,
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

/// Emits one audit event. Implementations must not fail the request if
/// logging fails — an audit-pipeline outage should not become a hardware
/// availability outage (best-effort, matching edge-mcp's own posture on
/// non-critical side channels).
pub trait AuditLogger {
    fn record(&self, event: &AuditEvent);
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
    fn record(&self, event: &AuditEvent) {
        use std::io::Write;
        // Endpoint::write emits one log line per call; clone for an owned,
        // independently writable handle (cheap — just the host handle + name).
        let mut endpoint = self.endpoint.clone();
        let _ = writeln!(endpoint, "{}", format_line(event));
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
        let allowed = format_line(&base(AuditDecision::Allowed));
        let quota = format_line(&base(AuditDecision::DeniedQuota));
        let proxy_error = format_line(&base(AuditDecision::ProxyError));
        let safety = format_line(&base(AuditDecision::DeniedSafety { field: "celsius".into() }));
        let all = [&allowed, &quota, &proxy_error, &safety];
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
