//! Schema-driven safety-limit evaluation for MHS device tool calls.
//!
//! A device's declared safety limits (numeric ranges, allowed enum values —
//! sourced from MHS device-discovery metadata) are evaluated against a
//! `tools/call`'s arguments *before* the call is proxied to the MHS driver
//! backend. No Fastly dependency; runs and tests on a plain host.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single field's declared safety bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Limit {
    /// A numeric field must fall within `[min, max]` inclusive.
    Range { min: f64, max: f64 },
    /// A string field must be one of `values`.
    Allowed { values: Vec<String> },
}

/// A device's declared safety limits, keyed by tool-argument field name.
/// Sourced from MHS device-discovery metadata (see `mhs-device-registry`).
///
/// `fields` is required (no `#[serde(default)]`) and unknown top-level keys
/// are rejected: a device-metadata document that doesn't match this shape
/// exactly — e.g. wire-shape drift, nesting limits under a different key —
/// must fail to parse rather than silently deserialize into an empty,
/// unintentionally permissive ruleset. An empty `fields` map is itself denied
/// by [`evaluate`] unless `unrestricted` explicitly opts in, so "the backend
/// forgot to populate real limits" and "this device genuinely has none" can
/// never be confused with each other.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceLimits {
    pub fields: BTreeMap<String, Limit>,
    /// Explicit operator acknowledgement that this device declares no
    /// bounds. Absent this, an empty `fields` map is treated as a
    /// configuration error, not permission.
    #[serde(default)]
    pub unrestricted: bool,
}

/// Why a `tools/call` was denied by the safety-policy check.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyViolation {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(PolicyViolation),
}

/// Evaluate `arguments` against `limits`. Only fields both declared in
/// `limits` and present in `arguments` are checked — a missing field is the
/// central schema validator's concern (upstream of this check), not this
/// function's. A present field whose value doesn't match the limit's
/// expected shape (e.g. a string against a `Range` limit) is denied rather
/// than skipped: fail closed on malformed input.
pub fn evaluate(limits: &DeviceLimits, arguments: &Value) -> PolicyDecision {
    if limits.fields.is_empty() && !limits.unrestricted {
        return PolicyDecision::Deny(PolicyViolation {
            field: "<no limits configured>".to_string(),
            reason: "device declares no safety limits and is not marked unrestricted".to_string(),
        });
    }
    for (field, limit) in &limits.fields {
        let Some(value) = arguments.get(field) else {
            continue;
        };
        if let Some(violation) = check(field, limit, value) {
            return PolicyDecision::Deny(violation);
        }
    }
    PolicyDecision::Allow
}

fn check(field: &str, limit: &Limit, value: &Value) -> Option<PolicyViolation> {
    match limit {
        Limit::Range { min, max } => {
            let Some(n) = value.as_f64() else {
                return Some(PolicyViolation {
                    field: field.to_string(),
                    reason: format!("expected a number in [{min}, {max}], got {value}"),
                });
            };
            if n < *min || n > *max {
                return Some(PolicyViolation {
                    field: field.to_string(),
                    reason: format!("{n} is outside the allowed range [{min}, {max}]"),
                });
            }
            None
        }
        Limit::Allowed { values } => {
            let Some(s) = value.as_str() else {
                return Some(PolicyViolation {
                    field: field.to_string(),
                    reason: format!("expected one of {values:?}, got {value}"),
                });
            };
            if !values.iter().any(|v| v == s) {
                return Some(PolicyViolation {
                    field: field.to_string(),
                    reason: format!("{s:?} is not one of the allowed values {values:?}"),
                });
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn range_limits(field: &str, min: f64, max: f64) -> DeviceLimits {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(field.to_string(), Limit::Range { min, max });
        DeviceLimits { fields, unrestricted: false }
    }

    fn allowed_limits(field: &str, values: &[&str]) -> DeviceLimits {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            field.to_string(),
            Limit::Allowed { values: values.iter().map(|s| s.to_string()).collect() },
        );
        DeviceLimits { fields, unrestricted: false }
    }

    #[test]
    fn no_limits_defined_denies_by_default() {
        // An empty ruleset must not mean "anything goes" — it can't be told
        // apart from a device-metadata backend that failed to populate real
        // limits (wire-shape drift, a bug, a truncated response). Genuinely
        // unconstrained devices must say so explicitly via `unrestricted`.
        let limits = DeviceLimits::default();
        let decision = evaluate(&limits, &json!({ "celsius": 999 }));
        match decision {
            PolicyDecision::Deny(_) => {}
            other => panic!("expected Deny for an empty, non-unrestricted ruleset, got {other:?}"),
        }
    }

    #[test]
    fn unrestricted_device_allows_despite_empty_fields() {
        let limits = DeviceLimits { fields: Default::default(), unrestricted: true };
        let decision = evaluate(&limits, &json!({ "celsius": 999999 }));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn unknown_top_level_key_fails_to_deserialize() {
        // Wire-shape drift (e.g. a metadata backend nesting limits under a
        // different key) must fail to parse rather than silently produce an
        // empty, denying-by-default-but-still-wrong ruleset.
        let result: Result<DeviceLimits, _> =
            serde_json::from_str(r#"{"limits": {"celsius": {"kind": "range", "min": 4.0, "max": 100.0}}}"#);
        assert!(result.is_err(), "an unrecognized top-level key must not deserialize");
    }

    #[test]
    fn fields_key_is_required() {
        let result: Result<DeviceLimits, _> = serde_json::from_str("{}");
        assert!(result.is_err(), "`fields` must be required, not defaulted to empty");
    }

    #[test]
    fn value_within_range_is_allowed() {
        let limits = range_limits("celsius", 4.0, 100.0);
        let decision = evaluate(&limits, &json!({ "celsius": 37.0 }));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn value_below_min_is_denied() {
        let limits = range_limits("celsius", 4.0, 100.0);
        let decision = evaluate(&limits, &json!({ "celsius": -10.0 }));
        match decision {
            PolicyDecision::Deny(v) => {
                assert_eq!(v.field, "celsius");
                assert!(v.reason.contains("4"), "reason should mention the min bound: {}", v.reason);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn value_above_max_is_denied() {
        let limits = range_limits("celsius", 4.0, 100.0);
        let decision = evaluate(&limits, &json!({ "celsius": 150.0 }));
        match decision {
            PolicyDecision::Deny(v) => {
                assert_eq!(v.field, "celsius");
                assert!(v.reason.contains("100"), "reason should mention the max bound: {}", v.reason);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn non_numeric_value_against_a_range_limit_is_denied_fail_closed() {
        let limits = range_limits("celsius", 4.0, 100.0);
        let decision = evaluate(&limits, &json!({ "celsius": "hot" }));
        match decision {
            PolicyDecision::Deny(v) => assert_eq!(v.field, "celsius"),
            other => panic!("expected fail-closed Deny for wrong type, got {other:?}"),
        }
    }

    #[test]
    fn field_absent_from_arguments_is_allowed() {
        // Presence/absence of required fields is the schema validator's job
        // (upstream, central). Safety-policy only bounds values that ARE present.
        let limits = range_limits("celsius", 4.0, 100.0);
        let decision = evaluate(&limits, &json!({ "other_field": 1 }));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn allowed_value_in_enum_limit_is_allowed() {
        let limits = allowed_limits("axis", &["x", "y", "z"]);
        let decision = evaluate(&limits, &json!({ "axis": "y" }));
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn value_outside_enum_limit_is_denied() {
        let limits = allowed_limits("axis", &["x", "y", "z"]);
        let decision = evaluate(&limits, &json!({ "axis": "w" }));
        match decision {
            PolicyDecision::Deny(v) => assert_eq!(v.field, "axis"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn first_violated_field_wins_deterministically() {
        // BTreeMap iteration order is deterministic (sorted by key), so with
        // two violated fields "axis" sorts before "celsius".
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("celsius".to_string(), Limit::Range { min: 4.0, max: 100.0 });
        fields.insert(
            "axis".to_string(),
            Limit::Allowed { values: vec!["x".into(), "y".into(), "z".into()] },
        );
        let limits = DeviceLimits { fields, unrestricted: false };
        let decision = evaluate(&limits, &json!({ "celsius": 999.0, "axis": "w" }));
        match decision {
            PolicyDecision::Deny(v) => assert_eq!(v.field, "axis"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }
}
