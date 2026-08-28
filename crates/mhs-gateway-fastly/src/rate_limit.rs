//! Per-principal/device/tool quota enforcement.
//!
//! The actual rate counting happens inside Fastly's edge rate limiter host
//! call (`fastly::erl`) — there is no local state to test. What *is* worth
//! testing on the host: the composite entry key must not let two distinct
//! (principal, device, tool) triples collide into the same counter (which
//! would let one caller's traffic exhaust another's budget, or let a quota
//! configured for one tool bleed into another), and the configured window
//! must map onto one of the three windows Fastly's rate counters support.

/// Identifies the quota bucket for one `tools/call`: a specific principal
/// calling a specific tool against a specific device. An authorized caller
/// can still be throttled per-device — repeated legitimate commands can wear
/// or damage hardware, independent of whether the caller is allowed to issue
/// them at all.
pub struct QuotaKey {
    pub principal_id: String,
    pub device_id: String,
    pub tool: String,
}

/// Build the composite rate-counter entry key for a [`QuotaKey`]. Each field
/// is length-prefixed so a delimiter occurring inside a field value can never
/// shift the field boundary and collide two distinct triples onto the same
/// counter (the classic `"a" + "b|c"` vs `"a|b" + "c"` bug).
pub fn entry_key(key: &QuotaKey) -> String {
    format!(
        "{}:{}|{}:{}|{}:{}",
        key.principal_id.len(),
        key.principal_id,
        key.device_id.len(),
        key.device_id,
        key.tool.len(),
        key.tool,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateWindowKind {
    OneSec,
    TenSecs,
    SixtySecs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidWindow(pub u32);

/// The only windows Fastly's rate counters support are 1s, 10s, and 60s.
pub fn window_from_secs(secs: u32) -> Result<RateWindowKind, InvalidWindow> {
    match secs {
        1 => Ok(RateWindowKind::OneSec),
        10 => Ok(RateWindowKind::TenSecs),
        60 => Ok(RateWindowKind::SixtySecs),
        other => Err(InvalidWindow(other)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitError(pub String);

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rate limit error: {}", self.0)
    }
}

/// A per-(principal, device, tool) quota check. `Ok(true)` means the call is
/// within budget; `Ok(false)` means it exceeded `max_per_window` and must be
/// denied (the caller maps this to an HTTP 429 and an audit event).
pub trait RateLimiter {
    fn allow(
        &self,
        key: &QuotaKey,
        max_per_window: u32,
        window_secs: u32,
        penalty_ttl_secs: u64,
    ) -> Result<bool, RateLimitError>;
}

/// The real Fastly-backed limiter: a named rate counter + penalty box pair,
/// provisioned as Compute resources (see the gateway's `fastly.toml`). This
/// is a thin adapter with no independent logic — the counting itself is
/// Fastly's edge rate limiter host call, not something to unit test here.
#[cfg(target_arch = "wasm32")]
pub struct FastlyErlRateLimiter {
    erl: fastly::erl::ERL,
}

#[cfg(target_arch = "wasm32")]
impl FastlyErlRateLimiter {
    pub fn open(ratecounter_name: &str, penaltybox_name: &str) -> Self {
        let counter = fastly::erl::RateCounter::open(ratecounter_name);
        let penaltybox = fastly::erl::Penaltybox::open(penaltybox_name);
        FastlyErlRateLimiter { erl: fastly::erl::ERL::open(counter, penaltybox) }
    }
}

#[cfg(target_arch = "wasm32")]
impl RateLimiter for FastlyErlRateLimiter {
    fn allow(
        &self,
        key: &QuotaKey,
        max_per_window: u32,
        window_secs: u32,
        penalty_ttl_secs: u64,
    ) -> Result<bool, RateLimitError> {
        let window = window_from_secs(window_secs)
            .map_err(|e| RateLimitError(format!("unsupported rate window: {}s", e.0)))?;
        let fastly_window = match window {
            RateWindowKind::OneSec => fastly::erl::RateWindow::OneSec,
            RateWindowKind::TenSecs => fastly::erl::RateWindow::TenSecs,
            RateWindowKind::SixtySecs => fastly::erl::RateWindow::SixtySecs,
        };
        let blocked = self
            .erl
            .check_rate(
                &entry_key(key),
                1,
                fastly_window,
                max_per_window,
                std::time::Duration::from_secs(penalty_ttl_secs),
            )
            .map_err(|e| RateLimitError(format!("{e:?}")))?;
        Ok(!blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(principal: &str, device: &str, tool: &str) -> QuotaKey {
        QuotaKey {
            principal_id: principal.to_string(),
            device_id: device.to_string(),
            tool: tool.to_string(),
        }
    }

    #[test]
    fn same_triple_produces_the_same_entry_key() {
        let a = key("user-1", "qpcr-1", "set_temperature");
        let b = key("user-1", "qpcr-1", "set_temperature");
        assert_eq!(entry_key(&a), entry_key(&b));
    }

    #[test]
    fn different_tool_produces_a_different_entry_key() {
        let a = key("user-1", "qpcr-1", "set_temperature");
        let b = key("user-1", "qpcr-1", "read_status");
        assert_ne!(entry_key(&a), entry_key(&b));
    }

    #[test]
    fn different_device_produces_a_different_entry_key() {
        let a = key("user-1", "qpcr-1", "set_temperature");
        let b = key("user-1", "robot-arm-2", "set_temperature");
        assert_ne!(entry_key(&a), entry_key(&b));
    }

    #[test]
    fn different_principal_produces_a_different_entry_key() {
        let a = key("user-1", "qpcr-1", "set_temperature");
        let b = key("user-2", "qpcr-1", "set_temperature");
        assert_ne!(entry_key(&a), entry_key(&b));
    }

    #[test]
    fn shifting_the_delimiter_boundary_does_not_collide() {
        // Without a delimiter that survives in the field values, ("a","b|c","d")
        // and ("a|b","c","d") would naively both stringify to "a|b|c|d".
        let a = key("a", "b|c", "d");
        let b = key("a|b", "c", "d");
        assert_ne!(entry_key(&a), entry_key(&b), "boundary shift across fields must not collide");
    }

    #[test]
    fn valid_windows_map_to_erl_rate_windows() {
        assert_eq!(window_from_secs(1), Ok(RateWindowKind::OneSec));
        assert_eq!(window_from_secs(10), Ok(RateWindowKind::TenSecs));
        assert_eq!(window_from_secs(60), Ok(RateWindowKind::SixtySecs));
    }

    #[test]
    fn invalid_window_is_rejected() {
        assert!(window_from_secs(30).is_err());
        assert!(window_from_secs(0).is_err());
    }
}
