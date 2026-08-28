//! `DeviceToolHandler` — the `mcp_core::ToolHandler` that turns one MHS
//! device/tool pair into a safety-checked, quota-checked, audited proxy call
//! to the MHS driver backend. This is where every MHS-specific security
//! control introduced by this gateway lives; everything upstream of it
//! (auth, scope authorization, central schema validation) is unmodified
//! `mcp-core`/`mcp-fastly`.

use serde_json::Value;

use mcp_core::jsonrpc::RpcError;
use mcp_core::result::{CallResult, CallResultExt};
use mcp_core::router::{RequestCtx, ToolDef, ToolHandler, ToolOutcome};

use mhs_gateway_fastly::audit::{hash_principal, AuditDecision, AuditEvent, AuditLogger};
use mhs_gateway_fastly::proxy::{self, BackendProxy};
use mhs_gateway_fastly::rate_limit::{QuotaKey, RateLimiter};
use mhs_safety_policy::{evaluate, DeviceLimits, PolicyDecision};

/// Looks up a device's declared safety limits. Implemented below for
/// `mhs_device_registry::DeviceRegistry<C, S>` (any cache/source pair, so the
/// Fastly KV-backed one wires up with no extra glue); a fake stands in for
/// it in tests.
pub trait LimitsLookup {
    fn limits_for(&self, device_id: &str, now: u64) -> Result<Option<DeviceLimits>, String>;
}

impl<C, S> LimitsLookup for mhs_device_registry::DeviceRegistry<C, S>
where
    C: mhs_device_registry::LimitsCache,
    S: mhs_device_registry::LimitsSource,
{
    fn limits_for(&self, device_id: &str, now: u64) -> Result<Option<DeviceLimits>, String> {
        mhs_device_registry::DeviceRegistry::limits_for(self, device_id, now).map_err(|e| e.0)
    }
}

pub struct DeviceToolConfig {
    pub device_id: String,
    pub tool_name: String,
    pub tool_title: Option<String>,
    pub tool_description: String,
    pub input_schema: Value,
    pub required_scopes: Vec<String>,
    pub backend_name: String,
    pub max_calls_per_window: u32,
    pub window_secs: u32,
    pub penalty_ttl_secs: u64,
}

/// The `ToolHandler` for one MHS device/tool pair. Auth, scope authorization,
/// and central JSON-Schema validation of `arguments` have already run (in
/// `mcp-core::dispatch`) by the time `call` executes — this handler's job is
/// everything MHS-specific: safety-limit check, quota check, proxy, audit.
pub struct DeviceToolHandler {
    config: DeviceToolConfig,
    limits: Box<dyn LimitsLookup>,
    rate_limiter: Box<dyn RateLimiter>,
    audit: Box<dyn AuditLogger>,
    proxy: Box<dyn BackendProxy>,
}

impl DeviceToolHandler {
    pub fn new(
        config: DeviceToolConfig,
        limits: Box<dyn LimitsLookup>,
        rate_limiter: Box<dyn RateLimiter>,
        audit: Box<dyn AuditLogger>,
        proxy: Box<dyn BackendProxy>,
    ) -> Self {
        DeviceToolHandler { config, limits, rate_limiter, audit, proxy }
    }

    fn principal_ids(ctx: &RequestCtx) -> (String, String) {
        match ctx.principal() {
            Some(p) => (p.cache_scope_id(), hash_principal(&p.issuer, &p.subject)),
            None => ("anonymous".to_string(), "anonymous".to_string()),
        }
    }
}

impl ToolHandler for DeviceToolHandler {
    fn definition(&self) -> ToolDef {
        ToolDef {
            name: self.config.tool_name.clone(),
            title: self.config.tool_title.clone(),
            description: self.config.tool_description.clone(),
            input_schema: self.config.input_schema.clone(),
            output_schema: None,
        }
    }

    fn required_scopes(&self) -> Vec<String> {
        self.config.required_scopes.clone()
    }

    fn call(&self, ctx: &RequestCtx, arguments: &Value) -> Result<ToolOutcome, RpcError> {
        let now = ctx.now_unix();
        let correlation_id = mcp_core::correlation_id();
        let (principal_key, principal_hash) = Self::principal_ids(ctx);

        let audit_event = |decision: AuditDecision| AuditEvent {
            correlation_id: correlation_id.clone(),
            principal_hash: principal_hash.clone(),
            device_id: self.config.device_id.clone(),
            tool: self.config.tool_name.clone(),
            decision,
        };

        let limits = self
            .limits
            .limits_for(&self.config.device_id, now)
            .map_err(|e| RpcError::internal(format!("device registry error: {e}")))?
            .ok_or_else(|| {
                RpcError::internal(format!(
                    "no safety limits configured for device {}",
                    self.config.device_id
                ))
            })?;

        if let PolicyDecision::Deny(violation) = evaluate(&limits, arguments) {
            self.audit.record(&audit_event(AuditDecision::DeniedSafety { field: violation.field.clone() }));
            return Ok(ToolOutcome::Complete(CallResult::tool_error(format!(
                "safety policy violation on field '{}': {}",
                violation.field, violation.reason
            ))));
        }

        let quota_key = QuotaKey {
            principal_id: principal_key,
            device_id: self.config.device_id.clone(),
            tool: self.config.tool_name.clone(),
        };
        let allowed = self
            .rate_limiter
            .allow(
                &quota_key,
                self.config.max_calls_per_window,
                self.config.window_secs,
                self.config.penalty_ttl_secs,
            )
            .map_err(|e| RpcError::internal(format!("rate limiter error: {e}")))?;
        if !allowed {
            self.audit.record(&audit_event(AuditDecision::DeniedQuota));
            return Ok(ToolOutcome::Complete(CallResult::tool_error(
                "rate limit exceeded for this device/tool",
            )));
        }

        let request = proxy::build_request(
            &self.config.backend_name,
            &self.config.device_id,
            &self.config.tool_name,
            arguments,
            &correlation_id,
        );
        match self.proxy.forward(&request) {
            Ok(resp) if (200..300).contains(&resp.status) => {
                self.audit.record(&audit_event(AuditDecision::Allowed));
                Ok(ToolOutcome::Complete(CallResult::text(String::from_utf8_lossy(&resp.body).into_owned())))
            }
            Ok(resp) => {
                eprintln!("mhs backend returned status {} [{correlation_id}]", resp.status);
                self.audit.record(&audit_event(AuditDecision::ProxyError));
                Ok(ToolOutcome::Complete(CallResult::tool_error(format!(
                    "device did not accept the command (correlation id: {correlation_id})"
                ))))
            }
            Err(e) => {
                eprintln!("mhs backend proxy failed: {e} [{correlation_id}]");
                self.audit.record(&audit_event(AuditDecision::ProxyError));
                Ok(ToolOutcome::Complete(CallResult::tool_error(format!(
                    "device request failed (correlation id: {correlation_id})"
                ))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_core::meta::{keys, Meta};
    use mcp_core::router::{RequestCtx, RoutingHeaders, ToolHandler};
    use mcp_core::{Principal, PROTOCOL_VERSION};
    use mhs_gateway_fastly::audit::{AuditDecision, AuditEvent, AuditLogger};
    use mhs_gateway_fastly::proxy::{BackendProxy, ProxyError, ProxyRequest, ProxyResponse};
    use mhs_gateway_fastly::rate_limit::{QuotaKey, RateLimitError, RateLimiter};
    use mhs_safety_policy::{DeviceLimits, Limit};
    use serde_json::json;
    use std::cell::{Cell, RefCell};

    fn ctx_with(principal: Option<Principal>) -> RequestCtx {
        let meta = Meta::from_params(&json!({
            "_meta": { keys::PROTOCOL_VERSION: PROTOCOL_VERSION, keys::CLIENT_CAPABILITIES: {} }
        }));
        RequestCtx::new(meta, principal, RoutingHeaders::default()).with_now_unix(1000)
    }

    fn a_principal() -> Principal {
        Principal {
            issuer: "https://issuer.example.com".into(),
            subject: "user-1".into(),
            scopes: vec!["mcp:mhs:qpcr-1:set_temperature".into()],
            claims: Default::default(),
        }
    }

    fn celsius_limits() -> DeviceLimits {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("celsius".to_string(), Limit::Range { min: 4.0, max: 100.0 });
        DeviceLimits { fields }
    }

    struct FakeLimits {
        result: Result<Option<DeviceLimits>, String>,
    }
    impl LimitsLookup for FakeLimits {
        fn limits_for(&self, _device_id: &str, _now: u64) -> Result<Option<DeviceLimits>, String> {
            self.result.clone()
        }
    }

    struct FakeRateLimiter {
        allow: Result<bool, RateLimitError>,
        calls: Cell<u32>,
    }
    impl RateLimiter for FakeRateLimiter {
        fn allow(&self, _key: &QuotaKey, _max: u32, _window: u32, _ttl: u64) -> Result<bool, RateLimitError> {
            self.calls.set(self.calls.get() + 1);
            self.allow.clone()
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        events: RefCell<Vec<AuditEvent>>,
    }
    impl AuditLogger for FakeAudit {
        fn record(&self, event: &AuditEvent) {
            self.events.borrow_mut().push(event.clone());
        }
    }

    struct FakeProxy {
        result: Result<ProxyResponse, ProxyError>,
        calls: Cell<u32>,
    }
    impl BackendProxy for FakeProxy {
        fn forward(&self, _request: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
            self.calls.set(self.calls.get() + 1);
            self.result.clone()
        }
    }

    fn config() -> DeviceToolConfig {
        DeviceToolConfig {
            device_id: "qpcr-1".into(),
            tool_name: "set_temperature".into(),
            tool_title: Some("Set Temperature".into()),
            tool_description: "Set the qPCR block temperature.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "celsius": { "type": "number" } },
                "required": ["celsius"]
            }),
            required_scopes: vec!["mcp:mhs:qpcr-1:set_temperature".into()],
            backend_name: "mhs_driver".into(),
            max_calls_per_window: 10,
            window_secs: 60,
            penalty_ttl_secs: 60,
        }
    }

    fn handler(
        limits: Result<Option<DeviceLimits>, String>,
        rate_allow: Result<bool, RateLimitError>,
        proxy_result: Result<ProxyResponse, ProxyError>,
    ) -> (DeviceToolHandler, std::rc::Rc<FakeAudit>, std::rc::Rc<FakeProxy>, std::rc::Rc<FakeRateLimiter>) {
        let audit = std::rc::Rc::new(FakeAudit::default());
        let proxy = std::rc::Rc::new(FakeProxy { result: proxy_result, calls: Cell::new(0) });
        let rate = std::rc::Rc::new(FakeRateLimiter { allow: rate_allow, calls: Cell::new(0) });
        let h = DeviceToolHandler::new(
            config(),
            Box::new(FakeLimits { result: limits }),
            Box::new(RcRateLimiter(rate.clone())),
            Box::new(RcAudit(audit.clone())),
            Box::new(RcProxy(proxy.clone())),
        );
        (h, audit, proxy, rate)
    }

    // Thin Rc-forwarding wrappers so the test can inspect the same fake
    // instance the handler was given (Box<dyn Trait> alone can't be cloned).
    struct RcRateLimiter(std::rc::Rc<FakeRateLimiter>);
    impl RateLimiter for RcRateLimiter {
        fn allow(&self, key: &QuotaKey, max: u32, window: u32, ttl: u64) -> Result<bool, RateLimitError> {
            self.0.allow(key, max, window, ttl)
        }
    }
    struct RcAudit(std::rc::Rc<FakeAudit>);
    impl AuditLogger for RcAudit {
        fn record(&self, event: &AuditEvent) {
            self.0.record(event)
        }
    }
    struct RcProxy(std::rc::Rc<FakeProxy>);
    impl BackendProxy for RcProxy {
        fn forward(&self, request: &ProxyRequest) -> Result<ProxyResponse, ProxyError> {
            self.0.forward(request)
        }
    }

    fn ok_response(text: &str) -> Result<ProxyResponse, ProxyError> {
        Ok(ProxyResponse { status: 200, body: text.as_bytes().to_vec() })
    }

    #[test]
    fn happy_path_allows_and_proxies_and_audits_allowed() {
        let (h, audit, proxy, rate) = handler(Ok(Some(celsius_limits())), Ok(true), ok_response("ok"));
        let ctx = ctx_with(Some(a_principal()));
        let outcome = h.call(&ctx, &json!({ "celsius": 37.0 })).unwrap();
        match outcome {
            mcp_core::router::ToolOutcome::Complete(r) => {
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["isError"], false);
                assert_eq!(v["content"][0]["text"], "ok");
            }
            _ => panic!("expected Complete"),
        }
        assert_eq!(proxy.calls.get(), 1, "proxy must be called on the happy path");
        assert_eq!(rate.calls.get(), 1);
        assert_eq!(audit.events.borrow().len(), 1);
        assert!(matches!(audit.events.borrow()[0].decision, AuditDecision::Allowed));
    }

    #[test]
    fn safety_violation_denies_without_calling_proxy_or_rate_limiter() {
        let (h, audit, proxy, rate) = handler(Ok(Some(celsius_limits())), Ok(true), ok_response("ok"));
        let ctx = ctx_with(Some(a_principal()));
        let outcome = h.call(&ctx, &json!({ "celsius": 999.0 })).unwrap();
        match outcome {
            mcp_core::router::ToolOutcome::Complete(r) => {
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["isError"], true);
                assert!(v["content"][0]["text"].as_str().unwrap().contains("celsius"));
            }
            _ => panic!("expected Complete"),
        }
        assert_eq!(proxy.calls.get(), 0, "a safety-denied call must never reach the backend");
        assert_eq!(rate.calls.get(), 0, "safety check runs before the quota check");
        assert_eq!(audit.events.borrow().len(), 1);
        assert!(matches!(
            audit.events.borrow()[0].decision,
            AuditDecision::DeniedSafety { .. }
        ));
    }

    #[test]
    fn quota_exceeded_denies_without_calling_proxy() {
        let (h, audit, proxy, _rate) = handler(Ok(Some(celsius_limits())), Ok(false), ok_response("ok"));
        let ctx = ctx_with(Some(a_principal()));
        let outcome = h.call(&ctx, &json!({ "celsius": 37.0 })).unwrap();
        match outcome {
            mcp_core::router::ToolOutcome::Complete(r) => {
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["isError"], true);
            }
            _ => panic!("expected Complete"),
        }
        assert_eq!(proxy.calls.get(), 0, "a quota-denied call must never reach the backend");
        assert_eq!(audit.events.borrow().len(), 1);
        assert!(matches!(audit.events.borrow()[0].decision, AuditDecision::DeniedQuota));
    }

    #[test]
    fn proxy_error_is_reported_as_a_tool_error_without_leaking_backend_detail() {
        let (h, audit, _proxy, _rate) = handler(
            Ok(Some(celsius_limits())),
            Ok(true),
            Err(ProxyError("connection reset by upstream 10.0.0.5:9999".into())),
        );
        let ctx = ctx_with(Some(a_principal()));
        let outcome = h.call(&ctx, &json!({ "celsius": 37.0 })).unwrap();
        match outcome {
            mcp_core::router::ToolOutcome::Complete(r) => {
                let v = serde_json::to_value(&r).unwrap();
                assert_eq!(v["isError"], true);
                let text = v["content"][0]["text"].as_str().unwrap();
                assert!(!text.contains("10.0.0.5"), "must not leak raw backend error detail: {text}");
            }
            _ => panic!("expected Complete"),
        }
        assert!(matches!(audit.events.borrow()[0].decision, AuditDecision::ProxyError));
    }

    #[test]
    fn unknown_device_is_an_internal_error_not_a_tool_error() {
        let (h, _audit, proxy, _rate) = handler(Ok(None), Ok(true), ok_response("ok"));
        let ctx = ctx_with(Some(a_principal()));
        let err = match h.call(&ctx, &json!({ "celsius": 37.0 })) {
            Err(e) => e,
            Ok(_) => panic!("expected an internal RpcError for an unknown device"),
        };
        assert_eq!(err.code, mcp_core::jsonrpc::ErrorCode::INTERNAL_ERROR);
        assert_eq!(proxy.calls.get(), 0);
    }

    #[test]
    fn registry_error_is_an_internal_error() {
        let (h, _audit, _proxy, _rate) = handler(Err("kv store unavailable".into()), Ok(true), ok_response("ok"));
        let ctx = ctx_with(Some(a_principal()));
        let err = match h.call(&ctx, &json!({ "celsius": 37.0 })) {
            Err(e) => e,
            Ok(_) => panic!("expected an internal RpcError when the registry itself fails"),
        };
        assert_eq!(err.code, mcp_core::jsonrpc::ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn definition_and_required_scopes_reflect_config() {
        let (h, ..) = handler(Ok(Some(celsius_limits())), Ok(true), ok_response("ok"));
        let def = h.definition();
        assert_eq!(def.name, "set_temperature");
        assert_eq!(h.required_scopes(), vec!["mcp:mhs:qpcr-1:set_temperature".to_string()]);
    }
}
