//! The demo MHS device/tool catalog: wires concrete Fastly-backed components
//! (`DeviceRegistry` over a KV cache + backend metadata source, the ERL rate
//! limiter, the real-time-log audit logger, the backend proxy) into
//! `DeviceToolHandler` instances and registers them on the router.
//!
//! Two devices exercise both `mhs-safety-policy` limit kinds: a qPCR
//! machine's `Range` (temperature bound) and a robot arm's `Allowed` (axis
//! enum) plus a second `Range` (angle bound).

use fastly::config_store::ConfigStore;
use mcp_core::Router;
use mhs_device_registry::DeviceRegistry;
use mhs_gateway_fastly::audit::FastlyLogAuditLogger;
use mhs_gateway_fastly::device_store::{BackendLimitsSource, KvLimitsCache};
use mhs_gateway_fastly::proxy::FastlyBackendProxy;
use mhs_gateway_fastly::rate_limit::FastlyErlRateLimiter;
use serde_json::json;

use crate::device_tool::{DeviceToolConfig, DeviceToolHandler};

/// Device-limits cache freshness: re-check the metadata backend at most this
/// often per device.
const LIMITS_MAX_AGE_SECS: u64 = 3600;

pub fn register_handlers(router: &mut Router) {
    router.with_server_info(json!({ "name": "edge-mhs", "version": "0.1.0" }));
    // Shares the "verifier" Config Store mcp-fastly's VerifierConfig already
    // reads from, rather than provisioning a second store for two strings.
    let config = ConfigStore::try_open("verifier").expect("verifier Config Store must exist");
    let registry_base_url = config
        .get("mhs_registry_base_url")
        .expect("mhs_registry_base_url must be set in the verifier Config Store");
    let driver_base_url = config
        .get("mhs_driver_base_url")
        .expect("mhs_driver_base_url must be set in the verifier Config Store");

    router
        .register_tool(qpcr_set_temperature(&registry_base_url, &driver_base_url))
        .register_tool(robot_arm_move_joint(&registry_base_url, &driver_base_url));
}

/// Both demo tools' driver acknowledgement is expected to be exactly
/// `{"status": "..."}` — closed, so an unexpected extra field in the
/// driver's response fails central output validation (mcp-core) instead of
/// being relayed into the agent's context unconstrained.
fn ack_output_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": { "status": { "type": "string" } },
        "required": ["status"],
        "additionalProperties": false
    })
}

fn registry_for(base_url: &str) -> DeviceRegistry<KvLimitsCache, BackendLimitsSource> {
    DeviceRegistry::new(
        KvLimitsCache,
        BackendLimitsSource::new("mhs_registry", base_url),
        LIMITS_MAX_AGE_SECS,
    )
}

/// `mhs_audit` real-time log endpoint must be configured on the service —
/// see `fastly.toml`. Audit logging is a security control, not best-effort
/// convenience, so a missing endpoint fails the whole server at startup
/// rather than silently running unaudited.
fn audit_logger() -> FastlyLogAuditLogger {
    FastlyLogAuditLogger::open("mhs_audit").expect("mhs_audit log endpoint must be configured")
}

fn qpcr_set_temperature(registry_base_url: &str, driver_base_url: &str) -> DeviceToolHandler {
    DeviceToolHandler::new(
        DeviceToolConfig {
            device_id: "qpcr-1".into(),
            tool_name: "set_temperature".into(),
            tool_title: Some("Set Temperature".into()),
            tool_description: "Set the qPCR block temperature, in Celsius.".into(),
            input_schema: json!({
                "type": "object",
                "properties": { "celsius": { "type": "number" } },
                "required": ["celsius"],
                "additionalProperties": false
            }),
            output_schema: ack_output_schema(),
            required_scopes: vec!["mcp:mhs:qpcr-1:set_temperature".into()],
            backend_name: "mhs_driver".into(),
            max_calls_per_window: 10,
            window_secs: 60,
            penalty_ttl_secs: 60,
        },
        Box::new(registry_for(registry_base_url)),
        Box::new(FastlyErlRateLimiter::open("mhs_rate_counter", "mhs_penalty_box")),
        Box::new(audit_logger()),
        Box::new(FastlyBackendProxy::new(driver_base_url)),
    )
}

fn robot_arm_move_joint(registry_base_url: &str, driver_base_url: &str) -> DeviceToolHandler {
    DeviceToolHandler::new(
        DeviceToolConfig {
            device_id: "robot-arm-2".into(),
            tool_name: "move_joint".into(),
            tool_title: Some("Move Joint".into()),
            tool_description: "Move one joint of the robot arm to an angle, in degrees.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "axis": { "type": "string" },
                    "angle_degrees": { "type": "number" }
                },
                "required": ["axis", "angle_degrees"],
                "additionalProperties": false
            }),
            output_schema: ack_output_schema(),
            required_scopes: vec!["mcp:mhs:robot-arm-2:move_joint".into()],
            backend_name: "mhs_driver".into(),
            max_calls_per_window: 5,
            window_secs: 10,
            penalty_ttl_secs: 300,
        },
        Box::new(registry_for(registry_base_url)),
        Box::new(FastlyErlRateLimiter::open("mhs_rate_counter", "mhs_penalty_box")),
        Box::new(audit_logger()),
        Box::new(FastlyBackendProxy::new(driver_base_url)),
    )
}
