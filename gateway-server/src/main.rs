#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
mod device_tool;
#[cfg(target_arch = "wasm32")]
mod tools;

#[cfg(target_arch = "wasm32")]
fn main() {
    use mcp_core::Router;

    let req = fastly::Request::from_client();

    // Fail CLOSED on config-load failure — same posture as edge-mcp's
    // example-server: a Config Store outage must not silently disable auth.
    let config = match mcp_fastly::stores::load_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("config load failed: {e}");
            return fastly::Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE)
                .with_body("configuration unavailable")
                .send_to_client();
        }
    };

    let mut router = Router::new();
    tools::register_handlers(&mut router);

    // Fail closed if any tool advertises a schema keyword the central
    // validator doesn't enforce (CMCP-010, inherited from edge-mcp).
    if let Err(e) = router.validate_registered_schemas() {
        eprintln!("schema registration error: {e}");
        return fastly::Response::from_status(fastly::http::StatusCode::SERVICE_UNAVAILABLE)
            .with_body("server misconfigured")
            .send_to_client();
    }

    match mcp_fastly::stores::load_signer() {
        Ok(signer) => {
            router.with_signer(Box::new(signer));
        }
        Err(e) => {
            eprintln!("warning: no token signer configured ({e}); MRTR/Tasks disabled");
        }
    }
    router.with_task_store(Box::new(mcp_fastly::kv_tasks::KvTaskStore::new()));
    router.with_idempotency_store(Box::new(mcp_fastly::kv_idempotency::KvIdempotencyStore::new()));

    mcp_fastly::adapter::serve(&router, &config, req).send_to_client();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!(
        "gateway-server is a Fastly Compute program. Build it with:\n  \
         cargo build --release --target wasm32-wasip1 --package gateway-server\n\
         The DeviceToolHandler logic is covered by `cargo test`."
    );
}
