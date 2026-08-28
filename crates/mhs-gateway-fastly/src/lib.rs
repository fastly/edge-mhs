//! Fastly Compute bindings for the MHS edge gateway.
//!
//! Each module pairs host-testable pure logic with a thin, wasm-gated
//! adapter over the actual Fastly host calls (`fastly::erl`, `fastly::log`,
//! `fastly::Request`, `fastly::kv_store`) — mirroring how `mcp-fastly` keeps
//! its JWT/JWKS verification logic host-testable while gating the KV/backend
//! calls themselves behind `#[cfg(target_arch = "wasm32")]`.

pub mod audit;
pub mod device_store;
pub mod proxy;
pub mod rate_limit;
