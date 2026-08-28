# edge-mhs-interlock

An **edge security gateway on [Fastly Compute](https://www.fastly.com/products/compute)
for [Model Hardware Standard](https://www.anthropic.com/news/model-hardware-standard-research-preview)
(MHS) device control over MCP** — forked and extended from
[`fastly/edge-mcp`](https://github.com/fastly/edge-mcp).

MHS lets AI agents operate physical lab and manufacturing hardware (robot arms,
qPCR machines, microscopes) through a standardized driver layer, exposed via
MCP among other control surfaces. That's a different risk profile than a
data-only MCP tool: a bad or malicious `tools/call` can damage real equipment,
not just corrupt data. This gateway sits between an MCP-speaking AI agent and
an MHS driver runtime and adds, at the edge:

- Everything `edge-mcp` already provides, **unmodified**: fail-closed JWT
  auth, default-deny scope authorization, central JSON-Schema validation, MRTR
  continuation tokens, KV-backed tasks, fail-closed edge caching.
- **A hardware-safety layer** — tool-call arguments are validated against a
  device's declared safety limits (numeric ranges, allowed values) before
  anything is proxied to the driver.
- **Per-(principal, device, tool) quota enforcement** — an authorized caller
  can still be throttled per device, since repeated legitimate commands can
  wear or damage hardware.
- **Structured audit logging** — every decision (allowed, safety-denied,
  quota-denied, proxy error) is logged with a hashed principal id and
  correlation id, never raw arguments or tokens.

edge-mcp's own `SECURITY.md` explicitly flags rate limiting/quotas and audit
logging as gaps a production deployment must close (CMCP-003, CMCP-007) —
those are exactly the two production controls this gateway adds, on top of the
MHS-specific safety layer.

See [`docs/superpowers/specs/2026-08-27-edge-mhs-interlock-design.md`](docs/superpowers/specs/2026-08-27-edge-mhs-interlock-design.md)
for the full design writeup (kept local, not committed — see `.gitignore`).

## Status

A **reference implementation to learn from and build on — not a certified or
turnkey production service.** Same posture as the edge-mcp base it's built on:

- **Agent-generated**, TDD throughout — audit it before relying on it.
- **No public MHS spec exists yet.** The two devices registered in
  `gateway-server/src/tools.rs` (a qPCR machine, a robot arm) and the MHS
  driver/registry HTTP contract (`gateway-server`'s `BackendLimitsSource` /
  `FastlyBackendProxy`) are placeholders — adjust the wire shape to whatever
  the real MHS driver runtime actually exposes once that's public.
- **Rate limiting is not locally verifiable.** Viceroy's `fastly::erl`
  (`RateCounter`/`Penaltybox`) host calls did not enforce limits in local
  testing — calls past a configured quota still succeeded. This needs
  validation on a real Fastly service before you rely on it; see
  `scripts/smoke-test.sh`'s output for the exact behavior observed.
- **`fastly` is pinned to `=0.13.0`.** `0.13.1` added a host import
  (`cache_override_v3_set`) that standalone Viceroy 0.20.1 doesn't implement,
  which breaks local testing. Bump the pin once Viceroy catches up.

## Layout

| Crate | Status | Role |
|---|---|---|
| `crates/mcp-core` | reused as-is from edge-mcp | Stateless MCP JSON-RPC engine: dispatch, `_meta`, MRTR, Tasks |
| `crates/mcp-fastly` | reused as-is from edge-mcp | JWT/JWKS verifier, KV task store, Secret Store signer, fail-closed edge caching |
| `crates/mhs-safety-policy` | new | Pure `evaluate()`: check tool-call arguments against a device's declared `Range`/`Allowed` limits |
| `crates/mhs-device-registry` | new | Cache-then-fetch device-limits lookup (mirrors `mcp-fastly`'s JWKS cache pattern) |
| `crates/mhs-gateway-fastly` | new | Fastly bindings: ERL rate limiter, real-time-log audit logger, MHS backend proxy, KV device-limits cache |
| `gateway-server` | new (forked from `example-server`) | The deployable Compute program: `DeviceToolHandler` wires it all together per device/tool |

The key finding from building this: **no changes to `mcp-core` or
`mcp-fastly` were needed.** Every MHS-specific control plugs into
`mcp-core`'s existing `ToolHandler` trait — auth, scope authorization, and
schema validation already run in `mcp-core::dispatch` before a handler
executes, so `DeviceToolHandler::call` only had to add the safety/quota/proxy/
audit steps, not fork the dispatch spine or the request adapter.

## Quick start

```bash
# 1. Fast native tests for all pure/host-testable logic (no wasm toolchain needed):
cargo test --workspace

# 2. Run gateway-server end-to-end under Viceroy against a mock MHS backend
#    and assert on it. Needs standalone viceroy >= 0.20 pinned to the
#    fastly = "=0.13.0" ABI (see Status above):
cargo install --locked viceroy
scripts/smoke-test.sh
```

The smoke test builds the wasm, starts a mock MHS backend
(`scripts/mock_mhs_backend.py` — there's no real one to test against yet),
starts Viceroy, and drives real HTTP JSON-RPC through `tools/list`, a
happy-path proxied `tools/call`, a `Range`-limit safety denial, an
`Allowed`-limit safety denial, and central schema validation.

## Adding a device

Register a `DeviceToolHandler` in `gateway-server/src/tools.rs`, following the
two existing examples. Each one needs: a `DeviceToolConfig` (tool name,
JSON-Schema, required scopes, quota), a `DeviceRegistry` (which safety limits
apply — served from the `mhs_registry` backend and KV-cached), and the shared
rate limiter / audit logger / backend proxy. The device's actual safety
limits live in MHS device-discovery metadata, not in this repo.

## Deploying

```bash
fastly compute build
fastly compute deploy
```

Provision the resources the server reads (see `fastly.toml` for exact names):
the `task_store`, `jwks_cache`, and `device_limits_cache` KV Stores, the
`auth` Secret Store (AEAD signing key ring), the `verifier` Config Store, the
`issuer_jwks` / `mhs_registry` / `mhs_driver` backends, an `mhs_rate_counter` +
`mhs_penalty_box` ERL pair, and an `mhs_audit` real-time log endpoint. Set the
`issuer_jwks` backend's timeout tight (≤10s) so a slow IdP fails fast, and do
the same for `mhs_driver` so a hung driver can't stall an edge request.

## Security

See [`SECURITY.md`](SECURITY.md) for what this code enforces and what a
production deployment must still add — mostly inherited from edge-mcp's own
`SECURITY.md`, plus the MHS-specific additions.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). `crates/mcp-core` and
`crates/mcp-fastly` are copied from
[fastly/edge-mcp](https://github.com/fastly/edge-mcp), Copyright 2026 Fastly,
Inc., under the same license.
