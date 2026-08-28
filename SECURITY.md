# Security

This is a **reference implementation**, forked from
[`fastly/edge-mcp`](https://github.com/fastly/edge-mcp). It aims to be secure
by default, but it is not a managed product. Before any real deployment, read
this document and complete the deployment-layer controls below.

## What this codebase enforces

Everything edge-mcp's own `SECURITY.md` lists is inherited unmodified
(`crates/mcp-core`, `crates/mcp-fastly` are reused as-is): fail-closed
authentication, ES256 JWT verification, default-deny scope authorization,
credential-cheap rejection, SSRF-guarded JWKS fetch, signed principal-bound
continuation/task tokens, client idempotency keys, central schema validation,
fail-closed edge caching, sanitized errors, reproducible builds.

On top of that, this gateway adds and tests:

- **Safety-policy evaluation** (`mhs-safety-policy`) — every `tools/call`'s
  arguments are checked against the target device's declared limits
  (`Range` or `Allowed`) before the call is proxied. Fails closed: an unknown
  device, a missing safety-limit lookup, or a value of the wrong type against
  a declared limit all deny rather than silently allow.
- **Per-(principal, device, tool) quota enforcement** (`mhs-gateway-fastly::
  rate_limit`) — the composite rate-counter key is built so distinct
  (principal, device, tool) triples can never collide onto the same counter
  (tested against the classic delimiter-boundary-shift bug).
- **Structured audit logging** (`mhs-gateway-fastly::audit`) — one event per
  decision, carrying a hashed principal id and correlation id. Tested to
  never serialize raw arguments, bearer tokens, or any field beyond the fixed
  allowed set.
- **Sanitized proxy errors** — a backend/driver failure is reported to the
  client as a generic message plus correlation id; the real error detail is
  logged server-side only, never echoed into the client-facing tool result
  (tested explicitly: `proxy_error_is_reported_as_a_tool_error_without_leaking_backend_detail`).
- **Backend response size cap** — the MHS driver's response body is bounded
  before being read into memory, mirroring edge-mcp's own JWKS-fetch guard.

## What you MUST add before production

These are the same two categories edge-mcp's own `SECURITY.md` flags as
deployment-layer gaps (CMCP-003, CMCP-007) — this gateway's code exercises
the *hooks* for both, but the actual enforcement depends on Fastly resources
you provision, not on code in this repo:

### Rate limiting, quotas, and cost control

- Provision the `mhs_rate_counter` / `mhs_penalty_box` ERL resources this
  code calls into (`fastly::erl::{RateCounter,Penaltybox}`). **Local Viceroy
  testing did not enforce these limits** — validate quota behavior on a real
  Fastly service before depending on it.
- The configured `max_calls_per_window`/`window_secs`/`penalty_ttl_secs` per
  tool in `gateway-server/src/tools.rs` are starting points, not calibrated
  values — they should reflect the actual physical tolerance of each device
  (how often it can safely receive commands), not just an API-abuse budget.
- Task quotas and cost budgets: unchanged from edge-mcp's own gap — this
  gateway does not add task/cost-budget enforcement beyond what edge-mcp's
  Tasks extension already provides.

### Security audit logging and alerting

- Provision the `mhs_audit` real-time log endpoint and ship it to your log
  pipeline. The event shape (`mhs-gateway-fastly::audit::AuditEvent`) is
  fixed and tested to exclude raw arguments/tokens/claims — but *alerting* on
  it (thresholds for denial spikes, repeated safety violations against one
  device, proxy-error bursts) is your operational responsibility, not
  something this code does.

### MHS-specific hardening

- **The device-metadata contract is a placeholder.** `BackendLimitsSource`
  fetches `GET <mhs_registry_base_url>/mhs/devices/<id>/limits` and expects
  `mhs-safety-policy::DeviceLimits`'s exact JSON shape back. There is no
  public MHS spec yet — when one exists, this almost certainly needs to
  change to match it.
- **No human-confirmation gate for high-impact actions.** This gateway
  enforces declared numeric/enum limits, not judgment calls. A tool call that
  is *within* limits but still inadvisable (e.g., a large-but-legal joint
  move at the wrong moment) is not caught here. Explicitly deferred to future
  work: gating specific tools behind MRTR `input_required` so a human must
  confirm before the call reaches the driver.
- **The MHS driver runtime's own safety enforcement is out of scope.** This
  gateway is a defense-in-depth layer at the edge, not a substitute for
  interlocks and limits enforced by the device driver / hardware itself.

### Other operational hardening (inherited from edge-mcp)

- Keep the `issuer_jwks` **and** `mhs_driver` backend timeouts tight (≤10s)
  so a slow IdP or a hung driver fails fast rather than stalling an edge
  request.
- Provide an emergency JWKS purge/refresh procedure and document key rotation
  (both the AEAD signer key ring and issuer JWKS).
- Validate real Fastly behavior (CPU/memory limits, KV consistency,
  cache-purge propagation, ERL enforcement) on a live service — local Viceroy
  cannot reproduce all of these, and this repo found at least one concrete
  gap (rate limiting) during its own smoke testing.

## Trust boundary reminder for consumers

Same reminder edge-mcp carries: MCP tool descriptions, prompt content,
resource content, and tool results cross into an AI trust boundary. A
consuming client/agent must treat all of them as **untrusted input**. For
MHS specifically, that extends to physical consequences — a client should
require human confirmation for high-impact physical actions regardless of
what this gateway allows, not rely on the gateway as the only safety check.
