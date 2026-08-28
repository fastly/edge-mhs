//! Fastly bindings for `mhs_device_registry`'s `LimitsCache`/`LimitsSource`
//! traits: a KV-Store-backed cache and a backend-fetch source for a device's
//! declared safety limits (MHS device-discovery metadata).
//!
//! The caching *decision* (fresh vs. stale vs. missing) is already fully
//! tested in `mhs-device-registry` — these are pure I/O adapters with no
//! independent logic, wasm-gated like the rest of this crate's real
//! bindings.

#[cfg(target_arch = "wasm32")]
mod wasm_impl {
    use std::io::Read;

    use fastly::kv_store::KVStore;
    use fastly::Request;

    use mhs_device_registry::{LimitsCache, LimitsSource, RegistryError};
    use mhs_safety_policy::DeviceLimits;

    const KV_STORE: &str = "device_limits_cache";
    /// Hard cap on a device-metadata document (ample for a safety-limit set;
    /// bounds memory against a misbehaving or compromised metadata backend).
    const MAX_LIMITS_BYTES: usize = 65_536;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct CachedLimits {
        fetched_at: u64,
        limits: DeviceLimits,
    }

    pub struct KvLimitsCache;

    impl LimitsCache for KvLimitsCache {
        fn read(&self, device_id: &str) -> Option<(DeviceLimits, u64)> {
            let store = KVStore::open(KV_STORE).ok()??;
            let mut lookup = store.lookup(device_id).ok()?;
            let bytes = lookup.take_body().into_bytes();
            let cached: CachedLimits = serde_json::from_slice(&bytes).ok()?;
            Some((cached.limits, cached.fetched_at))
        }

        fn write(&self, device_id: &str, limits: &DeviceLimits, fetched_at: u64) {
            let Ok(Some(store)) = KVStore::open(KV_STORE) else { return };
            let cached = CachedLimits { fetched_at, limits: limits.clone() };
            if let Ok(value) = serde_json::to_vec(&cached) {
                let _ = store.build_insert().execute(device_id, value);
            }
        }
    }

    /// Fetches a device's limits from the MHS device-metadata backend at
    /// `GET <base_url>/mhs/devices/<device_id>/limits`. `base_url` and
    /// `backend_name` are kept separate exactly like `mcp-fastly`'s
    /// `jwks_uri`/`jwks_backend` split, so the backend name (used only for
    /// `.send()` routing) doesn't have to double as a real hostname.
    pub struct BackendLimitsSource {
        backend_name: String,
        base_url: String,
    }

    impl BackendLimitsSource {
        pub fn new(backend_name: impl Into<String>, base_url: impl Into<String>) -> Self {
            BackendLimitsSource { backend_name: backend_name.into(), base_url: base_url.into() }
        }
    }

    impl LimitsSource for BackendLimitsSource {
        fn fetch(&self, device_id: &str) -> Result<Option<DeviceLimits>, RegistryError> {
            let url = format!("{}/mhs/devices/{device_id}/limits", self.base_url);
            let resp = Request::get(url)
                .send(&self.backend_name)
                .map_err(|e| RegistryError(format!("device metadata fetch failed: {e}")))?;

            if resp.get_status() == fastly::http::StatusCode::NOT_FOUND {
                return Ok(None); // unknown device, not a fetch failure
            }
            if !resp.get_status().is_success() {
                return Err(RegistryError(format!(
                    "device metadata fetch returned status {}",
                    resp.get_status()
                )));
            }

            let mut body = Vec::new();
            resp.into_body()
                .take((MAX_LIMITS_BYTES as u64) + 1)
                .read_to_end(&mut body)
                .map_err(|e| RegistryError(format!("device metadata read failed: {e}")))?;
            if body.len() > MAX_LIMITS_BYTES {
                return Err(RegistryError("device metadata document too large".to_string()));
            }

            serde_json::from_slice(&body)
                .map(Some)
                .map_err(|_| RegistryError("device metadata parse failed".to_string()))
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_impl::{BackendLimitsSource, KvLimitsCache};
