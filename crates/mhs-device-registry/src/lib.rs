//! Cached lookup of a device's declared safety limits.
//!
//! Mirrors `mcp-fastly`'s JWKS cache-then-fetch pattern: a fast local cache
//! backed by an upstream source, with an embedded `fetched_at` timestamp
//! deciding freshness (host-supplied clock, no ambient time here — see
//! `mcp_core::RequestCtx::now_unix` for why). Platform-neutral: the Fastly KV
//! cache and MHS-metadata-fetch bindings live in `mhs-gateway-fastly`.

use mhs_safety_policy::DeviceLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError(pub String);

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "device registry error: {}", self.0)
    }
}

/// A local cache of (limits, fetched_at) by device id. Implemented over a
/// Fastly KV Store in `mhs-gateway-fastly`; here it's an interface so the
/// freshness decision below is host-testable.
pub trait LimitsCache {
    fn read(&self, device_id: &str) -> Option<(DeviceLimits, u64)>;
    fn write(&self, device_id: &str, limits: &DeviceLimits, fetched_at: u64);
}

/// The upstream source of truth for a device's limits (MHS device-discovery
/// metadata). `Ok(None)` means the device is unknown; `Err` means the
/// upstream could not be reached — the caller must treat that as fail-closed,
/// not as "no limits".
pub trait LimitsSource {
    fn fetch(&self, device_id: &str) -> Result<Option<DeviceLimits>, RegistryError>;
}

/// Cache-then-fetch device limits lookup, mirroring `mcp-fastly`'s JWKS cache.
pub struct DeviceRegistry<C: LimitsCache, S: LimitsSource> {
    cache: C,
    source: S,
    max_age_secs: u64,
}

impl<C: LimitsCache, S: LimitsSource> DeviceRegistry<C, S> {
    pub fn new(cache: C, source: S, max_age_secs: u64) -> Self {
        DeviceRegistry { cache, source, max_age_secs }
    }

    /// Look up a device's limits as of wall-clock `now` (Unix seconds,
    /// host-supplied — this crate has no ambient clock).
    pub fn limits_for(&self, device_id: &str, now: u64) -> Result<Option<DeviceLimits>, RegistryError> {
        if let Some((limits, fetched_at)) = self.cache.read(device_id) {
            // checked_add, not saturating_add: if the freshness deadline
            // would overflow, treat the entry as stale (refetch) rather than
            // as "fresh forever" -- the safe failure direction for a cache
            // that gates a physical-safety check is toward a fresh fetch,
            // not toward indefinitely trusting a corrupted timestamp.
            if fetched_at.checked_add(self.max_age_secs).is_some_and(|expiry| now < expiry) {
                return Ok(Some(limits));
            }
        }
        match self.source.fetch(device_id)? {
            Some(limits) => {
                self.cache.write(device_id, &limits, now);
                Ok(Some(limits))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mhs_safety_policy::{DeviceLimits, Limit};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    fn limits_with(field: &str, min: f64, max: f64) -> DeviceLimits {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(field.to_string(), Limit::Range { min, max });
        DeviceLimits { fields, unrestricted: false }
    }

    #[derive(Default)]
    struct FakeCache {
        store: RefCell<HashMap<String, (DeviceLimits, u64)>>,
    }
    impl LimitsCache for FakeCache {
        fn read(&self, device_id: &str) -> Option<(DeviceLimits, u64)> {
            self.store.borrow().get(device_id).cloned()
        }
        fn write(&self, device_id: &str, limits: &DeviceLimits, fetched_at: u64) {
            self.store
                .borrow_mut()
                .insert(device_id.to_string(), (limits.clone(), fetched_at));
        }
    }

    #[derive(Default)]
    struct FakeSource {
        data: HashMap<String, DeviceLimits>,
        calls: Cell<u32>,
    }
    impl LimitsSource for FakeSource {
        fn fetch(&self, device_id: &str) -> Result<Option<DeviceLimits>, RegistryError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.data.get(device_id).cloned())
        }
    }

    #[derive(Default)]
    struct ErrorSource;
    impl LimitsSource for ErrorSource {
        fn fetch(&self, _device_id: &str) -> Result<Option<DeviceLimits>, RegistryError> {
            Err(RegistryError("upstream unavailable".into()))
        }
    }

    #[test]
    fn cache_miss_falls_through_to_source_and_populates_cache() {
        let mut data = HashMap::new();
        data.insert("qpcr-1".to_string(), limits_with("celsius", 4.0, 100.0));
        let source = FakeSource { data, calls: Cell::new(0) };
        let cache = FakeCache::default();
        let registry = DeviceRegistry::new(cache, source, 3600);

        let result = registry.limits_for("qpcr-1", 1000).unwrap();
        assert_eq!(result, Some(limits_with("celsius", 4.0, 100.0)));
        assert_eq!(registry.source.calls.get(), 1);
        assert!(registry.cache.read("qpcr-1").is_some(), "a cache miss must populate the cache");
    }

    #[test]
    fn fresh_cache_hit_does_not_call_source() {
        let source = FakeSource::default();
        let cache = FakeCache::default();
        cache.write("qpcr-1", &limits_with("celsius", 4.0, 100.0), 1000);
        let registry = DeviceRegistry::new(cache, source, 3600);

        let result = registry.limits_for("qpcr-1", 1500).unwrap(); // within max_age
        assert_eq!(result, Some(limits_with("celsius", 4.0, 100.0)));
        assert_eq!(registry.source.calls.get(), 0, "a fresh cache hit must not call the source");
    }

    #[test]
    fn freshness_check_does_not_overflow_on_a_near_max_timestamp() {
        // fetched_at is only ever written by this code from a host-supplied
        // clock, but a KV entry could in principle carry a corrupted or
        // adversarial value close to u64::MAX -- the freshness comparison
        // must not panic (debug builds) or wrap into "still fresh" (release).
        let source = FakeSource::default();
        let cache = FakeCache::default();
        cache.write("qpcr-1", &limits_with("celsius", 4.0, 100.0), u64::MAX - 5);
        let registry = DeviceRegistry::new(cache, source, 3600);

        let result = registry.limits_for("qpcr-1", u64::MAX - 1);
        assert_eq!(result, Ok(None), "must refetch (source has no data) rather than panic or wrap");
    }

    #[test]
    fn stale_cache_hit_refetches_and_refreshes_the_cache_timestamp() {
        let mut data = HashMap::new();
        data.insert("qpcr-1".to_string(), limits_with("celsius", -20.0, 200.0));
        let source = FakeSource { data, calls: Cell::new(0) };
        let cache = FakeCache::default();
        cache.write("qpcr-1", &limits_with("celsius", 4.0, 100.0), 1000);
        let registry = DeviceRegistry::new(cache, source, 3600);

        // now is past fetched_at(1000) + max_age(3600)
        let result = registry.limits_for("qpcr-1", 5000).unwrap();
        assert_eq!(result, Some(limits_with("celsius", -20.0, 200.0)), "must return the refreshed value");
        assert_eq!(registry.source.calls.get(), 1);
        let (_, refreshed_at) = registry.cache.read("qpcr-1").unwrap();
        assert_eq!(refreshed_at, 5000, "cache timestamp must advance to the refresh time");
    }

    #[test]
    fn unknown_device_is_none_not_an_error() {
        let source = FakeSource::default();
        let cache = FakeCache::default();
        let registry = DeviceRegistry::new(cache, source, 3600);

        let result = registry.limits_for("no-such-device", 1000).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn source_error_propagates_so_the_caller_can_fail_closed() {
        let registry = DeviceRegistry::new(FakeCache::default(), ErrorSource, 3600);
        let err = registry.limits_for("qpcr-1", 1000).unwrap_err();
        assert!(err.0.contains("upstream unavailable"));
    }
}
