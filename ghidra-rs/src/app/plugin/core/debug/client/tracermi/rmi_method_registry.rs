//! Port of `ghidra.app.plugin.core.debug.client.tracermi.RmiMethodRegistry` and its nested
//! `@TraceRmiMethod` annotation.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::app::plugin::core::debug::client::tracermi::RmiRemoteMethod;

/// The display metadata Java attaches to a remote method with the `@TraceRmiMethod` annotation.
///
/// Per the 2026-09-24 decision for Java annotation types, this is a plain metadata struct; every
/// element defaults to `""`, as the annotation's do. See [`RmiRemoteMethod::annotated`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceRmiMethod {
    /// `action()`.
    pub action: String,
    /// `display()`.
    pub display: String,
    /// `description()`.
    pub description: String,
    /// `okText()`.
    pub ok_text: String,
    /// `icon()`.
    pub icon: String,
}

/// The methods a client offers the front end, by name.
///
/// Java's registry is a bare `HashMap` that callers fill and the client reads; here it is
/// internally synchronized so it can be filled through a shared reference while the client's
/// reply thread reads it. The map is ordered by name so negotiation is deterministic.
#[derive(Debug, Default)]
pub struct RmiMethodRegistry {
    map: RwLock<BTreeMap<String, Arc<RmiRemoteMethod>>>,
}

impl RmiMethodRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors `getMethod(String)`.
    pub fn get_method(&self, key: &str) -> Option<Arc<RmiRemoteMethod>> {
        self.map.read().unwrap_or_else(|e| e.into_inner()).get(key).cloned()
    }

    /// Mirrors `putMethod(String, RmiRemoteMethod)`.
    pub fn put_method(&self, key: impl Into<String>, value: RmiRemoteMethod) {
        self.map.write().unwrap_or_else(|e| e.into_inner()).insert(key.into(), Arc::new(value));
    }

    /// Mirrors `getMap()`, as a snapshot.
    pub fn get_map(&self) -> BTreeMap<String, Arc<RmiRemoteMethod>> {
        self.map.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::debug::client::tracermi::rmi_remote_method_parameter::tests::named;

    fn method(name: &str) -> RmiRemoteMethod {
        RmiRemoteMethod::annotated(
            name,
            &TraceRmiMethod::default(),
            named("VOID"),
            vec![],
            Box::new(|_| Ok(None)),
        )
    }

    #[test]
    fn put_get_and_replace() {
        let reg = RmiMethodRegistry::new();
        assert!(reg.get_method("go").is_none());
        reg.put_method("go", method("go"));
        reg.put_method("attach", method("attach"));
        assert_eq!(reg.get_method("go").unwrap().get_name(), "go");
        assert_eq!(reg.get_map().keys().cloned().collect::<Vec<_>>(), vec!["attach", "go"]);
        reg.put_method("go", method("go2"));
        assert_eq!(reg.get_method("go").unwrap().get_name(), "go2");
        assert_eq!(reg.get_map().len(), 2);
    }

    #[test]
    fn annotation_defaults_are_empty() {
        let a = TraceRmiMethod::default();
        assert_eq!(a.action, "");
        assert_eq!(a.ok_text, "");
    }
}
