//! Registry for remote methods indexed by name or action.
//!
//! Corresponds to `ghidra.debug.api.tracermi.RemoteMethodRegistry`.

use crate::debug::seam_stubs::{ActionName, RemoteMethod};
use std::collections::{HashMap, HashSet};

/// A registry of remote methods, indexed by name and action.
///
/// Corresponds to `ghidra.debug.api.tracermi.RemoteMethodRegistry`.
pub trait RemoteMethodRegistry: Send + Sync {
    /// Get all remote methods indexed by name.
    fn all(&self) -> HashMap<String, Box<dyn RemoteMethod>>;

    /// Get a remote method by its name.
    fn get(&self, name: &str) -> Option<Box<dyn RemoteMethod>>;

    /// Get all remote methods associated with a given action.
    fn get_by_action(&self, action: &dyn ActionName) -> HashSet<Box<dyn RemoteMethod>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    struct TestRemoteMethod {
        _name: String,
    }

    impl RemoteMethod for TestRemoteMethod {}

    struct TestRegistry {
        methods: HashMap<String, Box<dyn RemoteMethod>>,
    }

    impl TestRegistry {
        fn new() -> Self {
            TestRegistry {
                methods: HashMap::new(),
            }
        }

        fn insert(&mut self, name: String, method: Box<dyn RemoteMethod>) {
            self.methods.insert(name, method);
        }
    }

    impl RemoteMethodRegistry for TestRegistry {
        fn all(&self) -> HashMap<String, Box<dyn RemoteMethod>> {
            self.methods.iter()
                .map(|(k, _v)| (k.clone(), Box::new(TestRemoteMethod { _name: k.clone() }) as Box<dyn RemoteMethod>))
                .collect()
        }

        fn get(&self, name: &str) -> Option<Box<dyn RemoteMethod>> {
            self.methods.get(name)
                .map(|_| Box::new(TestRemoteMethod { _name: name.to_string() }) as Box<dyn RemoteMethod>)
        }

        fn get_by_action(&self, _action: &dyn ActionName) -> HashSet<Box<dyn RemoteMethod>> {
            HashSet::new()
        }
    }

    #[test]
    fn registry_all_empty() {
        let registry = TestRegistry::new();
        assert!(registry.all().is_empty());
    }

    #[test]
    fn registry_get_returns_none_for_unknown() {
        let registry = TestRegistry::new();
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn registry_all_returns_methods() {
        let mut registry = TestRegistry::new();
        registry.insert("method1".to_string(), Box::new(TestRemoteMethod { _name: "method1".to_string() }));
        registry.insert("method2".to_string(), Box::new(TestRemoteMethod { _name: "method2".to_string() }));

        let all = registry.all();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("method1"));
        assert!(all.contains_key("method2"));
    }

    #[test]
    fn registry_get_returns_method() {
        let mut registry = TestRegistry::new();
        registry.insert("test_method".to_string(), Box::new(TestRemoteMethod { _name: "test_method".to_string() }));

        let method = registry.get("test_method");
        assert!(method.is_some());
    }

    #[test]
    fn registry_get_by_action_empty() {
        let registry = TestRegistry::new();
        let methods = registry.get_by_action(&MockActionName {});
        assert!(methods.is_empty());
    }

    struct MockActionName;

    impl ActionName for MockActionName {
        fn is_showing(&self, _context: &dyn crate::debug::seam_stubs::ActionContext) -> bool {
            false
        }

        fn is_enabled(&self, _obj: &dyn crate::debug::seam_stubs::TraceObject, _snap: i64) -> bool {
            false
        }

        fn name(&self, _name: &str) -> Box<dyn ActionName> {
            Box::new(MockActionName)
        }
    }
}
