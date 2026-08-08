//! The trace database's user-property manager.
//!
//! Java source: `ghidra.trace.database.property.DBTraceAddressPropertyManager`.
//!
//! The Java class is `DBTraceAddressPropertyManager implements TraceAddressPropertyManager,
//! DBTraceManager` -- both of which are already-ported, object-safe traits (respectively
//! [`TraceAddressPropertyManager`](crate::trace::seam_stubs::TraceAddressPropertyManager) and
//! [`DBTraceManager`]). It was selected as a dependency-cycle cut-point, so this trait is kept
//! minimal: it re-declares those two interfaces as supertraits (mirroring Java's `implements`
//! list) and adds the one further public member the concrete class exposes beyond them,
//! [`get_api_property_manager`](DBTraceAddressPropertyManager::get_api_property_manager).
//!
//! The constructor and the class's private, DB-record-backed storage (`propertyStore`, a
//! `DBCachedObjectStore<DBTraceAddressPropertyEntry>`; `propertyMapsByName`, keyed by property
//! name; and the package-private `doCreateMap`/`loadPropertyMaps` helpers that construct the
//! concrete `DBTraceIntPropertyMap`/`DBTraceLongPropertyMap`/... implementations by value class)
//! are implementation details, not part of the class's cross-package API contract --
//! `DBCachedObjectStore` and those concrete `DBTrace*PropertyMap` classes are not yet ported.
//! Mirroring
//! [`DBTraceStaticMappingManager`](crate::trace::database::module::DBTraceStaticMappingManager)'s
//! same exclusion of its own private storage, none of that is represented here;
//! `create_property_map`/`get_property_map`/... are inherited unchanged (as abstract methods)
//! from [`TraceAddressPropertyManager`], and `invalidate_cache`/`db_error` from [`DBTraceManager`].
//!
//! `get_api_property_manager` mirrors the class's own `getApiPropertyManager()`, which hands out
//! the `_API_`-name-prefixed `DBTraceAddressPropertyManagerApiView` wrapper (a package-private,
//! not-yet-ported class) as a plain
//! [`TraceAddressPropertyManager`](crate::trace::seam_stubs::TraceAddressPropertyManager); since
//! that trait already declares the interface's full method surface, the wrapper's own
//! implementation detail (prefixing names with `_API_` and filtering `getAllProperties()`) is not
//! reproduced here.

use crate::trace::database::db_trace_manager::DBTraceManager;
use crate::trace::seam_stubs::TraceAddressPropertyManager;

/// The trace database's manager of user-defined address properties.
///
/// Port of `ghidra.trace.database.property.DBTraceAddressPropertyManager`.
pub trait DBTraceAddressPropertyManager: TraceAddressPropertyManager + DBTraceManager {
    /// Get the public API view of this manager, whose property names are `_API_`-prefixed and
    /// hidden from callers using the internal (unprefixed) view.
    ///
    /// Mirrors `DBTraceAddressPropertyManager.getApiPropertyManager()`.
    fn get_api_property_manager(&self) -> Box<dyn TraceAddressPropertyManager>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::seam_stubs::AbstractDBTracePropertyMap;
    use std::any::TypeId;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockPropertyMap {
        value_class: TypeId,
    }

    impl AbstractDBTracePropertyMap for MockPropertyMap {
        fn get_value_class(&self) -> TypeId {
            self.value_class
        }
    }

    /// A minimal in-memory implementor backed by a `HashMap`, proving both supertraits plus
    /// `get_api_property_manager` are reachable through a single
    /// `Box<dyn DBTraceAddressPropertyManager>`, and that `create_property_map`/`get_property_map`
    /// round-trip real entries (not trivially-true assertions).
    struct MockManager {
        entries: Mutex<HashMap<String, TypeId>>,
        invalidate_calls: Mutex<Vec<bool>>,
        last_error: Mutex<Option<String>>,
    }

    impl crate::framework::db::util::error_handler::ErrorHandler for MockManager {
        fn db_error(&self, e: std::io::Error) {
            *self.last_error.lock().unwrap() = Some(e.to_string());
        }
    }

    impl DBTraceManager for MockManager {
        fn invalidate_cache(&mut self, all: bool) {
            self.invalidate_calls.lock().unwrap().push(all);
        }
    }

    impl TraceAddressPropertyManager for MockManager {
        fn create_property_map(
            &mut self,
            name: &str,
            value_class: TypeId,
        ) -> Result<
            Box<dyn AbstractDBTracePropertyMap>,
            crate::util::exception::DuplicateNameException,
        > {
            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(name) {
                return Err(crate::util::exception::DuplicateNameException::with_message(name));
            }
            entries.insert(name.to_string(), value_class);
            Ok(Box::new(MockPropertyMap { value_class }))
        }

        fn get_property_map(
            &self,
            name: &str,
            value_class: TypeId,
        ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
            let entries = self.entries.lock().unwrap();
            let stored = *entries.get(name)?;
            if stored != value_class {
                panic!("property {name} has a different type");
            }
            Some(Box::new(MockPropertyMap { value_class: stored }))
        }

        fn get_all_properties(&self) -> HashMap<String, Box<dyn AbstractDBTracePropertyMap>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .map(|(name, &value_class)| {
                    (
                        name.clone(),
                        Box::new(MockPropertyMap { value_class }) as Box<dyn AbstractDBTracePropertyMap>,
                    )
                })
                .collect()
        }
    }

    impl DBTraceAddressPropertyManager for MockManager {
        fn get_api_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn make_manager() -> MockManager {
        MockManager {
            entries: Mutex::new(HashMap::new()),
            invalidate_calls: Mutex::new(Vec::new()),
            last_error: Mutex::new(None),
        }
    }

    #[test]
    fn create_then_get_round_trips_through_trait_object() {
        let mut manager = make_manager();
        let mgr: &mut dyn DBTraceAddressPropertyManager = &mut manager;

        let created = mgr.create_property_map("comment", TypeId::of::<String>());
        assert!(created.is_ok());
        assert_eq!(created.unwrap().get_value_class(), TypeId::of::<String>());

        let fetched = mgr.get_property_map("comment", TypeId::of::<String>());
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().get_value_class(), TypeId::of::<String>());

        assert!(mgr.get_property_map("missing", TypeId::of::<String>()).is_none());
    }

    #[test]
    fn create_property_map_rejects_duplicate_name() {
        let mut manager = make_manager();
        let mgr: &mut dyn DBTraceAddressPropertyManager = &mut manager;

        mgr.create_property_map("comment", TypeId::of::<i32>())
            .expect("first create should succeed");
        let err = mgr.create_property_map("comment", TypeId::of::<i32>());
        assert!(err.is_err());
    }

    #[test]
    fn trait_object_reaches_both_supertraits() {
        let mut manager = make_manager();
        let mgr: &mut dyn DBTraceAddressPropertyManager = &mut manager;

        mgr.create_property_map("a", TypeId::of::<i32>()).unwrap();
        mgr.invalidate_cache(true);
        mgr.db_error(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));

        assert_eq!(mgr.get_all_properties().len(), 1);
        assert_eq!(manager.invalidate_calls.lock().unwrap().as_slice(), &[true]);
        assert_eq!(manager.last_error.lock().unwrap().as_deref(), Some("disk full"));
    }
}
