//! The manager for user properties of a trace.
//!
//! Java source: `ghidra.trace.model.property.TraceAddressPropertyManager`.
//!
//! Clients may create property maps of various value types. Each map is named, also considered
//! the "property name," and can be retrieved by that name.
//!
//! Java's `<T> ... Class<T> valueClass` generic methods are not object-safe as written (a `dyn
//! Trait` cannot dispatch a generic method), and this trait must stay usable as `Box<dyn
//! TraceAddressPropertyManager>` -- see
//! [`Trace::get_address_property_manager`](crate::trace::model::trace::Trace::get_address_property_manager)
//! and its many callers. So `Class<T>` becomes [`TypeId`], and the returned `TracePropertyMap<T>`
//! becomes the type-erased
//! [`AbstractDBTracePropertyMap`](crate::trace::seam_stubs::AbstractDBTracePropertyMap) (a
//! placeholder for the not-yet-ported `ghidra.trace.database.map.AbstractDBTracePropertyMap`,
//! distinct from the already-ported, value-typed
//! [`TracePropertyMap`](super::trace_property_map::TracePropertyMap) that concrete maps will
//! eventually also implement), matching this crate's established convention for an unconstrained
//! type parameter on an object-safe trait (see
//! [`TraceObjectValue::get_value`](crate::trace::model::target::trace_object_value::TraceObjectValue::get_value)'s
//! docs). Java's unchecked `TypeMismatchException` (no `throws` clause) is mirrored as a possible
//! panic, matching this crate's existing convention for that exception (see
//! [`PropertyMapManager`](crate::program::model::util::property_map_manager::PropertyMapManager)'s
//! "May panic" docs); only the checked `DuplicateNameException` on `createPropertyMap` becomes a
//! `Result`.
//!
//! All members default to panicking rather than being purely abstract: this interface was first
//! ported as a cycle-cut-point placeholder (see `STUBS.tsv`) and several implementors already
//! rely on that -- e.g. the marker `impl TraceAddressPropertyManager for
//! MockAddressPropertyManager {}` in [`Trace`](crate::trace::model::trace)'s tests, and
//! [`DBTraceAddressPropertyManager`](crate::trace::database::property::db_trace_address_property_manager::DBTraceAddressPropertyManager)'s
//! own `MockManager`, which only overrides the members it exercises. Keeping the defaults means
//! this promotion from placeholder to real port does not need to touch either.
use std::any::TypeId;
use std::collections::HashMap;

use crate::trace::seam_stubs::AbstractDBTracePropertyMap;
use crate::util::exception::DuplicateNameException;

/// The manager for user properties of a trace.
///
/// Port of `ghidra.trace.model.property.TraceAddressPropertyManager`.
pub trait TraceAddressPropertyManager: Send + Sync {
    /// Create a property map with the given name and value type.
    ///
    /// Port of `createPropertyMap(String, Class<T>)`.
    fn create_property_map(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Result<Box<dyn AbstractDBTracePropertyMap>, DuplicateNameException> {
        unimplemented!("TraceAddressPropertyManager::create_property_map placeholder not overridden")
    }

    /// Get the property map with the given name, if it has the given type. Returns `None` if no
    /// such map exists (Java's `null`).
    ///
    /// Port of `getPropertyMap(String, Class<T>)`. May panic if a map of that name exists but
    /// does not have the expected type (Java's `TypeMismatchException`).
    fn get_property_map(
        &self,
        _name: &str,
        _value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!("TraceAddressPropertyManager::get_property_map placeholder not overridden")
    }

    /// Get the property map with the given name, if its values extend the given type.
    ///
    /// Port of `getPropertyMapExtends(String, Class<T>)`. May panic if a map of that name exists
    /// but its values do not extend the expected type (Java's `TypeMismatchException`).
    fn get_property_map_extends(
        &self,
        _name: &str,
        _value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!(
            "TraceAddressPropertyManager::get_property_map_extends placeholder not overridden"
        )
    }

    /// Get the property map with the given name, creating it if necessary, of the given type.
    ///
    /// Port of `getOrCreatePropertyMap(String, Class<T>)`; see
    /// [`create_property_map`](Self::create_property_map).
    fn get_or_create_property_map(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        unimplemented!(
            "TraceAddressPropertyManager::get_or_create_property_map placeholder not overridden"
        )
    }

    /// Get the property map with the given name, creating it if necessary; if it already exists,
    /// its values' type must be a supertype of the given type.
    ///
    /// Port of `getOrCreatePropertyMapSuper(String, Class<T>)`; see
    /// [`get_or_create_property_map`](Self::get_or_create_property_map).
    fn get_or_create_property_map_super(
        &mut self,
        _name: &str,
        _value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        unimplemented!(
            "TraceAddressPropertyManager::get_or_create_property_map_super placeholder not overridden"
        )
    }

    /// Get the property map with the given name, without type-checking.
    ///
    /// Port of the overload `getPropertyMap(String)`. No type checking is performed here; the
    /// returned map is suitable only for clearing and querying where the property is present.
    /// The caller may perform run-time type checking via
    /// [`AbstractDBTracePropertyMap::get_value_class`].
    fn get_property_map_untyped(&self, _name: &str) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!(
            "TraceAddressPropertyManager::get_property_map_untyped placeholder not overridden"
        )
    }

    /// Get a copy of all the defined properties.
    ///
    /// Port of `getAllProperties()`.
    fn get_all_properties(&self) -> HashMap<String, Box<dyn AbstractDBTracePropertyMap>> {
        unimplemented!("TraceAddressPropertyManager::get_all_properties placeholder not overridden")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockPropertyMap {
        value_class: TypeId,
    }

    impl AbstractDBTracePropertyMap for MockPropertyMap {
        fn get_value_class(&self) -> TypeId {
            self.value_class
        }
    }

    /// A minimal in-memory implementor, proving `create_property_map`/`get_property_map` round-trip
    /// real entries (not trivially-true assertions) and that duplicate names are rejected, matching
    /// the Java interface's documented `DuplicateNameException` contract.
    struct MockManager {
        entries: Mutex<HashMap<String, TypeId>>,
    }

    impl TraceAddressPropertyManager for MockManager {
        fn create_property_map(
            &mut self,
            name: &str,
            value_class: TypeId,
        ) -> Result<Box<dyn AbstractDBTracePropertyMap>, DuplicateNameException> {
            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(name) {
                return Err(DuplicateNameException::with_message(name));
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

    fn make_manager() -> MockManager {
        MockManager { entries: Mutex::new(HashMap::new()) }
    }

    #[test]
    fn create_then_get_round_trips_through_trait_object() {
        let mut manager = make_manager();
        let mgr: &mut dyn TraceAddressPropertyManager = &mut manager;

        let created = mgr.create_property_map("comment", TypeId::of::<String>());
        assert!(created.is_ok());
        assert_eq!(created.unwrap().get_value_class(), TypeId::of::<String>());

        let fetched = mgr.get_property_map("comment", TypeId::of::<String>());
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().get_value_class(), TypeId::of::<String>());

        assert!(mgr.get_property_map("missing", TypeId::of::<String>()).is_none());
        assert_eq!(mgr.get_all_properties().len(), 1);
    }

    #[test]
    fn create_property_map_rejects_duplicate_name() {
        let mut manager = make_manager();
        let mgr: &mut dyn TraceAddressPropertyManager = &mut manager;

        mgr.create_property_map("comment", TypeId::of::<i32>())
            .expect("first create should succeed");
        let err = mgr.create_property_map("comment", TypeId::of::<i32>());
        assert!(err.is_err());
    }

    #[test]
    fn unoverridden_members_panic_by_default() {
        struct BareManager;
        impl TraceAddressPropertyManager for BareManager {}

        let mut manager = BareManager;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            manager.get_or_create_property_map("x", TypeId::of::<i32>())
        }));
        assert!(result.is_err());
    }
}
