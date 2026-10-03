//! Port of `ghidra.trace.database.property.DBTraceAddressPropertyManagerApiView`.
//!
//! A `TraceAddressPropertyManager` wrapper that prefixes every property name with `_API_`,
//! hiding those API-created properties from internal (unprefixed) callers of the manager it
//! wraps -- and, symmetrically, hiding internal properties from API callers going through this
//! view, since [`get_all_properties`](DBTraceAddressPropertyManagerApiView::get_all_properties)
//! only returns entries whose name actually starts with the prefix.
//!
//! # `internalView` is stored as `Box<dyn TraceAddressPropertyManager>`, not the concrete class
//!
//! Java's field is the concrete `DBTraceAddressPropertyManager internalView`, but every method
//! on this class only ever calls members inherited from `TraceAddressPropertyManager`
//! (`createPropertyMap`/`getPropertyMap`/...) -- never anything specific to the concrete class.
//! [`DBTraceAddressPropertyManager`](super::db_trace_address_property_manager::DBTraceAddressPropertyManager)'s
//! own module docs already anticipate this: `getApiPropertyManager()`'s Rust port hands out this
//! exact wrapper "as a plain `TraceAddressPropertyManager`". Following that (and this crate's
//! "decoupling is first-class" rule: prefer trait seams over pervasive concrete types), this port
//! stores the wrapped manager as `Box<dyn TraceAddressPropertyManager>` rather than requiring the
//! more specific `DBTraceAddressPropertyManager` trait.

use std::any::TypeId;
use std::collections::HashMap;

use crate::trace::model::property::TraceAddressPropertyManager;
use crate::trace::seam_stubs::AbstractDBTracePropertyMap;
use crate::util::exception::DuplicateNameException;

/// Port of `DBTraceAddressPropertyManagerApiView.API_PREFIX`.
pub const API_PREFIX: &str = "_API_";

/// A `TraceAddressPropertyManager` view that prefixes every property name with [`API_PREFIX`].
///
/// Port of `ghidra.trace.database.property.DBTraceAddressPropertyManagerApiView`. See the module
/// docs for why `internal_view` is `Box<dyn TraceAddressPropertyManager>` rather than the more
/// specific concrete/trait type Java's field declares.
pub struct DBTraceAddressPropertyManagerApiView {
    internal_view: Box<dyn TraceAddressPropertyManager>,
}

impl DBTraceAddressPropertyManagerApiView {
    /// Port of `DBTraceAddressPropertyManagerApiView(DBTraceAddressPropertyManager)`.
    pub fn new(internal_view: Box<dyn TraceAddressPropertyManager>) -> Self {
        DBTraceAddressPropertyManagerApiView { internal_view }
    }

    fn prefixed(name: &str) -> String {
        format!("{API_PREFIX}{name}")
    }
}

impl TraceAddressPropertyManager for DBTraceAddressPropertyManagerApiView {
    /// Port of `createPropertyMap(String, Class<T>)`.
    fn create_property_map(
        &mut self,
        name: &str,
        value_class: TypeId,
    ) -> Result<Box<dyn AbstractDBTracePropertyMap>, DuplicateNameException> {
        self.internal_view.create_property_map(&Self::prefixed(name), value_class)
    }

    /// Port of `getPropertyMap(String, Class<T>)`.
    fn get_property_map(
        &self,
        name: &str,
        value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        self.internal_view.get_property_map(&Self::prefixed(name), value_class)
    }

    /// Port of `getPropertyMapExtends(String, Class<T>)`.
    fn get_property_map_extends(
        &self,
        name: &str,
        value_class: TypeId,
    ) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        self.internal_view.get_property_map_extends(&Self::prefixed(name), value_class)
    }

    /// Port of `getOrCreatePropertyMap(String, Class<T>)`.
    fn get_or_create_property_map(
        &mut self,
        name: &str,
        value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        self.internal_view.get_or_create_property_map(&Self::prefixed(name), value_class)
    }

    /// Port of `getOrCreatePropertyMapSuper(String, Class<T>)`.
    fn get_or_create_property_map_super(
        &mut self,
        name: &str,
        value_class: TypeId,
    ) -> Box<dyn AbstractDBTracePropertyMap> {
        self.internal_view.get_or_create_property_map_super(&Self::prefixed(name), value_class)
    }

    /// Port of `getPropertyMap(String)`.
    fn get_property_map_untyped(&self, name: &str) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
        self.internal_view.get_property_map_untyped(&Self::prefixed(name))
    }

    /// Port of `getAllProperties()`: returns only the wrapped manager's `_API_`-prefixed
    /// properties, with the prefix stripped from each key.
    fn get_all_properties(&self) -> HashMap<String, Box<dyn AbstractDBTracePropertyMap>> {
        self.internal_view
            .get_all_properties()
            .into_iter()
            .filter_map(|(name, map)| name.strip_prefix(API_PREFIX).map(|stripped| (stripped.to_string(), map)))
            .collect()
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

    /// A minimal in-memory `TraceAddressPropertyManager`, proving the API view actually prefixes
    /// names on every write/read path and strips them back off in `get_all_properties`.
    struct MockManager {
        entries: Mutex<HashMap<String, TypeId>>,
    }

    impl MockManager {
        fn new() -> Self {
            MockManager { entries: Mutex::new(HashMap::new()) }
        }
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

        fn get_property_map_untyped(&self, name: &str) -> Option<Box<dyn AbstractDBTracePropertyMap>> {
            let entries = self.entries.lock().unwrap();
            let stored = *entries.get(name)?;
            Some(Box::new(MockPropertyMap { value_class: stored }))
        }

        fn get_all_properties(&self) -> HashMap<String, Box<dyn AbstractDBTracePropertyMap>> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .map(|(name, &value_class)| {
                    (name.clone(), Box::new(MockPropertyMap { value_class }) as Box<dyn AbstractDBTracePropertyMap>)
                })
                .collect()
        }
    }

    #[test]
    fn create_property_map_stores_under_the_prefixed_name() {
        let manager = MockManager::new();
        let mut view = DBTraceAddressPropertyManagerApiView::new(Box::new(manager));

        view.create_property_map("comment", TypeId::of::<String>()).expect("should create");

        // Reachable through the API view under the unprefixed name...
        assert!(view.get_property_map("comment", TypeId::of::<String>()).is_some());
        // ...but stored internally under the prefixed name (not reachable as "comment" on the
        // wrapped manager directly).
        let internal = &view.internal_view;
        assert!(internal.get_property_map("comment", TypeId::of::<String>()).is_none());
        assert!(internal.get_property_map("_API_comment", TypeId::of::<String>()).is_some());
    }

    #[test]
    fn get_property_map_reads_back_a_created_map() {
        let mut view = DBTraceAddressPropertyManagerApiView::new(Box::new(MockManager::new()));
        view.create_property_map("x", TypeId::of::<i32>()).unwrap();

        let fetched = view.get_property_map("x", TypeId::of::<i32>());
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().get_value_class(), TypeId::of::<i32>());

        assert!(view.get_property_map("missing", TypeId::of::<i32>()).is_none());
    }

    #[test]
    fn get_property_map_untyped_uses_the_prefixed_name_too() {
        let mut view = DBTraceAddressPropertyManagerApiView::new(Box::new(MockManager::new()));
        view.create_property_map("x", TypeId::of::<i32>()).unwrap();

        assert!(view.get_property_map_untyped("x").is_some());
        assert!(view.get_property_map_untyped("_API_x").is_none());
    }

    #[test]
    fn get_all_properties_returns_only_api_prefixed_entries_with_prefix_stripped() {
        let mut manager = MockManager::new();
        // A property created directly on the wrapped manager (not through the API view) --
        // simulating an internal, non-API property that should stay hidden from this view.
        manager.create_property_map("internal_only", TypeId::of::<i32>()).unwrap();

        let mut view = DBTraceAddressPropertyManagerApiView::new(Box::new(manager));
        view.create_property_map("comment", TypeId::of::<String>()).unwrap();
        view.create_property_map("bookmark", TypeId::of::<bool>()).unwrap();

        let all = view.get_all_properties();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("comment"));
        assert!(all.contains_key("bookmark"));
        assert!(!all.contains_key("internal_only"));
        assert!(!all.contains_key("_API_comment"));
    }

    #[test]
    fn create_property_map_rejects_duplicate_prefixed_name() {
        let mut view = DBTraceAddressPropertyManagerApiView::new(Box::new(MockManager::new()));
        view.create_property_map("comment", TypeId::of::<String>()).expect("first create should succeed");
        let err = view.create_property_map("comment", TypeId::of::<String>());
        assert!(err.is_err());
    }

    #[test]
    fn usable_as_a_trait_object() {
        let mgr: &mut dyn TraceAddressPropertyManager =
            &mut DBTraceAddressPropertyManagerApiView::new(Box::new(MockManager::new()));
        mgr.create_property_map("a", TypeId::of::<i32>()).unwrap();
        assert_eq!(mgr.get_all_properties().len(), 1);
    }
}
