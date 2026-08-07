//! A single value entry (attribute or element) attached to a trace object.
//!
//! Java source: `ghidra.trace.model.target.TraceObjectValue`.
//!
//! Ported as a trait because it was selected as a cycle cut-point: `TraceObjectValue` and
//! `TraceObject` (the still-unported `crate::trace::seam_stubs::TraceObject`) reference each
//! other directly (`getParent`/`getChild` vs. an object's values), so neither can be a concrete
//! struct until both sides of the cycle exist.
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{ConflictResolution, TraceObject, TraceObjectSchema};

/// The outcome of [`TraceObjectValue::truncate_or_delete`].
///
/// Mirrors the three cases of the Java return value (`this`, `null`, or a newly generated entry)
/// without requiring ownership of `self` to be moved out of a `&mut self` method.
pub enum TruncateOrDelete {
    /// The one entry remains (possibly with an adjusted lifespan); no new entry was created.
    Unchanged,
    /// The entry was deleted entirely.
    Deleted,
    /// The given span split the lifespan in two; this is the newly generated entry for the later
    /// lifespan.
    Split(Box<dyn TraceObjectValue>),
}

/// A single value entry (attribute or element) attached to a [`TraceObject`], valid over some
/// [`Lifespan`].
///
/// Port of `ghidra.trace.model.target.TraceObjectValue`.
///
/// The Java `castValue()` convenience (an unchecked generic cast of [`Self::get_value`]) is
/// omitted: it is a raw, unchecked cast in Java, and there is no equivalent unchecked cast in
/// Rust for an unconstrained type parameter on an object-safe trait. Callers should downcast the
/// `Box<dyn Any + Send + Sync>` returned by [`Self::get_value`] directly (e.g. via
/// `Any::downcast_ref`).
pub trait TraceObjectValue: Send + Sync {
    /// Get the trace containing this value entry.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the parent object of this entry, or `None` if this is the root value.
    fn get_parent(&self) -> Option<Box<dyn TraceObject>>;

    /// Get the key identifying this child to its parent.
    fn get_entry_key(&self) -> String;

    /// Check if the given key (or alias) matches this entry's key.
    fn has_entry_key(&self, key_or_alias: &str) -> bool {
        match self.get_parent() {
            None => self.get_entry_key() == key_or_alias,
            Some(parent) => {
                self.get_entry_key() == parent.get_schema().check_aliased_attribute(key_or_alias)
            }
        }
    }

    /// Get the "canonical path" of this value.
    ///
    /// This is the parent's canonical path extended by this value's entry key. Note, in the case
    /// this value has a child object, this is not necessarily its canonical path.
    fn get_canonical_path(&self) -> KeyPath;

    /// Get the value.
    fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync>;

    /// Get the value as an object.
    ///
    /// Mirrors `TraceObjectValue.getChild()`: implementors should panic if [`Self::is_object`] is
    /// `false`, matching the Java `ClassCastException`.
    fn get_child(&self) -> Box<dyn TraceObject>;

    /// Check if the value is an object (i.e., a [`TraceObject`]).
    fn is_object(&self) -> bool;

    /// Check if this value represents its child's canonical location.
    ///
    /// The value is canonical if the parent's canonical path extended by this value's key gives
    /// the child's canonical path. If the value is not a child object, the value cannot be
    /// canonical.
    fn is_canonical(&self) -> bool;

    /// Get the (target) schema for the value.
    fn get_target_schema(&self) -> Box<dyn TraceObjectSchema> {
        self.get_parent()
            .expect("getTargetSchema() requires a parent, mirroring the Java NPE on a root value")
            .get_schema()
            .get_child_schema(&self.get_entry_key())
    }

    /// Set the lifespan of this entry, truncating duplicates.
    fn set_lifespan(&mut self, lifespan: Box<dyn Lifespan>);

    /// Set the lifespan of this entry.
    ///
    /// **NOTE:** For storage efficiency, when expanding the lifespan, the manager may coalesce
    /// this value with intersecting values having equal keys and values. Thus, the resulting
    /// lifespan may be larger than specified.
    ///
    /// Values cannot intersect and have the same key, otherwise the value of that key could not
    /// be uniquely determined at a given snap. Thus, when lifespans are being adjusted, such
    /// conflicts must be resolved.
    fn set_lifespan_with_resolution(
        &mut self,
        span: Box<dyn Lifespan>,
        resolution: ConflictResolution,
    ) -> Result<(), DuplicateKeyException>;

    /// Get the lifespan of this entry.
    fn get_lifespan(&self) -> Box<dyn Lifespan>;

    /// Set the minimum snap of this entry.
    ///
    /// See [`Self::set_lifespan`]. Pass `i64::MIN` for "since the beginning of time".
    fn set_min_snap(&mut self, min_snap: i64);

    /// Get the minimum snap of this entry, or `i64::MIN` for "since the beginning of time".
    fn get_min_snap(&self) -> i64;

    /// Set the maximum snap of this entry.
    ///
    /// See [`Self::set_lifespan`]. Pass `i64::MAX` for "to the end of time".
    fn set_max_snap(&mut self, max_snap: i64);

    /// Get the maximum snap of this entry, or `i64::MAX` for "to the end of time".
    fn get_max_snap(&self) -> i64;

    /// Delete this entry.
    fn delete(&mut self);

    /// Check if this value entry has been deleted.
    fn is_deleted(&self) -> bool;

    /// Modify the lifespan or delete this entry, such that it no longer intersects the given
    /// span.
    ///
    /// If the given span and the current lifespan are already disjoint, this does nothing. If the
    /// given span splits the current lifespan in two, then a new entry is created for the later
    /// lifespan.
    fn truncate_or_delete(&mut self, span: Box<dyn Lifespan>) -> TruncateOrDelete;

    /// Check if the schema designates this value as hidden.
    fn is_hidden(&self) -> bool {
        match self.get_parent() {
            None => false,
            Some(parent) => parent.get_schema().is_hidden(&self.get_entry_key()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject;
    use crate::program::model::lang::{CompilerSpec, Language};
    use crate::program::seam_stubs::DataTypeManagerOwner;
    use crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager;
    use crate::trace::model::listing::TraceCodeManager;
    use crate::trace::model::modules::{TraceModuleManager, TraceStaticMappingManager};
    use crate::trace::model::program::TraceProgramView;
    use crate::trace::model::trace::TraceProgramViewListener;
    use crate::trace::model::time::trace_time_manager::TraceTimeManager;
    use crate::trace::model::trace_time_viewport::TraceTimeViewport;
    use crate::trace::model::target::trace_object_manager::TraceObjectManager;
    use crate::trace::model::thread::TraceThreadManager;
    use crate::trace::seam_stubs::{
        TraceAddressPropertyManager, TraceBasedDataTypeManager, TraceBookmarkManager,
        TraceEquateManager, TraceMemoryManager,
        TracePlatformManager, TraceReferenceManager,
        TraceRegisterContextManager, TraceStackManager,
        TraceSymbolManager, TraceVariableSnapProgramView,
    };
    use crate::util::lock_hold::{Lock, LockHold};
    use crate::debug::api::tracermi::SchemaName;

    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.min,
                max,
            })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    struct MockLock;
    impl Lock for MockLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockTrace {
        lock: MockLock,
    }

    impl DomainObject for MockTrace {}

    impl DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(MockDataTypeManager)
        }
    }

    impl DataTypeManagerDomainObject for MockTrace {}

    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_emulator_cache_version(&mut self, _version: i64) {}

        fn get_emulator_cache_version(&self) -> i64 {
            0
        }

        fn get_base_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_address_property_manager(&self) -> Box<dyn TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bookmark_manager(&self) -> Box<dyn TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_breakpoint_manager(&self) -> Box<dyn TraceBreakpointManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_code_manager(&self) -> Box<dyn TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_base_data_type_manager(&self) -> Box<dyn TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_equate_manager(&self) -> Box<dyn TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform_manager(&self) -> Box<dyn TracePlatformManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_memory_manager(&self) -> Box<dyn TraceMemoryManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_module_manager(&self) -> Box<dyn TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_object_manager(&self) -> Box<dyn TraceObjectManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_reference_manager(&self) -> Box<dyn TraceReferenceManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_register_context_manager(&self) -> Box<dyn TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_stack_manager(&self) -> Box<dyn TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_static_mapping_manager(&self) -> Box<dyn TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_symbol_manager(&self) -> Box<dyn TraceSymbolManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread_manager(&self) -> Box<dyn TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_time_manager(&self) -> Box<dyn TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_program_view(&self, _snap: i64) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            Vec::new()
        }

        fn get_program_view(&self) -> Box<dyn TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }

        fn create_time_viewport(&self) -> Box<dyn TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }

        fn add_program_view_listener(&mut self, _listener: Box<dyn TraceProgramViewListener>) {}

        fn remove_program_view_listener(&mut self, _listener: &dyn TraceProgramViewListener) {}

        fn lock_read(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }

        fn lock_write(&self) -> LockHold<'_, dyn Lock> {
            LockHold::lock(&self.lock)
        }
    }

    struct MockSchema {
        name: SchemaName,
        hidden_keys: Vec<String>,
    }

    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            self.name.clone()
        }

        fn to_string(&self) -> String {
            self.name.to_string()
        }

        fn is_hidden(&self, name: &str) -> bool {
            self.hidden_keys.iter().any(|k| k == name)
        }

        fn check_aliased_attribute(&self, name: &str) -> String {
            if name == "alias" {
                "real".to_string()
            } else {
                name.to_string()
            }
        }
    }

    struct MockObjectKey(i32);

    impl crate::trace::seam_stubs::ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn crate::trace::seam_stubs::ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockLifeSet {
        empty: bool,
    }

    impl crate::trace::seam_stubs::LifeSet for MockLifeSet {
        fn is_empty(&self) -> bool {
            self.empty
        }
    }

    struct MockObject {
        schema: MockSchema,
    }

    impl TraceObject for MockObject {
        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema {
                name: self.schema.name.clone(),
                hidden_keys: self.schema.hidden_keys.clone(),
            })
        }

        fn get_object_key(&self) -> Box<dyn crate::trace::seam_stubs::ObjectKey> {
            Box::new(MockObjectKey(0))
        }

        fn get_life(&self) -> Box<dyn crate::trace::seam_stubs::LifeSet> {
            Box::new(MockLifeSet { empty: false })
        }
    }

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    struct MockTraceObjectValue {
        parent: Option<MockObject>,
        entry_key: String,
        path: KeyPath,
        value: i64,
        lifespan: MockLifespan,
        deleted: bool,
    }

    impl TraceObjectValue for MockTraceObjectValue {
        fn get_trace(&self) -> Box<dyn Trace> {
            Box::new(MockTrace { lock: MockLock })
        }

        fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
            self.parent.as_ref().map(|p| {
                Box::new(MockObject {
                    schema: MockSchema {
                        name: p.schema.name.clone(),
                        hidden_keys: p.schema.hidden_keys.clone(),
                    },
                }) as Box<dyn TraceObject>
            })
        }

        fn get_entry_key(&self) -> String {
            self.entry_key.clone()
        }

        fn get_canonical_path(&self) -> KeyPath {
            self.path.clone()
        }

        fn get_value(&self) -> Box<dyn std::any::Any + Send + Sync> {
            Box::new(self.value)
        }

        fn get_child(&self) -> Box<dyn TraceObject> {
            panic!("value is not an object")
        }

        fn is_object(&self) -> bool {
            false
        }

        fn is_canonical(&self) -> bool {
            false
        }

        fn set_lifespan(&mut self, lifespan: Box<dyn Lifespan>) {
            self.lifespan = MockLifespan {
                min: lifespan.lmin(),
                max: lifespan.lmax(),
            };
        }

        fn set_lifespan_with_resolution(
            &mut self,
            span: Box<dyn Lifespan>,
            resolution: ConflictResolution,
        ) -> Result<(), DuplicateKeyException> {
            if resolution == ConflictResolution::Deny {
                return Err(DuplicateKeyException::new(self.entry_key.clone()));
            }
            self.set_lifespan(span);
            Ok(())
        }

        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(MockLifespan {
                min: self.lifespan.min,
                max: self.lifespan.max,
            })
        }

        fn set_min_snap(&mut self, min_snap: i64) {
            self.lifespan.min = min_snap;
        }

        fn get_min_snap(&self) -> i64 {
            self.lifespan.min
        }

        fn set_max_snap(&mut self, max_snap: i64) {
            self.lifespan.max = max_snap;
        }

        fn get_max_snap(&self) -> i64 {
            self.lifespan.max
        }

        fn delete(&mut self) {
            self.deleted = true;
        }

        fn is_deleted(&self) -> bool {
            self.deleted
        }

        fn truncate_or_delete(&mut self, span: Box<dyn Lifespan>) -> TruncateOrDelete {
            if span.lmin() <= self.lifespan.min && span.lmax() >= self.lifespan.max {
                self.deleted = true;
                TruncateOrDelete::Deleted
            } else {
                TruncateOrDelete::Unchanged
            }
        }
    }

    fn make_value(entry_key: &str, parent: Option<MockObject>) -> MockTraceObjectValue {
        MockTraceObjectValue {
            parent,
            entry_key: entry_key.to_string(),
            path: KeyPath::of(&[entry_key]),
            value: 42,
            lifespan: MockLifespan { min: 0, max: 10 },
            deleted: false,
        }
    }

    #[test]
    fn has_entry_key_without_parent_matches_exact_key() {
        let value = make_value("foo", None);
        assert!(value.has_entry_key("foo"));
        assert!(!value.has_entry_key("bar"));
    }

    #[test]
    fn has_entry_key_resolves_alias_through_parent_schema() {
        let parent = MockObject {
            schema: MockSchema {
                name: SchemaName::new("Process"),
                hidden_keys: Vec::new(),
            },
        };
        let value = make_value("real", Some(parent));
        assert!(value.has_entry_key("alias"));
        assert!(value.has_entry_key("real"));
        assert!(!value.has_entry_key("other"));
    }

    #[test]
    fn is_hidden_without_parent_is_false() {
        let value = make_value("foo", None);
        assert!(!value.is_hidden());
    }

    #[test]
    fn is_hidden_delegates_to_parent_schema() {
        let parent = MockObject {
            schema: MockSchema {
                name: SchemaName::new("Process"),
                hidden_keys: vec!["secret".to_string()],
            },
        };
        let hidden = make_value("secret", Some(parent));
        assert!(hidden.is_hidden());

        let parent2 = MockObject {
            schema: MockSchema {
                name: SchemaName::new("Process"),
                hidden_keys: vec!["secret".to_string()],
            },
        };
        let visible = make_value("visible", Some(parent2));
        assert!(!visible.is_hidden());
    }

    #[test]
    fn set_lifespan_with_resolution_deny_reports_duplicate() {
        let mut value = make_value("foo", None);
        let err = value
            .set_lifespan_with_resolution(
                Box::new(MockLifespan { min: 0, max: 5 }),
                ConflictResolution::Deny,
            )
            .unwrap_err();
        assert_eq!(err.key(), "foo");
    }

    #[test]
    fn set_lifespan_with_resolution_truncate_updates_span() {
        let mut value = make_value("foo", None);
        value
            .set_lifespan_with_resolution(
                Box::new(MockLifespan { min: 1, max: 9 }),
                ConflictResolution::Truncate,
            )
            .unwrap();
        assert_eq!(value.get_min_snap(), 1);
        assert_eq!(value.get_max_snap(), 9);
    }

    #[test]
    fn truncate_or_delete_removes_entry_when_span_covers_lifespan() {
        let mut value = make_value("foo", None);
        let result = value.truncate_or_delete(Box::new(MockLifespan { min: 0, max: 10 }));
        assert!(matches!(result, TruncateOrDelete::Deleted));
        assert!(value.is_deleted());
    }

    #[test]
    fn truncate_or_delete_leaves_entry_when_span_disjoint() {
        let mut value = make_value("foo", None);
        let result = value.truncate_or_delete(Box::new(MockLifespan { min: 20, max: 30 }));
        assert!(matches!(result, TruncateOrDelete::Unchanged));
        assert!(!value.is_deleted());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut value: Box<dyn TraceObjectValue> = Box::new(make_value("foo", None));
        assert_eq!(value.get_entry_key(), "foo");
        assert!(!value.is_object());
        let downcast = value.get_value().downcast::<i64>().unwrap();
        assert_eq!(*downcast, 42);
        value.delete();
        assert!(value.is_deleted());
    }
}
