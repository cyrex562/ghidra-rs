//! A record of a target object in a debugger.
//!
//! Java source: `ghidra.trace.model.target.TraceObject`.
//!
//! Ported as a trait: this is the focal point of the "debug target model," a genuine open
//! extension point which the database layer (`DBTraceObject`) implements and which every trace
//! interface (`TraceThread`, `TraceModule`, ...) is projected from.
//!
//! # Reifying Java's `Class<? extends TraceObjectInterface>`
//!
//! Java identifies a trace interface by its class token and looks its schema metadata up
//! reflectively from the `@TraceObjectInfo` annotation. This crate already reifies that annotation
//! as the plain [`TraceObjectInfo`] struct, so the class-token parameters and return values here
//! become `TraceObjectInfo` values. Where Java's signature is generic in the interface type and
//! returns *instances* of it (`<I extends TraceObjectInterface> I queryInterface(Class<I>)`), the
//! token is instead reified by a Rust type parameter, mirroring
//! [`TraceObjectManager::query_all_interface`](crate::trace::model::target::trace_object_manager::TraceObjectManager::query_all_interface);
//! those methods carry `where Self: Sized` and so are unavailable through a trait object.
//!
//! # `Stream` returns
//!
//! Java's `Stream<? extends T>` returns become `Vec<Box<dyn T>>`, matching the convention already
//! established by [`TraceObjectManager`](crate::trace::model::target::trace_object_manager) for
//! this same object graph.
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::target::duplicate_key_exception::DuplicateKeyException;
use crate::trace::model::target::iface::trace_execution_stateful::KEY_STATE;
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::path::key_path::KeyPath;
use crate::trace::model::target::path::PathFilter;
use crate::trace::model::target::trace_object_val_path::TraceObjectValPath;
use crate::trace::model::target::trace_object_value::TraceObjectValue;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_execution_state::TraceExecutionState;
use crate::trace::model::trace_unique_object::TraceUniqueObject;
use crate::trace::seam_stubs::{LifeSet, TraceObjectSchema};
use crate::trace::model::target::iface::TraceObjectInterface;

/// The attribute holding a comma-separated list of extra schema interfaces an object provides
/// beyond those named by its schema.
///
/// Mirrors `TraceObject.EXTRA_INTERFACES_ATTRIBUTE_NAME`.
pub const EXTRA_INTERFACES_ATTRIBUTE_NAME: &str = "_extra_ifs";

/// The schema name of `TraceObjectInterface` itself, i.e., the root of the trace-interface
/// hierarchy, taken from its `@TraceObjectInfo` annotation.
///
/// [`TraceObject::find_suitable_interface`] short-circuits on it, mirroring the Java
/// `iface == TraceObjectInterface.class` check: every object trivially provides the root
/// interface.
pub const OBJECT_SCHEMA_NAME: &str = "OBJECT";

/// The schema name of `TraceMethod`, taken from its `@TraceObjectInfo` annotation.
///
/// `TraceMethod` itself is not ported yet, but [`TraceObject::is_method`] only ever needs its
/// schema name.
pub const METHOD_SCHEMA_NAME: &str = "Method";

/// A value which may be stored under an object's key: either a primitive/foreign value or an
/// object.
///
/// Mirrors the unconstrained `Object` of Java's `setValue`, matching the boxed-`Any` shape
/// [`TraceObjectValue::get_value`] already uses.
pub type ObjectValue = Box<dyn std::any::Any + Send + Sync>;

/// A strategy for resolving duplicate keys.
///
/// Port of the nested `ghidra.trace.model.target.TraceObject.ConflictResolution` enum.
///
/// Values are not permitted to have intersecting lifespans if they have the same parent and key,
/// since this would imply the value is not unique for a given parent, key, and snap. Thus, when
/// values and lifespans are being set that would result in conflicting entries, the conflict must
/// be resolved, either by clearing the span or by denying the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Truncate, split, or delete conflicting entries to make way for the specified lifespan.
    Truncate,
    /// Fail with [`DuplicateKeyException`] if the specified lifespan would result in conflicting
    /// entries.
    Deny,
    /// Adjust the new entry to fit into the span available, possibly ignoring it altogether.
    Adjust,
}

/// A record of a target object in a debugger.
///
/// Port of `ghidra.trace.model.target.TraceObject`.
///
/// This object supports querying for and obtaining the interfaces which constitute what the object
/// is and define how the client may interact with it. The object may also have children, e.g., a
/// process should likely have threads.
///
/// The objects are arranged in a directory with links permitted. Links come in the form of
/// object-valued attributes or elements where the path does not match the object value's path.
/// Thus, the overall structure remains a tree, but by resolving links, the model may be treated as
/// a directed graph, likely containing cycles.
///
/// The implementation must guarantee that distinct objects from the same model do not share the
/// same path. That is, checking for object identity is sufficient to check that two variables
/// refer to the same object. The defaults below rely on that guarantee: where Java can simply
/// `return this`, a Rust default method holding only `&self` cannot produce an owned
/// `Box<dyn TraceObject>`, so it re-obtains a handle to this same object by looking its canonical
/// path up in the trace's object manager.
pub trait TraceObject: TraceUniqueObject + Send + Sync {
    /// Get the trace containing this object.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the database key for this object.
    fn get_key(&self) -> i64;

    /// Get the root of the tree containing this object.
    fn get_root(&self) -> Box<dyn TraceObject>;

    /// Get the canonical path of this object.
    fn get_canonical_path(&self) -> KeyPath;

    /// Get all ranges of this object's life, i.e., the union of the lifespans of all canonical
    /// parent values.
    ///
    /// The result is the range set for snaps at which this object is considered "inserted."
    fn get_life(&self) -> Box<dyn LifeSet>;

    /// Check if the object is alive at the given snap.
    ///
    /// This is preferable to [`Self::get_life`] when we only need to check one snap.
    fn is_alive(&self, snap: i64) -> bool;

    /// Check if the object is alive at all in the given span.
    ///
    /// Mirrors the `isAlive(Lifespan)` overload of [`Self::is_alive`].
    fn is_alive_span(&self, span: Lifespan) -> bool;

    /// Insert this object at its canonical path for the given lifespan.
    ///
    /// Any ancestor which does not exist is created. Values' lifespans are added or expanded to
    /// contain the given lifespan. Only the canonical path is considered when looking for existing
    /// ancestry. Returns the value path from root to the newly inserted object.
    fn insert(
        &mut self,
        lifespan: Lifespan,
        resolution: ConflictResolution,
    ) -> Box<dyn TraceObjectValPath>;

    /// Remove this object from its canonical path for the given span.
    ///
    /// Truncates the lifespan of this object's canonical parent value by the given span. If the
    /// parent value's lifespan is contained in the given span, the parent value is deleted.
    fn remove(&mut self, span: Lifespan);

    /// Remove this object and its successors from their canonical paths for the given span.
    ///
    /// Truncates the lifespans of this object's parent values and all canonical values succeeding
    /// this object. If a truncated value's lifespan is contained in the given span, the value is
    /// deleted.
    fn remove_tree(&mut self, span: Lifespan);

    /// Get the parent value along this object's canonical path for a given snapshot.
    ///
    /// To be the canonical parent value at a given snapshot, three things must be true: 1) the
    /// parent object must have this object's path with the final key removed; 2) the parent
    /// value's entry key must equal the final key of this object's path; 3) the value's lifespan
    /// must contain the given snapshot. If no value satisfies these, `None` is returned, and the
    /// object and its subtree are said to be "detached" at the given snapshot.
    fn get_canonical_parent(&self, snap: i64) -> Option<Box<dyn TraceObjectValue>>;

    /// Get the parent values along this object's canonical path for a given lifespan.
    ///
    /// The same three conditions as [`Self::get_canonical_parent`] apply, except the value's
    /// lifespan need only *intersect* the given lifespan. If the result is empty, the object and
    /// its subtree are said to be "detached" during the given lifespan.
    fn get_canonical_parents(&self, lifespan: Lifespan) -> Vec<Box<dyn TraceObjectValue>>;

    /// Check if this object is the root.
    fn is_root(&self) -> bool;

    /// Get all paths actually leading to this object, from the root, within the given span.
    ///
    /// Every value entry on each path must intersect the span. Aliased keys are excluded.
    fn get_all_paths(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all the interfaces provided by this object, according to the schema.
    ///
    /// Java returns the interfaces' class tokens; see the [module docs](self) for why they are
    /// reified as [`TraceObjectInfo`] here.
    fn get_interfaces(&self) -> Vec<TraceObjectInfo>;

    /// Request the specified interface provided by this object, or `None` if not provided.
    ///
    /// Java's `Class<I>` argument is reified by the type parameter `I`; see the
    /// [module docs](self).
    fn query_interface<I: TraceObjectInterface>(&self) -> Option<I>
    where
        Self: Sized;

    /// Get all values intersecting the given span and whose child is this object.
    ///
    /// Aliased keys are excluded.
    fn get_parents(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get all values (elements and attributes) of this object intersecting the given span.
    ///
    /// Aliased keys are excluded.
    fn get_values(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get values with the given key intersecting the given span.
    ///
    /// If the key is an alias, the target key's values are retrieved instead. Mirrors the
    /// `getValues(Lifespan, String)` overload of [`Self::get_values`].
    fn get_values_by_key(&self, span: Lifespan, key: &str) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get values with the given key intersecting the given span, ordered by time.
    ///
    /// If the key is an alias, the target key's values are retrieved instead. Pass `forward` to
    /// order from least- to most-recent, or `false` for most- to least-recent.
    fn get_ordered_values(
        &self,
        span: Lifespan,
        key: &str,
        forward: bool,
    ) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get all elements of this object intersecting the given span.
    fn get_elements(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get all attributes of this object intersecting the given span.
    ///
    /// Aliased keys are excluded.
    fn get_attributes(&self, span: Lifespan) -> Vec<Box<dyn TraceObjectValue>>;

    /// Get the value entry for the given snap and key.
    ///
    /// If the key is an alias, the target key's value is retrieved instead.
    fn get_value(&self, snap: i64, key: &str) -> Option<Box<dyn TraceObjectValue>>;

    /// Get the value entry for the given snap and element index.
    ///
    /// Equivalent to [`Self::get_value`], but converts the index to a key, i.e., adds brackets.
    fn get_element(&self, snap: i64, index: &str) -> Option<Box<dyn TraceObjectValue>> {
        self.get_value(snap, &KeyPath::make_key(index))
    }

    /// Get the value entry for the given snap and numeric element index.
    ///
    /// Equivalent to [`Self::get_element`], but converts the index to a string in decimal.
    fn get_element_num(&self, snap: i64, index: i64) -> Option<Box<dyn TraceObjectValue>> {
        self.get_element(snap, &index.to_string())
    }

    /// Get the value entry for the given snap and attribute name.
    ///
    /// Equivalent to [`Self::get_value`], except it validates that `name` is not an index. The
    /// Java `IllegalArgumentException` becomes a panic.
    fn get_attribute(&self, snap: i64, name: &str) -> Option<Box<dyn TraceObjectValue>> {
        assert!(!KeyPath::is_index(name), "{name} is an index, not an attribute name");
        self.get_value(snap, name)
    }

    /// Get all ancestor values of this object matching the given filter, intersecting the given
    /// span.
    ///
    /// Aliased keys are excluded; the filter should be formulated to use the aliases' target
    /// attributes. `root_filter` matches path keys relative to the root.
    fn get_ancestors_root(
        &self,
        span: Lifespan,
        root_filter: &dyn PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all ancestor values of this object matching the given filter, intersecting the given
    /// span.
    ///
    /// As [`Self::get_ancestors_root`], except `relative_filter` matches path keys relative to
    /// this object.
    fn get_ancestors(
        &self,
        span: Lifespan,
        relative_filter: &dyn PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all successor values of this object matching the given filter, intersecting the given
    /// span.
    ///
    /// Aliased keys are excluded; the filter should be formulated to use the aliases' target
    /// attributes. `relative_filter` matches path keys relative to this object.
    fn get_successors(
        &self,
        span: Lifespan,
        relative_filter: &dyn PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all successor values of this object at the given relative path, intersecting the given
    /// span, ordered by time.
    ///
    /// Pass `forward` to order from least- to most-recent, or `false` for most- to least-recent.
    fn get_ordered_successors(
        &self,
        span: Lifespan,
        relative_path: &KeyPath,
        forward: bool,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Get all canonical successor values of this object matching the given filter.
    ///
    /// If an object has a disjoint life, i.e., multiple canonical parents, then only the
    /// least-recent of those is traversed. Aliased keys are excluded; those can't be canonical
    /// anyway. By definition, a primitive value is not canonical, even if it is the final value in
    /// the path.
    fn get_canonical_successors(
        &self,
        relative_filter: &dyn PathFilter,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Set a value for the given lifespan, resolving duplicate keys by the given strategy.
    ///
    /// If the key is an alias, the target key's value is set instead. Setting `None` effectively
    /// deletes the value for the given lifespan and returns `None`. Java's `DuplicateKeyException`
    /// becomes an `Err`, mirroring
    /// [`TraceObjectValue::set_lifespan_with_resolution`]'s treatment of the same exception.
    fn set_value_with_resolution(
        &mut self,
        lifespan: Lifespan,
        key: &str,
        value: Option<ObjectValue>,
        resolution: ConflictResolution,
    ) -> Result<Option<Box<dyn TraceObjectValue>>, DuplicateKeyException>;

    /// Set a value for the given lifespan, truncating existing entries.
    ///
    /// Values of the same key intersecting the given lifespan are either truncated or deleted. If
    /// the key is an alias, the target key's value is set instead.
    fn set_value(
        &mut self,
        lifespan: Lifespan,
        key: &str,
        value: Option<ObjectValue>,
    ) -> Option<Box<dyn TraceObjectValue>> {
        self.set_value_with_resolution(lifespan, key, value, ConflictResolution::Truncate)
            .expect("Truncate never denies a duplicate key")
    }

    /// Set an attribute for the given lifespan.
    ///
    /// Equivalent to [`Self::set_value`], except it verifies the key is an attribute name. The
    /// Java `IllegalArgumentException` becomes a panic.
    fn set_attribute(
        &mut self,
        lifespan: Lifespan,
        name: &str,
        value: Option<ObjectValue>,
    ) -> Option<Box<dyn TraceObjectValue>> {
        assert!(!KeyPath::is_index(name), "{name} is an index, not an attribute name");
        self.set_value(lifespan, name, value)
    }

    /// Set an element for the given lifespan.
    ///
    /// Equivalent to [`Self::set_value`], except it converts the index to a key, i.e., adds
    /// brackets.
    fn set_element(
        &mut self,
        lifespan: Lifespan,
        index: &str,
        value: Option<ObjectValue>,
    ) -> Option<Box<dyn TraceObjectValue>> {
        self.set_value(lifespan, &KeyPath::make_key(index), value)
    }

    /// Set an element for the given lifespan, by numeric index.
    ///
    /// Equivalent to [`Self::set_element`], but converts the index to a string in decimal.
    fn set_element_num(
        &mut self,
        lifespan: Lifespan,
        index: i64,
        value: Option<ObjectValue>,
    ) -> Option<Box<dyn TraceObjectValue>> {
        self.set_element(lifespan, &index.to_string(), value)
    }

    /// Get the schema for this object.
    fn get_schema(&self) -> Box<dyn TraceObjectSchema>;

    /// Search for ancestors having the given interface, returning the paths to their values.
    fn find_ancestors_interface(
        &self,
        span: Lifespan,
        iface: &TraceObjectInfo,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Search for ancestors having the given interface and retrieve those interfaces.
    ///
    /// Java's `Class<I>` argument is reified by the type parameter `I`; see the
    /// [module docs](self).
    fn query_ancestors_interface<I: TraceObjectInterface>(&self, span: Lifespan) -> Vec<I>
    where
        Self: Sized;

    /// Search for ancestors on the canonical path having the given interface.
    ///
    /// The object may not yet be inserted at its canonical path.
    fn find_canonical_ancestors_interface(
        &self,
        iface: &TraceObjectInfo,
    ) -> Vec<Box<dyn TraceObject>>;

    /// Search for ancestors on the canonical path having the given interface and retrieve those
    /// interfaces.
    ///
    /// The object may not yet be inserted at its canonical path. Java's `Class<I>` argument is
    /// reified by the type parameter `I`; see the [module docs](self).
    fn query_canonical_ancestors_interface<I: TraceObjectInterface>(&self) -> Vec<I>
    where
        Self: Sized;

    /// Search for successors having the given interface, returning the paths to their values.
    ///
    /// Pass `require_canonical` to require the objects be found within their canonical container.
    fn find_successors_interface(
        &self,
        span: Lifespan,
        iface: &TraceObjectInfo,
        require_canonical: bool,
    ) -> Vec<Box<dyn TraceObjectValPath>>;

    /// Search for successors having the given interface and retrieve those interfaces.
    ///
    /// Java's `Class<I>` argument is reified by the type parameter `I`; see the
    /// [module docs](self).
    fn query_successors_interface<I: TraceObjectInterface>(
        &self,
        span: Lifespan,
        require_canonical: bool,
    ) -> Vec<I>
    where
        Self: Sized;

    /// Delete this object along with parent and child value entries referring to it.
    ///
    /// **Warning:** this removes the object from the manager *entirely*, not just over a given
    /// span. In general, this is used for cleaning and maintenance. Consider [`Self::remove`] or
    /// [`TraceObjectValue::delete`] instead. Note this does not delete the child objects or any
    /// successors. It is not recommended to invoke this on the root object, since it cannot be
    /// replaced without first clearing the manager.
    fn delete(&mut self);

    /// Check if this object represents a method at the given snap.
    fn is_method(&self, snap: i64) -> bool {
        if self
            .get_schema()
            .get_interfaces()
            .iter()
            .any(|i| i.schema_name == METHOD_SCHEMA_NAME)
        {
            return true;
        }
        let Some(extras) = self.get_attribute(snap, EXTRA_INTERFACES_ATTRIBUTE_NAME) else {
            return false;
        };
        match extras.get_value().downcast::<String>() {
            // Not ideal, but it's not a substring of any other schema interface....
            Ok(val) => val.contains("Method"),
            Err(_) => false,
        }
    }

    /// Re-obtain an owned handle to this same object from the trace's object manager.
    ///
    /// Java's defaults below can simply `return this`; a Rust default method holds only `&self`
    /// and cannot produce an owned `Box<dyn TraceObject>`. Since the model guarantees at most one
    /// object per canonical path, looking this object's own canonical path up in the manager
    /// yields a handle to this same object.
    fn find_self(&self) -> Option<Box<dyn TraceObject>> {
        self.get_trace()
            .get_object_manager()
            .get_object_by_canonical_path(&self.get_canonical_path())
    }

    /// Search for a suitable object having the given interface, or `None` if not found.
    ///
    /// This operates by examining the schema for a unique suitable path, without regard to
    /// lifespans. If needed, the caller should inspect the object's life.
    fn find_suitable_interface(&self, iface: &TraceObjectInfo) -> Option<Box<dyn TraceObject>> {
        if iface.schema_name == OBJECT_SCHEMA_NAME {
            return self.find_self();
        }
        let path = self
            .get_root()
            .get_schema()
            .search_for_suitable(&iface.schema_name, &self.get_canonical_path())?;
        self.get_trace()
            .get_object_manager()
            .get_object_by_canonical_path(&path)
    }

    /// Search for a suitable canonical container of the given interface, or `None` if not found.
    fn find_suitable_container_interface(
        &self,
        iface: &TraceObjectInfo,
    ) -> Option<Box<dyn TraceObject>> {
        let path = self
            .get_root()
            .get_schema()
            .search_for_suitable_container(&iface.schema_name, &self.get_canonical_path())?;
        self.get_trace()
            .get_object_manager()
            .get_object_by_canonical_path(&path)
    }

    /// Search for a suitable object having the given schema, or `None` if not found.
    ///
    /// This operates by examining the schema for a unique suitable path, without regard to
    /// lifespans. If needed, the caller should inspect the object's life.
    fn find_suitable_schema(&self, schema: &dyn TraceObjectSchema) -> Option<Box<dyn TraceObject>> {
        let path = self
            .get_root()
            .get_schema()
            .search_for_suitable_schema(schema, &self.get_canonical_path())?;
        self.get_trace()
            .get_object_manager()
            .get_object_by_canonical_path(&path)
    }

    /// Search for a suitable register container, or `None` if not found.
    ///
    /// `frame_level` must be 0 if not applicable.
    fn find_register_container(&self, frame_level: i32) -> Option<Box<dyn TraceObject>> {
        let manager = self.get_trace().get_object_manager();
        let canonical = self.get_canonical_path();
        for pattern in self
            .get_root()
            .get_schema()
            .search_for_register_container(frame_level, &canonical)
        {
            let path = pattern.as_path();
            // Mirrors PathPattern.getSingletonPath(), which is null for a wildcard pattern.
            if path.contains_wildcard() {
                continue;
            }
            if let Some(regs_obj) = manager.get_object_by_canonical_path(path) {
                return Some(regs_obj);
            }
        }
        None
    }

    /// Get the execution state, if applicable, of this object.
    ///
    /// This searches for the conventional stateful object defining this object's execution state.
    /// If such an object does not exist, `None` is returned. If one does exist, then its execution
    /// state at the given snap is returned. If that state is unset, it is assumed
    /// [`TraceExecutionState::Inactive`].
    fn get_execution_state(&self, snap: i64) -> Option<TraceExecutionState> {
        // Mirrors TraceExecutionStateful's @TraceObjectInfo annotation; the interface's own
        // `trace_object_info()` requires `Self: Sized` and so cannot be reached without a
        // concrete implementor.
        let stateful_info = TraceObjectInfo::new(
            "ExecutionStateful",
            "exec stateful",
            [KEY_STATE],
            [] as [&str; 0],
        );
        let stateful = self.find_suitable_interface(&stateful_info)?;
        let Some(state_val) = stateful.get_attribute(snap, KEY_STATE) else {
            return Some(TraceExecutionState::Inactive);
        };
        let name = state_val
            .get_value()
            .downcast::<String>()
            .expect("the _state attribute holds a TraceExecutionState name");
        Some(
            TraceExecutionState::value_of(&name)
                .unwrap_or_else(|| panic!("no TraceExecutionState named {name}")),
        )
    }
}

/// Emits a "not exercised by this smoke test" body for every required [`TraceObject`] member
/// *except* `get_schema`, `get_life`, and `get_canonical_path`, which the crate's test mocks
/// generally do care about and so spell out themselves.
///
/// [`TraceObject`] has 45 members; most mocks of it in this crate only ever pass an object around
/// opaquely (as a value entry's parent or child, say) and exercise two or three of them. Without
/// this, each such mock would carry ~35 lines of identical boilerplate. Every path is fully
/// qualified so the macro can be invoked from any module regardless of its imports.
#[cfg(test)]
macro_rules! unimplemented_trace_object_members {
    () => {
        fn get_trace(&self) -> Box<dyn $crate::trace::model::trace::Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_key(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_root(&self) -> Box<dyn $crate::trace::model::target::trace_object::TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_alive(&self, _snap: i64) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_alive_span(&self, _span: $crate::trace::model::lifespan::Lifespan) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn insert(
            &mut self,
            _lifespan: $crate::trace::model::lifespan::Lifespan,
            _resolution: $crate::trace::model::target::trace_object::ConflictResolution,
        ) -> Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath> {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove(&mut self, _span: $crate::trace::model::lifespan::Lifespan) {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove_tree(&mut self, _span: $crate::trace::model::lifespan::Lifespan) {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_parent(
            &self,
            _snap: i64,
        ) -> Option<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_parents(
            &self,
            _lifespan: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_root(&self) -> bool {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_all_paths(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_interfaces(
            &self,
        ) -> Vec<$crate::trace::model::target::info::trace_object_info::TraceObjectInfo> {
            Vec::new()
        }

        fn query_interface<I: $crate::trace::model::target::iface::TraceObjectInterface>(&self) -> Option<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parents(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_values(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_values_by_key(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _key: &str,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ordered_values(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _key: &str,
            _forward: bool,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_elements(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_attributes(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_value(
            &self,
            _snap: i64,
            _key: &str,
        ) -> Option<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ancestors_root(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _root_filter: &dyn $crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ancestors(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _relative_filter: &dyn $crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_successors(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _relative_filter: &dyn $crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_ordered_successors(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _relative_path: &$crate::trace::model::target::path::key_path::KeyPath,
            _forward: bool,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_successors(
            &self,
            _relative_filter: &dyn $crate::trace::model::target::path::PathFilter,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn set_value_with_resolution(
            &mut self,
            _lifespan: $crate::trace::model::lifespan::Lifespan,
            _key: &str,
            _value: Option<$crate::trace::model::target::trace_object::ObjectValue>,
            _resolution: $crate::trace::model::target::trace_object::ConflictResolution,
        ) -> Result<
            Option<Box<dyn $crate::trace::model::target::trace_object_value::TraceObjectValue>>,
            $crate::trace::model::target::duplicate_key_exception::DuplicateKeyException,
        > {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_ancestors_interface(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _iface: &$crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_ancestors_interface<I: $crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_canonical_ancestors_interface(
            &self,
            _iface: &$crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object::TraceObject>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_canonical_ancestors_interface<
            I: $crate::trace::model::target::iface::TraceObjectInterface,
        >(
            &self,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn find_successors_interface(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _iface: &$crate::trace::model::target::info::trace_object_info::TraceObjectInfo,
            _require_canonical: bool,
        ) -> Vec<Box<dyn $crate::trace::model::target::trace_object_val_path::TraceObjectValPath>>
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn query_successors_interface<I: $crate::trace::model::target::iface::TraceObjectInterface>(
            &self,
            _span: $crate::trace::model::lifespan::Lifespan,
            _require_canonical: bool,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            unimplemented!("not exercised by this smoke test")
        }

        fn delete(&mut self) {
            unimplemented!("not exercised by this smoke test")
        }
    };
}

#[cfg(test)]
pub(crate) use unimplemented_trace_object_members;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::api::tracermi::SchemaName;
    use crate::trace::seam_stubs::ObjectKey;
    use std::collections::HashMap;

    struct MockObjectKey(i32);

    impl ObjectKey for MockObjectKey {
        fn equals(&self, obj: &dyn std::any::Any) -> bool {
            obj.downcast_ref::<MockObjectKey>()
                .is_some_and(|other| other.0 == self.0)
        }

        fn hash_code(&self) -> i32 {
            self.0
        }

        fn compare_to(&self, that: &dyn ObjectKey) -> i32 {
            self.hash_code() - that.hash_code()
        }
    }

    struct MockLifeSet;

    impl LifeSet for MockLifeSet {
        fn is_empty(&self) -> bool {
            false
        }
    }

    struct MockSchema {
        interfaces: Vec<TraceObjectInfo>,
    }

    impl TraceObjectSchema for MockSchema {
        fn get_name(&self) -> SchemaName {
            SchemaName::new("Mock")
        }

        fn to_string(&self) -> String {
            "Mock".to_string()
        }

        fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
            self.interfaces.clone()
        }
    }

    /// A value entry which only carries a string, enough to exercise the `_extra_ifs` lookup.
    struct MockValue {
        key: String,
        value: String,
    }

    impl TraceObjectValue for MockValue {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_parent(&self) -> Option<Box<dyn TraceObject>> {
            None
        }

        fn get_entry_key(&self) -> String {
            self.key.clone()
        }

        fn get_canonical_path(&self) -> KeyPath {
            KeyPath::of(&[self.key.as_str()])
        }

        fn get_value(&self) -> ObjectValue {
            Box::new(self.value.clone())
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

        fn set_lifespan(&mut self, _lifespan: Lifespan) {}

        fn set_lifespan_with_resolution(
            &mut self,
            _span: Lifespan,
            _resolution: ConflictResolution,
        ) -> Result<(), DuplicateKeyException> {
            Ok(())
        }

        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }

        fn set_min_snap(&mut self, _min_snap: i64) {}

        fn get_min_snap(&self) -> i64 {
            0
        }

        fn set_max_snap(&mut self, _max_snap: i64) {}

        fn get_max_snap(&self) -> i64 {
            10
        }

        fn delete(&mut self) {}

        fn is_deleted(&self) -> bool {
            false
        }

        fn truncate_or_delete(
            &mut self,
            _span: Lifespan,
        ) -> crate::trace::model::target::trace_object_value::TruncateOrDelete {
            crate::trace::model::target::trace_object_value::TruncateOrDelete::Unchanged
        }
    }

    /// An object backed by a plain key-to-string map, so the key-conversion defaults
    /// (`get_element`, `get_attribute`, `set_element`, ...) can be observed directly.
    struct MockObject {
        interfaces: Vec<TraceObjectInfo>,
        values: HashMap<String, String>,
    }

    impl MockObject {
        fn new() -> Self {
            Self {
                interfaces: Vec::new(),
                values: HashMap::new(),
            }
        }
    }

    impl TraceUniqueObject for MockObject {
        fn get_object_key(&self) -> Box<dyn ObjectKey> {
            Box::new(MockObjectKey(0))
        }

        fn is_deleted(&self) -> bool {
            false
        }
    }

    impl TraceObject for MockObject {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_key(&self) -> i64 {
            0
        }

        fn get_root(&self) -> Box<dyn TraceObject> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_canonical_path(&self) -> KeyPath {
            KeyPath::root()
        }

        fn get_life(&self) -> Box<dyn LifeSet> {
            Box::new(MockLifeSet)
        }

        fn is_alive(&self, snap: i64) -> bool {
            (0..=10).contains(&snap)
        }

        fn is_alive_span(&self, span: Lifespan) -> bool {
            span.lmin() <= 10 && span.lmax() >= 0
        }

        fn insert(
            &mut self,
            _lifespan: Lifespan,
            _resolution: ConflictResolution,
        ) -> Box<dyn TraceObjectValPath> {
            unimplemented!("not exercised by this smoke test")
        }

        fn remove(&mut self, _span: Lifespan) {}

        fn remove_tree(&mut self, _span: Lifespan) {}

        fn get_canonical_parent(&self, _snap: i64) -> Option<Box<dyn TraceObjectValue>> {
            None
        }

        fn get_canonical_parents(&self, _lifespan: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn is_root(&self) -> bool {
            true
        }

        fn get_all_paths(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_interfaces(&self) -> Vec<TraceObjectInfo> {
            self.interfaces.clone()
        }

        fn query_interface<I: TraceObjectInterface>(&self) -> Option<I>
        where
            Self: Sized,
        {
            None
        }

        fn get_parents(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_values(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_values_by_key(&self, _span: Lifespan, _key: &str) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_ordered_values(
            &self,
            _span: Lifespan,
            _key: &str,
            _forward: bool,
        ) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_elements(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_attributes(&self, _span: Lifespan) -> Vec<Box<dyn TraceObjectValue>> {
            Vec::new()
        }

        fn get_value(&self, _snap: i64, key: &str) -> Option<Box<dyn TraceObjectValue>> {
            self.values.get(key).map(|v| {
                Box::new(MockValue {
                    key: key.to_string(),
                    value: v.clone(),
                }) as Box<dyn TraceObjectValue>
            })
        }

        fn get_ancestors_root(
            &self,
            _span: Lifespan,
            _root_filter: &dyn PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_ancestors(
            &self,
            _span: Lifespan,
            _relative_filter: &dyn PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_successors(
            &self,
            _span: Lifespan,
            _relative_filter: &dyn PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_ordered_successors(
            &self,
            _span: Lifespan,
            _relative_path: &KeyPath,
            _forward: bool,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn get_canonical_successors(
            &self,
            _relative_filter: &dyn PathFilter,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn set_value_with_resolution(
            &mut self,
            _lifespan: Lifespan,
            key: &str,
            value: Option<ObjectValue>,
            resolution: ConflictResolution,
        ) -> Result<Option<Box<dyn TraceObjectValue>>, DuplicateKeyException> {
            if resolution == ConflictResolution::Deny && self.values.contains_key(key) {
                return Err(DuplicateKeyException::new(key));
            }
            let Some(value) = value else {
                self.values.remove(key);
                return Ok(None);
            };
            let value = *value
                .downcast::<String>()
                .expect("this mock only stores strings");
            self.values.insert(key.to_string(), value.clone());
            Ok(Some(Box::new(MockValue {
                key: key.to_string(),
                value,
            })))
        }

        fn get_schema(&self) -> Box<dyn TraceObjectSchema> {
            Box::new(MockSchema {
                interfaces: self.interfaces.clone(),
            })
        }

        fn find_ancestors_interface(
            &self,
            _span: Lifespan,
            _iface: &TraceObjectInfo,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn query_ancestors_interface<I: TraceObjectInterface>(&self, _span: Lifespan) -> Vec<I>
        where
            Self: Sized,
        {
            Vec::new()
        }

        fn find_canonical_ancestors_interface(
            &self,
            _iface: &TraceObjectInfo,
        ) -> Vec<Box<dyn TraceObject>> {
            Vec::new()
        }

        fn query_canonical_ancestors_interface<I: TraceObjectInterface>(&self) -> Vec<I>
        where
            Self: Sized,
        {
            Vec::new()
        }

        fn find_successors_interface(
            &self,
            _span: Lifespan,
            _iface: &TraceObjectInfo,
            _require_canonical: bool,
        ) -> Vec<Box<dyn TraceObjectValPath>> {
            Vec::new()
        }

        fn query_successors_interface<I: TraceObjectInterface>(
            &self,
            _span: Lifespan,
            _require_canonical: bool,
        ) -> Vec<I>
        where
            Self: Sized,
        {
            Vec::new()
        }

        fn delete(&mut self) {}
    }

    fn method_info() -> TraceObjectInfo {
        TraceObjectInfo::new(METHOD_SCHEMA_NAME, "method", [] as [&str; 0], [] as [&str; 0])
    }

    #[test]
    fn extra_interfaces_attribute_name_matches_java() {
        assert_eq!(EXTRA_INTERFACES_ATTRIBUTE_NAME, "_extra_ifs");
    }

    #[test]
    fn is_method_is_true_when_schema_declares_the_method_interface() {
        let mut obj = MockObject::new();
        obj.interfaces.push(method_info());
        assert!(obj.is_method(0));
    }

    #[test]
    fn is_method_is_true_when_extra_interfaces_names_a_method() {
        let mut obj = MockObject::new();
        obj.values.insert(
            EXTRA_INTERFACES_ATTRIBUTE_NAME.to_string(),
            "Togglable,Method".to_string(),
        );
        assert!(obj.is_method(0));
    }

    #[test]
    fn is_method_is_false_without_schema_or_extra_interfaces() {
        let mut obj = MockObject::new();
        obj.interfaces.push(TraceObjectInfo::new(
            "Aggregate",
            "aggregate",
            [] as [&str; 0],
            [] as [&str; 0],
        ));
        obj.values.insert(
            EXTRA_INTERFACES_ATTRIBUTE_NAME.to_string(),
            "Togglable,Activatable".to_string(),
        );
        assert!(!obj.is_method(0));
    }

    #[test]
    fn element_accessors_bracket_the_index() {
        let mut obj = MockObject::new();
        obj.set_element(Lifespan::span(0, 10), "1", Some(Box::new("one".to_string())));
        // The element must be stored under the bracketed key, per KeyPath.makeKey.
        assert_eq!(obj.values.get("[1]").map(String::as_str), Some("one"));
        assert!(obj.get_element(0, "1").is_some());
        assert!(obj.get_value(0, "1").is_none());
    }

    #[test]
    fn numeric_element_index_is_rendered_in_decimal() {
        let mut obj = MockObject::new();
        obj.set_element_num(Lifespan::span(0, 10), 12, Some(Box::new("twelve".to_string())));
        assert_eq!(obj.values.get("[12]").map(String::as_str), Some("twelve"));
        let value = obj.get_element_num(0, 12).expect("element 12 was just set");
        assert_eq!(value.get_entry_key(), "[12]");
    }

    #[test]
    fn attribute_accessors_reject_an_index_key() {
        let obj = MockObject::new();
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| obj.get_attribute(0, "[1]")));
        assert!(result.is_err());
    }

    #[test]
    fn set_value_defaults_to_truncating_conflicts() {
        let mut obj = MockObject::new();
        obj.set_value(Lifespan::span(0, 10), "k", Some(Box::new("a".to_string())));
        // Unlike Deny, the default resolution overwrites rather than reporting a duplicate.
        obj.set_value(Lifespan::span(0, 10), "k", Some(Box::new("b".to_string())));
        assert_eq!(obj.values.get("k").map(String::as_str), Some("b"));

        let denied = obj.set_value_with_resolution(
            Lifespan::span(0, 10),
            "k",
            Some(Box::new("c".to_string())),
            ConflictResolution::Deny,
        );
        let err = denied.err().expect("Deny reports the duplicate key");
        assert_eq!(err.key(), "k");
    }

    #[test]
    fn setting_a_null_value_removes_the_entry() {
        let mut obj = MockObject::new();
        obj.set_attribute(Lifespan::span(0, 10), "a", Some(Box::new("x".to_string())));
        assert!(obj.get_attribute(0, "a").is_some());
        assert!(obj.set_attribute(Lifespan::span(0, 10), "a", None).is_none());
        assert!(obj.get_attribute(0, "a").is_none());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut obj = MockObject::new();
        obj.values.insert("k".to_string(), "v".to_string());
        let object: Box<dyn TraceObject> = Box::new(obj);
        assert!(object.is_alive(5));
        assert!(!object.is_alive(11));
        assert!(object.is_root());
        assert_eq!(object.get_value(0, "k").unwrap().get_entry_key(), "k");
    }
}
