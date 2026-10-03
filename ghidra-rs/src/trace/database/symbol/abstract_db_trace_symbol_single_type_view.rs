//! Port of `ghidra.trace.database.symbol.AbstractDBTraceSymbolSingleTypeView`.
//!
//! A per-symbol-type view over a [`DBCachedObjectStore`]: the storage and lookup machinery
//! `DBTraceSymbolManager` shares across all its per-type views (labels, namespaces, classes, ...).
//!
//! The Java class carries 6 instance fields and has two in-repo subclasses
//! (`AbstractDBTraceSymbolSingleTypeWithAddressView`, `AbstractDBTraceSymbolSingleTypeWithLocationView`,
//! neither yet ported), so per this crate's abstract-base shape rule it is split in two:
//! [`AbstractDBTraceSymbolSingleTypeViewBase`] holds the fields and every method the Java class
//! gives a body to; [`AbstractDBTraceSymbolSingleTypeView`] is the type-erased trait.
//!
//! Unlike the usual case this shape rule targets, the Java class declares no `abstract` method:
//! `constructView()` is its only overridable hook, and neither in-repo subclass overrides it (both
//! only add new methods of their own). So the trait here does not exist to hold Java `abstract`
//! declarations -- there are none. It exists for the same reason the Java class itself is `public
//! abstract` despite being fully concrete: `DBTraceSymbolManager` (not yet ported; see
//! [`crate::trace::seam_stubs::DBTraceSymbolManager`]) keeps one view per symbol type in a single
//! `Map<Byte, AbstractDBTraceSymbolSingleTypeView<?>>` field (`symbolViews`), and calls
//! `invalidateCache()` on every entry and `store.getObjectAt(key)` on one entry (from
//! `getSymbolByID`) polymorphically, across views whose `T` differs per symbol type. Object safety
//! forces that lookup's return type to erase `T` down to its upper bound, `AbstractDBTraceSymbol`;
//! [`AbstractDBTraceSymbolSingleTypeView::get_by_key`] mirrors that erasure. Callers that already
//! know their own concrete `T` should prefer
//! [`AbstractDBTraceSymbolSingleTypeViewBase::get_by_key`] instead, which returns `Arc<T>`
//! directly.
//!
//! Two adaptations, both forced by pieces this class depends on that aren't ported yet:
//! - The constructor does not derive `symbols_by_parent_id`/`symbols_by_name` from `store`
//!   in-place the way the Java constructor does (`store.getIndex(long.class,
//!   AbstractDBTraceSymbol.PARENT_COLUMN)`, `store.getIndex(String.class,
//!   AbstractDBTraceSymbol.NAME_COLUMN)`). Those `DBObjectColumn` tokens are `@DBAnnotatedColumn`
//!   static fields declared on whichever *concrete* Java subclass of `AbstractDBTraceSymbol` a
//!   given view manages (e.g. `DBTraceLabelSymbol.PARENT_COLUMN`) -- this crate's
//!   [`AbstractDBTraceSymbol`](crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol)
//!   trait intentionally does not model `DBAnnotatedObject`/DB-record mechanics (see that trait's
//!   own docs), so there is no in-repo column token to look up yet. [`AbstractDBTraceSymbolSingleTypeViewBase::new`]
//!   instead takes both indexes as constructor parameters, to be supplied by whatever concrete
//!   `T`-specific store setup eventually computes them.
//! - `constructView()` (`Collections.unmodifiableCollection(store.asMap().values())`) is mirrored
//!   by [`AbstractDBTraceSymbolSingleTypeViewBase::construct_view`], which calls a new
//!   [`DBCachedObjectStore::values`](crate::util::seam_stubs::DBCachedObjectStore::values) method
//!   directly rather than through `asMap()`: the already-ported
//!   [`DBCachedObjectStoreMap`](crate::util::database::db_cached_object_store_map::DBCachedObjectStoreMap)
//!   (the port of `asMap()`'s return type) has its own `values()` return the opaque
//!   `DBCachedObjectStoreValueCollection` marker, since no caller before this one has needed a
//!   real `T`-typed values view through that path.
//!
//! `view` is captured once at construction, like the Java field, rather than recomputed on every
//! [`AbstractDBTraceSymbolSingleTypeViewBase::get_all`] call. The Java field is a live wrapper
//! around `store.asMap().values()` (so later insertions into the store are visible through it);
//! since [`DBCachedObjectStore::values`](crate::util::seam_stubs::DBCachedObjectStore::values) is
//! a stub that always panics until a real store exists to back it, there is no live backing to
//! wrap yet either way.

use std::sync::Arc;

use crate::program::model::symbol::{Namespace, Symbol};
use crate::trace::database::symbol::abstract_db_trace_symbol::AbstractDBTraceSymbol;
use crate::trace::seam_stubs::DBTraceSymbolManager;
use crate::util::database::{DBAnnotatedObject, DBCachedObjectIndex};
use crate::util::lock_hold::LockHold;
use crate::util::seam_stubs::DBCachedObjectStore;
use crate::util::user_search_utils::UserSearchUtils;

/// The type-erased polymorphic surface of `AbstractDBTraceSymbolSingleTypeView`.
///
/// See the module documentation for why this trait exists despite the Java class declaring no
/// `abstract` method, and for why [`get_by_key`](Self::get_by_key) returns the erased
/// `Arc<dyn AbstractDBTraceSymbol>` rather than a concrete `Arc<T>`.
pub trait AbstractDBTraceSymbolSingleTypeView: Send + Sync {
    /// Mirrors `invalidateCache()`.
    fn invalidate_cache(&self);

    /// Mirrors `store.getObjectAt(long)`, as called (through a `symbolViews.get(typeID)` lookup)
    /// by `DBTraceSymbolManager.getSymbolByID(long)`.
    fn get_by_key(&self, key: i64) -> Arc<dyn AbstractDBTraceSymbol>;
}

/// The shared state and concrete behavior of `AbstractDBTraceSymbolSingleTypeView<T>`.
///
/// Port of `ghidra.trace.database.symbol.AbstractDBTraceSymbolSingleTypeView`'s fields and
/// methods (the class gives every one of its methods a body; see the module documentation for the
/// shape split and its adaptations).
pub struct AbstractDBTraceSymbolSingleTypeViewBase<T: AbstractDBTraceSymbol + DBAnnotatedObject> {
    /// The owning symbol manager. Mirrors the constructor-injected `manager` field.
    pub manager: Arc<dyn DBTraceSymbolManager>,
    /// The symbol type this view manages. Mirrors the constructor-injected `typeID` field.
    pub type_id: u8,
    /// The backing store of symbols of this type. Mirrors the constructor-injected `store` field.
    pub store: Arc<dyn DBCachedObjectStore<T>>,
    /// Every symbol currently in the store. Mirrors the `view` field; see the module
    /// documentation for why this is captured once rather than derived live.
    pub view: Vec<Arc<T>>,
    /// Index of symbols of this type by parent namespace id. Mirrors the `symbolsByParentID`
    /// field; see the module documentation for why this is constructor-injected rather than
    /// derived from `store` in-place.
    pub symbols_by_parent_id: Box<dyn DBCachedObjectIndex<i64, T>>,
    /// Index of symbols of this type by name. Mirrors the `symbolsByName` field; see the module
    /// documentation for why this is constructor-injected rather than derived from `store`
    /// in-place.
    pub symbols_by_name: Box<dyn DBCachedObjectIndex<String, T>>,
}

impl<T: AbstractDBTraceSymbol + DBAnnotatedObject> AbstractDBTraceSymbolSingleTypeViewBase<T> {
    /// Creates a view over `store`'s symbols of type `type_id`.
    ///
    /// Mirrors the constructor `AbstractDBTraceSymbolSingleTypeView(DBTraceSymbolManager, byte,
    /// DBCachedObjectStore<T>)`, except `symbols_by_parent_id`/`symbols_by_name` are taken as
    /// parameters instead of derived from `store` in-place -- see the module documentation.
    pub fn new(
        manager: Arc<dyn DBTraceSymbolManager>,
        type_id: u8,
        store: Arc<dyn DBCachedObjectStore<T>>,
        symbols_by_parent_id: Box<dyn DBCachedObjectIndex<i64, T>>,
        symbols_by_name: Box<dyn DBCachedObjectIndex<String, T>>,
    ) -> Self {
        let view = Self::construct_view(store.as_ref());
        Self {
            manager,
            type_id,
            store,
            view,
            symbols_by_parent_id,
            symbols_by_name,
        }
    }

    /// Mirrors the protected `constructView()`: every object currently in `store`. See the module
    /// documentation for why this goes through
    /// [`DBCachedObjectStore::values`](crate::util::seam_stubs::DBCachedObjectStore::values)
    /// rather than `store.asMap().values()`.
    pub fn construct_view(store: &dyn DBCachedObjectStore<T>) -> Vec<Arc<T>> {
        store.values()
    }

    /// Mirrors `getManager()`.
    pub fn get_manager(&self) -> Arc<dyn DBTraceSymbolManager> {
        Arc::clone(&self.manager)
    }

    /// Mirrors `getAll(boolean)`. `include_dynamic_symbols` is unused, matching the Java method
    /// (marked with `// TODO: A place to store/manage/generate/whatever dynamic symbols`).
    pub fn get_all(&self, include_dynamic_symbols: bool) -> Vec<Arc<T>> {
        let _ = include_dynamic_symbols;
        self.view.clone()
    }

    /// Mirrors `getChildrenNamed(String, TraceNamespaceSymbol)`. Takes `&dyn Namespace` rather
    /// than `&dyn TraceNamespaceSymbol` (the Java parameter type): only the `Namespace` facet is
    /// used (mirroring the Java cast `(Namespace) parent`), and Rust trait objects cannot be
    /// upcast from a `dyn TraceNamespaceSymbol` to a `dyn Namespace` here.
    pub fn get_children_named(&self, name: &str, parent: &dyn Namespace) -> Vec<Arc<T>> {
        let _hold = LockHold::lock(self.manager.read_lock());
        let dbns_parent = self.manager.assert_is_mine(parent);
        self.symbols_by_parent_id
            .get(&Symbol::get_id(dbns_parent.as_ref()))
            .into_iter()
            .filter(|s| Symbol::get_name(s.as_ref()) == name)
            .collect()
    }

    /// Mirrors `getChildren(TraceNamespaceSymbol)`. See
    /// [`get_children_named`](Self::get_children_named) for why this takes `&dyn Namespace`.
    pub fn get_children(&self, parent: &dyn Namespace) -> Vec<Arc<T>> {
        let _hold = LockHold::lock(self.manager.read_lock());
        let dbns_parent = self.manager.assert_is_mine(parent);
        self.symbols_by_parent_id.get(&Symbol::get_id(dbns_parent.as_ref()))
    }

    /// Mirrors `getNamed(String)`.
    pub fn get_named(&self, name: &str) -> Vec<Arc<T>> {
        self.symbols_by_name.get(&name.to_string())
    }

    /// Mirrors `getWithMatchingName(String, boolean)`.
    pub fn get_with_matching_name(
        &self,
        glob: &str,
        case_sensitive: bool,
    ) -> Result<Vec<Arc<T>>, regex::Error> {
        let pattern = UserSearchUtils::create_search_pattern(glob, case_sensitive)?;
        Ok(self
            .view
            .iter()
            .filter(|s| pattern.is_match(Symbol::get_name(s.as_ref())))
            .cloned()
            .collect())
    }

    /// Mirrors `scanByName(String)`.
    pub fn scan_by_name(&self, start_name: &str) -> std::vec::IntoIter<Arc<T>> {
        self.symbols_by_name
            .tail(&start_name.to_string(), true)
            .values()
            .into_iter()
    }

    /// Mirrors `getByKey(long)`.
    pub fn get_by_key(&self, key: i64) -> Arc<T> {
        self.store.get_object_at(key)
    }

    /// Mirrors `invalidateCache()`.
    pub fn invalidate_cache(&self) {
        self.store.invalidate_cache();
    }
}

impl<T: AbstractDBTraceSymbol + DBAnnotatedObject + 'static> AbstractDBTraceSymbolSingleTypeView
    for AbstractDBTraceSymbolSingleTypeViewBase<T>
{
    fn invalidate_cache(&self) {
        AbstractDBTraceSymbolSingleTypeViewBase::invalidate_cache(self)
    }

    fn get_by_key(&self, key: i64) -> Arc<dyn AbstractDBTraceSymbol> {
        AbstractDBTraceSymbolSingleTypeViewBase::get_by_key(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::symbol::{NamespaceType, SetParentNamespaceError, SourceType, SymbolType};
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::framework::db::record::DBRecord;
    use crate::trace::database::symbol::abstract_db_trace_symbol::SetSymbolNameError;
    use crate::trace::database::symbol::db_trace_namespace_symbol::DBTraceNamespaceSymbol;
    use crate::trace::model::lifespan::Lifespan;
    use crate::trace::model::symbol::trace_reference::TraceReference;
    use crate::trace::model::symbol::trace_symbol::TraceSymbol;
    use crate::trace::model::trace::Trace;
    use crate::trace::seam_stubs::{DBTraceOverlaySpaceAdapter, DBTraceProgramView};
    use crate::trace::model::thread::TraceThread;
    use crate::util::lock_hold::Lock;
    use crate::util::task::TaskMonitor;
    use crate::program::util::program_location::ProgramLocation;

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0)
    }

    /// A minimal `AbstractDBTraceSymbol`-shaped mock, standing in for a concrete symbol type
    /// (e.g. `DBTraceLabelSymbol`) that hasn't been ported yet.
    #[derive(Clone)]
    struct MockSymbol {
        id: i64,
        parent_id: i64,
        name: String,
    }

    impl DbObject for MockSymbol {
        fn state(&self) -> &DbObjectState {
            unimplemented!("not exercised by this smoke test")
        }
        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl DBAnnotatedObject for MockSymbol {
        fn store(&self) -> &dyn crate::util::seam_stubs::DBCachedObjectStoreCore {
            unimplemented!("not exercised by this smoke test")
        }
        fn adapter(&self) -> &dyn crate::util::database::db_cached_domain_object_adapter::DBCachedDomainObjectAdapter {
            unimplemented!("not exercised by this smoke test")
        }
        fn codecs(&self) -> &[Box<dyn crate::util::seam_stubs::DBFieldCodec>] {
            &[]
        }
        fn record(&self) -> DBRecord {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_record(&self, _record: DBRecord) {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            self.parent_id
        }
    }

    impl TraceSymbol for MockSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(
            &self,
        ) -> Option<Arc<dyn crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol>>
        {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }

    struct MockOverlaySpaceAdapter;
    impl DBTraceOverlaySpaceAdapter for MockOverlaySpaceAdapter {}
    struct MockProgramView;
    impl DBTraceProgramView for MockProgramView {}

    impl AbstractDBTraceSymbol for MockSymbol {
        fn get_overlay_space_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter> {
            Box::new(MockOverlaySpaceAdapter)
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 10)
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::from_address(self.get_address())
        }
        fn get_path(&self) -> Vec<String> {
            vec![self.name.clone()]
        }
        fn get_program(&self) -> Box<dyn DBTraceProgramView> {
            Box::new(MockProgramView)
        }
        fn get_program_location(&self) -> Box<dyn ProgramLocation> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_descendant(&self, namespace: &dyn Namespace) -> bool {
            namespace.get_id() == self.parent_id
        }
        fn is_valid_parent(&self, _ns: &dyn Namespace) -> bool {
            true
        }
        fn set_name(&mut self, new_name: &str, _new_source: SourceType) -> Result<(), SetSymbolNameError> {
            self.name = new_name.to_string();
            Ok(())
        }
        fn set_namespace(&self, _new_namespace: &dyn Namespace) -> std::io::Result<()> {
            Ok(())
        }
        fn set_name_and_namespace(
            &mut self,
            _new_name: &str,
            _new_namespace: &dyn Namespace,
            _new_source: SourceType,
        ) -> Result<(), SetParentNamespaceError> {
            Ok(())
        }
        fn set_source(&mut self, _new_source: SourceType) {}
        fn delete(&self) -> bool {
            true
        }
        fn is_global(&self) -> bool {
            self.parent_id == -1
        }
    }

    struct MockGlobalNamespace {
        id: i64,
    }

    impl Namespace for MockGlobalNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled")
        }
        fn get_name(&self) -> String {
            "Global".to_string()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }
        fn is_global(&self) -> bool {
            true
        }
    }

    /// A mock `DBCachedObjectStore` over a fixed, in-memory `Vec<Arc<MockSymbol>>`.
    struct MockStore {
        objects: Vec<Arc<MockSymbol>>,
    }

    impl DBCachedObjectStore<MockSymbol> for MockStore {
        fn get_object_at(&self, key: i64) -> Arc<MockSymbol> {
            self.objects
                .iter()
                .find(|s| s.id == key)
                .cloned()
                .expect("key must exist in this mock store")
        }
        fn values(&self) -> Vec<Arc<MockSymbol>> {
            self.objects.clone()
        }
    }

    /// A mock `DBCachedObjectIndex<i64, MockSymbol>` grouping by `parent_id`.
    struct MockParentIndex {
        objects: Vec<Arc<MockSymbol>>,
    }

    impl DBCachedObjectIndex<i64, MockSymbol> for MockParentIndex {
        fn store(&self) -> &dyn DBCachedObjectStore<MockSymbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn err_handler(&self) -> &dyn crate::framework::db::util::error_handler::ErrorHandler {
            unimplemented!("not exercised by this smoke test")
        }
        fn codec(&self) -> &dyn crate::util::seam_stubs::DBIndexFieldCodec<i64, MockSymbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn column_index(&self) -> i32 {
            0
        }
        fn field_span(&self) -> &dyn crate::util::database::field_span::FieldSpan {
            unimplemented!("not exercised by this smoke test")
        }
        fn direction(&self) -> crate::util::database::directed_iterator::Direction {
            crate::util::database::directed_iterator::Direction::Forward
        }
        fn restrict(
            &self,
            _field_span: Box<dyn crate::util::database::field_span::FieldSpan>,
            _direction: crate::util::database::directed_iterator::Direction,
        ) -> Box<dyn DBCachedObjectIndex<i64, MockSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get(&self, key: &i64) -> Vec<Arc<MockSymbol>> {
            self.objects.iter().filter(|s| s.parent_id == *key).cloned().collect()
        }
    }

    /// A mock `DBCachedObjectIndex<String, MockSymbol>` grouping by name, supporting `tail` for
    /// [`AbstractDBTraceSymbolSingleTypeViewBase::scan_by_name`].
    struct MockNameIndex {
        objects: Vec<Arc<MockSymbol>>,
    }

    impl DBCachedObjectIndex<String, MockSymbol> for MockNameIndex {
        fn store(&self) -> &dyn DBCachedObjectStore<MockSymbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn err_handler(&self) -> &dyn crate::framework::db::util::error_handler::ErrorHandler {
            unimplemented!("not exercised by this smoke test")
        }
        fn codec(&self) -> &dyn crate::util::seam_stubs::DBIndexFieldCodec<String, MockSymbol> {
            unimplemented!("not exercised by this smoke test")
        }
        fn column_index(&self) -> i32 {
            1
        }
        fn field_span(&self) -> &dyn crate::util::database::field_span::FieldSpan {
            unimplemented!("not exercised by this smoke test")
        }
        fn direction(&self) -> crate::util::database::directed_iterator::Direction {
            crate::util::database::directed_iterator::Direction::Forward
        }
        fn restrict(
            &self,
            _field_span: Box<dyn crate::util::database::field_span::FieldSpan>,
            _direction: crate::util::database::directed_iterator::Direction,
        ) -> Box<dyn DBCachedObjectIndex<String, MockSymbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get(&self, key: &String) -> Vec<Arc<MockSymbol>> {
            self.objects.iter().filter(|s| &s.name == key).cloned().collect()
        }
        fn tail(&self, from: &String, from_inclusive: bool) -> Box<dyn DBCachedObjectIndex<String, MockSymbol>> {
            let mut sorted: Vec<Arc<MockSymbol>> = self.objects.clone();
            sorted.sort_by(|a, b| a.name.cmp(&b.name));
            let filtered = sorted
                .into_iter()
                .filter(|s| {
                    if from_inclusive {
                        s.name.as_str() >= from.as_str()
                    } else {
                        s.name.as_str() > from.as_str()
                    }
                })
                .collect();
            Box::new(MockNameIndex { objects: filtered })
        }
        fn values(&self) -> Vec<Arc<MockSymbol>> {
            let mut sorted = self.objects.clone();
            sorted.sort_by(|a, b| a.name.cmp(&b.name));
            sorted
        }
    }

    #[derive(Default)]
    struct NoopLock;
    impl Lock for NoopLock {
        fn lock(&self) {}
        fn unlock(&self) {}
    }

    /// A mock `DBTraceSymbolManager` whose `assertIsMine` always succeeds and returns a fixed
    /// global namespace symbol.
    struct MockManager {
        lock: NoopLock,
        global: Arc<MockGlobalNamespaceSymbol>,
    }

    /// A `DBTraceNamespaceSymbol`-shaped mock standing in for the global namespace.
    struct MockGlobalNamespaceSymbol {
        id: i64,
    }

    impl Namespace for MockGlobalNamespaceSymbol {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            unimplemented!("identity default not modeled")
        }
        fn get_name(&self) -> String {
            "Global".to_string()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_type(&self) -> NamespaceType {
            NamespaceType::Namespace
        }
        fn is_global(&self) -> bool {
            true
        }
    }
    impl Symbol for MockGlobalNamespaceSymbol {
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_name(&self) -> &str {
            "Global"
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Global
        }
        fn get_source(&self) -> SourceType {
            SourceType::Default
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }
    impl TraceSymbol for MockGlobalNamespaceSymbol {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Option<Box<dyn TraceThread>> {
            None
        }
        fn get_parent_trace_namespace(
            &self,
        ) -> Option<Arc<dyn crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol>>
        {
            None
        }
        fn get_references_with_monitor(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn get_reference_collection(&self) -> Vec<Arc<dyn TraceReference>> {
            Vec::new()
        }
        fn set_pinned(&mut self, _pinned: bool) {}
        fn is_pinned(&self) -> bool {
            false
        }
    }
    impl crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol for MockGlobalNamespaceSymbol {
        fn get_parent_trace_namespace_symbol(
            &self,
        ) -> Option<Arc<dyn crate::trace::model::symbol::trace_namespace_symbol::TraceNamespaceSymbol>> {
            None
        }
        fn get_children(&self) -> Vec<Arc<dyn TraceSymbol>> {
            Vec::new()
        }
        fn get_path(&self) -> Vec<String> {
            Vec::new()
        }
    }
    impl AbstractDBTraceSymbol for MockGlobalNamespaceSymbol {
        fn get_overlay_space_adapter(&self) -> Box<dyn DBTraceOverlaySpaceAdapter> {
            Box::new(MockOverlaySpaceAdapter)
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::span(0, 0)
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn get_path(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_program(&self) -> Box<dyn DBTraceProgramView> {
            Box::new(MockProgramView)
        }
        fn get_program_location(&self) -> Box<dyn ProgramLocation> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_descendant(&self, _namespace: &dyn Namespace) -> bool {
            true
        }
        fn is_valid_parent(&self, _ns: &dyn Namespace) -> bool {
            true
        }
        fn set_name(&mut self, _new_name: &str, _new_source: SourceType) -> Result<(), SetSymbolNameError> {
            Ok(())
        }
        fn set_namespace(&self, _new_namespace: &dyn Namespace) -> std::io::Result<()> {
            Ok(())
        }
        fn set_name_and_namespace(
            &mut self,
            _new_name: &str,
            _new_namespace: &dyn Namespace,
            _new_source: SourceType,
        ) -> Result<(), SetParentNamespaceError> {
            Ok(())
        }
        fn set_source(&mut self, _new_source: SourceType) {}
        fn delete(&self) -> bool {
            true
        }
        fn is_global(&self) -> bool {
            true
        }
    }
    impl DBTraceNamespaceSymbol for MockGlobalNamespaceSymbol {
        fn check_circular(
            &self,
            _new_parent: &dyn DBTraceNamespaceSymbol,
        ) -> Result<(), crate::program::model::listing::CircularDependencyException> {
            Ok(())
        }
        fn do_get_path(&self, _list: &mut Vec<String>) {}
    }

    impl DBTraceSymbolManager for MockManager {
        fn get_global_namespace(&self) -> Arc<dyn DBTraceNamespaceSymbol> {
            self.global.clone()
        }
        fn read_lock(&self) -> &dyn Lock {
            &self.lock
        }
        fn assert_is_mine(&self, ns: &dyn Namespace) -> Arc<dyn DBTraceNamespaceSymbol> {
            let _ = ns;
            self.global.clone()
        }
    }

    fn make_view() -> AbstractDBTraceSymbolSingleTypeViewBase<MockSymbol> {
        let objects = vec![
            Arc::new(MockSymbol { id: 1, parent_id: 0, name: "alpha".to_string() }),
            Arc::new(MockSymbol { id: 2, parent_id: 0, name: "beta".to_string() }),
            Arc::new(MockSymbol { id: 3, parent_id: 5, name: "gamma".to_string() }),
        ];
        let manager: Arc<dyn DBTraceSymbolManager> = Arc::new(MockManager {
            lock: NoopLock,
            global: Arc::new(MockGlobalNamespaceSymbol { id: 0 }),
        });
        let store: Arc<dyn DBCachedObjectStore<MockSymbol>> =
            Arc::new(MockStore { objects: objects.clone() });
        let parent_index: Box<dyn DBCachedObjectIndex<i64, MockSymbol>> =
            Box::new(MockParentIndex { objects: objects.clone() });
        let name_index: Box<dyn DBCachedObjectIndex<String, MockSymbol>> =
            Box::new(MockNameIndex { objects });
        AbstractDBTraceSymbolSingleTypeViewBase::new(manager, 0, store, parent_index, name_index)
    }

    #[test]
    fn get_all_returns_every_symbol_captured_at_construction() {
        let view = make_view();
        let all = view.get_all(false);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn get_named_and_get_by_key_look_up_individual_symbols() {
        let view = make_view();
        assert_eq!(view.get_named("beta").len(), 1);
        assert!(view.get_named("nonexistent").is_empty());
        assert_eq!(view.get_by_key(2).name, "beta");
    }

    #[test]
    fn get_children_filters_by_parent_id() {
        let view = make_view();
        let global = MockGlobalNamespace { id: 0 };
        let children = view.get_children(&global);
        assert_eq!(children.len(), 2);
        let named = view.get_children_named("alpha", &global);
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].name, "alpha");
    }

    #[test]
    fn get_with_matching_name_uses_glob_style_patterns() {
        let view = make_view();
        let matches = view.get_with_matching_name("*a", true).unwrap();
        let mut names: Vec<&str> = matches.iter().map(|s| s.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn scan_by_name_starts_at_the_given_name_in_sorted_order() {
        let view = make_view();
        let scanned: Vec<String> = view.scan_by_name("beta").map(|s| s.name.clone()).collect();
        assert_eq!(scanned, vec!["beta".to_string(), "gamma".to_string()]);
    }

    #[test]
    fn invalidate_cache_delegates_to_the_store() {
        let view = make_view();
        // MockStore doesn't override invalidate_cache, so the default stub panics; this proves
        // the base's invalidate_cache really calls through to the store.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.invalidate_cache()));
        assert!(result.is_err());
    }

    #[test]
    fn erased_trait_object_delegates_to_the_base() {
        let view = make_view();
        let erased: &dyn AbstractDBTraceSymbolSingleTypeView = &view;
        let sym = erased.get_by_key(1);
        assert_eq!(Symbol::get_name(sym.as_ref()), "alpha");
    }
}
