//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::async_utils::AsyncExecutor;
use super::database::spatial::hyper::{HyperBox, HyperPoint};
use super::datastruct::NoSuchIndexException;
use super::exception::{CancelledException, NoValueException};
use super::graph::key_indexable_set::KeyIndexableSet;
use super::graph::keyed_object::KeyedObject;
use super::graph::vertex::Vertex;
use super::task::TaskMonitor;
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::program::model::block::CodeBlock;

/// Placeholder for `ghidra.util.task.Task`, needed by [`crate::util::TrackedTaskListener`].
pub trait Task: Send + Sync {}

/// Placeholder for `ghidra.program.model.block.IsolatedEntrySubModel`, needed by
/// [`crate::util::undefined_function::UndefinedFunction::find_function_using_isolated_block_model`].
///
/// The real class is a `CodeBlockModel` that treats every entry point (as identified by
/// symbols/references, independent of any existing disassembly) as starting its own block, used
/// as a fallback when [`crate::program::model::block::simple_block_model::SimpleBlockModel`]
/// finds nothing. Only the one query `UndefinedFunction.findFunctionUsingIsolatedBlockModel`
/// performs is modeled here; the real port would carry the full entry-point partitioning
/// algorithm.
pub trait IsolatedEntrySubModelLike {
    /// Stands in for `IsolatedEntrySubModel.getFirstCodeBlockContaining(Address, TaskMonitor)`
    /// (inherited from `CodeBlockModel`).
    fn get_first_code_block_containing(
        &self,
        addr: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn CodeBlock>>, CancelledException>;
}

/// Placeholder for `ghidra.util.filechooser.GhidraFileChooserModel`, needed by
/// [`crate::util::filechooser::GhidraFileFilter`].
///
/// `GhidraFileFilter.accept` only ever receives the model to hand it along to filter
/// implementations; the interface itself never calls a method on it, so this is a marker
/// trait until the real model is ported.
pub trait GhidraFileChooserModelLike: Send + Sync {}

/// Placeholder for `ghidra.util.Location`, needed by [`crate::util::Issue`].
pub trait Location: Send + Sync {}

/// Placeholder for `ghidra.util.datastruct.WeakSet`, needed by
/// [`crate::util::datastruct::WeakDataStructureFactory`].
///
/// The factory only creates and returns these; no accessors are called on them here, so
/// this is a marker trait until the real `WeakSet` family is ported.
pub trait WeakSet<T>: Send + Sync {}

/// Placeholder for `ghidra.util.map.ValueMap`, needed by
/// [`crate::util::map::LongIteratorImpl`].
///
/// Only the accessors `LongIteratorImpl` needs are declared here; the real port carries
/// the full page-indexed property storage.
pub trait ValueMapLike {
    /// Returns whether there is a property value at `index`.
    fn has_property(&self, index: i64) -> bool;

    /// Get the next index (exclusive of `index`) where a property value exists.
    fn get_next_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException>;

    /// Get the previous index (exclusive of `index`) where a property value exists.
    fn get_previous_property_index(&self, index: i64) -> Result<i64, NoSuchIndexException>;
}

/// Placeholder for `ghidra.util.graph.GraphIterator`, needed by
/// [`crate::util::graph::KeyIndexableSet`].
#[allow(deprecated)]
pub trait GraphIteratorLike<T: KeyedObject> {
    /// Returns true if the iterator has more elements.
    fn has_next(&self) -> bool;

    /// Returns the next element in the iteration.
    fn next(&mut self) -> Option<T>;

    /// Removes the last-returned object from the backing set.
    fn remove(&mut self) -> bool;
}

/// Placeholder for `ghidra.util.graph.attributes.Attribute`, needed by
/// [`crate::util::graph::attributes::AttributeManager`].
///
/// Only the accessor `AttributeManager` needs is declared here; the real port carries the
/// int/long/double/string/object value families and the owning-set bookkeeping.
pub trait AttributeLike<T: KeyedObject> {
    /// Undefine all values set for this attribute.
    fn clear(&mut self);
}

/// Placeholder for `ghidra.util.graph.attributes.IntegerAttribute`, needed by
/// [`crate::util::graph::directed_graph::DirectedGraph`] (`getLevels`/`complexityDepth`).
///
/// Only the int-valued get/set that make the returned attribute usable are declared here; the
/// real port carries the full `Attribute` value-family machinery.
#[allow(deprecated)]
pub trait IntegerAttributeLike<T: KeyedObject>: AttributeLike<T> {
    /// Returns the integer value associated with `obj`, or `NoValueException` if none is set.
    fn get_value(&self, obj: &T) -> Result<i32, NoValueException>;

    /// Sets the integer value associated with `obj`.
    fn set_value(&mut self, obj: &T, value: i32);
}

/// Placeholder for `ghidra.util.graph.VertexSet`, needed by
/// [`crate::util::graph::directed_graph::DirectedGraph`].
///
/// `DirectedGraph`'s defaults recover adjacency (sources/sinks/valence) by scanning `EdgeSet`
/// directly rather than through `VertexSet`'s first/last edge pointers, so the only surface
/// needed beyond the inherited [`KeyIndexableSet`] is `clear`; the real port also threads those
/// edge pointers on behalf of `EdgeSet`.
#[allow(deprecated)]
pub trait VertexSetLike<V: Vertex>: KeyIndexableSet<V> {
    /// Empties the vertex set while leaving capacity unchanged.
    fn clear(&mut self);
}

/// Placeholder for `ghidra.util.WordLocation`, needed by
/// [`crate::util::string_utilities::StringUtilities`] (`find_word`/`find_word_location`).
///
/// `WordLocation` is a concrete final class in Java, not an interface, but the port only
/// needs to hand callers *something* that carries the located word text without pulling in
/// the real type's full accessor set (`getContext`/`getStart`/`isEmpty`) up front; only
/// `getWord()` is consumed here, so only that accessor is declared.
pub trait WordLocationLike {
    /// Returns the located word text (or the empty string for an empty/`None` location).
    fn word(&self) -> &str;
}

/// Placeholder for `ghidra.util.TwoWayBreakdownAddressRangeIterator.Which`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Stands in for the yielded `Map.Entry<AddressRange, Which>` pairs. `Which` in the Java
/// original is a 3-valued enum (`LEFT`, `RIGHT`, `BOTH`) with `inSubtract`/`inXor`/
/// `inIntersect` query methods; those are represented directly as flags here rather than
/// pulling in the real breakdown iterator.
pub struct TwoWayBreakdownEntry {
    pub range: AddressRange,
    /// Only the first (`a`) operand included this range (`Which::LEFT`).
    pub in_a_only: bool,
    /// Only the second (`b`) operand included this range (`Which::RIGHT`).
    pub in_b_only: bool,
    /// Both operands included this range (`Which::BOTH`).
    pub in_both: bool,
}

impl TwoWayBreakdownEntry {
    /// Mirrors `Which.inSubtract`: included in `a - b`.
    pub fn in_subtract(&self) -> bool {
        self.in_a_only
    }

    /// Mirrors `Which.inXor`: included in the symmetric difference `a xor b`.
    pub fn in_xor(&self) -> bool {
        self.in_a_only || self.in_b_only
    }

    /// Mirrors `Which.inIntersect`: included in `a ∩ b`.
    pub fn in_intersect(&self) -> bool {
        self.in_both
    }
}

/// Placeholder for `ghidra.async.SwingExecutorService`, needed by
/// [`crate::util::async_utils::AsyncUtils::swing_executor`].
///
/// The real type wraps `SwingUtilities.invokeLater`/`Swing.runIfSwingOrRunLater` to dispatch
/// commands onto the UI thread. Until it and a UI-thread runtime concept are ported,
/// `AsyncUtils::swing_executor` returns a plain [`AsyncExecutor`] that runs synchronously; a
/// real implementation should satisfy this marker too.
pub trait SwingExecutorServiceLike: AsyncExecutor {}

/// Placeholder for `ghidra.framework.ApplicationProperties`, needed by
/// [`crate::util::application_utilities::ApplicationUtilities`].
///
/// `ApplicationProperties` extends `java.util.Properties` and carries the application's full
/// name/version/release/build-date key set; only the accessor consumed by `ApplicationUtilities`
/// is declared here, the real port carries the rest.
pub trait ApplicationPropertiesLike {
    /// Returns the application's name (empty string if undefined), mirroring
    /// `ApplicationProperties.getApplicationName()`.
    fn application_name(&self) -> String;
}

/// Placeholder for `ghidra.framework.ApplicationIdentifier`, needed by
/// [`crate::util::application_utilities::ApplicationUtilities`].
///
/// The real `ApplicationIdentifier` is constructed *from* an `ApplicationProperties`, and its
/// constructor itself calls `ApplicationUtilities.normalizeApplicationName` -- the other half of
/// the dependency cycle this port breaks. Because a placeholder trait cannot stand in for a
/// constructor, `ApplicationUtilities` methods that need an identifier take an already-built one
/// as a parameter rather than building it internally from `ApplicationPropertiesLike`; only the
/// two accessors consumed there are declared here.
pub trait ApplicationIdentifierLike {
    /// Returns the application name component, mirroring `getApplicationName()`.
    fn application_name(&self) -> String;

    /// Returns the full versioned identifier (`name_version_releaseName`), mirroring
    /// `toString()`.
    fn versioned_name(&self) -> String;
}

/// Placeholder for `ghidra.util.TwoWayBreakdownAddressRangeIterator`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Only the construction contract is declared: given two forward- or backward-ordered
/// `AddressRange` iterators, classify every range as belonging to the first iterator only,
/// the second only, or both. The real port carries the lazy merge-scan algorithm that
/// computes this.
pub trait TwoWayBreakdownFactory {
    /// Builds the breakdown of `a` and `b` into per-range membership entries.
    fn build_breakdown(
        &self,
        a: Box<dyn Iterator<Item = AddressRange>>,
        b: Box<dyn Iterator<Item = AddressRange>>,
        forward: bool,
    ) -> Box<dyn Iterator<Item = TwoWayBreakdownEntry>>;
}

/// Placeholder for `utility.module.ModuleUtilities.MANIFEST_FILE_NAME`, needed by
/// [`crate::util::extensions::ExtensionDetails`].
pub const MODULE_MANIFEST_FILE_NAME: &str = "Module.manifest";

/// Placeholder for `utility.module.ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED`, needed by
/// [`crate::util::extensions::ExtensionDetails`].
pub const MODULE_MANIFEST_FILE_NAME_UNINSTALLED: &str = "Module.manifest.uninstalled";

/// Placeholder for `ghidra.util.extensions.ExtensionUtils.PROPERTIES_FILE_NAME`, needed by
/// [`crate::util::extensions::ExtensionDetails`].
pub const EXTENSION_PROPERTIES_FILE_NAME: &str = "extension.properties";

/// Placeholder for `ghidra.util.extensions.ExtensionUtils.PROPERTIES_FILE_NAME_UNINSTALLED`,
/// needed by [`crate::util::extensions::ExtensionDetails`].
pub const EXTENSION_PROPERTIES_FILE_NAME_UNINSTALLED: &str = "extension.properties.uninstalled";

/// Placeholder for `ghidra.util.extensions.Extensions`, needed by
/// [`crate::util::extensions::ExtensionUtils`].
///
/// The real `Extensions` is a package-private collection class (`Map<String, List<ExtensionDetails>>`
/// keyed by name) used only by `ExtensionUtils` to dedupe extensions by name, mark ones pending
/// uninstall for removal, and report name collisions. Only the members `ExtensionUtils` calls are
/// declared here; the real port carries the full name-keyed bookkeeping.
pub trait ExtensionsLike {
    /// Adds an extension to this collection, mirroring `Extensions.add(ExtensionDetails)`.
    fn add(&mut self, extension: Box<dyn crate::util::extensions::ExtensionDetails>);

    /// Returns all installed extensions that are not marked for uninstall (one per name),
    /// mirroring `Extensions.getActiveExtensions()`.
    fn active_extensions(
        &self,
        app: &dyn crate::framework::Application,
    ) -> Vec<&dyn crate::util::extensions::ExtensionDetails>;

    /// Returns all unique extensions (no duplicates, one per name) that the application is aware
    /// of, mirroring `Extensions.get()`.
    fn all_extensions(&self) -> Vec<&dyn crate::util::extensions::ExtensionDetails>;

    /// Removes any extensions that have already been marked for removal, deleting their install
    /// directories, mirroring `Extensions.cleanupExtensionsMarkedForRemoval()`. This should be
    /// called before any class loading has occurred.
    fn cleanup_extensions_marked_for_removal(&mut self, app: &dyn crate::framework::Application);

    /// Logs any duplicate extensions (more than one entry sharing a name), mirroring
    /// `Extensions.reportDuplicateExtensions()`.
    fn report_duplicate_extensions(&self);
}

/// Placeholder for `generic.jar.ApplicationModule`, needed by
/// [`crate::util::ghidra_jar_builder::GhidraJarBuilder`].
///
/// The real `ApplicationModule` is a concrete, `Comparable` class wrapping a module directory and
/// its application root, computed entirely from the module directory's parent folder name (plus a
/// `Module.manifest`-driven `excludeFromGhidraJar` check). Only the name, category predicates, and
/// exclusion check `GhidraJarBuilder` consumes are declared here; the file-path-derived
/// construction, `getModuleDir()`/`getApplicationRoot()`/`getRelativePath()` accessors, and
/// `compareTo` ordering (reproduced directly against this trait's predicates by
/// `GhidraJarBuilder`'s own module-sorting helper, since a placeholder trait can't carry
/// `Ord`-through-trait-object) are left to the real port.
pub trait ApplicationModuleLike {
    /// Returns the module's name (its directory name), mirroring `ApplicationModule.getName()`.
    fn name(&self) -> String;

    /// Whether this module lives under an `Extensions` directory, mirroring
    /// `ApplicationModule.isExtension()`.
    fn is_extension(&self) -> bool;

    /// Whether this module lives under a `Framework` directory, mirroring
    /// `ApplicationModule.isFramework()`.
    fn is_framework(&self) -> bool;

    /// Whether this module lives under a `Debug` directory, mirroring
    /// `ApplicationModule.isDebug()`.
    fn is_debug(&self) -> bool;

    /// Whether this module lives under a `Processors` directory, mirroring
    /// `ApplicationModule.isProcessor()`.
    fn is_processor(&self) -> bool;

    /// Whether this module lives under a `Features` directory, mirroring
    /// `ApplicationModule.isFeature()`.
    fn is_feature(&self) -> bool;

    /// Whether this module lives under a `Configurations` directory, mirroring
    /// `ApplicationModule.isConfiguration()`.
    fn is_configuration(&self) -> bool;

    /// Whether this module lives under a `GPL` directory, mirroring
    /// `ApplicationModule.isGPL()`.
    fn is_gpl(&self) -> bool;

    /// Whether the module's `Module.manifest` marks it excluded from the standalone Ghidra jar,
    /// mirroring `ApplicationModule.excludeFromGhidraJar()` (`false` on any read error, matching
    /// the Java method's caught-`IOException` fallback).
    fn exclude_from_ghidra_jar(&self) -> bool;
}

/// Placeholder for `ghidra.util.UnionAddressRangeIterator`, needed by
/// [`crate::util::address_range_iterators::AddressRangeIteratorFactory`].
///
/// Only the construction contract is declared: coalesce the ranges from one or more
/// `AddressRange` iterators into their lazily-computed union. The real port carries the
/// merge algorithm; once ported it will itself implement [`AddressRangeIterator`] and can
/// satisfy this trait directly.
pub trait UnionAddressRangeIteratorFactory {
    /// Builds the union of the ranges produced by `iterators`.
    fn build_union(
        &self,
        iterators: Vec<Box<dyn Iterator<Item = AddressRange>>>,
        forward: bool,
    ) -> Box<dyn AddressRangeIterator>;
}

/// Placeholder for `ghidra.util.database.BackwardLongKeyIterator`, needed by
/// [`crate::util::database::directed_long_key_iterator`].
///
/// Wraps a `db.DBLongIterator`, running it backward: `hasNext`/`next` delegate to the wrapped
/// iterator's `hasPrevious`/`previous`.
pub trait BackwardLongKeyIterator: Send + Sync {
    fn has_next(&self) -> std::io::Result<bool>;
    fn next(&self) -> std::io::Result<i64>;
}

/// Placeholder for `ghidra.util.database.ForwardLongKeyIterator`, needed by
/// [`crate::util::database::directed_long_key_iterator`].
///
/// Wraps a `db.DBLongIterator`, running it forward: `hasNext`/`next` delegate directly to the
/// wrapped iterator's `hasNext`/`next`.
pub trait ForwardLongKeyIterator: Send + Sync {
    fn has_next(&self) -> std::io::Result<bool>;
    fn next(&self) -> std::io::Result<i64>;
}

/// Placeholder for `ghidra.util.database.DirectedLongKeyIterator.getIterator`'s construction
/// contract, needed by [`crate::util::database::directed_long_key_iterator`].
///
/// The real static factory computes `min`/`max` from a `KeySpan` and calls
/// `Table.longKeyIterator(min, max, start)` (not yet part of the ported
/// [`Table`](crate::framework::db::Table) API) to obtain a `DBLongIterator` over that range,
/// then wraps it in [`ForwardLongKeyIterator`] or [`BackwardLongKeyIterator`] depending on
/// `direction`. Until `Table`'s ranged key iteration and those two wrappers exist, this
/// declares the construction contract only.
pub trait DirectedLongKeyIteratorFactory {
    /// Builds a directed key iterator over `table`, restricted to `key_span`, running in
    /// `direction`.
    fn get_iterator(
        &self,
        table: &mut crate::framework::db::Table,
        key_span: &dyn crate::util::database::KeySpan,
        direction: crate::util::database::Direction,
    ) -> std::io::Result<Box<dyn crate::util::database::AbstractDirectedLongKeyIterator>>;
}

/// Placeholder for the not-yet-ported `delete()` member of `db.RecordIterator`, needed by
/// [`crate::util::database::abstract_directed_record_iterator::AbstractDirectedRecordIterator`].
///
/// The real port, [`RecordIterator`](crate::framework::db::RecordIterator), only carries the
/// `next`/`has_next` members ported so far. `delete` is the only member
/// `AbstractDirectedRecordIterator` needs from it, so only that member is stubbed here rather
/// than redefining the whole interface.
pub trait RecordIteratorDelete: Send + Sync {
    fn delete(&mut self) -> std::io::Result<bool>;
}

/// Placeholder for `ghidra.util.database.BackwardRecordIterator`, needed by
/// [`crate::util::database::directed_record_iterator`].
///
/// Wraps a `db.RecordIterator`, running it backward: `hasNext`/`next` delegate to the wrapped
/// iterator's `hasPrevious`/`previous`.
pub trait BackwardRecordIterator: Send + Sync {
    fn has_next(&self) -> std::io::Result<bool>;
    fn next(&self) -> std::io::Result<crate::framework::db::record::DBRecord>;
}

/// Placeholder for `ghidra.util.database.ForwardRecordIterator`, needed by
/// [`crate::util::database::directed_record_iterator`].
///
/// Wraps a `db.RecordIterator`, running it forward: `hasNext`/`next` delegate directly to the
/// wrapped iterator's `hasNext`/`next`.
pub trait ForwardRecordIterator: Send + Sync {
    fn has_next(&self) -> std::io::Result<bool>;
    fn next(&self) -> std::io::Result<crate::framework::db::record::DBRecord>;
}

/// Placeholder for `ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec`, needed by
/// [`crate::util::database::annot::DBAnnotatedField::codec`].
///
/// `DBAnnotatedField.codec()` only carries a `Class<? extends DBFieldCodec>` type token (which
/// concrete codec to reflectively instantiate later); it never calls a method on the codec
/// itself, so `store`/`load` default to panicking until a caller that actually invokes a codec
/// (currently [`DBAnnotatedObject`](crate::util::database::db_annotated_object::DBAnnotatedObject),
/// via its `codecs` field) needs a real implementation.
pub trait DBFieldCodec: Send + Sync {
    /// Encodes `obj`'s field into `record`, mirroring `DBFieldCodec.store(OT, DBRecord)`.
    fn store(
        &self,
        obj: &dyn crate::util::database::db_annotated_object::DBAnnotatedObject,
        record: &mut crate::framework::db::record::DBRecord,
    ) {
        let _ = (obj, record);
        panic!("DBFieldCodec::store is not implemented for this codec")
    }

    /// Decodes `record`'s field into `obj`, mirroring `DBFieldCodec.load(OT, DBRecord)`.
    fn load(
        &self,
        obj: &dyn crate::util::database::db_annotated_object::DBAnnotatedObject,
        record: &crate::framework::db::record::DBRecord,
    ) -> std::io::Result<()> {
        let _ = (obj, record);
        panic!("DBFieldCodec::load is not implemented for this codec")
    }
}

/// Placeholder for `ghidra.util.database.DirectedRecordIterator`'s two static factory methods
/// (`getIterator`/`getIndexIterator`), needed by
/// [`crate::util::database::directed_record_iterator`].
///
/// `getIterator` computes `min`/`max` from a `KeySpan` and calls `Table.iterator(min, max,
/// start)` (not yet part of the ported [`Table`](crate::framework::db::table::Table) API) to
/// obtain a `RecordIterator`, then wraps it in [`ForwardRecordIterator`] or
/// [`BackwardRecordIterator`] depending on `direction`. `getIndexIterator` does the same via
/// `Table.indexIterator(columnIndex, lower, upper, forward)` over a `FieldSpan`, then applies the
/// `applyBegFilter`/`applyEndFilter` exclusive-bound filters. Until `Table`'s ranged/indexed
/// iteration and those wrapper classes exist, this declares the construction contracts only.
pub trait DirectedRecordIteratorFactory {
    /// Builds a directed record iterator over `table`, restricted to `key_span`, running in
    /// `direction`.
    fn get_iterator(
        &self,
        table: &mut crate::framework::db::Table,
        key_span: &dyn crate::util::database::KeySpan,
        direction: crate::util::database::Direction,
    ) -> std::io::Result<Box<dyn crate::util::database::DirectedRecordIterator>>;

    /// Builds a directed record iterator over `table`'s index on `column_index`, restricted to
    /// `field_span`, running in `direction`.
    fn get_index_iterator(
        &self,
        table: &mut crate::framework::db::Table,
        column_index: usize,
        field_span: &dyn crate::util::database::FieldSpan,
        direction: crate::util::database::Direction,
    ) -> std::io::Result<Box<dyn crate::util::database::DirectedRecordIterator>>;
}

/// Placeholder for the subset of `ghidra.util.database.DBCachedObjectStore` that
/// [`DBAnnotatedObject`](crate::util::database::db_annotated_object::DBAnnotatedObject) calls
/// through its `store` field, independent of the store's managed object type.
///
/// The real `DBCachedObjectStore<T extends DBAnnotatedObject>` is generic in `T` (see the
/// `DBCachedObjectStore<T>` marker below, needed by
/// [`DBAnnotatedObjectFactory`](crate::util::database::db_annotated_object_factory::DBAnnotatedObjectFactory)),
/// but every operation `DBAnnotatedObject` itself performs -- delegating to
/// `adapter.getReadWriteLock()` for `readLock()`/`writeLock()`, implementing `ErrorHandler` for
/// `dbError`, `getTableName()`, and the backing `table` field's `putRecord`/`getRecord` plus
/// constructing this object's `ObjectKey` -- never touches `T`. That matches the `<?>` wildcard
/// `DBAnnotatedObject` declares its own `store` field with, so this is intentionally a separate,
/// non-generic trait rather than a use of the generic marker. Once the real `DBCachedObjectStore`
/// is ported, both traits collapse into it.
pub trait DBCachedObjectStoreCore: crate::framework::db::util::ErrorHandler + Send + Sync {
    /// Mirrors `readLock()` (via `ReadWriteLock.readLock()` on the adapter's `getReadWriteLock()`).
    fn read_lock(&self) -> &dyn crate::util::lock_hold::Lock;
    /// Mirrors `writeLock()` (via `ReadWriteLock.writeLock()` on the adapter's `getReadWriteLock()`).
    fn write_lock(&self) -> &dyn crate::util::lock_hold::Lock;
    /// Mirrors `getTableName()`.
    fn get_table_name(&self) -> String;
    /// Mirrors the backing `table` field's `putRecord(DBRecord)`.
    fn put_record(&self, record: &crate::framework::db::record::DBRecord) -> std::io::Result<()>;
    /// Mirrors the backing `table` field's `getRecord(long)`.
    fn get_record(&self, key: i64) -> std::io::Result<Option<crate::framework::db::record::DBRecord>>;
    /// Mirrors `new ObjectKey(store.table, key)`. Reuses
    /// [`crate::trace::seam_stubs::ObjectKey`], the existing placeholder for this same Java type
    /// (`ghidra.util.database.ObjectKey`), rather than declaring a second one.
    fn object_key(&self, key: i64) -> Box<dyn crate::trace::seam_stubs::ObjectKey>;
}

/// Placeholder for `ghidra.util.database.DBCachedObjectStoreEntrySubSet`, needed by
/// [`crate::util::database::db_cached_object_store_entry_set::DBCachedObjectStoreEntrySet`]'s
/// `subSet`/`headSet`/`tailSet` return type.
///
/// Mirrors the same `NavigableSet<Entry<Long, T>>` contract as
/// [`DBCachedObjectStoreEntrySet`](crate::util::database::db_cached_object_store_entry_set::DBCachedObjectStoreEntrySet)
/// itself, restricted to a sub-range of keys; `DBCachedObjectStoreEntrySet` only ever constructs
/// and returns these, never calls into one, so the full shape here is a forward-looking hint for
/// the real port (which will also need it as a return type from its own narrowing methods), not
/// a requirement of this particular caller.
pub trait DBCachedObjectStoreEntrySubSet: Send + Sync {
    fn first(&self) -> crate::util::database::db_cached_object_store_entry_set::StoreEntry;
    fn last(&self) -> crate::util::database::db_cached_object_store_entry_set::StoreEntry;
    fn size(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn contains(&self, o: &crate::util::database::db_cached_object_store_entry_set::StoreEntry) -> bool;
    fn to_vec(&self) -> Vec<crate::util::database::db_cached_object_store_entry_set::StoreEntry>;
    fn remove(&mut self, o: &crate::util::database::db_cached_object_store_entry_set::StoreEntry) -> bool;
    fn contains_all(&self, c: &[crate::util::database::db_cached_object_store_entry_set::StoreEntry]) -> bool;
    fn retain_all(&mut self, c: &[crate::util::database::db_cached_object_store_entry_set::StoreEntry]) -> bool;
    fn remove_all(&mut self, c: &[crate::util::database::db_cached_object_store_entry_set::StoreEntry]) -> bool;
    fn clear(&mut self);
    fn lower(
        &self,
        e: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
    ) -> Option<crate::util::database::db_cached_object_store_entry_set::StoreEntry>;
    fn floor(
        &self,
        e: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
    ) -> Option<crate::util::database::db_cached_object_store_entry_set::StoreEntry>;
    fn ceiling(
        &self,
        e: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
    ) -> Option<crate::util::database::db_cached_object_store_entry_set::StoreEntry>;
    fn higher(
        &self,
        e: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
    ) -> Option<crate::util::database::db_cached_object_store_entry_set::StoreEntry>;
    fn iter(
        &self,
    ) -> Box<
        dyn super::database::RemovableIterator<
                Item = crate::util::database::db_cached_object_store_entry_set::StoreEntry,
            > + '_,
    >;
    fn descending_set(&self) -> Box<dyn DBCachedObjectStoreEntrySubSet>;
    fn descending_iter(
        &self,
    ) -> Box<
        dyn super::database::RemovableIterator<
                Item = crate::util::database::db_cached_object_store_entry_set::StoreEntry,
            > + '_,
    >;
    fn sub_set(
        &self,
        from_element: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
        from_inclusive: bool,
        to_element: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreEntrySubSet>;
    fn head_set(
        &self,
        to_element: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
        inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreEntrySubSet>;
    fn tail_set(
        &self,
        from_element: &crate::util::database::db_cached_object_store_entry_set::StoreEntry,
        inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreEntrySubSet>;
}

/// Placeholder for `ghidra.util.database.DBCachedObjectStoreKeySubSet`, needed by
/// [`crate::util::database::db_cached_object_store_key_set::DBCachedObjectStoreKeySet`]'s
/// `subSet`/`headSet`/`tailSet` return type.
///
/// Mirrors the same `NavigableSet<Long>` contract as
/// [`DBCachedObjectStoreKeySet`](crate::util::database::db_cached_object_store_key_set::DBCachedObjectStoreKeySet)
/// itself, restricted to a sub-range of keys; `DBCachedObjectStoreKeySet` only ever constructs
/// and returns these, never calls into one, so the full shape here is a forward-looking hint for
/// the real port (which will also need it as a return type from its own narrowing methods), not
/// a requirement of this particular caller.
pub trait DBCachedObjectStoreKeySubSet: Send + Sync {
    fn first(&self) -> i64;
    fn last(&self) -> i64;
    fn size(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn contains(&self, key: i64) -> bool;
    fn to_vec(&self) -> Vec<i64>;
    fn remove(&mut self, key: i64) -> bool;
    fn contains_all(&self, c: &[i64]) -> bool;
    fn retain_all(&mut self, c: &[i64]) -> bool;
    fn remove_all(&mut self, c: &[i64]) -> bool;
    fn clear(&mut self);
    fn lower(&self, e: i64) -> Option<i64>;
    fn floor(&self, e: i64) -> Option<i64>;
    fn ceiling(&self, e: i64) -> Option<i64>;
    fn higher(&self, e: i64) -> Option<i64>;
    fn iter(&self) -> Box<dyn super::database::RemovableIterator<Item = i64> + '_>;
    fn descending_set(&self) -> Box<dyn DBCachedObjectStoreKeySubSet>;
    fn descending_iter(&self) -> Box<dyn super::database::RemovableIterator<Item = i64> + '_>;
    fn sub_set(
        &self,
        from_element: i64,
        from_inclusive: bool,
        to_element: i64,
        to_inclusive: bool,
    ) -> Box<dyn DBCachedObjectStoreKeySubSet>;
    fn head_set(&self, to_element: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet>;
    fn tail_set(&self, from_element: i64, inclusive: bool) -> Box<dyn DBCachedObjectStoreKeySubSet>;
}

/// Placeholder for `ghidra.util.database.DBCachedObjectStoreSubMap`, needed by
/// [`crate::util::database::db_cached_object_store_map::DBCachedObjectStoreMap`]'s
/// `subMap`/`headMap`/`tailMap` return type.
///
/// `DBCachedObjectStoreMap` only ever constructs and returns these, never calls a method on one
/// itself, so this is a marker trait until a consumer that actually calls into it needs the real
/// `NavigableMap<Long, T>`-restricted-to-a-key-range surface.
pub trait DBCachedObjectStoreSubMap: Send + Sync {}

/// Placeholder for `ghidra.util.database.DBCachedObjectStoreValueCollection`, needed by
/// [`crate::util::database::db_cached_object_store_map::DBCachedObjectStoreMap`]'s `values()`
/// return type.
///
/// `DBCachedObjectStoreMap` only ever constructs and returns these, never calls a method on one
/// itself, so this is a marker trait until a consumer that actually calls into it needs the real
/// `Collection<T>` surface.
pub trait DBCachedObjectStoreValueCollection: Send + Sync {}

/// Placeholder for `ghidra.util.database.DBCachedObjectStore`, needed by
/// [`crate::util::database::db_annotated_object_factory::DBAnnotatedObjectFactory`] and
/// [`crate::util::database::db_cached_object_index::DBCachedObjectIndex`].
///
/// `DBAnnotatedObjectFactory.create` only ever receives the store to hand it along to the
/// object being constructed, so that caller needs nothing beyond the marker bound. The
/// index-facing methods below cover the rest of the surface `DBCachedObjectIndex` reaches
/// through its `store` field: `findObjects`/`findOneObject`/the index `iterator` overload
/// (`Table.indexIterator`-backed, represented as an eagerly-collected `Vec` rather than a lazy
/// iterator, matching the convention `DBCachedObjectStoreEntrySet::to_vec` established for the
/// sibling cut-point traits in this same file), `contains`, and the backing `table` field's
/// `hasRecord`/`getMatchingRecordCount` (accessed directly as `store.table.hasRecord(...)` in
/// Java, folded into the store trait here since no separate `table` accessor exists on this
/// placeholder). Each new method defaults to panicking so the existing marker-only
/// implementations (e.g. `DBAnnotatedObjectFactory`'s test `MockStore`) keep compiling
/// unchanged; the real port replaces every default. `get_index`, `create`, locking, etc. remain
/// undeclared until a caller actually needs them.
pub trait DBCachedObjectStore<T: crate::util::database::db_annotated_object::DBAnnotatedObject>:
    Send + Sync
{
    /// Mirrors `findObjects(int, Field)`.
    fn find_objects(
        &self,
        column_index: i32,
        field: &crate::framework::db::field::Field,
    ) -> std::io::Result<Vec<std::sync::Arc<T>>> {
        let _ = (column_index, field);
        panic!("DBCachedObjectStore::find_objects is not implemented for this store")
    }

    /// Mirrors `findOneObject(int, Field)`.
    fn find_one_object(
        &self,
        column_index: i32,
        field: &crate::framework::db::field::Field,
    ) -> std::io::Result<Option<std::sync::Arc<T>>> {
        let _ = (column_index, field);
        panic!("DBCachedObjectStore::find_one_object is not implemented for this store")
    }

    /// Mirrors `iterator(int, FieldSpan, Direction)`.
    fn iterate(
        &self,
        column_index: i32,
        field_span: &dyn crate::util::database::FieldSpan,
        direction: crate::util::database::Direction,
    ) -> std::io::Result<Vec<std::sync::Arc<T>>> {
        let _ = (column_index, field_span, direction);
        panic!("DBCachedObjectStore::iterate is not implemented for this store")
    }

    /// Mirrors `contains(Object)`.
    fn contains(&self, value: &std::sync::Arc<T>) -> bool {
        let _ = value;
        panic!("DBCachedObjectStore::contains is not implemented for this store")
    }

    /// Mirrors the backing `table` field's `hasRecord(Field, int)`.
    fn has_record(
        &self,
        field: &crate::framework::db::field::Field,
        column_index: i32,
    ) -> std::io::Result<bool> {
        let _ = (field, column_index);
        panic!("DBCachedObjectStore::has_record is not implemented for this store")
    }

    /// Mirrors the backing `table` field's `getMatchingRecordCount(Field, int)`.
    fn get_matching_record_count(
        &self,
        field: &crate::framework::db::field::Field,
        column_index: i32,
    ) -> std::io::Result<i32> {
        let _ = (field, column_index);
        panic!("DBCachedObjectStore::get_matching_record_count is not implemented for this store")
    }

    /// Mirrors `getObjectAt(long)`, needed by
    /// [`AbstractDBTraceSymbolSingleTypeViewBase::get_by_key`](crate::trace::database::symbol::abstract_db_trace_symbol_single_type_view::AbstractDBTraceSymbolSingleTypeViewBase::get_by_key).
    fn get_object_at(&self, key: i64) -> std::sync::Arc<T> {
        let _ = key;
        panic!("DBCachedObjectStore::get_object_at is not implemented for this store")
    }

    /// Mirrors `asMap().values()`, needed by
    /// [`AbstractDBTraceSymbolSingleTypeViewBase::construct_view`](crate::trace::database::symbol::abstract_db_trace_symbol_single_type_view::AbstractDBTraceSymbolSingleTypeViewBase::construct_view).
    ///
    /// A direct, `T`-typed method rather than routing through `asMap()`:
    /// [`DBCachedObjectStoreMap`](crate::util::database::db_cached_object_store_map::DBCachedObjectStoreMap)
    /// (the port of `asMap()`'s return type) has its own `values()` return the opaque
    /// [`DBCachedObjectStoreValueCollection`] marker, since no caller before this one has needed a
    /// real `T`-typed values view through that path; going through it here would give
    /// `construct_view` nothing to actually iterate.
    fn values(&self) -> Vec<std::sync::Arc<T>> {
        panic!("DBCachedObjectStore::values is not implemented for this store")
    }

    /// Mirrors `invalidateCache()`, needed by
    /// [`AbstractDBTraceSymbolSingleTypeViewBase::invalidate_cache`](crate::trace::database::symbol::abstract_db_trace_symbol_single_type_view::AbstractDBTraceSymbolSingleTypeViewBase::invalidate_cache).
    fn invalidate_cache(&self) {
        panic!("DBCachedObjectStore::invalidate_cache is not implemented for this store")
    }
}

/// Placeholder for the K<->Field conversion half of
/// `ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec<K, T, F extends Field>`,
/// needed by [`crate::util::database::db_cached_object_index::DBCachedObjectIndex`].
///
/// The nested `DBFieldCodec` interface also declares `store`/`load` (`OT`-to-`DBRecord`
/// persistence), already covered narrowly for
/// [`DBAnnotatedObject::codecs`](crate::util::database::db_annotated_object::DBAnnotatedObject::codecs)
/// by the non-generic [`DBFieldCodec`] placeholder above (which must stay non-generic to remain
/// usable as `Box<dyn DBFieldCodec>` in that trait's heterogeneous per-column list).
/// `DBCachedObjectIndex` instead only ever calls the `K`-facing conversion half
/// (`encodeField`/`getValue`), so that surface is declared as its own placeholder here rather
/// than widening the store/load-only one. The `F extends Field` type parameter collapses into
/// the existing [`Field`](crate::framework::db::field::Field) enum, which already covers every
/// Java `Field` subtype.
pub trait DBIndexFieldCodec<K, T: crate::util::database::db_annotated_object::DBAnnotatedObject>:
    Send + Sync
{
    /// Encodes a key value into its indexed-column field representation, mirroring
    /// `encodeField(K)`.
    fn encode_field(&self, key: &K) -> crate::framework::db::field::Field;

    /// Extracts the key value from an object's indexed field, mirroring `getValue(T)`.
    fn get_value(&self, obj: &T) -> K;
}

/// Placeholder for `ghidra.util.database.spatial.hyper.Dimension`, needed by
/// [`crate::util::database::spatial::hyper::euclidean_hyper_space::EuclideanHyperSpace`].
///
/// The real `Dimension<T, P, B>` is generic in a per-dimension coordinate type `T` (e.g.
/// `String` for [`StringDimension`](crate::util::database::spatial::hyper::StringDimension),
/// `u64` for [`ULongDimension`](crate::util::database::spatial::hyper::ULongDimension));
/// `EuclideanHyperSpace` holds a heterogeneous list of dimensions (Java's
/// `List<Dimension<?, P, B>>` wildcard), so `T` can never appear in this trait's object-safe
/// surface. Every method `EuclideanHyperSpace` calls that would otherwise expose `T`
/// (`lower`/`upper`, used only for equality in `boxesEqual` and `collectBounds`) is replaced by
/// a string-keyed equivalent here; every method that combines `T` values internally
/// (`measureUnion`/`measureIntersection`, which read `unionLower`/`unionUpper` or
/// `intersectionLower`/`intersectionUpper`/`compare` then `distance`) is collapsed into a single
/// `f64`-returning method, so `T` never needs to leave a concrete `Dimension` implementation.
/// Only the members `EuclideanHyperSpace` needs are declared; the real port additionally carries
/// `mid`/`min`/`max`/`absoluteMin`/`absoluteMax`/`intersect`/`value` for its own T-typed callers.
pub trait Dimension<P: HyperPoint, B: HyperBox<P>>: Send + Sync {
    /// String key for this dimension's lower bound of `box_`, mirroring `lower(B)` -- used only
    /// for equality (`Objects.equals`), never compared ordinally, so a stable string
    /// representation stands in for the erased `T`.
    fn lower_key(&self, box_: &B) -> String;

    /// String key for this dimension's upper bound of `box_`, mirroring `upper(B)`.
    fn upper_key(&self, box_: &B) -> String;

    /// Whether `box_` contains `point` along this dimension, mirroring `contains(B, P)`.
    fn contains(&self, box_: &B, point: &P) -> bool;

    /// This dimension's extent of `box_`, mirroring `measure(B)` (`distance(upper, lower)`).
    fn measure(&self, box_: &B) -> f64;

    /// This dimension's extent of the union of `a` and `b`, mirroring `EuclideanHyperSpace`'s
    /// `measureUnion` (`distance(unionUpper(a, b), unionLower(a, b))`).
    fn measure_union(&self, a: &B, b: &B) -> f64;

    /// This dimension's extent of the intersection of `a` and `b`, or `0` if they don't overlap
    /// along this dimension, mirroring `EuclideanHyperSpace`'s `measureIntersection`
    /// (`compare(intersectionLower, intersectionUpper) > 0 ? 0 : distance(...)`).
    fn measure_intersection(&self, a: &B, b: &B) -> f64;

    /// Distance between `a` and `b` along this dimension, mirroring `pointDistance(P, P)`.
    fn point_distance(&self, a: &P, b: &P) -> f64;

    /// Whether `outer` encloses `inner` along this dimension, mirroring `encloses(B, B)`.
    fn encloses(&self, outer: &B, inner: &B) -> bool;
}
