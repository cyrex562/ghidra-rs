//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::async_utils::AsyncExecutor;
pub use super::bytesearch::PatternFactory;
use super::database::spatial::hyper::{HyperBox, HyperPoint};
use super::datastruct::NoSuchIndexException;
use super::exception::{CancelledException, NoValueException};
use super::graph::key_indexable_set::KeyIndexableSet;
use super::graph::keyed_object::KeyedObject;
use super::graph::vertex::Vertex;
use super::task::TaskMonitor;
use crate::feature::base::memsearch::bytesource::{
    AddressableByteSource, SearchRegion, generate_program_location,
};
use crate::program::model::address::{Address, AddressRange, AddressRangeIterator};
use crate::program::model::block::CodeBlock;
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::bytesearch::ByteSequence;
use std::sync::Arc;

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

/// Placeholder for `docking.widgets.table.TableRowMapper`, needed by
/// [`crate::util::table::program_location_table_row_mapper::ProgramLocationTableRowMapper`].
///
/// The real class also carries reflection-derived `getSourceType`/`getDestinationType`
/// accessors that recover `ROW_TYPE`/`EXPECTED_ROW_TYPE` at runtime, and is generic over a third
/// `DATA_SOURCE` type parameter; the only in-repo subclass ported so far
/// (`ProgramLocationTableRowMapper`) always instantiates `DATA_SOURCE` as `Program`, so that
/// parameter is fixed here rather than kept generic (an unbounded `dyn Program` type argument
/// would otherwise force every `map` call site to hand over a `'static` reference, which real
/// callers -- who only ever have a short-lived borrow -- can't do).
pub trait TableRowMapper<ROW_TYPE, EXPECTED_ROW_TYPE>: Send + Sync {
    /// Maps a row object of `ROW_TYPE` to the type expected by the destination table's dynamic
    /// columns, mirroring `TableRowMapper.map(ROW_TYPE, DATA_SOURCE, ServiceProvider)`.
    fn map(
        &self,
        row_object: &ROW_TYPE,
        data: &dyn crate::program::model::listing::program::Program,
        service_provider: &dyn crate::framework::plugintool::service_provider::ServiceProvider,
    ) -> EXPECTED_ROW_TYPE;
}

/// Placeholder for `ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn`, needed by
/// [`crate::util::table::field::abstract_program_location_table_column::AbstractProgramLocationTableColumn`].
///
/// The real class is an abstract base class that specializes `AbstractDynamicTableColumn` with
/// `Program` as the data source type. It carries constructor overloads for `uniqueID`; since
/// this trait carries no data, those are left to the real port. Only the marker role is needed here.
pub trait AbstractProgramBasedDynamicTableColumn: Send + Sync {}

/// Placeholder for `docking.widgets.table.DynamicTableColumn`, needed by
/// [`crate::util::table::program_location_table_row_mapper::ProgramLocationTableRowMapper`].
///
/// The real class carries the full column contract (name, width, renderer, editor, settings
/// definitions, ...) and a `DATA_SOURCE` type parameter fixed to `Program` here for the same
/// reason as [`TableRowMapper`] above; the only thing this crate's one caller needs from it is a
/// way to recover a `ProgramLocationTableColumn` view when the concrete column happens to also be
/// one, mirroring the Java method's `instanceof ProgramLocationTableColumn<?, ?>` check.
pub trait DynamicTableColumn<ROW_TYPE, COLUMN_TYPE>: Send + Sync {
    /// Returns this column as a `ProgramLocationTableColumn`, if it is also one. Defaults to
    /// `None`; overridden by columns that also implement
    /// [`ProgramLocationTableColumn`](crate::util::table::field::program_location_table_column::ProgramLocationTableColumn).
    fn as_program_location_table_column(
        &self,
    ) -> Option<
        &dyn crate::util::table::field::program_location_table_column::ProgramLocationTableColumn<
            ROW_TYPE,
            COLUMN_TYPE,
        >,
    > {
        None
    }
}

/// Placeholder for `ghidra.util.table.MappedProgramLocationTableColumn`, needed by
/// [`crate::util::table::program_location_table_row_mapper::ProgramLocationTableRowMapper`]'s
/// default `create_mapped_table_column`.
///
/// The real class also supports a custom unique-identifier constructor and prefers a row object
/// that already *is* a `ProgramLocation` over remapping it (`getProgramLocation`'s `rowObject
/// instanceof ProgramLocation` fast path); neither is needed to satisfy this crate's only caller,
/// so only the always-remap path is implemented here.
pub struct MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE> {
    pub mapper: std::sync::Arc<
        dyn crate::util::table::program_location_table_row_mapper::ProgramLocationTableRowMapper<
            ROW_TYPE,
            EXPECTED_ROW_TYPE,
        >,
    >,
    pub table_column: Box<dyn DynamicTableColumn<EXPECTED_ROW_TYPE, COLUMN_TYPE>>,
}

impl<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
    crate::util::table::field::program_based_dynamic_table_column::ProgramBasedDynamicTableColumn
    for MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
{
}

impl<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
    crate::util::table::field::program_location_table_column::ProgramLocationTableColumn<
        ROW_TYPE,
        COLUMN_TYPE,
    > for MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
{
    fn get_program_location(
        &self,
        row_object: &ROW_TYPE,
        settings: &dyn crate::docking::settings::settings::Settings,
        program: &dyn crate::program::model::listing::program::Program,
        service_provider: &dyn crate::framework::plugintool::service_provider::ServiceProvider,
    ) -> Box<dyn crate::program::util::program_location::ProgramLocation> {
        let mapped = self.mapper.map(row_object, program, service_provider);
        let program_column = self
            .table_column
            .as_program_location_table_column()
            .expect(
                "MappedProgramLocationTableColumn is only constructed from a ProgramLocationTableColumn",
            );
        program_column.get_program_location(&mapped, settings, program, service_provider)
    }
}

impl<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE> DynamicTableColumn<ROW_TYPE, COLUMN_TYPE>
    for MappedProgramLocationTableColumn<ROW_TYPE, EXPECTED_ROW_TYPE, COLUMN_TYPE>
{
    fn as_program_location_table_column(
        &self,
    ) -> Option<
        &dyn crate::util::table::field::program_location_table_column::ProgramLocationTableColumn<
            ROW_TYPE,
            COLUMN_TYPE,
        >,
    > {
        Some(self)
    }
}

/// Placeholder for `ghidra.util.bytesearch.Pattern`, referenced by [`crate::util::bytesearch::MatchAction`].
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait Pattern: Send + Sync {
    /// Returns post-rules for this pattern.
    fn get_post_rules(&self) -> Vec<Box<dyn crate::util::bytesearch::PostRule>>;

    /// Returns match actions for this pattern.
    fn get_match_actions(&self) -> Vec<Box<dyn crate::util::bytesearch::MatchAction>>;

    /// Sets match actions for this pattern.
    fn set_match_actions(&self, actions: &[Box<dyn crate::util::bytesearch::MatchAction>]);

    /// Returns the mark offset.
    fn get_mark_offset(&self) -> i32;

    /// Restore XML attributes from parser.
    fn restore_xml_attributes(
        &self,
        postrulelist: Vec<Box<dyn crate::util::bytesearch::PostRule>>,
        actionlist: Vec<Box<dyn crate::util::bytesearch::MatchAction>>,
        parser: &dyn XmlPullParser,
        pfactory: &dyn PatternFactory,
    ) -> std::io::Result<()>;

    /// Restore from XML. [referenced in target]
    fn restore_xml(&self, parser: &dyn XmlPullParser, pfactory: &dyn PatternFactory) -> std::io::Result<()>;

    /// Read patterns from file.
    fn read_patterns(
        &self,
        file: &dyn ResourceFile,
        patlist: Vec<Box<dyn Pattern>>,
        pfactory: &dyn PatternFactory,
    ) -> std::io::Result<()>;

    /// Handle XML parsing error.
    fn error(&self, exception: &dyn SAXParseException) -> std::io::Result<()>;

    /// Handle XML parsing fatal error.
    fn fatal_error(&self, exception: &dyn SAXParseException) -> std::io::Result<()>;

    /// Handle XML parsing warning.
    fn warning(&self, exception: &dyn SAXParseException) -> std::io::Result<()>;

    /// Read post-patterns from file.
    fn read_post_patterns(
        &self,
        file: &dyn FileMarker,
        pattern_list: Vec<Box<dyn Pattern>>,
        pfactory: &dyn PatternFactory,
    ) -> std::io::Result<()>;

    /// Check post-rules at offset.
    fn check_post_rules(&self, offset: i64) -> bool;

    /// Get pre-sequence length.
    fn get_pre_sequence_length(&self) -> i32;
}

/// Placeholder for `ghidra.xml.XmlPullParser`, referenced by `Pattern` and `MatchAction`.
pub trait XmlPullParser: Send + Sync {}

/// Placeholder for `java.io.File`, referenced by `Pattern`.
pub trait FileMarker: Send + Sync {}

/// Placeholder for `ghidra.util.filechooser.ResourceFile`, referenced by `Pattern`.
pub trait ResourceFile: Send + Sync {}

/// Placeholder for `org.xml.sax.SAXParseException`, referenced by `Pattern`.
pub trait SAXParseException: Send + Sync {}

/// Placeholder for `ghidra.util.NumericUtilities`, referenced by
/// [`PrettyBytes`](crate::pcode::exec::debugger_pcode_utils::PrettyBytes) before the real class is
/// ported. Java's version is a final class of statics, so this is a unit struct with associated
/// functions rather than a trait. Only the hex-rendering entry points that call site needs are
/// declared; unlike most stubs these carry real bodies, since their behavior is short and fully
/// determined: two lowercase, zero-padded hex digits per byte, joined by the delimiter.
pub struct NumericUtilities;

impl NumericUtilities {
    /// Port of `NumericUtilities.convertBytesToString(byte[], String)`.
    pub fn convert_bytes_to_string(bytes: &[u8], delimiter: &str) -> String {
        Self::convert_bytes_to_string_range(bytes, 0, bytes.len(), delimiter)
    }

    /// Port of `NumericUtilities.convertBytesToString(byte[], int, int, String)`.
    ///
    /// Panics where Java's `Objects.checkFromToIndex` throws `IndexOutOfBoundsException`.
    pub fn convert_bytes_to_string_range(
        bytes: &[u8],
        start: usize,
        len: usize,
        delimiter: &str,
    ) -> String {
        let end = start + len;
        assert!(end <= bytes.len(), "byte range exceeds the array's length");
        let mut sb = String::with_capacity(len * (2 + delimiter.len()));
        for byte in &bytes[start..end] {
            if !sb.is_empty() {
                sb.push_str(delimiter);
            }
            sb.push_str(&format!("{:02x}", byte));
        }
        sb
    }

    /// Port of `NumericUtilities.parseHexLong(String)`, needed by
    /// [`elf_loader_options_factory`](crate::app::util::opinion::elf_loader_options_factory).
    /// Treated as hex regardless of an optional `0x`/`0X` prefix, parsed as an up-to-64-bit
    /// unsigned magnitude and reinterpreted as a signed `i64` -- matching `parseHelper(s, true,
    /// BigInteger::longValue, MAX_UNSIGNED_LONG)`, whose `BigInteger.longValue()` truncates to the
    /// low 64 bits the same way an `as i64` bit-reinterpretation does.
    pub fn parse_hex_long(s: &str) -> Result<i64, std::num::ParseIntError> {
        let trimmed = s.trim();
        let digits = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        u64::from_str_radix(digits, 16).map(|v| v as i64)
    }
}

/// Placeholder for the unported Java type `ghidra.features.base.memsearch.bytesource.ProgramByteSource`,
/// referenced by [`crate::util::bytesearch::program_memory_searcher::ProgramMemorySearcher`].
/// `ProgramByteSource` is a concrete Java class (not an interface), so this stub is a struct
/// implementing the already-ported [`AddressableByteSource`] trait. Only the members
/// `ProgramMemorySearcher`'s constructor and the [`AddressableByteSequence`] it feeds actually
/// exercise (`get_bytes`) are backed by real behavior; `get_searchable_regions` is trimmed to an
/// empty list since no caller here enumerates regions. Replace with the real port when
/// `ProgramByteSource.java` is ported.
pub struct ProgramByteSource {
    program: Arc<dyn Program>,
}

impl ProgramByteSource {
    /// Java: `ProgramByteSource(Program)`, which caches `program.getMemory()`.
    pub fn new(program: Arc<dyn Program>) -> Self {
        Self { program }
    }

    fn memory(&self) -> Arc<dyn crate::program::model::mem::Memory> {
        self.program
            .get_memory()
            .expect("ProgramByteSource requires a program with memory")
    }
}

impl AddressableByteSource for ProgramByteSource {
    fn get_bytes(&self, address: &Address, bytes: &mut [u8], length: usize) -> usize {
        self.memory().get_bytes(address, &mut bytes[..length])
    }

    fn get_searchable_regions(&self) -> Vec<Box<dyn SearchRegion>> {
        Vec::new()
    }

    fn invalidate(&mut self) {
        // Java: no-op in the static (non-debugger) case.
    }

    fn get_canonical_location(&self, address: &Address) -> Box<dyn ProgramLocation> {
        generate_program_location(self.program.clone(), address)
    }

    fn rebase_from_canonical(&self, location: &dyn ProgramLocation) -> Address {
        let source_base = location
            .get_program()
            .get_image_base()
            .expect("rebase_from_canonical requires a source program with an image base");
        let offset = location.get_byte_address().subtract(&source_base);
        let target_base = self
            .program
            .get_image_base()
            .expect("rebase_from_canonical requires a program with an image base");
        target_base.add(offset).expect("rebased address overflow")
    }
}

/// Placeholder for the unported Java type `ghidra.util.bytesearch.AddressableByteSequence`,
/// referenced by [`crate::util::bytesearch::program_memory_searcher::ProgramMemorySearcher`].
/// `AddressableByteSequence` is a concrete Java class (not an interface), so this stub is a
/// struct implementing the already-ported [`ByteSequence`] trait, backed by real behavior (it is
/// exercised directly by `ProgramMemorySearcher`'s own smoke test). Replace with the real port
/// when `AddressableByteSequence.java` is ported.
pub struct AddressableByteSequence {
    byte_source: Arc<dyn AddressableByteSource>,
    bytes: Vec<u8>,
    capacity: usize,
    start_address: Option<Address>,
    length: usize,
}

impl AddressableByteSequence {
    /// Java: `AddressableByteSequence(AddressableByteSource, int)`.
    pub fn new(byte_source: Arc<dyn AddressableByteSource>, capacity: usize) -> Self {
        Self {
            byte_source,
            bytes: vec![0u8; capacity],
            capacity,
            start_address: None,
            length: 0,
        }
    }

    /// Java: `clear()`.
    pub fn clear(&mut self) {
        self.start_address = None;
        self.length = 0;
    }

    /// Java: `setRange(AddressRange)`.
    pub fn set_range(&mut self, range: &AddressRange) {
        self.set_range_at(range.min_address().clone(), range.length() as usize);
    }

    /// Java: `setRange(Address, int)`.
    pub fn set_range_at(&mut self, start: Address, length: usize) {
        assert!(length <= self.capacity, "Length exceeds capacity");
        self.byte_source.get_bytes(&start, &mut self.bytes[..length], length);
        self.start_address = Some(start);
        self.length = length;
    }

    /// Java: `getAddress(int)`.
    pub fn get_address(&self, index: usize) -> Address {
        assert!(index < self.length, "index out of bounds");
        if index == 0 {
            return self.start_address.clone().expect("range must be set");
        }
        self.start_address
            .as_ref()
            .expect("range must be set")
            .add(index as i64)
            .expect("address overflow")
    }
}

impl ByteSequence for AddressableByteSequence {
    fn len(&self) -> usize {
        self.length
    }

    fn get_byte(&self, index: usize) -> u8 {
        assert!(index < self.length, "index out of bounds");
        self.bytes[index]
    }

    fn get_bytes(&self, index: usize, size: usize) -> Vec<u8> {
        assert!(index + size <= self.length, "index out of bounds");
        self.bytes[index..index + size].to_vec()
    }

    fn has_available_bytes(&self, index: usize, length: usize) -> bool {
        index.checked_add(length).map_or(false, |end| end <= self.length)
    }
}

/// Placeholder for `ghidra.util.ascii.Sequence`, needed by [`crate::util::ascii::ByteStreamCharMatcher`].
///
/// A sequence represents a contiguous range of bytes in a stream, with metadata about
/// start/end positions and null termination. Only the accessors [`ByteStreamCharMatcher`]
/// needs are declared here; the real port carries the full sequence representation.
pub trait Sequence: Send + Sync {
    /// Returns the start index of this sequence in the byte stream.
    fn get_start(&self) -> i64;

    /// Returns the end index of this sequence in the byte stream.
    fn get_end(&self) -> i64;

    /// Returns whether this sequence is null-terminated.
    fn is_null_terminated(&self) -> bool;

    /// Returns the string data type associated with this sequence.
    fn get_string_data_type(&self) -> Box<dyn AbstractStringDataType>;

    /// Returns the length of this sequence.
    fn get_length(&self) -> i32;

    /// Compares this sequence to another object for equality.
    fn equals(&self, obj: &dyn std::any::Any) -> bool;

    /// Returns the hash code for this sequence.
    fn hash_code(&self) -> i32;

    /// Returns a string representation of this sequence.
    fn to_string(&self) -> String;
}

/// Placeholder for `ghidra.program.model.data.AbstractStringDataType`, needed by [`Sequence`].
///
/// Represents metadata about string data types. This is a marker trait until the real port
/// is available.
pub trait AbstractStringDataType: Send + Sync {}
