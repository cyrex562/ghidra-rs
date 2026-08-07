//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use super::async_utils::AsyncExecutor;
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

/// Placeholder for `ghidra.util.database.AbstractDirectedLongKeyIterator`, needed by
/// [`crate::util::database::directed_long_key_iterator`].
///
/// The real class wraps a `db.DBLongIterator` (already ported as
/// [`crate::framework::db::DBLongIterator`]) and implements
/// [`DirectedLongKeyIterator`](crate::util::database::DirectedLongKeyIterator)'s `hasNext`/`next`
/// by delegating to it in the direction imposed by the concrete subclass (see
/// [`ForwardLongKeyIterator`]/[`BackwardLongKeyIterator`] below); only `delete()` is common to
/// both subclasses, so only it is declared here.
pub trait AbstractDirectedLongKeyIterator: Send + Sync {
    fn delete(&self) -> std::io::Result<bool>;
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
    ) -> std::io::Result<Box<dyn AbstractDirectedLongKeyIterator>>;
}
