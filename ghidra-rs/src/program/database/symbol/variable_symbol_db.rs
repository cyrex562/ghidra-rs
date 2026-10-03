//! Port of `ghidra.program.database.symbol.VariableSymbolDB` as a trait (cycle cut-point).
//!
//! `VariableSymbolDB` is Java's concrete `public class VariableSymbolDB extends SymbolDB` -- the
//! base for function-local variable/parameter symbols (`SymbolType.PARAMETER`/`LOCAL_VAR`) and,
//! via [`GlobalVariableSymbolDb`](crate::program::database::symbol::GlobalVariableSymbolDb)'s
//! Java counterpart `GlobalVariableSymbolDB`, global variable symbols too. Note it extends
//! `SymbolDB` *directly*, not `MemorySymbol` -- variable storage addresses (stack/register/hash
//! space) are not memory addresses, so `MemorySymbol`'s constructor precondition
//! (`addr.isMemoryAddress() || isExternal()`) would not generally hold for them.
//!
//! Like every other concrete symbol leaf class in this package
//! ([`CodeSymbol`](crate::program::database::symbol::CodeSymbol),
//! [`FunctionSymbol`](crate::program::database::symbol::FunctionSymbol),
//! [`GlobalVariableSymbolDb`]), this is ported as an object-safe trait extending [`Symbol`]
//! directly rather than composing a concrete `SymbolDB` base, since `VariableSymbolDB`'s
//! constructor is wired directly to `SymbolManager`/`VariableStorageManagerDB` (both cut-points).
//! `VariableSymbolDB`'s substantial real logic -- `doGetName`'s parameter/local-var naming,
//! `computeVariableStorage`'s caching and sentinel-storage fallback, `getDataType`'s
//! datatype-id-or-undefined-fallback, `getFirstUseOffset`/`getOrdinal`'s shared-column dispatch,
//! `validateNameSource` -- is ported as real default methods; only genuine
//! `SymbolManager`/`VariableStorageManagerDB`/`FunctionManagerDB` reach-throughs are required
//! accessor methods.
//!
//! # Wiring into the existing `VariableDb`/`FunctionDb`/`LocalVariableDb` seam
//!
//! [`crate::program::database::function::VariableDb`] and
//! [`crate::program::database::function::LocalVariableDb`] (both already ported and DONE) were
//! built against [`crate::program::seam_stubs::VariableSymbolDb`], a placeholder trait whose doc
//! comment explicitly says it stands in "before the real class is ported". This module *is* that
//! real class, so rather than touching any of those already-shipped, already-tested call sites,
//! a blanket `impl<T: VariableSymbolDb> seam_stubs::VariableSymbolDb for T` at the bottom of this
//! file lets any future concrete implementor of this trait automatically satisfy that seam too,
//! with each seam method forwarding to this trait's real, faithfully-ported equivalent (see the
//! forwarding table in the impl block's doc comment).
//!
//! # What was left out
//! - `equals(Object)`: identity-only (`return obj == this`); no `Object` identity contract to
//!   satisfy in Rust, matching this crate's established convention for the same situation (see
//!   e.g. `VariableDb`'s module docs).
//! - The `OldGenericNamespaceAddress` branch of `computeVariableStorage()`: this port's `Address`
//!   type has no variant corresponding to Java's `OldGenericNamespaceAddress` subclass (see
//!   [`crate::program::model::address::old_generic_namespace_address::OldGenericNamespaceAddress`],
//!   a distinct, non-`Address` upgrade-only value type in this port), so `address instanceof
//!   OldGenericNamespaceAddress` is structurally always `false` here and the branch is dead code
//!   under this port's type system; [`VariableSymbolDb::compute_variable_storage`] only models the
//!   remaining (live) branch.
//! - `getObject()`, `delete()`, `getProgramLocation()`, `setStorageAndDataType(...)`: left as
//!   required methods with no default body, since each needs `FunctionManagerDB`/`FunctionDB`
//!   collaborators (or, for `getProgramLocation`, the unported `VariableNameFieldLocation`) that
//!   this trait's accessor surface cannot reach generically -- matching the convention already
//!   used by `CodeSymbol::delete_with_option`/`FunctionSymbol::delete`.
//! - The package-private constructor and `setRecordFields`/`static` helpers: implementation
//!   detail of a concrete DB-backed type's own construction path.

use std::sync::Arc;

use crate::program::database::function::FunctionDb;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::function::DEFAULT_LOCAL_PREFIX;
use crate::program::model::listing::variable::SetVariableNameError;
use crate::program::model::listing::{BadStorage, Program, UnassignedStorage, Variable, VariableStorage};
use crate::program::model::symbol::{
    DefaultSymbolUtilities, Namespace, Reference, SourceType, Symbol, SymbolType, SymbolUtilities,
};
use crate::program::util::ProgramLocation;
use crate::util::task::TaskMonitor;

/// Duplicate a `Box<dyn VariableStorage>`, preserving sentinel identity (bad/unassigned/void
/// storage). Mirrors
/// [`VariableDb`](crate::program::database::function::variable_db)'s private `duplicate_storage`
/// helper (duplicated locally since that one is private to its module; see this crate's existing
/// convention of duplicating small private cross-module helpers, e.g.
/// `variable_db_compare_varnode_lists`).
fn duplicate_variable_storage(s: &dyn VariableStorage) -> Box<dyn VariableStorage> {
    if s.is_unassigned_storage() {
        Box::new(UnassignedStorage)
    } else if s.is_bad_storage() {
        Box::new(BadStorage)
    } else if s.is_void_storage() {
        Box::new(crate::program::model::listing::VoidStorage)
    } else {
        s.with_varnodes(s.get_varnodes())
    }
}

/// Symbol class for function variables (parameters and local variables), and the base for global
/// variable symbols.
///
/// Port of `ghidra.program.database.symbol.VariableSymbolDB`. See the module docs for the
/// composition choice and everything intentionally left out.
pub trait VariableSymbolDb: Symbol {
    // -----------------------------------------------------------------------------------------
    // Required accessors: SymbolManager/VariableStorageManagerDB/FunctionManagerDB reach-throughs.
    // -----------------------------------------------------------------------------------------

    /// Accessor standing in for `symbolMgr.getProgram()`, used by
    /// [`do_get_name`](Self::do_get_name)/[`validate_name_source`](Self::validate_name_source)'s
    /// `SymbolUtilities` calls.
    fn program(&self) -> Arc<dyn Program>;

    /// Accessor standing in for `variableMgr.getVariableStorage(address)`, used by
    /// [`compute_variable_storage`](Self::compute_variable_storage). Returns `None` both for a
    /// genuine lookup miss and (collapsing Java's `catch (IOException e)` path) a database error.
    fn variable_storage_lookup(&self) -> Option<Box<dyn VariableStorage>>;

    /// Backing storage for the lazily-cached `variableStorage` field, read side. `None` means "not
    /// yet cached; recompute via [`compute_variable_storage`](Self::compute_variable_storage)".
    fn cached_variable_storage(&self) -> Option<Box<dyn VariableStorage>>;

    /// Backing storage for the lazily-cached `variableStorage` field, write side. Also stands in
    /// for `setInvalid()`'s `variableStorage = null` reset when called with `None`.
    fn set_cached_variable_storage(&self, storage: Option<Box<dyn VariableStorage>>);

    /// Accessor standing in for `symbolMgr.getDataType(getDataTypeId())`, used by
    /// [`get_data_type`](Self::get_data_type). Returns `None` when no data type ID is stored or it
    /// does not resolve, matching Java's `null` return.
    fn stored_data_type(&self) -> Option<Box<dyn DataType>>;

    /// Accessor standing in for the `DataType.VOID` singleton, used by
    /// [`get_data_type`](Self::get_data_type)'s void-storage fallback. Required because a concrete
    /// `VoidDataType` is not yet ported in this crate.
    fn void_data_type(&self) -> Box<dyn DataType>;

    /// Accessor standing in for `Undefined.getUndefinedDataType(int)`, used by
    /// [`get_data_type`](Self::get_data_type)'s non-void fallback. Required because a concrete
    /// `Undefined` family is not yet ported in this crate.
    fn undefined_data_type_of_size(&self, size: i32) -> Box<dyn DataType>;

    /// Accessor standing in for reading the shared "generic symbol data 2"
    /// `SYMBOL_VAROFFSET_COL` (ordinal for parameters, first-use offset for locals) off the
    /// backing record. Should return `0` when there is no backing record, matching Java's
    /// `if (record != null) { ... } return 0;`.
    fn variable_offset(&self) -> i32;

    /// Accessor standing in for `setVariableOffset(int)`'s record write, `updateRecord()`, and
    /// `symbolMgr.symbolDataChanged(this)` notification. Should no-op when there is no backing
    /// record, matching Java's `if (record != null) { ... }`.
    fn set_variable_offset(&self, offset: i32);

    /// Accessor standing in for `getSymbolComment()`'s `SYMBOL_COMMENT_COL` read.
    fn get_symbol_comment(&self) -> Option<String>;

    /// Accessor standing in for `setSymbolComment(String)`'s `SYMBOL_COMMENT_COL` write and
    /// `updateRecord()` (no change notification is issued, matching the Java doc comment).
    fn set_symbol_comment(&self, comment: Option<String>);

    /// Accessor standing in for `super.doGetName()` (`SymbolDB`'s own stored-name lookup), used as
    /// the fallback in [`do_get_name`](Self::do_get_name).
    fn base_do_get_name(&self) -> String;

    /// Accessor standing in for whether this symbol's record is still present
    /// (`refreshIfNeeded()`'s boolean result), used by [`do_get_name`](Self::do_get_name). Defaults
    /// to `true` (always valid/refreshed) so implementors unconcerned with deletion races are
    /// unaffected.
    fn is_refreshable(&self) -> bool {
        true
    }

    /// Accessor standing in for `symbolMgr.getReferenceManager().getReferencesTo(getObject())`,
    /// used by [`get_reference_count`](Self::get_reference_count)/
    /// [`has_references`](Self::has_references)/[`get_references`](Self::get_references). Required
    /// because it depends on both the reference manager and [`get_object`](Self::get_object), both
    /// cut-points from this trait's perspective.
    fn references_to_object(&self) -> Vec<Arc<dyn Reference>>;

    // -----------------------------------------------------------------------------------------
    // Required methods left with no default: genuine `FunctionManagerDB`/`FunctionDB` reach-throughs.
    // -----------------------------------------------------------------------------------------

    /// Stands in for `VariableSymbolDB.getFunction()`:
    /// `symbolMgr.getFunctionManager().getFunction(getParentNamespace().getID())`.
    fn get_function(&self) -> Option<Arc<dyn FunctionDb>>;

    /// Stands in for `VariableSymbolDB.getObject()`: `func.getVariable(this)` when
    /// [`get_function`](Self::get_function) resolves, else `None`. Left required (see module
    /// docs) since it depends on `FunctionDB`, a collaborator not modeled generically here.
    fn get_object(&self) -> Option<Box<dyn Variable>>;

    /// Stands in for `VariableSymbolDB.delete()`: notifies the owning function
    /// (`FunctionDB.doDeleteVariable`) before deleting the underlying symbol record
    /// (`super.delete()`, i.e. `symbolMgr.doRemoveSymbol(this)`). Returns whether the symbol was
    /// actually deleted. Left required (see module docs).
    fn delete(&self) -> bool;

    /// Stands in for `VariableSymbolDB.getProgramLocation()`: builds a `VariableNameFieldLocation`
    /// for [`get_object`](Self::get_object)'s result, or `None` if there is no such variable. Left
    /// required: `VariableNameFieldLocation` is not yet ported.
    fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>>;

    /// Stands in for the package-private `VariableSymbolDB.setStorageAndDataType(VariableStorage,
    /// DataType)`:
    /// ```java
    /// public void setStorageAndDataType(VariableStorage newStorage, DataType dt) {
    ///     long dataTypeID = symbolMgr.getProgram().getDataTypeManager().getResolvedID(dt);
    ///     variableStorage = newStorage;
    ///     Address newAddr = variableMgr.getVariableStorageAddress(newStorage, true);
    ///     setAddress(newAddr); // this may be the only symbol which changes its address
    ///     if (dataTypeID != getDataTypeId()) {
    ///         setDataTypeId(dataTypeID);
    ///     } else {
    ///         symbolMgr.symbolDataChanged(this);
    ///     }
    /// }
    /// ```
    /// Left required (see module docs): resolves the data type through the program's
    /// `DataTypeManager` and reassigns this symbol's address through `VariableStorageManagerDB`
    /// and `SymbolDB.setAddress`, none of which this trait's accessor surface reaches generically.
    /// A concrete implementor should also call
    /// [`set_cached_variable_storage`](Self::set_cached_variable_storage) with the new storage, so
    /// that a subsequent [`get_variable_storage`](Self::get_variable_storage) reflects it
    /// immediately (mirroring the Java method's direct `variableStorage = newStorage;` field
    /// write).
    fn set_storage_and_data_type(&self, new_storage: Box<dyn VariableStorage>, data_type: Box<dyn DataType>);

    /// Stands in for the inherited `SymbolDB.setName(String, SourceType)` (via
    /// `setNameAndNamespace`/`doSetNameAndNamespace`). Left required: duplicate-name checking and
    /// namespace validation both require `SymbolManager`, a cut-point from this trait's
    /// perspective. Named distinctly from [`Symbol::set_name`] since that takes `&mut self`, which
    /// cannot be called through the shared `Arc<dyn VariableSymbolDb>` a concrete implementor is
    /// typically held behind (mirroring
    /// [`crate::program::seam_stubs::VariableSymbolDb::rename`]'s identical rationale).
    fn rename(&self, name: &str, source: SourceType) -> Result<(), SetVariableNameError>;

    // -----------------------------------------------------------------------------------------
    // Real default methods.
    // -----------------------------------------------------------------------------------------

    /// Stands in for `VariableSymbolDB.isPrimary()`, which always returns `false` (variable
    /// symbols are never "primary" the way memory-address label/function symbols are). Named
    /// distinctly from [`Symbol::is_primary`] (see [`MemorySymbol::is_external`](crate::program::database::symbol::MemorySymbol::is_external)'s
    /// identical naming-overlap rationale) -- concrete implementors should forward their
    /// `Symbol::is_primary` to this method.
    fn is_primary(&self) -> bool {
        false
    }

    /// Stands in for `VariableSymbolDB.isExternal()`: a variable symbol is external exactly when
    /// its parent (owning function) symbol is. Named distinctly from [`Symbol::is_external`] for
    /// the same reason as [`is_primary`](Self::is_primary).
    fn is_external(&self) -> bool {
        self.get_parent_symbol()
            .map(|parent| parent.is_external())
            .unwrap_or(false)
    }

    /// Stands in for `VariableSymbolDB.isValidParent(Namespace)`: a variable symbol is locked to
    /// the single function whose namespace ID matches its own parent ID.
    fn is_valid_parent(&self, parent: &dyn Namespace) -> bool {
        parent.get_symbol().get_id() == self.get_parent_id()
    }

    /// Stands in for the private `computeVariableStorage()`, minus the dead
    /// `OldGenericNamespaceAddress` branch (see the module docs).
    fn compute_variable_storage(&self) -> Box<dyn VariableStorage> {
        match self.variable_storage_lookup() {
            Some(storage) => storage,
            None => {
                if self.get_symbol_type() == SymbolType::Parameter {
                    Box::new(UnassignedStorage)
                } else {
                    Box::new(BadStorage)
                }
            }
        }
    }

    /// Stands in for `VariableSymbolDB.getVariableStorage()`, including its lazy-cache semantics.
    fn get_variable_storage(&self) -> Box<dyn VariableStorage> {
        if let Some(cached) = self.cached_variable_storage() {
            return cached;
        }
        let computed = self.compute_variable_storage();
        self.set_cached_variable_storage(Some(duplicate_variable_storage(computed.as_ref())));
        computed
    }

    /// Stands in for `VariableSymbolDB.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType> {
        if let Some(dt) = self.stored_data_type() {
            return dt;
        }
        let storage = self.get_variable_storage();
        if storage.is_void_storage() {
            self.void_data_type()
        } else {
            self.undefined_data_type_of_size(storage.size())
        }
    }

    /// Stands in for the private `getParamName()`:
    /// `SymbolUtilities.getDefaultParamName(getOrdinal())`.
    fn param_name(&self) -> String {
        DefaultSymbolUtilities.get_default_param_name(self.get_ordinal())
    }

    /// Stands in for `VariableSymbolDB.getFirstUseOffset()`: `0` for parameters, the shared
    /// variable-offset column otherwise.
    fn get_first_use_offset(&self) -> i32 {
        if self.get_symbol_type() == SymbolType::Parameter {
            0
        } else {
            self.variable_offset()
        }
    }

    /// Stands in for `VariableSymbolDB.setFirstUseOffset(int)`: only applies to
    /// `SymbolType.LOCAL_VAR` symbols.
    fn set_first_use_offset(&self, first_use_offset: i32) {
        if self.get_symbol_type() == SymbolType::LocalVar {
            self.set_variable_offset(first_use_offset);
        }
    }

    /// Stands in for `VariableSymbolDB.getOrdinal()`: the shared variable-offset column for
    /// parameters, `Integer.MIN_VALUE` otherwise.
    fn get_ordinal(&self) -> i32 {
        if self.get_symbol_type() == SymbolType::Parameter {
            self.variable_offset()
        } else {
            i32::MIN
        }
    }

    /// Stands in for `VariableSymbolDB.setOrdinal(int)`: only applies to `SymbolType.PARAMETER`
    /// symbols.
    fn set_ordinal(&self, ordinal: i32) {
        if self.get_symbol_type() == SymbolType::Parameter {
            self.set_variable_offset(ordinal);
        }
    }

    /// Stands in for `VariableSymbolDB.doGetName()`.
    fn do_get_name(&self) -> String {
        if !self.is_refreshable() {
            // TODO: SCR
            return "[Invalid VariableSymbol - Deleted!]".to_string();
        }

        if self.get_symbol_type() == SymbolType::Parameter {
            if self.get_source() == SourceType::Default {
                return self.param_name();
            }
            let stored_name = self.base_do_get_name();
            if DefaultSymbolUtilities.is_default_parameter_name(Some(&stored_name)) {
                return self.param_name();
            }
            return stored_name;
        }

        let storage = self.get_variable_storage();
        if storage.is_bad_storage() {
            return format!("{DEFAULT_LOCAL_PREFIX}_!BAD!");
        }

        if self.get_source() == SourceType::Default {
            return DefaultSymbolUtilities.get_default_local_name(
                self.program().as_ref(),
                storage.as_ref(),
                self.get_first_use_offset(),
            );
        }

        self.base_do_get_name()
    }

    /// Stands in for `VariableSymbolDB.validateNameSource(String, SourceType)`.
    fn validate_name_source(&self, new_name: Option<&str>, source: SourceType) -> SourceType {
        let mut source = source;
        if DefaultSymbolUtilities.is_default_parameter_name(new_name) {
            source = SourceType::Default;
        }
        let sym_type = self.get_symbol_type();
        if sym_type == SymbolType::Parameter && DefaultSymbolUtilities.is_default_parameter_name(new_name) {
            source = SourceType::Default;
        } else if sym_type == SymbolType::LocalVar
            && DefaultSymbolUtilities.is_default_local_name(
                self.program().as_ref(),
                new_name,
                self.get_variable_storage().as_ref(),
            )
        {
            return SourceType::Default;
        }
        source
    }

    /// Stands in for `VariableSymbolDB.getReferenceCount()`: `getReferences(null).length`.
    fn get_reference_count(&self) -> i32 {
        self.references_to_object().len() as i32
    }

    /// Stands in for `VariableSymbolDB.hasReferences()`: `getReferences(null).length != 0`.
    fn has_references(&self) -> bool {
        !self.references_to_object().is_empty()
    }

    /// Stands in for `VariableSymbolDB.getReferences(TaskMonitor)`. The Java method ignores its
    /// `monitor` parameter entirely (a single synchronous manager call, no cancellation point), so
    /// this default does too.
    fn get_references(&self, _monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Reference>> {
        self.references_to_object()
    }
}

/// Blanket bridge into [`crate::program::seam_stubs::VariableSymbolDb`], the placeholder trait
/// [`VariableDb`](crate::program::database::function::VariableDb)/
/// [`LocalVariableDb`](crate::program::database::function::LocalVariableDb) were built against
/// before this real port existed (see the module docs). Any future concrete implementor of this
/// trait automatically satisfies that seam too, with each seam method forwarding to this trait's
/// equivalent:
///
/// | seam method                          | this trait's method              |
/// |---------------------------------------|-----------------------------------|
/// | `variable_data_type`                  | [`VariableSymbolDb::get_data_type`] |
/// | `variable_storage`                    | [`VariableSymbolDb::get_variable_storage`] |
/// | `set_variable_storage_and_data_type`  | [`VariableSymbolDb::set_storage_and_data_type`] |
/// | `variable_first_use_offset`           | [`VariableSymbolDb::get_first_use_offset`] |
/// | `set_variable_first_use_offset`       | [`VariableSymbolDb::set_first_use_offset`] |
/// | `variable_ordinal`                    | [`VariableSymbolDb::get_ordinal`] |
/// | `set_variable_ordinal`                | [`VariableSymbolDb::set_ordinal`] |
/// | `variable_symbol_comment`             | [`VariableSymbolDb::get_symbol_comment`] |
/// | `set_variable_symbol_comment`         | [`VariableSymbolDb::set_symbol_comment`] |
/// | `rename`                              | [`VariableSymbolDb::rename`] |
impl<T: VariableSymbolDb + ?Sized> crate::program::seam_stubs::VariableSymbolDb for T {
    fn variable_data_type(&self) -> Box<dyn DataType> {
        VariableSymbolDb::get_data_type(self)
    }

    fn variable_storage(&self) -> Box<dyn VariableStorage> {
        VariableSymbolDb::get_variable_storage(self)
    }

    fn set_variable_storage_and_data_type(
        &self,
        storage: Box<dyn VariableStorage>,
        data_type: Box<dyn DataType>,
    ) {
        VariableSymbolDb::set_storage_and_data_type(self, storage, data_type)
    }

    fn variable_first_use_offset(&self) -> i32 {
        VariableSymbolDb::get_first_use_offset(self)
    }

    fn set_variable_first_use_offset(&self, first_use_offset: i32) {
        VariableSymbolDb::set_first_use_offset(self, first_use_offset)
    }

    fn variable_ordinal(&self) -> i32 {
        VariableSymbolDb::get_ordinal(self)
    }

    fn set_variable_ordinal(&self, ordinal: i32) {
        VariableSymbolDb::set_ordinal(self, ordinal)
    }

    fn variable_symbol_comment(&self) -> Option<String> {
        VariableSymbolDb::get_symbol_comment(self)
    }

    fn set_variable_symbol_comment(&self, comment: Option<String>) {
        VariableSymbolDb::set_symbol_comment(self, comment)
    }

    fn rename(&self, name: &str, source: SourceType) -> Result<(), SetVariableNameError> {
        VariableSymbolDb::rename(self, name, source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::VoidStorage;
    use std::sync::Mutex;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[derive(Clone)]
    struct MockDataType {
        name: String,
        length: i32,
        void_type: bool,
    }

    impl DataType for MockDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_void_type(&self) -> bool {
            self.void_type
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name()
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockVarSymbol {
        symbol_type: SymbolType,
        source: SourceType,
        variable_offset: Mutex<i32>,
        storage_lookup: Mutex<Option<Box<dyn VariableStorage + Send + Sync>>>,
        cached_storage: Mutex<Option<Box<dyn VariableStorage + Send + Sync>>>,
        stored_dt: Mutex<Option<Box<dyn DataType + Send + Sync>>>,
        comment: Mutex<Option<String>>,
        base_name: String,
        refreshable: bool,
    }

    // `Box<dyn VariableStorage>`/`Box<dyn DataType>` are not `Send`, but the trait requires
    // `Symbol: Send + Sync`; store `Send + Sync`-bounded variants internally and widen on return.
    impl MockVarSymbol {
        fn new(symbol_type: SymbolType, source: SourceType) -> Self {
            MockVarSymbol {
                symbol_type,
                source,
                variable_offset: Mutex::new(0),
                storage_lookup: Mutex::new(None),
                cached_storage: Mutex::new(None),
                stored_dt: Mutex::new(None),
                comment: Mutex::new(None),
                base_name: "stored_name".to_string(),
                refreshable: true,
            }
        }
    }

    impl Symbol for MockVarSymbol {
        fn get_address(&self) -> Address {
            addr(0)
        }
        fn get_name(&self) -> &str {
            "mock_var"
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            VariableSymbolDb::is_primary(self)
        }
        fn get_id(&self) -> i64 {
            5
        }
        fn get_parent_id(&self) -> i64 {
            10
        }
        fn is_external(&self) -> bool {
            VariableSymbolDb::is_external(self)
        }
    }

    impl VariableSymbolDb for MockVarSymbol {
        fn program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn variable_storage_lookup(&self) -> Option<Box<dyn VariableStorage>> {
            self.storage_lookup
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| duplicate_variable_storage(s.as_ref()))
        }

        fn cached_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
            self.cached_storage
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| duplicate_variable_storage(s.as_ref()))
        }

        fn set_cached_variable_storage(&self, storage: Option<Box<dyn VariableStorage>>) {
            *self.cached_storage.lock().unwrap() = storage.map(|s| {
                let boxed: Box<dyn VariableStorage + Send + Sync> =
                    match_storage_send_sync(s.as_ref());
                boxed
            });
        }

        fn stored_data_type(&self) -> Option<Box<dyn DataType>> {
            self.stored_dt.lock().unwrap().as_ref().map(|dt| {
                let cloned: Box<dyn DataType> = Box::new(MockDataType {
                    name: dt.get_name(),
                    length: dt.get_length(),
                    void_type: dt.is_void_type(),
                });
                cloned
            })
        }

        fn void_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: "void".to_string(),
                length: 0,
                void_type: true,
            })
        }

        fn undefined_data_type_of_size(&self, size: i32) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: format!("undefined{size}"),
                length: size,
                void_type: false,
            })
        }

        fn variable_offset(&self) -> i32 {
            *self.variable_offset.lock().unwrap()
        }

        fn set_variable_offset(&self, offset: i32) {
            *self.variable_offset.lock().unwrap() = offset;
        }

        fn get_symbol_comment(&self) -> Option<String> {
            self.comment.lock().unwrap().clone()
        }

        fn set_symbol_comment(&self, comment: Option<String>) {
            *self.comment.lock().unwrap() = comment;
        }

        fn base_do_get_name(&self) -> String {
            self.base_name.clone()
        }

        fn is_refreshable(&self) -> bool {
            self.refreshable
        }

        fn references_to_object(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_function(&self) -> Option<Arc<dyn FunctionDb>> {
            None
        }

        fn get_object(&self) -> Option<Box<dyn Variable>> {
            None
        }

        fn delete(&self) -> bool {
            true
        }

        fn get_program_location(&self) -> Option<Box<dyn ProgramLocation>> {
            None
        }

        fn set_storage_and_data_type(&self, new_storage: Box<dyn VariableStorage>, _data_type: Box<dyn DataType>) {
            self.set_cached_variable_storage(Some(new_storage));
        }

        fn rename(&self, _name: &str, _source: SourceType) -> Result<(), SetVariableNameError> {
            Ok(())
        }
    }

    fn match_storage_send_sync(s: &dyn VariableStorage) -> Box<dyn VariableStorage + Send + Sync> {
        if s.is_unassigned_storage() {
            Box::new(UnassignedStorage)
        } else if s.is_bad_storage() {
            Box::new(BadStorage)
        } else if s.is_void_storage() {
            Box::new(VoidStorage)
        } else {
            // Test storage never exercises the general varnode case; sentinel-only round trip
            // is enough for these unit tests.
            Box::new(UnassignedStorage)
        }
    }

    #[test]
    fn is_primary_and_is_external_defaults() {
        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        assert!(!VariableSymbolDb::is_primary(&sym));
        assert!(!VariableSymbolDb::is_external(&sym));
    }

    #[test]
    fn parameter_ordinal_and_offset_dispatch_by_type() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        param.set_ordinal(2);
        assert_eq!(param.get_ordinal(), 2);
        assert_eq!(param.get_first_use_offset(), 0, "parameters always report offset 0");
        // setFirstUseOffset is a no-op for parameters.
        param.set_first_use_offset(99);
        assert_eq!(param.get_ordinal(), 2);

        let local = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        local.set_first_use_offset(8);
        assert_eq!(local.get_first_use_offset(), 8);
        assert_eq!(local.get_ordinal(), i32::MIN, "locals have no ordinal");
        // setOrdinal is a no-op for locals.
        local.set_ordinal(3);
        assert_eq!(local.get_first_use_offset(), 8);
    }

    #[test]
    fn compute_variable_storage_falls_back_by_type_when_lookup_misses() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        assert!(param.get_variable_storage().is_unassigned_storage());

        let local = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        assert!(local.get_variable_storage().is_bad_storage());
    }

    #[test]
    fn variable_storage_is_cached_after_first_computation() {
        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        assert!(sym.get_variable_storage().is_bad_storage());
        // Change what a fresh lookup would return; the cached value should still win.
        *sym.storage_lookup.lock().unwrap() = Some(Box::new(UnassignedStorage));
        assert!(
            sym.get_variable_storage().is_bad_storage(),
            "cached storage must persist across calls"
        );
    }

    #[test]
    fn get_data_type_prefers_stored_then_falls_back_by_storage_kind() {
        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        // No stored data type, bad storage (default fallback) -> undefined-of-size(storage.size()).
        let dt = sym.get_data_type();
        assert!(dt.get_name().starts_with("undefined"));

        *sym.stored_dt.lock().unwrap() = Some(Box::new(MockDataType {
            name: "myint".to_string(),
            length: 4,
            void_type: false,
        }));
        assert_eq!(sym.get_data_type().get_name(), "myint");
    }

    #[test]
    fn get_data_type_falls_back_to_void_for_void_storage() {
        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        *sym.storage_lookup.lock().unwrap() = Some(Box::new(VoidStorage));
        assert!(sym.get_data_type().is_void_type());
    }

    #[test]
    fn do_get_name_uses_default_param_name_for_default_source_parameters() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::Default);
        param.set_ordinal(1);
        assert_eq!(param.do_get_name(), param.param_name());
    }

    #[test]
    fn do_get_name_regenerates_default_name_even_when_source_is_stale() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        // base_do_get_name() reports a name that looks default-parameter-shaped.
        let mut sym = param;
        sym.base_name = DefaultSymbolUtilities.get_default_param_name(3);
        sym.set_ordinal(3);
        assert_eq!(sym.do_get_name(), sym.param_name());
    }

    #[test]
    fn do_get_name_returns_stored_name_for_named_parameters() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        assert_eq!(param.do_get_name(), "stored_name");
    }

    #[test]
    fn do_get_name_reports_bad_marker_for_bad_local_var_storage() {
        let local = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        // Default MockVarSymbol has no storage lookup -> BadStorage fallback for locals.
        assert_eq!(local.do_get_name(), format!("{DEFAULT_LOCAL_PREFIX}_!BAD!"));
    }

    #[test]
    fn do_get_name_reports_invalid_marker_when_not_refreshable() {
        let mut local = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        local.refreshable = false;
        assert_eq!(local.do_get_name(), "[Invalid VariableSymbol - Deleted!]");
    }

    #[test]
    fn validate_name_source_forces_default_for_default_shaped_names() {
        let param = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        let default_param_name = DefaultSymbolUtilities.get_default_param_name(0);
        assert_eq!(
            param.validate_name_source(Some(&default_param_name), SourceType::UserDefined),
            SourceType::Default
        );
        assert_eq!(
            param.validate_name_source(Some("real_name"), SourceType::UserDefined),
            SourceType::UserDefined
        );
    }

    #[test]
    fn is_valid_parent_compares_symbol_ids() {
        struct MockParentSymbol;
        impl Symbol for MockParentSymbol {
            fn get_address(&self) -> Address {
                addr(0)
            }
            fn get_name(&self) -> &str {
                "func"
            }
            fn get_symbol_type(&self) -> SymbolType {
                SymbolType::Function
            }
            fn get_source(&self) -> SourceType {
                SourceType::UserDefined
            }
            fn is_primary(&self) -> bool {
                true
            }
            fn get_id(&self) -> i64 {
                10
            }
            fn get_parent_id(&self) -> i64 {
                0
            }
        }
        struct MockParentNamespace;
        impl Namespace for MockParentNamespace {
            fn get_symbol(&self) -> Arc<dyn Symbol> {
                Arc::new(MockParentSymbol)
            }
            fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
                None
            }
        }

        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        assert!(sym.is_valid_parent(&MockParentNamespace));
    }

    #[test]
    fn reference_helpers_delegate_to_references_to_object() {
        let sym = MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined);
        assert_eq!(sym.get_reference_count(), 0);
        assert!(!sym.has_references());
        assert!(sym
            .get_references(&crate::util::task::DummyMonitor)
            .is_empty());
    }

    #[test]
    fn seam_stub_blanket_impl_forwards_correctly() {
        use crate::program::seam_stubs::VariableSymbolDb as SeamVariableSymbolDb;

        let sym = MockVarSymbol::new(SymbolType::Parameter, SourceType::UserDefined);
        sym.set_variable_ordinal(4);
        assert_eq!(SeamVariableSymbolDb::variable_ordinal(&sym), 4);
        assert_eq!(VariableSymbolDb::get_ordinal(&sym), 4);

        sym.set_variable_symbol_comment(Some("hi".to_string()));
        assert_eq!(SeamVariableSymbolDb::variable_symbol_comment(&sym), Some("hi".to_string()));

        assert!(SeamVariableSymbolDb::rename(&sym, "x", SourceType::UserDefined).is_ok());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let sym: Box<dyn VariableSymbolDb> =
            Box::new(MockVarSymbol::new(SymbolType::LocalVar, SourceType::UserDefined));
        assert!(!VariableSymbolDb::is_primary(sym.as_ref()));
    }
}
