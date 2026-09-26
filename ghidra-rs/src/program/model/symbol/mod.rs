use crate::program::model::address::{Address, BoxedAddressIterator, EmptyAddressIterator};
use crate::program::model::listing::{Function, GhidraClass, Program, Variable};
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use std::io;
use std::sync::Arc;

pub mod address_label_pair;
pub mod data_ref_type;
pub mod entry_point_reference;
pub mod equate;
pub mod equate_reference;
pub mod equate_table;
pub mod external_location;
pub mod external_location_iterator;
pub mod external_manager;
pub mod external_path;
pub mod external_reference;
pub mod flow_type;
pub mod illegal_char_cpp_transformer;
pub mod label_history;
pub mod mem_reference_impl;
pub mod name_transformer;
pub mod namespace;
pub mod offset_reference;
pub mod ref_type;
pub mod ref_type_factory;
pub mod reference;
pub mod reference_iterator;
pub mod reference_iterator_test_stub;
pub mod reference_listener;
pub mod reference_manager;
pub mod shifted_reference;
pub mod source_type;
pub mod stack_reference;
pub mod symbol_iterator;
pub mod symbol_table_listener;
pub mod symbol_type;
pub mod symbol_utilities;
pub mod thunk_reference;

pub use address_label_pair::AddressLabelPair;
pub use data_ref_type::DataRefType;
pub use entry_point_reference::EntryPointReference;
pub use equate::{Equate, SimpleEquate, UniversalId};
pub use equate_reference::{EquateReference, SimpleEquateReference};
pub use equate_table::{EquateTable, SimpleEquateTable};
pub use external_location::{ExternalLocation, SetExternalLocationError};
pub use external_location_iterator::{
    EmptyExternalLocationIterator, ExternalLocationAdapter, ExternalLocationIterator,
    ExternalLocationIteratorAdapter,
};
pub use external_manager::{
    AddExternalLibraryNameError, AddExternalLocationInLibraryError, ExternalManager,
    UpdateExternalLibraryNameError,
};
pub use external_path::{ExternalPath, ExternalPathError, EXTERNAL_PATH_DELIMITER};
pub use external_reference::ExternalReference;
pub use flow_type::FlowType;
pub use illegal_char_cpp_transformer::IllegalCharCppTransformer;
pub use label_history::{LabelHistory, LabelHistoryAction};
pub use mem_reference_impl::MemReferenceImpl;
pub use name_transformer::{IdentityNameTransformer, NameTransformer};
#[allow(deprecated)]
pub use namespace::NAMESPACE_DELIMITER;
pub use namespace::{Namespace, NamespaceType, SetParentNamespaceError, DELIMITER, GLOBAL_NAMESPACE_ID};
pub use offset_reference::OffsetReference;
pub use ref_type::RefType;
pub use ref_type_factory::RefTypeFactory;
pub use reference::{DynamicReference, Reference, MNEMONIC, OTHER};
pub use reference_iterator::{
    EmptyReferenceIterator, ReferenceAdapter, ReferenceIterator, ReferenceIteratorAdapter,
};
pub use reference_iterator_test_stub::ReferenceIteratorTestStub;
pub use reference_listener::ReferenceListener;
pub use reference_manager::{AddExternalReferenceError, ReferenceManager};
pub use shifted_reference::ShiftedReference;
pub use source_type::SourceType;
pub use stack_reference::StackReference;
pub use symbol_iterator::{EmptySymbolIterator, SymbolAdapter, SymbolIterator, SymbolIteratorAdapter};
pub use symbol_table_listener::SymbolTableListener;
pub use symbol_type::SymbolType;
pub use symbol_utilities::*;
pub use thunk_reference::ThunkReference;

pub trait Symbol: Send + Sync {
    fn get_address(&self) -> Address;
    fn get_name(&self) -> &str;
    fn get_symbol_type(&self) -> SymbolType;
    fn get_source(&self) -> SourceType;
    fn is_primary(&self) -> bool;
    fn get_id(&self) -> i64;
    fn get_parent_id(&self) -> i64;

    /// Returns true if this symbol is external (i.e. associated with a
    /// [`Library`](crate::program::model::listing::library::Library) rather than program
    /// memory). Real abstract method on `Symbol`.
    ///
    /// Defaults to `false` so existing implementors are unaffected; concrete implementations
    /// should override once external-symbol support is ported.
    fn is_external(&self) -> bool {
        false
    }

    /// The program that owns this symbol, if known. Stands in for `Symbol.getProgram()`.
    ///
    /// Defaults to `None` so existing implementors are unaffected; concrete implementations
    /// should override once program back-references are wired up. Added for
    /// [`SymbolType`](crate::program::model::symbol::SymbolType)'s port of
    /// `SymbolType.isValidParent`/`isValidParent` overrides, which compare program identity
    /// between the target program and a candidate parent namespace's owning program.
    fn get_program(&self) -> Option<Arc<dyn Program>> {
        None
    }

    /// The namespace this symbol represents, when its [`SymbolType`] is `Namespace`, `Class`,
    /// `Library`, or `Function`. Stands in for `Symbol.getObject()` narrowed to the `Namespace`
    /// case, since Rust trait objects cannot be downcast to another trait object without extra
    /// machinery.
    ///
    /// Defaults to `None` so existing implementors are unaffected.
    fn as_namespace(&self) -> Option<Arc<dyn Namespace>> {
        None
    }

    /// The namespace that contains this symbol, or `None` if this symbol is contained
    /// directly in the global namespace. Stands in for `Symbol.getParentNamespace()`.
    ///
    /// Defaults to `None` so existing implementors are unaffected; concrete implementations
    /// should override once namespace membership is wired up.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        None
    }

    /// The name of the memory block containing this symbol's address, if known. Stands in for
    /// `symbol.getProgram().getMemory().getBlock(symbol.getAddress()).getName()`, used by legacy
    /// callers that match symbols against memory-block-qualified paths.
    ///
    /// Defaults to `None` so existing implementors are unaffected; concrete implementations
    /// should override once program/memory back-references are wired up.
    fn get_containing_memory_block_name(&self) -> Option<String> {
        None
    }

    /// The symbol of this symbol's parent namespace, or `None` for the global namespace. Stands
    /// in for `Symbol.getParentSymbol()`.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_parent_symbol(&self) -> Option<Arc<dyn Symbol>> {
        None
    }

    /// Narrows this symbol to a [`Variable`] when its [`SymbolType`] is `Parameter` or
    /// `LocalVar`. Stands in for `Symbol.getObject()` narrowed to the `Variable` case; see
    /// [`Symbol::as_namespace`] for why a dedicated accessor is needed instead of a downcast.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn as_variable(&self) -> Option<Arc<dyn Variable>> {
        None
    }

    /// Narrows this symbol to a [`Function`] when its [`SymbolType`] is `Function`. Stands in
    /// for `Symbol.getObject()` narrowed to the `Function` case; see [`Symbol::as_namespace`]
    /// for why a dedicated accessor is needed instead of a downcast.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn as_function(&self) -> Option<Arc<dyn Function>> {
        None
    }

    /// Returns true if this is a name that was auto-generated by Ghidra's dynamic-naming
    /// convention (e.g. `LAB_00401000`) rather than user- or import-assigned. Stands in for
    /// `Symbol.isDynamic()`.
    ///
    /// Defaults to `false` so existing implementors are unaffected. Added for
    /// [`SymbolUtilities`](crate::program::model::symbol::symbol_utilities::SymbolUtilities).
    fn is_dynamic(&self) -> bool {
        false
    }

    /// Move this symbol into a different namespace. Stands in for
    /// `Symbol.setNamespace(Namespace)`.
    ///
    /// Defaults to rejecting the change so existing implementors are unaffected; concrete
    /// implementations should override once namespace reassignment is fully ported. Added for
    /// [`SymbolUtilities::create_preferred_label_or_function_symbol`](crate::program::model::symbol::symbol_utilities::SymbolUtilities::create_preferred_label_or_function_symbol).
    fn set_namespace(&mut self, namespace: Arc<dyn Namespace>) -> Result<(), SetParentNamespaceError> {
        let _ = namespace;
        Err(SetParentNamespaceError::InvalidInput(InvalidInputException::new()))
    }

    /// Rename this symbol. Stands in for `Symbol.setName(String, SourceType)`.
    ///
    /// Defaults to rejecting the change so existing implementors are unaffected; concrete
    /// implementations should override once symbol renaming is fully ported. Added for
    /// [`AbstractFrameSectionBase`](crate::app::plugin::exceptionhandlers::gcc::sections::abstract_frame_section::AbstractFrameSectionBase)'s
    /// port of `createCieLabel`, which renames an existing primary symbol to the CIE label.
    fn set_name(&mut self, name: &str, source: SourceType) -> Result<(), SetSymbolNameError> {
        let _ = (name, source);
        Err(SetSymbolNameError::InvalidInput(InvalidInputException::new()))
    }

    /// Returns true if this symbol has been pinned, preventing it from moving with reassembly of
    /// the program's memory map. Stands in for `Symbol.isPinned()`.
    ///
    /// Defaults to `false` so existing implementors are unaffected; concrete implementations
    /// (e.g. [`MemorySymbol`](crate::program::database::symbol::MemorySymbol), whose own
    /// `is_pinned` default this does *not* override -- see that trait's docs -- since it is a
    /// separate, non-overlapping trait) should provide the real, persisted answer. Added for
    /// [`ExtSymbol`](crate::sarif::export::symbols::ExtSymbol)'s port of
    /// `sarif.export.symbols.ExtSymbol`, which calls `Symbol.isPinned()` on a plain `Symbol`.
    fn is_pinned(&self) -> bool {
        false
    }

    /// Returns true if this symbol resides directly in the global namespace (i.e. has no parent
    /// namespace other than global). Stands in for `Symbol.isGlobal()`.
    ///
    /// Defaults to computing from [`Symbol::get_parent_namespace`], mirroring the real
    /// `SymbolDB.isGlobal()`'s `getParentNamespace().getID() == Namespace.GLOBAL_NAMESPACE_ID`
    /// check: `true` when there is no parent namespace recorded (the conservative, "not yet
    /// wired up" default every other member of this trait uses) or when the parent namespace
    /// itself reports [`Namespace::is_global`]. Added for
    /// [`ExtSymbol`](crate::sarif::export::symbols::ExtSymbol)'s port of
    /// `sarif.export.symbols.ExtSymbol`, which calls `Symbol.isGlobal()` on a plain `Symbol`.
    fn is_global(&self) -> bool {
        self.get_parent_namespace().map(|ns| ns.is_global()).unwrap_or(true)
    }

    /// Returns true if this symbol has been deleted. Stands in for `Symbol.isDeleted()`.
    ///
    /// Defaults to `false` so existing implementors are unaffected; concrete implementations
    /// backed by a database record should override this to report the record's live/deleted
    /// state. Added for
    /// [`SymbolRowObjectToAddressTableRowMapper`](crate::app::plugin::core::symtable::symbol_row_object_to_address_table_row_mapper::SymbolRowObjectToAddressTableRowMapper)
    /// and its `ProgramLocation` sibling, whose Java `map` methods both guard on `!s.isDeleted()`
    /// before trusting a looked-up symbol.
    fn is_deleted(&self) -> bool {
        false
    }

    /// Returns the location for this symbol. Stands in for `Symbol.getProgramLocation()`.
    ///
    /// Real symbol-type-specific overrides (`FunctionSymbol`, `CodeSymbol`, `VariableSymbol`,
    /// ...) each return a location tailored to that symbol's own field type; none of those
    /// subclasses are ported yet, so this default instead builds a generic program+address
    /// location -- the same minimal shape this crate's other simple-location builders use (e.g.
    /// [`generate_program_location`](crate::feature::base::memsearch::bytesource::addressable_byte_source::generate_program_location))
    /// -- falling back to `None` when [`Symbol::get_program`] is unknown. A concrete symbol type
    /// wanting the real field-specific location should override this directly. Added for
    /// [`SymbolRowObjectToProgramLocationTableRowMapper`](crate::app::plugin::core::symtable::symbol_row_object_to_program_location_table_row_mapper::SymbolRowObjectToProgramLocationTableRowMapper).
    fn get_program_location(&self) -> Option<Box<dyn crate::program::util::program_location::ProgramLocation>> {
        let program = self.get_program()?;
        Some(Box::new(SimpleSymbolProgramLocation { program, address: self.get_address() }))
    }
}

/// Minimal generic [`ProgramLocation`](crate::program::util::program_location::ProgramLocation)
/// used by [`Symbol::get_program_location`]'s default. Defined locally (rather than reusing
/// [`generate_program_location`](crate::feature::base::memsearch::bytesource::addressable_byte_source::generate_program_location))
/// so that `program::model::symbol` does not take on a runtime dependency toward `feature::*`.
struct SimpleSymbolProgramLocation {
    program: Arc<dyn Program>,
    address: Address,
}

impl crate::program::util::program_location::ProgramLocation for SimpleSymbolProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }
    fn get_address(&self) -> Address {
        self.address.clone()
    }
    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

/// Error produced by [`Symbol::set_name`], mirroring the two checked exceptions
/// `Symbol.setName(String, SourceType)` declares.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SetSymbolNameError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Error produced by [`SymbolTable::get_or_create_name_space`], mirroring the two checked
/// exceptions `SymbolTable.getOrCreateNameSpace` declares.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum GetOrCreateNamespaceError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

pub trait SymbolTable: Send + Sync {
    fn create_label(
        &mut self,
        addr: &Address,
        name: &str,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>>;

    /// Create a label named `name` at `addr` inside `namespace`. Stands in for
    /// `SymbolTable.createLabel(Address, String, Namespace, SourceType)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`AbstractOrdinalSupportLoader`](crate::app::util::opinion::abstract_ordinal_support_loader::AbstractOrdinalSupportLoader)'s
    /// port of `applyLibrarySymbols`, which names ordinal symbols in the global namespace.
    ///
    /// Defaults to [`create_label`](Self::create_label), i.e. to whichever namespace that
    /// overload places a label in, since the only namespace in-repo callers pass is the global
    /// one.
    fn create_label_in_namespace(
        &mut self,
        addr: &Address,
        name: &str,
        namespace: Arc<dyn Namespace>,
        source: SourceType,
    ) -> io::Result<Arc<dyn Symbol>> {
        let _ = namespace;
        self.create_label(addr, name, source)
    }

    fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>>;

    /// Iterate the symbols whose names match `search_str`, in which `*` matches any run of
    /// characters. Stands in for `SymbolTable.getSymbolIterator(String, boolean)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`AbstractOrdinalSupportLoader`](crate::app::util::opinion::abstract_ordinal_support_loader::AbstractOrdinalSupportLoader)'s
    /// port of `applyLibrarySymbols`, which walks every `Ordinal_*` symbol.
    ///
    /// Defaults to an empty iterator so existing implementors are unaffected.
    fn get_symbol_iterator(&self, search_str: &str, case_sensitive: bool) -> Box<dyn SymbolIterator> {
        let _ = (search_str, case_sensitive);
        Box::new(EmptySymbolIterator)
    }

    /// Iterate every symbol, in address order, starting at `start_addr` and running forward or
    /// backward. Stands in for `SymbolTable.getSymbolIterator(Address, boolean)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`load_syscall_function_map`](crate::pcode::emu::sys::emu_syscall_library::load_syscall_function_map),
    /// which scrapes the functions in a program's "syscall" space.
    ///
    /// Defaults to an empty iterator so existing implementors are unaffected.
    fn get_symbol_iterator_from(&self, start_addr: &Address, forward: bool) -> Box<dyn SymbolIterator> {
        let _ = (start_addr, forward);
        Box::new(EmptySymbolIterator)
    }

    fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>>;

    /// Get a global symbol by name and address.
    fn get_global_symbol(&self, name: &str, addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
        let symbols = self.get_symbols(addr)?;
        Ok(symbols.into_iter().find(|s| s.get_name() == name))
    }

    /// Get all global symbols (i.e. symbols in the global namespace) with the given name,
    /// across every address. Stands in for `SymbolTable.getGlobalSymbols(String)`.
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`dyld_chained_fixups::get_chained_fixups`](crate::format::macho::commands::chained::dyld_chained_fixups::get_chained_fixups),
    /// which resolves a bound chain entry's symbol name to its address.
    fn get_global_symbols(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let _ = name;
        Ok(Vec::new())
    }

    /// Get, or create if absent, the namespace named `name` inside `parent`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DemangledObject`](crate::demangler::demangled_object::DemangledObject)'s port of
    /// `createNamespace`. Stands in for
    /// `SymbolTable.getOrCreateNameSpace(Namespace, String, SourceType)`.
    ///
    /// Defaults to rejecting the request (as [`Namespace::set_parent_namespace`] does), so a
    /// symbol table that has not implemented namespace creation cannot silently report a
    /// namespace it did not create. `createNamespace` treats that as the error case it already
    /// handles: it logs and returns the partial namespace built so far.
    fn get_or_create_name_space(
        &mut self,
        parent: Arc<dyn Namespace>,
        name: &str,
        source: SourceType,
    ) -> Result<Arc<dyn Namespace>, GetOrCreateNamespaceError> {
        let _ = (parent, name, source);
        Err(GetOrCreateNamespaceError::InvalidInput(InvalidInputException::with_message(
            "namespace creation is not supported by this symbol table",
        )))
    }

    /// Make the symbol with the given ID the primary symbol at its address, returning whether
    /// the promotion was permitted.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DemangledObject`](crate::demangler::demangled_object::DemangledObject)'s port of
    /// `applyDemangledName`. Stands in for `Symbol.setPrimary()`, keyed by ID like the
    /// neighbouring [`set_symbol_pinned`](Self::set_symbol_pinned), since an `Arc<dyn Symbol>`
    /// handed out by this trait cannot be mutated through.
    ///
    /// Defaults to `false` (not permitted) so existing implementors are unaffected.
    fn set_primary_symbol(&mut self, symbol_id: i64) -> io::Result<bool> {
        let _ = symbol_id;
        Ok(false)
    }

    /// Set the pinned status of a symbol by its ID.
    fn set_symbol_pinned(&mut self, symbol_id: i64, pinned: bool) -> io::Result<()> {
        let _ = (symbol_id, pinned);
        Ok(())
    }

    /// Mark an address as an external entry point.
    fn add_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
        let _ = addr;
        Ok(())
    }

    /// Remove an address from external entry points.
    fn remove_external_entry_point(&mut self, addr: &Address) -> io::Result<()> {
        let _ = addr;
        Ok(())
    }

    /// Check if an address is marked as an external entry point.
    fn is_external_entry_point(&self, addr: &Address) -> io::Result<bool> {
        let _ = addr;
        Ok(false)
    }

    /// Iterate every address marked as an external entry point. Stands in for
    /// `SymbolTable.getExternalEntryPointIterator()`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ExtEntryPointSarifMgr::write`](crate::sarif::managers::ExtEntryPointSarifMgr::write),
    /// which walks every entry point address to export it as SARIF.
    ///
    /// Defaults to an empty iterator so existing implementors are unaffected.
    fn get_external_entry_point_iterator(&self) -> BoxedAddressIterator {
        Box::new(EmptyAddressIterator)
    }

    /// Get the primary symbol at the given address. Stands in for
    /// `SymbolTable.getPrimarySymbol(Address)`.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_primary_symbol(&self, addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
        let _ = addr;
        Ok(None)
    }

    /// Get all external symbols with the given name. Stands in for
    /// `SymbolTable.getExternalSymbols(String)`.
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_external_symbols_by_name(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let _ = name;
        Ok(Vec::new())
    }

    /// Get all external symbols. Stands in for the no-argument
    /// `SymbolTable.getExternalSymbols()`.
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_all_external_symbols(&self) -> io::Result<Vec<Arc<dyn Symbol>>> {
        Ok(Vec::new())
    }

    /// Get the symbol with the given name contained within the given namespace. Unifies
    /// `SymbolTable.getLibrarySymbol(String)`, `getClassSymbol(String, Namespace)`, and
    /// `getNamespaceSymbol(String, Namespace)` into a single lookup, since this trait does not
    /// distinguish those namespace kinds at the query layer.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn find_symbol_by_name_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> io::Result<Option<Arc<dyn Symbol>>> {
        let _ = (name, namespace);
        Ok(None)
    }

    /// Get the symbol with the given name, address, and namespace. Stands in for
    /// `SymbolTable.getSymbol(String, Address, Namespace)`.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn find_symbol_by_name_address_namespace(
        &self,
        name: &str,
        addr: &Address,
        namespace: &dyn Namespace,
    ) -> io::Result<Option<Arc<dyn Symbol>>> {
        let _ = (name, addr, namespace);
        Ok(None)
    }

    /// Get all symbols with the given name contained within the given namespace. Stands in for
    /// `SymbolTable.getSymbols(String, Namespace)`.
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_symbols_by_name_namespace(
        &self,
        name: &str,
        namespace: &dyn Namespace,
    ) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let _ = (name, namespace);
        Ok(Vec::new())
    }

    /// Get all symbols contained within the namespace with the given ID. Stands in for
    /// `SymbolTable.getSymbols(long namespaceID)`.
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility).
    fn get_symbols_in_namespace(&self, namespace_id: i64) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let _ = namespace_id;
        Ok(Vec::new())
    }

    /// Get all non-namespace-restricted label or function symbols with the given name. Stands in
    /// for `SymbolTable.getLabelOrFunctionSymbols(String, Namespace)` (Java's only caller,
    /// `SymbolUtilities`, always passes a `null` namespace).
    ///
    /// Defaults to empty so existing implementors are unaffected. Added for
    /// [`SymbolUtilities`](crate::program::model::symbol::symbol_utilities::SymbolUtilities).
    fn get_label_or_function_symbols(&self, name: &str) -> io::Result<Vec<Arc<dyn Symbol>>> {
        let _ = name;
        Ok(Vec::new())
    }

    /// Get the symbol associated with the given reference's destination. Stands in for
    /// `SymbolTable.getSymbol(Reference)`.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`CodeUnitFormat`](crate::program::model::listing::code_unit_format::CodeUnitFormat).
    fn get_symbol_for_reference(&self, reference: &dyn Reference) -> io::Result<Option<Arc<dyn Symbol>>> {
        let _ = reference;
        Ok(None)
    }

    /// Get the namespace containing the given address. Stands in for
    /// `SymbolTable.getNamespace(Address)`.
    ///
    /// Defaults to `None` so existing implementors are unaffected. Added for
    /// [`CodeUnitFormat`](crate::program::model::listing::code_unit_format::CodeUnitFormat).
    fn get_namespace(&self, addr: &Address) -> io::Result<Option<Arc<dyn Namespace>>> {
        let _ = addr;
        Ok(None)
    }

    /// Iterate every class namespace (`GhidraClass`) defined in the program. Stands in for
    /// `SymbolTable.getClassNamespaces()`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`ExternalLibSarifMgr::write`](crate::sarif::managers::ExternalLibSarifMgr::write), which
    /// exports SARIF for every class namespace known to the program.
    ///
    /// Defaults to empty so existing implementors are unaffected.
    fn get_class_namespaces(&self) -> Vec<Arc<dyn GhidraClass>> {
        Vec::new()
    }

    /// Remove a symbol, with special handling for function symbols (which get renamed to a
    /// fallback name -- absorbing whatever non-primary label happens to exist at the function's
    /// entry point, or else the default `FUN_...` name -- rather than deleted outright, since a
    /// function must always have a primary symbol). Stands in for
    /// `SymbolTable.removeSymbolSpecial(Symbol)`.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`remove_all_labels`](crate::feature::vt::api::util::label_markup_utils::remove_all_labels),
    /// which removes every non-function label symbol at an address. The real method's
    /// function-renaming branch needs write access to the owning `FunctionManagerDB`/reference
    /// manager that this trait does not model, so it is left to implementors; the caller this
    /// method was grown for already filters out function symbols before calling it (mirroring
    /// the Java caller, which checks `symbol instanceof FunctionSymbol` first), so that branch is
    /// never exercised through this port's only current use.
    ///
    /// Defaults to `false` (removal refused) so existing implementors are unaffected.
    fn remove_symbol_special(&mut self, symbol: &dyn Symbol) -> bool {
        let _ = symbol;
        false
    }
}
