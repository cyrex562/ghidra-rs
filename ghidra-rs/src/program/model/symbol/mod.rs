use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Variable};
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

    fn get_symbol(&self, id: i64) -> io::Result<Option<Arc<dyn Symbol>>>;

    fn get_symbols(&self, addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>>;

    /// Get a global symbol by name and address.
    fn get_global_symbol(&self, name: &str, addr: &Address) -> io::Result<Option<Arc<dyn Symbol>>> {
        let symbols = self.get_symbols(addr)?;
        Ok(symbols.into_iter().find(|s| s.get_name() == name))
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
}
