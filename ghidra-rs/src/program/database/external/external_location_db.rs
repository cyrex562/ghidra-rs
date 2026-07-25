//! An external location, tied to a symbol in the associated library.
//!
//! Port of `ghidra.program.database.external.ExternalLocationDB` as a trait (cycle cut-point): the
//! Java class holds an `ExternalManagerDB` field (obtained at construction) and a `MemorySymbol`
//! field, and is itself constructed *by* `ExternalManagerDB`. That mutual construction is what
//! makes this class a cycle cut-point.
//!
//! `MemorySymbol` (the Java superclass' sibling this class wraps, not extends -- `symbol` is a
//! plain field, not inherited state) is not stubbed out as its own placeholder trait; instead, the
//! handful of `MemorySymbol`-specific accessors this class needs (beyond the base
//! [`Symbol`] contract already reachable through [`symbol`](ExternalLocationDb::symbol)) are
//! modeled as required `symbol_*`/`set_symbol_*` methods directly on this trait, mirroring the
//! [`FunctionSymbol`](crate::program::database::symbol::FunctionSymbol) and
//! [`CodeSymbol`](crate::program::database::symbol::CodeSymbol) convention for the analogous
//! `MemorySymbol` superclass-chain state those traits also needed.
//!
//! `ExternalManagerDB`, by contrast, is a genuinely separate referenced core type (composition, not
//! superclass state), so it gets an actual minimal placeholder --
//! [`ExternalManagerDb`](crate::program::seam_stubs::ExternalManagerDb) in `seam_stubs.rs` -- for
//! the one member ([`ExternalManagerDb::get_program`]) this trait's default methods call directly.
//! `ExternalManagerDB.createFunction(ExternalLocation)` is instead modeled as a required method
//! directly on this trait ([`ext_manager_create_function`](ExternalLocationDb::ext_manager_create_function)),
//! since satisfying it means passing `this` back to the manager -- something a concrete implementor
//! can trivially do in its own method body, but which a generic placeholder trait can't express any
//! more cleanly.
//!
//! `ghidra.app.util.NamespaceUtils`'s static `createNamespaceHierarchy` helper is similarly
//! un-portable here (it performs real database writes), so it's modeled as a required method,
//! [`create_namespace_hierarchy`](ExternalLocationDb::create_namespace_hierarchy). Its sibling
//! static helper `NamespaceUtils.getLibrary(Namespace)`, however, is a stateless algorithm over the
//! already-ported [`Namespace`] trait (walk up until a Library is found), so -- like
//! `SymbolPathParser`'s parsing logic in
//! [`SymbolPath`](crate::app::util::symbol_path::SymbolPath) -- it's reproduced directly as the
//! private free function [`namespace_or_owning_library`] rather than stubbed.
//!
//! Every method Java declares `throws DuplicateNameException`/`CircularDependencyException` that
//! this class's own body immediately catches and rethrows as `AssertException` becomes a Rust
//! `panic!` here, matching this crate's convention of treating unchecked/assertion-only exceptions
//! as programmer-error panics rather than `Result` variants.

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::app::util::symbol_path::{SymbolPath, SymbolPathNode};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::{Function, Library};
use crate::program::model::symbol::{
    ExternalLocation, Namespace, SetExternalLocationError, SourceType, Symbol, SymbolType,
    DELIMITER,
};
use crate::program::seam_stubs::ExternalManagerDb;
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use crate::program::model::listing::CircularDependencyException;

/// Error produced by [`ExternalLocationDb::set_symbol_name_and_namespace`], mirroring the three
/// checked exceptions declared on `Symbol.setNameAndNamespace(String, Namespace, SourceType)`
/// (`DuplicateNameException`, `InvalidInputException`, `CircularDependencyException`).
#[derive(Error, Debug, PartialEq)]
pub enum SetSymbolNameAndNamespaceError {
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Circular(#[from] CircularDependencyException),
}

/// An external location, tied to a symbol in the associated library.
///
/// Port of `ghidra.program.database.external.ExternalLocationDB` (cycle cut-point; see the module
/// docs for how the `MemorySymbol`/`ExternalManagerDB` fields this class wraps are modeled).
pub trait ExternalLocationDb: ExternalLocation {
    /// Accessor standing in for the `symbol` field's base [`Symbol`] identity (name, address,
    /// source, symbol type, parent namespace).
    fn symbol(&self) -> Arc<dyn Symbol>;

    /// Stands in for `MemorySymbol.getExternalOriginalImportedName()`.
    fn symbol_external_original_imported_name(&self) -> Option<String>;

    /// Stands in for `MemorySymbol.setExternalOriginalImportedName(String, boolean)`. The
    /// `propagate`-style boolean parameter (change-manager notification) isn't modeled since no
    /// such notification pipeline exists here.
    fn set_symbol_external_original_imported_name(&mut self, name: Option<String>);

    /// Stands in for `MemorySymbol.getExternalProgramAddress()`.
    fn symbol_external_program_address(&self) -> Option<Address>;

    /// Stands in for `MemorySymbol.setExternalProgramAddress(Address, boolean)`.
    fn set_symbol_external_program_address(&mut self, address: Option<Address>);

    /// Stands in for `MemorySymbol.getDataTypeId()`.
    fn symbol_data_type_id(&self) -> i64;

    /// Stands in for `MemorySymbol.setDataTypeId(long)`.
    fn set_symbol_data_type_id(&mut self, data_type_id: i64);

    /// Stands in for `MemorySymbol.getObject()`, narrowed to the `Function` this class always
    /// downcasts it to (only ever called after confirming [`Symbol::get_symbol_type`] is
    /// `SymbolType::Function`).
    fn symbol_object(&self) -> Option<Arc<dyn Function>>;

    /// Stands in for `Symbol.setNameAndNamespace(String, Namespace, SourceType)`.
    fn set_symbol_name_and_namespace(
        &mut self,
        new_name: &str,
        new_namespace: Arc<dyn Namespace>,
        source: SourceType,
    ) -> Result<(), SetSymbolNameAndNamespaceError>;

    /// Stands in for `symbol = (FunctionSymbol) function.getSymbol();`, executed after
    /// `extMgr.createFunction(this)` succeeds in [`create_function`](Self::create_function).
    fn adopt_function_symbol(&mut self, function: &Arc<dyn Function>);

    /// Accessor for the owning `ExternalManagerDB`, standing in for the `extMgr` field.
    fn ext_manager(&self) -> Arc<dyn ExternalManagerDb>;

    /// Stands in for `extMgr.createFunction(this)`.
    fn ext_manager_create_function(&mut self) -> Arc<dyn Function>;

    /// Stands in for the static `NamespaceUtils.createNamespaceHierarchy(String, Namespace,
    /// Program, SourceType)`, which creates (or reuses) the chain of simple namespaces named by
    /// `parent_path` (`::`-delimited, deepest-last) underneath `parent`.
    ///
    /// # Errors
    /// Returns `Err` if any namespace name along the path is invalid.
    fn create_namespace_hierarchy(
        &self,
        parent_path: Option<&str>,
        parent: Option<Arc<dyn Namespace>>,
        source: SourceType,
    ) -> Result<Arc<dyn Namespace>, InvalidInputException>;

    /// Private helper standing in for `ExternalLocationDB.getLibrary()`: walks up this location's
    /// parent namespace chain to find the enclosing Library, returned as a [`Namespace`] (rather
    /// than narrowed to [`Library`]) so it can be passed directly to
    /// [`ExternalLocation::set_name`]/[`create_namespace_hierarchy`](Self::create_namespace_hierarchy)
    /// without needing a `Library` -> `Namespace` trait-object upcast, which this crate's ported
    /// traits don't otherwise rely on.
    fn get_library(&self) -> Option<Arc<dyn Namespace>> {
        let mut parent = self.symbol().get_parent_namespace();
        while let Some(p) = parent {
            if p.is_library() {
                return Some(p);
            }
            parent = p.get_parent_namespace();
        }
        None
    }

    /// Stands in for `ExternalLocationDB.getExtNameID()`.
    fn get_ext_name_id(&self) -> i64 {
        self.symbol()
            .get_parent_namespace()
            .expect("external location symbol always has a parent namespace")
            .get_id()
    }

    /// Set the label and optional namespace associated with this external location. Any
    /// non-existing namespace will be created as a simple namespace within the associated library.
    ///
    /// Stands in for `ExternalLocationDB.setLabel(String, SourceType)`.
    ///
    /// # Errors
    /// Returns `Err` if the name contains illegal characters (e.g. a space).
    fn set_label(
        &mut self,
        label: Option<&str>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        match label {
            None => {
                let library = self
                    .get_library()
                    .expect("external location symbol always has a library ancestor");
                ExternalLocationDb::set_name(self, library, "", SourceType::Default)
            }
            Some(label) if !label.contains(DELIMITER) => {
                let parent = self
                    .symbol()
                    .get_parent_namespace()
                    .expect("external location symbol always has a parent namespace");
                ExternalLocationDb::set_name(self, parent, label, source)
            }
            Some(label) => {
                let path = SymbolPathNode::parse(label)
                    .expect("label already confirmed to contain a namespace delimiter");
                let library = self.get_library();
                let namespace = self.create_namespace_hierarchy(
                    path.parent_path().as_deref(),
                    library,
                    source,
                )?;
                ExternalLocationDb::set_name(self, namespace, path.name(), source)
            }
        }
    }

    /// Saves the prior name as this location's original imported name if appropriate, e.g. when
    /// this location was just renamed away from an imported (mangled) name.
    ///
    /// Stands in for `ExternalLocationDB.saveOriginalNameIfNeeded(Namespace, String, SourceType)`.
    fn save_original_name_if_needed(
        &mut self,
        old_namespace: Option<Arc<dyn Namespace>>,
        old_name: &str,
        old_source: SourceType,
    ) {
        let was_in_library = old_namespace
            .as_ref()
            .map(|ns| ns.as_library().is_some())
            .unwrap_or(false);

        let original_imported_name = ExternalLocationDb::get_original_imported_name(self);
        if original_imported_name.as_deref() == Some(ExternalLocationDb::get_label(self).as_str())
        {
            self.set_symbol_external_original_imported_name(None);
        } else if was_in_library
            && ExternalLocationDb::get_source(self) != SourceType::Default
            && old_source == SourceType::Imported
            && original_imported_name.is_none()
        {
            self.set_symbol_external_original_imported_name(Some(old_name.to_string()));
        }
    }

    /// Stands in for `ExternalLocationDB.getSymbol()`.
    fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
        Some(self.symbol())
    }

    /// Stands in for `ExternalLocationDB.getLibraryName()`.
    fn get_library_name(&self) -> String {
        match self.get_library().and_then(|ns| ns.as_library()) {
            Some(lib) => lib.get_name(),
            None => "<UNKNOWN>".to_string(),
        }
    }

    /// Stands in for `ExternalLocationDB.getExternalLibraryPath()`.
    fn get_external_library_path(&self) -> Option<String> {
        self.get_library()
            .and_then(|ns| ns.as_library())
            .and_then(|lib| lib.get_associated_program_path())
    }

    /// Stands in for `ExternalLocationDB.getParentNameSpace()`.
    fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
        self.symbol().get_parent_namespace()
    }

    /// Stands in for `ExternalLocationDB.getParentName()`.
    fn get_parent_name(&self) -> String {
        self.symbol()
            .get_parent_namespace()
            .expect("external location symbol always has a parent namespace")
            .get_name()
    }

    /// Stands in for `ExternalLocationDB.getLabel()`.
    fn get_label(&self) -> String {
        self.symbol().get_name().to_string()
    }

    /// Stands in for `ExternalLocationDB.getOriginalImportedName()`.
    fn get_original_imported_name(&self) -> Option<String> {
        self.symbol_external_original_imported_name()
    }

    /// Stands in for `ExternalLocationDB.getSource()`.
    fn get_source(&self) -> SourceType {
        self.symbol().get_source()
    }

    /// Stands in for `ExternalLocationDB.getAddress()`.
    fn get_address(&self) -> Option<Address> {
        self.symbol_external_program_address()
    }

    /// Stands in for `ExternalLocationDB.getExternalSpaceAddress()`.
    fn get_external_space_address(&self) -> Option<Address> {
        Some(self.symbol().get_address())
    }

    /// Stands in for `ExternalLocationDB.isFunction()`.
    fn is_function(&self) -> bool {
        self.symbol().get_symbol_type() == SymbolType::Function
    }

    /// Stands in for `ExternalLocationDB.getDataType()`.
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        let data_type_id = self.symbol_data_type_id();
        if data_type_id < 0 {
            return None;
        }
        self.ext_manager()
            .get_program()
            .get_data_type_manager()
            .and_then(|dtm| dtm.get_data_type_by_id(data_type_id))
    }

    /// Stands in for `ExternalLocationDB.setDataType(DataType)`.
    fn set_data_type(&mut self, dt: Box<dyn DataType>) {
        let data_type_id = self
            .ext_manager()
            .get_program()
            .get_data_type_manager()
            .map(|mut dtm| dtm.get_resolved_id(dt.as_ref()))
            .unwrap_or(-1);
        self.set_symbol_data_type_id(data_type_id);
    }

    /// Stands in for `ExternalLocationDB.getFunction()`.
    fn get_function(&self) -> Option<Arc<dyn Function>> {
        if self.symbol().get_symbol_type() == SymbolType::Function {
            self.symbol_object()
        } else {
            None
        }
    }

    /// Stands in for `ExternalLocationDB.createFunction()`.
    fn create_function(&mut self) -> Arc<dyn Function> {
        if self.symbol().get_symbol_type() == SymbolType::Function {
            return ExternalLocationDb::get_function(self)
                .expect("a Function-typed symbol must resolve to a Function");
        }
        let function = self.ext_manager_create_function();
        self.adopt_function_symbol(&function);
        function
    }

    /// Stands in for `ExternalLocationDB.setLocation(String, Address, SourceType)`.
    fn set_location(
        &mut self,
        label: Option<&str>,
        addr: Option<Address>,
        source: SourceType,
    ) -> Result<(), SetExternalLocationError> {
        let label = label.filter(|l| !l.is_empty());
        if label.is_none() && addr.is_none() {
            return Err(InvalidInputException::with_message(
                "Either an external label or address is required",
            )
            .into());
        }
        if let Some(address) = &addr {
            if !address.is_memory_address() {
                return Err(InvalidInputException::with_message("Invalid memory address").into());
            }
        }
        self.set_label(label, source)?;
        ExternalLocationDb::set_address(self, addr)?;
        Ok(())
    }

    /// Stands in for `ExternalLocationDB.setAddress(Address)`.
    fn set_address(&mut self, address: Option<Address>) -> Result<(), InvalidInputException> {
        if address.is_none() && ExternalLocationDb::get_source(self) == SourceType::Default {
            return Err(InvalidInputException::with_message(
                "Either an external label or address is required",
            ));
        }
        self.set_symbol_external_program_address(address);
        Ok(())
    }

    /// Stands in for `ExternalLocationDB.setName(Namespace, String, SourceType)`.
    ///
    /// # Errors
    /// Returns `Err` if neither a name nor an address is available once a blank/empty `name` is
    /// resolved against the original imported name.
    ///
    /// # Panics
    /// Panics if `namespace` is not external (standing in for the Java method's unchecked
    /// `IllegalArgumentException`), or if the underlying symbol rename reports a
    /// `DuplicateNameException`/`CircularDependencyException` (standing in for the Java method's
    /// own catch-and-rethrow-as-`AssertException`, since external locations do not support
    /// namespace behavior and duplicate names are permitted).
    fn set_name(
        &mut self,
        namespace: Arc<dyn Namespace>,
        name: &str,
        source_type: SourceType,
    ) -> Result<(), InvalidInputException> {
        assert!(namespace.is_external(), "external namespace required");

        let (final_namespace, final_name, final_source) = if name.is_empty() {
            match ExternalLocationDb::get_original_imported_name(self) {
                Some(original_name) => (
                    namespace_or_owning_library(&namespace),
                    original_name,
                    SourceType::Imported,
                ),
                None => {
                    if ExternalLocationDb::get_address(self).is_none() {
                        return Err(InvalidInputException::with_message(
                            "Either an external label or address is required",
                        ));
                    }
                    (namespace, String::new(), SourceType::Default)
                }
            }
        } else {
            let source = if namespace.as_library().is_some()
                && ExternalLocationDb::get_original_imported_name(self).as_deref() == Some(name)
            {
                SourceType::Imported
            } else {
                source_type
            };
            (namespace, name.to_string(), source)
        };

        match self.set_symbol_name_and_namespace(&final_name, final_namespace, final_source) {
            Ok(()) => Ok(()),
            Err(SetSymbolNameAndNamespaceError::InvalidInput(e)) => Err(e),
            Err(SetSymbolNameAndNamespaceError::Duplicate(e)) => {
                panic!("Unexpected exception: {e}")
            }
            Err(SetSymbolNameAndNamespaceError::Circular(e)) => {
                panic!("Unexpected exception: {e}")
            }
        }
    }

    /// Stands in for `ExternalLocationDB.restoreOriginalName()`.
    ///
    /// # Panics
    /// Panics if the underlying symbol rename reports any error, standing in for the Java
    /// method's own catch-and-rethrow-as-`AssertException`.
    fn restore_original_name(&mut self) {
        let Some(original_name) = ExternalLocationDb::get_original_imported_name(self) else {
            return;
        };
        let parent = self
            .symbol()
            .get_parent_namespace()
            .expect("external location symbol always has a parent namespace");
        let library = namespace_or_owning_library(&parent);

        self.set_symbol_external_original_imported_name(None);
        if self
            .set_symbol_name_and_namespace(&original_name, library, SourceType::Imported)
            .is_err()
        {
            panic!("Can't happen here");
        }
    }

    /// Stands in for `ExternalLocationDB.isEquivalent(ExternalLocation)`.
    fn is_equivalent(&self, other: &dyn ExternalLocation) -> bool {
        if ExternalLocationDb::is_function(self) != other.is_function() {
            return false;
        }

        let name = ExternalLocationDb::get_label(self);
        let original_import_name = ExternalLocationDb::get_original_imported_name(self);
        let other_name = other.get_label();
        let other_original_import_name = other.get_original_imported_name();

        if let Some(orig) = &original_import_name {
            if Some(orig.as_str()) == other_original_import_name.as_deref() {
                return true;
            }
        }
        if Some(other_name.as_str()) == original_import_name.as_deref() {
            return true;
        }
        if Some(name.as_str()) == other_original_import_name.as_deref() {
            return true;
        }
        if original_import_name.is_some() || other_original_import_name.is_some() {
            return false;
        }

        let self_qualified = ExternalLocationDb::get_symbol(self)
            .map(|s| SymbolPathNode::from_symbol(s.as_ref(), false).path());
        let other_qualified = other
            .get_symbol()
            .map(|s| SymbolPathNode::from_symbol(s.as_ref(), false).path());
        if self_qualified != other_qualified {
            return false;
        }

        ExternalLocationDb::get_address(self) == other.get_address()
    }
}

/// Stands in for the static utility `NamespaceUtils.getLibrary(Namespace)`: returns `namespace`
/// itself if it is already a Library, otherwise walks its parent chain to find the nearest
/// enclosing Library, falling back to the outermost namespace reached if none is found.
/// Reproduced directly (like `SymbolPathNode`'s own parsing helpers) rather than stubbed, since
/// it's a stateless algorithm over the already-ported [`Namespace`] trait, not a polymorphic core
/// type.
fn namespace_or_owning_library(namespace: &Arc<dyn Namespace>) -> Arc<dyn Namespace> {
    let mut current = namespace.clone();
    loop {
        if current.is_library() {
            return current;
        }
        match current.get_parent_namespace() {
            Some(parent) => current = parent,
            None => return current,
        }
    }
}

impl fmt::Display for dyn ExternalLocationDb + '_ {
    /// Stands in for `ExternalLocationDB.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let qualified = ExternalLocationDb::get_symbol(self)
            .map(|s| SymbolPathNode::from_symbol(s.as_ref(), false).path())
            .unwrap_or_default();
        write!(f, "{qualified}")?;
        if let Some(orig) = ExternalLocationDb::get_original_imported_name(self) {
            write!(f, " ({orig})")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::listing::Program;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct MockSymbol {
        name: String,
        address: Address,
        source: SourceType,
        parent: Option<Arc<dyn Namespace>>,
        symbol_type: SymbolType,
        id: i64,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            self.parent.as_ref().map(|p| p.get_id()).unwrap_or(-1)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    struct MockNamespace {
        id: i64,
        symbol: Arc<dyn Symbol>,
        parent: Option<Arc<dyn Namespace>>,
        external: bool,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn is_external(&self) -> bool {
            self.external
        }
    }

    struct MockLibrary {
        id: i64,
        symbol: Arc<dyn Symbol>,
        program_path: Option<String>,
    }

    impl Namespace for MockLibrary {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            None
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn is_external(&self) -> bool {
            true
        }
        fn as_library(&self) -> Option<Arc<dyn Library>> {
            Some(Arc::new(MockLibrary {
                id: self.id,
                symbol: self.symbol.clone(),
                program_path: self.program_path.clone(),
            }))
        }
    }

    impl Library for MockLibrary {
        fn get_associated_program_path(&self) -> Option<String> {
            self.program_path.clone()
        }
        fn set_associated_program_path(
            &mut self,
            program_path: Option<&str>,
        ) -> Result<(), InvalidInputException> {
            self.program_path = program_path.map(str::to_string);
            Ok(())
        }
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {
        fn get_resolved_id(&mut self, _dt: &dyn DataType) -> i64 {
            7
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            if data_type_id == 42 {
                Some(Box::new(MockDataType))
            } else {
                None
            }
        }
    }

    struct MockProgram;
    impl crate::framework::model::domain_object::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            Some(Box::new(MockDataTypeManager))
        }
    }

    struct MockExternalManagerDb {
        program: Arc<dyn Program>,
    }

    impl ExternalManagerDb for MockExternalManagerDb {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
    }

    struct MockExternalLocationDb {
        symbol: Arc<dyn Symbol>,
        ext_manager: Arc<dyn ExternalManagerDb>,
        original_imported_name: Option<String>,
        external_program_address: Option<Address>,
        data_type_id: i64,
        last_name_and_namespace: Mutex<Option<(String, i64, SourceType)>>,
        namespace_hierarchy_calls: Mutex<Vec<(Option<String>, Option<i64>, SourceType)>>,
    }

    impl ExternalLocation for MockExternalLocationDb {
        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            ExternalLocationDb::get_symbol(self)
        }
        fn get_library_name(&self) -> String {
            ExternalLocationDb::get_library_name(self)
        }
        fn get_external_library_path(&self) -> Option<String> {
            ExternalLocationDb::get_external_library_path(self)
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            ExternalLocationDb::get_parent_namespace(self)
        }
        fn get_parent_name(&self) -> String {
            ExternalLocationDb::get_parent_name(self)
        }
        fn get_label(&self) -> String {
            ExternalLocationDb::get_label(self)
        }
        fn get_original_imported_name(&self) -> Option<String> {
            ExternalLocationDb::get_original_imported_name(self)
        }
        fn get_source(&self) -> SourceType {
            ExternalLocationDb::get_source(self)
        }
        fn get_address(&self) -> Option<Address> {
            ExternalLocationDb::get_address(self)
        }
        fn get_external_space_address(&self) -> Option<Address> {
            ExternalLocationDb::get_external_space_address(self)
        }
        fn is_function(&self) -> bool {
            ExternalLocationDb::is_function(self)
        }
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            ExternalLocationDb::get_data_type(self)
        }
        fn set_data_type(&mut self, dt: Box<dyn DataType>) {
            ExternalLocationDb::set_data_type(self, dt)
        }
        fn get_function(&self) -> Option<Arc<dyn Function>> {
            ExternalLocationDb::get_function(self)
        }
        fn create_function(&mut self) -> Arc<dyn Function> {
            ExternalLocationDb::create_function(self)
        }
        fn set_location(
            &mut self,
            label: Option<&str>,
            addr: Option<Address>,
            source: SourceType,
        ) -> Result<(), SetExternalLocationError> {
            ExternalLocationDb::set_location(self, label, addr, source)
        }
        fn set_address(&mut self, address: Option<Address>) -> Result<(), InvalidInputException> {
            ExternalLocationDb::set_address(self, address)
        }
        fn set_name(
            &mut self,
            namespace: Arc<dyn Namespace>,
            name: &str,
            source_type: SourceType,
        ) -> Result<(), InvalidInputException> {
            ExternalLocationDb::set_name(self, namespace, name, source_type)
        }
        fn restore_original_name(&mut self) {
            ExternalLocationDb::restore_original_name(self)
        }
        fn is_equivalent(&self, other: &dyn ExternalLocation) -> bool {
            ExternalLocationDb::is_equivalent(self, other)
        }
    }

    impl ExternalLocationDb for MockExternalLocationDb {
        fn symbol(&self) -> Arc<dyn Symbol> {
            self.symbol.clone()
        }
        fn symbol_external_original_imported_name(&self) -> Option<String> {
            self.original_imported_name.clone()
        }
        fn set_symbol_external_original_imported_name(&mut self, name: Option<String>) {
            self.original_imported_name = name;
        }
        fn symbol_external_program_address(&self) -> Option<Address> {
            self.external_program_address.clone()
        }
        fn set_symbol_external_program_address(&mut self, address: Option<Address>) {
            self.external_program_address = address;
        }
        fn symbol_data_type_id(&self) -> i64 {
            self.data_type_id
        }
        fn set_symbol_data_type_id(&mut self, data_type_id: i64) {
            self.data_type_id = data_type_id;
        }
        fn symbol_object(&self) -> Option<Arc<dyn Function>> {
            None
        }
        fn set_symbol_name_and_namespace(
            &mut self,
            new_name: &str,
            new_namespace: Arc<dyn Namespace>,
            source: SourceType,
        ) -> Result<(), SetSymbolNameAndNamespaceError> {
            *self.last_name_and_namespace.lock().unwrap() =
                Some((new_name.to_string(), new_namespace.get_id(), source));
            Ok(())
        }
        fn adopt_function_symbol(&mut self, _function: &Arc<dyn Function>) {}
        fn ext_manager(&self) -> Arc<dyn ExternalManagerDb> {
            self.ext_manager.clone()
        }
        fn ext_manager_create_function(&mut self) -> Arc<dyn Function> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_namespace_hierarchy(
            &self,
            parent_path: Option<&str>,
            parent: Option<Arc<dyn Namespace>>,
            source: SourceType,
        ) -> Result<Arc<dyn Namespace>, InvalidInputException> {
            let parent_id = parent.as_ref().map(|p| p.get_id());
            self.namespace_hierarchy_calls.lock().unwrap().push((
                parent_path.map(str::to_string),
                parent_id,
                source,
            ));
            Ok(Arc::new(MockNamespace {
                id: 999,
                symbol: self.symbol.clone(),
                parent,
                external: true,
            }))
        }
    }

    fn library() -> Arc<dyn Namespace> {
        Arc::new(MockLibrary {
            id: 10,
            symbol: Arc::new(MockSymbol {
                name: "advapi32.dll".to_string(),
                address: addr(0),
                source: SourceType::Imported,
                parent: None,
                symbol_type: SymbolType::Library,
                id: 10,
            }),
            program_path: Some("/External/advapi32.dll".to_string()),
        })
    }

    fn location(name: &str, original_imported_name: Option<&str>) -> MockExternalLocationDb {
        let lib = library();
        let symbol = Arc::new(MockSymbol {
            name: name.to_string(),
            address: addr(0x2000),
            source: SourceType::Imported,
            parent: Some(lib),
            symbol_type: SymbolType::Label,
            id: 20,
        });
        MockExternalLocationDb {
            symbol,
            ext_manager: Arc::new(MockExternalManagerDb {
                program: Arc::new(MockProgram),
            }),
            original_imported_name: original_imported_name.map(str::to_string),
            external_program_address: Some(addr(0x3000)),
            data_type_id: -1,
            last_name_and_namespace: Mutex::new(None),
            namespace_hierarchy_calls: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn basic_accessors_delegate_to_symbol() {
        let loc = location("CreateFileA", None);
        assert_eq!(ExternalLocationDb::get_label(&loc), "CreateFileA");
        assert_eq!(ExternalLocationDb::get_source(&loc), SourceType::Imported);
        assert_eq!(ExternalLocationDb::get_address(&loc), Some(addr(0x3000)));
        assert_eq!(
            ExternalLocationDb::get_external_space_address(&loc),
            Some(addr(0x2000))
        );
        assert!(!ExternalLocationDb::is_function(&loc));
        assert_eq!(ExternalLocationDb::get_parent_name(&loc), "advapi32.dll");
        assert_eq!(ExternalLocationDb::get_ext_name_id(&loc), 10);
    }

    #[test]
    fn library_name_and_path_resolve_through_parent_namespace() {
        let loc = location("CreateFileA", None);
        assert_eq!(ExternalLocationDb::get_library_name(&loc), "advapi32.dll");
        assert_eq!(
            ExternalLocationDb::get_external_library_path(&loc),
            Some("/External/advapi32.dll".to_string())
        );
    }

    #[test]
    fn set_label_without_delimiter_targets_current_parent_namespace() {
        let mut loc = location("CreateFileA", None);
        ExternalLocationDb::set_label(&mut loc, Some("NewLabel"), SourceType::UserDefined)
            .unwrap();
        let recorded = loc.last_name_and_namespace.lock().unwrap().clone().unwrap();
        assert_eq!(recorded, ("NewLabel".to_string(), 10, SourceType::UserDefined));
        assert!(loc.namespace_hierarchy_calls.lock().unwrap().is_empty());
    }

    #[test]
    fn set_label_with_delimiter_builds_namespace_hierarchy() {
        let mut loc = location("CreateFileA", None);
        ExternalLocationDb::set_label(&mut loc, Some("Inner::Leaf"), SourceType::UserDefined)
            .unwrap();

        let calls = loc.namespace_hierarchy_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, Some("Inner".to_string()));
        assert_eq!(calls[0].1, Some(10));

        let recorded = loc.last_name_and_namespace.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0, "Leaf");
        assert_eq!(recorded.1, 999);
    }

    #[test]
    fn set_label_none_targets_library_with_empty_name() {
        let mut loc = location("CreateFileA", None);
        ExternalLocationDb::set_label(&mut loc, None, SourceType::UserDefined).unwrap();
        let recorded = loc.last_name_and_namespace.lock().unwrap().clone().unwrap();
        assert_eq!(recorded, (String::new(), 10, SourceType::Default));
    }

    #[test]
    fn save_original_name_if_needed_clears_when_label_matches_original() {
        let mut loc = location("mangled_name", Some("mangled_name"));
        loc.save_original_name_if_needed(None, "old_name", SourceType::Imported);
        assert_eq!(loc.original_imported_name, None);
    }

    #[test]
    fn save_original_name_if_needed_captures_prior_imported_name() {
        let mut loc = location("Demangled", None);
        let old_ns = library();
        loc.save_original_name_if_needed(Some(old_ns), "mangled_name", SourceType::Imported);
        assert_eq!(
            loc.original_imported_name,
            Some("mangled_name".to_string())
        );
    }

    #[test]
    fn restore_original_name_renames_back_to_import_and_clears_original() {
        let mut loc = location("Demangled", Some("mangled_name"));
        ExternalLocationDb::restore_original_name(&mut loc);
        assert_eq!(loc.original_imported_name, None);
        let recorded = loc.last_name_and_namespace.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0, "mangled_name");
        assert_eq!(recorded.2, SourceType::Imported);
    }

    #[test]
    fn restore_original_name_is_a_no_op_without_an_original_name() {
        let mut loc = location("Demangled", None);
        ExternalLocationDb::restore_original_name(&mut loc);
        assert!(loc.last_name_and_namespace.lock().unwrap().is_none());
    }

    #[test]
    fn is_equivalent_matches_on_shared_original_import_name() {
        let a = location("aaa", Some("mangled"));
        let b = location("bbb", Some("mangled"));
        assert!(ExternalLocationDb::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_false_when_function_ness_differs() {
        let mut a = location("same", None);
        a.symbol = Arc::new(MockSymbol {
            name: "same".to_string(),
            address: addr(0x2000),
            source: SourceType::Imported,
            parent: a.symbol.get_parent_namespace(),
            symbol_type: SymbolType::Function,
            id: 20,
        });
        let b = location("same", None);
        assert!(!ExternalLocationDb::is_equivalent(&a, &b));
    }

    #[test]
    fn is_equivalent_compares_qualified_name_and_address_when_no_original_names() {
        let a = location("same_label", None);
        let b = location("same_label", None);
        assert!(ExternalLocationDb::is_equivalent(&a, &b));

        let mut c = location("same_label", None);
        c.external_program_address = Some(addr(0x9999));
        assert!(!ExternalLocationDb::is_equivalent(&a, &c));
    }

    #[test]
    fn get_data_type_resolves_through_program_data_type_manager() {
        let mut loc = location("CreateFileA", None);
        assert!(ExternalLocationDb::get_data_type(&loc).is_none());

        loc.data_type_id = 42;
        assert!(ExternalLocationDb::get_data_type(&loc).is_some());
    }

    #[test]
    fn set_data_type_stores_the_resolved_id() {
        let mut loc = location("CreateFileA", None);
        ExternalLocationDb::set_data_type(&mut loc, Box::new(MockDataType));
        assert_eq!(loc.data_type_id, 7);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let loc: Box<dyn ExternalLocationDb> = Box::new(location("CreateFileA", None));
        assert_eq!(ExternalLocationDb::get_label(loc.as_ref()), "CreateFileA");
        assert!(!ExternalLocationDb::is_function(loc.as_ref()));
        assert_eq!(format!("{}", &*loc as &dyn ExternalLocationDb), "advapi32.dll::CreateFileA");
    }
}
