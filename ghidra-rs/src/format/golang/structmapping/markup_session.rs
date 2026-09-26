//! Port of `ghidra.app.util.bin.format.golang.structmapping.MarkupSession`.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSet};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::undefined::is_undefined;
use crate::program::model::listing::bookmark_type::WARNING;
use crate::program::model::listing::{CommentType, Program};
use crate::program::model::symbol::ref_type::RefType;
use crate::program::model::symbol::source_type::SourceType;
use crate::program::model::symbol::symbol_utilities::SymbolUtilities;
use crate::util::task::TaskMonitor;

use super::data_type_mapper::DataTypeMapper;
use super::field_context::FieldContext;
use super::structure_context::StructureContext;
use super::structure_mapped::{MarkupTarget, StructureMapped};

/// `DataUtilities`'s and `SymbolUtilities`'s statics are trait default methods in this port.
struct Utilities;
impl DataUtilities for Utilities {}
impl SymbolUtilities for Utilities {}

/// State and methods needed for structure mapped objects to add markup, comments, labels, etc
/// to a program.
///
/// The session borrows its [`DataTypeMapper`] (Java keeps a reference to it) and reaches the
/// program's managers through the `&self` `Program` accessors, which hand out short-lived
/// locked handles.
pub struct MarkupSession<'a> {
    program: Arc<dyn Program>,
    mapping_context: &'a DataTypeMapper,
    markedup_structs: HashSet<Address>,
    markedup_addrs: AddressSet,
    monitor: &'a dyn TaskMonitor,
}

impl<'a> MarkupSession<'a> {
    /// Creates a new markup session (`MarkupSession(DataTypeMapper, TaskMonitor)`).
    pub fn new(program_context: &'a DataTypeMapper, monitor: &'a dyn TaskMonitor) -> Self {
        MarkupSession {
            program: program_context.get_program().clone(),
            mapping_context: program_context,
            markedup_structs: HashSet::new(),
            markedup_addrs: AddressSet::new(),
            monitor,
        }
    }

    /// `getProgram()`.
    pub fn get_program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    /// `getMappingContext()`.
    pub fn get_mapping_context(&self) -> &'a DataTypeMapper {
        self.mapping_context
    }

    /// `getMarkedupAddresses()`.
    pub fn get_markedup_addresses(&self) -> &AddressSet {
        &self.markedup_addrs
    }

    /// Decorates the specified object's memory using the various structure mapping tags that
    /// were applied the object's type definition. The object can be a structure mapped instance,
    /// or an `Option`/`Vec`/`Result` of them.
    ///
    /// Port of `markup(T, boolean)`.
    ///
    /// # Errors
    /// On a cancelled monitor, or any markup error.
    pub fn markup<X: MarkupTarget>(&mut self, obj: X, nested: bool) -> io::Result<()> {
        self.check_cancelled()?;
        obj.markup_target(self, nested)
    }

    /// The single-instance arm of `markup(T, boolean)`: marks up one structure mapped
    /// instance through its own [`StructureContext`].
    ///
    /// # Errors
    /// When the instance has no `StructureContext` (Java's `IllegalArgumentException`).
    pub fn markup_instance<T: StructureMapped>(&mut self, obj: &T, nested: bool) -> io::Result<()> {
        self.check_cancelled()?;
        let structure_context = obj.structure_context().ok_or_else(|| {
            io::Error::other(format!("No StructureContext for {}", T::descriptor().type_name))
        })?;
        self.monitor.increment_progress(1);
        self.markup_structure(structure_context, obj, nested)
    }

    /// Applies the specified data type at the specified address (`markupAddress(Address,
    /// DataType)`).
    pub fn markup_address(&mut self, addr: &Address, dt: &dyn DataType) -> io::Result<()> {
        self.markup_address_with_length(addr, dt, -1)
    }

    /// Applies the specified data type at the specified address, with a length for dynamic data
    /// types (`markupAddress(Address, DataType, int)`).
    ///
    /// Java first asks `DWARFDataInstanceHelper.isDataTypeCompatibleWithAddress` (with
    /// truncation disallowed) whether the new data may replace what is there. That class is not
    /// ported; this port applies the data only in its first, unconditional case -- the whole
    /// range is still undefined -- and otherwise leaves existing data alone, as Java does for
    /// every incompatible case.
    pub fn markup_address_with_length(&mut self, addr: &Address, dt: &dyn DataType, length: i32) -> io::Result<()> {
        let end = addr.add_wrap(dt.get_length().max(1) as i64 - 1);
        if !Utilities.is_undefined_range(self.program.as_ref(), addr, &end) {
            return Ok(());
        }
        let new_type = self.clone_into_program(dt)?;
        match Utilities.create_data(
            self.program.as_ref(),
            addr,
            new_type,
            length,
            ClearDataMode::ClearAllConflictData,
        ) {
            Ok(data) => {
                self.markedup_addrs.add_range(&data.get_min_address(), &data.get_max_address());
            }
            Err(e) => {
                self.log_warning_at(addr, &format!("Failed to apply data type [{}]: {}", dt.get_name(), e));
            }
        }
        Ok(())
    }

    /// Applies the specified data type at the address if there is no data there yet, or only
    /// undefined data (`markupAddressIfUndefined(Address, DataType)`).
    pub fn markup_address_if_undefined(&mut self, addr: &Address, dt: &dyn DataType) -> io::Result<()> {
        let data = Utilities.get_data_at_address(self.program.as_ref(), Some(addr));
        let undefined = match &data {
            None => true,
            Some(d) => is_undefined(d.get_base_data_type()),
        };
        if undefined {
            self.markup_address(addr, dt)?;
        }
        Ok(())
    }

    /// Places a label at the specified structure mapped object's address
    /// (`labelStructure(T, String, String)`).
    pub fn label_structure<T: StructureMapped>(
        &mut self,
        obj: &T,
        symbol_name: &str,
        namespace_name: Option<&str>,
    ) -> io::Result<()> {
        let addr = self.mapping_context.get_address_of_structure(obj).ok_or_else(|| {
            io::Error::other(format!("No address for {} instance", T::descriptor().type_name))
        })?;
        self.label_address_in_namespace(&addr, symbol_name, namespace_name)
    }

    /// Places a label at the specified address (`labelAddress(Address, String)`).
    pub fn label_address(&mut self, addr: &Address, symbol_name: &str) -> io::Result<()> {
        self.label_address_in_namespace(addr, symbol_name, None)
    }

    /// Places a label at the specified address, in the named namespace (the global namespace
    /// when `namespace_name` is blank or the namespace cannot be created as a duplicate).
    ///
    /// Port of `labelAddress(Address, String, String)`. Invalid input is logged as a warning
    /// bookmark, as in Java.
    pub fn label_address_in_namespace(
        &mut self,
        addr: &Address,
        symbol_name: &str,
        namespace_name: Option<&str>,
    ) -> io::Result<()> {
        let program = self.program.clone();
        let mut symbol_table = program
            .get_symbol_table()
            .ok_or_else(|| io::Error::other("Program has no symbol table"))?;
        let global_ns = program.get_global_namespace();
        let ns = match (namespace_name.filter(|n| !n.trim().is_empty()), &global_ns) {
            (Some(name), Some(global)) => {
                match symbol_table.get_or_create_name_space(global.clone(), name, SourceType::Imported) {
                    Ok(ns) => Some(ns),
                    Err(crate::program::model::symbol::GetOrCreateNamespaceError::Duplicate(_)) => {
                        Some(global.clone())
                    }
                    Err(e) => {
                        drop(symbol_table);
                        self.log_warning_at(addr, &format!("Failed to label [{symbol_name}]: {e}"));
                        return Ok(());
                    }
                }
            }
            _ => global_ns.clone(),
        };
        let symbol_name = Utilities
            .replace_invalid_chars(Some(symbol_name), true)
            .unwrap_or_default();
        let result = match ns {
            Some(ns) => symbol_table.create_label_in_namespace(addr, &symbol_name, ns, SourceType::Imported),
            None => symbol_table.create_label(addr, &symbol_name, SourceType::Imported),
        };
        match result {
            Ok(sym) => {
                symbol_table.set_primary_symbol(sym.get_id())?;
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                drop(symbol_table);
                self.log_warning_at(addr, &format!("Failed to label [{symbol_name}]: {e}"));
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Adds a comment to the specified field, appending to any existing comment
    /// (`appendComment(FieldContext, CommentType, String, String, String)`).
    pub fn append_comment_at_field<T: StructureMapped>(
        &mut self,
        field_context: &FieldContext<'_, T>,
        comment_type: CommentType,
        prefix: Option<&str>,
        comment: &str,
        sep: &str,
    ) -> io::Result<()> {
        self.append_comment_at(&field_context.get_address(), comment_type, prefix, comment, sep)
    }

    /// Adds a comment to the specified structure, appending to any existing comment
    /// (`appendComment(StructureContext, CommentType, String, String, String)`).
    pub fn append_comment_at_structure<T: StructureMapped>(
        &mut self,
        structure_context: &StructureContext<T>,
        comment_type: CommentType,
        prefix: Option<&str>,
        comment: &str,
        sep: &str,
    ) -> io::Result<()> {
        self.append_comment_at(&structure_context.get_structure_address(), comment_type, prefix, comment, sep)
    }

    /// Adds a plate comment to a function, appending to any existing comment
    /// (`appendComment(Function, String, String)`).
    pub fn append_function_comment(
        &mut self,
        func: Option<&dyn crate::program::model::listing::function::Function>,
        prefix: Option<&str>,
        comment: &str,
    ) -> io::Result<()> {
        match func {
            Some(func) => self.append_comment_at(&func.get_entry_point(), CommentType::Plate, prefix, comment, "\n"),
            None => Ok(()),
        }
    }

    /// `DWARFUtil.appendComment(Program, Address, CommentType, String, String, String)`, reached
    /// through the program's shared listing handle: a blank comment, or one the existing comment
    /// already contains, is not added; otherwise it is appended after `sep`
    /// (`AppendCommentCmd`).
    fn append_comment_at(
        &mut self,
        address: &Address,
        comment_type: CommentType,
        prefix: Option<&str>,
        comment: &str,
        sep: &str,
    ) -> io::Result<()> {
        if comment.trim().is_empty() {
            return Ok(());
        }
        let mut listing = self
            .program
            .get_listing()
            .ok_or_else(|| io::Error::other("Program has no listing to add comments to"))?;
        let existing = listing.get_comment(comment_type, address);
        if existing.as_deref().is_some_and(|c| c.contains(comment)) {
            // don't add same comment twice
            return Ok(());
        }
        let new_comment = format!("{}{}", prefix.unwrap_or(""), comment);
        let combined = match existing {
            Some(prev) => format!("{prev}{sep}{new_comment}"),
            None => new_comment,
        };
        listing.set_comment(address, comment_type, Some(combined));
        Ok(())
    }

    /// Decorates a structure mapped instance's memory (`markupStructure(StructureContext,
    /// boolean)`).
    ///
    /// A top-level (non-`nested`) structure is marked up at most once per session: its
    /// structure data type is applied and, for a `StructureMarkup` type, its label placed. Then
    /// its fields are marked up, and a `StructureMarkup` type gets its `additional_markup`.
    pub fn markup_structure<T: StructureMapped>(
        &mut self,
        structure_context: &StructureContext<T>,
        instance: &T,
        nested: bool,
    ) -> io::Result<()> {
        let addr = structure_context.get_structure_address();
        if !nested && !self.markedup_structs.insert(addr.clone()) {
            return Ok(());
        }
        let hooks = T::descriptor().structure_markup.as_ref();
        if !nested {
            let applied = structure_context
                .get_structure_data_type_for(instance, self.mapping_context)
                .and_then(|struct_dt| {
                    if struct_dt.is_deleted() {
                        return Err(io::Error::other(format!(
                            "Structure mapping data type invalid: {}",
                            struct_dt.get_name()
                        )));
                    }
                    self.markup_address(&addr, struct_dt.as_ref())
                });
            if let Err(e) = applied {
                return Err(io::Error::other(format!(
                    "Markup failed for structure {} at {}: {e}",
                    structure_context.get_mapping_info().get_description(),
                    addr
                )));
            }
            if let Some(hooks) = hooks {
                let structure_label = (hooks.structure_label)(instance)?;
                let namespace_name = (hooks.structure_namespace)(instance)?;
                if let Some(label) = structure_label.filter(|l| !l.trim().is_empty()) {
                    self.label_address_in_namespace(&addr, &label, namespace_name.as_deref())?;
                }
            }
        }
        self.markup_fields(structure_context, instance)?;
        if let Some(hooks) = hooks {
            (hooks.additional_markup)(instance, self)?;
        }
        Ok(())
    }

    /// Port of `markupFields(StructureContext)`: every field markup function, then a
    /// `StructureMarkup` type's external instances, then the structure's own markup functions.
    fn markup_fields<T: StructureMapped>(
        &mut self,
        structure_context: &StructureContext<T>,
        instance: &T,
    ) -> io::Result<()> {
        let mapping_info = structure_context.get_mapping_info().clone();
        for fmi in mapping_info.get_fields() {
            for func in fmi.get_markup_funcs() {
                let field_context = structure_context.create_field_context(instance, fmi, None)?;
                fmi.markup_field(*func, &field_context, self)?;
            }
        }
        if let Some(hooks) = T::descriptor().structure_markup.as_ref() {
            (hooks.external_instances_to_markup)(instance, self)?;
        }
        for markup_func in mapping_info.get_markup_funcs() {
            mapping_info.run_markup_func(markup_func, structure_context, instance, self)?;
        }
        Ok(())
    }

    /// Creates references from each element of an array to a list of target addresses
    /// (`markupArrayElementReferences(Address, int, List)`).
    pub fn markup_array_element_references(
        &mut self,
        array_addr: &Address,
        element_size: i32,
        target_addrs: &[Option<Address>],
    ) -> io::Result<()> {
        if !target_addrs.is_empty() {
            let mut ref_mgr = self
                .program
                .get_reference_manager()
                .ok_or_else(|| io::Error::other("Program has no reference manager"))?;
            let mut array_addr = array_addr.clone();
            for target_addr in target_addrs {
                if let Some(target_addr) = target_addr {
                    ref_mgr.add_memory_reference(
                        array_addr.clone(),
                        target_addr.clone(),
                        RefType::Data,
                        SourceType::Imported,
                        0,
                    );
                }
                array_addr = array_addr.add_wrap(element_size as i64);
            }
        }
        Ok(())
    }

    /// Creates a reference from the specified field to the specified address
    /// (`addReference(FieldContext, Address)`).
    pub fn add_reference<T: StructureMapped>(
        &mut self,
        field_context: &FieldContext<'_, T>,
        ref_dest: Address,
    ) -> io::Result<()> {
        let field_addr = field_context.get_address();
        let mut ref_mgr = self
            .program
            .get_reference_manager()
            .ok_or_else(|| io::Error::other("Program has no reference manager"))?;
        ref_mgr.add_memory_reference(field_addr, ref_dest, RefType::Data, SourceType::Imported, 0);
        Ok(())
    }

    /// Logs a warning bookmark at the address (`logWarningAt(Address, String)`).
    pub fn log_warning_at(&mut self, addr: &Address, msg: &str) {
        Self::log_warning_at_program(self.program.as_ref(), addr, msg);
    }

    /// Adds `msg` to the "Golang" warning bookmark at `addr`, unless that bookmark already
    /// contains it (`logWarningAt(Program, Address, String)`). A program without a bookmark
    /// manager gets no bookmark.
    pub fn log_warning_at_program(program: &dyn Program, addr: &Address, msg: &str) {
        let Some(mut bmm) = program.get_bookmark_manager_mut() else {
            return;
        };
        let existing_txt = bmm
            .get_bookmark(addr.clone(), WARNING, "Golang")
            .map(|bm| bm.get_comment().to_string())
            .unwrap_or_default();
        if existing_txt.contains(msg) {
            return;
        }
        let msg = if existing_txt.is_empty() { msg.to_string() } else { format!("{existing_txt}; {msg}") };
        bmm.set_bookmark(addr.clone(), WARNING, "Golang", &msg);
    }

    fn check_cancelled(&self) -> io::Result<()> {
        self.monitor
            .check_cancelled()
            .map_err(|e| io::Error::new(io::ErrorKind::Interrupted, e.to_string()))
    }

    /// `DataUtilities.createData` takes ownership of the data type; Java passes the shared one
    /// and the listing resolves it into the program. Clone it against the program's manager.
    fn clone_into_program(&self, dt: &dyn DataType) -> io::Result<Box<dyn DataType>> {
        let dtm = self
            .program
            .get_data_type_manager()
            .ok_or_else(|| io::Error::other("Program has no data type manager"))?;
        Ok(dt.clone_data_type(dtm.as_ref()))
    }
}
