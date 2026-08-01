use crate::framework::model::DomainObject;
use crate::program::model::address::{Address, AddressFactory, AddressSet, AddressSetView};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::{CompilerSpecID, RegisterRef};
use crate::program::model::listing::{FunctionManager, Listing, ProgramContext};
use crate::program::model::mem::Memory;
use crate::program::model::symbol::{EquateTable, ExternalManager, Namespace, ReferenceManager, SymbolTable};
use std::sync::Arc;

/// Name of the properties list holding general program information.
///
/// Stands in for `Program.PROGRAM_INFO`.
pub const PROGRAM_INFO: &str = "Program Information";

pub trait Program: DomainObject + Send + Sync {
    fn get_name(&self) -> String;
    fn get_language_id(&self) -> String;

    /// Get the language associated with this program.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`CodeUnitFormat`](crate::program::model::listing::code_unit_format::CodeUnitFormat)'s
    /// port of `Program.getLanguage()`, which needs it to check `Language.supportsPcode()`
    /// before performing operand mark-up.
    fn get_language(&self) -> Option<Arc<dyn crate::program::model::lang::Language>> {
        None
    }

    fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
        None
    }

    fn get_loaded_and_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::new())
    }

    fn get_all_initialized_address_set(&self) -> Box<dyn AddressSetView> {
        Box::new(AddressSet::new())
    }

    fn get_listing(&mut self) -> Option<&mut dyn Listing> {
        None
    }

    /// Get the memory for this program.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`DataUtilities`](crate::program::model::data::data_utilities::DataUtilities)'s port of
    /// the private `DataUtilities.getDtInstance`, which needs it to build a `MemBuffer` at a
    /// candidate data address.
    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        None
    }

    /// The namespace representing this program's global symbol scope. Stands in for
    /// `Program.getGlobalNamespace()`.
    ///
    /// Defaults to `None` so existing implementors are unaffected; concrete implementations
    /// should override once global-namespace support is ported. Added for
    /// [`SimpleDiffUtility`](crate::program::util::SimpleDiffUtility::get_symbol).
    fn get_global_namespace(&self) -> Option<Arc<dyn Namespace>> {
        None
    }

    /// Get the reference manager for this program.
    fn get_reference_manager(&mut self) -> Option<&mut dyn ReferenceManager> {
        None
    }

    /// Get the equate table for this program.
    fn get_equate_table(&mut self) -> Option<&mut dyn EquateTable> {
        None
    }

    /// Get the symbol table for this program.
    fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
        None
    }

    /// Get the external manager for this program.
    fn get_external_manager(&mut self) -> Option<&mut dyn ExternalManager> {
        None
    }

    /// Get the function manager for this program.
    fn get_function_manager(&mut self) -> Option<&mut dyn FunctionManager> {
        None
    }

    /// Get the data type manager for this program.
    ///
    /// Unlike the other manager accessors above, this is `&self` rather than `&mut self`: it is
    /// reached through the shared `Arc<dyn Program>` handed back by
    /// [`Variable::get_program`](crate::program::model::listing::Variable::get_program) and
    /// [`Function::get_program`](crate::program::model::listing::Function::get_program), which
    /// only allow read access.
    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        None
    }

    /// Get the path to the program's executable file.
    ///
    /// Returns an empty string if the executable path is not set or unknown.
    fn get_executable_path(&self) -> String {
        String::new()
    }

    /// Get the executable format for this program (e.g., "ELF", "PE", "Mach-O").
    ///
    /// Returns an empty string if the format is not set or unknown.
    fn get_executable_format(&self) -> String {
        String::new()
    }

    /// Get a name for the compiler that produced this program, if known.
    ///
    /// Returns an empty string if the compiler is not set or unknown.
    fn get_compiler(&self) -> String {
        String::new()
    }

    /// Get the ID of the compiler spec associated with this program, if known.
    fn get_compiler_spec_id(&self) -> Option<CompilerSpecID> {
        None
    }

    /// Get a register by name.
    ///
    /// Returns the register with the given name, or `None` if not found.
    fn get_register(&self, _name: &str) -> Option<RegisterRef> {
        None
    }

    /// Get the register whose storage covers the given address, or `None` if `address` does not
    /// correspond to a register.
    ///
    /// Stands in for `Program.getRegister(Varnode)`/`Program.getRegister(Address)`, used by
    /// [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities)
    /// before a full register/address map is ported.
    fn get_register_at(&self, _address: &Address) -> Option<RegisterRef> {
        None
    }

    /// Get the compiler specification associated with this program's language, if known.
    ///
    /// Stands in for `Program.getCompilerSpec()`, used by
    /// [`VariableUtilities`](crate::program::model::listing::variable_utilities::VariableUtilities)
    /// before `ProgramDB`'s architecture wiring is ported.
    fn get_compiler_spec(&self) -> Option<Box<dyn CompilerSpec>> {
        None
    }

    /// Get the program context (register value ranges keyed by address) associated with this
    /// program's language.
    fn get_program_context(&mut self) -> Option<&mut dyn ProgramContext> {
        None
    }

    /// Get the program's image base address, if known.
    ///
    /// Grown (defaulted, so existing implementors keep compiling) for
    /// [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)'s
    /// port of `PointerDataType.getAddressValue`, which needs it to resolve an
    /// image-base-relative pointer.
    fn get_image_base(&self) -> Option<Address> {
        None
    }
}
