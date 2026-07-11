use crate::framework::model::DomainObject;
use crate::program::model::address::{AddressFactory, AddressSet, AddressSetView};
use crate::program::model::lang::{CompilerSpecID, RegisterRef};
use crate::program::model::listing::Listing;
use crate::program::model::symbol::{EquateTable, ExternalManager, ReferenceManager, SymbolTable};
use std::sync::Arc;

/// Name of the properties list holding general program information.
///
/// Stands in for `Program.PROGRAM_INFO`.
pub const PROGRAM_INFO: &str = "Program Information";

pub trait Program: DomainObject + Send + Sync {
    fn get_name(&self) -> String;
    fn get_language_id(&self) -> String;

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
}
