use crate::framework::model::DomainObject;
use crate::program::model::address::AddressFactory;
use crate::program::model::listing::Listing;
use crate::program::model::symbol::{EquateTable, ReferenceManager};
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

    /// Get the path to the program's executable file.
    ///
    /// Returns an empty string if the executable path is not set or unknown.
    fn get_executable_path(&self) -> String {
        String::new()
    }
}
