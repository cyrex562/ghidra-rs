//! Port of `ghidra.util.table.ProgramTableModel`.

use std::sync::Arc;

use crate::program::model::listing::program::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::util::seam_stubs::ProgramSelection;

/// An interface for translating table rows and columns into program locations and selections.
///
/// This trait allows implementations to map table model rows and columns to program-specific
/// concepts (addresses, selections, etc.), enabling UI components to navigate and interact
/// with program data based on table selections.
///
/// Port of `ghidra.util.table.ProgramTableModel`.
pub trait ProgramTableModel: Send + Sync {
    /// Returns a program location corresponding to the given row and column.
    ///
    /// Motivation: Given a table that has a column that contains addresses. If the user clicks on
    /// this column, then it would be nice to have the CodeBrowser navigate to this address.
    ///
    /// # Arguments
    /// * `model_row` - the row index in the model
    /// * `model_column` - the column index in the model
    ///
    /// # Returns
    /// A program location corresponding to the given row and column
    fn get_program_location(&self, model_row: i32, model_column: i32) -> Box<dyn ProgramLocation>;

    /// Returns a program selection corresponding to the specified row index array.
    ///
    /// # Arguments
    /// * `model_rows` - the currently selected row indices
    ///
    /// # Returns
    /// A program selection
    fn get_program_selection(&self, model_rows: &[i32]) -> Box<dyn ProgramSelection>;

    /// Returns the program associated with this model.
    ///
    /// # Returns
    /// The program associated with this model
    fn get_program(&self) -> Arc<dyn Program>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    struct MockProgramLocation {
        address: Address,
    }
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct MockProgramSelection;
    impl ProgramSelection for MockProgramSelection {}

    struct TestTableModel {
        program: Arc<dyn Program>,
    }

    impl ProgramTableModel for TestTableModel {
        fn get_program_location(&self, _model_row: i32, _model_column: i32) -> Box<dyn ProgramLocation> {
            let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
            Box::new(MockProgramLocation {
                address: Address::new(ram, 0x1000),
            })
        }

        fn get_program_selection(&self, _model_rows: &[i32]) -> Box<dyn ProgramSelection> {
            Box::new(MockProgramSelection)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
    }

    #[test]
    fn get_program_location_returns_location() {
        let program = Arc::new(MockProgram);
        let model = TestTableModel {
            program: program.clone(),
        };

        let location = model.get_program_location(0, 0);
        assert_eq!(location.get_address().offset(), 0x1000);
    }

    #[test]
    fn get_program_selection_returns_selection() {
        let program = Arc::new(MockProgram);
        let model = TestTableModel {
            program: program.clone(),
        };

        let _selection = model.get_program_selection(&[0, 1, 2]);
        // Test just verifies the method returns without error
    }

    #[test]
    fn get_program_returns_program() {
        let program = Arc::new(MockProgram);
        let model = TestTableModel {
            program: program.clone(),
        };

        let returned_program = model.get_program();
        assert_eq!(Program::get_name(&*returned_program), "test_program");
        assert_eq!(returned_program.get_language_id(), "x86:LE:64:default");
    }
}
