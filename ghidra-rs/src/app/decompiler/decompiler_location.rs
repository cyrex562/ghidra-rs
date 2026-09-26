//! Port of `ghidra.app.decompiler.DecompilerLocation`.
//!
//! This trait represents a location in the Decompiler. It allows the Decompiler to subclass more
//! general [`ProgramLocation`]s while adding more detailed Decompiler information.

use crate::app::decompiler::clang_node::ClangNode;
use crate::app::seam_stubs::DecompileResults;
use crate::program::model::address::Address;

/// A location in the Decompiler with detailed decompilation information.
///
/// This is a port of the Java interface `ghidra.app.decompiler.DecompilerLocation`.
pub trait DecompilerLocation: Send + Sync {
    /// Returns the entry point address of the function at this location.
    fn get_function_entry_point(&self) -> Address;

    /// Returns the decompilation results (C-AST, DFG, and CFG) for this location.
    ///
    /// # Returns
    ///
    /// Decompilation results if available, `None` if there are no results attached to this location.
    fn get_decompile(&self) -> Option<Box<dyn DecompileResults>>;

    /// Returns the C text token (as a ClangNode) at the current cursor location.
    ///
    /// # Returns
    ///
    /// The token at this location, or `None` if there are no decompiler results.
    fn get_token(&self) -> Option<Box<dyn ClangNode>>;

    /// Returns the name of the token for the current location.
    fn get_token_name(&self) -> String;

    /// Returns the line number.
    fn get_line_number(&self) -> i32;

    /// Returns the character position.
    fn get_char_pos(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::decompiler::clang_node::ClangNode;
    use crate::program::model::address::AddressSpaceType;
    use std::sync::Arc;

    /// A simple test implementation of DecompilerLocation for testing.
    struct TestDecompilerLocation {
        entry_point: Address,
        token_name: String,
        line_number: i32,
        char_pos: i32,
    }

    impl DecompilerLocation for TestDecompilerLocation {
        fn get_function_entry_point(&self) -> Address {
            self.entry_point.clone()
        }

        fn get_decompile(&self) -> Option<Box<dyn DecompileResults>> {
            None
        }

        fn get_token(&self) -> Option<Box<dyn ClangNode>> {
            None
        }

        fn get_token_name(&self) -> String {
            self.token_name.clone()
        }

        fn get_line_number(&self) -> i32 {
            self.line_number
        }

        fn get_char_pos(&self) -> i32 {
            self.char_pos
        }
    }

    fn test_address_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    #[test]
    fn location_returns_entry_point() {
        let space = test_address_space();
        let address = Address::new(space, 0x1000);
        let location = TestDecompilerLocation {
            entry_point: address.clone(),
            token_name: "foo".to_string(),
            line_number: 5,
            char_pos: 10,
        };

        assert_eq!(location.get_function_entry_point().offset(), 0x1000);
    }

    #[test]
    fn location_returns_token_name() {
        let space = test_address_space();
        let address = Address::new(space, 0x2000);
        let location = TestDecompilerLocation {
            entry_point: address,
            token_name: "bar".to_string(),
            line_number: 3,
            char_pos: 7,
        };

        assert_eq!(location.get_token_name(), "bar");
        assert_eq!(location.get_line_number(), 3);
        assert_eq!(location.get_char_pos(), 7);
    }

    #[test]
    fn location_returns_none_for_decompile_and_token() {
        let space = test_address_space();
        let address = Address::new(space, 0x3000);
        let location = TestDecompilerLocation {
            entry_point: address,
            token_name: "test".to_string(),
            line_number: 1,
            char_pos: 0,
        };

        assert!(location.get_decompile().is_none());
        assert!(location.get_token().is_none());
    }
}
