//! Interface for translating addresses between programs.

use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// Translates an address from one program to another.
///
/// Corresponds to Java `ghidra.app.util.viewer.multilisting.AddressTranslator`.
pub trait AddressTranslator {
    /// Translates an address from one program space to another.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to translate.
    /// * `primary_program` - The primary program context.
    /// * `program` - The program context for the translation.
    ///
    /// # Returns
    ///
    /// The translated address.
    fn translate(&self, address: Address, primary_program: &dyn Program, program: &dyn Program) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "test".to_string()
        }
    }

    struct TestTranslator;

    impl AddressTranslator for TestTranslator {
        fn translate(&self, address: Address, _primary_program: &dyn Program, _program: &dyn Program) -> Address {
            address
        }
    }

    #[test]
    fn test_translate_returns_address() {
        let translator = TestTranslator;
        let mock = MockProgram;
        let test_addr = Address::new(0, 0x1000);
        let result = translator.translate(test_addr, &mock, &mock);
        assert_eq!(result, test_addr);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let translator: Box<dyn AddressTranslator> = Box::new(TestTranslator);
        let mock = MockProgram;
        let test_addr = Address::new(0, 0x2000);
        let result = translator.translate(test_addr, &mock, &mock);
        assert_eq!(result, test_addr);
    }
}
