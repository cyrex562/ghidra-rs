use crate::app::util::viewer::multilisting::address_translator::AddressTranslator;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// Maps program-specific addresses for translation during merge operations.
///
/// Corresponds to Java `ghidra.app.merge.ProgramSpecificAddressTranslator`.
/// Implements address translation by maintaining a mapping of programs to their specific addresses.
pub struct ProgramSpecificAddressTranslator {
    map: HashMap<ProgramKey, Address>,
}

/// Wrapper for Arc<dyn Program> that uses pointer equality for hashing and comparison.
/// This allows us to use trait objects as HashMap keys based on object identity.
struct ProgramKey(Arc<dyn Program>);

impl Hash for ProgramKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let ptr_val = self.0.as_ref() as *const dyn Program as *const () as usize;
        ptr_val.hash(state);
    }
}

impl PartialEq for ProgramKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ProgramKey {}

impl Clone for ProgramKey {
    fn clone(&self) -> Self {
        ProgramKey(Arc::clone(&self.0))
    }
}

impl ProgramSpecificAddressTranslator {
    /// Creates a new ProgramSpecificAddressTranslator with an empty program-address mapping.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Adds a mapping from a program to its specific address.
    ///
    /// # Arguments
    /// * `program` - The program to associate with the address.
    /// * `address` - The address specific to that program.
    pub fn add_program_address(&mut self, program: Arc<dyn Program>, address: Address) {
        self.map.insert(ProgramKey(program), address);
    }
}

impl Default for ProgramSpecificAddressTranslator {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressTranslator for ProgramSpecificAddressTranslator {
    fn translate(&self, address: Address, _primary_program: &dyn Program, program: &dyn Program) -> Address {
        let program_ptr = program as *const dyn Program as *const ();
        for (key, addr) in &self.map {
            let key_ptr = key.0.as_ref() as *const dyn Program as *const ();
            if program_ptr == key_ptr {
                return addr.clone();
            }
        }
        address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct TestProgram {
        name: String,
    }

    impl crate::framework::model::DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "test".to_string()
        }
    }

    #[test]
    fn new_translator_created_empty() {
        let translator = ProgramSpecificAddressTranslator::new();
        assert_eq!(translator.map.len(), 0);
    }

    #[test]
    fn add_program_address_stores_mapping() {
        let mut translator = ProgramSpecificAddressTranslator::new();
        let space = crate::program::model::address::AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        let program: Arc<dyn Program> = Arc::new(TestProgram { name: "test".to_string() });

        translator.add_program_address(program.clone(), addr);
        assert_eq!(translator.map.len(), 1);
    }

    #[test]
    fn translate_returns_stored_address_for_program() {
        let mut translator = ProgramSpecificAddressTranslator::new();
        let space = crate::program::model::address::AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0x2000);
        let lookup_addr = Address::new(space.clone(), 0x1000);
        let program: Arc<dyn Program> = Arc::new(TestProgram { name: "test".to_string() });

        translator.add_program_address(program.clone(), addr.clone());

        let result = translator.translate(lookup_addr, program.as_ref(), program.as_ref());
        assert_eq!(result, addr);
    }

    #[test]
    fn translate_returns_original_address_when_program_not_found() {
        let translator = ProgramSpecificAddressTranslator::new();
        let space = crate::program::model::address::AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let lookup_addr = Address::new(space.clone(), 0x1000);
        let program: Arc<dyn Program> = Arc::new(TestProgram { name: "test".to_string() });

        let result = translator.translate(lookup_addr.clone(), program.as_ref(), program.as_ref());
        assert_eq!(result, lookup_addr);
    }

    #[test]
    fn default_creates_empty_translator() {
        let translator = ProgramSpecificAddressTranslator::default();
        assert_eq!(translator.map.len(), 0);
    }

    #[test]
    fn multiple_programs_stored_separately() {
        let mut translator = ProgramSpecificAddressTranslator::new();
        let space = crate::program::model::address::AddressSpace::new("ram", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let addr1 = Address::new(space.clone(), 0x1000);
        let addr2 = Address::new(space.clone(), 0x2000);
        let program1: Arc<dyn Program> = Arc::new(TestProgram { name: "prog1".to_string() });
        let program2: Arc<dyn Program> = Arc::new(TestProgram { name: "prog2".to_string() });

        translator.add_program_address(program1.clone(), addr1);
        translator.add_program_address(program2.clone(), addr2);

        assert_eq!(translator.map.len(), 2);
    }
}
