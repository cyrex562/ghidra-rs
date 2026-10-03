use std::sync::Arc;

use crate::demangler::demangler_options::DemanglerOptions;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// A simple struct to contain the context of a mangled symbol for demangling.
///
/// Mirrors `ghidra.app.util.demangler.MangledContext`.
#[derive(Clone)]
pub struct MangledContext {
    program: Option<Arc<dyn Program>>,
    options: DemanglerOptions,
    mangled: String,
    address: Option<Address>,
}

impl MangledContext {
    /// Creates a new `MangledContext`.
    ///
    /// Mirrors `MangledContext(Program, DemanglerOptions, String, Address)`.
    pub fn new(
        program: Option<Arc<dyn Program>>,
        options: DemanglerOptions,
        mangled: String,
        address: Option<Address>,
    ) -> Self {
        Self { program, options, mangled, address }
    }

    /// Returns the program; can be `None`.
    ///
    /// Mirrors `getProgram()`.
    pub fn program(&self) -> Option<Arc<dyn Program>> {
        self.program.as_ref().map(Arc::clone)
    }

    /// Returns the demangler options.
    ///
    /// Mirrors `getOptions()`.
    pub fn options(&self) -> &DemanglerOptions {
        &self.options
    }

    /// Returns the mangled string.
    ///
    /// Mirrors `getMangled()`.
    pub fn mangled(&self) -> &str {
        &self.mangled
    }

    /// Returns the address; can be `None`.
    ///
    /// Mirrors `getAddress()`.
    pub fn address(&self) -> Option<Address> {
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockProgram {
        name: String,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_language_id(&self) -> String {
            "mock_language".to_string()
        }
    }

    fn make_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn test_getters_with_program_and_address() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "test.bin".to_string() });
        let options = DemanglerOptions::new();
        let address = make_address(0x1000);

        let context = MangledContext::new(
            Some(program.clone()),
            options.clone(),
            "_Z3fooi".to_string(),
            Some(address.clone()),
        );

        assert_eq!(Program::get_name(&*context.program().unwrap()), "test.bin");
        assert_eq!(context.options(), &options);
        assert_eq!(context.mangled(), "_Z3fooi");
        assert_eq!(context.address().unwrap().offset(), address.offset());
    }

    #[test]
    fn test_getters_with_null_program_and_address() {
        let options = DemanglerOptions::new();

        let context =
            MangledContext::new(None, options.clone(), "_Z3fooi".to_string(), None);

        assert!(context.program().is_none());
        assert_eq!(context.options(), &options);
        assert_eq!(context.mangled(), "_Z3fooi");
        assert!(context.address().is_none());
    }

    #[test]
    fn test_clone() {
        let program: Arc<dyn Program> = Arc::new(MockProgram { name: "cloned".to_string() });
        let context = MangledContext::new(
            Some(program),
            DemanglerOptions::new(),
            "_Z3bari".to_string(),
            Some(make_address(0x2000)),
        );

        let cloned = context.clone();

        assert_eq!(cloned.mangled(), context.mangled());
        assert_eq!(Program::get_name(&*cloned.program().unwrap()), "cloned");
        assert_eq!(cloned.address().unwrap().offset(), 0x2000);
    }
}
