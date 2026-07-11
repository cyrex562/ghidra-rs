use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use std::fmt;
use std::sync::Arc;

/// Raised when an address cannot be mapped to a dynamic address.
///
/// Java equivalent: `ghidra.app.plugin.core.debug.stack.DynamicMappingException`
#[derive(Clone)]
pub struct DynamicMappingException {
    message: String,
    program: Arc<dyn Program>,
    address: Address,
}

impl fmt::Debug for DynamicMappingException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicMappingException")
            .field("message", &self.message)
            .field("program_name", &crate::program::model::listing::Program::get_name(&*self.program))
            .field("address", &self.address)
            .finish()
    }
}

impl DynamicMappingException {
    pub fn new(program: Arc<dyn Program>, address: Address) -> Self {
        let message = format!(
            "Cannot map {}:{} to dynamic adress",
            crate::program::model::listing::Program::get_name(&*program),
            address
        );
        Self { message, program, address }
    }

    pub fn program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }

    pub fn address(&self) -> Address {
        self.address.clone()
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for DynamicMappingException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DynamicMappingException {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use crate::framework::model::DomainObject;

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

    #[test]
    fn test_new_creates_exception() {
        let program = Arc::new(MockProgram {
            name: "test.bin".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x1000);

        let exc = DynamicMappingException::new(program.clone(), address.clone());

        assert_eq!(exc.message(), "Cannot map test.bin:ram:0x1000 to dynamic adress");
        assert_eq!(exc.address().offset(), 0x1000);
    }

    #[test]
    fn test_program_getter() {
        let program = Arc::new(MockProgram {
            name: "myprogram".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x2000);

        let exc = DynamicMappingException::new(program.clone(), address);
        let retrieved = exc.program();

        assert_eq!(crate::program::model::listing::Program::get_name(&*retrieved), "myprogram".to_string());
    }

    #[test]
    fn test_address_getter() {
        let program = Arc::new(MockProgram {
            name: "prog".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "stack",
            64,
            1,
            crate::program::model::address::AddressSpaceType::Stack,
            0,
        );
        let address = Address::new(space.clone(), -0x100);

        let exc = DynamicMappingException::new(program, address.clone());
        let retrieved = exc.address();

        assert_eq!(retrieved.offset(), address.offset());
        assert_eq!(retrieved.space().name(), "stack");
    }

    #[test]
    fn test_display_shows_message() {
        let program = Arc::new(MockProgram {
            name: "binary".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x0);

        let exc = DynamicMappingException::new(program, address);

        assert_eq!(
            exc.to_string(),
            "Cannot map binary:ram:0x0 to dynamic adress"
        );
    }

    #[test]
    fn test_is_error() {
        let program = Arc::new(MockProgram {
            name: "test".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x0);

        let exc = DynamicMappingException::new(program, address);
        let _: &dyn Error = &exc;
    }

    #[test]
    fn test_clone() {
        let program = Arc::new(MockProgram {
            name: "cloned".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x500);

        let exc = DynamicMappingException::new(program, address);
        let cloned = exc.clone();

        assert_eq!(exc.message(), cloned.message());
        assert_eq!(exc.address().offset(), cloned.address().offset());
    }

    #[test]
    fn test_debug_formatting() {
        let program = Arc::new(MockProgram {
            name: "dbg".to_string(),
        });
        let space = crate::program::model::address::AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        let address = Address::new(space, 0x0);

        let exc = DynamicMappingException::new(program, address);
        let debug_str = format!("{:?}", exc);

        assert!(debug_str.contains("DynamicMappingException"));
    }
}
