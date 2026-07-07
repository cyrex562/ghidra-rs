use crate::program::model::address::Address;
use crate::program::model::lang::parser_context::ParserContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::unknown_context_exception::UnknownContextException;
use crate::program::model::mem::MemoryAccessException;
use crate::program::seam_stubs::MemBuffer;

/// Utilized by a shared instruction prototype to access all relevant instruction data
/// and context-register storage needed during instruction parse and semantic pcode generation.
///
/// Port of `ghidra.program.model.lang.InstructionContext`.
pub trait InstructionContext {
    /// Get the instruction address that this context corresponds to.
    fn get_address(&self) -> Address;

    /// Get the read-only processor context containing the context-register state
    /// at the corresponding instruction. This is primarily used during the
    /// parse phase to provide the initial context-register state.
    fn get_processor_context(&self) -> &dyn ProcessorContextView;

    /// Get the read-only memory buffer containing the instruction bytes. Its position will
    /// correspond to the instruction address.
    fn get_mem_buffer(&self) -> &dyn MemBuffer;

    /// Get the instruction parser context for the instruction which corresponds to this
    /// context object.
    ///
    /// # Errors
    /// Returns [`MemoryAccessException`] if a memory error occurred while resolving
    /// instruction details.
    fn get_parser_context(&self) -> Result<Box<dyn ParserContext>, MemoryAccessException>;

    /// Get the instruction parser context which corresponds to the specified instruction
    /// address. This may be obtained via either caching or by parsing the instruction
    /// at the specified address. The returned ParserContext may be cast to the prototype's
    /// implementation without checking.
    ///
    /// # Errors
    /// Returns [`UnknownContextException`] if a compatible ParserContext is not found at
    /// the specified address or if the instruction at the specified address was not
    /// previously parsed or attempting to instantiate context resulted in an exception.
    ///
    /// Returns [`MemoryAccessException`] if a memory error occurred while resolving
    /// instruction details.
    fn get_parser_context_at(
        &self,
        instruction_address: Address,
    ) -> Result<Box<dyn ParserContext>, InstructionContextError>;
}

/// Error type for [`InstructionContext`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstructionContextError {
    /// The instruction context was not found at the specified address.
    UnknownContext(UnknownContextException),
    /// A memory access error occurred.
    MemoryAccess(MemoryAccessException),
}

impl From<UnknownContextException> for InstructionContextError {
    fn from(err: UnknownContextException) -> Self {
        InstructionContextError::UnknownContext(err)
    }
}

impl From<MemoryAccessException> for InstructionContextError {
    fn from(err: MemoryAccessException) -> Self {
        InstructionContextError::MemoryAccess(err)
    }
}

impl std::fmt::Display for InstructionContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstructionContextError::UnknownContext(err) => write!(f, "{}", err),
            InstructionContextError::MemoryAccess(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for InstructionContextError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::seam_stubs::ParserContext as SeamParserContext;
    use std::sync::Arc;

    struct MockMemBuffer;

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
            Address::new(space, 0x1000)
        }
    }

    struct MockProcessorContextView;

    impl ProcessorContextView for MockProcessorContextView {
        fn get_base_context_register(
            &self,
        ) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_registers(&self) -> Vec<crate::program::model::lang::RegisterRef> {
            vec![]
        }

        fn get_register(&self, _name: &str) -> Option<crate::program::model::lang::RegisterRef> {
            None
        }

        fn get_value(
            &self,
            _register: &crate::program::model::lang::Register,
            _signed: bool,
        ) -> Option<i128> {
            None
        }

        fn get_register_value(
            &self,
            _register: &crate::program::model::lang::Register,
        ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
            None
        }

        fn has_value(&self, _register: &crate::program::model::lang::Register) -> bool {
            false
        }
    }

    struct MockParserContext;

    impl SeamParserContext for MockParserContext {
        fn get_prototype(&self) -> Arc<dyn crate::program::model::lang::InstructionPrototype> {
            unimplemented!()
        }
    }

    struct MockInstructionContext;

    impl InstructionContext for MockInstructionContext {
        fn get_address(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
            Address::new(space, 0x2000)
        }

        fn get_processor_context(&self) -> &dyn ProcessorContextView {
            &MockProcessorContextView
        }

        fn get_mem_buffer(&self) -> &dyn MemBuffer {
            &MockMemBuffer
        }

        fn get_parser_context(&self) -> Result<Box<dyn ParserContext>, MemoryAccessException> {
            Ok(Box::new(MockParserContext))
        }

        fn get_parser_context_at(
            &self,
            _instruction_address: Address,
        ) -> Result<Box<dyn ParserContext>, InstructionContextError> {
            Ok(Box::new(MockParserContext))
        }
    }

    #[test]
    fn get_address_returns_instruction_address() {
        let ctx = MockInstructionContext;
        let addr = ctx.get_address();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
        assert_eq!(addr, Address::new(space, 0x2000));
    }

    #[test]
    fn get_processor_context_returns_trait_object() {
        let ctx = MockInstructionContext;
        let proc_ctx = ctx.get_processor_context();
        assert!(proc_ctx.get_registers().is_empty());
    }

    #[test]
    fn get_mem_buffer_returns_trait_object() {
        let ctx = MockInstructionContext;
        let buf = ctx.get_mem_buffer();
        let addr = buf.get_address();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
        assert_eq!(addr, Address::new(space, 0x1000));
    }

    #[test]
    fn get_parser_context_succeeds() {
        let ctx = MockInstructionContext;
        assert!(ctx.get_parser_context().is_ok());
    }

    #[test]
    fn get_parser_context_at_succeeds() {
        let ctx = MockInstructionContext;
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
        let result = ctx.get_parser_context_at(Address::new(space, 0x3000));
        assert!(result.is_ok());
    }

    #[test]
    fn instruction_context_error_from_unknown_context() {
        let err = UnknownContextException::new();
        let ctx_err: InstructionContextError = err.into();
        match ctx_err {
            InstructionContextError::UnknownContext(_) => {},
            _ => panic!("Expected UnknownContext variant"),
        }
    }

    #[test]
    fn instruction_context_error_from_memory_access() {
        let err = MemoryAccessException::new("test");
        let ctx_err: InstructionContextError = err.into();
        match ctx_err {
            InstructionContextError::MemoryAccess(_) => {},
            _ => panic!("Expected MemoryAccess variant"),
        }
    }

    #[test]
    fn instruction_context_error_display() {
        let unknown_err = InstructionContextError::UnknownContext(
            UnknownContextException::with_message("test context"),
        );
        assert_eq!(unknown_err.to_string(), "test context");

        let memory_err = InstructionContextError::MemoryAccess(
            MemoryAccessException::new("memory problem"),
        );
        assert_eq!(memory_err.to_string(), "memory problem");
    }

    #[test]
    fn usable_as_trait_object() {
        let ctx: Box<dyn InstructionContext> = Box::new(MockInstructionContext);
        let addr = ctx.get_address();
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Memory, 1);
        assert_eq!(addr, Address::new(space, 0x2000));
        assert!(ctx.get_parser_context().is_ok());
    }
}
