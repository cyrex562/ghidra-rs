//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.DwarfDecodeContext`.
//!
//! Organizational class to record vital data used by a
//! [`DwarfEHDecoder`](crate::app::plugin::exceptionhandlers::gcc::dwarf_eh_decoder::DwarfEHDecoder).

use crate::program::model::address::Address;
use crate::program::model::listing::{Function, Program};
use crate::program::model::mem::MemoryBlock;
use std::sync::Arc;

/// Records the program and address of an encoded DWARF exception-handling value, plus the
/// optional exception-handling memory block and associated function entry point, and the
/// decoded value once a decode has run.
#[derive(Clone)]
pub struct DwarfDecodeContext {
    program: Arc<dyn Program>,
    addr: Address,
    eh_block: Option<Arc<dyn MemoryBlock>>,
    function_entry_point: Option<Address>,
    decoded_value: Option<i64>,
    encoded_length: i32,
}

impl DwarfDecodeContext {
    /// Constructs a Dwarf decode context for `addr` within `program`, optionally recording the
    /// exception-handling memory block and/or the associated function's entry point.
    pub fn new(
        program: Arc<dyn Program>,
        addr: Address,
        eh_block: Option<Arc<dyn MemoryBlock>>,
        function_entry_point: Option<Address>,
    ) -> Self {
        Self {
            program,
            addr,
            eh_block,
            function_entry_point,
            decoded_value: None,
            encoded_length: 0,
        }
    }

    /// Constructs a Dwarf decode context for `addr` within `program`.
    pub fn for_address(program: Arc<dyn Program>, addr: Address) -> Self {
        Self::new(program, addr, None, None)
    }

    /// Constructs a Dwarf decode context for `addr` within `program`, recording the
    /// exception-handling memory block.
    pub fn with_eh_block(
        program: Arc<dyn Program>,
        addr: Address,
        eh_block: Arc<dyn MemoryBlock>,
    ) -> Self {
        Self::new(program, addr, Some(eh_block), None)
    }

    /// Constructs a Dwarf decode context for `addr` within `program`, recording the associated
    /// function's entry point.
    pub fn with_entry_point(
        program: Arc<dyn Program>,
        addr: Address,
        entry_point: Address,
    ) -> Self {
        Self::new(program, addr, None, Some(entry_point))
    }

    /// Constructs a Dwarf decode context for `addr` within `program`, recording the entry point
    /// of the associated `function`.
    pub fn for_function(program: Arc<dyn Program>, addr: Address, function: &dyn Function) -> Self {
        Self::new(program, addr, None, Some(function.get_entry_point()))
    }

    /// Gets the program containing the encoded data.
    pub fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    /// Gets the min address of the encoded data.
    pub fn get_address(&self) -> Address {
        self.addr.clone()
    }

    /// Sets the value and value-length after decode.
    pub fn set_decoded_value(&mut self, value: i64, encoded_length: i32) {
        self.decoded_value = Some(value);
        self.encoded_length = encoded_length;
    }

    /// Gets the decoded value that is at the address, if a decode has run.
    pub fn get_decoded_value(&self) -> Option<i64> {
        self.decoded_value
    }

    /// Gets the length of the encoded data that is at the address.
    pub fn get_encoded_length(&self) -> i32 {
        self.encoded_length
    }

    /// Gets the exception handling memory block associated with this dwarf encoded data, if any.
    pub fn get_eh_block(&self) -> Option<Arc<dyn MemoryBlock>> {
        self.eh_block.clone()
    }

    /// Gets the associated function's entry point, if any.
    pub fn get_function_entry_point(&self) -> Option<Address> {
        self.function_entry_point.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:64:default".to_string()
        }
    }

    fn ram_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn for_address_leaves_eh_block_and_entry_point_unset() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let context = DwarfDecodeContext::for_address(program, ram_address(0x1000));

        assert_eq!(context.get_address().offset(), 0x1000);
        assert!(context.get_eh_block().is_none());
        assert!(context.get_function_entry_point().is_none());
        assert!(context.get_decoded_value().is_none());
        assert_eq!(context.get_encoded_length(), 0);
    }

    #[test]
    fn with_entry_point_records_the_entry_point() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let entry = ram_address(0x400000);
        let context =
            DwarfDecodeContext::with_entry_point(program, ram_address(0x1000), entry.clone());

        assert_eq!(context.get_function_entry_point(), Some(entry));
    }

    #[test]
    fn set_decoded_value_updates_value_and_length() {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let mut context = DwarfDecodeContext::for_address(program, ram_address(0x1000));

        context.set_decoded_value(0x2a, 4);

        assert_eq!(context.get_decoded_value(), Some(0x2a));
        assert_eq!(context.get_encoded_length(), 4);
    }
}
