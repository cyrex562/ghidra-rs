//! A trace-property access shim for a specific property.
//!
//! Port of `ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess`.

use std::sync::Arc;

use crate::pcode::exec::trace::data::pcode_trace_access::PcodeTraceAccess;
use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::program::model::lang::language::Language;

/// A trace-property access shim for a specific property.
///
/// `T` is the type of the property's values.
///
/// See [`PcodeTraceAccess`] and [`PcodeTraceDataAccess`].
pub trait PcodeTracePropertyAccess<T> {
    /// The language.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the property's value at the given address.
    ///
    /// This may search for the same property from other related data sources, e.g., from mapped
    /// static images. Returns `None` if not set.
    fn get(&self, address: &Address) -> Option<T>;

    /// Get the property's entry (range, value) at the given address, or `None` if not set.
    fn get_entry(&self, address: &Address) -> Option<(AddressRange, T)>;

    /// Set the property's value at the given address.
    ///
    /// The value is effective for future snapshots up to but excluding the next snapshot where
    /// another value is set at the same address.
    fn put(&mut self, address: &Address, value: T);

    /// Set the property's value at the given range.
    ///
    /// The value is effective for future snapshots up to but excluding the next snapshot where
    /// another value is set at the same address.
    fn put_range(&mut self, range: &AddressRange, value: T);

    /// Clear the property's value across a range.
    fn clear(&mut self, range: &AddressRange);

    /// Check if the trace has allocated property space for the given address space.
    ///
    /// This is available for optimizations when it may take effort to compute an address. If the
    /// space is not allocated, then no matter the offset, the property will not have a value.
    /// Clients can check this method to avoid the address computation, if they already know the
    /// address space.
    fn has_space(&self, space: &Arc<AddressSpace>) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::address::{
        AddressFactory, AddressSet, AddressSetView, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::processor_context::ProcessorContext;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use crate::util::task::TaskMonitor;
    use std::collections::{HashMap, HashSet};

    struct MockLanguage {
        factory: DefaultAddressFactory,
    }

    impl MockLanguage {
        fn new(space: &Arc<AddressSpace>) -> Self {
            MockLanguage {
                factory: DefaultAddressFactory::new(vec![space.clone()]),
            }
        }
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("test:LE:64:default").unwrap()
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.factory.get_default_address_space().unwrap()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            self.get_default_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(UnknownInstructionException::new()))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// A minimal in-memory property access, mirroring `DefaultPcodeTracePropertyAccess`'s
    /// address-keyed put/get/clear/has_space behavior (sans platform mapping and overlays).
    struct FakePropertyAccess {
        space: Arc<AddressSpace>,
        values: HashMap<i64, i32>,
    }

    impl PcodeTracePropertyAccess<i32> for FakePropertyAccess {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage::new(&self.space))
        }

        fn get(&self, address: &Address) -> Option<i32> {
            self.values.get(&address.offset()).copied()
        }

        fn get_entry(&self, address: &Address) -> Option<(AddressRange, i32)> {
            let value = self.get(address)?;
            Some((AddressRange::new(address.clone(), address.clone()), value))
        }

        fn put(&mut self, address: &Address, value: i32) {
            self.values.insert(address.offset(), value);
        }

        fn put_range(&mut self, range: &AddressRange, value: i32) {
            for addr in range.addresses() {
                self.values.insert(addr.offset(), value);
            }
        }

        fn clear(&mut self, range: &AddressRange) {
            for addr in range.addresses() {
                self.values.remove(&addr.offset());
            }
        }

        fn has_space(&self, space: &Arc<AddressSpace>) -> bool {
            Arc::ptr_eq(&self.space, space)
        }
    }

    #[test]
    fn test_get_put_entry_clear_has_space() {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let mut access = FakePropertyAccess {
            space: space.clone(),
            values: HashMap::new(),
        };

        let a0 = space.address(0x1000);
        let a1 = space.address(0x1001);

        assert_eq!(access.get(&a0), None);
        assert!(access.has_space(&space));
        assert_eq!(access.get_language().get_language_id().to_string(), "test:LE:64:default");

        access.put(&a0, 42);
        assert_eq!(access.get(&a0), Some(42));
        assert_eq!(
            access.get_entry(&a0),
            Some((AddressRange::new(a0.clone(), a0.clone()), 42))
        );

        let range = AddressRange::new(a0.clone(), a1.clone());
        access.put_range(&range, 7);
        assert_eq!(access.get(&a0), Some(7));
        assert_eq!(access.get(&a1), Some(7));

        access.clear(&range);
        assert_eq!(access.get(&a0), None);
        assert_eq!(access.get(&a1), None);

        let other_space = AddressSpace::new("other", 64, 1, AddressSpaceType::Ram, 1);
        assert!(!access.has_space(&other_space));
    }
}
