use crate::program::model::address::{Address, AddressRange, AddressSetView};
use crate::program::model::lang::{Language, Register};
use crate::program::seam_stubs::RegisterValue;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::TracePlatform;

/// Operations for reading and writing register (processor context) values over ranges of
/// addresses and time within a trace.
///
/// Port of `ghidra.trace.model.context.TraceRegisterContextOperations`.
pub trait TraceRegisterContextOperations {
    /// Gets the language-defined default value of the register, or `None` if no default is
    /// defined for the parameters.
    fn get_default_value(
        &self,
        language: &dyn Language,
        register: &Register,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Sets the register value over the given lifespan and address range.
    fn set_value(
        &mut self,
        language: &dyn Language,
        value: &dyn RegisterValue,
        lifespan: &dyn Lifespan,
        range: &AddressRange,
    );

    /// Removes any register value over the given span and address range.
    fn remove_value(
        &mut self,
        language: &dyn Language,
        register: &Register,
        span: &dyn Lifespan,
        range: &AddressRange,
    );

    /// Gets the register value at the given snap and address, without falling back to the
    /// language-defined default.
    fn get_value(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Gets the address-range/value pair recording the register value at the given snap and
    /// address, or `None` if there is no such entry.
    fn get_entry(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)>;

    /// Gets the register value at the given snap and address on the given platform, falling
    /// back to the language-defined default if no value is recorded.
    fn get_value_with_default(
        &self,
        platform: &dyn TracePlatform,
        register: &Register,
        snap: i64,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>>;

    /// Gets the addresses within `within` where the register has a recorded value at the given
    /// snap.
    fn get_register_value_address_ranges_within(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> Box<dyn AddressSetView>;

    /// Gets all addresses where the register has a recorded value at the given snap.
    fn get_register_value_address_ranges(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
    ) -> Box<dyn AddressSetView>;

    /// Checks whether the register has a recorded value anywhere within `within` at the given
    /// snap.
    fn has_register_value_in_address_range(
        &self,
        language: &dyn Language,
        register: &Register,
        snap: i64,
        within: &AddressRange,
    ) -> bool;

    /// Checks whether the register has a recorded value anywhere at the given snap.
    fn has_register_value(&self, language: &dyn Language, register: &Register, snap: i64) -> bool;

    /// Removes all register values over the given span and address range.
    fn clear(&mut self, span: &dyn Lifespan, range: &AddressRange);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::RegisterRef;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct MockLanguage {
        registers: Vec<RegisterRef>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }

        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this test")
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }

        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this test")
        }

        fn get_version(&self) -> i32 {
            1
        }

        fn get_minor_version(&self) -> i32 {
            0
        }

        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this test")
        }

        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this test")
        }

        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this test")
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
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this test")
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
            self.registers.clone()
        }

        fn get_register_names(&self) -> Vec<String> {
            self.registers.iter().map(|r| r.borrow().name().to_string()).collect()
        }

        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.iter().find(|r| r.borrow().name() == name).cloned()
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

        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }

        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }

        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }

        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this test")
        }

        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by this test")
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

        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
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

        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }

        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }

        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }

        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockRegisterValue {
        register: RegisterRef,
        value: u128,
    }

    impl RegisterValue for MockRegisterValue {
        fn get_register(&self) -> RegisterRef {
            self.register.clone()
        }

        fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue> {
            Box::new(MockRegisterValue {
                register: Register::from_register(register),
                value: self.value,
            })
        }

        fn has_any_value(&self) -> bool {
            true
        }

        fn get_unsigned_value_ignore_mask(&self) -> u128 {
            self.value
        }

        fn has_value(&self) -> bool {
            self.has_any_value()
        }

        fn combine_values(&self, _other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    struct MockPlatform;

    impl TracePlatform for MockPlatform {}

    /// A minimal in-memory implementor of `TraceRegisterContextOperations`, backed by a single
    /// `(range, value)` slot per snap, sufficient to prove object-safety and exercise real
    /// set/get/clear behavior.
    struct MockOperations {
        // (snap, range, value)
        entries: RefCell<HashMap<i64, (AddressRange, u128)>>,
    }

    impl TraceRegisterContextOperations for MockOperations {
        fn get_default_value(
            &self,
            _language: &dyn Language,
            _register: &Register,
            _address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            None
        }

        fn set_value(
            &mut self,
            _language: &dyn Language,
            value: &dyn RegisterValue,
            lifespan: &dyn Lifespan,
            range: &AddressRange,
        ) {
            self.entries.borrow_mut().insert(
                lifespan.lmin(),
                (range.clone(), value.get_unsigned_value_ignore_mask()),
            );
        }

        fn remove_value(
            &mut self,
            _language: &dyn Language,
            _register: &Register,
            span: &dyn Lifespan,
            _range: &AddressRange,
        ) {
            self.entries.borrow_mut().remove(&span.lmin());
        }

        fn get_value(
            &self,
            _language: &dyn Language,
            register: &Register,
            snap: i64,
            address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            let entries = self.entries.borrow();
            let (range, value) = entries.get(&snap)?;
            if !range.contains(address) {
                return None;
            }
            Some(Box::new(MockRegisterValue {
                register: Register::from_register(register),
                value: *value,
            }))
        }

        fn get_entry(
            &self,
            _language: &dyn Language,
            register: &Register,
            snap: i64,
            address: &Address,
        ) -> Option<(Box<dyn TraceAddressSnapRange>, Box<dyn RegisterValue>)> {
            let entries = self.entries.borrow();
            let (range, value) = entries.get(&snap)?;
            if !range.contains(address) {
                return None;
            }
            let snap_range: Box<dyn TraceAddressSnapRange> = Box::new(MockSnapRange {
                range: range.clone(),
                lifespan: MockLifespan { min: snap, max: snap },
            });
            let reg_value: Box<dyn RegisterValue> = Box::new(MockRegisterValue {
                register: Register::from_register(register),
                value: *value,
            });
            Some((snap_range, reg_value))
        }

        fn get_value_with_default(
            &self,
            _platform: &dyn TracePlatform,
            register: &Register,
            snap: i64,
            address: &Address,
        ) -> Option<Box<dyn RegisterValue>> {
            self.get_value(&MockLanguage { registers: Vec::new() }, register, snap, address)
        }

        fn get_register_value_address_ranges_within(
            &self,
            _language: &dyn Language,
            _register: &Register,
            snap: i64,
            within: &AddressRange,
        ) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            if let Some((range, _)) = self.entries.borrow().get(&snap) {
                if let Some(intersection) = range.intersect(within) {
                    set.add_range_object(&intersection);
                }
            }
            Box::new(set)
        }

        fn get_register_value_address_ranges(
            &self,
            _language: &dyn Language,
            _register: &Register,
            snap: i64,
        ) -> Box<dyn AddressSetView> {
            let mut set = crate::program::model::address::AddressSet::new();
            if let Some((range, _)) = self.entries.borrow().get(&snap) {
                set.add_range_object(range);
            }
            Box::new(set)
        }

        fn has_register_value_in_address_range(
            &self,
            _language: &dyn Language,
            _register: &Register,
            snap: i64,
            within: &AddressRange,
        ) -> bool {
            self.entries
                .borrow()
                .get(&snap)
                .is_some_and(|(range, _)| range.intersects(within))
        }

        fn has_register_value(&self, _language: &dyn Language, _register: &Register, snap: i64) -> bool {
            self.entries.borrow().contains_key(&snap)
        }

        fn clear(&mut self, span: &dyn Lifespan, _range: &AddressRange) {
            self.entries.borrow_mut().remove(&span.lmin());
        }
    }

    #[derive(Clone, Copy)]
    struct MockLifespan {
        min: i64,
        max: i64,
    }

    impl Lifespan for MockLifespan {
        fn lmin(&self) -> i64 {
            self.min
        }

        fn lmax(&self) -> i64 {
            self.max
        }

        fn contains(&self, n: i64) -> bool {
            self.min <= n && n <= self.max
        }

        fn with_min(&self, min: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min, max: self.max })
        }

        fn with_max(&self, max: i64) -> Box<dyn Lifespan> {
            Box::new(MockLifespan { min: self.min, max })
        }

        fn iter(&self) -> Box<dyn Iterator<Item = i64> + '_> {
            Box::new(self.min..=self.max)
        }
    }

    #[derive(Clone)]
    struct MockSnapRange {
        range: AddressRange,
        lifespan: MockLifespan,
    }

    impl TraceAddressSnapRange for MockSnapRange {
        fn get_lifespan(&self) -> Box<dyn Lifespan> {
            Box::new(self.lifespan)
        }

        fn get_range(&self) -> AddressRange {
            self.range.clone()
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            Box::new(self.clone())
        }

        fn immutable(
            &self,
            x1: Address,
            x2: Address,
            y1: i64,
            y2: i64,
        ) -> Box<dyn TraceAddressSnapRange> {
            Box::new(MockSnapRange {
                range: AddressRange::new(x1, x2),
                lifespan: MockLifespan { min: y1, max: y2 },
            })
        }
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "context",
            "Processor context register",
            Address::new(space, 0),
            4,
            false,
            Register::TYPE_NONE,
        )
    }

    #[test]
    fn set_get_and_clear_round_trip_through_trait_object() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let range = AddressRange::new(Address::new(space.clone(), 0), Address::new(space.clone(), 0xf));
        let addr = Address::new(space, 4);
        let register = mock_register();
        let language = MockLanguage { registers: vec![register.clone()] };
        let platform = MockPlatform;
        let lifespan = MockLifespan { min: 0, max: 10 };

        let mut ops: Box<dyn TraceRegisterContextOperations> =
            Box::new(MockOperations { entries: RefCell::new(HashMap::new()) });

        assert!(!ops.has_register_value(&language, &register.borrow(), 0));

        let value = MockRegisterValue { register: register.clone(), value: 0x2a };
        ops.set_value(&language, &value, &lifespan, &range);

        assert!(ops.has_register_value(&language, &register.borrow(), 0));
        assert!(ops.has_register_value_in_address_range(&language, &register.borrow(), 0, &range));

        let got = ops.get_value(&language, &register.borrow(), 0, &addr).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0x2a);

        let got_default = ops
            .get_value_with_default(&platform, &register.borrow(), 0, &addr)
            .unwrap();
        assert_eq!(got_default.get_unsigned_value_ignore_mask(), 0x2a);

        let ranges = ops.get_register_value_address_ranges(&language, &register.borrow(), 0);
        assert!(ranges.contains(&addr));

        let (entry_range, entry_value) =
            ops.get_entry(&language, &register.borrow(), 0, &addr).unwrap();
        assert_eq!(entry_range.get_range(), range);
        assert_eq!(entry_value.get_unsigned_value_ignore_mask(), 0x2a);

        ops.remove_value(&language, &register.borrow(), &lifespan, &range);
        assert!(!ops.has_register_value(&language, &register.borrow(), 0));

        ops.set_value(&language, &value, &lifespan, &range);
        ops.clear(&lifespan, &range);
        assert!(!ops.has_register_value(&language, &register.borrow(), 0));
    }
}
