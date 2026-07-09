use std::collections::HashMap;
use std::sync::Arc;

use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;

/// Translates registers between two [`Language`]s of the same processor family by matching them
/// up by their offset within the "register" address space and by size.
///
/// Port of `ghidra.program.model.lang.RegisterTranslator`.
pub struct RegisterTranslator {
    old_lang: Arc<dyn Language>,
    new_lang: Arc<dyn Language>,
    old_register_map: HashMap<i32, Vec<RegisterRef>>,
    new_register_map: HashMap<i32, Vec<RegisterRef>>,
}

impl RegisterTranslator {
    pub fn new(old_lang: Arc<dyn Language>, new_lang: Arc<dyn Language>) -> Self {
        let old_register_map = Self::build_offset_map(old_lang.get_registers());
        let new_register_map = Self::build_offset_map(new_lang.get_registers());
        RegisterTranslator {
            old_lang,
            new_lang,
            old_register_map,
            new_register_map,
        }
    }

    fn build_offset_map(registers: Vec<RegisterRef>) -> HashMap<i32, Vec<RegisterRef>> {
        let mut offset_map: HashMap<i32, Vec<RegisterRef>> = HashMap::new();
        for register in registers {
            let (is_register_space, offset) = {
                let reg = register.borrow();
                // Must disregard registers which are not in the "register" named space since
                // these would never have been encoded/decoded properly by the addressMap.
                let is_register_space = reg.address().is_register_address()
                    && reg.address_space().name().eq_ignore_ascii_case("register");
                (is_register_space, reg.offset())
            };
            if !is_register_space {
                continue;
            }
            offset_map.entry(offset).or_default().push(register);
        }
        for register_list in offset_map.values_mut() {
            // Sort largest to smallest.
            register_list.sort_by(|r1, r2| r2.borrow().bit_length().cmp(&r1.borrow().bit_length()));
        }
        offset_map
    }

    fn find_register(map: &HashMap<i32, Vec<RegisterRef>>, offset: i32, size: i32) -> Option<RegisterRef> {
        let list = map.get(&offset)?;
        if size == 0 {
            return list.first().cloned();
        }
        list.iter()
            .rev()
            .find(|reg| reg.borrow().minimum_byte_size() >= size)
            .cloned()
    }

    /// Returns the register in the old language at `offset` with at least `size` bytes, or the
    /// largest register at that offset if `size` is 0.
    pub fn get_old_register_at(&self, offset: i32, size: i32) -> Option<RegisterRef> {
        Self::find_register(&self.old_register_map, offset, size)
    }

    /// Returns the register in the new language at `offset` with at least `size` bytes, or the
    /// largest register at that offset if `size` is 0.
    pub fn get_new_register_at(&self, offset: i32, size: i32) -> Option<RegisterRef> {
        Self::find_register(&self.new_register_map, offset, size)
    }

    /// Returns the register in the new language with the same name as `old_reg`.
    pub fn get_new_register_for(&self, old_reg: &RegisterRef) -> Option<RegisterRef> {
        self.new_lang.get_register_by_name(&old_reg.borrow().name())
    }

    /// Returns the register in the old language with the same name as `new_reg`.
    pub fn get_old_register_for(&self, new_reg: &RegisterRef) -> Option<RegisterRef> {
        self.old_lang.get_register_by_name(&new_reg.borrow().name())
    }

    /// Returns all registers defined by the new language.
    pub fn get_new_registers(&self) -> Vec<RegisterRef> {
        self.new_lang.get_registers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::Register;

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
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
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

        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            false
        }

        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
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

        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<RegisterRef> {
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

        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<RegisterRef> {
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
        ) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            Vec::new()
        }

        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }

        fn get_segmented_space(&self) -> String {
            String::new()
        }

        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
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

        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this test")
        }

        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn make_language(registers: Vec<RegisterRef>) -> Arc<dyn Language> {
        Arc::new(MockLanguage { registers })
    }

    #[test]
    fn get_old_and_new_register_at_matches_by_offset_and_size() {
        let space = register_space();
        let old_r0 = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let old_r0l =
            Register::with_bit_range("R0L", "", space.address(0x0), 2, 0, 16, false, Register::TYPE_NONE);
        let new_r0 = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);

        let old_lang = make_language(vec![old_r0.clone(), old_r0l.clone()]);
        let new_lang = make_language(vec![new_r0.clone()]);
        let translator = RegisterTranslator::new(old_lang, new_lang);

        // size == 0 returns the largest register at the offset.
        let found = translator.get_old_register_at(0, 0).unwrap();
        assert_eq!(found.borrow().name(), "R0");

        // A size that only the smaller register can satisfy exactly still returns the smallest
        // register whose storage is big enough.
        let found = translator.get_old_register_at(0, 2).unwrap();
        assert_eq!(found.borrow().name(), "R0L");

        let found = translator.get_new_register_at(0, 4).unwrap();
        assert_eq!(found.borrow().name(), "R0");

        assert!(translator.get_old_register_at(0x100, 0).is_none());
    }

    #[test]
    fn offset_map_ignores_registers_outside_register_space() {
        let reg_space = register_space();
        let mem_space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let in_space = Register::new("R0", "", reg_space.address(0x0), 4, false, Register::TYPE_NONE);
        let out_of_space =
            Register::new("MEMREG", "", mem_space.address(0x0), 4, false, Register::TYPE_NONE);

        let old_lang = make_language(vec![in_space.clone(), out_of_space]);
        let new_lang = make_language(vec![in_space]);
        let translator = RegisterTranslator::new(old_lang, new_lang);

        assert!(translator.get_old_register_at(0, 0).is_some());
        assert_eq!(translator.get_new_registers().len(), 1);
    }

    #[test]
    fn get_new_register_for_and_get_old_register_for_match_by_name() {
        let space = register_space();
        let old_reg = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let new_reg = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);

        let old_lang = make_language(vec![old_reg.clone()]);
        let new_lang = make_language(vec![new_reg.clone()]);
        let translator = RegisterTranslator::new(old_lang, new_lang);

        let found = translator.get_new_register_for(&old_reg).unwrap();
        assert_eq!(found.borrow().name(), "EAX");

        let found = translator.get_old_register_for(&new_reg).unwrap();
        assert_eq!(found.borrow().name(), "EAX");
    }
}
