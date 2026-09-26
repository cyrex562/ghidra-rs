//! Test fixtures shared by the emulator's tests: a language with a program counter.
//!
//! It stands in for the piece not yet ported: a `.sla`-only
//! [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) has no program counter
//! (only a `.pspec` declares one). Threads decode with the real
//! [`SleighInstructionDecoder`](crate::pcode::emu::sleigh_instruction_decoder::SleighInstructionDecoder).

use std::collections::HashSet;
use std::sync::Arc;

use crate::app::plugin::processors::generic::MemoryBlockDefinition;
use crate::program::model::address::{Address, AddressFactory, AddressSetView, AddressSpace};
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language::{Language, ParseError};
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::{AddressLabelInfo, Processor};
use crate::util::task::TaskMonitor;

/// A language answering every query from `inner`, except that it declares `pc` as its program
/// counter, as the `.pspec` a real language ships with would.
pub(crate) struct PcLanguage {
    pub(crate) inner: Arc<dyn Language>,
    pub(crate) pc: RegisterRef,
}

impl Language for PcLanguage {
    fn get_language_id(&self) -> LanguageID {
        Language::get_language_id(self.inner.as_ref())
    }
    fn get_language_description(&self) -> Box<dyn LanguageDescription> {
        Language::get_language_description(self.inner.as_ref())
    }
    fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
        Language::get_parallel_instruction_helper(self.inner.as_ref())
    }
    fn get_processor(&self) -> Box<dyn Processor> {
        Language::get_processor(self.inner.as_ref())
    }
    fn get_version(&self) -> i32 {
        Language::get_version(self.inner.as_ref())
    }
    fn get_minor_version(&self) -> i32 {
        Language::get_minor_version(self.inner.as_ref())
    }
    fn get_address_factory(&self) -> Box<dyn AddressFactory> {
        Language::get_address_factory(self.inner.as_ref())
    }
    fn get_default_space(&self) -> Arc<AddressSpace> {
        Language::get_default_space(self.inner.as_ref())
    }
    fn get_default_data_space(&self) -> Arc<AddressSpace> {
        Language::get_default_data_space(self.inner.as_ref())
    }
    fn is_big_endian(&self) -> bool {
        Language::is_big_endian(self.inner.as_ref())
    }
    fn get_instruction_alignment(&self) -> i32 {
        Language::get_instruction_alignment(self.inner.as_ref())
    }
    fn supports_pcode(&self) -> bool {
        Language::supports_pcode(self.inner.as_ref())
    }
    fn is_volatile(&self, addr: &Address) -> bool {
        Language::is_volatile(self.inner.as_ref(), addr)
    }
    fn parse(
        &self,
        buf: &dyn MemBuffer,
        context: &mut dyn ProcessorContext,
        in_delay_slot: bool,
    ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
        Language::parse(self.inner.as_ref(), buf, context, in_delay_slot)
    }
    fn get_number_of_user_defined_op_names(&self) -> i32 {
        Language::get_number_of_user_defined_op_names(self.inner.as_ref())
    }
    fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
        Language::get_user_defined_op_name(self.inner.as_ref(), index)
    }
    fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
        Language::get_registers_at(self.inner.as_ref(), address)
    }
    fn get_register_in_space(
        &self,
        addrspc: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
    ) -> Option<RegisterRef> {
        Language::get_register_in_space(self.inner.as_ref(), addrspc, offset, size)
    }
    fn get_registers(&self) -> Vec<RegisterRef> {
        Language::get_registers(self.inner.as_ref())
    }
    fn get_register_names(&self) -> Vec<String> {
        Language::get_register_names(self.inner.as_ref())
    }
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        Language::get_register_by_name(self.inner.as_ref(), name)
    }
    fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
        Language::get_register_at(self.inner.as_ref(), addr, size)
    }
    fn get_program_counter(&self) -> Option<RegisterRef> {
        Some(self.pc.clone())
    }
    fn get_context_base_register(&self) -> Option<RegisterRef> {
        Language::get_context_base_register(self.inner.as_ref())
    }
    fn get_context_registers(&self) -> Vec<RegisterRef> {
        Language::get_context_registers(self.inner.as_ref())
    }
    fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
        Language::get_default_memory_blocks(self.inner.as_ref())
    }
    fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
        Language::get_default_symbols(self.inner.as_ref())
    }
    fn get_segmented_space(&self) -> String {
        Language::get_segmented_space(self.inner.as_ref())
    }
    fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
        Language::get_volatile_addresses(self.inner.as_ref())
    }
    fn apply_context_settings(&self, ctx: &mut dyn DefaultProgramContext) {
        Language::apply_context_settings(self.inner.as_ref(), ctx)
    }
    fn reload_language(&self, task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
        Language::reload_language(self.inner.as_ref(), task_monitor)
    }
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        Language::get_compatible_compiler_spec_descriptions(self.inner.as_ref())
    }
    fn get_compiler_spec_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
        Language::get_compiler_spec_by_id(self.inner.as_ref(), compiler_spec_id)
    }
    fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        Language::get_default_compiler_spec(self.inner.as_ref())
    }
    fn has_property(&self, key: &str) -> bool {
        Language::has_property(self.inner.as_ref(), key)
    }
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32 {
        Language::get_property_as_int(self.inner.as_ref(), key, default_int)
    }
    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool {
        Language::get_property_as_boolean(self.inner.as_ref(), key, default_boolean)
    }
    fn get_property_or(&self, key: &str, default_string: &str) -> String {
        Language::get_property_or(self.inner.as_ref(), key, default_string)
    }
    fn get_property(&self, key: &str) -> Option<String> {
        Language::get_property(self.inner.as_ref(), key)
    }
    fn get_property_keys(&self) -> HashSet<String> {
        Language::get_property_keys(self.inner.as_ref())
    }
    fn has_manual(&self) -> bool {
        Language::has_manual(self.inner.as_ref())
    }
    fn get_manual_entry(&self, instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
        Language::get_manual_entry(self.inner.as_ref(), instruction_mnemonic)
    }
    fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
        Language::get_manual_instruction_mnemonic_keys(self.inner.as_ref())
    }
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
        Language::get_manual_exception(self.inner.as_ref())
    }
    fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
        Language::get_sorted_vector_registers(self.inner.as_ref())
    }
    fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
        Language::get_register_addresses(self.inner.as_ref())
    }
    fn get_maximum_instruction_length(&self) -> Option<i32> {
        Language::get_maximum_instruction_length(self.inner.as_ref())
    }
}
