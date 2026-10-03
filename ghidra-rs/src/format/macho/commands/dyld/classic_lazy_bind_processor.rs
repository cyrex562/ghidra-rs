//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.ClassicLazyBindProcessor`.
//!
//! Applies "classic" (pre-`LC_DYLD_INFO`) lazy bindings: every `S_LAZY_SYMBOL_POINTERS`
//! section's indirect-symbol slots, plus self-modifying 5-byte `S_SYMBOL_STUBS` (i386 `jmp`
//! stubs).

use crate::format::macho::commands::dyld::abstract_classic_processor::{
    AbstractClassicProcessor, ClassicProcessorError,
};
use crate::format::macho::commands::dynamic_symbol_table_command::DynamicSymbolTableCommand;
use crate::format::macho::commands::dynamic_symbol_table_constants::INDIRECT_SYMBOL_ABS;
use crate::format::macho::commands::n_list_constants::DESC_N_WEAK_REF;
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::section_attributes::S_ATTR_SELF_MODIFYING_CODE;
use crate::format::macho::section_types::{SECTION_TYPE_MASK, S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS};
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.ClassicLazyBindProcessor`.
pub struct ClassicLazyBindProcessor<'a> {
    base: AbstractClassicProcessor<'a>,
}

impl<'a> ClassicLazyBindProcessor<'a> {
    /// Java `ClassicLazyBindProcessor(MachHeader, Program)`.
    pub fn new(header: &'a MachHeader, program: &'a dyn Program) -> Self {
        ClassicLazyBindProcessor { base: AbstractClassicProcessor::new(header, program) }
    }

    /// The inherited `AbstractClassicProcessor` state and helpers.
    pub fn base(&self) -> &AbstractClassicProcessor<'a> {
        &self.base
    }

    /// Java `process(TaskMonitor)`.
    ///
    /// Where Java would throw a `NullPointerException` (no `LC_SYMTAB`, or an indirect symbol
    /// index with no `nlist`), this port reports an error for the former and skips the slot for
    /// the latter, as `ClassicBindProcessor` does.
    pub fn process(&self, monitor: &dyn TaskMonitor) -> Result<(), ClassicProcessorError> {
        let header = self.base.header;
        let program = self.base.program;
        let commands = header.get_load_commands_of::<DynamicSymbolTableCommand>();
        if commands.is_empty() {
            return Ok(());
        }
        let symbol_table_command = header
            .get_first_load_command::<SymbolTableCommand>()
            .ok_or("classic lazy bind: header has no LC_SYMTAB")?;
        let pointer_size = program.get_default_pointer_size() as i64;

        for command in commands {
            if monitor.is_cancelled() {
                break;
            }
            for section in header.get_all_sections() {
                if monitor.is_cancelled() {
                    return Ok(());
                }
                if section.get_size() == 0 {
                    continue;
                }
                let flags = section.get_flags() as u32;
                let section_type = flags & SECTION_TYPE_MASK;
                let (count, stride, skip_abs) = if section_type == S_LAZY_SYMBOL_POINTERS {
                    (section.get_size() / pointer_size, pointer_size, false)
                } else if section_type == S_SYMBOL_STUBS
                    && (flags & S_ATTR_SELF_MODIFYING_CODE) != 0
                    && section.get_reserved2() == 5
                {
                    (section.get_size() / 5, 5, true)
                } else {
                    continue;
                };
                let indirect_offset = section.get_reserved1() as i64;
                for i in 0..count {
                    let symbol_index = *command
                        .get_indirect_symbols()
                        .get((indirect_offset + i) as usize)
                        .ok_or("classic lazy bind: indirect symbol index out of range")?;
                    if skip_abs && symbol_index as u32 == INDIRECT_SYMBOL_ABS {
                        continue;
                    }
                    let Some(n_list) = symbol_table_command.get_symbol_at(symbol_index) else {
                        continue;
                    };
                    let is_weak = (n_list.get_description() as u16 & DESC_N_WEAK_REF) != 0;
                    let from_dylib =
                        self.base.get_classic_ordinal_name(n_list.get_library_ordinal());
                    let address = section.get_address() + i * stride;
                    self.base.perform(
                        section.get_segment_name(),
                        section.get_section_name(),
                        address,
                        &from_dylib,
                        n_list,
                        is_weak,
                        monitor,
                    )?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macho::commands::dyld::abstract_classic_processor::test_support::{
        classic_image, MockProgram,
    };
    use crate::program::model::reloc::relocation::RelocationStatus;
    use crate::util::task::DummyMonitor;

    #[test]
    fn binds_lazy_symbol_pointers_only() {
        let header = classic_image();
        let program = MockProgram::new(0x2000, 8, &[("_malloc", 0x5000), ("_free", 0x6000)]);
        ClassicLazyBindProcessor::new(&header, &program).process(&DummyMonitor).unwrap();
        assert_eq!(
            program.relocations(),
            vec![(0x1010, RelocationStatus::Applied, Some("_free".to_string()))]
        );
        assert_eq!(program.read(0x1010, 8), 0x6000i64.to_le_bytes());
        assert_eq!(program.read(0x1000, 0x10), [0u8; 0x10]);
    }
}
