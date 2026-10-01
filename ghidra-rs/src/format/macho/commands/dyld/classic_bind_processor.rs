//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.ClassicBindProcessor`.
//!
//! Applies "classic" (pre-`LC_DYLD_INFO`) non-lazy bindings: external relocations from each
//! `LC_DYSYMTAB`, then every `S_NON_LAZY_SYMBOL_POINTERS` section's indirect-symbol slots.

use crate::format::macho::commands::dyld::abstract_classic_processor::{
    AbstractClassicProcessor, ClassicProcessorError,
};
use crate::format::macho::commands::dynamic_symbol_table_command::DynamicSymbolTableCommand;
use crate::format::macho::commands::dynamic_symbol_table_constants::INDIRECT_SYMBOL_LOCAL;
use crate::format::macho::commands::n_list_constants::DESC_N_WEAK_REF;
use crate::format::macho::commands::symbol_table_command::SymbolTableCommand;
use crate::format::macho::mach_header::MachHeader;
use crate::format::macho::section_types::{SECTION_TYPE_MASK, S_NON_LAZY_SYMBOL_POINTERS};
use crate::program::model::listing::program::Program;
use crate::util::task::TaskMonitor;

/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.ClassicBindProcessor`.
pub struct ClassicBindProcessor<'a> {
    base: AbstractClassicProcessor<'a>,
}

impl<'a> ClassicBindProcessor<'a> {
    /// Java `ClassicBindProcessor(MachHeader, Program)`.
    pub fn new(header: &'a MachHeader, program: &'a dyn Program) -> Self {
        ClassicBindProcessor { base: AbstractClassicProcessor::new(header, program) }
    }

    /// The inherited `AbstractClassicProcessor` state and helpers.
    pub fn base(&self) -> &AbstractClassicProcessor<'a> {
        &self.base
    }

    /// Java `process(TaskMonitor)`.
    ///
    /// Java dereferences the header's `LC_SYMTAB` unconditionally; a header without one is
    /// reported as an error here instead of a `NullPointerException`.
    pub fn process(&self, monitor: &dyn TaskMonitor) -> Result<(), ClassicProcessorError> {
        let header = self.base.header;
        let program = self.base.program;
        let commands = header.get_load_commands_of::<DynamicSymbolTableCommand>();
        if commands.is_empty() {
            return Ok(());
        }
        let symbol_table_command = header
            .get_first_load_command::<SymbolTableCommand>()
            .ok_or("classic bind: header has no LC_SYMTAB")?;
        let pointer_size = program.get_default_pointer_size() as i64;

        for command in commands {
            if monitor.is_cancelled() {
                break;
            }

            for relocation in command.get_external_relocations() {
                if monitor.is_cancelled() {
                    break;
                }
                let base = self
                    .base
                    .get_relocation_base()
                    .ok_or("classic bind: header has no segments")?;
                let address = (relocation.get_address() as i64).wrapping_add(base);
                let symbol_index = relocation.get_value();
                let Some(n_list) = symbol_table_command.get_symbol_at(symbol_index) else {
                    continue;
                };
                let is_weak = (n_list.get_description() as u16 & DESC_N_WEAK_REF) != 0;
                let from_dylib = self.base.get_classic_ordinal_name(n_list.get_library_ordinal());
                let Some(section) = self.base.get_section_name(address) else {
                    // TODO (Java too): couldn't handle relocation.
                    continue;
                };
                // Java has an (empty) `MH_PREBOUND` branch here.
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

            for section in header.get_all_sections() {
                if monitor.is_cancelled() {
                    return Ok(());
                }
                if section.get_size() == 0 {
                    continue;
                }
                let section_type = section.get_flags() as u32 & SECTION_TYPE_MASK;
                if section_type != S_NON_LAZY_SYMBOL_POINTERS {
                    continue;
                }
                let indirect_offset = section.get_reserved1() as i64;
                let count = section.get_size() / pointer_size;
                for i in 0..count {
                    let symbol_index = *command
                        .get_indirect_symbols()
                        .get((indirect_offset + i) as usize)
                        .ok_or("classic bind: indirect symbol index out of range")?;
                    if symbol_index as u32 == INDIRECT_SYMBOL_LOCAL {
                        continue;
                    }
                    let Some(n_list) = symbol_table_command.get_symbol_at(symbol_index) else {
                        continue;
                    };
                    let is_weak = (n_list.get_description() as u16 & DESC_N_WEAK_REF) != 0;
                    let from_dylib =
                        self.base.get_classic_ordinal_name(n_list.get_library_ordinal());
                    let address = section.get_address() + i * pointer_size;
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
    fn binds_external_relocations_then_non_lazy_pointers() {
        let header = classic_image();
        let program = MockProgram::new(0x2000, 8, &[("_malloc", 0x5000), ("_free", 0x6000)]);
        let p = ClassicBindProcessor::new(&header, &program);
        assert_eq!(p.base().get_relocation_base(), Some(0x1000));
        assert_eq!(p.base().get_classic_ordinal_name(1), "dyld info library ordinal out of range1");
        assert_eq!(p.base().get_classic_ordinal_name(0), "this-image");
        assert_eq!(
            p.base().get_section_name(0x1012).map(|s| s.get_section_name().to_string()),
            Some("__la_symbol_ptr".to_string())
        );

        p.process(&DummyMonitor).unwrap();

        assert_eq!(
            program.relocations(),
            vec![
                (0x1008, RelocationStatus::Applied, Some("_free".to_string())),
                (0x1000, RelocationStatus::Applied, Some("_malloc".to_string())),
            ]
        );
        assert_eq!(program.read(0x1000, 8), 0x5000i64.to_le_bytes());
        assert_eq!(program.read(0x1008, 8), 0x6000i64.to_le_bytes());
        // The lazy pointer is not touched by the non-lazy processor.
        assert_eq!(program.read(0x1010, 8), [0u8; 8]);
    }
}
