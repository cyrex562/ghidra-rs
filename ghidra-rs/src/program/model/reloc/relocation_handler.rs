use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::{MemoryAccessException, MemoryBlock};
use crate::program::model::reloc::Relocation;
use crate::util::task::TaskMonitor;

/// Handles relocations for a particular relocation handler.
///
/// This trait mirrors `ghidra.program.model.reloc.RelocationHandler`.
///
/// Note: In the original Java, all RelocationHandler classes must end in "RelocationHandler"
/// for discovery. This constraint is handled by the module system in Rust.
pub trait RelocationHandler: Send + Sync {
    /// Returns true if this relocation handler can relocate the given program.
    ///
    /// For example, an ELF program requires an ELF-specific relocation handler.
    ///
    /// # Arguments
    /// * `program` - the program to relocate
    ///
    /// # Returns
    /// true if this relocation handler can relocate the given program
    fn can_relocate(&self, program: &dyn Program) -> bool;

    /// Relocates the entire program to a new image base.
    ///
    /// # Arguments
    /// * `program` - the program to relocate
    /// * `new_image_base` - the new image base address
    /// * `monitor` - a task monitor for progress reporting
    ///
    /// # Errors
    /// Returns `MemoryAccessException` if memory access fails during relocation
    fn relocate(
        &self,
        program: &mut dyn Program,
        new_image_base: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MemoryAccessException>;

    /// Relocates a memory block to a new start address.
    ///
    /// All relocations in the memory block will be fixed-up.
    ///
    /// # Arguments
    /// * `program` - the program to relocate
    /// * `block` - the memory block to relocate
    /// * `new_start_address` - the new start address for the block
    /// * `monitor` - a task monitor for progress reporting
    ///
    /// # Errors
    /// Returns `MemoryAccessException` if memory access fails during relocation
    fn relocate_block(
        &self,
        program: &mut dyn Program,
        block: &mut dyn MemoryBlock,
        new_start_address: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MemoryAccessException>;

    /// Performs relocation for a single relocation entry.
    ///
    /// # Arguments
    /// * `program` - the program to relocate
    /// * `relocation` - the relocation to perform
    /// * `monitor` - a task monitor for progress reporting
    ///
    /// # Errors
    /// Returns `MemoryAccessException` if memory access fails during relocation
    fn perform_relocation(
        &self,
        program: &mut dyn Program,
        relocation: &Relocation,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MemoryAccessException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRelocationHandler;

    impl RelocationHandler for MockRelocationHandler {
        fn can_relocate(&self, _program: &dyn Program) -> bool {
            true
        }

        fn relocate(
            &self,
            _program: &mut dyn Program,
            _new_image_base: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn relocate_block(
            &self,
            _program: &mut dyn Program,
            _block: &mut dyn MemoryBlock,
            _new_start_address: &Address,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }

        fn perform_relocation(
            &self,
            _program: &mut dyn Program,
            _relocation: &Relocation,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    #[test]
    fn mock_handler_implements_trait() {
        let handler = MockRelocationHandler;
        assert!(handler.can_relocate(&mut (&MockProgram as &dyn Program)));
    }

    struct MockProgram;

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock".to_string()
        }
    }
}
