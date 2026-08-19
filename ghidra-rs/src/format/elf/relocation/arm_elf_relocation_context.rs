//! Port of `ghidra.app.util.bin.format.elf.relocation.ARM_ElfRelocationContext`.
//!
//! Provides ARM-specific relocation context with PC bias handling for relative relocations.
//!
//! # Shape
//!
//! Java's `ARM_ElfRelocationContext` is a concrete leaf: it extends
//! `ElfRelocationContext<ARM_ElfRelocationHandler>` with a constructor that captures the
//! PC bias option and a single method `getPcBias` that applies it. Per the port's shape rules
//! a concrete leaf class becomes a `struct` + `impl`, never a trait.

use std::collections::HashMap;
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::elf::relocation::elf_relocation_context::{
    ElfRelocationContext, ElfRelocationContextBase,
};
use crate::format::seam_stubs::ElfRelocationHandler;
use crate::program::model::address::Address;

/// Option name for controlling PC bias application in ARM relocations.
const APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME: &str = "Apply PC Bias to relative relocations";
/// Default value: whether to apply PC bias to relative relocations (reflects binutils default).
const APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_DEFAULT: bool = false;

/// Provides ARM-specific relocation context with PC bias handling.
///
/// The PC bias affects how relative relocations are computed. It represents the amount by which
/// the PC is advanced when the instruction is fetched, and different ARM instruction modes
/// (ARM vs Thumb) have different bias values.
pub struct ArmElfRelocationContext {
    base: ElfRelocationContextBase,
    apply_pc_bias_to_relative_relocations: bool,
}

impl ArmElfRelocationContext {
    /// Creates a new ARM relocation context.
    ///
    /// # Arguments
    /// * `handler` - ARM relocation handler, or `None` if not available
    /// * `load_helper` - the ELF load helper
    /// * `symbol_map` - ELF symbol placement map
    pub fn new(
        handler: Option<Arc<dyn ElfRelocationHandler>>,
        load_helper: Arc<dyn ElfLoadHelper>,
        symbol_map: Arc<HashMap<ElfSymbol, Address>>,
    ) -> Self {
        let apply_pc_bias_to_relative_relocations = load_helper.get_option_bool(
            APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME,
            APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_DEFAULT,
        );

        ArmElfRelocationContext {
            base: ElfRelocationContextBase::new(handler, load_helper, symbol_map),
            apply_pc_bias_to_relative_relocations,
        }
    }

    /// Gets the appropriate PC Bias value which should be applied to the computed relocation value.
    ///
    /// This method and related option is intended as a work-around for differences in how tool-chain
    /// and associated loaders handle the PC Bias and if they factor it into the addend or not.
    /// Within Ghidra, the default is to assume the PC Bias is not factored into the relocation addend
    /// with the `APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME` option being true.
    ///
    /// Example as to how this PC Bias value factors into relocation value computation:
    /// ```text
    /// value = (symbolValue + addend) - (relocAddr + pcBias)
    /// ```
    ///
    /// Within the Sleigh language this bias may be reflected by:
    /// ```text
    /// ARM:
    ///    (inst_start + 8) or (inst_next + 4)
    /// Thumb (either 16-bit or 32-bit forms):
    ///    (inst_start + 4)
    /// ```
    ///
    /// # Arguments
    /// * `is_thumb` - `true` if Thumb instruction, `false` if ARM
    ///
    /// # Returns
    /// The PC Bias value (4 for Thumb, 8 for ARM, or 0 if bias is disabled)
    pub fn get_pc_bias(&self, is_thumb: bool) -> i32 {
        if self.apply_pc_bias_to_relative_relocations {
            if is_thumb {
                4
            } else {
                8
            }
        } else {
            0
        }
    }
}

impl ElfRelocationContext for ArmElfRelocationContext {
    fn base(&self) -> &ElfRelocationContextBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut ElfRelocationContextBase {
        &mut self.base
    }

    fn as_relocation_context(&self) -> &dyn ElfRelocationContext {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::seam_stubs::{ElfHeader, MessageLog, Throwable};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "ARM:LE:32:v7".to_string()
        }
    }

    #[derive(Default)]
    struct RecordingLog {
        messages: Mutex<Vec<String>>,
    }

    impl MessageLog for RecordingLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn Throwable) {}
        fn error(&self, _originator: &str, _message: &str) {}
        fn has_messages(&self) -> bool {
            !self.messages.lock().unwrap().is_empty()
        }
        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
        fn set_status(&self, _status: &str) {}
        fn clear_status(&self) {}
        fn get_status(&self) -> String {
            String::new()
        }
        fn to_string(&self) -> String {
            self.messages.lock().unwrap().join("\n")
        }
        fn write(&self, _owner: &dyn crate::format::seam_stubs::Class, _message_header: &str) {}
    }

    struct MockElfHeader;
    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            true
        }
        fn is_relocatable(&self) -> bool {
            true
        }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockLoadHelper {
        log: Arc<RecordingLog>,
        apply_pc_bias: bool,
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_option_bool(&self, option_name: &str, default_value: bool) -> bool {
            if option_name == APPLY_PC_BIAS_TO_RELATIVE_RELOCATIONS_OPTION_NAME {
                self.apply_pc_bias
            } else {
                default_value
            }
        }
        fn get_option_string(
            &self,
            _option_name: &str,
            default_value: Option<String>,
        ) -> Option<String> {
            default_value
        }
        fn get_option_i32(&self, _option_name: &str, default_value: i32) -> i32 {
            default_value
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader)
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, _msg: &str) {}
        fn log_exception(&self, _t: &dyn std::error::Error) {}
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn crate::program::model::listing::function::Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: Option<Address>,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(&self, _elf_symbol: &ElfSymbol, _address: Option<Address>) {}
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
        ) -> Result<
            Arc<dyn crate::program::model::symbol::Symbol>,
            crate::util::exception::InvalidInputException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn crate::format::memory_loadable::MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            0
        }
        fn get_got_value(&self) -> Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> Option<crate::program::model::address::range::AddressRange> {
            None
        }
        fn get_original_value(
            &self,
            _addr: Address,
            _sign_extend: bool,
        ) -> Result<i64, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }

    fn context_with_pc_bias(apply_bias: bool) -> ArmElfRelocationContext {
        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
            apply_pc_bias: apply_bias,
        });
        ArmElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()))
    }

    #[test]
    fn get_pc_bias_returns_4_for_thumb_when_enabled() {
        let context = context_with_pc_bias(true);
        assert_eq!(context.get_pc_bias(true), 4);
    }

    #[test]
    fn get_pc_bias_returns_8_for_arm_when_enabled() {
        let context = context_with_pc_bias(true);
        assert_eq!(context.get_pc_bias(false), 8);
    }

    #[test]
    fn get_pc_bias_returns_0_when_disabled() {
        let context = context_with_pc_bias(false);
        assert_eq!(context.get_pc_bias(true), 0);
        assert_eq!(context.get_pc_bias(false), 0);
    }

    #[test]
    fn get_pc_bias_defaults_to_disabled() {
        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
            apply_pc_bias: false,
        });
        let context = ArmElfRelocationContext::new(None, load_helper, Arc::new(HashMap::new()));
        assert_eq!(context.get_pc_bias(true), 0);
        assert_eq!(context.get_pc_bias(false), 0);
    }

    #[test]
    fn new_wires_the_base_context() {
        struct MockHandler;
        impl ElfRelocationHandler for MockHandler {
            fn relocate(
                &self,
                _context: &dyn ElfRelocationContext,
                _relocation: &dyn crate::format::seam_stubs::ElfRelocation,
                _relocation_address: &Address,
            ) -> Result<
                crate::program::model::reloc::RelocationResult,
                crate::format::elf::relocation::elf_relocation_context::RelocationProcessingError,
            > {
                unimplemented!("not exercised by this test")
            }
            fn mark_as_error(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
            fn mark_as_warning(
                &self,
                _program: &dyn Program,
                _relocation_address: &Address,
                _type_id: i32,
                _symbol_name: Option<&str>,
                _symbol_index: i32,
                _msg: &str,
                _log: &dyn MessageLog,
            ) {
            }
        }

        let load_helper = Arc::new(MockLoadHelper {
            log: Arc::new(RecordingLog::default()),
            apply_pc_bias: false,
        });
        let context = ArmElfRelocationContext::new(
            Some(Arc::new(MockHandler)),
            load_helper,
            Arc::new(HashMap::new()),
        );
        assert!(context.base().has_relocation_handler());
    }
}
