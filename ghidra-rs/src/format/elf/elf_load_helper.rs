//! Port of `ghidra.app.util.bin.format.elf.ElfLoadHelper`.
//!
//! Loader methods useful to `ElfExtension` implementations while an ELF image is being turned
//! into a `Program`. Java's version is an `interface`; its only implementor,
//! `ElfProgramBuilder`, is not yet ported, so this stays a trait with no implementation of its
//! own (mirroring [`ElfLoadAdapter`](crate::format::elf::extend::elf_load_adapter::ElfLoadAdapter)
//! and [`ElfRelocationContext`](crate::format::elf::relocation::elf_relocation_context::ElfRelocationContext),
//! which already hold `dyn ElfLoadHelper`/`Arc<dyn ElfLoadHelper>` against this same seam).
//!
//! # Departures from the Java interface
//!
//! * `<T> T getOption(String, T)` is generic, which is not object-safe and this trait is used
//!   exclusively through `&dyn ElfLoadHelper`/`Arc<dyn ElfLoadHelper>`. It becomes three
//!   type-specialized methods -- [`get_option_bool`](ElfLoadHelper::get_option_bool),
//!   [`get_option_string`](ElfLoadHelper::get_option_string),
//!   [`get_option_i32`](ElfLoadHelper::get_option_i32) -- matching the same split already made
//!   for `OptionUtils.getOption` (see `crate::app::seam_stubs::option_utils`), the only other
//!   generic `getOption` in this crate's ELF loading path.
//! * Every `Address` parameter is taken by value: Java references are shared handles, and
//!   `Address` here is a cheaply-cloned value type (matches the convention already used by e.g.
//!   `FunctionManager::create_function`'s `entry_point: Address`).

use std::sync::Arc;

use crate::format::elf::elf_symbol::ElfSymbol;
use crate::format::memory_loadable::MemoryLoadable;
use crate::format::seam_stubs::{ElfHeader, MessageLog};
use crate::program::model::address::range::AddressRange;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::function::Function;
use crate::program::model::listing::program::Program;
use crate::program::model::mem::memory_access_exception::MemoryAccessException;
use crate::program::model::symbol::namespace::Namespace;
use crate::program::model::symbol::Symbol;
use crate::util::exception::InvalidInputException;

/// `ghidra.app.util.bin.format.elf.ElfLoadHelper`.
pub trait ElfLoadHelper: Send + Sync {
    /// `ElfLoadHelper.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// `ElfLoadHelper.getOption(String, T)` specialized to `T = Boolean`. See the module docs for
    /// why the generic method was split.
    fn get_option_bool(&self, option_name: &str, default_value: bool) -> bool;

    /// `ElfLoadHelper.getOption(String, T)` specialized to `T = String` (nullable, matching
    /// Java's `(String) null` default).
    fn get_option_string(
        &self,
        option_name: &str,
        default_value: Option<String>,
    ) -> Option<String>;

    /// `ElfLoadHelper.getOption(String, T)` specialized to `T = Integer`.
    fn get_option_i32(&self, option_name: &str, default_value: i32) -> i32;

    /// `ElfLoadHelper.getElfHeader()`.
    fn get_elf_header(&self) -> Arc<dyn ElfHeader>;

    /// `ElfLoadHelper.getLog()`.
    fn get_log(&self) -> Arc<dyn MessageLog>;

    /// `ElfLoadHelper.log(String)`.
    fn log(&self, msg: &str);

    /// `ElfLoadHelper.log(Throwable)`.
    fn log_exception(&self, t: &dyn std::error::Error);

    /// `ElfLoadHelper.markAsCode(Address)`. Marks this location as code in the CodeMap; analyzers
    /// pick it up later and disassemble it.
    fn mark_as_code(&self, address: Address);

    /// `ElfLoadHelper.createOneByteFunction(String, Address, boolean)`. `name` of `None` mirrors
    /// Java's `null` ("default, or label already applied").
    fn create_one_byte_function(
        &self,
        name: Option<&str>,
        address: Address,
        is_entry: bool,
    ) -> Arc<dyn Function>;

    /// `ElfLoadHelper.createExternalFunctionLinkage(String, Address, Address)`. Returns `None` if
    /// creation failed; `indirect_pointer_addr` of `None` mirrors Java's nullable parameter (no
    /// indirect pointer is written).
    fn create_external_function_linkage(
        &self,
        name: &str,
        function_addr: Address,
        indirect_pointer_addr: Option<Address>,
    ) -> Option<Arc<dyn Function>>;

    /// `ElfLoadHelper.createUndefinedData(Address, int)`. Returns `None` if a conflict occurs or
    /// the operation is disabled by option (see `ElfLoaderOptionsFactory::apply_undefined_symbol_data`).
    fn create_undefined_data(&self, address: Address, length: i32) -> Option<Arc<dyn Data>>;

    /// `ElfLoadHelper.createData(Address, DataType)`. Returns `None` if a conflict occurs.
    fn create_data(&self, address: Address, dt: Box<dyn DataType>) -> Option<Arc<dyn Data>>;

    /// `ElfLoadHelper.setElfSymbolAddress(ElfSymbol, Address)`. Adds `elf_symbol` to the loader
    /// symbol map after its program address has been assigned; `address` of `None` mirrors Java's
    /// nullable parameter (not applicable).
    fn set_elf_symbol_address(&self, elf_symbol: &ElfSymbol, address: Option<Address>);

    /// `ElfLoadHelper.getElfSymbolAddress(ElfSymbol)`. Returns `None` if unknown.
    fn get_elf_symbol_address(&self, elf_symbol: &ElfSymbol) -> Option<Address>;

    /// `ElfLoadHelper.createSymbol(Address, String, boolean, boolean, Namespace)`. `namespace` of
    /// `None` mirrors Java's nullable parameter (global namespace).
    fn create_symbol(
        &self,
        addr: Address,
        name: &str,
        is_primary: bool,
        pin_absolute: bool,
        namespace: Option<Arc<dyn Namespace>>,
    ) -> Result<Arc<dyn Symbol>, InvalidInputException>;

    /// `ElfLoadHelper.findLoadAddress(MemoryLoadable, long)`. Returns `None` if not loaded.
    fn find_load_address(
        &self,
        section: &dyn MemoryLoadable,
        byte_offset_within_section: i64,
    ) -> Option<Address>;

    /// `ElfLoadHelper.getDefaultAddress(long)`.
    fn get_default_address(&self, addressable_word_offset: i64) -> Address;

    /// `ElfLoadHelper.getImageBaseWordAdjustmentOffset()`.
    fn get_image_base_word_adjustment_offset(&self) -> i64;

    /// `ElfLoadHelper.getGOTValue()`, whose Java return type is the nullable `Long`.
    fn get_got_value(&self) -> Option<i64>;

    /// `ElfLoadHelper.allocateLinkageBlock(int, int, String)`. Returns `None` if no unallocated
    /// range was found.
    fn allocate_linkage_block(&self, alignment: i32, size: i32, purpose: &str) -> Option<AddressRange>;

    /// `ElfLoadHelper.getOriginalValue(Address, boolean)`.
    fn get_original_value(
        &self,
        addr: Address,
        sign_extend: bool,
    ) -> Result<i64, MemoryAccessException>;

    /// `ElfLoadHelper.addArtificialRelocTableEntry(Address, int)`. Returns `false` on conflict
    /// with an existing relocation entry or a memory addressing error.
    fn add_artificial_reloc_table_entry(&self, address: Address, length: i32) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{new_boolean, option_utils, Option};
    use std::sync::Mutex;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.elf".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockElfHeader;
    impl ElfHeader for MockElfHeader {
        fn is32_bit(&self) -> bool {
            true
        }
        fn is_relocatable(&self) -> bool {
            false
        }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::ElfSectionHeader>> {
            Vec::new()
        }
    }

    struct MockMessageLog {
        messages: Mutex<Vec<String>>,
    }
    impl MessageLog for MockMessageLog {
        fn copy_from(&self, _log: &dyn MessageLog) {}
        fn append_msg(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
        fn append_exception(&self, _t: &dyn crate::format::seam_stubs::Throwable) {}
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

    /// Routes `get_option_*` through `option_utils`, the same `OptionUtils.getOption` port
    /// `ElfProgramBuilder.getOption` itself delegates to in Java (`OptionUtils.getOption(optionName,
    /// options, defaultValue)`).
    struct MockLoadHelper {
        options: Vec<Box<dyn Option>>,
        log: Arc<MockMessageLog>,
    }

    impl ElfLoadHelper for MockLoadHelper {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_option_bool(&self, option_name: &str, default_value: bool) -> bool {
            option_utils::get_bool_option(option_name, &self.options, default_value)
        }
        fn get_option_string(
            &self,
            option_name: &str,
            default_value: std::option::Option<String>,
        ) -> std::option::Option<String> {
            option_utils::get_string_option(option_name, &self.options, default_value)
        }
        fn get_option_i32(&self, option_name: &str, default_value: i32) -> i32 {
            option_utils::get_int_option(option_name, &self.options, default_value)
        }
        fn get_elf_header(&self) -> Arc<dyn ElfHeader> {
            Arc::new(MockElfHeader)
        }
        fn get_log(&self) -> Arc<dyn MessageLog> {
            self.log.clone()
        }
        fn log(&self, msg: &str) {
            self.log.append_msg(msg);
        }
        fn log_exception(&self, _t: &dyn std::error::Error) {}
        fn mark_as_code(&self, _address: Address) {}
        fn create_one_byte_function(
            &self,
            _name: std::option::Option<&str>,
            _address: Address,
            _is_entry: bool,
        ) -> Arc<dyn Function> {
            unimplemented!("not exercised by these tests")
        }
        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: std::option::Option<Address>,
        ) -> std::option::Option<Arc<dyn Function>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> std::option::Option<Arc<dyn Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn DataType>,
        ) -> std::option::Option<Arc<dyn Data>> {
            unimplemented!("not exercised by these tests")
        }
        fn set_elf_symbol_address(
            &self,
            _elf_symbol: &ElfSymbol,
            _address: std::option::Option<Address>,
        ) {
        }
        fn get_elf_symbol_address(&self, _elf_symbol: &ElfSymbol) -> std::option::Option<Address> {
            None
        }
        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: std::option::Option<Arc<dyn Namespace>>,
        ) -> Result<Arc<dyn Symbol>, InvalidInputException> {
            unimplemented!("not exercised by these tests")
        }
        fn find_load_address(
            &self,
            _section: &dyn MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> std::option::Option<Address> {
            None
        }
        fn get_default_address(&self, _addressable_word_offset: i64) -> Address {
            unimplemented!("not exercised by these tests")
        }
        fn get_image_base_word_adjustment_offset(&self) -> i64 {
            0
        }
        fn get_got_value(&self) -> std::option::Option<i64> {
            None
        }
        fn allocate_linkage_block(
            &self,
            _alignment: i32,
            _size: i32,
            _purpose: &str,
        ) -> std::option::Option<AddressRange> {
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

    /// Mirrors `OptionUtils.getOption(String, List<Option>, T)`'s two documented outcomes: the
    /// caller-supplied default when the named option is absent, and the stored value when
    /// present. This is `ElfProgramBuilder.getOption`'s entire (delegated) behavior in Java.
    #[test]
    fn get_option_bool_falls_back_to_default_then_reads_stored_value() {
        let helper = MockLoadHelper { options: Vec::new(), log: Arc::new(MockMessageLog { messages: Mutex::new(Vec::new()) }) };
        assert_eq!(helper.get_option_bool("Perform Symbol Relocations", true), true);

        let mut options: Vec<Box<dyn Option>> = Vec::new();
        options.push(new_boolean("Perform Symbol Relocations").value(Box::new(false)).build());
        let helper = MockLoadHelper { options, log: Arc::new(MockMessageLog { messages: Mutex::new(Vec::new()) }) };
        assert_eq!(helper.get_option_bool("Perform Symbol Relocations", true), false);
    }

    #[test]
    fn log_forwards_to_message_log() {
        let helper = MockLoadHelper {
            options: Vec::new(),
            log: Arc::new(MockMessageLog { messages: Mutex::new(Vec::new()) }),
        };
        helper.log("hello");
        assert!(helper.get_log().has_messages());
    }
}
