//! Port of `ghidra.app.util.bin.format.MemoryLoadable`.
//!
//! A marker trait that identifies a memory-loadable portion of a binary file (supports use as a
//! HashMap/dictionary key). It also supplies the necessary input stream to create a MemoryBlock.
//!
//! # Implementation
//!
//! This trait is implemented by memory-loadable section and program headers. The methods allow
//! the ELF loader to determine whether filtered/decompressed input streams are needed and to
//! obtain the raw binary data for loading.

use std::io::{self, Read};
use std::sync::Arc;

use crate::format::elf::elf_load_helper::ElfLoadHelper;
use crate::program::model::address::Address;
use crate::program::model::address::AddressSpaceType;

/// Identifies a memory-loadable portion of a binary file and supplies an input stream.
///
/// `ghidra.app.util.bin.format.MemoryLoadable`.
pub trait MemoryLoadable: Send + Sync {
    /// Determine if the use of input stream decompression or filtering via an extension is necessary.
    ///
    /// If this method returns true, a [`get_filtered_load_input_stream`](Self::get_filtered_load_input_stream)
    /// is required and will prevent the use of a direct mapping to file bytes for affected memory regions.
    ///
    /// Java: `MemoryLoadable.hasFilteredLoadInputStream(ElfLoadHelper, Address)`.
    fn has_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
    ) -> bool;

    /// Return filtered InputStream for loading a memory block (includes non-loaded OTHER blocks).
    ///
    /// See [`has_filtered_load_input_stream`](Self::has_filtered_load_input_stream).
    ///
    /// The `error_consumer` callback, if provided, will be called with error messages and exceptions
    /// that occur during stream decompression. If `None`, errors are logged via the standard mechanism.
    ///
    /// Java: `MemoryLoadable.getFilteredLoadInputStream(ElfLoadHelper, Address, long, BiConsumer)`.
    fn get_filtered_load_input_stream(
        &self,
        elf_load_helper: &dyn ElfLoadHelper,
        start: Address,
        data_length: i64,
        error_consumer: Option<&(dyn Fn(&str, &dyn std::error::Error) + Send)>,
    ) -> io::Result<Box<dyn Read + Send>>;

    /// Raw data input stream associated with this loadable object.
    ///
    /// Java: `MemoryLoadable.getRawInputStream()`.
    fn get_raw_input_stream(&self) -> io::Result<Box<dyn Read + Send>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of MemoryLoadable for testing.
    struct MockLoadable {
        data: Vec<u8>,
    }

    impl MockLoadable {
        fn new(data: Vec<u8>) -> Self {
            MockLoadable { data }
        }
    }

    impl MemoryLoadable for MockLoadable {
        fn has_filtered_load_input_stream(
            &self,
            _elf_load_helper: &dyn ElfLoadHelper,
            _start: Address,
        ) -> bool {
            false
        }

        fn get_filtered_load_input_stream(
            &self,
            _elf_load_helper: &dyn ElfLoadHelper,
            _start: Address,
            _data_length: i64,
            _error_consumer: Option<&(dyn Fn(&str, &dyn std::error::Error) + Send)>,
        ) -> io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(std::io::Cursor::new(self.data.clone())))
        }

        fn get_raw_input_stream(&self) -> io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(std::io::Cursor::new(self.data.clone())))
        }
    }

    #[test]
    fn test_memory_loadable_raw_input_stream() {
        let test_data = vec![1, 2, 3, 4, 5];
        let loadable = MockLoadable::new(test_data.clone());

        let mut stream = loadable.get_raw_input_stream().expect("Should create stream");
        let mut buffer = Vec::new();
        stream.read_to_end(&mut buffer).expect("Should read stream");

        assert_eq!(buffer, test_data);
    }

    #[test]
    fn test_memory_loadable_filtered_input_stream() {
        let test_data = vec![0x01, 0x02, 0x03];
        let loadable = MockLoadable::new(test_data.clone());

        let stream = loadable.get_filtered_load_input_stream(
            &MockElfLoadHelper,
            make_test_address(),
            test_data.len() as i64,
            None,
        ).expect("Should create filtered stream");

        let bytes: Vec<u8> = stream.bytes().map(|b| b.unwrap()).collect();
        assert_eq!(bytes, test_data);
    }

    #[test]
    fn test_memory_loadable_has_filtered_returns_false() {
        let loadable = MockLoadable::new(vec![]);
        let has_filtered = loadable.has_filtered_load_input_stream(
            &MockElfLoadHelper,
            make_test_address(),
        );
        assert!(!has_filtered);
    }

    fn make_test_address() -> Address {
        Address::new(
            crate::program::model::address::AddressSpace::new(
                "ram",
                32,
                1,
                AddressSpaceType::Ram,
                0,
            ),
            0,
        )
    }

    /// Mock implementation of ElfLoadHelper for testing.
    struct MockElfLoadHelper;

    impl ElfLoadHelper for MockElfLoadHelper {
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("Mock ElfLoadHelper")
        }

        fn get_option_bool(&self, _option_name: &str, default_value: bool) -> bool {
            default_value
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

        fn get_elf_header(&self) -> Arc<dyn crate::format::seam_stubs::ElfHeader> {
            unimplemented!("Mock ElfLoadHelper")
        }

        fn get_log(&self) -> Arc<dyn crate::format::seam_stubs::MessageLog> {
            unimplemented!("Mock ElfLoadHelper")
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
            unimplemented!("Mock ElfLoadHelper")
        }

        fn create_external_function_linkage(
            &self,
            _name: &str,
            _function_addr: Address,
            _indirect_pointer_addr: Option<Address>,
        ) -> Option<Arc<dyn crate::program::model::listing::function::Function>> {
            None
        }

        fn create_undefined_data(
            &self,
            _address: Address,
            _length: i32,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn create_data(
            &self,
            _address: Address,
            _dt: Box<dyn crate::program::model::data::data_type::DataType>,
        ) -> Option<Arc<dyn crate::program::model::listing::data::Data>> {
            None
        }

        fn set_elf_symbol_address(
            &self,
            _elf_symbol: &crate::format::elf::elf_symbol::ElfSymbol,
            _address: Option<Address>,
        ) {
        }

        fn get_elf_symbol_address(
            &self,
            _elf_symbol: &crate::format::elf::elf_symbol::ElfSymbol,
        ) -> Option<Address> {
            None
        }

        fn create_symbol(
            &self,
            _addr: Address,
            _name: &str,
            _is_primary: bool,
            _pin_absolute: bool,
            _namespace: Option<Arc<dyn crate::program::model::symbol::namespace::Namespace>>,
        ) -> Result<Arc<dyn crate::program::model::symbol::Symbol>, crate::util::exception::InvalidInputException>
        {
            Err(crate::util::exception::InvalidInputException::default())
        }

        fn find_load_address(
            &self,
            _section: &dyn MemoryLoadable,
            _byte_offset_within_section: i64,
        ) -> Option<Address> {
            None
        }

        fn get_default_address(
            &self,
            _addressable_word_offset: i64,
        ) -> Address {
            make_test_address()
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
        ) -> Result<i64, crate::program::model::mem::memory_access_exception::MemoryAccessException>
        {
            Err(crate::program::model::mem::memory_access_exception::MemoryAccessException::default())
        }

        fn add_artificial_reloc_table_entry(&self, _address: Address, _length: i32) -> bool {
            false
        }
    }
}
