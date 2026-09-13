//! Port of `ghidra.app.util.bin.format.elf.info.ElfComment`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::elf::info::elf_info_item::{read_item_from_section, ElfInfoItem, ItemWithAddress};
use crate::framework::options::Options;
use crate::program::model::address::Address;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::{ClearDataMode, DataUtilities};
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::listing::{Program, PROGRAM_INFO};
use crate::program::model::symbol::SourceType;
use crate::util::msg::Msg;

/// An Elf section that contains null-terminated strings, typically added by the compiler to the
/// binary.
///
/// Mirrors `ghidra.app.util.bin.format.elf.info.ElfComment`.
pub struct ElfComment {
    comment_strings: Vec<String>,
    /// Retains the original (byte, including the null terminator) string lengths so memory can
    /// be correctly marked up.
    comment_string_lengths: Vec<i32>,
}

impl ElfComment {
    /// Mirrors `ElfComment.SECTION_NAME` (`.comment`).
    pub const SECTION_NAME: &'static str = ".comment";

    pub fn new(comment_strings: Vec<String>, comment_string_lengths: Vec<i32>) -> Self {
        ElfComment { comment_strings, comment_string_lengths }
    }

    /// Reads an `ElfComment` from the standard `.comment` section in the specified program.
    ///
    /// Returns `None` if not found or on a data error.
    ///
    /// Mirrors `ElfComment.fromProgram(Program)`.
    pub fn from_program(program: &dyn Program) -> Option<ElfComment> {
        let wrapped: Option<ItemWithAddress<ElfComment>> =
            read_item_from_section(program, Self::SECTION_NAME, ElfComment::read);
        wrapped.map(|item| item.item)
    }

    /// Reads an `ElfComment` from the specified reader.
    ///
    /// `program` is unused, present to match the signature expected by
    /// [`read_item_from_section`].
    ///
    /// Mirrors `ElfComment.read(BinaryReader, Program)`.
    pub fn read(br: &mut dyn BinaryReader, _program: &dyn Program) -> io::Result<ElfComment> {
        let mut comment_strings = Vec::new();
        let mut comment_string_lengths = Vec::new();
        while br.has_next() {
            let start = br.get_pointer_index();
            let s = br.read_next_utf8_string()?;
            comment_strings.push(s);
            comment_string_lengths.push((br.get_pointer_index() - start) as i32);
        }
        Ok(ElfComment { comment_strings, comment_string_lengths })
    }

    /// Mirrors `ElfComment.getCommentStrings()`.
    pub fn get_comment_strings(&self) -> &[String] {
        &self.comment_strings
    }
}

impl ElfInfoItem for ElfComment {
    /// Mirrors `ElfComment.markupProgram(Program, Address)`. Records each comment string as a
    /// `Program Information` option, labels its address, and marks up its bytes as a fixed-length
    /// UTF-8 string.
    ///
    /// Like the Java method, any single comment's failure (label creation, or data markup)
    /// aborts markup of every *remaining* comment -- the Java `try` wraps the entire loop, so an
    /// exception on comment *N* skips comments *N+1..* entirely, while comments `0..N` (and the
    /// successfully-applied parts of comment *N* itself, such as its option) are left in place.
    /// This port preserves that quirk rather than continuing best-effort past a failure.
    fn markup_program(&self, program: &mut dyn Program, address: &Address) {
        let mut current_address = address.clone();

        for (comment_num, comment_str) in self.comment_strings.iter().enumerate() {
            let str_len = self.comment_string_lengths[comment_num];

            let result: Result<(), Box<dyn std::error::Error>> = (|| {
                let mut options = program.get_options(PROGRAM_INFO);
                options.set_string(&format!("Elf Comment[{comment_num}]"), comment_str);

                {
                    let Some(symbol_table) = program.get_symbol_table() else {
                        // No symbol table available on this Program implementation; Java's
                        // `program.getSymbolTable()` never returns null, so this has no direct
                        // Java analog -- treat it like any other markup failure.
                        return Err(Box::<dyn std::error::Error>::from(
                            "no symbol table available",
                        ));
                    };
                    symbol_table.create_label(
                        &current_address,
                        &format!("ElfComment[{comment_num}]"),
                        SourceType::Imported,
                    )?;
                }

                let utils = Utils;
                utils.create_data(
                    program,
                    &current_address,
                    Box::new(FallbackStringUtf8DataType),
                    str_len,
                    ClearDataMode::ClearAllUndefinedConflictData,
                )?;

                Ok(())
            })();

            match result {
                Ok(()) => {
                    // need to allow wrap so we don't error when hitting end-of-section
                    current_address = current_address.add_wrap(str_len as i64);
                }
                Err(_e) => {
                    Msg::error(
                        "ElfComment",
                        &format!("Failed to markup ElfComment at {current_address}: {self}"),
                    );
                    return;
                }
            }
        }
    }
}

impl std::fmt::Display for ElfComment {
    /// Mirrors `ElfComment.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ElfComment [commentStrings=[{}]]", self.comment_strings.join(", "))
    }
}

/// Fallback [`DataType`], standing in for `StringUTF8DataType.dataType`. See the module docs for
/// why the real `StringUTF8DataType` (currently only a trait with no concrete implementer in this
/// crate) cannot be constructed generically yet. Mirrors the "fixed-length UTF-8 string" shape
/// closely enough for [`DataUtilities::create_data`] to accept `str_len` as this data's length
/// (via [`Dynamic::can_specify_length`]). Not a port of any specific Java class.
struct FallbackStringUtf8DataType;

impl DataType for FallbackStringUtf8DataType {
    fn get_name(&self) -> String {
        "string-utf8".to_string()
    }

    fn get_length(&self) -> i32 {
        -1
    }

    fn as_dynamic(&self) -> Option<&dyn Dynamic> {
        Some(self)
    }
}

impl BuiltInDataType for FallbackStringUtf8DataType {
    fn get_c_type_declaration(
        &self,
        _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
    ) -> Option<String> {
        None
    }

    fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
}

impl Dynamic for FallbackStringUtf8DataType {
    fn get_dynamic_length(&self, _buf: &dyn crate::program::model::mem::MemBuffer, max_length: i32) -> i32 {
        max_length
    }

    fn can_specify_length(&self) -> bool {
        true
    }

    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        struct ReplacementBaseType;
        impl DataType for ReplacementBaseType {
            fn get_length(&self) -> i32 {
                -1
            }
        }
        Box::new(ReplacementBaseType)
    }
}

/// Smoke-test-only marker struct making [`DataUtilities`] (an all-default-methods trait)
/// implementable without any state, mirroring the same pattern used throughout this crate's
/// `DataUtilities` call sites (e.g. `data_type_db.rs`'s `Utils`).
struct Utils;
impl DataUtilities for Utils {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::mem::{Memory, MemoryAccessException, MemoryBlock};
    use crate::program::model::symbol::{Symbol, SymbolTable, SymbolType};

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            self.0
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    struct TestReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        index: u64,
        little_endian: bool,
    }

    impl TestReader {
        fn new(bytes: Vec<u8>) -> Self {
            TestReader {
                provider: Rc::new(RefCell::new(VecProvider(bytes))),
                index: 0,
                little_endian: true,
            }
        }
    }

    impl BinaryReader for TestReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let prev = self.index;
            self.index = index;
            prev
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(TestReader {
                provider: Rc::clone(&self.provider),
                index: new_index,
                little_endian: self.little_endian,
            })
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    // ---- read()/from_program() tests ----

    fn build_two_comment_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"GCC: (GNU) 12.2.0\0");
        v.extend_from_slice(b"hi\0");
        v
    }

    #[test]
    fn read_parses_multiple_null_terminated_strings() {
        let mut reader = TestReader::new(build_two_comment_bytes());
        let comment = ElfComment::read(&mut reader, &MockProgram).unwrap();

        assert_eq!(
            comment.get_comment_strings(),
            &["GCC: (GNU) 12.2.0".to_string(), "hi".to_string()]
        );
        // Lengths include the null terminator, matching `br.getPointerIndex() - start`.
        // "GCC: (GNU) 12.2.0" is 17 characters + 1 null terminator = 18.
        assert_eq!(comment.comment_string_lengths, vec![18, 3]);
        assert!(!reader.has_next());
    }

    #[test]
    fn read_handles_empty_section() {
        let mut reader = TestReader::new(Vec::new());
        let comment = ElfComment::read(&mut reader, &MockProgram).unwrap();
        assert!(comment.get_comment_strings().is_empty());
    }

    #[test]
    fn read_handles_single_empty_string() {
        // A lone null byte is a valid (empty) string.
        let mut reader = TestReader::new(vec![0u8]);
        let comment = ElfComment::read(&mut reader, &MockProgram).unwrap();
        assert_eq!(comment.get_comment_strings(), &["".to_string()]);
        assert_eq!(comment.comment_string_lengths, vec![1]);
    }

    #[test]
    fn to_string_matches_java_format() {
        let comment = ElfComment::new(vec!["a".to_string(), "b".to_string()], vec![2, 2]);
        assert_eq!(comment.to_string(), "ElfComment [commentStrings=[a, b]]");
    }

    // ---- from_program() tests ----

    struct FakeMemoryBlock {
        name: String,
        start: Address,
        data: Vec<u8>,
    }

    impl MemoryBlock for FakeMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_start(&self) -> Address {
            self.start.clone()
        }
        fn get_end(&self) -> Address {
            self.start.add((self.data.len() as i64 - 1).max(0)).unwrap()
        }
        fn get_size(&self) -> u64 {
            self.data.len() as u64
        }
        fn is_initialized(&self) -> bool {
            true
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.subtract(&self.start) as usize;
            self.data.get(offset).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.subtract(&self.start) as usize;
            let available = self.data.len().saturating_sub(offset);
            let n = dest.len().min(available);
            dest[..n].copy_from_slice(&self.data[offset..offset + n]);
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
    }

    struct FakeMemory {
        block: Arc<dyn MemoryBlock>,
    }

    impl Memory for FakeMemory {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.block.get_byte(addr)
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            self.block.get_bytes(addr, dest)
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!("not needed by these tests")
        }
        fn get_block_by_name(&self, name: &str) -> Option<Arc<dyn MemoryBlock>> {
            if self.block.get_name() == name { Some(self.block.clone()) } else { None }
        }
    }

    struct FakeMemoryProgram {
        memory: Arc<dyn Memory>,
    }
    impl crate::framework::model::DomainObject for FakeMemoryProgram {}
    impl Program for FakeMemoryProgram {
        fn get_name(&self) -> String {
            "elf_comment_test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn program_with_comment_section(data: &[u8]) -> FakeMemoryProgram {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        let start = Address::new(space, 0x2000);
        let block: Arc<dyn MemoryBlock> = Arc::new(FakeMemoryBlock {
            name: ElfComment::SECTION_NAME.to_string(),
            start,
            data: data.to_vec(),
        });
        FakeMemoryProgram { memory: Arc::new(FakeMemory { block }) }
    }

    #[test]
    fn from_program_reads_comment_section() {
        let program = program_with_comment_section(&build_two_comment_bytes());
        let comment = ElfComment::from_program(&program).expect("section present");
        assert_eq!(
            comment.get_comment_strings(),
            &["GCC: (GNU) 12.2.0".to_string(), "hi".to_string()]
        );
    }

    #[test]
    fn from_program_returns_none_when_section_missing() {
        struct EmptyMemory;
        impl Memory for EmptyMemory {
            fn is_big_endian(&self) -> bool {
                false
            }
            fn get_byte(&self, _addr: &Address) -> Result<u8, MemoryAccessException> {
                Err(MemoryAccessException::new("no memory"))
            }
            fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
                0
            }
            fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
                unimplemented!()
            }
            fn get_block_by_name(&self, _name: &str) -> Option<Arc<dyn MemoryBlock>> {
                None
            }
        }
        struct NoSectionProgram;
        impl crate::framework::model::DomainObject for NoSectionProgram {}
        impl Program for NoSectionProgram {
            fn get_name(&self) -> String {
                "no_section".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:32:default".to_string()
            }
            fn get_memory(&self) -> Option<Arc<dyn Memory>> {
                Some(Arc::new(EmptyMemory))
            }
        }

        assert!(ElfComment::from_program(&NoSectionProgram).is_none());
    }

    // ---- markup_program() tests ----
    //
    // `Program`/`SymbolTable` both require `Send + Sync` (so `Program` handles can cross thread
    // boundaries elsewhere in the crate), so these test doubles share their recorded state
    // through `Arc<Mutex<_>>` rather than the `Rc<RefCell<_>>` used above for the (non-Send)
    // `BinaryReader`/`ByteProvider` mocks.

    struct RecordingOptions {
        calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }
    impl Options for RecordingOptions {
        fn set_string(&mut self, option_name: &str, value: &str) {
            self.calls.lock().unwrap().push((option_name.to_string(), value.to_string()));
        }
    }

    struct MockSymbol {
        address: Address,
        name: String,
    }
    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }
        fn get_source(&self) -> SourceType {
            SourceType::Imported
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn get_id(&self) -> i64 {
            1
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
    }

    struct RecordingSymbolTable {
        created_labels: std::sync::Arc<std::sync::Mutex<Vec<(Address, String)>>>,
    }
    impl SymbolTable for RecordingSymbolTable {
        fn create_label(
            &mut self,
            addr: &Address,
            name: &str,
            _source: SourceType,
        ) -> io::Result<Arc<dyn Symbol>> {
            self.created_labels.lock().unwrap().push((addr.clone(), name.to_string()));
            Ok(Arc::new(MockSymbol { address: addr.clone(), name: name.to_string() }))
        }
        fn get_symbol(&self, _id: i64) -> io::Result<Option<Arc<dyn Symbol>>> {
            Ok(None)
        }
        fn get_symbols(&self, _addr: &Address) -> io::Result<Vec<Arc<dyn Symbol>>> {
            Ok(Vec::new())
        }
    }

    /// A `Program` that has a working `Options`/`SymbolTable` (so those two markup steps can be
    /// observed) but no `Listing` (matching the `Program` trait's own default), so the final
    /// `DataUtilities::create_data` step always fails. This exercises the real, faithfully-ported
    /// Java quirk: `markupProgram`'s `try` wraps the *entire* loop, so a failure on one comment
    /// aborts every remaining comment, while the options/labels already applied for earlier (and
    /// the partially-applied current) comments are left in place.
    struct NoListingProgram {
        options_calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }
    impl crate::framework::model::DomainObject for NoListingProgram {
        fn get_options(&self, _property_list_name: &str) -> Box<dyn Options> {
            Box::new(RecordingOptions { calls: std::sync::Arc::clone(&self.options_calls) })
        }
    }
    impl Program for NoListingProgram {
        fn get_name(&self) -> String {
            "no_listing".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        // No `get_symbol_table` override: falls back to the `Program` trait's own default of
        // `None`, so markup fails at that step (before ever reaching `DataUtilities::create_data`).
    }

    fn test_address() -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, 0x3000)
    }

    #[test]
    fn markup_program_aborts_remaining_comments_after_first_failure() {
        let comment = ElfComment::new(
            vec!["first".to_string(), "second".to_string()],
            vec![6, 7],
        );

        let options_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut program =
            NoListingProgram { options_calls: std::sync::Arc::clone(&options_calls) };

        comment.markup_program(&mut program, &test_address());

        // Since `get_symbol_table` returns `None` on this Program stand-in, markup fails before
        // ever reaching `DataUtilities::create_data` -- but only *after* the option for comment 0
        // was already recorded, matching Java's "try wraps the whole loop" semantics: comment 0's
        // option persists, nothing from comment 1 is ever attempted.
        let calls = options_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], ("Elf Comment[0]".to_string(), "first".to_string()));
    }

    #[test]
    fn markup_program_records_label_before_data_markup_fails() {
        struct ProgramWithSymbolTableOnly {
            options_calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
            symtab: RecordingSymbolTable,
        }
        impl crate::framework::model::DomainObject for ProgramWithSymbolTableOnly {
            fn get_options(&self, _property_list_name: &str) -> Box<dyn Options> {
                Box::new(RecordingOptions { calls: std::sync::Arc::clone(&self.options_calls) })
            }
        }
        impl Program for ProgramWithSymbolTableOnly {
            fn get_name(&self) -> String {
                "with_symtab".to_string()
            }
            fn get_language_id(&self) -> String {
                "test:LE:32:default".to_string()
            }
            fn get_symbol_table(&mut self) -> Option<&mut dyn SymbolTable> {
                Some(&mut self.symtab)
            }
        }

        let comment = ElfComment::new(vec!["only".to_string()], vec![5]);
        let options_calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let created_labels = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut program = ProgramWithSymbolTableOnly {
            options_calls: std::sync::Arc::clone(&options_calls),
            symtab: RecordingSymbolTable {
                created_labels: std::sync::Arc::clone(&created_labels),
            },
        };

        let addr = test_address();
        comment.markup_program(&mut program, &addr);

        // The label is created successfully (real `SymbolTable`), but `create_data` still fails
        // because this Program has no `Listing` -- proving the label-creation step really does
        // run (and persist) even though the overall markup of this comment ultimately fails.
        let calls = options_calls.lock().unwrap();
        let labels = created_labels.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], (addr, "ElfComment[0]".to_string()));
    }
}
