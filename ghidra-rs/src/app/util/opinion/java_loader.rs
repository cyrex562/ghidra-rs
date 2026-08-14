//! Port of `ghidra.app.util.opinion.JavaLoader`.
//!
//! Loads a Java `.class` file into a `Program`: the raw class file bytes are mapped verbatim into
//! the `constantPool` address space, a `method_lookup` table is reserved at a fixed address, and
//! each method's bytecode is laid out as its own memory block with an alignment-pad register set
//! per byte (cycling 3, 2, 1, 0) so the JVM pcode's per-instruction offset arithmetic lines up.
//!
//! # Departures from the Java class
//!
//! * `JavaLoader` extends `AbstractProgramWrapperLoader` (in turn `AbstractProgramLoader`), which
//!   implement the bulk of the `Loader` interface (program creation, transaction management,
//!   language/compiler-spec matching for load-into, `getTier()`/`getTierPriority()`, ...) and are
//!   not ported. `JavaLoader.java` itself only overrides `findSupportedLoadSpecs`, `getName`, and
//!   `load(Program, ImporterSettings)`, so -- like
//!   [`UnixAoutProgramLoader`](crate::app::util::opinion::unix_aout_program_loader::UnixAoutProgramLoader)
//!   -- this port models just that overridden surface as inherent methods on a standalone struct,
//!   rather than implementing the [`Loader`](crate::app::util::opinion::loader::Loader) trait
//!   (which would additionally require the inherited machinery this class never defines).
//! * `ByteProvider`/`BinaryReader`/`ClassFileJava`/`MethodInfoJava`/`CodeAttribute`/
//!   `ConstantPoolUtf8Info`/`JavaClassUtil`/`LoadSpec`/`LanguageCompilerSpecPair` are used via
//!   their real ported paths. `ClassFileJava`/`MethodInfoJava`/`CodeAttribute`/`JavaClassUtil` were
//!   grown in [`format::seam_stubs`](crate::format::seam_stubs) (and `LoadSpec` in
//!   [`app::seam_stubs`](crate::app::seam_stubs)) to carry the extra surface this loader needs;
//!   see those modules for what is and is not modeled. The crate has no canonical production
//!   [`BinaryReader`](crate::app::util::bin::binary_reader::BinaryReader) implementer yet, so this
//!   module defines its own minimal `ByteProvider`-backed one, mirroring the identical local
//!   helper in
//!   [`ClassFileAnalysisState`](crate::format::javaclass::class_file_analysis_state)/`elf_info_item`.
//! * `Memory.createInitializedBlock(String, Address, InputStream, long, TaskMonitor, boolean)`
//!   copies bytes from a stream as part of block creation. The ported
//!   [`Memory`](crate::program::model::mem::Memory) trait's `create_initialized_block` only fills
//!   a block with a single repeated byte value, so this port creates the block filled with zero
//!   and then overwrites it with the real bytes via `set_bytes` -- two steps instead of Java's
//!   one, but the same final memory contents.
//! * `MemoryBlock.setRead`/`setWrite`/`setExecute`, called by `createMethodLookupMemoryBlock` to
//!   mark that block read-only and non-executable, have no equivalent on the ported
//!   [`MemoryBlock`](crate::program::model::mem::MemoryBlock) trait (it only exposes the getters).
//!   This port creates the block but cannot mark its permissions; once setters are ported, wire
//!   them in at the point noted below.
//! * `Memory.setInt(Address, int)` has no equivalent on the ported `Memory` trait; this port
//!   writes the same four bytes via `set_bytes`, choosing big/little-endian order from
//!   `Memory.is_big_endian()` exactly as Java's `setInt` would.
//! * `PointerDataType.dataType` (a static default-pointer singleton) is not ported (see
//!   [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)'s module
//!   docs: there is no way to construct a concrete one generically yet). This port uses a local
//!   fallback [`DataType`] of length `-1`, the same `FallbackPointerDataType` pattern already
//!   established in
//!   [`VariableUtilities`](crate::program::model::listing::variable_utilities).
//! * `ByteProvider.getName()` is not on the ported `ByteProvider` trait (only `get_fsrl`/
//!   `get_file` are). This port derives the same display name Java would from those two instead.
//! * Every method below that Java lets an uncaught exception propagate out of (aborting either
//!   `doLoad` or the whole `createMethodMemoryBlocks` loop, then logged by the caller's
//!   `printStackTrace`) is translated the same way: the first error inside `create_method_memory_blocks`
//!   or `create_method_lookup_memory_block` is logged via [`Msg::error_with_error`] and the
//!   surrounding loop stops, matching Java's single `catch (Exception e1)` wrapping the whole
//!   method-processing loop.

use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::seam_stubs::LoadSpec;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::format::javaclass::constantpool::abstract_constant_pool_info_java::AbstractConstantPoolInfoJava;
use crate::format::javaclass::java_class_constants::MAGIC;
use crate::format::seam_stubs::{ClassFileJava, ConstantPoolUtf8Info, JavaClassUtil, MethodInfoJava};
use crate::program::model::address::{Address, AddressOverflowException, AddressSet};
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::{CompilerSpecID, LanguageID, RegisterRef};
use crate::program::model::listing::Program;
use crate::program::model::mem::memory::CreateBlockError;
use crate::program::seam_stubs::LanguageCompilerSpecPair;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// `JavaLoader.JAVA_NAME`.
const JAVA_NAME: &str = "Java Class File";

/// `JavaLoader.CODE_OFFSET`.
pub const CODE_OFFSET: i64 = 0x10000;

/// `JavaLoader.CONSTANT_POOL`.
pub const CONSTANT_POOL: &str = "constantPool";

/// Combines the failure modes of [`JavaLoader::do_load`]: the checked exceptions
/// [`Loader.load`](crate::app::util::opinion::loader::Loader::load) declares (only `IOException`
/// propagates out of Java's `load`; the rest are caught and logged there) plus the block-creation
/// failures the ported [`Memory`](crate::program::model::mem::Memory) trait reports.
#[derive(Debug, thiserror::Error)]
pub enum DoLoadError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    CreateBlock(#[from] CreateBlockError),
}

/// A minimal [`BinaryReader`](crate::app::util::bin::binary_reader::BinaryReader) backed by a
/// [`ByteProvider`]. See the module docs for why this crate-wide gap is filled locally here
/// instead of reused from elsewhere.
struct JavaClassBinaryReader {
    provider: Rc<RefCell<dyn ByteProvider>>,
    is_little_endian: bool,
    current_index: u64,
}

impl JavaClassBinaryReader {
    fn new(provider: Rc<RefCell<dyn ByteProvider>>, is_little_endian: bool) -> Self {
        JavaClassBinaryReader { provider, is_little_endian, current_index: 0 }
    }
}

impl crate::app::util::bin::binary_reader::BinaryReader for JavaClassBinaryReader {
    fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }

    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    fn set_pointer_index(&mut self, index: u64) -> u64 {
        let previous = self.current_index;
        self.current_index = index;
        previous
    }

    fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    fn set_little_endian(&mut self, is_little_endian: bool) {
        self.is_little_endian = is_little_endian;
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

    fn clone_at(&self, new_index: u64) -> Box<dyn crate::app::util::bin::binary_reader::BinaryReader> {
        Box::new(JavaClassBinaryReader {
            provider: Rc::clone(&self.provider),
            is_little_endian: self.is_little_endian,
            current_index: new_index,
        })
    }
}

/// Fallback pointer [`DataType`], standing in for `PointerDataType.dataType`. See the module docs
/// for why the real `PointerDataType` cannot be constructed generically yet. Not a port of any
/// specific Java class.
struct FallbackPointerDataType;

impl DataType for FallbackPointerDataType {
    fn get_name(&self) -> String {
        "pointer".to_string()
    }

    fn get_length(&self) -> i32 {
        -1
    }

    fn is_pointer(&self) -> bool {
        true
    }
}

/// Loader for Java `.class` files.
///
/// Port of `ghidra.app.util.opinion.JavaLoader`.
pub struct JavaLoader {
    /// The `alignmentPad` register, if this program's language defines one. Set by
    /// [`do_load`](Self::do_load), mirroring the Java field `alignmentReg`, which is likewise
    /// only populated once loading starts.
    alignment_reg: Option<RegisterRef>,
}

impl Default for JavaLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaLoader {
    pub fn new() -> Self {
        JavaLoader { alignment_reg: None }
    }

    /// `JavaLoader.findSupportedLoadSpecs(ByteProvider)`.
    pub fn find_supported_load_specs(
        &self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
    ) -> io::Result<Vec<LoadSpec>> {
        let mut load_specs = Vec::new();
        if Self::check_class(provider)? {
            let pair = LanguageCompilerSpecPair::new(
                LanguageID::new("JVM:BE:32:default").expect("non-empty language id"),
                CompilerSpecID::new(Some("default")),
            );
            load_specs.push(LoadSpec::with_language_compiler_spec(0, pair, true));
        }
        Ok(load_specs)
    }

    /// `JavaLoader.checkClass(ByteProvider)`.
    fn check_class(provider: &Rc<RefCell<dyn ByteProvider>>) -> io::Result<bool> {
        let mut reader = JavaClassBinaryReader::new(Rc::clone(provider), false);
        let magic = crate::app::util::bin::binary_reader::BinaryReader::peek_next_int(&reader)?;
        if magic != MAGIC as i32 {
            return Ok(false);
        }
        // Mirrors `catch (IOException e)` / `catch (RuntimeException re)`, both of which return
        // false; the stub `ClassFileJava::new` never panics, so only the IOException arm is live.
        Ok(ClassFileJava::new(&mut reader).is_ok())
    }

    /// `JavaLoader.getName()`.
    pub fn get_name(&self) -> &'static str {
        JAVA_NAME
    }

    /// `JavaLoader.load(Program, ImporterSettings)`. Only `IOException` propagates; every other
    /// checked exception `doLoad` can raise is caught and logged here, mirroring Java's five
    /// `catch` blocks.
    pub fn load(
        &mut self,
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<()> {
        match self.do_load(provider, program, monitor) {
            Ok(()) => Ok(()),
            Err(DoLoadError::Io(e)) => Err(e),
            Err(e @ DoLoadError::CreateBlock(_)) => {
                Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                Ok(())
            }
        }
    }

    /// `JavaLoader.doLoad(ByteProvider, Program, TaskMonitor)`.
    fn do_load(
        &mut self,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), DoLoadError> {
        let address_factory = program.get_address_factory().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "program has no address factory")
        })?;
        let space = address_factory.get_address_space_by_name(CONSTANT_POOL).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "program has no constantPool address space")
        })?;
        self.alignment_reg = program.get_register("alignmentPad");

        let mut reader = JavaClassBinaryReader::new(Rc::clone(provider), false);
        let class_file = ClassFileJava::new(&mut reader)?;

        let address = space.address(0);
        let block_name = format!("_{}_", Self::provider_name(provider));
        let full_len = provider.borrow_mut().length()?;
        let content = provider.borrow_mut().read_bytes(0, full_len as usize)?;

        {
            let memory = program.get_memory_mut().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "program has no memory")
            })?;
            memory.create_initialized_block(&block_name, &address, full_len, 0, monitor, false)?;
            memory.set_bytes(&address, &content).map_err(|e| {
                DoLoadError::Io(io::Error::new(io::ErrorKind::Other, e.to_string()))
            })?;
        }

        Self::create_method_lookup_memory_block(program, monitor);
        self.create_method_memory_blocks(program, provider, &reader, &class_file, monitor);

        Ok(())
    }

    /// `JavaLoader.createMethodLookupMemoryBlock(Program, TaskMonitor)`.
    fn create_method_lookup_memory_block(program: &mut dyn Program, monitor: &dyn TaskMonitor) {
        let address = Self::to_addr(program, JavaClassUtil::LOOKUP_ADDRESS);
        let Some(memory) = program.get_memory_mut() else { return };
        match memory.create_initialized_block(
            "method_lookup",
            &address,
            JavaClassUtil::METHOD_INDEX_SIZE,
            0xff,
            monitor,
            false,
        ) {
            Ok(_block) => {
                // Java additionally does block.setRead(true)/setWrite(false)/setExecute(false)
                // here; see the module docs for why the ported `MemoryBlock` trait cannot express
                // that yet.
            }
            Err(e) => Msg::error_with_error("JavaLoader", &e.to_string(), &e),
        }
    }

    /// `JavaLoader.createMethodMemoryBlocks(Program, ByteProvider, ClassFileJava, TaskMonitor)`.
    fn create_method_memory_blocks(
        &self,
        program: &mut dyn Program,
        provider: &Rc<RefCell<dyn ByteProvider>>,
        reader: &dyn crate::app::util::bin::binary_reader::BinaryReader,
        class_file: &ClassFileJava,
        monitor: &dyn TaskMonitor,
    ) {
        let constant_pool = class_file.get_constant_pool();
        let methods = class_file.get_methods();

        monitor.set_message("Processing Methods...");
        monitor.set_progress(0);
        monitor.set_maximum(methods.len() as i64);

        let mut start = Self::to_addr(program, CODE_OFFSET);

        for (i, method) in methods.iter().enumerate() {
            monitor.increment_progress(1);
            let Some(code) = method.get_code_attribute() else { continue };
            let length = code.get_code_length();
            let offset = code.get_code_offset();

            let Some(method_name) = Self::method_display_name(reader, constant_pool, method) else {
                Msg::error_with_error(
                    "JavaLoader",
                    &"unable to resolve method name from constant pool",
                    &io::Error::new(io::ErrorKind::InvalidData, "bad constant pool index"),
                );
                break;
            };

            let content = match provider.borrow_mut().read_bytes(offset as u64, length as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                    break;
                }
            };

            let block = {
                let Some(memory) = program.get_memory_mut() else { break };
                let block = match memory
                    .create_initialized_block(&method_name, &start, length as u64, 0, monitor, false)
                {
                    Ok(block) => block,
                    Err(e) => {
                        Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                        break;
                    }
                };
                if let Err(e) = memory.set_bytes(&start, &content) {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                    break;
                }
                block
            };

            let method_index_address = JavaClassUtil::to_lookup_address(program, i as i32);

            {
                let Some(memory) = program.get_memory_mut() else { break };
                let big_endian = memory.is_big_endian();
                let offset_value = start.offset() as i32;
                let bytes =
                    if big_endian { offset_value.to_be_bytes() } else { offset_value.to_le_bytes() };
                if let Err(e) = memory.set_bytes(&method_index_address, &bytes) {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                    break;
                }
            }

            if let Some(listing) = program.get_listing() {
                if let Err(e) =
                    listing.create_data(method_index_address.clone(), Box::new(FallbackPointerDataType))
                {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                    break;
                }
            }

            let block_range = AddressSet::from_start_end(block.get_start(), block.get_end());
            self.set_alignment_info(program, &block_range);

            match Self::advance_past_method(&start, length) {
                Ok(next) => start = next,
                Err(e) => {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                    break;
                }
            }
        }
    }

    /// `methodNameInfo.getString() + methodDescriptorInfo.getString()`, resolving both constant
    /// pool entries via [`ConstantPoolUtf8Info::from_entry`]. Returns `None` where Java's
    /// unchecked cast to `ConstantPoolUtf8Info` would throw (bad index or a read failure),
    /// aborting the caller's loop exactly as an uncaught `ClassCastException`/`IOException` would.
    fn method_display_name(
        reader: &dyn crate::app::util::bin::binary_reader::BinaryReader,
        constant_pool: &[AbstractConstantPoolInfoJava],
        method: &MethodInfoJava,
    ) -> Option<String> {
        let name_entry = constant_pool.get(method.get_name_index() as usize)?;
        let descriptor_entry = constant_pool.get(method.get_descriptor_index() as usize)?;
        let name = ConstantPoolUtf8Info::from_entry(reader, name_entry).ok()?;
        let descriptor = ConstantPoolUtf8Info::from_entry(reader, descriptor_entry).ok()?;
        Some(format!("{}{}", name.get_string(), descriptor.get_string()))
    }

    /// `start = start.add(length + 1); while (start.getOffset() % 4 != 0) { start = start.add(1); }`.
    fn advance_past_method(start: &Address, length: i32) -> Result<Address, AddressOverflowException> {
        let mut next = start.add(length as i64 + 1)?;
        while next.offset() % 4 != 0 {
            next = next.add(1)?;
        }
        Ok(next)
    }

    /// `JavaLoader.setAlignmentInfo(Program, AddressSet)`.
    fn set_alignment_info(&self, program: &mut dyn Program, set: &AddressSet) {
        use crate::program::model::address::AddressSetView;

        let Some(register_ref) = self.alignment_reg.as_ref() else { return };
        let register = register_ref.borrow();
        let mut alignment_value: i128 = 3;
        for address in set.addresses(true) {
            if let Some(context) = program.get_program_context() {
                if let Err(e) = context.set_value(&register, &address, &address, Some(alignment_value))
                {
                    Msg::error_with_error("JavaLoader", &e.to_string(), &e);
                }
            }
            alignment_value = if alignment_value == 0 { 3 } else { alignment_value - 1 };
        }
    }

    /// `JavaLoader.toAddr(Program, long)`.
    fn to_addr(program: &dyn Program, offset: i64) -> Address {
        let factory = program
            .get_address_factory()
            .expect("JavaLoader.toAddr: program has no address factory");
        let space = factory
            .get_default_address_space()
            .expect("JavaLoader.toAddr: program has no default address space");
        space.address(offset)
    }

    /// Stands in for `provider.getName()`, which is not on the ported [`ByteProvider`] trait. See
    /// the module docs.
    fn provider_name(provider: &Rc<RefCell<dyn ByteProvider>>) -> String {
        let borrowed = provider.borrow();
        if let Some(name) = borrowed.get_fsrl().and_then(|f| f.name()) {
            return name;
        }
        if let Some(path) = borrowed.get_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                return name.to_string();
            }
        }
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::javaclass::constantpool::constant_pool_tags_java::CONSTANT_UTF8;
    use crate::format::seam_stubs::CodeAttribute;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct FakeByteProvider {
        data: Vec<u8>,
    }

    impl ByteProvider for FakeByteProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.data.len() as u64
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "not enough data"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            self.data[index as usize] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            self.data[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    fn provider_with(data: Vec<u8>) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::new(RefCell::new(FakeByteProvider { data }))
    }

    #[test]
    fn constants_match_java() {
        assert_eq!(JAVA_NAME, "Java Class File");
        assert_eq!(CODE_OFFSET, 0x10000);
        assert_eq!(CONSTANT_POOL, "constantPool");
    }

    #[test]
    fn get_name_returns_java_name() {
        let loader = JavaLoader::new();
        assert_eq!(loader.get_name(), "Java Class File");
    }

    #[test]
    fn check_class_rejects_wrong_magic() {
        let provider = provider_with(vec![0x00, 0x00, 0x00, 0x00]);
        assert_eq!(JavaLoader::check_class(&provider).unwrap(), false);
    }

    #[test]
    fn check_class_accepts_class_file_magic() {
        // 0xCAFEBABE magic, followed by enough bytes that peeking/parsing does not error.
        let provider = provider_with(vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0]);
        assert_eq!(JavaLoader::check_class(&provider).unwrap(), true);
    }

    #[test]
    fn check_class_propagates_io_error_from_short_provider() {
        // Too short for even the 4-byte magic peek: `peekNextInt()`'s IOException is not caught
        // by `checkClass`, so it must propagate.
        let provider = provider_with(vec![0xCA, 0xFE]);
        assert!(JavaLoader::check_class(&provider).is_err());
    }

    #[test]
    fn find_supported_load_specs_returns_preferred_jvm_spec_when_valid() {
        let loader = JavaLoader::new();
        let provider = provider_with(vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 0]);
        let specs = loader.find_supported_load_specs(&provider).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].desired_image_base, 0);
        assert!(specs[0].preferred);
        let pair = specs[0].language_compiler_spec.as_ref().unwrap();
        assert_eq!(pair.get_language_id().get_id_as_string(), "JVM:BE:32:default");
        assert_eq!(pair.get_compiler_spec_id().get_id_as_string(), "default");
    }

    #[test]
    fn find_supported_load_specs_empty_when_invalid_magic() {
        let loader = JavaLoader::new();
        let provider = provider_with(vec![0x00, 0x00, 0x00, 0x00]);
        let specs = loader.find_supported_load_specs(&provider).unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn advance_past_method_rounds_up_to_next_multiple_of_four() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = space.address(0x10000);
        // length 10 -> start + 11 = 0x1000B -> rounds up to 0x1000C.
        let next = JavaLoader::advance_past_method(&start, 10).unwrap();
        assert_eq!(next.offset(), 0x1000C);
    }

    #[test]
    fn advance_past_method_stays_when_already_aligned() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let start = space.address(0x10000);
        // length 3 -> start + 4 = 0x10004, already a multiple of 4.
        let next = JavaLoader::advance_past_method(&start, 3).unwrap();
        assert_eq!(next.offset(), 0x10004);
    }

    /// Writes a `CONSTANT_Utf8_info` entry (`u1 tag; u2 length; u1 bytes[length];`) at `offset`
    /// and returns the parsed [`AbstractConstantPoolInfoJava`] header for it.
    fn write_utf8_entry(
        data: &mut Vec<u8>,
        offset: usize,
        text: &str,
    ) -> AbstractConstantPoolInfoJava {
        if data.len() < offset {
            data.resize(offset, 0);
        }
        data.truncate(offset);
        data.push(CONSTANT_UTF8);
        let bytes = text.as_bytes();
        data.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        data.extend_from_slice(bytes);

        let provider = provider_with(data.clone());
        let mut reader = JavaClassBinaryReader::new(provider, false);
        crate::app::util::bin::binary_reader::BinaryReader::set_pointer_index(
            &mut reader,
            offset as u64,
        );
        AbstractConstantPoolInfoJava::new(&mut reader).unwrap()
    }

    #[test]
    fn method_display_name_concatenates_name_and_descriptor() {
        let mut data = Vec::new();
        let name_entry = write_utf8_entry(&mut data, 0, "main");
        let descriptor_offset = data.len();
        let descriptor_entry =
            write_utf8_entry(&mut data, descriptor_offset, "([Ljava/lang/String;)V");

        let provider = provider_with(data);
        let reader = JavaClassBinaryReader::new(provider, false);
        let constant_pool = vec![name_entry, descriptor_entry];
        let method = MethodInfoJava::with_details(0, 0, 1, Some(CodeAttribute::new(0, 0)));

        let name =
            JavaLoader::method_display_name(&reader, &constant_pool, &method).expect("resolved name");
        assert_eq!(name, "main([Ljava/lang/String;)V");
    }

    #[test]
    fn method_display_name_none_for_out_of_range_index() {
        let data = Vec::new();
        let provider = provider_with(data);
        let reader = JavaClassBinaryReader::new(provider, false);
        let method = MethodInfoJava::with_details(0, 5, 6, Some(CodeAttribute::new(0, 0)));
        assert!(JavaLoader::method_display_name(&reader, &[], &method).is_none());
    }
}
