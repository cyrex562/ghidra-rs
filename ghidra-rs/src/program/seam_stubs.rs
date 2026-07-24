//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::pcode::floatformat::big_float::BigFloat;
use crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException;
use crate::program::model::address::{Address, AddressRange, AddressSpace};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::Function;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::function_prototype::FunctionPrototype;
use crate::program::model::pcode::global_symbol_map::GlobalSymbolMap;
use crate::program::model::pcode::list_linked::LinkedIter;
use crate::program::model::pcode::Varnode;
use crate::program::model::block::code_block_iterator::CodeBlockIterator;
use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
use crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic;
use crate::program::util::language_translator::LanguageTranslator;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use std::any::Any;
use std::fmt;
use std::sync::Arc;

pub use crate::program::model::data::data_type_path::DataTypePath;

/// Placeholder for `ghidra.app.merge.DataTypeManagerOwner`, referenced by
/// [`DataTypeManagerDomainObject`](crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject)
/// before the real interface is ported.
pub trait DataTypeManagerOwner {
    /// Gets the associated data type manager.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager>;
}

/// Placeholder for `ghidra.program.model.listing.VariableStorage`, referenced by
/// [`Variable`](crate::program::model::listing::variable::Variable)
/// before the real class is ported.
///
/// Grown (all with defaults, so pre-existing bare `impl VariableStorage for Foo {}` blocks keep
/// compiling) to also cover the query surface
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// needs before the real class is ported.
pub trait VariableStorage {
    /// Stands in for `VariableStorage.isHashStorage()`.
    fn is_hash_storage(&self) -> bool {
        false
    }

    /// Stands in for `VariableStorage.isMemoryStorage()`.
    fn is_memory_storage(&self) -> bool {
        false
    }

    /// Stands in for `VariableStorage.getFirstVarnode()`.
    fn get_first_varnode(&self) -> Option<Varnode> {
        None
    }

    /// Stands in for `VariableStorage.intersects(VariableStorage)`. Defaults to "does not
    /// intersect", mirroring storage in an unrelated location.
    fn intersects(&self, other: &dyn VariableStorage) -> bool {
        let _ = other;
        false
    }

    /// Stands in for `VariableStorage.equals(Object)`, compared by an implementation-defined key
    /// (the real class compares varnode lists). Defaults to `false`.
    fn storage_equals(&self, other: &dyn VariableStorage) -> bool {
        let _ = other;
        false
    }
}

/// Trivial placeholder implementing [`VariableStorage`], used as a default return value by stub
/// traits/methods (e.g. [`HighSymbol::get_storage`], [`FunctionPrototype::get_return_storage`])
/// whose real Java counterparts always return concrete storage; also stands in for
/// `VariableStorage.UNASSIGNED_STORAGE`. Not a port of any specific Java class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlaceholderVariableStorage;

impl VariableStorage for PlaceholderVariableStorage {}

/// Minimal [`VariableStorage`] backing [`DynamicEntry::get_storage`] and
/// [`HighFunctionDBUtil::write_union_facet`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::write_union_facet):
/// reports itself as hash-addressed storage keyed by `hash`, mirroring how real hash-space
/// storage encodes its dynamic hash. Not a port of any specific Java class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashVariableStorage(pub i64);

impl VariableStorage for HashVariableStorage {
    fn is_hash_storage(&self) -> bool {
        true
    }
}

/// Rust-ergonomics helper letting multiple independent `Box<dyn DataType>` handles share one
/// underlying value, since `dyn DataType` has no `Clone` bound. Not a port of any specific Java
/// class; used where Java code reuses the same `DataType` object reference across several calls
/// (e.g. assigning the same data type to every variable in a merge set).
struct SharedDataType(Arc<dyn DataType>);

impl DataType for SharedDataType {
    fn get_name(&self) -> String {
        self.0.get_name()
    }

    fn get_length(&self) -> i32 {
        self.0.get_length()
    }

    fn is_void_type(&self) -> bool {
        self.0.is_void_type()
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.0.is_equivalent(dt)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.0.clone_data_type(dtm)
    }
}

/// Hands back a fresh `Box<dyn DataType>` sharing `data_type`'s underlying value. See
/// [`SharedDataType`].
pub fn share_data_type(data_type: &Arc<dyn DataType>) -> Box<dyn DataType> {
    Box::new(SharedDataType(data_type.clone()))
}

/// Rust-ergonomics helper letting multiple independent `Box<dyn VariableStorage>` handles share
/// one underlying value, since `dyn VariableStorage` has no `Clone` bound. Not a port of any
/// specific Java class. See [`SharedDataType`] for the `DataType` analogue.
struct SharedVariableStorage(Arc<dyn VariableStorage>);

impl VariableStorage for SharedVariableStorage {
    fn is_hash_storage(&self) -> bool {
        self.0.is_hash_storage()
    }

    fn is_memory_storage(&self) -> bool {
        self.0.is_memory_storage()
    }

    fn get_first_varnode(&self) -> Option<Varnode> {
        self.0.get_first_varnode()
    }

    fn intersects(&self, other: &dyn VariableStorage) -> bool {
        self.0.intersects(other)
    }

    fn storage_equals(&self, other: &dyn VariableStorage) -> bool {
        self.0.storage_equals(other)
    }
}

/// Hands back a fresh `Box<dyn VariableStorage>` sharing `storage`'s underlying value. See
/// [`SharedVariableStorage`].
pub fn share_variable_storage(storage: &Arc<dyn VariableStorage>) -> Box<dyn VariableStorage> {
    Box::new(SharedVariableStorage(storage.clone()))
}

/// Trivial fixed-length placeholder implementing [`DataType`], used as a default return value by
/// stub traits (e.g. [`HighSymbol::get_data_type`]) whose real Java counterparts always return a
/// concrete data type. Not a port of any specific Java class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlaceholderDataType;

impl DataType for PlaceholderDataType {}

/// Stands in for `Undefined.getUndefinedDataType(int)`, referenced by
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real `Undefined1..8DataType` family is ported. Represents an opaque fixed-length
/// "undefined" data type of the requested length.
pub fn undefined_data_type(length: i32) -> Box<dyn DataType> {
    struct UndefinedDataTypePlaceholder(i32);

    impl DataType for UndefinedDataTypePlaceholder {
        fn get_name(&self) -> String {
            format!("undefined{}", self.0)
        }

        fn get_length(&self) -> i32 {
            self.0
        }

        fn is_undefined_type(&self) -> bool {
            true
        }
    }

    Box::new(UndefinedDataTypePlaceholder(length))
}

/// Placeholder for `ghidra.program.model.lang.VariableUtilities`'s static `resizeStorage`,
/// referenced by
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real class (and its storage-resizing algorithm) is ported. Returns `storage`
/// unchanged, mirroring an implementation that could not find room to grow/shrink.
pub fn resize_storage(
    storage: Box<dyn VariableStorage>,
    data_type: &dyn DataType,
    align: bool,
    function: &dyn Function,
) -> Box<dyn VariableStorage> {
    let _ = (data_type, align, function);
    storage
}

/// Placeholder for `ghidra.program.model.pcode.DynamicEntry`, referenced by
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real class (and the `DynamicHash` algorithm backing its static `build` factory) are
/// ported. Computes a placeholder hash directly from the representative varnode's address/space
/// rather than running the real `DynamicHash` algorithm, which is out of scope for this
/// placeholder; this keeps the value stable and specific to a given varnode without needing the
/// real hashing scheme.
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    hash: i64,
    pc_address: Option<Address>,
}

impl DynamicEntry {
    /// Stands in for the static `DynamicEntry.build(Varnode)`.
    pub fn build(representative: &Varnode) -> Self {
        DynamicEntry {
            hash: representative.get_offset() ^ ((representative.get_space_id() as i64) << 32),
            pc_address: Some(representative.get_address().clone()),
        }
    }

    /// Stands in for `DynamicEntry.getStorage()`.
    pub fn get_storage(&self) -> Box<dyn VariableStorage> {
        Box::new(HashVariableStorage(self.hash))
    }

    /// Stands in for `DynamicEntry.getPCAdress()`.
    pub fn get_pc_address(&self) -> Option<Address> {
        self.pc_address.clone()
    }

    /// Stands in for `DynamicEntry.getHash()`.
    #[allow(dead_code)]
    pub fn get_hash(&self) -> i64 {
        self.hash
    }
}

/// Placeholder for `ghidra.program.model.pcode.UnionFacetSymbol`, referenced by
/// [`HighFunctionDBUtil::write_union_facet`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::write_union_facet)
/// before the real class is ported. Exposes only the static naming/type-check helpers that method
/// needs; the real class's DB persistence is handled directly by `write_union_facet` via the
/// [`DatabaseVariableImpl`] stub.
pub mod union_facet_symbol {
    use super::{Address, DataType};

    /// Stands in for `UnionFacetSymbol.BASENAME`.
    pub const BASENAME: &str = "unionfacet";

    /// Stands in for `UnionFacetSymbol.isUnionType(DataType)`.
    pub fn is_union_type(dt: &dyn DataType) -> bool {
        dt.is_union()
    }

    /// Stands in for `UnionFacetSymbol.buildSymbolName(int, Address, boolean)`.
    pub fn build_symbol_name(field_num: i32, addr: &Address, is_addr: bool) -> String {
        if is_addr {
            format!("{BASENAME}_{addr}")
        } else {
            format!("{BASENAME}_{field_num}")
        }
    }
}

/// Placeholder covering three unported, DB-backed Java classes referenced by
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil):
/// `ghidra.program.database.function.ParameterDB`'s construction helper `ParameterImpl`, and
/// `ReturnParameterImpl`/`LocalVariableImpl`. All three are simple, not-yet-persisted
/// `Variable` value holders passed into `Function.updateFunction`/`addLocalVariable`, so one
/// struct covers their shared shape (name, first-use offset, data type, storage, owning
/// program).
pub struct DatabaseVariableImpl {
    name: Option<String>,
    first_use_offset: i32,
    data_type: Arc<dyn DataType>,
    storage: Arc<dyn VariableStorage>,
    program: Arc<dyn crate::program::model::listing::Program>,
    comment: Option<String>,
}

impl DatabaseVariableImpl {
    /// Constructs a new, not-yet-persisted variable value. `name` of `None` mirrors the Java
    /// constructors' default-name behavior (`new ParameterImpl(name, ...)` /
    /// `new LocalVariableImpl(null, ...)`).
    pub fn new(
        name: Option<String>,
        first_use_offset: i32,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        program: Arc<dyn crate::program::model::listing::Program>,
    ) -> Self {
        DatabaseVariableImpl {
            name,
            first_use_offset,
            data_type: Arc::from(data_type),
            storage: Arc::from(storage),
            program,
            comment: None,
        }
    }
}

impl crate::program::model::listing::Variable for DatabaseVariableImpl {
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        _force: bool,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), crate::util::exception::InvalidInputException> {
        self.data_type = Arc::from(data_type);
        self.storage = Arc::from(storage);
        Ok(())
    }

    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), crate::util::exception::InvalidInputException> {
        self.data_type = Arc::from(data_type);
        Ok(())
    }

    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        _align_stack: bool,
        _force: bool,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), crate::util::exception::InvalidInputException> {
        self.data_type = Arc::from(data_type);
        Ok(())
    }

    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.data_type.get_length()
    }

    fn is_valid(&self) -> bool {
        true
    }

    fn get_function(&self) -> Option<Box<dyn Function>> {
        None
    }

    fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
        self.program.clone()
    }

    fn get_source(&self) -> crate::program::model::symbol::SourceType {
        crate::program::model::symbol::SourceType::UserDefined
    }

    fn set_name(
        &mut self,
        name: &str,
        _source: crate::program::model::symbol::SourceType,
    ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
        self.name = Some(name.to_string());
        Ok(())
    }

    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }

    fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        Some(share_variable_storage(&self.storage))
    }

    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.storage.get_first_varnode()
    }

    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.storage.get_first_varnode()
    }

    fn is_stack_variable(&self) -> bool {
        false
    }

    fn has_stack_storage(&self) -> bool {
        false
    }

    fn is_register_variable(&self) -> bool {
        false
    }

    fn get_register(&self) -> Option<RegisterRef> {
        None
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        None
    }

    fn get_min_address(&self) -> Option<Address> {
        self.storage
            .get_first_varnode()
            .map(|vn| vn.get_address().clone())
    }

    fn get_stack_offset(
        &self,
    ) -> Result<i32, crate::program::model::listing::variable::UnsupportedOperationError> {
        Err(crate::program::model::listing::variable::UnsupportedOperationError(
            "not a simple stack variable".to_string(),
        ))
    }

    fn is_memory_variable(&self) -> bool {
        self.storage.is_memory_storage()
    }

    fn is_unique_variable(&self) -> bool {
        self.storage.is_hash_storage()
    }

    fn is_compound_variable(&self) -> bool {
        false
    }

    fn has_assigned_storage(&self) -> bool {
        true
    }

    fn get_first_use_offset(&self) -> i32 {
        self.first_use_offset
    }

    fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
        None
    }

    fn is_equivalent(&self, variable: &dyn crate::program::model::listing::Variable) -> bool {
        self.get_name() == variable.get_name() && self.get_length() == variable.get_length()
    }

    fn compare_to(&self, other: &dyn crate::program::model::listing::Variable) -> std::cmp::Ordering {
        self.get_name().cmp(&other.get_name())
    }
}

/// Placeholder for `ghidra.program.model.data.StandAloneDataTypeManager`, referenced by
/// [`DataTypeArchive`](crate::program::model::listing::data_type_archive::DataTypeArchive)
/// before the real class is ported. `DataTypeArchive` only ever returns this type opaquely, so
/// no members are needed yet.
pub trait StandAloneDataTypeManager {}

/// Placeholder for `ghidra.program.model.data.DefaultDataType`, referenced by
/// [`Undefined::is_undefined`](crate::program::model::data::undefined::is_undefined) (via
/// `DataType::is_default_data_type`) before the real class is ported. `Undefined` only ever
/// checks `instanceof DefaultDataType`, so no members are needed yet.
pub trait DefaultDataType {}

/// Placeholder for `ghidra.program.model.data.PointerType`, referenced by
/// [`PointerTypedefBuilder`](crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder)
/// before the real enum is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PointerType {
    /// Normal absolute pointer offset.
    #[default]
    Default,
    /// Pointer offset relative to program image base.
    ImageBaseRelative,
    /// Pointer offset relative to pointer storage address.
    Relative,
    /// Pointer offset corresponds to file offset within an associated file.
    FileOffset,
}

/// Placeholder for `ghidra.program.model.mem.MemBuffer`, referenced by
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset),
/// [`ArrayStringable`](crate::program::model::data::array_stringable::ArrayStringable),
/// [`Array`](crate::program::model::data::array::Array), and
/// [`Label`](crate::app::plugin::processors::generic::label::Label)
/// before the real interface is ported.
pub trait MemBuffer {
    /// Stands in for `MemBuffer.getAddress()`.
    fn get_address(&self) -> Address;

    /// Stands in for `MemBuffer.isInitializedMemory()`.
    fn is_initialized_memory(&self) -> bool {
        false
    }

    /// Stands in for `buf.getMemory().getAllInitializedAddressSet().contains(buf.getAddress())`,
    /// used by [`Array::get_array_value`](crate::program::model::data::array::Array::get_array_value)
    /// until `Memory`'s address-set queries and `MemBuffer.getAddress()` are ported.
    fn is_at_initialized_memory_address(&self) -> bool {
        false
    }

    /// Stands in for `MemBuffer.getByte(int)`, used by
    /// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType) before the
    /// real interface is ported.
    fn get_byte(&self, offset: i32) -> Result<i8, MemoryAccessException> {
        let _ = offset;
        Err(MemoryAccessException::default())
    }

    /// Stands in for `MemBuffer.getUnsignedByte(int)`, used by
    /// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType) before the
    /// real interface is ported.
    fn get_unsigned_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.get_byte(offset).map(|b| b as u8)
    }

    /// Stands in for `MemBuffer.getShort(int)`, used by
    /// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType) before the
    /// real interface is ported.
    fn get_short(&self, offset: i32) -> Result<i16, MemoryAccessException> {
        let _ = offset;
        Err(MemoryAccessException::default())
    }

    /// Stands in for `MemBuffer.getInt(int)`, used by
    /// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType) before the
    /// real interface is ported.
    fn get_int(&self, offset: i32) -> Result<i32, MemoryAccessException> {
        let _ = offset;
        Err(MemoryAccessException::default())
    }

    /// Stands in for `MemBuffer.getBytes(byte[], int)`, used by
    /// [`AbstractFloatDataType`](crate::program::model::data::abstract_float_data_type::AbstractFloatDataType)
    /// before the real interface is ported. Returns the number of bytes actually copied into
    /// `buffer` starting at `offset`, mirroring the Java method's `int` return (rather than
    /// throwing, unlike the single-value getters above). Named `get_bytes_into` rather than
    /// `get_bytes` to avoid an ambiguous-method clash with the unrelated, already-ported
    /// `CodeUnit::get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException>`.
    fn get_bytes_into(&self, buffer: &mut [u8], offset: i32) -> i32 {
        let _ = (buffer, offset);
        0
    }

    /// Stands in for `MemBuffer.isBigEndian()`, used by
    /// [`AbstractFloatDataType`](crate::program::model::data::abstract_float_data_type::AbstractFloatDataType)
    /// before the real interface is ported.
    fn is_big_endian(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.pcode.floatformat.FloatFormat`, referenced by
/// [`AbstractFloatDataType`](crate::program::model::data::abstract_float_data_type::AbstractFloatDataType)
/// before the real class is ported. Exposes only the members that type's default methods need:
/// decoding raw bytes to a [`BigFloat`], encoding a [`BigFloat`]/`f64` back to bytes, parsing and
/// rounding a decimal string, and rendering a [`BigFloat`] as a decimal string.
///
/// This is a second, independently minimal placeholder for the same eventual Java class as
/// [`crate::pcode::seam_stubs::FloatFormat`] (which only covers what `BigFloat`'s own
/// `to_display_string_with_format` needs); the two should be consolidated into one real
/// `FloatFormat` port once that class is ported.
pub trait FloatFormat {
    /// Stands in for `FloatFormat.decodeBigFloat(long)`.
    fn decode_big_float(&self, value: i64) -> Result<Box<dyn BigFloat>, UnsupportedFloatFormatException>;

    /// Stands in for `FloatFormat.decodeBigFloat(BigInteger)`.
    fn decode_big_float_from_big_integer(
        &self,
        value: i128,
    ) -> Result<Box<dyn BigFloat>, UnsupportedFloatFormatException>;

    /// Stands in for `FloatFormat.getEncoding(double)`.
    fn get_encoding(&self, value: f64) -> i64;

    /// Stands in for `FloatFormat.getEncoding(BigFloat)`.
    fn get_encoding_big_float(&self, value: &dyn BigFloat) -> i128;

    /// Stands in for `FloatFormat.getBigFloat(String)`.
    fn get_big_float(&self, repr: &str) -> Box<dyn BigFloat>;

    /// Stands in for `FloatFormat.round(BigFloat)`, which rounds `value` in place to this
    /// format's precision (distinct from `BigFloat`'s own no-argument `round`).
    fn round(&self, value: &mut dyn BigFloat);

    /// Stands in for `FloatFormat.toDecimalString(BigFloat, boolean)`.
    fn to_decimal_string(&self, value: &dyn BigFloat, use_english: bool) -> String;
}

/// Placeholder for `ghidra.program.model.data.StringDataInstance`, referenced by
/// [`DataTypeWithCharset`](crate::program::model::data::data_type_with_charset::DataTypeWithCharset)
/// and [`ArrayStringable`](crate::program::model::data::array_stringable::ArrayStringable)
/// before the real class is ported.
///
/// Models just the instance methods that `DataTypeWithCharset`'s and `ArrayStringable`'s default
/// methods delegate to once a `StringDataInstance` has been built for a given data
/// type/settings/buffer/length.
pub trait StringDataInstance {
    /// Encode a normalized character value (one code point, as one or two UTF-16 style chars)
    /// as replacement bytes.
    fn encode_replacement_from_char_value(&self, value: &[char]) -> Result<Vec<u8>, String>;

    /// Encode a single-character string representation as replacement bytes.
    fn encode_replacement_from_char_representation(&self, repr: &str) -> Result<Vec<u8>, String>;

    /// Stands in for `StringDataInstance.getStringValue()`.
    fn get_string_value(&self) -> Option<String> {
        None
    }
}

/// Placeholder for `ghidra.program.model.data.StringDataInstance.DEFAULT_CHARSET_NAME`.
pub const DEFAULT_CHARSET_NAME: &str = "US-ASCII";

/// Placeholder for `ghidra.program.model.listing.CommentType`, referenced by
/// [`CodeUnit`](crate::program::model::listing::code_unit::CodeUnit)
/// before the real enum is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

impl CommentType {
    /// Get the comment type which corresponds to the specified ordinal value. Stands in for
    /// `CommentType.valueOf(int)`.
    pub fn from_ordinal(ordinal: i32) -> Option<Self> {
        match ordinal {
            0 => Some(CommentType::Eol),
            1 => Some(CommentType::Pre),
            2 => Some(CommentType::Post),
            3 => Some(CommentType::Plate),
            4 => Some(CommentType::Repeatable),
            _ => None,
        }
    }
}

/// Placeholder for `ghidra.program.model.symbol.RefType`, referenced by
/// [`Data`](crate::program::model::listing::data::Data)
/// before the real class is ported.
pub trait RefType {}

/// Placeholder for `ghidra.program.model.symbol.Reference`, referenced by
/// [`Data`](crate::program::model::listing::data::Data)
/// before the real interface is ported.
pub trait Reference {}

/// Placeholder for `ghidra.program.model.data.GenericCallingConvention`, referenced by
/// [`FunctionDefinition`](crate::program::model::data::function_definition::FunctionDefinition)
/// before the real enum is ported.
pub trait GenericCallingConvention {}

/// Placeholder for `db.Transaction`, referenced by
/// [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager)
/// before the real class is ported.
pub trait Transaction {}

/// Placeholder for `ghidra.program.util.GroupPath`, referenced by
/// [`Group::get_group_path`](crate::program::model::listing::group::Group::get_group_path)
/// before the real class is ported. Only the construction and access needed by that default
/// method are provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPath {
    group_names: Vec<String>,
}

impl GroupPath {
    /// Construct a new `GroupPath` with the given names, the first being the oldest ancestor and
    /// the last being the youngest descendant in the path.
    pub fn new(group_names: Vec<String>) -> Self {
        GroupPath { group_names }
    }

    /// Returns the array of names that make up this group's path.
    pub fn get_path(&self) -> &[String] {
        &self.group_names
    }
}

pub use crate::program::model::listing::stack_frame::StackFrame;

/// Placeholder for `ghidra.program.model.listing.VariableFilter`, referenced by
/// [`Function`](crate::program::model::listing::function::Function)
/// before the real interface is ported.
pub trait VariableFilter {}

/// Placeholder for `ghidra.program.model.lang.InstructionError.InstructionErrorType`, referenced
/// by [`InstructionBlock`](crate::program::model::lang::instruction_block::InstructionBlock)
/// before the real `InstructionError` class is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionErrorType {
    /// Duplicate instruction detected while instructions were being added to program.
    Duplicate,
    /// Conflict with existing instruction detected while instructions were being added to
    /// program.
    InstructionConflict,
    /// Conflict with existing data detected while instructions were being added to program.
    DataConflict,
    /// Offcut conflict with existing instruction detected while instructions were being added to
    /// program.
    OffcutInstruction,
    /// Instruction parsing failed at the conflict address.
    Parse,
    /// Instruction parsing failed at the conflict address due to a memory error.
    Memory,
    /// Instruction contains an unaligned flow which is indicative of a language problem.
    FlowAlignment,
}

impl InstructionErrorType {
    /// Stands in for `InstructionErrorType.isConflict`: true if this error type is associated
    /// with a conflict with an existing code unit (instruction or data).
    pub fn is_conflict(self) -> bool {
        matches!(
            self,
            InstructionErrorType::Duplicate
                | InstructionErrorType::InstructionConflict
                | InstructionErrorType::DataConflict
                | InstructionErrorType::OffcutInstruction
        )
    }
}

/// Placeholder for `ghidra.program.model.lang.InstructionError`, referenced by
/// [`InstructionBlock`](crate::program::model::lang::instruction_block::InstructionBlock) before
/// the real class is ported. The real class's constructor takes the owning `InstructionBlock`
/// back (`new InstructionError(this, type, ...)`), which is the source of the cycle
/// `InstructionBlock` was cut at; `InstructionBlock` itself never calls a method on the error it
/// holds (only constructs and opaquely returns it), so no members are needed yet.
pub trait InstructionError {}

/// Placeholder for `ghidra.program.model.lang.InstructionBlockFlow`, referenced by
/// [`InstructionBlock`](crate::program::model::lang::instruction_block::InstructionBlock) before
/// the real class is ported. `InstructionBlock` only ever stores and returns this type opaquely,
/// so no members are needed yet.
pub trait InstructionBlockFlow {}

/// Placeholder for `ghidra.program.model.lang.RegisterValue`, referenced by
/// [`ProgramContext`](crate::program::model::listing::program_context::ProgramContext) (which
/// only ever passes this type through) and by
/// [`ProcessorContextView`](crate::program::model::lang::processor_context_view::ProcessorContextView)
/// and its `dump_context_value` helper, before the real class is ported.
pub trait RegisterValue {
    /// The base register this value is associated with.
    fn get_register(&self) -> RegisterRef;

    /// The value associated with a child register of [`RegisterValue::get_register`]'s base
    /// register.
    fn get_register_value(&self, register: &Register) -> Box<dyn RegisterValue>;

    /// True if this value (or mask) has any bits set.
    fn has_any_value(&self) -> bool;

    /// The unsigned value of this register value, ignoring any mask bits.
    fn get_unsigned_value_ignore_mask(&self) -> u128;
}

/// Placeholder for `ghidra.program.model.lang.ParserContext`, referenced by
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
/// before the real interface is ported.
pub trait ParserContext {
    /// Stands in for `ParserContext.getPrototype()`.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype>;
}

/// Placeholder for `ghidra.program.model.lang.Mask`, referenced by
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
/// before the real interface is ported. `InstructionPrototype` only ever returns this type
/// opaquely, so no members are needed yet.
pub trait Mask {}

/// Placeholder for `ghidra.program.model.lang.InstructionContext`, referenced by
/// [`Instruction`](crate::program::model::listing::instruction::Instruction)
/// before the real interface is ported. `Instruction` only ever passes this type through (via
/// `get_instruction_context`), so no members are needed yet.
pub trait InstructionContext {}

/// Placeholder for `ghidra.program.model.listing.FlowOverride`, referenced by
/// [`Instruction`](crate::program::model::listing::instruction::Instruction)
/// before the real enum is ported. `Instruction` only gets/sets this value, so the static
/// `FlowOverride.getModifiedFlowType`/`getFlowOverride` helper logic is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FlowOverride {
    #[default]
    None,
    Branch,
    Call,
    CallReturn,
    Return,
}

/// Placeholder for `ghidra.program.model.listing.CodeUnitIterator`, referenced by
/// [`Listing`](crate::program::model::listing::listing::Listing)
/// before the real interface is ported. `Listing` only ever returns this type (never calls
/// `hasNext`/`next` on it itself), so no members are needed yet.
pub trait CodeUnitIterator {}

/// Placeholder for `ghidra.program.model.listing.InstructionIterator`, referenced by
/// [`Listing`](crate::program::model::listing::listing::Listing)
/// before the real interface is ported.
///
/// [`has_next`](Self::has_next) was added for
/// [`StructureFactory`](crate::program::model::data::structure_factory::StructureFactory), which
/// needs to check whether a candidate address range already contains instructions (mirrors
/// `InstructionIterator.hasNext()`, inherited from `java.util.Iterator`). Defaults to `false` so
/// existing bare `impl InstructionIterator for Foo {}` blocks keep compiling unmodified.
pub trait InstructionIterator {
    /// Stands in for `InstructionIterator.hasNext()`.
    fn has_next(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.program.model.listing.DataIterator`, referenced by
/// [`Listing`](crate::program::model::listing::listing::Listing)
/// before the real interface is ported. `Listing` only ever returns this type, so no members are
/// needed yet.
pub trait DataIterator {}

pub use crate::program::model::listing::function_iterator::FunctionIterator;

/// Placeholder for `ghidra.program.model.listing.InstructionSet`, referenced by
/// [`Listing::add_instructions`](crate::program::model::listing::listing::Listing::add_instructions)
/// before the real class is ported. `Listing` only ever passes this type through, so no members
/// are needed yet.
pub trait InstructionSet {}

/// Placeholder for `ghidra.program.model.listing.CommentHistory`, referenced by
/// [`Listing`](crate::program::model::listing::listing::Listing)
/// before the real class is ported. `Listing` only ever returns this type, so no members are
/// needed yet.
pub trait CommentHistory {}

/// Placeholder for `ghidra.program.model.listing.CodeUnitComments`, referenced by
/// [`Listing::get_all_comments`](crate::program::model::listing::listing::Listing::get_all_comments)
/// before the real class is ported. `Listing` only ever returns this type, so no members are
/// needed yet.
pub trait CodeUnitComments {}

/// Placeholder for `ghidra.program.model.lang.Processor`, referenced by
/// [`Language`](crate::program::model::lang::language::Language) and
/// [`LanguageDescription`](crate::program::model::lang::language_description::LanguageDescription)
/// before the real class is ported. `Language` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait Processor {}

/// Placeholder for `ghidra.program.model.lang.AddressLabelInfo`, referenced by
/// [`Language`](crate::program::model::lang::language::Language)
/// before the real class is ported. `Language` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait AddressLabelInfo {}

/// Placeholder for `ghidra.app.plugin.processors.generic.MemoryBlockDefinition`, referenced by
/// [`Language`](crate::program::model::lang::language::Language)
/// before the real class is ported. `Language` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait MemoryBlockDefinition {}

/// Placeholder for `ghidra.program.model.lang.PcodeInjectLibrary`, referenced by
/// [`CompilerSpec`](crate::program::model::lang::compiler_spec::CompilerSpec)
/// before the real class is ported. `CompilerSpec` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait PcodeInjectLibrary {}

/// Placeholder for `ghidra.program.model.lang.InjectContext`, referenced by
/// [`InjectPayload`](crate::program::model::lang::inject_payload::InjectPayload)
/// before the real class is ported. `InjectPayload` only ever passes this type through, so no
/// members are needed yet.
pub trait InjectContext {}

/// Placeholder for `ghidra.app.plugin.processors.sleigh.PcodeEmit`, referenced by
/// [`InjectPayload`](crate::program::model::lang::inject_payload::InjectPayload)
/// before the real class is ported. `InjectPayload::inject` only ever passes this type through
/// to accumulate p-code, so no members are needed yet.
pub trait PcodeEmit {}

/// Placeholder for `ghidra.program.model.lang.LanguageCompilerSpecPair`, referenced by
/// [`ProgramArchitecture`](crate::program::model::lang::program_architecture::ProgramArchitecture)'s
/// `get_language_compiler_spec_pair` default method, before the real class is ported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageCompilerSpecPair {
    language_id: LanguageID,
    compiler_spec_id: CompilerSpecID,
}

impl LanguageCompilerSpecPair {
    /// Creates a new language and compiler pair.
    pub fn new(language_id: LanguageID, compiler_spec_id: CompilerSpecID) -> Self {
        LanguageCompilerSpecPair {
            language_id,
            compiler_spec_id,
        }
    }

    /// Get the language ID.
    pub fn get_language_id(&self) -> &LanguageID {
        &self.language_id
    }

    /// Get the compiler spec ID.
    pub fn get_compiler_spec_id(&self) -> &CompilerSpecID {
        &self.compiler_spec_id
    }
}

/// Placeholder for `ghidra.program.model.lang.LanguageNotFoundException`, referenced by
/// [`LanguageProvider`](crate::program::model::lang::language_provider::LanguageProvider)
/// before the real exception class is ported. Carries only the formatted message; the real
/// port should retain the `LanguageID`/`Throwable` cause fields from the Java constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageNotFoundException(pub String);

impl fmt::Display for LanguageNotFoundException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LanguageNotFoundException {}

/// Placeholder for `ghidra.program.model.lang.LanguageCompilerSpecQuery`, referenced by
/// [`LanguageService`](crate::program::model::lang::language_service::LanguageService)
/// before the real class is ported. A `None` field mirrors a `null` Java field, meaning
/// "don't care" for that criterion.
pub struct LanguageCompilerSpecQuery {
    pub processor: Option<Box<dyn Processor>>,
    pub endian: Option<Endian>,
    pub size: Option<i32>,
    pub variant: Option<String>,
    pub compiler_spec_id: Option<CompilerSpecID>,
}

impl LanguageCompilerSpecQuery {
    /// Constructs a new `LanguageCompilerSpecQuery`.
    pub fn new(
        processor: Option<Box<dyn Processor>>,
        endian: Option<Endian>,
        size: Option<i32>,
        variant: Option<String>,
        compiler_spec_id: Option<CompilerSpecID>,
    ) -> Self {
        LanguageCompilerSpecQuery {
            processor,
            endian,
            size,
            variant,
            compiler_spec_id,
        }
    }
}

/// Placeholder for `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`, referenced by
/// [`LanguageService`](crate::program::model::lang::language_service::LanguageService)
/// before the real class is ported. Analog to [`LanguageCompilerSpecQuery`], for querying
/// external languages (e.g. IDA-Pro's "metapc").
pub struct ExternalLanguageCompilerSpecQuery {
    pub external_processor_name: Option<String>,
    pub external_tool: Option<String>,
    pub endian: Option<Endian>,
    pub size: Option<i32>,
    pub compiler_spec_id: Option<CompilerSpecID>,
}

impl ExternalLanguageCompilerSpecQuery {
    /// Constructs a new `ExternalLanguageCompilerSpecQuery`.
    pub fn new(
        external_processor_name: Option<String>,
        external_tool: Option<String>,
        endian: Option<Endian>,
        size: Option<i32>,
        compiler_spec_id: Option<CompilerSpecID>,
    ) -> Self {
        ExternalLanguageCompilerSpecQuery {
            external_processor_name,
            external_tool,
            endian,
            size,
            compiler_spec_id,
        }
    }
}

/// Placeholder for `ghidra.program.model.lang.PrototypePieces`, referenced by
/// [`ParamList`](crate::program::model::lang::param_list::ParamList),
/// [`ParamListStandardOut`](crate::program::model::lang::param_list_standard_out::ParamListStandardOut),
/// and
/// [`ParamListStandard`](crate::program::model::lang::param_list_standard::ParamListStandard)
/// before the real class is ported. Only the `outtype` (return data-type) and `intypes` (input
/// data-types) fields are modeled, since those are the only members those interfaces read; the
/// `model`/`firstVarArgSlot` fields are omitted until something needs them. `Debug` is
/// intentionally not derived since `DataType` has no `Debug` supertrait yet.
#[derive(Default, Clone)]
pub struct PrototypePieces {
    /// Return data-type of the prototype (`PrototypePieces.outtype`).
    pub outtype: Option<Arc<dyn DataType>>,
    /// Input data-types of the prototype, in parameter order (`PrototypePieces.intypes`).
    pub intypes: Vec<Arc<dyn DataType>>,
}

/// Placeholder for `ghidra.program.model.lang.ParameterPieces`, referenced by
/// [`ParamList`](crate::program::model::lang::param_list::ParamList),
/// [`ParamListStandardOut`](crate::program::model::lang::param_list_standard_out::ParamListStandardOut),
/// and
/// [`ParamListStandard`](crate::program::model::lang::param_list_standard::ParamListStandard)
/// before the real class is ported. Only the `type`/`isIndirect`/`hiddenReturnPtr`/`address`
/// fields are modeled, since those are the only members those interfaces read or write;
/// `joinPieces` and `isThisPointer` are omitted until something needs them. `Debug` is
/// intentionally not derived since `DataType` has no `Debug` supertrait yet.
#[derive(Default, Clone)]
pub struct ParameterPieces {
    /// The data-type of the parameter (`ParameterPieces.type`; renamed since `type` is a Rust
    /// keyword).
    pub data_type: Option<Arc<dyn DataType>>,
    /// True if parameter is an indirect pointer to the actual parameter
    /// (`ParameterPieces.isIndirect`).
    pub is_indirect: bool,
    /// True if this is an input pointer to return storage (`ParameterPieces.hiddenReturnPtr`).
    pub hidden_return_ptr: bool,
    /// The starting address of the parameter's storage, or `None` if not yet assigned
    /// (`ParameterPieces.address`).
    pub address: Option<Address>,
}

/// Placeholder for `ghidra.program.model.lang.ParamListStandard`, referenced by
/// [`AssignAction`](crate::program::model::lang::protorules::assign_action::AssignAction) and
/// [`ParamListStandardOut`](crate::program::model::lang::param_list_standard_out::ParamListStandardOut)
/// before the real class is ported. `AssignAction::clone_box` only ever receives this type
/// opaquely, but `ParamListStandardOut::assign_map_out` needs the inherited `numgroup`,
/// `spacebase`, and `assignAddress` behavior, so those are modeled here as provided methods with
/// placeholder defaults; real implementations are expected to override them.
pub trait ParamListStandardLike {
    /// Number of parameter "groups" in this parameter convention (`ParamListStandard.numgroup`).
    fn num_group(&self) -> i32 {
        0
    }

    /// Space containing relative offset parameters (`ParamListStandard.spacebase`), or `None`.
    fn spacebase(&self) -> Option<Arc<AddressSpace>> {
        None
    }

    /// Inherited address-assignment behavior (`ParamListStandard.assignAddress`). Defaults to
    /// always failing, since no concrete resource list is available in this placeholder.
    fn assign_address(
        &self,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        let _ = (dt, proto, pos, dt_manager, status, res);
        crate::program::model::lang::protorules::assign_action::FAIL
    }
}

/// Placeholder for `ghidra.program.model.lang.ParamEntry`, referenced by
/// [`ParamListStandard`](crate::program::model::lang::param_list_standard::ParamListStandard)
/// before the real class is ported. Exposes only the accessors that trait's default methods
/// read (and the one method, `get_addr_by_slot`, that mutates a [`ParameterPieces`]); the real
/// slot-allocation algorithm, XML restore, and join-space handling live on the concrete class.
pub trait ParamEntryLike {
    /// Stands in for `ParamEntry.getSpace()`. Left required since there is no universally
    /// sensible placeholder address space.
    fn get_space(&self) -> Arc<AddressSpace>;

    /// Stands in for `ParamEntry.getGroup()`.
    fn get_group(&self) -> i32 {
        0
    }

    /// Stands in for `ParamEntry.getAllGroups()`.
    fn get_all_groups(&self) -> Vec<i32> {
        vec![self.get_group()]
    }

    /// Stands in for `ParamEntry.getMinSize()`.
    fn get_min_size(&self) -> i32 {
        0
    }

    /// Stands in for `ParamEntry.getSize()`.
    fn get_size(&self) -> i32 {
        0
    }

    /// Stands in for `ParamEntry.getAlign()`.
    fn get_align(&self) -> i32 {
        0
    }

    /// Stands in for `ParamEntry.getAddressBase()`.
    fn get_address_base(&self) -> i64 {
        0
    }

    /// Stands in for `ParamEntry.getType()`.
    fn get_type(&self) -> crate::program::model::lang::storage_class::StorageClass {
        crate::program::model::lang::storage_class::StorageClass::General
    }

    /// Stands in for `ParamEntry.isExclusion()`.
    fn is_exclusion(&self) -> bool {
        false
    }

    /// Stands in for `ParamEntry.isReverseStack()`.
    fn is_reverse_stack(&self) -> bool {
        false
    }

    /// Stands in for `ParamEntry.isGrouped()`.
    fn is_grouped(&self) -> bool {
        false
    }

    /// Stands in for `ParamEntry.isBigEndian()`.
    fn is_big_endian(&self) -> bool {
        false
    }

    /// Stands in for `ParamEntry.justifiedContain(Address, int)`. Defaults to "does not
    /// contain", mirroring an entry in an unrelated address space.
    fn justified_contain(&self, loc: &Address, size: i32) -> i32 {
        let _ = (loc, size);
        -1
    }

    /// Stands in for `ParamEntry.getSlot(Address, int)`.
    fn get_slot(&self, loc: &Address, skip: i32) -> i32 {
        let _ = (loc, skip);
        0
    }

    /// Stands in for `ParamEntry.getAddrBySlot(int, int, int, ParameterPieces)`; the real method
    /// allocates from consumed resource slots and writes the resulting address into
    /// `param.address`. This default never finds room (leaves `param.address` as `None`),
    /// mirroring an entry with no free slots.
    fn get_addr_by_slot(
        &self,
        slot_num: i32,
        size: i32,
        align: i32,
        param: &mut ParameterPieces,
    ) -> i32 {
        let _ = (size, align);
        param.address = None;
        slot_num
    }

    /// Stands in for `ParamEntry.encode(Encoder)`.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let _ = encoder;
        Ok(())
    }

    /// Stands in for `ParamEntry.isEquivalent(ParamEntry)`.
    fn is_equivalent(&self, other: &dyn ParamEntryLike) -> bool {
        let _ = other;
        false
    }
}

/// Placeholder for `ghidra.program.model.lang.protorules.ModelRule`, referenced by
/// [`ParamListStandard`](crate::program::model::lang::param_list_standard::ParamListStandard)
/// before the real class is ported. Exposes only the members that trait's default methods need;
/// `DatatypeFilter`/`QualifierFilter`/precondition and side-effect `AssignAction` handling live
/// on the concrete class.
pub trait ModelRuleLike {
    /// Stands in for `ModelRule.assignAddress(...)`. Defaults to always failing, mirroring a
    /// rule whose filter never matches.
    fn assign_address(
        &self,
        dt: &Arc<dyn DataType>,
        proto: &PrototypePieces,
        pos: i32,
        dt_manager: &dyn DataTypeManager,
        status: &mut [i32],
        res: &mut ParameterPieces,
    ) -> i32 {
        let _ = (dt, proto, pos, dt_manager, status, res);
        crate::program::model::lang::protorules::assign_action::FAIL
    }

    /// Stands in for `ModelRule.encode(Encoder)`.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()> {
        let _ = encoder;
        Ok(())
    }

    /// Stands in for `ModelRule.isEquivalent(ModelRule)`.
    fn is_equivalent(&self, other: &dyn ModelRuleLike) -> bool {
        let _ = other;
        false
    }
}

/// Placeholder for `ghidra.program.model.data.VoidDataType`'s static `isVoidDataType` helper,
/// referenced by
/// [`ParamListStandardOut`](crate::program::model::lang::param_list_standard_out::ParamListStandardOut)
/// before the real class is ported. The Java method also unwraps a `TypeDef` to its base type
/// before testing; that step is omitted here since it needs supertrait downcasting this crate
/// does not rely on elsewhere; any real `VoidDataType` port should override
/// [`DataType::is_void_type`](crate::program::model::data::data_type::DataType::is_void_type) so
/// this check keeps working unchanged.
pub fn is_void_data_type(dt: Option<&dyn DataType>) -> bool {
    dt.is_some_and(DataType::is_void_type)
}

/// Placeholder for `ghidra.program.database.mem.FileBytes`, referenced by
/// [`MemoryBlockSourceInfo`](crate::program::model::mem::memory_block_source_info::MemoryBlockSourceInfo)
/// before the real class is ported. `MemoryBlockSourceInfo` only ever returns this type opaquely,
/// so no members are needed yet.
pub trait FileBytes {}

/// Placeholder for `ghidra.program.database.mem.ByteMappingScheme`, referenced by
/// [`MemoryBlockSourceInfo`](crate::program::model::mem::memory_block_source_info::MemoryBlockSourceInfo)
/// before the real class is ported. `MemoryBlockSourceInfo` only ever returns this type opaquely,
/// so no members are needed yet.
pub trait ByteMappingScheme {}

/// Placeholder for `ghidra.program.model.data.CharsetSettingsDefinition`, referenced by
/// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType)
/// before the real class is ported. Only the `CHARSET` singleton and its `getCharset` accessor
/// are modeled; it also implements [`SettingsDefinition`] with the real name/storage
/// key/description so it can be placed alongside genuine settings definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CharsetSettingsDefinition;

impl CharsetSettingsDefinition {
    /// The singleton instance of this settings definition.
    pub const CHARSET: CharsetSettingsDefinition = CharsetSettingsDefinition;

    /// Stands in for `CharsetSettingsDefinition.getCharset(Settings, String)`.
    pub fn get_charset(&self, settings: &dyn Settings, default_value: &str) -> String {
        settings
            .get_string("charset")
            .unwrap_or_else(|| default_value.to_string())
    }
}

impl SettingsDefinition for CharsetSettingsDefinition {
    fn get_name(&self) -> String {
        "Charset".to_string()
    }

    fn get_storage_key(&self) -> String {
        "charset".to_string()
    }

    fn get_description(&self) -> String {
        "Character set".to_string()
    }

    fn has_value(&self, settings: &dyn Settings) -> bool {
        settings.get_value("charset").is_some()
    }

    fn get_value_string(&self, settings: &dyn Settings) -> Option<String> {
        settings.get_string("charset")
    }

    fn clear(&self, settings: &mut dyn Settings) {
        settings.clear_setting("charset");
    }
}

/// Placeholder for `ghidra.util.charset.CharsetInfoManager.UTF16`, referenced by
/// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType)
/// before the real class is ported.
pub const CHARSET_UTF16: &str = "UTF-16";

/// Placeholder for `ghidra.util.charset.CharsetInfoManager.UTF32`, referenced by
/// [`CharDataType`](crate::program::model::data::char_data_type::CharDataType)
/// before the real class is ported.
pub const CHARSET_UTF32: &str = "UTF-32";

/// Placeholder for `ghidra.program.database.ProgramOverlayAddressSpace`, referenced by
/// [`ProgramAddressFactory`](crate::program::database::program_address_factory::ProgramAddressFactory)
/// before the real class is ported. Only the accessors that `ProgramAddressFactory` calls
/// directly are modeled: its ordered key and (display) name, used to detect a stale overlay
/// condition, and the ability to invalidate its cached defined region.
pub trait ProgramOverlayAddressSpace {
    /// Stands in for `ProgramOverlayAddressSpace.getOrderedKey()` (inherited from
    /// `OverlayAddressSpace`). This is the unique, DB-stable key used internally to identify the
    /// overlay space, which may drift from [`ProgramOverlayAddressSpace::get_name`] after a
    /// rename.
    fn get_ordered_key(&self) -> &str;

    /// Stands in for `ProgramOverlayAddressSpace.getName()`, the current display name of the
    /// overlay space.
    fn get_name(&self) -> &str;

    /// Stands in for `ProgramOverlayAddressSpace.invalidate()`, which clears the cached defined
    /// address set so it will be recomputed via `OverlayRegionSupplier` on next access.
    fn invalidate(&self);
}

/// Placeholder for `ghidra.program.model.block.CodeBlock`, referenced by
/// [`CodeBlockIterator`](crate::program::model::block::code_block_iterator::CodeBlockIterator),
/// [`CodeBlockReference`](crate::program::model::block::code_block_reference::CodeBlockReference),
/// and
/// [`SubroutineDestReferenceIterator`](crate::program::model::block::subroutine_dest_reference_iterator)
/// before the real interface is ported. `get_min_address`/`contains` default to the values for an
/// empty/unbounded block so pre-existing bare `impl CodeBlock for Foo {}` blocks keep compiling;
/// `get_model`/`get_destinations` are left required since there is no generic placeholder
/// `CodeBlockModel`/`CodeBlockReferenceIterator` to hand back.
pub trait CodeBlock {
    /// Stands in for `CodeBlock.getMinAddress()`.
    fn get_min_address(&self) -> Option<Address> {
        None
    }

    /// Stands in for `CodeBlock.getModel()`.
    fn get_model(&self) -> Box<dyn CodeBlockModel>;

    /// Stands in for `CodeBlock.contains(Address)`.
    fn contains(&self, address: &Address) -> bool {
        let _ = address;
        false
    }

    /// Stands in for `CodeBlock.getDestinations(TaskMonitor)`.
    fn get_destinations(
        &self,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException>;
}

/// Placeholder for `ghidra.program.model.symbol.FlowType`, referenced by
/// [`CodeBlockReference`](crate::program::model::block::code_block_reference::CodeBlockReference)
/// and
/// [`SubroutineDestReferenceIterator`](crate::program::model::block::subroutine_dest_reference_iterator)
/// before the real enum is ported. All members default to `false` so pre-existing bare
/// `impl FlowType for Foo {}` blocks keep compiling.
pub trait FlowType {
    /// Stands in for `FlowType.isCall()`.
    fn is_call(&self) -> bool {
        false
    }

    /// Stands in for `FlowType.isJump()`.
    fn is_jump(&self) -> bool {
        false
    }

    /// Stands in for `FlowType.isFallthrough()`.
    fn is_fallthrough(&self) -> bool {
        false
    }
}

/// Placeholder for `ghidra.program.model.data.SignedDWordDataType`, referenced by
/// [`DWordDataType`](crate::program::model::data::dword_data_type::DWordDataType)
/// before the real class is ported. `DWordDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait SignedDWordDataType {}

/// Placeholder for `ghidra.program.model.data.SignedQWordDataType`, referenced by
/// [`QWordDataType`](crate::program::model::data::qword_data_type::QWordDataType)
/// before the real class is ported. `QWordDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait SignedQWordDataType {}

/// Placeholder for `ghidra.program.model.data.SignedWordDataType`, referenced by
/// [`WordDataType`](crate::program::model::data::word_data_type::WordDataType)
/// before the real class is ported. `WordDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait SignedWordDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedIntegerDataType`, referenced by
/// [`IntegerDataType`](crate::program::model::data::integer_data_type::IntegerDataType)
/// before the real class is ported. `IntegerDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedIntegerDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedShortDataType`, referenced by
/// [`ShortDataType`](crate::program::model::data::short_data_type::ShortDataType)
/// before the real class is ported. `ShortDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedShortDataType {}

/// Placeholder for `ghidra.program.model.data.UInt16TDataType`, referenced by
/// [`Int16TDataType`](crate::program::model::data::int16_t_data_type::Int16TDataType)
/// before the real class is ported. `Int16TDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UInt16TDataType {}

/// Placeholder for `ghidra.program.model.data.UInt64TDataType`, referenced by
/// [`Int64TDataType`](crate::program::model::data::int64_t_data_type::Int64TDataType)
/// before the real class is ported. `Int64TDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UInt64TDataType {}

/// Placeholder for `ghidra.program.model.data.UInt32TDataType`, referenced by
/// [`Int32TDataType`](crate::program::model::data::int32_t_data_type::Int32TDataType)
/// before the real class is ported. `Int32TDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UInt32TDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedPointerSizedIntegerDataType`, referenced by
/// [`PointerSizedIntegerDataType`](crate::program::model::data::pointer_sized_integer_data_type::PointerSizedIntegerDataType)
/// before the real class is ported. `PointerSizedIntegerDataType` only ever returns this type
/// opaquely (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedPointerSizedIntegerDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedInteger16DataType`, referenced by
/// [`Integer16DataType`](crate::program::model::data::integer16_data_type::Integer16DataType)
/// before the real class is ported. `Integer16DataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedInteger16DataType {}

/// Placeholder for `ghidra.program.model.data.UInt8TDataType`, referenced by
/// [`Int8TDataType`](crate::program::model::data::int8_t_data_type::Int8TDataType)
/// before the real class is ported. `Int8TDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UInt8TDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedInteger3DataType`, referenced by
/// [`Integer3DataType`](crate::program::model::data::integer3_data_type::Integer3DataType)
/// before the real class is ported. `Integer3DataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedInteger3DataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedInteger5DataType`, referenced by
/// [`Integer5DataType`](crate::program::model::data::integer5_data_type::Integer5DataType)
/// before the real class is ported. `Integer5DataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedInteger5DataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedInteger6DataType`, referenced by
/// [`Integer6DataType`](crate::program::model::data::integer6_data_type::Integer6DataType)
/// before the real class is ported. `Integer6DataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedInteger6DataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedInteger7DataType`, referenced by
/// [`Integer7DataType`](crate::program::model::data::integer7_data_type::Integer7DataType)
/// before the real class is ported. `Integer7DataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedInteger7DataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedLongDataType`, referenced by
/// [`LongDataType`](crate::program::model::data::long_data_type::LongDataType) before the real
/// class is ported. `LongDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedLongDataType {}

/// Placeholder for `ghidra.program.model.data.UnsignedLongLongDataType`, referenced by
/// [`LongLongDataType`](crate::program::model::data::long_long_data_type::LongLongDataType)
/// before the real class is ported. `LongLongDataType` only ever returns this type opaquely
/// (from `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UnsignedLongLongDataType {}

/// Port of `ghidra.program.model.pcode.PcodeBlock`'s `PLAIN`..`INFLOOP` type-tag constants and
/// its `typeToName` static helper, referenced by
/// [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph)'s `encodeBody` override
/// before the rest of `PcodeBlock` is ported. The full table is reproduced (rather than just
/// `GRAPH`) since `typeToName` must handle whatever type tag a contained block reports.
pub const PCODE_BLOCK_PLAIN: i32 = 0;
pub const PCODE_BLOCK_BASIC: i32 = 1;
pub const PCODE_BLOCK_GRAPH: i32 = 2;
pub const PCODE_BLOCK_COPY: i32 = 3;
pub const PCODE_BLOCK_GOTO: i32 = 4;
pub const PCODE_BLOCK_MULTIGOTO: i32 = 5;
pub const PCODE_BLOCK_LIST: i32 = 6;
pub const PCODE_BLOCK_CONDITION: i32 = 7;
pub const PCODE_BLOCK_PROPERIF: i32 = 8;
pub const PCODE_BLOCK_IFELSE: i32 = 9;
pub const PCODE_BLOCK_IFGOTO: i32 = 10;
pub const PCODE_BLOCK_WHILEDO: i32 = 11;
pub const PCODE_BLOCK_DOWHILE: i32 = 12;
pub const PCODE_BLOCK_SWITCH: i32 = 13;
pub const PCODE_BLOCK_INFLOOP: i32 = 14;

/// Stands in for `PcodeBlock.typeToName(int)`. Returns `None` for an unrecognized type tag,
/// mirroring the Java method's `return null` fallthrough.
pub fn pcode_block_type_to_name(block_type: i32) -> Option<&'static str> {
    match block_type {
        PCODE_BLOCK_PLAIN => Some("plain"),
        PCODE_BLOCK_BASIC => Some("basic"),
        PCODE_BLOCK_GRAPH => Some("graph"),
        // "this a trick for the decompiler c-side"
        PCODE_BLOCK_COPY => Some("plain"),
        PCODE_BLOCK_GOTO => Some("goto"),
        PCODE_BLOCK_MULTIGOTO => Some("multigoto"),
        PCODE_BLOCK_LIST => Some("list"),
        PCODE_BLOCK_CONDITION => Some("condition"),
        PCODE_BLOCK_PROPERIF => Some("properif"),
        PCODE_BLOCK_IFELSE => Some("ifelse"),
        PCODE_BLOCK_IFGOTO => Some("ifgoto"),
        PCODE_BLOCK_WHILEDO => Some("whiledo"),
        PCODE_BLOCK_DOWHILE => Some("dowhile"),
        PCODE_BLOCK_SWITCH => Some("switch"),
        PCODE_BLOCK_INFLOOP => Some("infloop"),
        _ => None,
    }
}

/// Placeholder for `ghidra.program.model.pcode.PcodeBlock`, referenced by
/// [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph) (which extends it, and
/// stores/inspects sibling and child blocks of this type) before the real class is ported.
///
/// Exposes only the members `BlockGraph`'s own logic touches: the inherited `index` field
/// accessors, the inherited `blocktype` field getter, the protected `addInEdge`, and the
/// protected `encodeBody`/`decodeBody` overrides `BlockGraph` composes with its own (both
/// default to a no-op, matching `PcodeBlock`'s own "no body by default" implementation), plus
/// the public `encode`/`decode` wrappers used to (de)serialize each block in `BlockGraph`'s
/// list. `addInEdge`, `encode`, and `decode` are left as required methods since their real
/// bodies depend on `PcodeBlock`'s `BlockEdge` in/out-edge bookkeeping, which is out of scope
/// for this placeholder.
///
/// Setters use `&self` (implying interior mutability in the real implementation), matching this
/// crate's existing convention for shared, graph-like nodes (e.g.
/// `Decoder::set_address_factory` in `crate::program::model::pcode::decoder`) and allowing
/// blocks to be shared (via `Arc`) between a container's list and its edges.
///
/// The write-only `parent` back-pointer assignment (`bl.parent = this` in
/// `BlockGraph.addBlock`) is not modeled: `BlockGraph.java` never reads it back within its own
/// source, and faithfully representing a self-referential parent pointer needs the real port's
/// chosen ownership model (e.g. `Weak`/arena index), not this placeholder.
pub trait PcodeBlock {
    /// Stands in for the inherited `index` field getter (`PcodeBlock.getIndex()`).
    fn get_index(&self) -> i32;

    /// Stands in for the inherited `index` field setter (`PcodeBlock.setIndex(int)`).
    fn set_index(&self, index: i32);

    /// Stands in for the inherited `blocktype` field getter (`PcodeBlock.getType()`).
    fn get_block_type(&self) -> i32;

    /// Stands in for the protected `PcodeBlock.addInEdge(PcodeBlock, int)`.
    fn add_in_edge(&self, begin: Arc<dyn PcodeBlock>, label: i32);

    /// Stands in for the protected `PcodeBlock.encodeBody(Encoder)`. Defaults to a no-op,
    /// matching `PcodeBlock`'s own default ("no body by default").
    fn encode_body(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
        Ok(())
    }

    /// Stands in for the protected `PcodeBlock.decodeBody(Decoder, BlockMap)`. Defaults to a
    /// no-op, matching `PcodeBlock`'s own default ("no body to restore by default").
    fn decode_body(
        &self,
        _decoder: &dyn Decoder,
        _resolver: &dyn BlockMap,
    ) -> Result<(), DecoderException> {
        Ok(())
    }

    /// Stands in for the public `PcodeBlock.encode(Encoder)`, used by `BlockGraph.encodeBody` to
    /// encode each child block in its list.
    fn encode(&self, encoder: &mut dyn Encoder) -> std::io::Result<()>;

    /// Stands in for the public `PcodeBlock.decode(Decoder, BlockMap)`, used by
    /// `BlockGraph.decodeBody` to decode each newly-created child block.
    fn decode(&self, decoder: &dyn Decoder, resolver: &dyn BlockMap)
        -> Result<(), DecoderException>;

    /// Returns this block viewed as a
    /// [`BlockGraph`](crate::program::model::pcode::block_graph::BlockGraph) when it is one.
    /// Mirrors the `instanceof BlockGraph` checks in `BlockGraph.addBlock` and
    /// `BlockGraph.transferObjectRef`. Defaults to `None`; `BlockGraph` implementations
    /// override it to return `Some(self)`.
    fn as_block_graph(&self) -> Option<&dyn crate::program::model::pcode::block_graph::BlockGraph> {
        None
    }

    /// Returns this block viewed as a [`BlockCopy`] when it is one. Mirrors the `instanceof
    /// BlockCopy` check in `BlockGraph.transferObjectRef`. Defaults to `None`.
    fn as_block_copy(&self) -> Option<&dyn BlockCopy> {
        None
    }

    /// Stands in for the inherited `parent` field getter (`PcodeBlock.getParent()`), used by
    /// [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
    /// to walk up from a goto's root block by the recorded depth. Defaults to `None`, matching an
    /// unparented (e.g. top-level) block.
    fn get_parent(&self) -> Option<Arc<dyn PcodeBlock>> {
        None
    }

    /// Returns this block viewed as a [`BlockGoto`] when it is one. Mirrors the `instanceof
    /// BlockGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_goto(&self) -> Option<&dyn BlockGoto> {
        None
    }

    /// Returns this block viewed as a [`BlockIfGoto`] when it is one. Mirrors the `instanceof
    /// BlockIfGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_if_goto(&self) -> Option<&dyn BlockIfGoto> {
        None
    }

    /// Returns this block viewed as a [`BlockMultiGoto`] when it is one. Mirrors the `instanceof
    /// BlockMultiGoto` check in `BlockMap.resolveGotoReferences`. Defaults to `None`.
    fn as_block_multi_goto(&self) -> Option<&dyn BlockMultiGoto> {
        None
    }
}

/// Stands in for `PcodeBlock.nameToType(String)`, used by
/// [`BlockMap::create_block`](crate::program::model::pcode::block_map::BlockMap::create_block) to
/// resolve an XML element name back to a block type tag. Returns `-1` for an unrecognized name,
/// mirroring the Java method's fallthrough (including its "basic" gap: `nameToType` never
/// recognizes the name `typeToName` produces for [`PCODE_BLOCK_BASIC`]).
pub fn pcode_block_name_to_type(name: &str) -> i32 {
    match name.chars().next() {
        Some('c') => PCODE_BLOCK_COPY,
        Some('d') => PCODE_BLOCK_DOWHILE,
        Some('g') => {
            if name == "goto" {
                PCODE_BLOCK_GOTO
            } else {
                PCODE_BLOCK_GRAPH
            }
        }
        Some('i') => {
            if name == "ifelse" {
                PCODE_BLOCK_IFELSE
            } else if name == "infloop" {
                PCODE_BLOCK_INFLOOP
            } else {
                PCODE_BLOCK_IFGOTO
            }
        }
        Some('l') => PCODE_BLOCK_LIST,
        Some('m') => PCODE_BLOCK_MULTIGOTO,
        Some('p') => {
            if name == "properif" {
                PCODE_BLOCK_PROPERIF
            } else {
                PCODE_BLOCK_PLAIN
            }
        }
        Some('s') => PCODE_BLOCK_SWITCH,
        Some('w') => PCODE_BLOCK_WHILEDO,
        _ => -1,
    }
}

/// Placeholder for `ghidra.program.model.pcode.BlockCopy`, referenced by
/// [`BlockGraph::transfer_object_ref`](crate::program::model::pcode::block_graph::BlockGraph::transfer_object_ref)
/// before the real class is ported. Exposes only the members that method needs: the alternate
/// index used to correlate a copy block with the original graph's copy block, the opaque
/// underlying-block reference and start address, and the setter used to transfer both from one
/// copy block to another.
pub trait BlockCopy {
    /// Stands in for `BlockCopy.getAltIndex()`.
    fn get_alt_index(&self) -> i32;

    /// Stands in for `BlockCopy.getRef()`. Modeled as an opaque `Any` handle, mirroring the
    /// Java field's `Object` type.
    fn get_ref(&self) -> Option<Arc<dyn Any + Send + Sync>>;

    /// Stands in for `BlockCopy.getStart()` (the `PcodeBlock.getStart()` override).
    fn get_start(&self) -> Address;

    /// Stands in for the protected `BlockCopy.set(Object, Address)`.
    fn set(&self, r: Option<Arc<dyn Any + Send + Sync>>, addr: Address);
}

/// Placeholder for `ghidra.program.model.pcode.BlockGoto`, referenced by
/// [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
/// before the real class is ported. Exposes only the setter that method needs.
pub trait BlockGoto {
    /// Stands in for `BlockGoto.setGotoTarget(PcodeBlock)`.
    fn set_goto_target(&self, target: Arc<dyn PcodeBlock>);
}

/// Placeholder for `ghidra.program.model.pcode.BlockIfGoto`, referenced by
/// [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
/// before the real class is ported. Exposes only the setter that method needs.
pub trait BlockIfGoto {
    /// Stands in for `BlockIfGoto.setGotoTarget(PcodeBlock)`.
    fn set_goto_target(&self, target: Arc<dyn PcodeBlock>);
}

/// Placeholder for `ghidra.program.model.pcode.BlockMultiGoto`, referenced by
/// [`BlockMap::resolve_goto_references`](crate::program::model::pcode::block_map::BlockMap::resolve_goto_references)
/// before the real class is ported. Exposes only the mutator that method needs.
pub trait BlockMultiGoto {
    /// Stands in for `BlockMultiGoto.addGotoTarget(PcodeBlock)`.
    fn add_goto_target(&self, target: Arc<dyn PcodeBlock>);
}

/// Placeholder for `ghidra.program.model.pcode.HighSymbol`, referenced by
/// [`GlobalSymbolMap`](crate::program::model::pcode::global_symbol_map::GlobalSymbolMap) and
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real class is ported. `GlobalSymbolMap` only ever reads the id used to key its
/// lookup maps and reconcile its next-available synthetic id counter (`insertSymbol`'s use of
/// `HighSymbol.getId()`/`HighSymbol.ID_BASE`). The remaining accessors were added for
/// `HighFunctionDBUtil`, all defaulted so `GlobalSymbolMap`'s existing bare impls keep compiling;
/// `get_high_function` is left required since there is no sensible placeholder `HighFunction` to
/// hand back.
pub trait HighSymbol: Send + Sync {
    /// Stands in for `HighSymbol.getId()`.
    fn get_id(&self) -> i64;

    /// Stands in for `HighSymbol.getHighFunction()`.
    fn get_high_function(&self) -> Arc<dyn HighFunction>;

    /// Stands in for `HighSymbol.getName()`.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Stands in for `HighSymbol.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    /// Stands in for `HighSymbol.getSize()`.
    fn get_size(&self) -> i32 {
        0
    }

    /// Stands in for `HighSymbol.getStorage()`.
    fn get_storage(&self) -> Box<dyn VariableStorage> {
        Box::new(PlaceholderVariableStorage)
    }

    /// Stands in for `HighSymbol.getPCAddress()`.
    fn get_pc_address(&self) -> Option<Address> {
        None
    }

    /// Stands in for `HighSymbol.getHighVariable()`.
    fn get_high_variable(&self) -> Option<Box<dyn HighVariable>> {
        None
    }

    /// Stands in for `HighSymbol.isParameter()`.
    fn is_parameter(&self) -> bool {
        false
    }

    /// Stands in for `HighSymbol.isGlobal()`.
    fn is_global(&self) -> bool {
        false
    }

    /// Stands in for `((HighParam) highSymbol.getHighVariable()).getSlot()`, narrowed onto
    /// `HighSymbol` itself as `HighSymbol.getCategoryIndex()` (the parameter slot a `HighSymbol`
    /// occupies), since the real `HighParam` downcast is not modeled separately here.
    fn get_category_index(&self) -> i32 {
        0
    }

    /// Simplified stand-in for `symbol.getFirstWholeMap() instanceof DynamicEntry ?
    /// ((DynamicEntry) symbol.getFirstWholeMap()).getHash() : null`, used by
    /// `HighFunctionDBUtil`'s private `isValidUniqueVariable` helper. The real `SymbolEntry`/
    /// `DynamicEntry` class hierarchy is not modeled separately here; implementors backed by a
    /// dynamic (hash-addressed) entry are expected to override this to return that entry's hash.
    fn get_dynamic_hash(&self) -> Option<i64> {
        None
    }
}

/// Placeholder for `ghidra.program.model.pcode.HighFunction`, referenced by
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real class is ported. Exposes only the accessors that utility's default methods
/// read: the underlying database [`Function`] being annotated, the decompiler's recovered
/// parameter/return model, the compiler spec used to resolve calling-convention names, and the
/// local variable/parameter symbol table. `get_function`/`get_compiler_spec`/
/// `get_local_symbol_map` are left required since there is no sensible placeholder `Function`/
/// `CompilerSpec`/`LocalSymbolMap` to hand back.
pub trait HighFunction: Send + Sync {
    /// Stands in for `HighFunction.getFunction()`.
    fn get_function(&self) -> Box<dyn Function>;

    /// Stands in for `HighFunction.getFunctionPrototype()`. Defaults to `None`, mirroring a
    /// `HighFunction` built without a recovered prototype.
    fn get_function_prototype(&self) -> Option<Box<dyn FunctionPrototype>> {
        None
    }

    /// Stands in for `HighFunction.getCompilerSpec()`.
    fn get_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec>;

    /// Stands in for `HighFunction.getLocalSymbolMap()`.
    fn get_local_symbol_map(&self) -> Box<dyn LocalSymbolMap>;

    /// Stands in for `HighFunction.getGlobalSymbolMap()`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    /// Left required since there is no sensible placeholder `GlobalSymbolMap` to hand back (its
    /// `new_symbol`/`populate_symbol` mutators have no meaningful default behavior).
    fn get_global_symbol_map(&self) -> Arc<dyn GlobalSymbolMap>;

    /// Stands in for `HighFunction.getPCAddress(Varnode)`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    /// Defaults to `None`, mirroring a `HighFunction` that cannot resolve the defining p-code
    /// op's address for the given representative varnode.
    fn get_pc_address(&self, representative: &Varnode) -> Option<Address> {
        let _ = representative;
        None
    }
}

/// Stands in for the static `HighFunction.findCreateOverrideSpace(Function)`, used by
/// [`HighFunctionDBUtil::write_override`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::write_override)
/// before the real `HighFunction` (and the DB-backed "override" namespace it creates on demand)
/// are ported. Always returns `None` (mirroring a database that cannot create the namespace)
/// until the real lookup/creation logic is available.
pub fn high_function_find_create_override_space(
    function: &mut dyn Function,
) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
    let _ = function;
    None
}

/// Placeholder for `ghidra.program.model.pcode.PcodeDataTypeManager`, referenced by
/// [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype)'s
/// `encode_prototype` before the real class is ported. `FunctionPrototype::encode_prototype` only
/// ever passes this type through opaquely (the real serialization logic is left to concrete
/// implementors), so no members are needed yet.
pub trait PcodeDataTypeManager {}

/// Placeholder for `ghidra.program.model.pcode.PcodeFactory`, referenced by
/// [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype)'s
/// `decode_prototype` before the real class is ported. `FunctionPrototype::decode_prototype` only
/// ever passes this type through opaquely (the real deserialization logic is left to concrete
/// implementors), so no members are needed yet.
pub trait PcodeFactory {}

/// Placeholder for `ghidra.program.model.pcode.LocalSymbolMap`, referenced by [`HighFunction`]
/// before the real class is ported. Exposes only the parameter accessors
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// needs; `get_param_symbol` is left required since there is no sensible placeholder `HighSymbol`
/// to hand back.
pub trait LocalSymbolMap: Send + Sync {
    /// Stands in for `LocalSymbolMap.getNumParams()`.
    fn get_num_params(&self) -> i32 {
        0
    }

    /// Stands in for `LocalSymbolMap.getParamSymbol(int)`.
    fn get_param_symbol(&self, index: i32) -> Arc<dyn HighSymbol>;

    /// Stands in for `LocalSymbolMap.getSymbols()`. Modeled as a `Vec` snapshot rather than an
    /// `Iterator<HighSymbol>`, since the current callers collect it eagerly regardless.
    fn get_symbols(&self) -> Vec<Arc<dyn HighSymbol>> {
        Vec::new()
    }

    /// Stands in for `LocalSymbolMap.getSymbol(long)`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    /// Defaults to `None`, mirroring a symbol reference id with no matching local symbol.
    fn get_symbol(&self, id: i64) -> Option<Arc<dyn HighSymbol>> {
        let _ = id;
        None
    }
}

/// Placeholder for `ghidra.program.model.pcode.HighVariable`, referenced by
/// [`HighSymbol::get_high_variable`] and
/// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
/// before the real class is ported.
pub trait HighVariable: Send + Sync {
    /// Stands in for `HighVariable.requiresDynamicStorage()`.
    fn requires_dynamic_storage(&self) -> bool {
        false
    }

    /// Stands in for `HighVariable.getRepresentative()`.
    fn get_representative(&self) -> Varnode;

    /// Simplified stand-in for `highVar instanceof HighParam ? ((HighParam)
    /// highVar).getSlot() : null`, used by
    /// [`HighFunctionDBUtil::get_function_variable`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::get_function_variable).
    /// The real `HighParam` subtype is not modeled separately here; implementors representing a
    /// parameter are expected to override this to return their slot.
    fn as_param_slot(&self) -> Option<i32> {
        None
    }

    /// Stands in for `HighVariable.getHighFunction()`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    /// Left required since there is no sensible placeholder `HighFunction` to hand back.
    fn get_high_function(&self) -> Arc<dyn HighFunction>;

    /// Stands in for `HighVariable.getDataType()`, used by
    /// [`HighConstant::get_scalar`](crate::program::model::pcode::high_constant::HighConstant::get_scalar).
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    /// Stands in for `HighVariable.getSize()`, used by
    /// [`HighConstant::get_scalar`](crate::program::model::pcode::high_constant::HighConstant::get_scalar).
    /// Defaults to the representative varnode's size, matching the real class's usual
    /// `getSize() == getRepresentative().getSize()` invariant.
    fn get_size(&self) -> i32 {
        self.get_representative().get_size()
    }

    /// Stands in for the package-private `HighVariable.decodeInstances(Decoder)`, used by
    /// [`HighConstant::decode`](crate::program::model::pcode::high_constant::HighConstant::decode).
    /// The real method decodes the representative and any merged "instance" varnodes from the
    /// stream; that decoding logic belongs to `HighVariable` itself, which is not yet ported, so
    /// this defaults to a no-op that consumes nothing from the stream.
    fn decode_instances(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let _ = decoder;
        Ok(())
    }
}

/// Placeholder for `ghidra.program.model.data.DataTypeSymbol`, referenced by
/// [`HighFunctionDBUtil::write_override`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::write_override)
/// and
/// [`HighFunctionDBUtil::read_override`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil::read_override)
/// before the real class is ported.
pub trait DataTypeSymbol: Send + Sync {
    /// Stands in for `DataTypeSymbol.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType>;
}

/// Stands in for the static `DataTypeSymbol.readSymbol(String, Symbol)`. Always returns `None`
/// (mirroring no override symbol found) until the real DB-backed lookup is ported.
pub fn read_data_type_symbol(
    category: &str,
    sym: &dyn crate::program::model::symbol::Symbol,
) -> Option<Box<dyn DataTypeSymbol>> {
    let _ = (category, sym);
    None
}

/// Stands in for constructing a `FunctionDefinitionDataType` from a [`FunctionSignature`] and
/// persisting it via `new DataTypeSymbol(fsig, "prt", AUTO_CAT).writeSymbol(...)`. Always
/// succeeds as a no-op until the real `DataTypeSymbol`/`FunctionDefinitionDataType` classes are
/// ported.
pub fn write_data_type_symbol_override(
    namespace: &dyn crate::program::model::symbol::Namespace,
    callsite: Address,
    sig: &dyn crate::program::model::listing::FunctionSignature,
) {
    let _ = (namespace, callsite, sig);
}

/// Placeholder for `ghidra.program.model.pcode.PcodeOpAST`, referenced by
/// [`PcodeBlockBasic`](crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic) (which
/// downcasts each `PcodeOp` it stores to this subtype on every insert/remove, to set/read the
/// op's parent block and its cursor position within the block's op list) before the real class is
/// ported. Exposes only the members `PcodeBlockBasic`'s insertion/removal logic touches.
pub trait PcodeOpAst {
    /// Stands in for the protected `PcodeOpAST.setParent(PcodeBlockBasic)`.
    fn set_parent(&self, parent: Option<Arc<dyn PcodeBlockBasic>>);

    /// Stands in for the protected `PcodeOpAST.setBasicIter(Iterator<PcodeOp>)`.
    fn set_basic_iter(&self, iter: LinkedIter);

    /// Stands in for the protected `PcodeOpAST.getBasicIter()`.
    fn get_basic_iter(&self) -> LinkedIter;
}

/// Placeholder for `ghidra.program.model.util.DataTypeInfo`, referenced (as a superclass) by
/// [`CompositeDataTypeElementInfo`](crate::program::model::util::composite_data_type_element_info::CompositeDataTypeElementInfo)
/// before the real class is ported. Exposes only the three getters that superclass provides.
/// The Java `dataTypeHandle` field is `Object`, used purely for display and identity comparison
/// (`Object.equals`/`toString`); it is represented here as `Arc<dyn Display + Send + Sync>`,
/// matching the repo's convention (see
/// [`verts_to_referent_set`](crate::util::graph::directed_graph::verts_to_referent_set)) of
/// standing in for `Object.equals`/`hashCode` with the value's `Display` form.
pub trait DataTypeInfoLike {
    /// Stands in for `DataTypeInfo.getDataTypeHandle()`.
    fn get_data_type_handle(&self) -> Arc<dyn fmt::Display + Send + Sync>;

    /// Stands in for `DataTypeInfo.getDataTypeLength()`.
    fn get_data_type_length(&self) -> i32;

    /// Stands in for `DataTypeInfo.getDataTypeAlignment()`.
    fn get_data_type_alignment(&self) -> i32;
}

/// Placeholder for `ghidra.program.database.map.AddressKeyIterator`, referenced by
/// [`PropertyMapDB`](crate::program::database::properties::property_map_db::PropertyMapDB)'s
/// `getAddressKeyIterator` overloads before the real class is ported. Models the `DBLongIterator`
/// surface `AddressKeyIterator` implements (`hasNext`/`hasPrevious`/`next`/`previous`),
/// translating Java's `NoSuchElementException` from `next`/`previous` into `None` returns; the
/// `delete()` member of `DBLongIterator` is omitted since no current caller needs it.
pub trait AddressKeyIteratorLike {
    /// Stands in for `DBLongIterator.hasNext()`.
    fn has_next(&mut self) -> bool;

    /// Stands in for `DBLongIterator.hasPrevious()`.
    fn has_previous(&mut self) -> bool;

    /// Stands in for `DBLongIterator.next()`, returning `None` rather than throwing
    /// `NoSuchElementException`.
    fn next(&mut self) -> Option<i64>;

    /// Stands in for `DBLongIterator.previous()`, returning `None` rather than throwing
    /// `NoSuchElementException`.
    fn previous(&mut self) -> Option<i64>;
}

/// Placeholder for `ghidra.program.util.AddressCorrelationRange`, referenced by
/// [`AddressCorrelation`](crate::program::util::address_correlation::AddressCorrelation)'s
/// `getCorrelatedDestinationRange` before the real class is ported. Models the three accessors
/// the Java class exposes (`getMinAddress`/`getRange`/`getCorrelatorName`).
pub trait AddressCorrelationRangeLike: Send + Sync {
    /// Stands in for `AddressCorrelationRange.getMinAddress()`.
    fn min_address(&self) -> Address;

    /// Stands in for `AddressCorrelationRange.getRange()`.
    fn range(&self) -> AddressRange;

    /// Stands in for `AddressCorrelationRange.getCorrelatorName()`.
    fn correlator_name(&self) -> String;
}

/// Placeholder for `ghidra.program.model.block.CodeBlockModel`, referenced (as a supertrait) by
/// [`SubroutineBlockModel`](crate::program::model::block::subroutine_block_model::SubroutineBlockModel)
/// and used by
/// [`SubroutineDestReferenceIterator`](crate::program::model::block::subroutine_dest_reference_iterator)
/// before the real interface is ported. `externals_included` defaults to `false` so pre-existing
/// bare `impl CodeBlockModel for Foo {}` blocks keep compiling; `get_basic_block_model`/
/// `get_code_blocks_containing` are left required since there is no generic placeholder
/// `CodeBlockModel`/`CodeBlockIterator` to hand back. This is an independent, minimal placeholder
/// from the identically-named `CodeBlockModel` in [`crate::app::seam_stubs`] (used by
/// `BlockModelService`); the two should be consolidated once the real `CodeBlockModel` is ported.
pub trait CodeBlockModel {
    /// Stands in for `CodeBlockModel.externalsIncluded()`.
    fn externals_included(&self) -> bool {
        false
    }

    /// Stands in for `CodeBlockModel.getBasicBlockModel()`.
    fn get_basic_block_model(&self) -> Box<dyn CodeBlockModel>;

    /// Stands in for `CodeBlockModel.getCodeBlocksContaining(CodeBlock, TaskMonitor)`.
    fn get_code_blocks_containing(
        &self,
        block: &dyn CodeBlock,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn CodeBlockIterator>, CancelledException>;
}

/// Placeholder for `ghidra.program.util.CodeUnitLocation`, referenced (as a superclass) by
/// [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation)
/// before the real class is ported. `CodeUnitLocation` itself extends `ProgramLocation` (see
/// [`crate::app::seam_stubs::ProgramLocation`]), but `OffsetFieldLocation` never calls a method
/// on either superclass (it only adds a `getType()` accessor of its own), so this placeholder is
/// a marker with no members.
pub trait CodeUnitLocation {}

/// Placeholder for `ghidra.program.util.OffsetFieldType`, referenced by
/// [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation)
/// before the real enum is ported. All four variants are mirrored since
/// `OffsetFieldLocation::get_type` returns this value opaquely to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OffsetFieldType {
    File,
    Function,
    ImageBase,
    MemoryBlock,
}

/// Placeholder for `ghidra.program.util.VarnodeContext`, referenced by
/// [`SymbolicPropogator`](crate::program::util::symbolic_propogator::SymbolicPropogator)
/// before the real class is ported. `SymbolicPropogator`'s trait methods only ever pass this type
/// through opaquely (as the varnode-level register/memory state accumulated while flowing
/// constants), so no members are needed yet.
pub trait VarnodeContext {}

/// Placeholder for the `ghidra.program.util.OldLanguageFactory` singleton, referenced by
/// [`LanguageVersionException::check`](crate::program::model::lang::language_version_exception::check)
/// before the real factory is ported. The Java method reaches through
/// `OldLanguageFactory.getOldLanguageFactory().getOldLanguage(id, version)`; only that single
/// lookup is exposed here, taken as a parameter instead of a static singleton getter.
pub trait OldLanguageFactory {
    /// Returns the old-language stub matching `language_id` at `language_version`, or `None` if
    /// no such stub exists to facilitate an upgrade translation.
    fn get_old_language(
        &self,
        language_id: &LanguageID,
        language_version: i32,
    ) -> Option<Arc<dyn Language>>;
}

/// Placeholder for the `ghidra.program.util.LanguageTranslatorFactory` singleton, referenced by
/// [`LanguageVersionException::check`](crate::program::model::lang::language_version_exception::check)
/// and
/// [`LanguageVersionException::check_for_language_change`](crate::program::model::lang::language_version_exception::check_for_language_change)
/// before the real factory is ported. Java overloads `getLanguageTranslator` on parameter types
/// (`Language, Language` vs. `LanguageID, int`); Rust gives each overload its own method name.
pub trait LanguageTranslatorFactory {
    /// Returns a translator that upgrades `old_language` to `new_language`, or `None` if no such
    /// translator is registered.
    fn get_language_translator_for_languages(
        &self,
        old_language: &Arc<dyn Language>,
        new_language: &Arc<dyn Language>,
    ) -> Option<Arc<dyn LanguageTranslator>>;

    /// Returns a translator that upgrades the language identified by `language_id` from
    /// `language_version`, or `None` if no such translator is registered.
    fn get_language_translator_for_version(
        &self,
        language_id: &LanguageID,
        language_version: i32,
    ) -> Option<Arc<dyn LanguageTranslator>>;
}

/// Placeholder for `ghidra.program.model.pcode.ParamMeasure`, referenced by
/// [`HighParamID`](crate::program::model::pcode::high_param_id::HighParamID)
/// before the real class is ported. Exposes only `isEmpty`/`getVarnode`/`getDataType`/`getRank`,
/// the members `HighParamID` itself calls. Defaults mirror a freshly constructed (not yet
/// decoded) `ParamMeasure`, whose fields are all `null` until `ParamMeasure.decode` runs.
pub trait ParamMeasure {
    /// Stands in for `ParamMeasure.isEmpty()`.
    fn is_empty(&self) -> bool {
        true
    }

    /// Stands in for `ParamMeasure.getVarnode()`.
    fn get_varnode(&self) -> Option<Varnode> {
        None
    }

    /// Stands in for `ParamMeasure.getDataType()`.
    fn get_data_type(&self) -> Option<Box<dyn DataType>> {
        None
    }

    /// Stands in for `ParamMeasure.getRank()`.
    fn get_rank(&self) -> Option<i32> {
        None
    }
}

