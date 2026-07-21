//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::pcode::floatformat::big_float::BigFloat;
use crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException;
use crate::program::model::address::Address;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::block_map::BlockMap;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::list_linked::LinkedIter;
use crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic;
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
pub trait VariableStorage {}

/// Placeholder for `ghidra.program.model.data.StandAloneDataTypeManager`, referenced by
/// [`DataTypeArchive`](crate::program::model::listing::data_type_archive::DataTypeArchive)
/// before the real class is ported. `DataTypeArchive` only ever returns this type opaquely, so
/// no members are needed yet.
pub trait StandAloneDataTypeManager {}

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

/// Placeholder for `ghidra.program.model.lang.PrototypeModel`, referenced by
/// [`DataTypeManager`](crate::program::model::data::data_type_manager::DataTypeManager)
/// before the real class is ported.
pub trait PrototypeModel {}

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

/// Placeholder for `ghidra.program.model.pcode.PcodeOverride`, referenced by
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
/// before the real interface is ported. `InstructionPrototype` only ever passes this type
/// through, so no members are needed yet.
pub trait PcodeOverride {}

/// Placeholder for `ghidra.program.model.pcode.PatchEncoder`, referenced by
/// [`InstructionPrototype`](crate::program::model::lang::instruction_prototype::InstructionPrototype)
/// before the real interface is ported. `InstructionPrototype` only ever passes this type
/// through, so no members are needed yet.
pub trait PatchEncoder {}

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
/// before the real interface is ported. `Listing` only ever returns this type, so no members are
/// needed yet.
pub trait InstructionIterator {}

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
/// [`ParamList`](crate::program::model::lang::param_list::ParamList)
/// before the real class is ported. `ParamList::assign_map` only ever passes this type through,
/// so no members are needed yet.
#[derive(Debug, Default, Clone)]
pub struct PrototypePieces;

/// Placeholder for `ghidra.program.model.lang.ParameterPieces`, referenced by
/// [`ParamList`](crate::program::model::lang::param_list::ParamList)
/// before the real class is ported. `ParamList::assign_map` only ever appends this type to its
/// result list, so no members are needed yet.
#[derive(Debug, Default, Clone)]
pub struct ParameterPieces;

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
/// [`CodeBlockIterator`](crate::program::model::block::code_block_iterator::CodeBlockIterator)
/// and [`CodeBlockReference`](crate::program::model::block::code_block_reference::CodeBlockReference)
/// before the real interface is ported. Neither caller invokes methods on this type, so no
/// members are needed yet.
pub trait CodeBlock {}

/// Placeholder for `ghidra.program.model.symbol.FlowType`, referenced by
/// [`CodeBlockReference`](crate::program::model::block::code_block_reference::CodeBlockReference)
/// before the real enum is ported. `CodeBlockReference` only ever returns this type opaquely, so
/// no members are needed yet.
pub trait FlowType {}

/// Placeholder for `ghidra.program.model.data.SignedDWordDataType`, referenced by
/// [`DWordDataType`](crate::program::model::data::dword_data_type::DWordDataType)
/// before the real class is ported. `DWordDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait SignedDWordDataType {}

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

/// Placeholder for `ghidra.program.model.data.UInt8TDataType`, referenced by
/// [`Int8TDataType`](crate::program::model::data::int8_t_data_type::Int8TDataType)
/// before the real class is ported. `Int8TDataType` only ever returns this type opaquely (from
/// `getOppositeSignednessDataType()`), so no members are needed yet.
pub trait UInt8TDataType {}

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

