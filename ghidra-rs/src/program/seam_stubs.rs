//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::program::model::address::Address;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::register::{Register, RegisterRef};
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

/// Placeholder for `ghidra.program.model.data.PointerTypedefBuilder`, referenced by
/// [`Pointer`](crate::program::model::data::pointer::Pointer)
/// before the real class is ported.
pub trait PointerTypedefBuilder {}

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

/// Placeholder for `ghidra.program.model.lang.LanguageDescription`, referenced by
/// [`Language`](crate::program::model::lang::language::Language)
/// before the real interface is ported. `Language` only ever returns this type opaquely, so no
/// members are needed yet.
pub trait LanguageDescription {}

/// Placeholder for `ghidra.program.model.lang.Processor`, referenced by
/// [`Language`](crate::program::model::lang::language::Language) and
/// [`LanguageDescription`] before the real class is ported. `Language` only ever returns this
/// type opaquely, so no members are needed yet.
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

/// Placeholder for `ghidra.program.model.lang.CompilerSpecID`, referenced by
/// [`CompilerSpec`](crate::program::model::lang::compiler_spec::CompilerSpec) and
/// [`LanguageCompilerSpecPair`], before the real class is ported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompilerSpecID(String);

impl CompilerSpecID {
    /// Stands in for `CompilerSpecID.DEFAULT_ID`.
    pub const DEFAULT_ID: &'static str = "default";

    /// Creates a new compiler spec ID, defaulting to [`Self::DEFAULT_ID`] when `id` is `None`.
    pub fn new(id: Option<&str>) -> Self {
        CompilerSpecID(id.unwrap_or(Self::DEFAULT_ID).to_string())
    }

    /// Returns the compiler spec ID as a string.
    pub fn get_id_as_string(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompilerSpecID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

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

/// Placeholder for `ghidra.program.model.pcode.Encoder`, referenced by
/// [`InjectPayload`](crate::program::model::lang::inject_payload::InjectPayload)
/// before the real interface is ported. `InjectPayload::encode` only ever passes this type
/// through to the underlying stream encoder, so no members are needed yet.
pub trait Encoder {}

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

