//! Port of `ghidra.app.plugin.processors.sleigh.SleighLanguage`: a [`Language`] backed by a
//! compiled SLEIGH specification (`.sla`).
//!
//! # What is ported
//! * `.sla` decoding (`decode`/`parseSpaces`, including `.ldefs` endianness validation and
//!   address-space truncation when a [`SleighLanguageDescription`] is supplied), the sleigh
//!   [`SymbolTable`] and instruction decision tree.
//! * Register construction from the symbol table (`loadRegisters`/`registerContext`), and every
//!   register query of [`Language`].
//! * Description-derived answers (id, processor, version, compiler spec descriptions), address
//!   factory/spaces, endianness, alignment, user-op names, volatile addresses, properties,
//!   maximum instruction length, the parallel-instruction helper, and the processor manual index
//!   (see [`manual`]).
//!
//! # What is not (yet) ported
//! * Reading the processor specification (`.pspec`; Java `readInitialDescription`/
//!   `readRemainingSpecification`/`read`) needs `XmlPullParserFactory`, which is not ported. A
//!   language is therefore in the state Java's is in for a `.pspec` that declares nothing: no
//!   properties, no program counter, no context settings, no volatile ranges, no default
//!   symbols or memory blocks, no register renames/aliases/groups/lane sizes, and no segmented
//!   space.
//! * [`Language::parse`] builds a [`SleighInstructionPrototype`] but does not cache prototypes
//!   by hash (Java's `instructProtoMap`), and cannot apply the instruction's global context
//!   commits: Java only applies them when the processor context is a `DisassemblerContext`,
//!   which a `&mut dyn ProcessorContext` cannot be tested for here. A language can only parse
//!   once it is shared through [`SleighLanguage::into_shared`] (prototypes hold the language).
//! * [`Language::get_compiler_spec_by_id`] needs the language to have been shared through
//!   [`SleighLanguage::into_shared`] (a spec refers back to its language).
//! * [`Language::reload_language`] needs `SlaFormat.buildDecoder` (not ported) to re-read the
//!   `.sla` file, and reports that as an I/O error, as Java does for a failed reload.
//!
//! # Registers and thread-safety
//! The register set is built once, from the symbol table, when the language is decoded, and
//! kept in a [`RegisterManager`] that owns the language's
//! [`RegisterStore`](crate::program::model::lang::register::RegisterStore). Register queries
//! return [`Register`] handles into that one store, so a register looked up twice is the same
//! register ([`Register::same`]), as with Java's `Register` objects. Registers, the manager and
//! therefore `SleighLanguage` are `Send + Sync` (the language is shared through `Arc` by the
//! p-code emulator, `ProgramDB`, and others).
//!
//! # Compiler specs
//! As in Java (`compilerSpecs`), each compiler spec is loaded on first request and cached, so
//! every request for the same id returns the same spec. The language owns its specs; a spec
//! refers back to its language only weakly (see
//! [`WeakLanguage`](crate::program::model::lang::language::WeakLanguage)), so dropping the last
//! `Arc` to the language frees the language and its specs together. A spec must therefore not be
//! used after its language has been dropped.

use super::Endian;
use crate::app::plugin::processors::generic::MemoryBlockDefinition;
use crate::app::plugin::processors::sleigh::context_cache::{ContextCache, DefaultContextCache};
use crate::app::plugin::processors::sleigh::sleigh_instruction_prototype::SleighInstructionPrototype;
use crate::app::plugin::processors::sleigh::sleigh_language_description::SleighLanguageDescription;
use crate::app::plugin::processors::sleigh::sleigh_parser_context::{
    read_context_words, snapshot_mem_buffer,
};
use crate::program::model::address::{
    Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    DefaultAddressFactory,
};
use crate::program::model::lang::basic_compiler_spec::BasicCompilerSpec;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
use crate::program::model::lang::ghidra_language_property_keys::MAXIMUM_INSTRUCTION_LENGTH;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::language::{Language, ParseError};
use crate::program::model::lang::language_description::LanguageDescription;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_builder::RegisterBuilder;
use crate::program::model::lang::register_manager::RegisterManager;
use crate::program::model::lang::insufficient_bytes_exception::InsufficientBytesException;
use crate::program::model::lang::nested_delay_slot_exception::NestedDelaySlotException;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_ALIGN, ATTRIB_BIGENDIAN, ATTRIB_DEFAULTSPACE, ATTRIB_DELAY,
    ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_NUMSECTIONS, ATTRIB_SIZE, ATTRIB_UNIQBASE, ATTRIB_UNIQMASK,
    ATTRIB_VERSION, ATTRIB_WORDSIZE, ELEM_SLEIGH, ELEM_SOURCEFILES, ELEM_SPACE, ELEM_SPACES,
    ELEM_SPACE_OTHER, ELEM_SPACE_UNIQUE,
};
use crate::program::seam_stubs::{AddressLabelInfo, Processor};
use crate::util::manual_entry::ManualEntry;
use crate::util::task::TaskMonitor;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock, Weak};

pub mod constructor;
pub mod decision;
pub mod expression;
pub mod handle;
pub mod manual;
pub mod pattern;
pub mod symbol;
pub mod template;
pub mod walker;

pub use handle::FixedHandle;
pub use walker::{ParserWalker, SleighError};

use expression::{ContextField, PatternExpression};
use manual::ManualState;
use symbol::{ContextSymbol, SleighSymbol, SubtableSymbol, SymbolTable};

/// The language description a [`SleighLanguage`] is built from, shared so that
/// [`Language::get_language_description`] can hand out the same description on every call.
pub type SharedSleighLanguageDescription = Arc<dyn SleighLanguageDescription + Send + Sync>;

/// A [`Language`] backed by a compiled SLEIGH specification. See the module docs for what is and
/// is not yet ported.
pub struct SleighLanguage {
    _id: String,
    _endian: Endian,
    _instruction_endian: Endian,
    _unique_base: u64,
    _alignment: i32,
    _unique_allocate_mask: i32,
    _num_sections: i32,
    _address_factory: Arc<DefaultAddressFactory>,
    _default_space: Option<Arc<AddressSpace>>,
    _space_table: HashMap<String, Arc<AddressSpace>>,
    _symbol_table: SymbolTable,
    /// The `.ldefs` description (`description`); `None` for a language decoded straight from a
    /// `.sla` stream via [`SleighLanguage::decode`].
    description: Option<SharedSleighLanguageDescription>,
    /// `defaultDataSpace`: the default space unless a `.pspec` `<data_space>` overrides it.
    default_data_space: Option<Arc<AddressSpace>>,
    /// `defaultPointerWordSize`: the default data space's addressable unit size.
    default_pointer_word_size: i32,
    /// `volatileAddresses`.
    volatile_addresses: AddressSet,
    /// `properties` (from the `.pspec` `<properties>` element).
    properties: HashMap<String, String>,
    /// `segmentedspace` (from the `.pspec` `<segmented_address>` element).
    segmented_space: String,
    /// `maxInstructionLength`.
    max_instruction_length: Option<i32>,
    /// `manual`/`manualException`, loaded on first use (`initManual`).
    manual: OnceLock<ManualState>,
    /// This language, once shared through [`SleighLanguage::into_shared`]: instruction
    /// prototypes hold their language (Java passes `this`).
    self_ref: Weak<SleighLanguage>,
    /// `registerManager`: every register of this language, built once from the symbol table
    /// when the language is decoded.
    register_manager: RegisterManager,
    /// `compilerSpecs`: the compiler specs loaded so far, by id.
    compiler_specs: Mutex<HashMap<CompilerSpecID, Arc<BasicCompilerSpec>>>,
}

impl fmt::Display for SleighLanguage {
    /// Port of `SleighLanguage.toString()`, which is `description.toString()`
    /// (`BasicLanguageDescription.toString()`); falls back to the language id without one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::program::model::lang::basic_language_description::BasicLanguageDescription;
        match &self.description {
            Some(d) => f.write_str(&d.to_display_string()),
            None => f.write_str(&self._id),
        }
    }
}

impl SleighLanguage {
    pub fn get_id(&self) -> &str {
        &self._id
    }

    /// Port of `SleighLanguage.getSymbolTable()` (the sleigh symbol table, not the program's).
    pub fn get_symbol_table(&self) -> &SymbolTable {
        &self._symbol_table
    }

    pub fn get_address_factory(&self) -> Arc<DefaultAddressFactory> {
        self._address_factory.clone()
    }

    /// Port of `SleighLanguage.isBigEndian()`: the `.ldefs` endianness when a description is
    /// present, otherwise the endianness recorded in the `.sla` file.
    pub fn is_big_endian(&self) -> bool {
        match &self.description {
            Some(d) => d.get_endian().is_big_endian(),
            None => self._endian == Endian::Big,
        }
    }

    /// Returns the first free offset within the unique address space, as recorded in the `.sla`
    /// file's `<sleigh uniqbase="...">` attribute.
    ///
    /// Port of `SleighLanguage.getUniqueBase()`.
    pub fn get_unique_base(&self) -> u64 {
        self._unique_base
    }

    /// Number of bytes between allocations within the unique space. Port of
    /// `SleighLanguage.getUniqueAllocationMask()`.
    pub fn get_unique_allocation_mask(&self) -> i32 {
        self._unique_allocate_mask
    }

    /// The (maximum) number of named p-code sections. Port of `SleighLanguage.numSections()`.
    pub fn num_sections(&self) -> i32 {
        self._num_sections
    }

    /// The default word size to use when analyzing pointer offsets. Port of the deprecated
    /// `SleighLanguage.getDefaultPointerWordSize()`.
    pub fn get_default_pointer_word_size(&self) -> i32 {
        self.default_pointer_word_size
    }

    /// The `.ldefs` description this language was built from, if any. Port of the covariant
    /// `SleighLanguage.getLanguageDescription()` (which returns `SleighLanguageDescription`).
    pub fn get_sleigh_language_description(&self) -> Option<&SharedSleighLanguageDescription> {
        self.description.as_ref()
    }

    /// Returns the number of user-defined (`CALLOTHER`) ops known to this language.
    ///
    /// Port of `SleighLanguage.getNumberOfUserDefinedOpNames()`, which delegates to
    /// `SymbolTable.getNumberOfUserDefinedOpNames()`.
    pub fn get_number_of_user_defined_op_names(&self) -> i32 {
        self._symbol_table.user_ops.len() as i32
    }

    /// Returns the name of the `index`th user-defined op, or `None` if `index` is out of range.
    ///
    /// Port of `SleighLanguage.getUserDefinedOpName(int)`, which delegates to
    /// `SymbolTable.getUserDefinedOpName(int)`.
    pub fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
        let id = *self._symbol_table.user_ops.get(index as usize)?;
        self._symbol_table
            .find_symbol(id)
            .map(|sym| sym.header().name.clone())
    }

    /// Decodes a language from a `.sla` stream alone, identified by `id`, with no `.ldefs`
    /// description (so no endianness validation, space truncation, or compiler specs).
    pub fn decode(decoder: &dyn Decoder, id: String) -> Result<Self, DecoderError> {
        Self::decode_internal(decoder, id, None)
    }

    /// Decodes a language from a `.sla` stream for the given `.ldefs` description. This is the
    /// `.sla` half of Java's `SleighLanguage(SleighLanguageDescription)` constructor (`decode`):
    /// the language id comes from the description, the `.sla` endianness is validated against it,
    /// and the description's address-space truncations are applied.
    ///
    /// # Errors
    /// Returns an error on malformed `.sla` data, an endianness mismatch with the description, an
    /// invalid or unapplied space truncation, or a missing default space.
    pub fn decode_with_description(
        decoder: &dyn Decoder,
        description: SharedSleighLanguageDescription,
    ) -> Result<Self, DecoderError> {
        let id = description.get_language_id().get_id_as_string().to_string();
        Self::decode_internal(decoder, id, Some(description))
    }

    fn decode_internal(
        decoder: &dyn Decoder,
        id: String,
        description: Option<SharedSleighLanguageDescription>,
    ) -> Result<Self, DecoderError> {
        if id.is_empty() {
            return Err(DecoderError::Generic("empty language id not allowed".to_string()));
        }
        let el = decoder.open_element_with_id(ELEM_SLEIGH)?;

        let mut version = 0;
        let mut unique_base = 0;
        let mut alignment = 1;
        let mut unique_allocate_mask = 0;
        let mut num_sections = 0;
        let mut is_big_endian = false;

        loop {
            let attr = decoder.get_next_attribute_id()?;
            if attr == 0 {
                break;
            }

            if attr == ATTRIB_VERSION.id {
                version = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_BIGENDIAN.id {
                is_big_endian = decoder.read_bool()?;
            } else if attr == ATTRIB_UNIQBASE.id {
                unique_base = decoder.read_unsigned_integer()?;
            } else if attr == ATTRIB_ALIGN.id {
                alignment = decoder.read_signed_integer()? as i32;
            } else if attr == ATTRIB_UNIQMASK.id {
                unique_allocate_mask = decoder.read_unsigned_integer()? as i32;
            } else if attr == ATTRIB_NUMSECTIONS.id {
                num_sections = decoder.read_unsigned_integer()? as i32;
            }
        }

        if version < 4 {
            return Err(DecoderError::Generic(format!(
                "Unsupported .sla version: {}",
                version
            )));
        }

        let endian = if is_big_endian {
            Endian::Big
        } else {
            Endian::Little
        };
        let mut instruction_endian = endian;
        if let Some(d) = &description {
            let ldef_endian = d.get_endian();
            let inst_endian = d.get_instruction_endian();
            if endian != ldef_endian && inst_endian == ldef_endian {
                return Err(DecoderError::Generic(format!(
                    ".ldefs says {id} is {ldef_endian} but .sla says {endian}"
                )));
            }
            instruction_endian = inst_endian;
        }

        if decoder.peek_element()? == ELEM_SOURCEFILES.id {
            let indexer_el = decoder.open_element()?;
            decoder.close_element_skipping(indexer_el)?;
        }

        let (space_table, default_space) =
            Self::parse_spaces(decoder, &id, description.as_deref())?;

        let mut all_spaces: Vec<Arc<AddressSpace>> = space_table.values().cloned().collect();
        all_spaces.sort_by_key(|s| s.space_id());
        let address_factory = Arc::new(DefaultAddressFactory::with_default_space(
            all_spaces,
            default_space.clone(),
        ));
        decoder.set_address_factory(address_factory.clone());

        // Java: `defaultDataSpace = default_space;
        // defaultPointerWordSize = defaultDataSpace.getAddressableUnitSize()`, which fails (NPE)
        // when the `.sla` names a default space it does not define.
        let Some(default_space_ref) = default_space.as_ref() else {
            return Err(DecoderError::Generic(format!(
                "default address space of {id} is not defined"
            )));
        };
        let default_pointer_word_size = default_space_ref.unit_size();

        let mut sleigh = Self {
            _id: id,
            _endian: endian,
            _instruction_endian: instruction_endian,
            _unique_base: unique_base,
            _alignment: alignment,
            _unique_allocate_mask: unique_allocate_mask,
            _num_sections: num_sections,
            _address_factory: address_factory,
            default_data_space: default_space.clone(),
            _default_space: default_space,
            _space_table: space_table,
            _symbol_table: SymbolTable::new(),
            description,
            default_pointer_word_size,
            volatile_addresses: AddressSet::new(),
            properties: HashMap::new(),
            segmented_space: String::new(),
            max_instruction_length: None,
            manual: OnceLock::new(),
            self_ref: Weak::new(),
            compiler_specs: Mutex::new(HashMap::new()),
            // Replaced below, once the symbol table the registers come from is decoded.
            register_manager: RegisterBuilder::new().register_manager(),
        };

        let mut symbol_table = SymbolTable::new();
        symbol_table.decode(decoder, &sleigh)?;
        sleigh._symbol_table = symbol_table;
        sleigh.register_manager = sleigh.build_register_manager();

        decoder.close_element(el)?;

        // Java: `getPropertyAsInt(MAXIMUM_INSTRUCTION_LENGTH, -1)`, kept only when positive.
        let max_length = sleigh.get_property_as_int(MAXIMUM_INSTRUCTION_LENGTH, -1);
        if max_length > 0 {
            sleigh.max_instruction_length = Some(max_length);
        }

        Ok(sleigh)
    }

    fn parse_spaces(
        decoder: &dyn Decoder,
        id: &str,
        description: Option<&(dyn SleighLanguageDescription + Send + Sync)>,
    ) -> Result<
        (
            HashMap<String, Arc<AddressSpace>>,
            Option<Arc<AddressSpace>>,
        ),
        DecoderError,
    > {
        let truncated_space_names: HashSet<String> = description
            .map(|d| d.get_truncated_space_names())
            .unwrap_or_default();
        let mut truncated_space_cnt = truncated_space_names.len();

        let el = decoder.open_element_with_id(ELEM_SPACES)?;
        let defname = decoder.read_string_with_id(ATTRIB_DEFAULTSPACE)?;

        let mut space_table = HashMap::new();

        let const_spc = AddressSpace::new("constant", 64, 1, AddressSpaceType::Constant, 0);
        space_table.insert("constant".to_string(), const_spc);

        let subel = decoder.peek_element()?;
        if subel == ELEM_SPACE_OTHER.id {
            let other_id = decoder.open_element()?;
            decoder.close_element_skipping(other_id)?;
            let other_spc = AddressSpace::new("OTHER", 32, 1, AddressSpaceType::Other, 0);
            space_table.insert("OTHER".to_string(), other_spc);
        } else {
            return Err(DecoderError::Generic(
                ".sla file missing required OTHER space tag".to_string(),
            ));
        }

        while decoder.peek_element()? != 0 {
            let mut wordsize = 1;
            let mut name = String::new();
            let mut index = 0;
            let mut delay = -1;
            let mut size = 0;

            let subel = decoder.open_element()?;
            loop {
                let attr = decoder.get_next_attribute_id()?;
                if attr == 0 {
                    break;
                }

                if attr == ATTRIB_NAME.id {
                    name = decoder.read_string()?;
                } else if attr == ATTRIB_INDEX.id {
                    index = decoder.read_signed_integer()? as i32;
                } else if attr == ATTRIB_DELAY.id {
                    delay = decoder.read_signed_integer()? as i32;
                } else if attr == ATTRIB_SIZE.id {
                    size = decoder.read_signed_integer()? as i32;
                } else if attr == ATTRIB_WORDSIZE.id {
                    wordsize = decoder.read_signed_integer()? as i32;
                }
            }

            let space_type = if subel == ELEM_SPACE.id {
                if delay > 0 {
                    AddressSpaceType::Ram
                } else {
                    AddressSpaceType::Register
                }
            } else if subel == ELEM_SPACE_UNIQUE.id {
                AddressSpaceType::Unique
            } else {
                return Err(DecoderError::Generic(
                    "Unknown space definition type".to_string(),
                ));
            };

            if truncated_space_names.contains(&name) {
                if space_type != AddressSpaceType::Ram {
                    return Err(DecoderError::Generic(format!(
                        "Non-ram space does not support truncation: {name}"
                    )));
                }
                let truncated_size = description
                    .and_then(|d| d.get_truncated_space_size(&name))
                    .unwrap_or(0);
                if truncated_size <= 0 || truncated_size >= size {
                    return Err(DecoderError::Generic(format!(
                        "Invalid space truncation: {name}:{size} -> {truncated_size}"
                    )));
                }
                size = truncated_size;
                truncated_space_cnt -= 1;
            }

            let spc = AddressSpace::new(&name, 8 * size, wordsize, space_type, index);
            space_table.insert(name.clone(), spc);
            decoder.close_element(subel)?;
        }
        if truncated_space_cnt > 0 {
            return Err(DecoderError::Generic(format!(
                "One or more truncated spaced not applied: {id}"
            )));
        }

        let default_space = space_table.get(&defname).cloned();
        decoder.close_element(el)?;

        Ok((space_table, default_space))
    }

    /// Builds this language's registers from the sleigh symbol table. Port of
    /// `SleighLanguage.loadRegisters(RegisterBuilder)` followed by
    /// `RegisterBuilder.getRegisterManager()`; called once, at decode time.
    fn build_register_manager(&self) -> RegisterManager {
        let mut builder = RegisterBuilder::new();
        self.load_registers(&mut builder);
        builder.register_manager()
    }

    fn load_registers(&self, builder: &mut RegisterBuilder) {
        let big_endian = self.is_big_endian();
        for sym in self._symbol_table.symbols.iter().flatten() {
            match sym {
                SleighSymbol::Varnode(vn) => {
                    let Some(space) = &vn.space else { continue };
                    // Java adds register- and ram-space varnodes alike; for ram it additionally
                    // marks the space as having mapped registers, which this crate's
                    // `AddressSpace` does not model (see `RegisterManager::is_register_addressable`).
                    if matches!(
                        space.space_type(),
                        AddressSpaceType::Register | AddressSpaceType::Ram
                    ) {
                        let a = Address::new(space.clone(), vn.offset as i64);
                        builder.add_register(
                            vn.header.name.clone(),
                            "",
                            a,
                            vn.size,
                            big_endian,
                            0,
                        );
                    }
                }
                SleighSymbol::VarnodeList(sym) => {
                    if let Some(PatternExpression::ContextField(field)) = &sym.patval {
                        Self::register_context_field(&sym.header.name, field, builder);
                    }
                }
                SleighSymbol::Context(sym) => self.register_context_symbol(sym, builder),
                _ => {}
            }
        }
    }

    /// Port of `SleighLanguage.registerContext(String, ContextField, RegisterBuilder)`.
    fn register_context_field(name: &str, field: &ContextField, builder: &mut RegisterBuilder) {
        let startbit = field.bitstart;
        let endbit = field.bitend;
        let bit_length = endbit - startbit + 1;
        let context_byte_length = (endbit / 8) + 1;
        let context_bit_length = context_byte_length * 8;
        // Java passes `builder.getProcessContextAddress()` unchecked; with no context register
        // added yet it is null and Java's `Register` constructor fails. Such a field cannot be
        // placed, so it is skipped with an error instead.
        let Some(address) = builder.process_context_address().cloned() else {
            crate::util::msg::Msg::error(
                "SleighLanguage",
                &format!("context field {name} precedes any context register"),
            );
            return;
        };
        builder.add_register_with_bit_range(
            name,
            name,
            address,
            context_byte_length,
            context_bit_length - endbit - 1,
            bit_length,
            true,
            Register::TYPE_CONTEXT,
        );
    }

    /// Port of `SleighLanguage.registerContext(ContextSymbol, RegisterBuilder)`.
    fn register_context_symbol(&self, sym: &ContextSymbol, builder: &mut RegisterBuilder) {
        let Some(PatternExpression::ContextField(field)) = &sym.patval else { return };
        let Some(SleighSymbol::Varnode(vn)) = self._symbol_table.find_symbol(sym.varnode_id) else {
            return;
        };
        let Some(space) = &vn.space else { return };
        let startbit = field.bitstart;
        let endbit = field.bitend;
        let bit_length = endbit - startbit + 1;
        let context_bit_length = vn.size * 8;
        let a = Address::new(space.clone(), vn.offset as i64);

        let mut flags = Register::TYPE_CONTEXT;
        if !sym.follows_flow() {
            flags |= Register::TYPE_DOES_NOT_FOLLOW_FLOW;
        }
        builder.add_register_with_bit_range(
            sym.header.name.clone(),
            sym.header.name.clone(),
            a,
            vn.size,
            context_bit_length - endbit - 1,
            bit_length,
            true,
            flags,
        );
    }

    fn manual(&self) -> &ManualState {
        self.manual.get_or_init(|| {
            ManualState::load(self.description.as_ref().and_then(|d| d.get_manual_index_file()))
        })
    }

    /// The default space; always present, since decoding fails without one.
    fn default_space(&self) -> Arc<AddressSpace> {
        self._default_space
            .clone()
            .expect("decode rejects a language without a default space")
    }

    /// The compiler spec `compiler_spec_id`, loaded from its `.cspec` file on first request and
    /// cached: repeated requests return the same spec.
    ///
    /// Port of `SleighLanguage.getCompilerSpecByID`, returning the concrete spec;
    /// [`Language::get_compiler_spec_by_id`] hands out this same spec as a `dyn CompilerSpec`.
    ///
    /// # Errors
    /// [`CompilerSpecNotFoundException`] if the description lists no such compiler spec, its
    /// description names no `.cspec` file, the language was never shared through
    /// [`SleighLanguage::into_shared`], or the file cannot be read or parsed.
    pub fn get_basic_compiler_spec_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Arc<BasicCompilerSpec>, CompilerSpecNotFoundException> {
        let known = self
            .get_compatible_compiler_spec_descriptions()
            .iter()
            .any(|d| &d.get_compiler_spec_id() == compiler_spec_id);
        if !known {
            return Err(CompilerSpecNotFoundException::new(
                &self.get_language_id(),
                compiler_spec_id,
            ));
        }
        if let Some(spec) = self.cached_compiler_specs().get(compiler_spec_id) {
            return Ok(spec.clone());
        }
        let not_found = || CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id);
        let Some(description) = &self.description else {
            return Err(not_found());
        };
        let compiler_spec_description: Arc<dyn CompilerSpecDescription> =
            Arc::from(description.get_compiler_spec_description_by_id(compiler_spec_id)?);
        let Some(file) = compiler_spec_description
            .as_sleigh_compiler_spec_description()
            .map(|d| d.get_file().clone())
        else {
            return Err(not_found());
        };
        let Some(language) = self.self_ref.upgrade() else {
            return Err(not_found());
        };
        // Built without holding the lock: reading the `.cspec` calls back into this language.
        let spec = Arc::new(BasicCompilerSpec::from_file(compiler_spec_description, &language, &file)?);
        // If another thread loaded the same spec meanwhile, keep the first so every caller
        // shares one spec.
        let mut specs = self.cached_compiler_specs();
        Ok(specs.entry(compiler_spec_id.clone()).or_insert(spec).clone())
    }

    /// The compiler-spec cache. A panic while it was held cannot leave it inconsistent (it is
    /// only ever inserted into), so a poisoned lock is recovered.
    fn cached_compiler_specs(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<CompilerSpecID, Arc<BasicCompilerSpec>>> {
        self.compiler_specs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Shares this language, so it can parse instructions: every instruction prototype holds
    /// the language it was parsed with, as Java's does.
    pub fn into_shared(self) -> Arc<Self> {
        Arc::new_cyclic(|weak| {
            let mut lang = self;
            lang.self_ref = weak.clone();
            lang
        })
    }

    /// The constant address space.
    pub fn constant_space(&self) -> Arc<AddressSpace> {
        self._space_table
            .get("constant")
            .cloned()
            .expect("decode always creates the constant space")
    }

    /// The `instruction` subtable, whose decision tree is the root of every instruction's
    /// parse. Stands in for `SleighLanguage.getRootDecisionNode()` (the decision tree of that
    /// subtable).
    pub fn get_root_subtable(&self) -> Option<&SubtableSymbol> {
        match self._symbol_table.find_global_symbol("instruction")? {
            SleighSymbol::Subtable(sub) => Some(sub),
            _ => None,
        }
    }

    /// A context cache for this language's context register (Java's `contextcache`, which
    /// `SleighLanguage` registers the context base register with). Each call returns a new
    /// cache; the context cache is not `Send + Sync`, so the language cannot hold one.
    pub fn new_context_cache(&self) -> DefaultContextCache {
        let mut cache = DefaultContextCache::new();
        if let Some(base) = self.get_context_base_register() {
            cache.register_variable(&base);
        }
        cache
    }

    /// The body of Java's `parse(MemBuffer, ProcessorContext, boolean)`, given the packed
    /// context words at the instruction: the alignment check, resolving a new prototype, and
    /// the nested delay slot check.
    ///
    /// # Errors
    /// [`SleighError::UnknownInstruction`] for a misaligned address, a byte pattern matching no
    /// instruction, a delay slot instruction that itself has delay slots, or a language not
    /// shared through [`SleighLanguage::into_shared`]; [`SleighError::MemoryAccess`] if the
    /// bytes cannot be read.
    pub fn parse_prototype(
        &self,
        buf: Arc<dyn MemBuffer>,
        context: Vec<i32>,
        in_delay_slot: bool,
    ) -> Result<SleighInstructionPrototype, SleighError> {
        if self._alignment != 1 && buf.get_address().offset() % self._alignment as i64 != 0 {
            return Err(UnknownInstructionException::with_message(format!(
                "Instructions must be aligned on {}byte boundary.",
                self._alignment
            ))
            .into());
        }
        let language = self.self_ref.upgrade().ok_or_else(|| {
            UnknownInstructionException::with_message(format!(
                "SleighLanguage {} must be shared through SleighLanguage::into_shared to parse",
                self._id
            ))
        })?;
        let proto = SleighInstructionPrototype::new(language, buf, context, in_delay_slot)?;
        if in_delay_slot && proto.has_delay_slots() {
            return Err(UnknownInstructionException::with_message(
                NestedDelaySlotException::new().message(),
            )
            .into());
        }
        Ok(proto)
    }
    /// [`Language::parse`], yielding the concrete prototype: what a caller that shares
    /// prototypes across threads (a [`SharedPrototype`](crate::program::model::listing::instruction_record::SharedPrototype))
    /// needs, since the trait method boxes it without `Send + Sync`.
    ///
    /// # Errors
    /// As [`Language::parse`].
    pub fn parse_sleigh(
        &self,
        buf: &dyn MemBuffer,
        context: &mut dyn ProcessorContext,
        in_delay_slot: bool,
    ) -> Result<SleighInstructionPrototype, ParseError> {
        let view: &dyn ProcessorContextView = &*context;
        let words = read_context_words(self, view);
        let mem = snapshot_mem_buffer(buf, 0)
            .map_err(|e| InsufficientBytesException::with_message(e.to_string()))?;
        let proto = match self.parse_prototype(mem.clone(), words.clone(), in_delay_slot) {
            Ok(proto) => proto,
            Err(SleighError::MemoryAccess(e)) => {
                return Err(InsufficientBytesException::with_message(e.to_string()).into())
            }
            Err(SleighError::UnknownInstruction(e)) => return Err(e.into()),
            Err(SleighError::Sleigh(e)) => {
                return Err(UnknownInstructionException::with_message(e.message()).into())
            }
        };
        // Java builds the instruction's parser context here to apply its context commits; a
        // failure to do so is an unknown instruction
        proto
            .new_parser_context(mem, words)
            .map_err(|_| UnknownInstructionException::new())?;
        Ok(proto)
    }
}

impl Language for SleighLanguage {
    /// Port of `getLanguageID()` (`description.getLanguageID()`); without a description, the id
    /// the language was decoded under.
    fn get_language_id(&self) -> LanguageID {
        match &self.description {
            Some(d) => d.get_language_id(),
            None => LanguageID::new(self._id.clone()).expect("decode rejects an empty id"),
        }
    }

    /// Port of `getLanguageDescription()`.
    ///
    /// # Panics
    /// If the language was decoded without a description ([`SleighLanguage::decode`]); Java's
    /// `SleighLanguage` always has one.
    fn get_language_description(&self) -> Box<dyn LanguageDescription> {
        let d = self.description.as_ref().unwrap_or_else(|| {
            panic!("SleighLanguage {} was decoded without a language description", self._id)
        });
        Box::new(Arc::clone(d))
    }

    /// Port of `getParallelInstructionHelper()`. Java instantiates the class named by the
    /// `parallelInstructionHelperClass` property, which only a `.pspec` can set (not ported), so
    /// the helper is `null`/`None`.
    fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
        None
    }

    /// Port of `getProcessor()` (`description.getProcessor()`).
    ///
    /// # Panics
    /// If the language was decoded without a description (see
    /// [`Language::get_language_description`]).
    fn get_processor(&self) -> Box<dyn Processor> {
        match &self.description {
            Some(d) => d.get_processor(),
            None => panic!(
                "SleighLanguage {} was decoded without a language description",
                self._id
            ),
        }
    }

    /// Port of `getVersion()` (`description.getVersion()`); without a description, `1`, the
    /// constant [`Language::get_version`] documents for languages without versioning.
    fn get_version(&self) -> i32 {
        self.description.as_ref().map_or(1, |d| d.get_version())
    }

    /// Port of `getMinorVersion()`; without a description, `0` (see [`Self::get_version`]).
    fn get_minor_version(&self) -> i32 {
        self.description.as_ref().map_or(0, |d| d.get_minor_version())
    }

    /// Port of `getAddressFactory()`: the factory over the `.sla` address spaces.
    fn get_address_factory(&self) -> Box<dyn AddressFactory> {
        Box::new((*self._address_factory).clone())
    }

    /// Port of `getDefaultSpace()`.
    fn get_default_space(&self) -> Arc<AddressSpace> {
        self.default_space()
    }

    /// Port of `getDefaultDataSpace()`.
    fn get_default_data_space(&self) -> Arc<AddressSpace> {
        self.default_data_space
            .clone()
            .unwrap_or_else(|| self.default_space())
    }

    /// Port of `isBigEndian()`.
    fn is_big_endian(&self) -> bool {
        SleighLanguage::is_big_endian(self)
    }

    /// Port of `getInstructionAlignment()`.
    fn get_instruction_alignment(&self) -> i32 {
        self._alignment
    }

    /// Port of `supportsPcode()`.
    fn supports_pcode(&self) -> bool {
        true
    }

    /// Port of `isVolatile(Address)`.
    fn is_volatile(&self, addr: &Address) -> bool {
        self.volatile_addresses.contains(addr)
    }

    /// Port of `parse(MemBuffer, ProcessorContext, boolean)`: resolves the instruction at
    /// `buf` into a [`SleighInstructionPrototype`]. See the module docs for what differs from
    /// Java (no prototype cache; global context commits are not applied).
    ///
    /// # Errors
    /// [`ParseError::InsufficientBytes`] if the instruction bytes cannot be read, or
    /// [`ParseError::UnknownInstruction`] for a misaligned address, a byte pattern matching no
    /// instruction, a nested delay slot, a failure recovering the instruction's operands, or a
    /// language not shared through [`SleighLanguage::into_shared`].
    fn parse(
        &self,
        buf: &dyn MemBuffer,
        context: &mut dyn ProcessorContext,
        in_delay_slot: bool,
    ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
        Ok(Box::new(self.parse_sleigh(buf, context, in_delay_slot)?))
    }

    fn get_number_of_user_defined_op_names(&self) -> i32 {
        SleighLanguage::get_number_of_user_defined_op_names(self)
    }

    fn get_user_defined_op_name(&self, index: i32) -> Option<String> {
        SleighLanguage::get_user_defined_op_name(self, index)
    }

    /// Port of `getRegisters(Address)`.
    fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
        self.register_manager.get_registers_at(address)
    }

    /// Port of `getRegister(AddressSpace, long, int)`.
    fn get_register_in_space(
        &self,
        addrspc: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
    ) -> Option<RegisterRef> {
        self.get_register_at(&Address::new(addrspc.clone(), offset), size)
    }

    /// Port of `getRegisters()`.
    fn get_registers(&self) -> Vec<RegisterRef> {
        self.register_manager.get_registers()
    }

    /// Port of `getRegisterNames()`.
    fn get_register_names(&self) -> Vec<String> {
        self.register_manager.get_register_names()
    }

    /// Port of `getRegister(String)`.
    fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        self.register_manager.get_register_by_name(name)
    }

    /// Port of `getRegister(Address, int)`.
    fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
        self.register_manager.get_register_at(addr, size)
    }

    /// Port of `getProgramCounter()`. Only a `.pspec` `<programcounter>` sets it (not ported),
    /// so this is Java's `null`.
    fn get_program_counter(&self) -> Option<RegisterRef> {
        None
    }

    /// Port of `getContextBaseRegister()`; `None` stands in for `Register.NO_CONTEXT`.
    fn get_context_base_register(&self) -> Option<RegisterRef> {
        let base = self.register_manager.get_context_base_register();
        let is_context = base.is_processor_context();
        is_context.then_some(base)
    }

    /// Port of `getContextRegisters()`.
    fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.register_manager.get_context_registers()
    }

    /// Port of `getDefaultMemoryBlocks()`: empty unless a `.pspec` declares
    /// `<default_memory_blocks>` (not ported).
    fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
        Vec::new()
    }

    /// Port of `getDefaultSymbols()`: empty unless a `.pspec` declares `<default_symbols>` (not
    /// ported).
    fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
        Vec::new()
    }

    /// Port of `getSegmentedSpace()`.
    fn get_segmented_space(&self) -> String {
        self.segmented_space.clone()
    }

    /// Port of `getVolatileAddresses()`.
    fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
        Box::new(self.volatile_addresses.clone())
    }

    /// Port of `applyContextSettings(DefaultProgramContext)`. Context settings come only from a
    /// `.pspec` `<context_data>` element (not ported), so there are none to apply.
    fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}

    /// Port of `reloadLanguage(TaskMonitor)`. Re-reading the `.sla` file needs
    /// `SlaFormat.buildDecoder` (not ported), so this fails the way a failed Java reload does,
    /// with an I/O error.
    fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
        Err(std::io::Error::other(format!(
            "Failed to reload Sleigh language {}: reading .sla files (SlaFormat) is not yet ported",
            self._id
        )))
    }

    /// Port of `getCompatibleCompilerSpecDescriptions()`; empty without a description.
    fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
        self.description
            .as_ref()
            .map(|d| d.get_compatible_compiler_spec_descriptions())
            .unwrap_or_default()
    }

    /// Port of `getCompilerSpecByID(CompilerSpecID)`: the cached compiler spec parsed from the
    /// `.cspec` file named by the description; see
    /// [`SleighLanguage::get_basic_compiler_spec_by_id`].
    ///
    /// # Errors
    /// As [`SleighLanguage::get_basic_compiler_spec_by_id`].
    fn get_compiler_spec_by_id(
        &self,
        compiler_spec_id: &CompilerSpecID,
    ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
        Ok(Box::new(self.get_basic_compiler_spec_by_id(compiler_spec_id)?))
    }

    /// Port of `getDefaultCompilerSpec()`: the first compatible compiler spec.
    ///
    /// # Panics
    /// If there are no compatible compiler specs (Java's `NoSuchElementException`), or if that
    /// spec cannot be loaded (Java wraps the `CompilerSpecNotFoundException` in an
    /// `IllegalStateException`).
    fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
        let first = self
            .get_compatible_compiler_spec_descriptions()
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("language {} has no compiler specs", self._id));
        match self.get_compiler_spec_by_id(&first.get_compiler_spec_id()) {
            Ok(spec) => spec,
            Err(e) => panic!("{e}"),
        }
    }

    /// Port of `hasProperty(String)`.
    fn has_property(&self, key: &str) -> bool {
        self.properties.contains_key(key)
    }

    /// Port of `getPropertyAsInt(String, int)`.
    ///
    /// # Panics
    /// If the property is not an integer (Java's `NumberFormatException`).
    fn get_property_as_int(&self, key: &str, default_int: i32) -> i32 {
        match self.properties.get(key) {
            Some(v) => v
                .parse()
                .unwrap_or_else(|_| panic!("property {key}={v} is not an integer")),
            None => default_int,
        }
    }

    /// Port of `getPropertyAsBoolean(String, boolean)` (`Boolean.parseBoolean` semantics).
    fn get_property_as_boolean(&self, key: &str, default_boolean: bool) -> bool {
        match self.properties.get(key) {
            Some(v) => v.eq_ignore_ascii_case("true"),
            None => default_boolean,
        }
    }

    /// Port of `getProperty(String, String)`.
    fn get_property_or(&self, key: &str, default_string: &str) -> String {
        self.properties
            .get(key)
            .cloned()
            .unwrap_or_else(|| default_string.to_string())
    }

    /// Port of `getProperty(String)`.
    fn get_property(&self, key: &str) -> Option<String> {
        self.properties.get(key).cloned()
    }

    /// Port of `getPropertyKeys()`.
    fn get_property_keys(&self) -> HashSet<String> {
        self.properties.keys().cloned().collect()
    }

    /// Port of `hasManual()`.
    fn has_manual(&self) -> bool {
        let manual = self.manual();
        let has_index = self
            .description
            .as_ref()
            .is_some_and(|d| d.get_manual_index_file().is_some());
        has_index && manual.error.is_none()
    }

    /// Port of `getManualEntry(String)`.
    fn get_manual_entry(&self, instruction_mnemonic: &str) -> Option<ManualEntry> {
        self.manual().index.get_entry(instruction_mnemonic)
    }

    /// Port of `getManualInstructionMnemonicKeys()`.
    fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
        self.manual().index.keys()
    }

    /// Port of `getManualException()`.
    fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.manual()
            .error
            .as_ref()
            .map(|e| Box::new(std::io::Error::other(e.clone())) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Port of `getSortedVectorRegisters()`.
    fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
        self.register_manager.get_sorted_vector_registers()
    }

    /// Port of `getRegisterAddresses()`.
    fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
        self.register_manager.get_register_addresses()
    }

    /// Port of `getMaximumInstructionLength()`.
    fn get_maximum_instruction_length(&self) -> Option<i32> {
        self.max_instruction_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{
        Address, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::pcode::PackedDecode;

    #[test]
    fn test_sleigh_decode_basic() {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));

        let mut data = vec![];

        // <sleigh version="4" bigendian="false">
        // ELEM_SLEIGH = 33 -> 0x60, 0xA1
        data.extend_from_slice(&[0x60, 0xA1]);
        // ATTRIB_VERSION = 34 -> 0xE0, 0xA2. Value 4.
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]);
        // ATTRIB_BIGENDIAN = 35 -> 0xE0, 0xA3. Value false.
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]);

        // <spaces defaultspace="ram">
        // ELEM_SPACES = 34 -> 0x60, 0xA2
        data.extend_from_slice(&[0x60, 0xA2]);
        // ATTRIB_DEFAULTSPACE = 41 -> 0xE0, 0xA9. Value "ram".
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);

        // <space_other/>
        // ELEM_SPACE_OTHER = 45 -> 0x60, 0xAD
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);

        // <space name="ram" size="4" index="1" delay="1"/>
        // ELEM_SPACE = 37 -> 0x60, 0xA5
        data.extend_from_slice(&[0x60, 0xA5]);
        // ATTRIB_NAME = 12 -> 0xCC
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        // ATTRIB_SIZE = 15 -> 0xCF
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        // ATTRIB_INDEX = 9 -> 0xC9
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        // ATTRIB_DELAY = 42 -> 0xE0, 0xAA
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        // </space>
        data.extend_from_slice(&[0xA0, 0xA5]);

        // </spaces>
        data.extend_from_slice(&[0xA0, 0xA2]);

        // <symbol_table scopesize="1" symbolsize="0">
        // ELEM_SYMBOL_TABLE = 38 -> 0x60, 0xA6
        data.extend_from_slice(&[0x60, 0xA6]);
        // ATTRIB_SCOPESIZE = 45 -> 0xE0, 0xAD
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        // ATTRIB_SYMBOLSIZE = 46 -> 0xE0, 0xAE
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 0]);

        // <scope id="0" parent="0"/>
        // ELEM_SCOPE = 22 -> 0x56
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);

        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA6]);

        // </sleigh>
        data.extend_from_slice(&[0xA0, 0xA1]);

        let decoder = PackedDecode::new(factory, data);
        let sleigh = SleighLanguage::decode(&decoder, "test".to_string()).unwrap();

        assert_eq!(sleigh._id, "test");
        assert_eq!(sleigh._endian, Endian::Little);
        assert!(sleigh._space_table.contains_key("ram"));
        assert_eq!(sleigh._default_space.as_ref().unwrap().name(), "ram");
    }

    struct MockMemBuffer {
        addr: Address,
        data: Vec<u8>,
    }

    impl walker::MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.data
                .get(offset as usize)
                .cloned()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            if start >= self.data.len() {
                return 0;
            }
            let len = (self.data.len() - start).min(buf.len());
            buf[..len].copy_from_slice(&self.data[start..start + len]);
            len
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_sleigh_resolve_basic() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0x1000);
        let mem: Arc<dyn MemBuffer> = Arc::new(MockMemBuffer {
            addr: addr.clone(),
            data: vec![0x39, 0x00, 0x00, 0x00],
        });

        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        // ELEM_SLEIGH = 33 -> 0x60, 0xA1
        data.extend_from_slice(&[0x60, 0xA1]);
        // ATTRIB_VERSION = 34 -> 0xE0, 0xA2. Value 4.
        data.extend_from_slice(&[0xE0, 0xA2, 0x21, 4]);
        // ATTRIB_BIGENDIAN = 35 -> 0xE0, 0xA3. Value false.
        data.extend_from_slice(&[0xE0, 0xA3, 0x10]);

        // <spaces defaultspace="ram">
        // ELEM_SPACES = 34 -> 0x60, 0xA2
        data.extend_from_slice(&[0x60, 0xA2]);
        // ATTRIB_DEFAULTSPACE = 41 -> 0xE0, 0xA9. Value "ram".
        data.extend_from_slice(&[0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        // ELEM_SPACE_OTHER = 45 -> 0x60, 0xAD
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        // ELEM_SPACE = 37 -> 0x60, 0xA5
        data.extend_from_slice(&[0x60, 0xA5]);
        // ATTRIB_NAME = 12 -> 0xCC
        data.extend_from_slice(&[0xCC, 0x71, 3, b'r', b'a', b'm']);
        // ATTRIB_SIZE = 15 -> 0xCF
        data.extend_from_slice(&[0xCF, 0x21, 4]);
        // ATTRIB_INDEX = 9 -> 0xC9
        data.extend_from_slice(&[0xC9, 0x21, 1]);
        // ATTRIB_DELAY = 42 -> 0xE0, 0xAA
        data.extend_from_slice(&[0xE0, 0xAA, 0x21, 1]);
        // </space>
        data.extend_from_slice(&[0xA0, 0xA5]);

        // </spaces>
        data.extend_from_slice(&[0xA0, 0xA2]);

        // <symbol_table scopesize="1" symbolsize="1">
        // ELEM_SYMBOL_TABLE = 38 -> 0x60, 0xA6
        data.extend_from_slice(&[0x60, 0xA6]);
        // ATTRIB_SCOPESIZE = 45 -> 0xE0, 0xAD
        data.extend_from_slice(&[0xE0, 0xAD, 0x21, 1]);
        // ATTRIB_SYMBOLSIZE = 46 -> 0xE0, 0xAE
        data.extend_from_slice(&[0xE0, 0xAE, 0x21, 1]);

        // <scope id="0" parent="0"/>
        // ELEM_SCOPE = 22 -> 0x56
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);

        // <subtable_sym_head name="instruction" id="0" scope="0"/>
        // ELEM_SUBTABLE_SYM_HEAD = 72 -> 0x60, 0xC8
        data.extend_from_slice(&[0x60, 0xC8]);
        // ATTRIB_NAME = 12 -> 0xCC
        data.extend_from_slice(&[
            0xCC, 0x71, 11, b'i', b'n', b's', b't', b'r', b'u', b'c', b't', b'i', b'o', b'n',
        ]);
        // ATTRIB_ID = 3 -> 0xC3
        data.extend_from_slice(&[0xC3, 0x41, 0]);
        // ATTRIB_SCOPE = 13 -> 0xCD
        data.extend_from_slice(&[0xCD, 0x41, 0]);
        // </subtable_sym_head>
        data.extend_from_slice(&[0xA0, 0xC8]);

        // <subtable_sym id="0" numct="1">
        // ELEM_SUBTABLE_SYM = 71 -> 0x60, 0xC7
        data.extend_from_slice(&[0x60, 0xC7, 0xC3, 0x41, 0]);
        // ATTRIB_NUMCT = 53 -> 0xE0, 0xB5
        data.extend_from_slice(&[0xE0, 0xB5, 0x21, 1]);

        // <constructor parent="0" first="0" length="1" source="0" line="1">
        // ELEM_CONSTRUCTOR = 20 -> 0x54
        data.extend_from_slice(&[0x54]);
        // ATTRIB_PARENT = 22 -> 0xD6
        data.extend_from_slice(&[0xD6, 0x41, 0]);
        // ATTRIB_FIRST = 27 -> 0xDB
        data.extend_from_slice(&[0xDB, 0x21, 0]);
        // ATTRIB_LENGTH = 26 -> 0xDA
        data.extend_from_slice(&[0xDA, 0x21, 1]);
        // ATTRIB_SOURCE = 25 -> 0xD9
        data.extend_from_slice(&[0xD9, 0x21, 0]);
        // ATTRIB_LINE = 24 -> 0xD8
        data.extend_from_slice(&[0xD8, 0x21, 1]);
        // </constructor>
        data.push(0x94);

        // <decision context="false" startbit="0" size="0">
        // ELEM_DECISION = 16 -> 0x50
        data.extend_from_slice(&[0x50]);
        // ATTRIB_CONTEXT = 21 -> 0xD5. Value false.
        data.extend_from_slice(&[0xD5, 0x10]);
        // ATTRIB_STARTBIT = 14 -> 0xCE
        data.extend_from_slice(&[0xCE, 0x21, 0]);
        // ATTRIB_SIZE = 15 -> 0xCF
        data.extend_from_slice(&[0xCF, 0x21, 0]);

        // <pair id="0">
        // ELEM_PAIR = 9 -> 0x49
        data.extend_from_slice(&[0x49, 0xC3, 0x41, 0]);
        // <instruct_pat>
        // ELEM_INSTRUCT_PAT = 18 -> 0x52
        data.extend_from_slice(&[0x52]);
        // <pat_block off="0" nonzero="1">
        // ELEM_PAT_BLOCK = 7 -> 0x47
        data.extend_from_slice(&[0x47]);
        // ATTRIB_OFF = 6 -> 0xC6
        data.extend_from_slice(&[0xC6, 0x21, 0]);
        // ATTRIB_NONZERO = 10 -> 0xCA
        data.extend_from_slice(&[0xCA, 0x21, 4]); // 4 bytes in a word
                                                  // <mask_word mask="0x39000000" val="0x39000000"/>
                                                  // ELEM_MASK_WORD = 6 -> 0x46
        data.extend_from_slice(&[0x46]);
        // ATTRIB_MASK = 8 -> 0xC8. Value 0x39000000 (needs 5 bytes unsigned int encoding: 0x80 markers)
        // 0x39000000 = 0011 1001 0000 0000 0000 0000 0000 0000
        // Raw data encoding: 0x80 | (val >> 28), 0x80 | (val >> 21), 0x80 | (val >> 14), 0x80 | (val >> 7), val & 0x7F
        // 0x39000000 >> 28 = 0x03
        // (0x39000000 >> 21) & 0x7F = 0x48
        // (0x39000000 >> 14) & 0x7F = 0x00
        // (0x39000000 >> 7) & 0x7F = 0x00
        // 0x39000000 & 0x7F = 0x00
        data.extend_from_slice(&[0xC8, 0x45, 0x83, 0xC8, 0x80, 0x80, 0x00]);
        // ATTRIB_VAL = 2 -> 0xC2
        data.extend_from_slice(&[0xC2, 0x45, 0x83, 0xC8, 0x80, 0x80, 0x00]);
        // </mask_word>
        data.push(0x86);
        // </pat_block>
        data.push(0x87);
        // </instruct_pat>
        data.push(0x92);
        // </pair>
        data.push(0x89);

        // </decision>
        data.push(0x90);

        // </subtable_sym>
        data.extend_from_slice(&[0xA0, 0xC7]);

        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0xA6]);

        // </sleigh>
        data.extend_from_slice(&[0xA0, 0xA1]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![space.clone()],
        ));
        let decoder = crate::program::model::pcode::PackedDecode::new(factory, data);
        let sleigh = SleighLanguage::decode(&decoder, "test".to_string())
            .unwrap()
            .into_shared();

        // The single constructor (line 1, one byte long) matches 0x39.
        let proto = SleighInstructionPrototype::new(sleigh, mem, vec![0], false).unwrap();
        assert_eq!(proto.get_length(), 1);
        assert_eq!(proto.dump_constructor_tree(), "1");
        assert_eq!(proto.get_num_operands(), 0);
    }
}

/// Tests for the `Language` implementation, decoding `.sla` fixtures built with the real
/// [`PackedEncode`](crate::program::model::pcode::PackedEncode) encoder.
#[cfg(test)]
mod language_tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_language_file::SleighLanguageFile;
    use crate::generic::jar::resource_file::ResourceFile;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::ids::*;
    use crate::program::model::pcode::PackedDecode;
    use crate::program::model::pcode::PackedEncode;

    const RAM: i32 = 1;
    const REGISTER: i32 = 2;
    const UNIQUE: i32 = 3;

    /// Knobs for the generated `.sla` fixture.
    struct Sla {
        big_endian: bool,
        alignment: i64,
        ram_size: i64,
        default_space: &'static str,
    }

    impl Default for Sla {
        fn default() -> Self {
            Sla { big_endian: false, alignment: 1, ram_size: 4, default_space: "ram" }
        }
    }

    fn space(e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, index: i64, size: i64, delay: i64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
        e.write_signed_integer(ATTRIB_DELAY, delay).unwrap();
        e.close_element(elem).unwrap();
    }

    fn head(e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, id: u64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        e.write_unsigned_integer(ATTRIB_SCOPE, 0).unwrap();
        e.close_element(elem).unwrap();
    }

    fn varnode(e: &mut PackedEncode<Vec<u8>>, id: u64, space: i32, offset: u64, size: i64) {
        e.open_element(ELEM_VARNODE_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        e.write_space_indexed(ATTRIB_SPACE, space, "").unwrap();
        e.write_unsigned_integer(ATTRIB_OFF, offset).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
        e.close_element(ELEM_VARNODE_SYM).unwrap();
    }

    /// A small language: `r0` (4 bytes) and its low half `r0l` at register:0, `sp` in RAM at
    /// 0x100, a 4-byte `contextreg` at register:0x40 holding the context variable `TMode`
    /// (bit 0, no flow) and one user op `syscall`.
    fn sla(cfg: &Sla) -> Vec<u8> {
        let mut e = PackedEncode::new(Vec::<u8>::new());
        e.open_element(ELEM_SLEIGH).unwrap();
        e.write_signed_integer(ATTRIB_VERSION, 4).unwrap();
        e.write_bool(ATTRIB_BIGENDIAN, cfg.big_endian).unwrap();
        e.write_signed_integer(ATTRIB_ALIGN, cfg.alignment).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQBASE, 0x1000).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQMASK, 0xff).unwrap();
        e.write_unsigned_integer(ATTRIB_NUMSECTIONS, 2).unwrap();

        e.open_element(ELEM_SPACES).unwrap();
        e.write_string(ATTRIB_DEFAULTSPACE, cfg.default_space).unwrap();
        e.open_element(ELEM_SPACE_OTHER).unwrap();
        e.close_element(ELEM_SPACE_OTHER).unwrap();
        space(&mut e, ELEM_SPACE, "ram", RAM as i64, cfg.ram_size, 1);
        space(&mut e, ELEM_SPACE, "register", REGISTER as i64, 4, 0);
        space(&mut e, ELEM_SPACE_UNIQUE, "unique", UNIQUE as i64, 4, 0);
        e.close_element(ELEM_SPACES).unwrap();

        e.open_element(ELEM_SYMBOL_TABLE).unwrap();
        e.write_signed_integer(ATTRIB_SCOPESIZE, 1).unwrap();
        e.write_signed_integer(ATTRIB_SYMBOLSIZE, 6).unwrap();
        e.open_element(ELEM_SCOPE).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 0).unwrap();
        e.write_unsigned_integer(ATTRIB_PARENT, 0).unwrap();
        e.close_element(ELEM_SCOPE).unwrap();

        head(&mut e, ELEM_VARNODE_SYM_HEAD, "r0", 0);
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "r0l", 1);
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "sp", 2);
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "contextreg", 3);
        head(&mut e, ELEM_CONTEXT_SYM_HEAD, "TMode", 4);
        head(&mut e, ELEM_USEROP_HEAD, "syscall", 5);

        varnode(&mut e, 0, REGISTER, 0, 4);
        varnode(&mut e, 1, REGISTER, 0, 2);
        varnode(&mut e, 2, RAM, 0x100, 4);
        varnode(&mut e, 3, REGISTER, 0x40, 4);

        e.open_element(ELEM_CONTEXT_SYM).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 4).unwrap();
        e.write_unsigned_integer(ATTRIB_VARNODE, 3).unwrap();
        e.write_signed_integer(ATTRIB_LOW, 0).unwrap();
        e.write_signed_integer(ATTRIB_HIGH, 0).unwrap();
        e.write_bool(ATTRIB_FLOW, false).unwrap();
        e.open_element(ELEM_CONTEXTFIELD).unwrap();
        e.write_bool(ATTRIB_SIGNBIT, false).unwrap();
        e.write_signed_integer(ATTRIB_STARTBIT, 0).unwrap();
        e.write_signed_integer(ATTRIB_ENDBIT, 0).unwrap();
        e.write_signed_integer(ATTRIB_STARTBYTE, 0).unwrap();
        e.write_signed_integer(ATTRIB_ENDBYTE, 0).unwrap();
        e.write_signed_integer(ATTRIB_SHIFT, 7).unwrap();
        e.close_element(ELEM_CONTEXTFIELD).unwrap();
        e.close_element(ELEM_CONTEXT_SYM).unwrap();

        e.open_element(ELEM_USEROP).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 5).unwrap();
        e.write_signed_integer(ATTRIB_INDEX, 0).unwrap();
        e.close_element(ELEM_USEROP).unwrap();

        e.close_element(ELEM_SYMBOL_TABLE).unwrap();
        e.close_element(ELEM_SLEIGH).unwrap();
        e.into_inner()
    }

    fn decoder(bytes: Vec<u8>) -> PackedDecode {
        PackedDecode::new(Arc::new(DefaultAddressFactory::new(vec![])), bytes)
    }

    fn language(cfg: &Sla) -> SleighLanguage {
        SleighLanguage::decode(&decoder(sla(cfg)), "toy:LE:32:default".to_string()).unwrap()
    }

    struct MockProcessor;
    impl Processor for MockProcessor {
        fn name(&self) -> String {
            "toy".to_string()
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }
        fn get_compiler_spec_name(&self) -> String {
            "Default".to_string()
        }
        fn get_source(&self) -> String {
            "toy.cspec".to_string()
        }
    }

    /// A `.ldefs` description: data endianness `endian`, instruction endianness `inst_endian`.
    struct MockDescription {
        endian: Endian,
        inst_endian: Endian,
        truncated: HashMap<String, i32>,
        manual_index_file: Option<ResourceFile>,
    }

    impl MockDescription {
        fn new(endian: Endian) -> Self {
            MockDescription {
                endian,
                inst_endian: endian,
                truncated: HashMap::new(),
                manual_index_file: None,
            }
        }
    }

    impl LanguageDescription for MockDescription {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new("toy:BE:32:v2").unwrap()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_endian(&self) -> Endian {
            self.endian
        }
        fn get_instruction_endian(&self) -> Endian {
            self.inst_endian
        }
        fn get_size(&self) -> i32 {
            32
        }
        fn get_variant(&self) -> String {
            "v2".to_string()
        }
        fn get_version(&self) -> i32 {
            3
        }
        fn get_minor_version(&self) -> i32 {
            7
        }
        fn get_description(&self) -> String {
            "toy processor".to_string()
        }
        fn is_deprecated(&self) -> bool {
            false
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            vec![Box::new(MockCompilerSpecDescription)]
        }
        fn get_compiler_spec_description_by_id(
            &self,
            compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpecDescription>, CompilerSpecNotFoundException> {
            Err(CompilerSpecNotFoundException::new(&self.get_language_id(), compiler_spec_id))
        }
        fn get_external_names(&self, _external_tool: &str) -> Option<Vec<String>> {
            None
        }
    }

    impl SleighLanguageDescription for MockDescription {
        fn get_truncated_space_names(&self) -> HashSet<String> {
            self.truncated.keys().cloned().collect()
        }
        fn get_truncated_space_size(&self, space_name: &str) -> Option<i32> {
            self.truncated.get(space_name).copied()
        }
        fn get_defs_file(&self) -> Option<&ResourceFile> {
            None
        }
        fn set_defs_file(&mut self, _defs_file: Option<ResourceFile>) {}
        fn get_spec_file(&self) -> Option<&ResourceFile> {
            None
        }
        fn set_spec_file(&mut self, _spec_file: Option<ResourceFile>) {}
        fn get_manual_index_file(&self) -> Option<&ResourceFile> {
            self.manual_index_file.as_ref()
        }
        fn set_manual_index_file(&mut self, manual_index_file: Option<ResourceFile>) {
            self.manual_index_file = manual_index_file;
        }
        fn get_language_file(&self) -> Option<&dyn SleighLanguageFile> {
            None
        }
        fn set_language_file(&mut self, _language_file: Option<Box<dyn SleighLanguageFile>>) {}
    }

    fn with_description(cfg: &Sla, d: MockDescription) -> Result<SleighLanguage, DecoderError> {
        SleighLanguage::decode_with_description(&decoder(sla(cfg)), Arc::new(d))
    }

    fn name(r: &RegisterRef) -> String {
        r.name().to_string()
    }

    #[test]
    fn is_a_send_sync_language_usable_through_arc_dyn() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SleighLanguage>();
        let lang: Arc<dyn Language> = Arc::new(language(&Sla::default()));
        assert_eq!(lang.get_default_space().name(), "ram");
        assert_eq!(lang.get_language_id().get_id_as_string(), "toy:LE:32:default");
    }

    #[test]
    fn sla_attributes_spaces_and_defaults() {
        let lang = language(&Sla { alignment: 2, ..Sla::default() });
        assert!(!Language::is_big_endian(&lang));
        assert_eq!(lang.get_instruction_alignment(), 2);
        assert_eq!(lang.get_unique_base(), 0x1000);
        assert_eq!(lang.get_unique_allocation_mask(), 0xff);
        assert_eq!(lang.num_sections(), 2);
        assert!(lang.supports_pcode());
        assert_eq!(lang.get_default_space().name(), "ram");
        assert_eq!(lang.get_default_data_space().name(), "ram");
        assert_eq!(lang.get_default_pointer_word_size(), 1);
        let factory = Language::get_address_factory(&lang);
        assert_eq!(factory.get_default_address_space().unwrap().name(), "ram");
        assert_eq!(
            factory.get_address_space_by_name("register").unwrap().space_type(),
            AddressSpaceType::Register
        );
        // No description: Language's documented version defaults, no compiler specs.
        assert_eq!(lang.get_version(), 1);
        assert_eq!(lang.get_minor_version(), 0);
        assert!(lang.get_compatible_compiler_spec_descriptions().is_empty());
        assert_eq!(lang.to_string(), "toy:LE:32:default");
    }

    #[test]
    fn big_endian_sla() {
        let lang = language(&Sla { big_endian: true, ..Sla::default() });
        assert!(Language::is_big_endian(&lang));
    }

    #[test]
    fn missing_default_space_is_a_decode_error() {
        let res = SleighLanguage::decode(
            &decoder(sla(&Sla { default_space: "nowhere", ..Sla::default() })),
            "toy".to_string(),
        );
        assert!(res.is_err());
    }

    #[test]
    fn empty_id_is_rejected() {
        assert!(SleighLanguage::decode(&decoder(sla(&Sla::default())), String::new()).is_err());
    }

    #[test]
    fn registers_are_built_from_the_symbol_table() {
        let lang = language(&Sla::default());
        // Alphabetical, including the context register and context field.
        assert_eq!(
            lang.get_register_names(),
            vec!["TMode", "contextreg", "r0", "r0l", "sp"]
        );
        assert_eq!(lang.get_registers().len(), 5);

        let r0 = lang.get_register_by_name("r0").unwrap();
        assert_eq!(r0.num_bytes(), 4);
        assert_eq!(r0.address().offset(), 0);
        // Case-variations resolve too (RegisterBuilder's name map).
        assert_eq!(name(&lang.get_register_by_name("R0").unwrap()), "r0");
        assert!(lang.get_register_by_name("r9").is_none());

        let reg_space = lang.get_address_factory().get_address_space_by_name("register").unwrap();
        let at0 = Address::new(reg_space.clone(), 0);
        // Size 0 is the largest register at the address; a smaller size picks the sub-register.
        assert_eq!(name(&lang.get_register_at(&at0, 0).unwrap()), "r0");
        assert_eq!(name(&lang.get_register_at(&at0, 4).unwrap()), "r0");
        assert_eq!(name(&lang.get_register_at(&at0, 2).unwrap()), "r0l");
        assert_eq!(name(&lang.get_register_in_space(&reg_space, 0, 2).unwrap()), "r0l");
        let mut at_names: Vec<String> = lang.get_registers_at(&at0).iter().map(name).collect();
        at_names.sort();
        assert_eq!(at_names, vec!["r0", "r0l"]);

        let regs = lang.get_register_addresses();
        assert!(regs.contains(&Address::new(reg_space.clone(), 3)));
        assert!(!regs.contains(&Address::new(reg_space, 4)));
        assert!(lang.get_sorted_vector_registers().is_empty());
        assert!(lang.get_program_counter().is_none());
    }

    #[test]
    fn context_symbols_become_context_registers() {
        let lang = language(&Sla::default());
        let tmode = lang.get_register_by_name("TMode").unwrap();
        {
            let t = tmode;
            assert!(t.is_processor_context());
            assert_eq!(t.bit_length(), 1);
            // Added with lsb = contextBitLength - endbit - 1 = 31 over 4 big-endian bytes, which
            // `Register`'s constructor narrows to the single most significant byte (at the
            // lowest address, 0x40), leaving lsb 31 - 3 * 8 = 7.
            assert_eq!(t.least_significant_bit(), 7);
            assert_eq!(t.num_bytes(), 1);
            assert_eq!(t.address().offset(), 0x40);
            assert_eq!(t.type_flags() & Register::TYPE_DOES_NOT_FOLLOW_FLOW, Register::TYPE_DOES_NOT_FOLLOW_FLOW);
        }
        // The containing varnode becomes the context base register ("if my child is context, so
        // am I").
        let base = lang.get_context_base_register().unwrap();
        assert_eq!(name(&base), "contextreg");
        let mut ctx: Vec<String> = lang.get_context_registers().iter().map(name).collect();
        ctx.sort();
        assert_eq!(ctx, vec!["TMode", "contextreg"]);
    }

    #[test]
    fn register_queries_agree_across_calls() {
        let lang = language(&Sla::default());
        let first = lang.get_register_by_name("r0").unwrap();
        let second = lang.get_register_by_name("r0").unwrap();
        assert_eq!(first, second);
        // Registers are built once at decode time: the same register (same store, same id)
        // comes back from every query, whichever query it is.
        assert!(Register::same(&first, &second));
        assert_eq!(first.id(), second.id());
        let at0 = Address::new(
            lang.get_address_factory().get_address_space_by_name("register").unwrap(),
            0,
        );
        assert!(Register::same(&first, &lang.get_register_at(&at0, 4).unwrap()));
        let from_list = lang.get_registers().into_iter().find(|r| r.name() == "r0").unwrap();
        assert!(Register::same(&first, &from_list));
        let base = lang.get_context_base_register().unwrap();
        assert!(Register::same(&base, &lang.get_context_base_register().unwrap()));
    }

    #[test]
    fn registers_are_linked_by_id_within_the_language() {
        let lang = language(&Sla::default());
        let r0 = lang.get_register_by_name("r0").unwrap();
        let r0l = lang.get_register_by_name("r0l").unwrap();
        // r0l (2 bytes at register:0) is r0's child; r0 is its own base.
        assert_eq!(r0l.parent_id(), Some(r0.id()));
        assert!(Register::same(&r0l.parent_register().unwrap(), &r0));
        assert!(Register::same(&r0l.get_base_register(), &r0));
        assert_eq!(r0.child_ids(), &[r0l.id()]);
        assert!(r0.is_base_register());
        assert!(r0.contains(&r0l));
        // Little-endian: r0l is r0's low half.
        assert_eq!(r0l.base_mask(), vec![0x00, 0x00, 0xFF, 0xFF]);

        // The context field hangs off the context base register, in the same store.
        let tmode = lang.get_register_by_name("TMode").unwrap();
        let base = lang.get_context_base_register().unwrap();
        assert!(Register::same(&tmode.get_base_register(), &base));
        assert!(Arc::ptr_eq(tmode.store(), r0.store()));
        assert_eq!(tmode.store().get(tmode.base_register_id()).name(), "contextreg");
        // Big-endian context: bit 31 of the 4-byte base (lsb 7 of its most significant byte).
        assert_eq!(tmode.least_significant_bit_in_base_register(), 31);
        assert_eq!(tmode.base_mask(), vec![0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn user_ops_properties_and_pspec_defaults() {
        let lang = language(&Sla::default());
        assert_eq!(Language::get_number_of_user_defined_op_names(&lang), 1);
        assert_eq!(Language::get_user_defined_op_name(&lang, 0).as_deref(), Some("syscall"));
        assert_eq!(Language::get_user_defined_op_name(&lang, 1), None);

        assert!(!lang.has_property("x"));
        assert_eq!(lang.get_property("x"), None);
        assert_eq!(lang.get_property_or("x", "dflt"), "dflt");
        assert_eq!(lang.get_property_as_int("x", 7), 7);
        assert!(lang.get_property_as_boolean("x", true));
        assert!(lang.get_property_keys().is_empty());
        assert_eq!(lang.get_maximum_instruction_length(), None);
        assert!(lang.get_parallel_instruction_helper().is_none());

        let ram = lang.get_default_space();
        assert!(!lang.is_volatile(&Address::new(ram, 0)));
        assert!(lang.get_volatile_addresses().is_empty());
        assert_eq!(lang.get_segmented_space(), "");
        assert!(lang.get_default_symbols().is_empty());
        assert!(lang.get_default_memory_blocks().is_empty());
        assert!(!lang.has_manual());
        assert!(lang.get_manual_entry("ADD").is_none());
        assert!(lang.get_manual_exception().is_none());
    }

    #[test]
    fn reload_is_an_io_error() {
        let lang = language(&Sla::default());
        let monitor = crate::util::task::DummyMonitor;
        assert!(lang.reload_language(&monitor).is_err());
    }

    #[test]
    fn misaligned_parse_is_unknown_instruction() {
        struct Buf(Address);
        impl MemBuffer for Buf {
            fn get_byte(&self, _o: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
                Ok(0)
            }
            fn get_bytes(&self, buf: &mut [u8], _o: i32) -> usize {
                buf.len()
            }
            fn is_big_endian(&self) -> bool {
                false
            }
            fn get_address(&self) -> Address {
                self.0.clone()
            }
        }
        struct Ctx;
        impl crate::program::model::lang::processor_context_view::ProcessorContextView for Ctx {
            fn get_base_context_register(&self) -> Option<RegisterRef> {
                None
            }
            fn get_registers(&self) -> Vec<RegisterRef> {
                Vec::new()
            }
            fn get_register(&self, _name: &str) -> Option<RegisterRef> {
                None
            }
            fn get_value(&self, _r: &Register, _s: bool) -> Option<i128> {
                None
            }
            fn get_register_value(&self, _r: &Register) -> Option<crate::program::model::lang::register_value::RegisterValue> {
                None
            }
            fn has_value(&self, _r: &Register) -> bool {
                false
            }
        }
        impl ProcessorContext for Ctx {
            fn set_value(&mut self, _r: &Register, _v: i128) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
            fn set_register_value(&mut self, _v: crate::program::model::lang::register_value::RegisterValue) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
            fn clear_register(&mut self, _r: &Register) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException> {
                Ok(())
            }
        }
        let lang = language(&Sla { alignment: 4, ..Sla::default() });
        let buf = Buf(Address::new(lang.get_default_space(), 0x1002));
        match lang.parse(&buf, &mut Ctx, false) {
            Err(ParseError::UnknownInstruction(e)) => {
                assert!(e.to_string().contains("aligned on 4byte boundary"))
            }
            _ => panic!("expected an alignment failure"),
        }
    }

    #[test]
    fn description_supplies_id_version_endianness_and_compiler_specs() {
        let lang = with_description(&Sla::default(), MockDescription::new(Endian::Little)).unwrap();
        assert_eq!(lang.get_language_id().get_id_as_string(), "toy:BE:32:v2");
        assert_eq!(lang.get_id(), "toy:BE:32:v2");
        assert_eq!(lang.get_version(), 3);
        assert_eq!(lang.get_minor_version(), 7);
        assert_eq!(lang.get_processor().name(), "toy");
        assert_eq!(lang.get_language_description().get_variant(), "v2");
        assert_eq!(lang.to_string(), "toy/little/32/v2");
        let specs = lang.get_compatible_compiler_spec_descriptions();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].get_compiler_spec_id(), CompilerSpecID::new(Some("default")));
        match lang.get_compiler_spec_by_id(&CompilerSpecID::new(Some("gcc"))) {
            Err(e) => assert!(e.to_string().contains("gcc")),
            Ok(_) => panic!("gcc is not a compatible compiler spec"),
        }
    }

    #[test]
    fn ldefs_endianness_must_match_sla_unless_instructions_differ() {
        // Data big, instructions big, .sla little: rejected.
        let err = with_description(&Sla::default(), MockDescription::new(Endian::Big));
        assert!(err.is_err());
        // Bi-endian: data big but instructions little -- accepted, and the description's data
        // endianness wins.
        let mut d = MockDescription::new(Endian::Big);
        d.inst_endian = Endian::Little;
        let lang = with_description(&Sla::default(), d).unwrap();
        assert!(Language::is_big_endian(&lang));
    }

    #[test]
    fn space_truncation_is_applied_and_validated() {
        let mut d = MockDescription::new(Endian::Little);
        d.truncated.insert("ram".to_string(), 2);
        let lang = with_description(&Sla::default(), d).unwrap();
        assert_eq!(lang.get_default_space().size(), 16);

        // Not smaller than the real size.
        let mut d = MockDescription::new(Endian::Little);
        d.truncated.insert("ram".to_string(), 4);
        assert!(with_description(&Sla::default(), d).is_err());

        // Non-ram spaces cannot be truncated.
        let mut d = MockDescription::new(Endian::Little);
        d.truncated.insert("register".to_string(), 2);
        assert!(with_description(&Sla::default(), d).is_err());

        // A truncation naming no space is reported.
        let mut d = MockDescription::new(Endian::Little);
        d.truncated.insert("bogus".to_string(), 2);
        assert!(with_description(&Sla::default(), d).is_err());
    }

    #[test]
    fn manual_index_comes_from_the_description() {
        let dir = std::env::temp_dir().join(format!("ghidra_rs_sleigh_lang_manual_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("toy.pdf"), b"pdf").unwrap();
        std::fs::write(dir.join("toy.idx"), "@toy.pdf\nADD, 5\n").unwrap();
        let mut d = MockDescription::new(Endian::Little);
        d.manual_index_file = Some(ResourceFile::new(dir.join("toy.idx")));
        let lang = with_description(&Sla::default(), d).unwrap();
        assert!(lang.has_manual());
        assert!(lang.get_manual_exception().is_none());
        assert_eq!(lang.get_manual_entry("add").unwrap().page_number(), "5");
        assert_eq!(
            lang.get_manual_instruction_mnemonic_keys(),
            ["ADD".to_string()].into_iter().collect::<HashSet<String>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Captures the bytes a `RegisterValue` would be built from.
    struct CapturingBuilder(std::cell::RefCell<Vec<u8>>);

    impl crate::app::seam_stubs::RegisterValueBuilder for CapturingBuilder {
        fn build_register_value(
            &self,
            register: RegisterRef,
            bytes: Vec<u8>,
        ) -> crate::program::model::lang::register_value::RegisterValue {
            assert_eq!(register.name(), "contextreg");
            *self.0.borrow_mut() = bytes;
            crate::program::model::lang::register_value::RegisterValue::new(register)
        }
    }

    #[test]
    fn parser_context_exports_its_context_words_as_the_context_register() {
        use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
        use crate::program::model::mem::ByteMemBufferImpl;
        let lang = language(&Sla::default()).into_shared();
        let mem: Arc<dyn MemBuffer> = Arc::new(ByteMemBufferImpl::new(
            Address::new(lang.get_default_space(), 0),
            vec![0],
            false,
        ));
        let ctx = SleighParserContext::for_resolve(mem, lang.clone(), vec![0x8012_3456u32 as i32]);
        let builder = CapturingBuilder(std::cell::RefCell::new(Vec::new()));
        assert!(ctx.get_context_register_value(&builder).is_some());
        // four mask bytes, then the word big-endian
        assert_eq!(
            *builder.0.borrow(),
            vec![0xff, 0xff, 0xff, 0xff, 0x80, 0x12, 0x34, 0x56]
        );
        // the context cache sizes the words from the same register
        assert_eq!(lang.new_context_cache().get_context_size(), 1);
    }

    #[derive(Default)]
    struct RecordingDisassemblerContext {
        future: Vec<Address>,
    }

    impl crate::program::model::lang::processor_context_view::ProcessorContextView
        for RecordingDisassemblerContext
    {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(
            &self,
            _register: &Register,
        ) -> Option<crate::program::model::lang::register_value::RegisterValue> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for RecordingDisassemblerContext {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException>
        {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: crate::program::model::lang::register_value::RegisterValue,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException>
        {
            Ok(())
        }
        fn clear_register(
            &mut self,
            _register: &Register,
        ) -> Result<(), crate::program::model::listing::context_change_exception::ContextChangeException>
        {
            Ok(())
        }
    }

    impl crate::program::model::lang::disassembler_context::DisassemblerContext
        for RecordingDisassemblerContext
    {
        fn set_future_register_value(
            &mut self,
            address: Address,
            _value: crate::program::model::lang::register_value::RegisterValue,
        ) {
            self.future.push(address);
        }
        fn set_future_register_value_for_flow(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _value: crate::program::model::lang::register_value::RegisterValue,
        ) {
        }
    }

    #[test]
    fn apply_commits_sets_future_context_at_the_committed_address() {
        use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
        use crate::program::model::lang::sleigh::walker::ConstructTree;
        use crate::program::model::mem::ByteMemBufferImpl;
        let lang = language(&Sla::default()).into_shared();
        let mem: Arc<dyn MemBuffer> = Arc::new(ByteMemBufferImpl::new(
            Address::new(lang.get_default_space(), 0x40),
            vec![0],
            false,
        ));
        let ctx = SleighParserContext::for_resolve(mem, lang, vec![0x8000_0001u32 as i32]);
        // globalset(sp, TMode): symbol 2 is `sp`, a varnode at ram:0x100
        ctx.add_commit(ConstructTree::ROOT, 2, 0, 0x8000_0000u32 as i32);
        let builder = CapturingBuilder(std::cell::RefCell::new(Vec::new()));
        let mut dis = RecordingDisassemblerContext::default();
        ctx.apply_commits(&mut dis, &builder).unwrap();

        assert_eq!(dis.future.len(), 1);
        assert_eq!(dis.future[0].offset(), 0x100);
        // mask word, then the committed (masked) value word
        assert_eq!(
            *builder.0.borrow(),
            vec![0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]
        );
        // the commits are consumed
        assert!(ctx.get_context_commits().is_empty());
        ctx.apply_commits(&mut dis, &builder).unwrap();
        assert_eq!(dis.future.len(), 1);
    }
}
