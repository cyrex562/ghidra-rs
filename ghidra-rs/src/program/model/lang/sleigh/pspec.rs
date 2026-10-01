//! The processor-specification (`.pspec`) half of `SleighLanguage`: Java's
//! `readInitialDescription`, `readRemainingSpecification` and `read(XmlPullParser)`, with the
//! helpers they use (`setDefaultDataSpace`, `setProgramCounter`, `parseRange`,
//! `buildVolatileSymbolAddresses`).
//!
//! As in Java, the `.pspec` is validated against its RELAX NG schema
//! ([`SleighLanguageValidator::validate_pspec_file`]) and its `<segmented_address>` read before the
//! `.sla` is decoded (the segmented space changes how that space is built); everything else is
//! read once the `.sla` registers are in the [`RegisterBuilder`], which the `.pspec` then edits
//! (renames, aliases, groups, flags, vector lane sizes).
//!
//! # Errors
//! Java distinguishes two kinds of failure while reading the remaining specification:
//! an `XmlParseException` (an unknown top-level tag, an invalid default symbol, a payload that
//! fails to restore) is logged and ends the read, keeping what was read so far; anything else
//! (a bad register in `<context_data>`, an unknown address space, a failed register rename, an
//! invalid lane size, a malformed document) aborts building the language. [`PspecError`] keeps
//! that distinction.

use super::SleighLanguage;
use crate::app::plugin::processors::generic::memory_block_definition::DefaultMemoryBlockDefinition;
use crate::app::plugin::processors::sleigh::sleigh_exception::SleighException;
use crate::app::plugin::processors::sleigh::sleigh_language_validator::SleighLanguageValidator;
use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::address::{Address, AddressFactory, AddressSet, AddressSpace};
use crate::program::model::lang::address_label_info::AddressLabelInfo;
use crate::program::model::lang::inject_payload_jump_assist::InjectPayloadJumpAssist;
use crate::program::model::lang::inject_payload_segment::InjectPayloadSegment;
use crate::program::model::lang::inject_payload_sleigh::InjectPayloadSleigh;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterId};
use crate::program::model::lang::register_builder::RegisterBuilder;
use crate::program::util::processor_symbol_type::ProcessorSymbolType;
use crate::util::msg::Msg;
use crate::util::xml::spec_xml_utils::{decode_boolean, decode_int, decode_long, decode_nullable_boolean};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_parse_exception::XmlParseException;
use crate::util::xml::xml_pull_parser::XmlPullParser;
use crate::util::xml::xml_pull_parser_factory;
use std::collections::HashSet;
use std::sync::Arc;

const ORIGINATOR: &str = "SleighLanguage";

/// A failure while reading the `.pspec`; see the module docs.
#[derive(Debug)]
pub(super) enum PspecError {
    /// Java's checked `XmlParseException`: logged, ending the read.
    Parse(XmlParseException),
    /// Java's unchecked `SleighException`/`XmlException` (and other runtime failures): fatal.
    Fatal(String),
}

impl From<XmlException> for PspecError {
    /// The pull parser's structural errors are Java's unchecked `XmlException`.
    fn from(e: XmlException) -> Self {
        PspecError::Fatal(e.to_string())
    }
}

impl From<XmlParseException> for PspecError {
    fn from(e: XmlParseException) -> Self {
        PspecError::Parse(e)
    }
}

fn fatal(message: impl Into<String>) -> PspecError {
    PspecError::Fatal(message.into())
}

/// A `<context_set>`/`<tracked_set>` `<set>` read from the `.pspec`, whose register is resolved
/// against the final register manager once the `.pspec` has been read (Java's `ContextSetting`
/// holds the `Register` object itself).
pub(super) struct PendingContextSetting {
    pub(super) register: RegisterId,
    pub(super) value: u128,
    pub(super) start: Address,
    pub(super) end: Address,
}

/// Port of `SleighLanguageValidator.validatePspecFile(description.getSpecFile())`, the first
/// thing Java's `initialize` does.
pub(super) fn validate(spec_file: &ResourceFile) -> Result<(), SleighException> {
    SleighLanguageValidator::validate_pspec_file(spec_file)
}

/// Port of `readInitialDescription()`: the `space` and `type` of the first
/// `<segmented_address>` element anywhere in the `.pspec`, or two empty strings if there is
/// none. Java leaves `segmentedspace` at its `""` default when the element is absent, and reads
/// a missing `type` as `""`.
///
/// # Errors
/// If the file cannot be read or parsed (Java's `SleighException`, "Error reading initial
/// description - language probably did not compile properly").
pub(super) fn read_initial_description(spec_file: &ResourceFile) -> Result<(String, String), SleighException> {
    let wrap = |e: &dyn std::fmt::Display| {
        SleighException::with_message(format!(
            "Error reading initial description - language probably did not compile properly: {e}"
        ))
    };
    let mut parser = xml_pull_parser_factory::create_from_resource_file(spec_file, None, false)
        .map_err(|e| wrap(&e))?;
    let mut result = (String::new(), String::new());
    while parser.has_next() {
        if parser.peek().get_name() == "segmented_address" {
            let element = parser.start(&[]).map_err(|e| wrap(&e))?;
            // Java: `segmentedspace = element.getAttribute("space")`; the schema requires it.
            result.0 = element.get_attribute("space").unwrap_or_default();
            result.1 = element.get_attribute("type").unwrap_or_default();
            break;
        }
        parser.next();
    }
    parser.dispose();
    Ok(result)
}

impl SleighLanguage {
    /// Port of `readRemainingSpecification()`: reads the `.pspec` into this language and
    /// `builder`. An [`PspecError::Parse`] is logged (Java's `Msg.error`, "Failed to parse Sleigh
    /// Specification"), keeping whatever was read before it.
    ///
    /// # Errors
    /// The file cannot be read, or a [`PspecError::Fatal`] failure (see the module docs).
    pub(super) fn read_remaining_specification(
        &mut self,
        spec_file: &ResourceFile,
        builder: &mut RegisterBuilder,
        pending_context: &mut Vec<PendingContextSetting>,
    ) -> Result<(), SleighException> {
        let mut parser = xml_pull_parser_factory::create_from_resource_file(spec_file, None, false)
            .map_err(|e| {
                SleighException::with_message(format!(
                    "Error reading remaining spec - language probably did not compile properly: {e}"
                ))
            })?;
        let result = self.read(&mut parser, builder, pending_context);
        parser.dispose();
        match result {
            Ok(()) => Ok(()),
            Err(PspecError::Parse(e)) => {
                Msg::error(
                    ORIGINATOR,
                    &format!("Failed to parse Sleigh Specification ({}): {e}", spec_file.name()),
                );
                Ok(())
            }
            Err(PspecError::Fatal(message)) => Err(SleighException::with_message(message)),
        }
    }

    fn spec_file_name(&self) -> String {
        self.description
            .as_ref()
            .and_then(|d| d.get_spec_file().map(|f| f.absolute_path()))
            .unwrap_or_default()
    }

    /// Port of `addAdditionInject(InjectPayloadSleigh)`.
    fn add_addition_inject(&mut self, payload: Arc<dyn InjectPayloadSleigh>) {
        self.additional_inject.get_or_insert_with(Vec::new).push(payload);
    }

    /// Port of `setDefaultDataSpace(String)`.
    fn set_default_data_space(&mut self, space_name: Option<String>) {
        let Some(space_name) = space_name else { return };
        match self._address_factory.get_address_space_by_name(&space_name) {
            Some(space) if space.is_loaded_memory_space() => {
                self.default_pointer_word_size = space.unit_size();
                self.default_data_space = Some(space);
            }
            _ => Msg::error(
                ORIGINATOR,
                &format!("unknown/invalid BSS space {space_name}: {}", self.spec_file_name()),
            ),
        }
    }

    /// Port of `setProgramCounter(String)`.
    fn set_program_counter(&mut self, builder: &mut RegisterBuilder, program_counter_name: Option<String>) {
        let Some(name) = program_counter_name else { return };
        let Some(id) = builder.get_register(&name).map(|r| r.id()) else {
            Msg::error(
                ORIGINATOR,
                &format!("unknown program counter register {name}: {}", self.spec_file_name()),
            );
            return;
        };
        builder.set_flag(&name, Register::TYPE_PC);
        self.program_counter = Some(id);
    }

    /// Port of `parseRange(XmlElement)`: the `space` attribute's space, from `first` (default 0)
    /// to `last` (default the space's maximum offset).
    fn parse_range<E: XmlElement>(&self, element: &E) -> Result<(Address, Address), PspecError> {
        let space = element.get_attribute("space").unwrap_or_default();
        let addrspace: &Arc<AddressSpace> = self
            ._space_table
            .get(&space)
            .ok_or_else(|| fatal(format!("Invalid address space name: {space}")))?;
        let mut first = 0;
        let mut last = addrspace.max_offset();
        if let Some(s) = element.get_attribute("first") {
            first = decode_long(Some(&s));
        }
        if let Some(s) = element.get_attribute("last") {
            last = decode_long(Some(&s));
        }
        // Java's `getAddress` throws AddressOutOfBoundsException (unchecked) for a bad offset.
        let address = |offset| addrspace.checked_address(offset).map_err(|e| fatal(e.to_string()));
        Ok((address(first)?, address(last)?))
    }

    /// Port of `read(XmlPullParser)`.
    fn read<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
        builder: &mut RegisterBuilder,
        pending_context: &mut Vec<PendingContextSetting>,
    ) -> Result<(), PspecError> {
        let mut register_data_set: HashSet<String> = HashSet::new();

        let el = parser.start(&["processor_spec"])?;
        while parser.peek().is_start() {
            let el_name = parser.peek().get_name().to_string();
            match el_name.as_str() {
                "properties" => {
                    let subel = parser.start(&[])?;
                    while !parser.peek().is_end() {
                        let next = parser.start(&["property"])?;
                        let key = next.get_attribute("key").unwrap_or_default();
                        let value = next.get_attribute("value").unwrap_or_default();
                        self.set_property(key, value);
                        parser.end_matching(&next)?;
                    }
                    parser.end_matching(&subel)?;
                }
                "programcounter" => {
                    let subel = parser.start(&[])?;
                    self.set_program_counter(builder, subel.get_attribute("register"));
                    parser.end_matching(&subel)?;
                }
                "data_space" => {
                    let subel = parser.start(&[])?;
                    self.set_default_data_space(subel.get_attribute("space"));
                    if let Some(override_string) = subel.get_attribute("ptr_wordsize") {
                        let val = decode_int(Some(&override_string));
                        if val <= 0 || val >= 32 {
                            return Err(fatal("Bad ptr_wordsize attribute"));
                        }
                        self.default_pointer_word_size = val;
                    }
                    parser.end_matching(&subel)?;
                }
                "context_data" => {
                    let subel = parser.start(&[])?;
                    while !parser.peek().is_end() {
                        let next = parser.start(&[])?;
                        let is_context = next.get_name() == "context_set";
                        let (first, last) = self.parse_range(&next)?;
                        while parser.peek().get_name() == "set" {
                            let set = parser.start(&[])?;
                            let name = set.get_attribute("name").unwrap_or_default();
                            let value = parse_context_value(&set.get_attribute("val").unwrap_or_default());
                            let reg = builder.get_register(&name);
                            let bad = match reg {
                                None => true,
                                Some(r) if is_context => !r.is_processor_context(),
                                Some(r) => r.is_processor_context(),
                            };
                            let Some(reg) = reg.filter(|_| !bad) else {
                                return Err(fatal(format!("Bad register name: {name}")));
                            };
                            pending_context.push(PendingContextSetting {
                                register: reg.id(),
                                value,
                                start: first.clone(),
                                end: last.clone(),
                            });
                            parser.end_matching(&set)?;
                        }
                        parser.end_matching(&next)?;
                    }
                    parser.end_matching(&subel)?;
                }
                "volatile" => {
                    let subel = parser.start(&[])?;
                    while parser.peek().get_name() != "volatile" {
                        let next = parser.start(&[])?;
                        if next.get_name() == "register" {
                            return Err(fatal("no support for volatile registers yet"));
                        }
                        let (first, last) = self.parse_range(&next)?;
                        self.volatile_addresses.add_range(&first, &last);
                        parser.end_matching(&next)?;
                    }
                    parser.end_matching(&subel)?;
                }
                "jumpassist" => {
                    let subel = parser.start(&[])?;
                    let source = format!("pspec: {}", self.get_language_id().get_id_as_string());
                    let name = subel.get_attribute("name").unwrap_or_default();
                    while parser.peek().is_start() {
                        let mut payload = InjectPayloadJumpAssist::new(name.clone(), source.clone());
                        payload.restore_xml(parser)?;
                        self.add_addition_inject(Arc::new(payload));
                    }
                    parser.end_matching(&subel)?;
                }
                "register_data" => {
                    let subel = parser.start(&[])?;
                    while parser.peek().get_name() == "register" {
                        let reg = parser.start(&[])?;
                        self.read_register_data(&reg, builder, &mut register_data_set)?;
                        parser.end_matching(&reg)?;
                    }
                    parser.end_matching(&subel)?;
                }
                "default_symbols" => {
                    let subel = parser.start(&[])?;
                    let mut previous_addr: Option<Address> = None;
                    let mut previous_size = 1;
                    while parser.peek().get_name() == "symbol" {
                        let symbol = parser.start(&[])?;
                        let (start_address, range_size) =
                            self.read_default_symbol(&symbol, previous_addr.as_ref(), previous_size)?;
                        parser.end_matching(&symbol)?;
                        previous_addr = start_address;
                        previous_size = range_size;
                    }
                    parser.end_matching(&subel)?;
                }
                "default_memory_blocks" => {
                    let subel = parser.start(&[])?;
                    let mut list = Vec::new();
                    while parser.peek().get_name() == "memory_block" {
                        let mblock = parser.start(&[])?;
                        // Java's `XmlAttributeException` is unchecked.
                        list.push(DefaultMemoryBlockDefinition::from_xml_element(&mblock).map_err(|e| fatal(e.to_string()))?);
                        parser.end_matching(&mblock)?;
                    }
                    parser.end_matching(&subel)?;
                    self.default_memory_blocks = list;
                }
                "incidentalcopy" | "inferptrbounds" => {
                    let subel = parser.start(&[])?;
                    while parser.peek().is_start() {
                        parser.discard_sub_tree();
                    }
                    parser.end_matching(&subel)?;
                }
                "segmentop" => {
                    let source = format!("pspec: {}", self.get_language_id().get_id_as_string());
                    let mut payload = InjectPayloadSegment::new(source);
                    payload.restore_xml(parser, self)?;
                    self.add_addition_inject(Arc::new(payload));
                }
                "segmented_address" => {
                    // Already read by `read_initial_description`.
                    let subel = parser.start(&[])?;
                    parser.end_matching(&subel)?;
                }
                _ => {
                    return Err(PspecError::Parse(XmlParseException::new(format!(
                        "Unknown pspec tag: {el_name}"
                    ))))
                }
            }
        }
        parser.end_matching(&el)?;
        Ok(())
    }

    /// One `<register>` of `<register_data>` (the body of Java's loop).
    fn read_register_data<E: XmlElement>(
        &mut self,
        reg: &E,
        builder: &mut RegisterBuilder,
        register_data_set: &mut HashSet<String>,
    ) -> Result<(), PspecError> {
        let mut register_name = reg.get_attribute("name").unwrap_or_default();
        let register_rename = reg.get_attribute("rename");
        let register_alias = reg.get_attribute("alias");
        let group_name = reg.get_attribute("group");
        let is_hidden = decode_boolean(reg.get_attribute("hidden").as_deref().unwrap_or(""));
        let is_volatile = decode_boolean(reg.get_attribute("volatile").as_deref().unwrap_or(""));
        if let Some(rename) = register_rename {
            if !builder.rename_register(&register_name, &rename) {
                return Err(fatal(format!("error renaming {register_name} to {rename}")));
            }
            register_name = rename;
        }

        let Some(register) = builder.get_register(&register_name) else {
            Msg::error(
                ORIGINATOR,
                &format!("unknown register {register_name}: {}", self.spec_file_name()),
            );
            return Ok(());
        };
        let first = register.address().clone();
        let num_bytes = register.num_bytes();
        if !register_data_set.insert(register_name.clone()) {
            Msg::error(
                ORIGINATOR,
                &format!("duplicate register {register_name}: {}", self.spec_file_name()),
            );
        }
        if let Some(alias) = register_alias {
            builder.add_alias(&register_name, &alias);
        }
        if let Some(group) = group_name {
            builder.set_group(&register_name, &group);
        }
        if is_hidden {
            builder.set_flag(&register_name, Register::TYPE_HIDDEN);
        }
        if is_volatile {
            // Java's `Address.add` throws (unchecked) on overflow.
            let second = first.add((num_bytes - 1) as i64).map_err(|e| fatal(e.to_string()))?;
            self.volatile_addresses.add_range(&first, &second);
        }
        if let Some(sizes) = reg.get_attribute("vector_lane_sizes") {
            for lane in sizes.split(',') {
                let lane_size = decode_int(Some(lane.trim()));
                // Java's UnsupportedOperationException/IllegalArgumentException are unchecked.
                builder.add_lane_size(&register_name, lane_size).map_err(fatal)?;
            }
        }
        Ok(())
    }

    /// One `<symbol>` of `<default_symbols>` (the body of Java's loop). Returns the symbol's
    /// start address (if it resolved) and its `size` attribute, which become the "previous"
    /// address and size for a following `address="next"`.
    fn read_default_symbol<E: XmlElement>(
        &mut self,
        symbol: &E,
        previous_addr: Option<&Address>,
        previous_size: i32,
    ) -> Result<(Option<Address>, i32), PspecError> {
        let label_name = symbol.get_attribute("name").unwrap_or_default();
        let address_string = symbol.get_attribute("address").unwrap_or_default();
        let type_string = symbol.get_attribute("type");
        let comment = symbol.get_attribute("description");
        // Java's IllegalArgumentException for an unknown type is unchecked.
        let symbol_type = ProcessorSymbolType::get_type(type_string.as_deref()).map_err(fatal)?;
        let is_entry = decode_boolean(symbol.get_attribute("entry").as_deref().unwrap_or(""));
        let mut start_address = None;
        if address_string.eq_ignore_ascii_case("next") {
            match previous_addr {
                None => Msg::error(
                    ORIGINATOR,
                    &format!(
                        "use of addr=\"next\" tag with no previous address for {label_name} : {}",
                        self.spec_file_name()
                    ),
                ),
                Some(previous) => {
                    let next = previous.add(previous_size as i64).map_err(|e| fatal(e.to_string()))?;
                    start_address = Some(next);
                }
            }
        } else {
            start_address = self._address_factory.get_address(&address_string);
        }
        let range_size = decode_int(symbol.get_attribute("size").as_deref());
        let is_volatile = symbol
            .get_attribute("volatile")
            .and_then(|s| decode_nullable_boolean(&s));
        match &start_address {
            None => Msg::error(
                ORIGINATOR,
                &format!("invalid symbol address \"{address_string}\": {}", self.spec_file_name()),
            ),
            Some(start) => {
                let info = AddressLabelInfo::new(
                    start.clone(),
                    Some(range_size),
                    label_name.clone(),
                    comment,
                    false,
                    is_entry,
                    symbol_type,
                    is_volatile,
                )
                .map_err(|e| {
                    PspecError::Parse(XmlParseException::new(format!(
                        "invalid symbol definition: {label_name}: {e}"
                    )))
                })?;
                if let Some(volatile) = is_volatile {
                    let end_address = info.get_end_address().clone();
                    let set = if volatile {
                        self.volatile_symbol_addresses.get_or_insert_with(AddressSet::new)
                    } else {
                        // punch a hole in the volatile address space.
                        self.non_volatile_symbol_addresses.get_or_insert_with(AddressSet::new)
                    };
                    set.add_range(start, &end_address);
                }
                self.default_symbols.push(info);
            }
        }
        Ok((start_address, range_size))
    }

    /// Port of `buildVolatileSymbolAddresses()`.
    pub(super) fn build_volatile_symbol_addresses(&mut self) {
        if let Some(set) = &self.volatile_symbol_addresses {
            self.volatile_addresses.add_set(set);
        }
        if let Some(set) = &self.non_volatile_symbol_addresses {
            self.volatile_addresses.delete_set(set);
        }
    }
}

/// The value of a `<set val="...">`: Java's `new BigInteger(sValue, radix)` with a `0x`/`0X`
/// prefix selecting hex, and `0` for anything unparseable.
fn parse_context_value(s: &str) -> u128 {
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (s, 10),
    };
    u128::from_str_radix(digits, radix).unwrap_or(0)
}

/// Loads the real `.pspec` files from `orig_src/Ghidra/Processors` against generated `.sla`
/// fixtures declaring the registers and context variables each `.pspec` refers to (no compiled
/// `.sla` files are available), and checks what is read against the files.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_language_description::SleighLanguageDescription;
    use crate::app::plugin::processors::sleigh::sleigh_language_file::SleighLanguageFile;
    use crate::program::model::address::{AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::register_value::RegisterValue;
    use crate::program::model::lang::Endian;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::model::pcode::ids::*;
    use crate::program::model::pcode::{DecoderError, PackedDecode, PackedEncode};
    use crate::program::seam_stubs::Processor;
    use std::collections::HashSet;
    use std::path::PathBuf;

    /// What the generated `.sla` declares. `ram` lists the ram spaces as (name, size, wordsize),
    /// the first being the default space; `registers` are laid out one after another in the
    /// 4-byte `register` space; each context variable is one bit of a 4-byte `contextreg`.
    struct Fixture {
        big_endian: bool,
        ram: Vec<(&'static str, i64, i64)>,
        registers: Vec<(&'static str, i64)>,
        context: Vec<&'static str>,
    }

    fn space(e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, index: i64, size: i64, delay: i64, wordsize: i64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_signed_integer(ATTRIB_INDEX, index).unwrap();
        e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
        e.write_signed_integer(ATTRIB_DELAY, delay).unwrap();
        if wordsize != 1 {
            e.write_signed_integer(ATTRIB_WORDSIZE, wordsize).unwrap();
        }
        e.close_element(elem).unwrap();
    }

    fn head(e: &mut PackedEncode<Vec<u8>>, elem: ElementId, name: &str, id: u64) {
        e.open_element(elem).unwrap();
        e.write_string(ATTRIB_NAME, name).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
        e.write_unsigned_integer(ATTRIB_SCOPE, 0).unwrap();
        e.close_element(elem).unwrap();
    }

    fn sla(f: &Fixture) -> Vec<u8> {
        let register_index = f.ram.len() as i64 + 1;
        let mut e = PackedEncode::new(Vec::<u8>::new());
        e.open_element(ELEM_SLEIGH).unwrap();
        e.write_signed_integer(ATTRIB_VERSION, 4).unwrap();
        e.write_bool(ATTRIB_BIGENDIAN, f.big_endian).unwrap();
        e.write_signed_integer(ATTRIB_ALIGN, 1).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQBASE, 0x1000).unwrap();
        e.write_unsigned_integer(ATTRIB_UNIQMASK, 0xff).unwrap();
        e.write_unsigned_integer(ATTRIB_NUMSECTIONS, 1).unwrap();
        e.open_element(ELEM_SPACES).unwrap();
        e.write_string(ATTRIB_DEFAULTSPACE, f.ram[0].0).unwrap();
        e.open_element(ELEM_SPACE_OTHER).unwrap();
        e.close_element(ELEM_SPACE_OTHER).unwrap();
        for (i, (name, size, wordsize)) in f.ram.iter().enumerate() {
            space(&mut e, ELEM_SPACE, name, i as i64 + 1, *size, 1, *wordsize);
        }
        space(&mut e, ELEM_SPACE, "register", register_index, 4, 0, 1);
        space(&mut e, ELEM_SPACE_UNIQUE, "unique", register_index + 1, 4, 0, 1);
        e.close_element(ELEM_SPACES).unwrap();

        let nregs = f.registers.len() as u64;
        let nctx = f.context.len() as u64;
        e.open_element(ELEM_SYMBOL_TABLE).unwrap();
        e.write_signed_integer(ATTRIB_SCOPESIZE, 1).unwrap();
        e.write_signed_integer(ATTRIB_SYMBOLSIZE, (nregs + 1 + nctx) as i64).unwrap();
        e.open_element(ELEM_SCOPE).unwrap();
        e.write_unsigned_integer(ATTRIB_ID, 0).unwrap();
        e.write_unsigned_integer(ATTRIB_PARENT, 0).unwrap();
        e.close_element(ELEM_SCOPE).unwrap();
        for (i, (name, _)) in f.registers.iter().enumerate() {
            head(&mut e, ELEM_VARNODE_SYM_HEAD, name, i as u64);
        }
        head(&mut e, ELEM_VARNODE_SYM_HEAD, "contextreg", nregs);
        for (i, name) in f.context.iter().enumerate() {
            head(&mut e, ELEM_CONTEXT_SYM_HEAD, name, nregs + 1 + i as u64);
        }
        let varnode = |e: &mut PackedEncode<Vec<u8>>, id: u64, offset: u64, size: i64| {
            e.open_element(ELEM_VARNODE_SYM).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, id).unwrap();
            e.write_space_indexed(ATTRIB_SPACE, register_index as i32, "").unwrap();
            e.write_unsigned_integer(ATTRIB_OFF, offset).unwrap();
            e.write_signed_integer(ATTRIB_SIZE, size).unwrap();
            e.close_element(ELEM_VARNODE_SYM).unwrap();
        };
        let mut offset = 0u64;
        for (i, (_, size)) in f.registers.iter().enumerate() {
            varnode(&mut e, i as u64, offset, *size);
            offset += (*size as u64).next_multiple_of(8);
        }
        varnode(&mut e, nregs, 0x10000, 4);
        for i in 0..nctx {
            let bit = i as i64;
            e.open_element(ELEM_CONTEXT_SYM).unwrap();
            e.write_unsigned_integer(ATTRIB_ID, nregs + 1 + i).unwrap();
            e.write_unsigned_integer(ATTRIB_VARNODE, nregs).unwrap();
            e.write_signed_integer(ATTRIB_LOW, bit).unwrap();
            e.write_signed_integer(ATTRIB_HIGH, bit).unwrap();
            e.write_bool(ATTRIB_FLOW, true).unwrap();
            e.open_element(ELEM_CONTEXTFIELD).unwrap();
            e.write_bool(ATTRIB_SIGNBIT, false).unwrap();
            e.write_signed_integer(ATTRIB_STARTBIT, bit).unwrap();
            e.write_signed_integer(ATTRIB_ENDBIT, bit).unwrap();
            e.write_signed_integer(ATTRIB_STARTBYTE, 0).unwrap();
            e.write_signed_integer(ATTRIB_ENDBYTE, 0).unwrap();
            e.write_signed_integer(ATTRIB_SHIFT, 7 - bit).unwrap();
            e.close_element(ELEM_CONTEXTFIELD).unwrap();
            e.close_element(ELEM_CONTEXT_SYM).unwrap();
        }
        e.close_element(ELEM_SYMBOL_TABLE).unwrap();
        e.close_element(ELEM_SLEIGH).unwrap();
        e.into_inner()
    }

    struct MockProcessor;
    impl Processor for MockProcessor {}

    /// A `.ldefs` description naming `spec_file` as its `.pspec`.
    struct Description {
        id: &'static str,
        endian: Endian,
        spec_file: ResourceFile,
    }

    impl LanguageDescription for Description {
        fn get_language_id(&self) -> LanguageID {
            LanguageID::new(self.id).unwrap()
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }
        fn get_endian(&self) -> Endian {
            self.endian
        }
        fn get_instruction_endian(&self) -> Endian {
            self.endian
        }
        fn get_size(&self) -> i32 {
            32
        }
        fn get_variant(&self) -> String {
            "default".to_string()
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_description(&self) -> String {
            String::new()
        }
        fn is_deprecated(&self) -> bool {
            false
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
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

    impl SleighLanguageDescription for Description {
        fn get_truncated_space_names(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_truncated_space_size(&self, _space_name: &str) -> Option<i32> {
            None
        }
        fn get_defs_file(&self) -> Option<&ResourceFile> {
            None
        }
        fn set_defs_file(&mut self, _defs_file: Option<ResourceFile>) {}
        fn get_spec_file(&self) -> Option<&ResourceFile> {
            Some(&self.spec_file)
        }
        fn set_spec_file(&mut self, _spec_file: Option<ResourceFile>) {}
        fn get_manual_index_file(&self) -> Option<&ResourceFile> {
            None
        }
        fn set_manual_index_file(&mut self, _manual_index_file: Option<ResourceFile>) {}
        fn get_language_file(&self) -> Option<&dyn SleighLanguageFile> {
            None
        }
        fn set_language_file(&mut self, _language_file: Option<Box<dyn SleighLanguageFile>>) {}
    }

    fn pspec(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../orig_src/Ghidra/Processors").join(path)
    }

    fn load_file(id: &'static str, spec_file: PathBuf, f: &Fixture) -> Result<SleighLanguage, DecoderError> {
        let endian = if f.big_endian { Endian::Big } else { Endian::Little };
        let description = Description { id, endian, spec_file: ResourceFile::new(spec_file) };
        let decoder = PackedDecode::new(Arc::new(DefaultAddressFactory::new(vec![])), sla(f));
        SleighLanguage::decode_with_description(&decoder, Arc::new(description))
    }

    fn load(id: &'static str, path: &str, f: &Fixture) -> SleighLanguage {
        load_file(id, pspec(path), f).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    fn reg(lang: &SleighLanguage, name: &str) -> Register {
        lang.get_register_by_name(name).unwrap_or_else(|| panic!("no register {name}"))
    }

    fn inject_names(lang: &SleighLanguage) -> Vec<String> {
        lang.get_additional_inject()
            .unwrap_or_default()
            .iter()
            .map(|p| p.get_name())
            .collect()
    }

    /// Records the default values a language applies.
    #[derive(Default)]
    struct RecordingContext {
        set: Vec<(String, u128, Address, Address)>,
    }

    impl DefaultProgramContext for RecordingContext {
        fn set_default_value(&mut self, register_value: RegisterValue, start: &Address, end: &Address) {
            let name = register_value.register().name().to_string();
            let value = register_value.unsigned_value().unwrap();
            self.set.push((name, value, start.clone(), end.clone()));
        }
        fn get_default_value(&self, _register: &Register, _address: &Address) -> Option<RegisterValue> {
            None
        }
    }

    fn x86_fixture() -> Fixture {
        Fixture {
            big_endian: false,
            ram: vec![("ram", 4, 1)],
            registers: vec![
                ("EIP", 4),
                ("DF", 1),
                ("CF", 1),
                ("ST0", 10),
                ("DR0", 4),
                ("CR0", 4),
                ("XMM0", 16),
                ("YMM0", 32),
                ("ZMM0", 64),
                ("eflags", 4),
                ("segover", 1),
                ("DS", 2),
            ],
            context: vec!["addrsize", "opsize", "protectedMode"],
        }
    }

    #[test]
    fn x86_pspec() {
        let lang = load("x86:LE:32:default", "x86/data/languages/x86.pspec", &x86_fixture());

        // <properties>
        let keys = lang.get_property_keys();
        assert_eq!(keys.len(), 3);
        assert_eq!(lang.get_property("useropLibs").as_deref(), Some("x86"));
        assert!(lang.get_property_as_boolean("useOperandReferenceAnalyzerSwitchTables", false));
        assert_eq!(lang.get_property("assemblyRating:x86:LE:32:default").as_deref(), Some("GOLD"));

        // <programcounter>
        let pc = lang.get_program_counter().unwrap();
        assert_eq!(pc.name(), "EIP");
        assert!(pc.is_program_counter());
        assert!(Register::same(&pc, &reg(&lang, "EIP")));

        // <register_data>: groups, lane sizes and hidden flags.
        assert_eq!(reg(&lang, "DR0").group(), Some("DEBUG"));
        assert_eq!(reg(&lang, "CR0").group(), Some("CONTROL"));
        assert_eq!(reg(&lang, "ST0").group(), Some("ST"));
        assert_eq!(reg(&lang, "eflags").group(), Some("FLAGS"));
        let zmm0 = reg(&lang, "ZMM0");
        assert_eq!(zmm0.group(), Some("AVX"));
        assert_eq!(zmm0.lane_sizes(), Some(vec![1, 2, 4, 8]));
        assert!(zmm0.is_vector_register());
        assert!(reg(&lang, "segover").is_hidden());
        assert!(!reg(&lang, "EIP").is_hidden());
        let vector: Vec<String> = lang.get_sorted_vector_registers().iter().map(|r| r.name().to_string()).collect();
        assert_eq!(vector, ["ZMM0", "YMM0", "XMM0"]);

        // <context_data>: two context settings and one tracked register over all of ram.
        let mut ctx = RecordingContext::default();
        lang.apply_context_settings(&mut ctx);
        let ram = lang.get_default_space();
        let all = (ram.address(0), ram.address(0xffff_ffff));
        let expected = [("addrsize", 1u128), ("opsize", 1), ("DF", 0)];
        assert_eq!(ctx.set.len(), expected.len());
        for ((name, value, start, end), (want_name, want_value)) in ctx.set.iter().zip(expected) {
            assert_eq!((name.as_str(), *value), (want_name, want_value));
            assert_eq!((start, end), (&all.0, &all.1));
        }

        // Nothing else is declared.
        assert!(lang.get_additional_inject().is_none());
        assert!(lang.get_default_symbols().is_empty());
        assert!(lang.get_default_memory_blocks().is_empty());
        assert!(lang.get_volatile_addresses().is_empty());
        assert_eq!(lang.get_segmented_space(), "");
    }

    #[test]
    fn x86_16_protected_mode_segmented_space_and_segmentop() {
        let lang = load("x86:LE:16:Protected Mode", "x86/data/languages/x86-16.pspec", &x86_fixture());
        // <segmented_address space="ram" type="protected">: a 32-bit protected-mode space.
        assert_eq!(lang.get_segmented_space(), "ram");
        let ram = lang.get_default_space();
        assert_eq!(ram.name(), "ram");
        assert_eq!(ram.size(), 32);
        assert_eq!(ram.space_type(), AddressSpaceType::Ram);

        // <segmentop>, with its <constresolve> given by register name.
        assert_eq!(inject_names(&lang), ["segment_pcode"]);
        let mut ctx = RecordingContext::default();
        lang.apply_context_settings(&mut ctx);
        let names: Vec<(&str, u128)> = ctx.set.iter().map(|(n, v, _, _)| (n.as_str(), *v)).collect();
        assert_eq!(names, [("addrsize", 0), ("opsize", 0), ("protectedMode", 1), ("DF", 0)]);
        assert_eq!(lang.get_program_counter().unwrap().name(), "EIP");
    }

    #[test]
    fn arm_pspec_aliases_context_and_default_symbols() {
        let fixture = Fixture {
            big_endian: false,
            ram: vec![("ram", 4, 1)],
            registers: vec![("pc", 4), ("spsr", 4), ("TB", 1)],
            context: vec!["TMode", "LRset"],
        };
        let lang = load("ARM:LE:32:v4t", "ARM/data/languages/ARMt_v45.pspec", &fixture);
        assert_eq!(lang.get_property_keys().len(), 7);
        assert_eq!(
            lang.get_property("emulateInstructionStateModifierClass").as_deref(),
            Some("ghidra.program.emulation.ARMEmulateInstructionStateModifier")
        );
        assert!(!lang.get_property_as_boolean("enableSharedReturnAnalysis", true));
        assert_eq!(lang.get_program_counter().unwrap().name(), "pc");

        // <register name="TB" alias="ISAModeSwitch"/>
        let tb = reg(&lang, "TB");
        assert!(Register::same(&tb, &reg(&lang, "ISAModeSwitch")));
        assert!(tb.aliases().any(|a| a == "ISAModeSwitch"));

        let mut ctx = RecordingContext::default();
        lang.apply_context_settings(&mut ctx);
        let names: Vec<&str> = ctx.set.iter().map(|(n, _, _, _)| n.as_str()).collect();
        assert_eq!(names, ["TMode", "LRset", "spsr"]);

        let symbols = lang.get_default_symbols();
        assert_eq!(symbols.len(), 16);
        let ram = lang.get_default_space();
        assert_eq!(symbols[0].get_label(), "Reset");
        assert_eq!(symbols[0].get_address(), &ram.address(0));
        assert!(symbols[0].is_entry());
        assert!(!symbols[0].is_primary());
        assert_eq!(symbols[0].get_processor_symbol_type(), None);
        assert_eq!(symbols[7].get_label(), "FIQ");
        assert_eq!(symbols[7].get_address(), &ram.address(0x1c));
        assert_eq!(symbols[15].get_label(), "H_FIQ");
        assert_eq!(symbols[15].get_address(), &ram.address(0xFFFF_001c));
    }

    #[test]
    fn mos6502_default_symbols_and_memory_blocks() {
        let fixture = Fixture {
            big_endian: false,
            ram: vec![("RAM", 2, 1)],
            registers: vec![("PC", 2)],
            context: vec![],
        };
        let lang = load("6502:LE:16:default", "6502/data/languages/6502.pspec", &fixture);
        assert!(lang.get_property_keys().is_empty());
        assert_eq!(lang.get_program_counter().unwrap().name(), "PC");

        let ram = lang.get_default_space();
        let symbols = lang.get_default_symbols();
        let got: Vec<(&str, i64)> = symbols.iter().map(|s| (s.get_label(), s.get_address().offset())).collect();
        assert_eq!(got, [("NMI", 0xFFFA), ("RES", 0xFFFC), ("IRQ", 0xFFFE)]);
        for s in &symbols {
            assert!(s.is_entry());
            assert_eq!(s.get_processor_symbol_type(), Some(ProcessorSymbolType::CodePtr));
            assert_eq!(s.get_byte_size(), 1);
            assert_eq!(s.get_address().space(), &ram);
        }

        let blocks = lang.get_default_memory_blocks();
        let names: Vec<String> = blocks.iter().map(|b| b.get_block_name()).collect();
        assert_eq!(names, ["ZERO_PAGE", "STACK"]);
        let shown: Vec<String> = lang.default_memory_blocks.iter().map(|b| b.to_string()).collect();
        assert_eq!(shown, ["ZERO_PAGE: start_address=0x0000, uninitialized, length=0x100", "STACK: start_address=0x0100, uninitialized, length=0x100"]);
    }

    #[test]
    fn avr8_data_space_volatile_ranges_and_word_addressed_symbols() {
        let fixture = Fixture {
            big_endian: false,
            ram: vec![("code", 3, 2), ("mem", 2, 1)],
            registers: vec![("PC", 3), ("R1", 1)],
            context: vec![],
        };
        let lang = load("avr8:LE:16:default", "Atmel/data/languages/avr8.pspec", &fixture);
        assert_eq!(lang.get_property("assemblyRating:avr8:LE:16:extended").as_deref(), Some("PLATINUM"));

        // <data_space space="mem"/>
        let mem = lang.get_address_factory().get_address_space_by_name("mem").unwrap();
        assert_eq!(lang.get_default_data_space(), mem);
        assert_eq!(lang.get_default_space().name(), "code");
        assert_eq!(lang.get_default_pointer_word_size(), 1);

        // <volatile>: two ranges of mem.
        let volatile = lang.get_volatile_addresses();
        assert!(lang.is_volatile(&mem.address(0x20)));
        assert!(lang.is_volatile(&mem.address(0x57)));
        assert!(!lang.is_volatile(&mem.address(0x58)));
        assert!(lang.is_volatile(&mem.address(0x60)));
        assert!(lang.is_volatile(&mem.address(0xff)));
        assert!(!lang.is_volatile(&mem.address(0x100)));
        assert_eq!(volatile.num_addresses(), 0x38 + 0xa0);

        // <tracked_set space="code"><set name="R1" val="0"/>
        let mut ctx = RecordingContext::default();
        lang.apply_context_settings(&mut ctx);
        assert_eq!(ctx.set.len(), 1);
        let code = lang.get_default_space();
        assert_eq!(ctx.set[0].0, "R1");
        assert_eq!((&ctx.set[0].2, &ctx.set[0].3), (&code.address(0), &code.max_address()));

        let symbols = lang.get_default_symbols();
        let reset = symbols.iter().find(|s| s.get_label() == "Reset").unwrap();
        assert_eq!(reset.get_address(), &code.address(0));
        assert!(reset.is_entry());
        let pinf = symbols.iter().find(|s| s.get_label() == "PINF").unwrap();
        assert_eq!(pinf.get_address(), &mem.address(0x20));
        assert!(!pinf.is_entry());
    }

    #[test]
    fn jvm_pspec_properties_and_jump_assist() {
        let fixture = Fixture {
            big_endian: true,
            ram: vec![("ram", 4, 1)],
            registers: vec![("PC", 4), ("SP", 4)],
            context: vec![],
        };
        let lang = load("JVM:BE:32:default", "JVM/data/languages/JVM.pspec", &fixture);
        assert_eq!(lang.get_property_keys().len(), 4);
        assert_eq!(
            lang.get_property("pcodeInjectLibraryClass").as_deref(),
            Some("ghidra.app.util.pcodeInject.PcodeInjectLibraryJava")
        );
        assert!(lang.has_property("DisableAllAnalyzers"));
        assert!(lang.get_property_as_boolean("Analyzers.Java Class Analyzer", false));
        assert_eq!(lang.get_program_counter().unwrap().name(), "PC");
        assert_eq!(reg(&lang, "SP").group(), Some("Alt"));

        // <jumpassist name="switchAssist">: one payload per child, sourced from the pspec.
        assert_eq!(
            inject_names(&lang),
            [
                "switchAssist_index2case",
                "switchAssist_index2addr",
                "switchAssist_defaultaddr",
                "switchAssist_calcsize"
            ]
        );
        let payloads = lang.get_additional_inject().unwrap();
        assert_eq!(payloads[0].get_source(), "pspec: JVM:BE:32:default");
        let inputs: Vec<String> = payloads[0].get_input().iter().map(|p| p.get_name().to_string()).collect();
        assert_eq!(inputs, ["index", "opcodeAddr", "padding", "default", "npairs"]);
        assert_eq!(payloads[0].get_output()[0].get_name(), "case");
    }

    #[test]
    fn dalvik_pspec_without_program_counter() {
        let fixture = Fixture {
            big_endian: false,
            ram: vec![("ram", 4, 1)],
            registers: vec![("sp", 4)],
            context: vec![],
        };
        let lang = load("Dalvik:LE:32:default", "Dalvik/data/languages/Dalvik_Base.pspec", &fixture);
        assert_eq!(lang.get_property_keys().len(), 9);
        assert_eq!(
            lang.get_property("pcodeInjectLibraryClass").as_deref(),
            Some("ghidra.dalvik.dex.inject.PcodeInjectLibraryDex")
        );
        assert!(lang.get_property_as_boolean("Analyzers.Android DEX/CDEX Data Markup", false));
        assert!(lang.get_program_counter().is_none());
        assert_eq!(
            inject_names(&lang),
            ["switchAssist_index2case", "switchAssist_index2addr", "switchAssist_defaultaddr"]
        );
    }

    fn write_temp_pspec(xml: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pspec");
        std::fs::write(&path, xml).unwrap();
        (dir, path)
    }

    fn toy() -> Fixture {
        Fixture { big_endian: false, ram: vec![("ram", 4, 1)], registers: vec![("r0", 4), ("r1", 4)], context: vec!["mode"] }
    }

    #[test]
    fn a_pspec_failing_schema_validation_is_rejected() {
        let (_dir, path) = write_temp_pspec("<processor_spec><bogus/></processor_spec>");
        assert!(load_file("toy:LE:32:default", path, &toy()).is_err());
    }

    #[test]
    fn register_data_renames_flags_volatile_registers_and_symbols() {
        let (_dir, path) = write_temp_pspec(
            r#"<processor_spec>
  <programcounter register="pc"/>
  <register_data>
    <register name="r0" rename="pc" alias="ip" group="SYS" volatile="true"/>
    <register name="r1" hidden="true"/>
    <register name="nosuch"/>
  </register_data>
  <default_symbols>
    <symbol name="A" address="0x100" size="4" volatile="true"/>
    <symbol name="B" address="next" size="2" volatile="false"/>
    <symbol name="C" address="next"/>
  </default_symbols>
  <volatile outputop="w" inputop="r">
    <range space="ram" first="0x0" last="0x1ff"/>
  </volatile>
</processor_spec>"#,
        );
        let lang = load_file("toy:LE:32:default", path, &toy()).unwrap();
        // The program counter is read before the rename, so `pc` is unknown to it.
        assert!(lang.get_program_counter().is_none());
        let pc = reg(&lang, "pc");
        assert!(lang.get_register_by_name("r0").is_none());
        assert!(Register::same(&pc, &reg(&lang, "ip")));
        assert_eq!(pc.group(), Some("SYS"));
        assert!(reg(&lang, "r1").is_hidden());
        // volatile="true" on a register makes its bytes volatile.
        assert!(lang.is_volatile(pc.address()));

        let ram = lang.get_default_space();
        let symbols = lang.get_default_symbols();
        let got: Vec<(&str, i64, i32)> =
            symbols.iter().map(|s| (s.get_label(), s.get_address().offset(), s.get_byte_size())).collect();
        // "next" follows the previous symbol's `size` attribute (0 when absent, as in Java).
        assert_eq!(got, [("A", 0x100, 4), ("B", 0x104, 2), ("C", 0x106, 1)]);
        // B (volatile="false") punches a hole in the volatile <range>.
        assert!(lang.is_volatile(&ram.address(0x103)));
        assert!(!lang.is_volatile(&ram.address(0x104)));
        assert!(!lang.is_volatile(&ram.address(0x105)));
        assert!(lang.is_volatile(&ram.address(0x106)));
    }

    #[test]
    fn bad_context_register_is_fatal() {
        let (_dir, path) = write_temp_pspec(
            r#"<processor_spec>
  <context_data>
    <context_set space="ram"><set name="r0" val="1"/></context_set>
  </context_data>
</processor_spec>"#,
        );
        let err = load_file("toy:LE:32:default", path, &toy()).err().unwrap();
        assert!(err.to_string().contains("Bad register name: r0"), "{err}");
    }

    #[test]
    fn context_values_and_ranges() {
        let (_dir, path) = write_temp_pspec(
            r#"<processor_spec>
  <context_data>
    <context_set space="ram" first="0x1000" last="0x1fff"><set name="mode" val="0x1"/></context_set>
    <tracked_set space="ram"><set name="r1" val="0x2a"/><set name="r0" val="42"/></tracked_set>
  </context_data>
</processor_spec>"#,
        );
        let lang = load_file("toy:LE:32:default", path, &toy()).unwrap();
        let ram = lang.get_default_space();
        let mut ctx = RecordingContext::default();
        lang.apply_context_settings(&mut ctx);
        assert_eq!(
            ctx.set,
            [
                ("mode".to_string(), 1, ram.address(0x1000), ram.address(0x1fff)),
                ("r1".to_string(), 0x2a, ram.address(0), ram.max_address()),
                ("r0".to_string(), 42, ram.address(0), ram.max_address()),
            ]
        );
    }

    #[test]
    fn a_language_without_a_pspec_reads_nothing() {
        let decoder = PackedDecode::new(Arc::new(DefaultAddressFactory::new(vec![])), sla(&toy()));
        let lang = SleighLanguage::decode(&decoder, "toy:LE:32:default".to_string()).unwrap();
        assert!(lang.get_program_counter().is_none());
        assert!(lang.get_property_keys().is_empty());
        assert!(lang.get_default_symbols().is_empty());
    }
}

#[cfg(test)]
mod value_tests {
    use super::parse_context_value;

    #[test]
    fn context_values_parse_like_java_big_integer() {
        assert_eq!(parse_context_value("42"), 42);
        assert_eq!(parse_context_value("0x2a"), 42);
        assert_eq!(parse_context_value("0X2A"), 42);
        // Java catches the NumberFormatException and uses 0.
        assert_eq!(parse_context_value("junk"), 0);
        assert_eq!(parse_context_value(""), 0);
    }
}
