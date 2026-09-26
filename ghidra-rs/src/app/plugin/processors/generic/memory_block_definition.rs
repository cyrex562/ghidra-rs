//! Port of `ghidra.app.plugin.processors.generic.MemoryBlockDefinition`.
//!
//! In Java this is a concrete, immutable class built from an `XmlElement` (or its constituent
//! attribute strings) that knows how to create or reconcile a processor-defined default memory
//! block within a program. It was selected as a dependency-cycle cut point -- consumers such as
//! [`Language::get_default_memory_blocks`](crate::program::model::lang::language::Language::get_default_memory_blocks)
//! need to hand back these definitions without depending on this module's `ProgramDB`-driven
//! implementation -- so its public API is exposed here as a trait. [`DefaultMemoryBlockDefinition`]
//! is the concrete, XML-driven implementation that mirrors the original Java class.
//!
//! This promotes the placeholder `trait MemoryBlockDefinition {}` that previously lived in
//! `program::seam_stubs`. Every trait method below carries a default so that the pre-existing
//! bare `impl MemoryBlockDefinition for MockX {}` blocks (grown from that placeholder) keep
//! compiling unmodified.

use std::fmt;
use std::sync::{Arc, RwLock};

use crate::framework::model::DomainObject;
use crate::framework::store::LockException;
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::{Address, AddressOverflowException};
use crate::program::model::listing::Program;
use crate::program::model::mem::{
    InvalidAddressException, MemoryBlock, MemoryBlockException, MemoryBlockType,
    MemoryConflictException,
};
use crate::util::msg::Msg;
use crate::util::xml::xml_attribute_exception::XmlAttributeException;
use crate::util::xml::xml_element::XmlElement;

/// Default block access mode used when no `mode` attribute is specified. Stands in for
/// `MemoryBlockDefinition.DEFAULT_MODE`.
#[allow(dead_code)]
const DEFAULT_MODE: &str = "rw";

/// Aggregates the checked exceptions Java's `MemoryBlockDefinition.fixupBlock`/`createBlock`
/// declare (`LockException`, `MemoryBlockException`, `MemoryConflictException`,
/// `AddressOverflowException`, `InvalidAddressException`), plus an `Unsupported` variant for
/// operations this port cannot yet perform because the memory-management API it would need
/// (`Memory.getBlock(String)`, mapped-block creation/adjustment, `Memory.join`,
/// `Program.getMemory()`) has not been ported yet.
#[derive(Debug)]
pub enum MemoryBlockDefinitionError {
    Lock(LockException),
    Block(MemoryBlockException),
    Conflict(MemoryConflictException),
    Overflow(AddressOverflowException),
    InvalidAddress(InvalidAddressException),
    Unsupported(String),
}

impl fmt::Display for MemoryBlockDefinitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lock(e) => write!(f, "{e}"),
            Self::Block(e) => write!(f, "{e}"),
            Self::Conflict(e) => write!(f, "{e}"),
            Self::Overflow(e) => write!(f, "{e}"),
            Self::InvalidAddress(e) => write!(f, "{e}"),
            Self::Unsupported(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for MemoryBlockDefinitionError {}

impl From<LockException> for MemoryBlockDefinitionError {
    fn from(e: LockException) -> Self {
        Self::Lock(e)
    }
}

impl From<MemoryBlockException> for MemoryBlockDefinitionError {
    fn from(e: MemoryBlockException) -> Self {
        Self::Block(e)
    }
}

impl From<MemoryConflictException> for MemoryBlockDefinitionError {
    fn from(e: MemoryConflictException) -> Self {
        Self::Conflict(e)
    }
}

impl From<AddressOverflowException> for MemoryBlockDefinitionError {
    fn from(e: AddressOverflowException) -> Self {
        Self::Overflow(e)
    }
}

impl From<InvalidAddressException> for MemoryBlockDefinitionError {
    fn from(e: InvalidAddressException) -> Self {
        Self::InvalidAddress(e)
    }
}

/// Provides a default memory block specification. Mirrors `MemoryBlockDefinition`'s public API.
pub trait MemoryBlockDefinition {
    /// Stands in for `MemoryBlockDefinition.getBlockName()`.
    fn get_block_name(&self) -> String {
        String::new()
    }

    /// Stands in for `MemoryBlockDefinition.fixupBlock(ProgramDB)`: create or fix up the block
    /// described by this definition within `program`'s memory map.
    fn fixup_block(
        &self,
        program: &ProgramDB,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryBlockDefinitionError> {
        let _ = program;
        Err(MemoryBlockDefinitionError::Unsupported(
            "MemoryBlockDefinition::fixup_block has no default implementation".to_string(),
        ))
    }

    /// Stands in for `MemoryBlockDefinition.createBlock(Program)`: create a new block described
    /// by this definition within `program`.
    fn create_block(
        &self,
        program: &dyn Program,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryBlockDefinitionError> {
        let _ = program;
        Err(MemoryBlockDefinitionError::Unsupported(
            "MemoryBlockDefinition::create_block has no default implementation".to_string(),
        ))
    }
}

/// Default, XML-driven memory block specification. Mirrors the concrete Java class
/// `MemoryBlockDefinition` that the [`MemoryBlockDefinition`] trait was promoted from.
pub struct DefaultMemoryBlockDefinition {
    block_name: String,
    address_string: String,
    length: u64,
    initialized: bool,
    overlay: bool,
    bit_mapped_address: Option<String>,
    byte_mapped_address: Option<String>,
    byte_mapping_ratio: Option<String>,
    #[allow(dead_code)]
    mode: String,
    read_permission: bool,
    write_permission: bool,
    execute_permission: bool,
    is_volatile: bool,
}

impl DefaultMemoryBlockDefinition {
    /// Stands in for the private text-based constructor used when parsing XML.
    #[allow(dead_code, clippy::too_many_arguments)]
    pub(crate) fn new(
        block_name: Option<&str>,
        address_string: Option<&str>,
        bit_mapped_address: Option<&str>,
        byte_mapped_address_ratio: Option<&str>,
        mode: Option<&str>,
        length_string: Option<&str>,
        initialized_string: Option<&str>,
        overlay_string: Option<&str>,
    ) -> Result<Self, XmlAttributeException> {
        let mode = mode
            .map(str::to_lowercase)
            .unwrap_or_else(|| DEFAULT_MODE.to_string());

        // Parse specified access mode
        let read_permission = mode.contains('r');
        let write_permission = mode.contains('w');
        let execute_permission = mode.contains('x');
        let is_volatile = mode.contains('v');

        let block_name = block_name
            .ok_or_else(|| XmlAttributeException::new("Missing default memory block 'name'"))?
            .to_string();

        let address_string = address_string
            .ok_or_else(|| {
                XmlAttributeException::new("Missing default memory block 'start_address'")
            })?
            .to_string();

        let bit_mapped_address = bit_mapped_address.map(str::to_string);

        let (byte_mapped_address, byte_mapping_ratio) =
            if let Some(ratio) = byte_mapped_address_ratio {
                if bit_mapped_address.is_some() {
                    return Err(XmlAttributeException::new(
                        "may not specify both bit_mapped_address and byte_mapped_address",
                    ));
                }
                match ratio.find('/') {
                    Some(index) => (
                        Some(ratio[..index].to_string()),
                        Some(ratio[index + 1..].to_string()),
                    ),
                    // 1:1 mapping scheme assumed (no mapping ratio)
                    None => (Some(ratio.to_string()), None),
                }
            }
            else {
                (None, None)
            };

        // Parse specified length string
        let parsed_len = length_string
            .and_then(|s| parse_xml_int(s).ok())
            .unwrap_or(-1);
        if parsed_len <= 0 {
            return Err(XmlAttributeException::new(format!(
                "{} is not a valid 'length'",
                length_string.unwrap_or("")
            )));
        }
        let length = parsed_len as u64;

        if initialized_string.is_some()
            && (bit_mapped_address.is_some() || byte_mapped_address.is_some())
        {
            return Err(XmlAttributeException::new(
                "mapped block specifications must not specify initialized attribute",
            ));
        }
        let initialized = parse_xml_bool(initialized_string);
        let overlay = parse_xml_bool(overlay_string);

        Ok(Self {
            block_name,
            address_string,
            length,
            initialized,
            overlay,
            bit_mapped_address,
            byte_mapped_address,
            byte_mapping_ratio,
            mode,
            read_permission,
            write_permission,
            execute_permission,
            is_volatile,
        })
    }

    /// Stands in for the public `MemoryBlockDefinition(XmlElement)` constructor.
    #[allow(dead_code)]
    pub(crate) fn from_xml_element(
        element: &impl XmlElement,
    ) -> Result<Self, XmlAttributeException> {
        Self::new(
            element.get_attribute("name").as_deref(),
            element.get_attribute("start_address").as_deref(),
            element.get_attribute("bit_mapped_address").as_deref(),
            element.get_attribute("byte_mapped_address").as_deref(),
            element.get_attribute("mode").as_deref(),
            element.get_attribute("length").as_deref(),
            element.get_attribute("initialized").as_deref(),
            element.get_attribute("overlay").as_deref(),
        )
    }

    /// Stands in for the private `getBlockType()` helper.
    fn get_block_type(&self) -> MemoryBlockType {
        if self.bit_mapped_address.is_some() {
            MemoryBlockType::BitMapped
        }
        else if self.byte_mapped_address.is_some() {
            MemoryBlockType::ByteMapped
        }
        else {
            MemoryBlockType::Default
        }
    }

    /// Encodes this definition's access-mode flags for `MemoryMapDB::create_block` (bit0=read,
    /// bit1=write, bit2=execute, bit3=volatile). `MemoryBlockDB` does not yet decode these flags
    /// back into `MemoryBlock::is_read`/etc., so today this only round-trips the raw byte.
    fn access_flags(&self) -> u8 {
        (self.read_permission as u8)
            | ((self.write_permission as u8) << 1)
            | ((self.execute_permission as u8) << 2)
            | ((self.is_volatile as u8) << 3)
    }
}

/// Stands in for `MemoryBlockDefinition.parseAddress(String, Program, String)`.
fn parse_address(
    address_string: &str,
    program: &dyn Program,
    description: &str,
) -> Result<Address, MemoryBlockDefinitionError> {
    let factory = program.get_address_factory().ok_or_else(|| {
        MemoryBlockDefinitionError::InvalidAddress(InvalidAddressException::new(format!(
            "no address factory available while parsing {description}: {address_string}"
        )))
    })?;
    factory.get_address(address_string).ok_or_else(|| {
        MemoryBlockDefinitionError::InvalidAddress(InvalidAddressException::new(format!(
            "Invalid {description} in memory block definition: {address_string}"
        )))
    })
}

/// Stands in for `XmlUtilities.parseInt(String)`: accepts a decimal integer, or a hexadecimal
/// integer prefixed with `0x`/`0X`.
#[allow(dead_code)]
fn parse_xml_int(s: &str) -> Result<i32, std::num::ParseIntError> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => i32::from_str_radix(hex, 16),
        None => s.parse::<i32>(),
    }
}

/// Stands in for `XmlUtilities.parseBoolean(String)`: `y`/`true` (case-insensitive) are true,
/// everything else (including a missing attribute) is false.
#[allow(dead_code)]
fn parse_xml_bool(s: Option<&str>) -> bool {
    match s {
        None => false,
        Some(v) => matches!(v.trim().to_lowercase().as_str(), "y" | "true"),
    }
}

impl fmt::Display for DefaultMemoryBlockDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.block_name)?;
        if self.overlay {
            write!(f, "overlay")?;
        }
        write!(f, " start_address={}", self.address_string)?;
        if self.initialized {
            write!(f, ", initialized ")?;
        }
        else if let Some(bit_mapped) = &self.bit_mapped_address {
            write!(f, ", bit_mapped_address={bit_mapped}")?;
        }
        else if let Some(byte_mapped) = &self.byte_mapped_address {
            write!(f, ", byte_mapped_address={byte_mapped}")?;
            if let Some(ratio) = &self.byte_mapping_ratio {
                write!(f, "/{ratio}")?;
            }
        }
        else {
            write!(f, ", uninitialized")?;
        }
        write!(f, ", length=0x{:x}", self.length)
    }
}

impl MemoryBlockDefinition for DefaultMemoryBlockDefinition {
    fn get_block_name(&self) -> String {
        self.block_name.clone()
    }

    fn fixup_block(
        &self,
        program: &ProgramDB,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryBlockDefinitionError> {
        // Mirrors MemoryBlockDefinition.fixupBlock(ProgramDB): only the "block does not yet
        // exist" path is implemented, since MemoryMapDB does not yet expose getBlock(String),
        // block expansion/access adjustment, mapped-block creation, or join to reconcile an
        // already-existing block -- everything past that point in the Java method.
        if !program.has_exclusive_access() {
            return Err(MemoryBlockDefinitionError::Lock(LockException::new(
                "the program does not have exclusive access",
            )));
        }

        match self.get_block_type() {
            MemoryBlockType::BitMapped | MemoryBlockType::ByteMapped => {
                Err(MemoryBlockDefinitionError::Unsupported(format!(
                    "mapped memory block creation is not yet supported: {}",
                    self.block_name
                )))
            }
            MemoryBlockType::Default => {
                Msg::info(
                    "MemoryBlockDefinition",
                    &format!("Adding process-defined memory block: {}", self.block_name),
                );
                let addr = parse_address(&self.address_string, program, "block address")?;
                let memory = program.get_memory();
                let mut memory = memory.write().unwrap();
                let block = memory
                    .create_block(
                        self.block_name.clone(),
                        addr,
                        self.length,
                        self.access_flags(),
                    )
                    .map_err(|e| {
                        MemoryBlockDefinitionError::Block(MemoryBlockException::with_source(
                            "Create block failed",
                            e,
                        ))
                    })?;
                Ok(block as Arc<RwLock<dyn MemoryBlock>>)
            }
        }
    }

    fn create_block(
        &self,
        program: &dyn Program,
    ) -> Result<Arc<RwLock<dyn MemoryBlock>>, MemoryBlockDefinitionError> {
        let _addr = parse_address(&self.address_string, program, "block address")?;

        match self.get_block_type() {
            MemoryBlockType::BitMapped => {
                let bit_mapped = self
                    .bit_mapped_address
                    .as_deref()
                    .expect("bit-mapped block type implies bit_mapped_address is set");
                let _mapped_addr = parse_address(bit_mapped, program, "bit-mapped address")?;
                Err(MemoryBlockDefinitionError::Unsupported(format!(
                    "bit-mapped memory block creation is not yet supported: {}",
                    self.block_name
                )))
            }
            MemoryBlockType::ByteMapped => {
                let byte_mapped = self
                    .byte_mapped_address
                    .as_deref()
                    .expect("byte-mapped block type implies byte_mapped_address is set");
                let _mapped_addr = parse_address(byte_mapped, program, "byte-mapped address")?;
                Err(MemoryBlockDefinitionError::Unsupported(format!(
                    "byte-mapped memory block creation is not yet supported: {}",
                    self.block_name
                )))
            }
            MemoryBlockType::Default => Err(MemoryBlockDefinitionError::Unsupported(format!(
                "memory block creation is not yet supported: Program does not yet expose \
                 memory block management ({})",
                self.block_name
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::pcode::PackedDecode;
    use crate::program::model::lang::sleigh::SleighLanguage;
    use std::collections::HashMap;

    struct MockXmlElement {
        attributes: HashMap<String, String>,
    }

    impl MockXmlElement {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self {
                attributes: pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    impl XmlElement for MockXmlElement {
        fn get_level(&self) -> i32 {
            0
        }
        fn is_start(&self) -> bool {
            true
        }
        fn is_end(&self) -> bool {
            false
        }
        fn is_content(&self) -> bool {
            false
        }
        fn get_name(&self) -> &str {
            "default_memory_blocks"
        }
        fn get_attributes(&self) -> HashMap<String, String> {
            self.attributes.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attributes.iter().map(|(k, v)| (k.clone(), v.clone())))
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attributes.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attributes.get(key).cloned()
        }
        fn get_text(&self) -> &str {
            ""
        }
        fn get_column_number(&self) -> i32 {
            0
        }
        fn get_line_number(&self) -> i32 {
            0
        }
        fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
            self.attributes.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            name == self.get_name()
        }
    }

    /// Object-safety smoke test: a bare `impl` relying entirely on the trait's defaults, exactly
    /// like the pre-existing mock implementations grown from the placeholder this promotes.
    struct MockMemoryBlockDefinition;
    impl MemoryBlockDefinition for MockMemoryBlockDefinition {}

    #[test]
    fn mock_is_object_safe_and_uses_defaults() {
        let defs: Vec<Box<dyn MemoryBlockDefinition>> = vec![Box::new(MockMemoryBlockDefinition)];
        assert_eq!(defs[0].get_block_name(), "");
    }

    #[test]
    fn from_xml_element_parses_default_block() {
        let element = MockXmlElement::new(&[
            ("name", "RESET"),
            ("start_address", "ram:0x1000"),
            ("length", "0x100"),
            ("initialized", "y"),
        ]);
        let def = DefaultMemoryBlockDefinition::from_xml_element(&element).unwrap();
        assert_eq!(def.get_block_name(), "RESET");
        assert_eq!(def.length, 0x100);
        assert!(def.initialized);
        assert!(!def.overlay);
        assert!(def.read_permission);
        assert!(def.write_permission);
        assert!(!def.execute_permission);
    }

    #[test]
    fn from_xml_element_parses_custom_mode() {
        let element = MockXmlElement::new(&[
            ("name", "CODE"),
            ("start_address", "ram:0x0"),
            ("length", "0x10"),
            ("mode", "rx"),
        ]);
        let def = DefaultMemoryBlockDefinition::from_xml_element(&element).unwrap();
        assert!(def.read_permission);
        assert!(!def.write_permission);
        assert!(def.execute_permission);
        assert!(!def.is_volatile);
    }

    #[test]
    fn from_xml_element_parses_byte_mapped_ratio() {
        let element = MockXmlElement::new(&[
            ("name", "MAPPED"),
            ("start_address", "ram:0x2000"),
            ("byte_mapped_address", "rom:0x1000/2:4"),
            ("length", "0x20"),
        ]);
        let def = DefaultMemoryBlockDefinition::from_xml_element(&element).unwrap();
        assert_eq!(def.byte_mapped_address.as_deref(), Some("rom:0x1000"));
        assert_eq!(def.byte_mapping_ratio.as_deref(), Some("2:4"));
        assert_eq!(def.get_block_type(), MemoryBlockType::ByteMapped);
    }

    #[test]
    fn missing_name_is_rejected() {
        let element = MockXmlElement::new(&[("start_address", "ram:0x0"), ("length", "0x10")]);
        assert!(DefaultMemoryBlockDefinition::from_xml_element(&element).is_err());
    }

    #[test]
    fn missing_start_address_is_rejected() {
        let element = MockXmlElement::new(&[("name", "X"), ("length", "0x10")]);
        assert!(DefaultMemoryBlockDefinition::from_xml_element(&element).is_err());
    }

    #[test]
    fn invalid_length_is_rejected() {
        let element =
            MockXmlElement::new(&[("name", "X"), ("start_address", "ram:0x0"), ("length", "0")]);
        assert!(DefaultMemoryBlockDefinition::from_xml_element(&element).is_err());
    }

    #[test]
    fn both_bit_and_byte_mapped_addresses_is_rejected() {
        let element = MockXmlElement::new(&[
            ("name", "X"),
            ("start_address", "ram:0x0"),
            ("length", "0x10"),
            ("bit_mapped_address", "rom:0x0"),
            ("byte_mapped_address", "rom:0x0"),
        ]);
        assert!(DefaultMemoryBlockDefinition::from_xml_element(&element).is_err());
    }

    #[test]
    fn initialized_with_mapped_address_is_rejected() {
        let element = MockXmlElement::new(&[
            ("name", "X"),
            ("start_address", "ram:0x0"),
            ("length", "0x10"),
            ("bit_mapped_address", "rom:0x0"),
            ("initialized", "y"),
        ]);
        assert!(DefaultMemoryBlockDefinition::from_xml_element(&element).is_err());
    }

    #[test]
    fn to_string_reports_uninitialized_default_block() {
        let element = MockXmlElement::new(&[
            ("name", "BLOCK"),
            ("start_address", "ram:0x400"),
            ("length", "0x40"),
        ]);
        let def = DefaultMemoryBlockDefinition::from_xml_element(&element).unwrap();
        let s = def.to_string();
        assert!(s.starts_with("BLOCK:"));
        assert!(s.contains("start_address=ram:0x400"));
        assert!(s.contains("uninitialized"));
        assert!(s.contains("length=0x40"));
    }

    /// Builds a minimal real `ProgramDB` (mirrors the fixture in
    /// `program::database::program_db`'s own tests) so `fixup_block`/`create_block` can be
    /// exercised against genuine `Program`/address-factory behavior rather than a mock.
    fn build_test_program_db() -> ProgramDB {
        let mut data = vec![];
        // <sleigh version="4" bigendian="false">
        data.extend_from_slice(&[0x60, 0xA1, 0xE0, 0xA2, 0x21, 4, 0xE0, 0xA3, 0x10]);
        // <spaces defaultspace="ram">
        data.extend_from_slice(&[0x60, 0xA2, 0xE0, 0xA9, 0x71, 3, b'r', b'a', b'm']);
        // <space_other/>
        data.extend_from_slice(&[0x60, 0xAD, 0xA0, 0xAD]);
        // <space name="ram" size="4" index="1" delay="1"/>
        data.extend_from_slice(&[
            0x60, 0xA5, 0xCC, 0x71, 3, b'r', b'a', b'm', 0xCF, 0x21, 4, 0xC9, 0x21, 1, 0xE0, 0xAA,
            0x21, 1, 0xA0, 0xA5,
        ]);
        // </spaces>
        data.extend_from_slice(&[0xA0, 0x80 | 34]);
        // <symbol_table scopesize="1" symbolsize="0">
        data.extend_from_slice(&[0x60, 0xA6, 0xE0, 0xAD, 0x21, 1, 0xE0, 0xAE, 0x21, 0]);
        // <scope id="0" parent="0"/>
        data.extend_from_slice(&[0x56, 0xC3, 0x41, 0, 0xD6, 0x41, 0, 0x96]);
        // </symbol_table>
        data.extend_from_slice(&[0xA0, 0x80 | 38]);
        // </sleigh>
        data.extend_from_slice(&[0xA0, 0x80 | 33]);

        let factory = Arc::new(crate::program::model::address::DefaultAddressFactory::new(
            vec![],
        ));
        let decoder = PackedDecode::new(factory, data);
        let language = Arc::new(SleighLanguage::decode(&decoder, "test".to_string()).unwrap());
        ProgramDB::new("mbd_test_prog".to_string(), language).unwrap()
    }

    #[test]
    fn fixup_block_without_exclusive_access_returns_lock_error() {
        let program = build_test_program_db();
        let def = DefaultMemoryBlockDefinition::new(
            Some("RESET"),
            Some("ram:0x1000"),
            None,
            None,
            None,
            Some("0x100"),
            Some("y"),
            None,
        )
        .unwrap();

        let result = def.fixup_block(&program);
        assert!(matches!(result, Err(MemoryBlockDefinitionError::Lock(_))));
    }

    #[test]
    fn create_block_parses_address_then_reports_unsupported() {
        let program = build_test_program_db();
        let def = DefaultMemoryBlockDefinition::new(
            Some("RESET"),
            Some("ram:0x1000"),
            None,
            None,
            None,
            Some("0x100"),
            Some("y"),
            None,
        )
        .unwrap();

        let result = def.create_block(&program);
        assert!(matches!(
            result,
            Err(MemoryBlockDefinitionError::Unsupported(_))
        ));
    }

    #[test]
    fn create_block_rejects_invalid_address() {
        let program = build_test_program_db();
        let def = DefaultMemoryBlockDefinition::new(
            Some("RESET"),
            Some("not_a_real_space:0x1000"),
            None,
            None,
            None,
            Some("0x100"),
            Some("y"),
            None,
        )
        .unwrap();

        let result = def.create_block(&program);
        assert!(matches!(
            result,
            Err(MemoryBlockDefinitionError::InvalidAddress(_))
        ));
    }

    #[test]
    fn create_block_reports_unsupported_for_bit_mapped_block() {
        let program = build_test_program_db();
        let def = DefaultMemoryBlockDefinition::new(
            Some("MAPPED"),
            Some("ram:0x2000"),
            Some("ram:0x0"),
            None,
            None,
            Some("0x10"),
            None,
            None,
        )
        .unwrap();

        let result = def.create_block(&program);
        assert!(matches!(
            result,
            Err(MemoryBlockDefinitionError::Unsupported(_))
        ));
    }

    #[test]
    fn parse_xml_int_supports_hex_and_decimal() {
        assert_eq!(parse_xml_int("0x10").unwrap(), 16);
        assert_eq!(parse_xml_int("16").unwrap(), 16);
        assert!(parse_xml_int("not_a_number").is_err());
    }

    #[test]
    fn parse_xml_bool_accepts_y_and_true_case_insensitively() {
        assert!(parse_xml_bool(Some("y")));
        assert!(parse_xml_bool(Some("TRUE")));
        assert!(!parse_xml_bool(Some("n")));
        assert!(!parse_xml_bool(None));
    }

    #[test]
    fn access_flags_encodes_permission_bits() {
        let def = DefaultMemoryBlockDefinition::new(
            Some("X"),
            Some("ram:0x0"),
            None,
            None,
            Some("rwxv"),
            Some("0x10"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(def.access_flags(), 0b1111);
    }

}
