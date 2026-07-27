//! Port of `ghidra.program.model.pcode.AddressXML`.
//!
//! Utility for the myriad ways of marshaling/unmarshaling an address and an optional size,
//! to/from XML (or the packed binary encoding) for the various configuration files. An
//! [`AddressXml`] instance is the most general form, where the specified address:
//!   - MAY have an associated size given in bytes
//!   - MAY be in the JOIN address space, with physical pieces making up the logical value
//!     explicitly provided
//!
//! In Java this is a concrete class. It was selected as a dependency-cycle cut-point (it sits
//! between [`ParamEntry`](crate::program::model::lang::param_entry::ParamEntry),
//! [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype), and
//! [`PcodeDataTypeManager`](crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager)),
//! so its instance surface (the space/offset/size/join-record accessors, plus `encode`) is
//! promoted to a trait here, with [`DefaultAddressXml`] as the straightforward in-memory
//! implementation the constructors and `restoreXml`/`restoreRangeXml` factories build. The
//! remaining static methods (`decode`, `decodeFromAttributes`, `decodeStorageFromAttributes`,
//! the `encodeAttributes`/`encode` overloads) don't operate on an instance, so they stay as free
//! functions in this module, one per Java overload (Rust has no overloading).
//!
//! `Varnode.decodePieces`/`Varnode.encodePiece` (needed by the join-address wire format) are not
//! yet part of the ported [`Varnode`](crate::program::model::pcode::Varnode) type, so their
//! logic is inlined here as private helpers rather than growing `Varnode`'s own API.

use std::io;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory, AddressSpace, AddressSpaceType};
use crate::program::model::address::special_address::SpecialAddress;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_FIRST, ATTRIB_LAST, ATTRIB_LOGICALSIZE, ATTRIB_OFFSET, ATTRIB_PIECE, ATTRIB_SIZE,
    ATTRIB_SPACE, ATTRIB_VALUE, ELEM_ADDR, ELEM_IOP, ELEM_SPACEID,
};
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::{PcodeFactory, PlaceholderVariableStorage, VariableStorage, VarnodeListStorage};
use crate::util::xml::spec_xml_utils::{decode_int, decode_long};
use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_parse_exception::XmlParseException;

/// Maximum pieces that can be marshaled in one join address. Port of `AddressXML.MAX_PIECES`.
pub const MAX_PIECES: usize = 64;

/// A sized address (optionally a "join" of several physical pieces), and its (de)serialization to
/// the `<addr>` XML/packed-binary wire format. Port of the instance contract of
/// `ghidra.program.model.pcode.AddressXML` (see the module docs for why this is a trait).
pub trait AddressXml {
    /// The address space associated with this address, if any. Port of `AddressXML.getAddressSpace()`.
    fn get_address_space(&self) -> Option<Arc<AddressSpace>>;

    /// The byte offset of this address. Port of `AddressXML.getOffset()`.
    fn get_offset(&self) -> i64;

    /// The size in bytes associated with this address. Port of `AddressXML.getSize()`.
    fn get_size(&self) -> i64;

    /// The physical pieces making up this logical address range, if it is in the JOIN address
    /// space. Port of `AddressXML.getJoinRecord()`.
    fn get_join_record(&self) -> Option<&[Varnode]>;

    /// Build a raw Varnode from the address and size. Port of `AddressXML.getVarnode()`.
    ///
    /// # Panics
    /// Panics if no address space is associated with this address.
    fn get_varnode(&self) -> Varnode {
        let space = self
            .get_address_space()
            .expect("AddressXML.getVarnode() requires an address space");
        Varnode::new(space.address(self.get_offset()), self.get_size() as i32)
    }

    /// The first address in the range. Port of `AddressXML.getFirstAddress()`.
    ///
    /// # Panics
    /// Panics if no address space is associated with this address.
    fn get_first_address(&self) -> Address {
        let space = self
            .get_address_space()
            .expect("AddressXML.getFirstAddress() requires an address space");
        space.address(self.get_offset())
    }

    /// The last address in the range. Port of `AddressXML.getLastAddress()`.
    ///
    /// # Panics
    /// Panics if no address space is associated with this address.
    fn get_last_address(&self) -> Address {
        let space = self
            .get_address_space()
            .expect("AddressXML.getLastAddress() requires an address space");
        space.address(self.get_offset() + self.get_size() - 1)
    }

    /// Encode this sized address as an `<addr>` element to the stream. Port of
    /// `AddressXML.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        if let Some(join_record) = self.get_join_record() {
            let size_sum: i64 = join_record.iter().map(|vn| vn.get_size() as i64).sum();
            let logical_size = if size_sum == self.get_size() { 0 } else { self.get_size() };
            return encode_varnodes(encoder, Some(join_record), logical_size);
        }
        encoder.open_element(ELEM_ADDR)?;
        if let Some(space) = self.get_address_space() {
            encoder.write_space(ATTRIB_SPACE, space.as_ref())?;
            encoder.write_unsigned_integer(ATTRIB_OFFSET, self.get_offset() as u64)?;
            if self.get_size() != 0 {
                encoder.write_signed_integer(ATTRIB_SIZE, self.get_size())?;
            }
        }
        encoder.close_element(ELEM_ADDR)
    }
}

/// Straightforward in-memory [`AddressXml`], holding the space/offset/size/join-record state
/// directly. Port of `AddressXML`'s private fields plus its public constructors.
#[derive(Debug, Clone)]
pub struct DefaultAddressXml {
    space: Option<Arc<AddressSpace>>,
    offset: i64,
    size: i64,
    join_record: Option<Vec<Varnode>>,
}

impl DefaultAddressXml {
    /// Construct an address range as a space/offset/size. Port of
    /// `AddressXML(AddressSpace, long, int)`.
    pub fn new(space: Arc<AddressSpace>, offset: i64, size: i32) -> Self {
        Self { space: Some(space), offset, size: size as i64, join_record: None }
    }

    /// Construct a logical memory range, representing multiple ranges pieced together, assigned
    /// an address in the JOIN address space. Port of `AddressXML(AddressSpace, long, int,
    /// Varnode[])`.
    ///
    /// # Panics
    /// Panics if `space` is not the JOIN address space (mirrors the Java
    /// `IllegalArgumentException`).
    pub fn with_join(space: Arc<AddressSpace>, offset: i64, size: i32, pieces: Vec<Varnode>) -> Self {
        assert_eq!(
            space.space_type(),
            AddressSpaceType::Join,
            "JOIN address space required to represent an Address with pieces"
        );
        Self { space: Some(space), offset, size: size as i64, join_record: Some(pieces) }
    }

    /// Internal constructor for incremental initialization, mirroring the Java class's private
    /// no-arg constructor used by the `restoreXml`/`restoreRangeXml` factories.
    fn empty() -> Self {
        Self { space: None, offset: 0, size: 0, join_record: None }
    }
}

impl AddressXml for DefaultAddressXml {
    fn get_address_space(&self) -> Option<Arc<AddressSpace>> {
        self.space.clone()
    }

    fn get_offset(&self) -> i64 {
        self.offset
    }

    fn get_size(&self) -> i64 {
        self.size
    }

    fn get_join_record(&self) -> Option<&[Varnode]> {
        self.join_record.as_deref()
    }
}

/// Restore an Address (as an AddressSpace and an offset) and an optional size from an XML tag.
/// The tag can have any name, but it must either have a "name" attribute (a register name) or a
/// "space" and "offset" attribute. Supports the "join" address space attached to the compiler
/// specification. Port of `AddressXML.restoreXml(XmlElement, CompilerSpec)`.
///
/// # Errors
/// Returns an error for problems parsing the XML.
pub fn restore_xml<E: XmlElement>(el: &E, cspec: &dyn CompilerSpec) -> Result<DefaultAddressXml, XmlParseException> {
    if el.get_name() == "register" {
        let reg_name = el
            .get_attribute("name")
            .ok_or_else(|| XmlParseException::new("Missing pentry register name"))?;
        let language = cspec.get_language();
        let register = language
            .get_register_by_name(&reg_name)
            .ok_or_else(|| XmlParseException::new(format!("Unknown pentry register: {reg_name}")))?;
        let register = register.borrow();
        return Ok(DefaultAddressXml::new(
            register.address_space(),
            register.address().offset(),
            register.minimum_byte_size(),
        ));
    }

    let mut result = DefaultAddressXml::empty();
    let space_name = el.get_attribute("space");
    let space = space_name
        .as_deref()
        .and_then(|name| cspec.get_address_space(name))
        .ok_or_else(|| {
            XmlParseException::new(format!(
                "Unknown address space: {}",
                space_name.as_deref().unwrap_or("null")
            ))
        })?;
    if space.space_type() == AddressSpaceType::Join {
        let (offset, size, pieces) = read_join_xml(el, cspec)?;
        result.offset = offset;
        result.size = size;
        result.join_record = Some(pieces);
    } else {
        result.offset = decode_long(el.get_attribute("offset").as_deref());
    }
    result.space = Some(space);
    if let Some(size_string) = el.get_attribute("size") {
        result.size = decode_int(Some(&size_string)) as i64;
    }
    Ok(result)
}

/// Read the "pieceN" attributes of a "join" `<addr>` tag. Port of `AddressXML.readJoinXML`.
fn read_join_xml<E: XmlElement>(
    el: &E,
    cspec: &dyn CompilerSpec,
) -> Result<(i64, i64, Vec<Varnode>), XmlParseException> {
    let mut pieces = Vec::new();
    let mut size_sum: i64 = 0;
    let mut pos = 0usize;
    loop {
        let attr_name = format!("piece{}", pos + 1);
        let attr_val = match el.get_attribute(&attr_name) {
            Some(v) => v,
            None => break,
        };
        let vn = match attr_val.find(':') {
            None => {
                let language = cspec.get_language();
                let register = language.get_register_by_name(&attr_val).ok_or_else(|| {
                    XmlParseException::new(format!("Unknown pentry register: {attr_val}"))
                })?;
                let register = register.borrow();
                Varnode::new(register.address().clone(), register.bit_length() / 8)
            }
            Some(off_pos) => {
                let sz_pos = attr_val[off_pos + 1..]
                    .find(':')
                    .map(|p| p + off_pos + 1)
                    .ok_or_else(|| XmlParseException::new("join address piece attribute is malformed"))?;
                let spc_name = &attr_val[..off_pos];
                let space = cspec
                    .get_address_space(spc_name)
                    .ok_or_else(|| XmlParseException::new(format!("Unknown address space: {spc_name}")))?;
                let off = decode_long(Some(&attr_val[off_pos + 1..sz_pos]));
                let sz = decode_long(Some(&attr_val[sz_pos + 1..]));
                Varnode::new(space.address(off), sz as i32)
            }
        };
        size_sum += vn.get_size() as i64;
        pieces.push(vn);
        pos += 1;
    }
    Ok((0, size_sum, pieces))
}

/// Restore an Address (as an AddressSpace and an offset) and an optional size from an XML tag,
/// resolving spaces/registers directly against a [`Language`] rather than a [`CompilerSpec`] (so
/// the "join" address space is not supported here). Port of `AddressXML.restoreXml(XmlElement,
/// Language)`.
///
/// # Errors
/// Returns an error for problems parsing the XML.
pub fn restore_xml_with_language<E: XmlElement>(
    el: &E,
    language: &dyn Language,
) -> Result<DefaultAddressXml, XmlParseException> {
    if el.get_name() == "register" {
        let reg_name = el
            .get_attribute("name")
            .ok_or_else(|| XmlParseException::new("Missing register name"))?;
        let register = language
            .get_register_by_name(&reg_name)
            .ok_or_else(|| XmlParseException::new(format!("Unknown register: {reg_name}")))?;
        let register = register.borrow();
        return Ok(DefaultAddressXml::new(
            register.address_space(),
            register.address().offset(),
            register.minimum_byte_size(),
        ));
    }

    let mut result = DefaultAddressXml::empty();
    let space_name = el.get_attribute("space");
    let space = space_name
        .as_deref()
        .and_then(|name| language.get_address_factory().get_address_space_by_name(name))
        .ok_or_else(|| {
            XmlParseException::new(format!(
                "Unknown address space: {}",
                space_name.as_deref().unwrap_or("null")
            ))
        })?;
    result.offset = decode_long(el.get_attribute("offset").as_deref());
    result.space = Some(space);
    if let Some(size_string) = el.get_attribute("size") {
        result.size = decode_int(Some(&size_string)) as i64;
    }
    Ok(result)
}

/// A memory range read from attributes of an XML tag. The tag must either have a "name" attribute
/// (a register) or a "space" attribute with optional "first"/"last" attributes ("first" defaults
/// to 0, "last" defaults to the last offset in the space). Port of
/// `AddressXML.restoreRangeXml(XmlElement, CompilerSpec)`.
///
/// # Errors
/// Returns an error for problems parsing the XML.
pub fn restore_range_xml<E: XmlElement>(
    el: &E,
    cspec: &dyn CompilerSpec,
) -> Result<DefaultAddressXml, XmlParseException> {
    let mut result = DefaultAddressXml::empty();
    result.offset = 0;
    let mut last: i64 = -1;
    let mut seen_last = false;

    if let Some(space_name) = el.get_attribute("space") {
        let space = cspec
            .get_address_space(&space_name)
            .ok_or_else(|| XmlParseException::new(format!("Undefined space: {space_name}")))?;
        result.space = Some(space);
    }
    if let Some(first) = el.get_attribute("first") {
        result.offset = decode_long(Some(&first));
    }
    if let Some(last_str) = el.get_attribute("last") {
        last = decode_long(Some(&last_str));
        seen_last = true;
    }
    if let Some(reg_name) = el.get_attribute("name") {
        let language = cspec.get_language();
        let register = language
            .get_register_by_name(&reg_name)
            .ok_or_else(|| XmlParseException::new(format!("Unknown register: {reg_name}")))?;
        let register = register.borrow();
        result.space = Some(register.address_space());
        result.offset = register.address().offset();
        last = (result.offset - 1) + register.minimum_byte_size() as i64;
        seen_last = true;
    }
    let space = result
        .space
        .clone()
        .ok_or_else(|| XmlParseException::new("No address space indicated in range tag"))?;
    if !seen_last {
        last = space.max_address().offset();
    }
    result.size = (last - result.offset) + 1;
    Ok(result)
}

/// Adapt a [`DecoderError`] from the low-level [`Decoder`] trait to the [`DecoderException`] this
/// module's public API reports, mirroring `AddressXML`'s static methods' `throws
/// DecoderException`.
fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode AddressXML", e)
}

/// Create an address from "space" and "offset" attributes of the current element. Port of
/// `AddressXML.decodeFromAttributes(Decoder)`.
///
/// # Errors
/// Returns an error for any problems decoding the stream.
pub fn decode_from_attributes(decoder: &dyn Decoder) -> Result<Address, DecoderException> {
    let mut spc: Option<Arc<AddressSpace>> = None;
    let mut offset: i64 = -1;
    loop {
        let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
        if attrib_id == 0 {
            break;
        }
        if attrib_id == ATTRIB_SPACE.id {
            spc = Some(decoder.read_space().map_err(decode_err)?);
        } else if attrib_id == ATTRIB_OFFSET.id {
            offset = decoder.read_unsigned_integer().map_err(decode_err)? as i64;
        }
    }
    match spc {
        None => Ok(SpecialAddress::no_address()),
        Some(spc) => Ok(spc.address(offset)),
    }
}

/// Decode a `VariableStorage` object from the attributes in the current address element. The
/// start of storage corresponds to the decoded address; the size is either passed in or decoded
/// from a "size" attribute. Port of `AddressXML.decodeStorageFromAttributes(int, Decoder,
/// PcodeFactory)`.
///
/// # Errors
/// Returns an error for any errors in the encoding or problems creating the storage.
pub fn decode_storage_from_attributes(
    mut size: i32,
    decoder: &dyn Decoder,
    pcode_factory: &dyn PcodeFactory,
) -> Result<Box<dyn VariableStorage>, DecoderException> {
    let var_addr = decode_from_attributes(decoder)?;
    if var_addr == SpecialAddress::no_address() {
        return Ok(Box::new(PlaceholderVariableStorage));
    }
    let spc = var_addr.space().clone();
    if spc.space_type() != AddressSpaceType::Variable {
        if size <= 0 {
            size = decoder.read_signed_integer_with_id(ATTRIB_SIZE).map_err(decode_err)? as i32;
        }
        let varnode = Varnode::new(var_addr, size);
        Ok(Box::new(VarnodeListStorage(vec![varnode])))
    } else {
        decoder.rewind_attributes();
        let (pieces, _logical_size) = decode_varnode_pieces(decoder)?;
        Ok(pcode_factory.get_join_storage(pieces))
    }
}

/// Create an address from a stream encoding, recognizing `<addr>`, `<spaceid>`, `<iop>`, or any
/// element with "space" and "offset" attributes. An empty `<addr>` element results in the
/// sentinel "no address" being returned. Port of `AddressXML.decode(Decoder)`.
///
/// # Errors
/// Returns an error for any problems decoding the stream.
pub fn decode(decoder: &dyn Decoder) -> Result<Address, DecoderException> {
    let el = decoder.open_element().map_err(decode_err)?;
    if el == ELEM_SPACEID.id {
        let spc = decoder.read_space_with_id(crate::program::model::pcode::ids::ATTRIB_NAME).map_err(decode_err)?;
        decoder.close_element(el).map_err(decode_err)?;
        let spaceid = spc.space_id();
        let const_space = decoder
            .get_address_factory()
            .get_constant_space()
            .ok_or_else(|| DecoderException::new("no constant space in address factory"))?;
        return Ok(const_space.address(spaceid as i64));
    } else if el == ELEM_IOP.id {
        let reference = decoder.read_unsigned_integer_with_id(ATTRIB_VALUE).map_err(decode_err)?;
        decoder.close_element(el).map_err(decode_err)?;
        let const_space = decoder
            .get_address_factory()
            .get_constant_space()
            .ok_or_else(|| DecoderException::new("no constant space in address factory"))?;
        return Ok(const_space.address(reference as i64));
    }

    let mut spc: Option<Arc<AddressSpace>> = None;
    let mut offset: i64 = -1;
    loop {
        let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
        if attrib_id == 0 {
            break;
        }
        if attrib_id == ATTRIB_SPACE.id {
            spc = Some(decoder.read_space().map_err(decode_err)?);
        } else if attrib_id == ATTRIB_OFFSET.id {
            offset = decoder.read_unsigned_integer().map_err(decode_err)? as i64;
        }
    }
    decoder.close_element(el).map_err(decode_err)?;
    match spc {
        // EXTERNAL_SPACE is currently a placeholder for an unsupported decompiler address space
        None => Ok(SpecialAddress::no_address()),
        Some(spc) => Ok(spc.address(offset)),
    }
}

/// Decode the "pieceN"/"logicalsize" attributes of the current element into a list of physical
/// varnode pieces plus the overall logical size. Port of the relevant part of
/// `Varnode.decodePieces(Decoder)` (the `ATTRIB_UNKNOWN`/`getIndexedAttributeId` fallback used
/// only by decoders that can't resolve an attribute name up front is not modeled, since this
/// crate's [`Decoder`] implementations always resolve attribute ids directly).
fn decode_varnode_pieces(decoder: &dyn Decoder) -> Result<(Vec<Varnode>, i32), DecoderException> {
    let mut pieces = Vec::new();
    let mut size_accum: i32 = 0;
    let mut logical_size: i32 = 0;
    loop {
        let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
        if attrib_id == 0 {
            break;
        }
        if attrib_id == ATTRIB_LOGICALSIZE.id {
            logical_size = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
            continue;
        }
        if attrib_id >= ATTRIB_PIECE.id {
            let index = (attrib_id - ATTRIB_PIECE.id) as usize;
            if index > MAX_PIECES {
                continue;
            }
            if index != pieces.len() {
                return Err(DecoderException::new("\"piece\" attributes must be in order"));
            }
            let piece_str = decoder.read_string().map_err(decode_err)?;
            let addr_factory = decoder.get_address_factory();
            let vn = decode_varnode_piece(&piece_str, addr_factory.as_ref())?;
            size_accum += vn.get_size();
            pieces.push(vn);
        }
    }
    let total = if logical_size != 0 { logical_size } else { size_accum };
    Ok((pieces, total))
}

/// Decode a single `"space:0xoffset:size"` join-address piece. Port of the relevant part of
/// `Varnode.decodePiece(String, AddressFactory)` (the register-name form is a `// TODO` in the
/// Java source itself -- `addrFactory` can't resolve register names -- so it is not modeled).
fn decode_varnode_piece(piece_str: &str, addr_factory: &dyn AddressFactory) -> Result<Varnode, DecoderException> {
    let tokens: Vec<&str> = piece_str.split(':').collect();
    if tokens.len() != 3 {
        return Err(DecoderException::new(&format!("Invalid \"join\" address piece: {piece_str}")));
    }
    let space = addr_factory.get_address_space_by_name(tokens[0]).ok_or_else(|| {
        DecoderException::new(&format!("Invalid space for \"join\" address piece: {piece_str}"))
    })?;
    let hex = tokens[1].strip_prefix("0x").ok_or_else(|| {
        DecoderException::new(&format!("Invalid offset for \"join\" address piece: {piece_str}"))
    })?;
    let offset = u64::from_str_radix(hex, 16).map_err(|_| {
        DecoderException::new(&format!("Invalid offset for \"join\" address piece: {piece_str}"))
    })?;
    let size: i32 = tokens[2].parse().map_err(|_| {
        DecoderException::new(&format!("Invalid size for \"join\" address piece: {piece_str}"))
    })?;
    Ok(Varnode::new(space.address(offset as i64), size))
}

/// Encode "space" and "offset" attributes for the current element, describing the given Address
/// to the stream. Port of `AddressXML.encodeAttributes(Encoder, Address)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_attributes(encoder: &mut dyn Encoder, addr: &Address) -> io::Result<()> {
    encoder.write_space(ATTRIB_SPACE, addr.space())?;
    encoder.write_unsigned_integer(ATTRIB_OFFSET, addr.unsigned_offset())
}

/// Encode "space", "offset", and "size" attributes for the current element, describing the given
/// memory range to the stream. Port of `AddressXML.encodeAttributes(Encoder, Address, int)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_attributes_with_size(encoder: &mut dyn Encoder, addr: &Address, size: i32) -> io::Result<()> {
    encoder.write_space(ATTRIB_SPACE, addr.space())?;
    encoder.write_unsigned_integer(ATTRIB_OFFSET, addr.unsigned_offset())?;
    encoder.write_signed_integer(ATTRIB_SIZE, size as i64)
}

/// Encode a memory range, as "space", "first", and "last" attributes, for the current element, to
/// the stream. Port of `AddressXML.encodeAttributes(Encoder, Address, Address)`.
///
/// # Panics
/// Panics if `start_addr` and `end_addr` are not in the same address space, or if `end_addr`
/// comes before `start_addr` (mirrors the Java `IllegalArgumentException`).
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_attributes_range(encoder: &mut dyn Encoder, start_addr: &Address, end_addr: &Address) -> io::Result<()> {
    let space = start_addr.space();
    let offset = start_addr.offset();
    let size = end_addr.offset() - offset + 1;

    assert!(space == end_addr.space(), "Range boundaries are not in the same address space");
    assert!(size >= 0, "Start of range comes after end of range");

    let last = offset + size - 1;
    let use_first = offset != 0;
    let use_last = last != -1;
    encoder.write_space(ATTRIB_SPACE, space)?;
    if use_first {
        encoder.write_unsigned_integer(ATTRIB_FIRST, offset as u64)?;
    }
    if use_last {
        encoder.write_unsigned_integer(ATTRIB_LAST, last as u64)?;
    }
    Ok(())
}

/// Encode the given Address as an `<addr>` element to the stream. Port of
/// `AddressXML.encode(Encoder, Address)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_addr(encoder: &mut dyn Encoder, addr: &Address) -> io::Result<()> {
    encoder.open_element(ELEM_ADDR)?;
    if *addr != SpecialAddress::no_address() {
        encode_attributes(encoder, addr)?;
    }
    encoder.close_element(ELEM_ADDR)
}

/// Encode the given Address and a size as an `<addr>` element to the stream. Port of
/// `AddressXML.encode(Encoder, Address, int)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream.
pub fn encode_addr_with_size(encoder: &mut dyn Encoder, addr: &Address, size: i32) -> io::Result<()> {
    encoder.open_element(ELEM_ADDR)?;
    encode_attributes_with_size(encoder, addr, size)?;
    encoder.close_element(ELEM_ADDR)
}

/// Encode a sequence of Varnodes as a single `<addr>` element to the stream. If there is more
/// than one Varnode, or if the logical size is non-zero, the `<addr>` element specifies the
/// address space as "join" (via the VARIABLE address space) and has additional "piece"
/// attributes. Port of `AddressXML.encode(Encoder, Varnode[], long)`.
///
/// # Errors
/// Returns an error for problems writing to the underlying stream, or if `varnodes` exceeds
/// [`MAX_PIECES`].
pub fn encode_varnodes(encoder: &mut dyn Encoder, varnodes: Option<&[Varnode]>, logical_size: i64) -> io::Result<()> {
    let varnodes = match varnodes {
        None => {
            encoder.open_element(ELEM_ADDR)?;
            encoder.close_element(ELEM_ADDR)?;
            return Ok(());
        }
        Some(v) => v,
    };
    if varnodes.len() == 1 && logical_size == 0 {
        return encode_addr_with_size(encoder, varnodes[0].get_address(), varnodes[0].get_size());
    }
    if varnodes.len() > MAX_PIECES {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Exceeded maximum pieces in one join address"));
    }
    encoder.open_element(ELEM_ADDR)?;
    encoder.write_space(ATTRIB_SPACE, variable_space().as_ref())?;
    for (i, vn) in varnodes.iter().enumerate() {
        encoder.write_string_indexed(ATTRIB_PIECE, i as i32, &encode_varnode_piece(vn))?;
    }
    if logical_size != 0 {
        encoder.write_unsigned_integer(ATTRIB_LOGICALSIZE, logical_size as u64)?;
    }
    encoder.close_element(ELEM_ADDR)
}

/// Encode a single Varnode as a `"space:0xoffset:size"` join-address piece string. Port of
/// `Varnode.encodePiece()`.
fn encode_varnode_piece(vn: &Varnode) -> String {
    let addr = vn.get_address();
    format!("{}:0x{:x}:{}", addr.space().name(), addr.unsigned_offset(), vn.get_size())
}

/// Stands in for `AddressSpace.VARIABLE_SPACE`: the address space used to contain all variables
/// and parameters described using "join" address pieces.
fn variable_space() -> Arc<AddressSpace> {
    AddressSpace::new("VARIABLE", 32, 1, AddressSpaceType::Variable, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::lang::compiler_spec::{EvaluationModelType, CALLING_CONVENTION_CDECL};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::program::seam_stubs::PcodeInjectLibrary;
    use std::collections::HashSet;
    use std::io;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn join_space() -> Arc<AddressSpace> {
        AddressSpace::new("join", 32, 1, AddressSpaceType::Join, 1)
    }

    // --- DefaultAddressXml + trait object-safety ---

    #[test]
    fn simple_address_reports_first_last_and_varnode() {
        let space = ram_space();
        let addr = DefaultAddressXml::new(space.clone(), 0x1000, 4);
        assert_eq!(addr.get_first_address(), space.address(0x1000));
        assert_eq!(addr.get_last_address(), space.address(0x1003));
        let vn = addr.get_varnode();
        assert_eq!(vn.get_offset(), 0x1000);
        assert_eq!(vn.get_size(), 4);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let space = ram_space();
        let boxed: Box<dyn AddressXml> = Box::new(DefaultAddressXml::new(space.clone(), 0x2000, 8));
        assert_eq!(boxed.get_offset(), 0x2000);
        assert_eq!(boxed.get_size(), 8);
        assert!(boxed.get_join_record().is_none());
    }

    #[test]
    #[should_panic(expected = "JOIN address space required")]
    fn with_join_requires_join_space() {
        let space = ram_space();
        DefaultAddressXml::with_join(space, 0, 4, vec![]);
    }

    // --- encode ---

    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string_indexed(&mut self, attrib_id: AttributeId, index: i32, val: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, val));
            Ok(())
        }
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
            Ok(())
        }
        fn write_space_indexed(&mut self, attrib_id: AttributeId, index: i32, name: &str) -> io::Result<()> {
            self.events.push(format!("attr:{}[{}]={}", attrib_id.name, index, name));
            Ok(())
        }
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_simple_address_writes_space_offset_size() {
        let space = ram_space();
        let addr = DefaultAddressXml::new(space.clone(), 0x100, 4);
        let mut encoder = RecordingEncoder::default();
        addr.encode(&mut encoder).unwrap();
        assert_eq!(
            encoder.events,
            vec![
                "open:addr".to_string(),
                "attr:space=ram".to_string(),
                "attr:offset=256".to_string(),
                "attr:size=4".to_string(),
                "close:addr".to_string(),
            ]
        );
    }

    #[test]
    fn encode_zero_size_omits_size_attribute() {
        let space = ram_space();
        let addr = DefaultAddressXml::new(space, 0x100, 0);
        let mut encoder = RecordingEncoder::default();
        addr.encode(&mut encoder).unwrap();
        assert!(!encoder.events.iter().any(|e| e.starts_with("attr:size")));
    }

    #[test]
    fn encode_join_address_writes_pieces() {
        let ram = ram_space();
        let piece0 = Varnode::new(ram.address(0x10), 2);
        let piece1 = Varnode::new(ram.address(0x20), 2);
        let addr = DefaultAddressXml::with_join(join_space(), 0, 4, vec![piece0, piece1]);

        let mut encoder = RecordingEncoder::default();
        addr.encode(&mut encoder).unwrap();

        assert_eq!(encoder.events[0], "open:addr");
        assert_eq!(encoder.events[1], "attr:space=VARIABLE");
        assert!(encoder.events[2].starts_with("attr:piece[0]=ram:0x10:2"));
        assert!(encoder.events[3].starts_with("attr:piece[1]=ram:0x20:2"));
        assert_eq!(encoder.events.last().unwrap(), "close:addr");
        // logical size == piece size sum, so no explicit logicalsize attribute is written.
        assert!(!encoder.events.iter().any(|e| e.starts_with("attr:logicalsize")));
    }

    #[test]
    fn encode_join_address_with_explicit_logical_size() {
        let ram = ram_space();
        let piece0 = Varnode::new(ram.address(0x10), 2);
        // Requested logical size (6) differs from the piece size sum (2), so an explicit
        // logicalsize attribute must be written.
        let addr = DefaultAddressXml::with_join(join_space(), 0, 6, vec![piece0]);

        let mut encoder = RecordingEncoder::default();
        addr.encode(&mut encoder).unwrap();
        assert!(encoder.events.iter().any(|e| e == "attr:logicalsize=6"));
    }

    #[test]
    fn encode_addr_free_fn_omits_attributes_for_no_address() {
        let mut encoder = RecordingEncoder::default();
        encode_addr(&mut encoder, &SpecialAddress::no_address()).unwrap();
        assert_eq!(encoder.events, vec!["open:addr".to_string(), "close:addr".to_string()]);
    }

    #[test]
    fn encode_varnodes_single_piece_no_logical_size_is_plain_addr() {
        let ram = ram_space();
        let vn = Varnode::new(ram.address(0x40), 4);
        let mut encoder = RecordingEncoder::default();
        encode_varnodes(&mut encoder, Some(&[vn]), 0).unwrap();
        assert_eq!(
            encoder.events,
            vec![
                "open:addr".to_string(),
                "attr:space=ram".to_string(),
                "attr:offset=64".to_string(),
                "attr:size=4".to_string(),
                "close:addr".to_string(),
            ]
        );
    }

    #[test]
    fn encode_varnodes_too_many_pieces_errors() {
        let ram = ram_space();
        let pieces: Vec<Varnode> = (0..(MAX_PIECES + 1)).map(|i| Varnode::new(ram.address(i as i64), 1)).collect();
        let mut encoder = RecordingEncoder::default();
        let err = encode_varnodes(&mut encoder, Some(&pieces), 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    #[should_panic(expected = "same address space")]
    fn encode_attributes_range_rejects_mismatched_spaces() {
        let ram = ram_space();
        let other = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let mut encoder = RecordingEncoder::default();
        let _ = encode_attributes_range(&mut encoder, &ram.address(0), &other.address(0));
    }

    // --- Decoder-backed static methods ---

    struct MockDecoder {
        factory: Arc<dyn AddressFactory>,
        attrs: Vec<(i32, MockAttrValue)>,
        pos: std::sync::atomic::AtomicUsize,
        elem_id: i32,
    }

    #[derive(Clone)]
    enum MockAttrValue {
        Space(Arc<AddressSpace>),
        UInt(u64),
        SInt(i64),
        Str(String),
    }

    impl MockDecoder {
        fn new(factory: Arc<dyn AddressFactory>, elem_id: i32, attrs: Vec<(i32, MockAttrValue)>) -> Self {
            Self { factory, attrs, pos: std::sync::atomic::AtomicUsize::new(0), elem_id }
        }

        fn pos(&self) -> usize {
            self.pos.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn set_pos(&self, v: usize) {
            self.pos.store(v, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.factory.clone()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(self.elem_id)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            Ok(self.elem_id)
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            let idx = self.pos();
            if idx >= self.attrs.len() {
                return Ok(0);
            }
            self.set_pos(idx + 1);
            Ok(self.attrs[idx].0)
        }
        fn rewind_attributes(&self) {
            self.set_pos(0);
        }
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::SInt(v) => Ok(*v),
                _ => panic!("not a signed integer attribute"),
            }
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_unsigned_integer_with_id(&self, _attrib_id: AttributeId) -> Result<u64, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::UInt(v) => Ok(*v),
                _ => panic!("not an unsigned integer attribute"),
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::Str(v) => Ok(v.clone()),
                _ => panic!("not a string attribute"),
            }
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            self.read_string()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            match &self.attrs[self.pos() - 1].1 {
                MockAttrValue::Space(s) => Ok(s.clone()),
                _ => panic!("not a space attribute"),
            }
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            self.read_space()
        }
    }

    #[test]
    fn decode_from_attributes_builds_address() {
        let space = ram_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let decoder = MockDecoder::new(
            factory,
            ELEM_ADDR.id,
            vec![(ATTRIB_SPACE.id, MockAttrValue::Space(space.clone())), (ATTRIB_OFFSET.id, MockAttrValue::UInt(0x50))],
        );
        let addr = decode_from_attributes(&decoder).unwrap();
        assert_eq!(addr, space.address(0x50));
    }

    #[test]
    fn decode_from_attributes_with_no_space_is_no_address() {
        let space = ram_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![space]));
        let decoder = MockDecoder::new(factory, ELEM_ADDR.id, vec![]);
        let addr = decode_from_attributes(&decoder).unwrap();
        assert_eq!(addr, SpecialAddress::no_address());
    }

    #[test]
    fn decode_reads_addr_element_body() {
        let space = ram_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let decoder = MockDecoder::new(
            factory,
            ELEM_ADDR.id,
            vec![(ATTRIB_SPACE.id, MockAttrValue::Space(space.clone())), (ATTRIB_OFFSET.id, MockAttrValue::UInt(0x1234))],
        );
        let addr = decode(&decoder).unwrap();
        assert_eq!(addr, space.address(0x1234));
    }

    #[test]
    fn decode_storage_from_attributes_builds_single_varnode_storage() {
        let space = ram_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![space.clone()]));
        let decoder = MockDecoder::new(
            factory,
            ELEM_ADDR.id,
            vec![(ATTRIB_SPACE.id, MockAttrValue::Space(space.clone())), (ATTRIB_OFFSET.id, MockAttrValue::UInt(0x8))],
        );
        struct MockPcodeFactory;
        impl PcodeFactory for MockPcodeFactory {}

        let storage = decode_storage_from_attributes(4, &decoder, &MockPcodeFactory).unwrap();
        assert_eq!(storage.size(), 4);
        assert_eq!(storage.get_first_varnode().unwrap().get_offset(), 0x8);
    }

    #[test]
    fn decode_storage_from_attributes_no_address_is_void_storage() {
        let space = ram_space();
        let factory = Arc::new(DefaultAddressFactory::new(vec![space]));
        let decoder = MockDecoder::new(factory, ELEM_ADDR.id, vec![]);
        struct MockPcodeFactory;
        impl PcodeFactory for MockPcodeFactory {}

        let storage = decode_storage_from_attributes(4, &decoder, &MockPcodeFactory).unwrap();
        assert!(!storage.is_valid());
    }

    // --- restore_xml / restore_range_xml (CompilerSpec + Language) ---

    struct MockXmlElement {
        name: String,
        attrs: std::collections::HashMap<String, String>,
    }

    impl MockXmlElement {
        fn new(name: &str, attrs: &[(&str, &str)]) -> Self {
            Self {
                name: name.to_string(),
                attrs: attrs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
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
            &self.name
        }
        fn get_attributes(&self) -> std::collections::HashMap<String, String> {
            self.attrs.clone()
        }
        fn get_attribute_iter(&self) -> Box<dyn Iterator<Item = (String, String)> + '_> {
            Box::new(self.attrs.iter().map(|(k, v)| (k.clone(), v.clone())))
        }
        fn has_attribute(&self, key: &str) -> bool {
            self.attrs.contains_key(key)
        }
        fn get_attribute(&self, key: &str) -> Option<String> {
            self.attrs.get(key).cloned()
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
            self.attrs.insert(key.into(), value.into());
        }
        fn is_start_with(&self, name: &str) -> bool {
            self.is_start() && self.name == name
        }
    }

    struct MockLanguage {
        registers: std::collections::HashMap<String, RegisterRef>,
        address_factory: Arc<dyn AddressFactory>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("MockLanguage exposes its factory via get_address_factory_arc for tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.registers.values().cloned().collect()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers.keys().cloned().collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers.get(name).cloned()
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockCompilerSpecDescription;
    impl CompilerSpecDescription for MockCompilerSpecDescription {
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }
        fn get_compiler_spec_name(&self) -> String {
            "default".to_string()
        }
        fn get_source(&self) -> String {
            String::new()
        }
    }

    struct MockPcodeInjectLibrary;
    impl PcodeInjectLibrary for MockPcodeInjectLibrary {}

    struct MockPrototypeModel;
    impl PrototypeModel for MockPrototypeModel {}

    struct MockCompilerSpec {
        language: Arc<MockLanguage>,
    }

    impl CompilerSpec for MockCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(SharedLanguage(self.language.clone()))
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            Box::new(MockCompilerSpecDescription)
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            None
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, space_name: &str) -> Option<Arc<AddressSpace>> {
            self.language.address_factory.get_address_space_by_name(space_name)
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            self.get_stack_space()
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }
        fn get_calling_convention(&self, name: &str) -> Option<Box<dyn PrototypeModel>> {
            if name == CALLING_CONVENTION_CDECL {
                Some(Box::new(MockPrototypeModel))
            } else {
                None
            }
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            vec![Box::new(MockPrototypeModel)]
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            Some(Box::new(MockPrototypeModel))
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            DecompilerLanguage::CLanguage
        }
        fn get_prototype_evaluation_model(&self, _model_type: EvaluationModelType) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }
        fn is_global(&self, _addr: &Address) -> bool {
            true
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            Box::new(MockPcodeInjectLibrary)
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }
        fn find_best_calling_convention(&self, _params: &[&dyn Parameter]) -> Box<dyn PrototypeModel> {
            Box::new(MockPrototypeModel)
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
            true
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, other: &dyn CompilerSpec) -> bool {
            self.get_compiler_spec_id() == other.get_compiler_spec_id()
        }
    }

    /// Wraps a shared [`MockLanguage`], overriding `get_address_factory` (which the base impl
    /// leaves `unimplemented!()`) to hand back a real, working [`AddressFactory`]. Needed because
    /// `Language::get_address_factory` returns an owned `Box<dyn AddressFactory>`, which a plain
    /// `Arc<MockLanguage>` can't produce without re-implementing the trait.
    struct SharedLanguage(Arc<MockLanguage>);
    impl Language for SharedLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            self.0.get_language_id()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            self.0.get_language_description()
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(ArcAddressFactory(self.0.address_factory.clone()))
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            self.0.get_registers()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.0.get_register_names()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.0.get_register_by_name(name)
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::program::seam_stubs::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// Adapts a shared `Arc<dyn AddressFactory>` to the owned `Box<dyn AddressFactory>` shape
    /// `Language::get_address_factory` returns.
    struct ArcAddressFactory(Arc<dyn AddressFactory>);
    impl AddressFactory for ArcAddressFactory {
        fn get_address(&self, addr_string: &str) -> Option<Address> {
            self.0.get_address(addr_string)
        }
        fn get_all_addresses_case(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address> {
            self.0.get_all_addresses_case(addr_string, case_sensitive)
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            self.0.get_default_address_space()
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.0.get_address_spaces()
        }
        fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
            self.0.get_address_space_by_name(name)
        }
        fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
            self.0.get_address_space_by_id(id)
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.0.get_all_address_spaces()
        }
        fn get_num_address_spaces(&self) -> usize {
            self.0.get_num_address_spaces()
        }
        fn is_valid_address(&self, address: &Address) -> bool {
            self.0.is_valid_address(address)
        }
        fn get_index(&self, address: &Address) -> i64 {
            self.0.get_index(address)
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            self.0.get_physical_space(space)
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.0.get_physical_spaces()
        }
        fn address(&self, space_id: i32, offset: i64) -> Option<Address> {
            self.0.address(space_id, offset)
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            self.0.get_stack_space()
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            self.0.get_constant_space()
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            self.0.get_unique_space()
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            self.0.get_register_space()
        }
        fn get_constant_address(&self, offset: i64) -> Option<Address> {
            self.0.get_constant_address(offset)
        }
        fn get_address_set_range(&self, min: &Address, max: &Address) -> crate::program::model::address::AddressSet {
            self.0.get_address_set_range(min, max)
        }
        fn get_address_set(&self) -> crate::program::model::address::AddressSet {
            self.0.get_address_set()
        }
        fn old_get_address_from_long(&self, value: i64) -> Option<Address> {
            self.0.old_get_address_from_long(value)
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            self.0.has_multiple_memory_spaces()
        }
    }

    fn mock_compiler_spec() -> MockCompilerSpec {
        let ram = ram_space();
        let reg_addr = ram.address(0x100);
        let register: RegisterRef = Register::new("eax", "accumulator", reg_addr, 4, false, 0);
        let mut registers = std::collections::HashMap::new();
        registers.insert("eax".to_string(), register);
        let factory: Arc<dyn AddressFactory> = Arc::new(DefaultAddressFactory::new(vec![ram]));
        MockCompilerSpec { language: Arc::new(MockLanguage { registers, address_factory: factory }) }
    }

    #[test]
    fn restore_xml_register_form_uses_register_address_and_size() {
        let cspec = mock_compiler_spec();
        let el = MockXmlElement::new("register", &[("name", "eax")]);
        let addr = restore_xml(&el, &cspec).unwrap();
        assert_eq!(addr.get_offset(), 0x100);
        assert_eq!(addr.get_size(), 4);
    }

    #[test]
    fn restore_xml_space_offset_form() {
        let cspec = mock_compiler_spec();
        let el = MockXmlElement::new("addr", &[("space", "ram"), ("offset", "0x200"), ("size", "8")]);
        let addr = restore_xml(&el, &cspec).unwrap();
        assert_eq!(addr.get_offset(), 0x200);
        assert_eq!(addr.get_size(), 8);
        assert_eq!(addr.get_address_space().unwrap().name(), "ram");
    }

    #[test]
    fn restore_xml_unknown_space_errors() {
        let cspec = mock_compiler_spec();
        let el = MockXmlElement::new("addr", &[("space", "nope"), ("offset", "0x0")]);
        assert!(restore_xml(&el, &cspec).is_err());
    }

    #[test]
    fn restore_xml_with_language_register_form() {
        let cspec = mock_compiler_spec();
        let language = SharedLanguage(cspec.language.clone());
        let el = MockXmlElement::new("register", &[("name", "eax")]);
        let addr = restore_xml_with_language(&el, &language).unwrap();
        assert_eq!(addr.get_offset(), 0x100);
        assert_eq!(addr.get_size(), 4);
    }

    #[test]
    fn restore_range_xml_uses_first_and_last() {
        let cspec = mock_compiler_spec();
        let el = MockXmlElement::new("range", &[("space", "ram"), ("first", "0x10"), ("last", "0x1f")]);
        let range = restore_range_xml(&el, &cspec).unwrap();
        assert_eq!(range.get_offset(), 0x10);
        assert_eq!(range.get_size(), 0x10);
    }

    #[test]
    fn restore_range_xml_register_form_covers_register_extent() {
        let cspec = mock_compiler_spec();
        let el = MockXmlElement::new("range", &[("name", "eax")]);
        let range = restore_range_xml(&el, &cspec).unwrap();
        assert_eq!(range.get_offset(), 0x100);
        assert_eq!(range.get_size(), 4);
    }
}
