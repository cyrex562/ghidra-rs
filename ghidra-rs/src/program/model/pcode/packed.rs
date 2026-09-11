use super::decoder::{Decoder, DecoderError};
use super::encoder::Encoder;
use super::ids::{AttributeId, ElementId, ATTRIB_UNKNOWN};
use crate::decompiler::opcodes::op_code::OpCode;
use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

pub const HEADER_MASK: u8 = 0xc0;
pub const ELEMENT_START: u8 = 0x40;
pub const ELEMENT_END: u8 = 0x80;
pub const ATTRIBUTE: u8 = 0xc0;
pub const HEADEREXTEND_MASK: u8 = 0x20;
pub const ELEMENTID_MASK: u8 = 0x1f;
pub const RAWDATA_MASK: u8 = 0x7f;
pub const RAWDATA_BITSPERBYTE: u32 = 7;
pub const RAWDATA_MARKER: u8 = 0x80;
pub const TYPECODE_SHIFT: u32 = 4;
pub const LENGTHCODE_MASK: u8 = 0xf;

pub const TYPECODE_BOOLEAN: u8 = 1;
pub const TYPECODE_SIGNEDINT_POSITIVE: u8 = 2;
pub const TYPECODE_SIGNEDINT_NEGATIVE: u8 = 3;
pub const TYPECODE_UNSIGNEDINT: u8 = 4;
pub const TYPECODE_ADDRESSSPACE: u8 = 5;
pub const TYPECODE_SPECIALSPACE: u8 = 6;
pub const TYPECODE_STRING: u8 = 7;

pub const SPECIALSPACE_STACK: u8 = 0;
pub const SPECIALSPACE_JOIN: u8 = 1;
pub const SPECIALSPACE_FSPEC: u8 = 2;
pub const SPECIALSPACE_IOP: u8 = 3;
pub const SPECIALSPACE_SPACEBASE: u8 = 4;

pub struct PackedDecode {
    addr_factory: RwLock<Arc<dyn AddressFactory>>,
    data: Vec<u8>,
    start_pos: AtomicUsize,
    cur_pos: AtomicUsize,
    end_pos: AtomicUsize,
    attribute_read: AtomicBool,
    spaces: RwLock<Vec<Option<Arc<AddressSpace>>>>,
}

impl PackedDecode {
    pub fn new(addr_factory: Arc<dyn AddressFactory>, data: Vec<u8>) -> Self {
        let spaces = Self::build_spaces(addr_factory.as_ref());

        Self {
            addr_factory: RwLock::new(addr_factory),
            data,
            start_pos: AtomicUsize::new(0),
            cur_pos: AtomicUsize::new(0),
            end_pos: AtomicUsize::new(0),
            attribute_read: AtomicBool::new(true),
            spaces: RwLock::new(spaces),
        }
    }

    fn build_spaces(addr_factory: &dyn AddressFactory) -> Vec<Option<Arc<AddressSpace>>> {
        let mut spaces = Vec::new();
        let all_spaces = addr_factory.get_all_address_spaces();
        for spc in all_spaces {
            // Port of `PackedDecode.buildAddrSpaceArray`: only these five space types are
            // indexed by the packed "basic address space" encoding (TYPECODE_ADDRESSSPACE).
            // Java explicitly `continue`s past every other type (code, stack, join, symbol,
            // external, variable, deleted, unknown, none) - stack/join/etc. instead go through
            // the TYPECODE_SPECIALSPACE path. This filter was missing from the original partial
            // port, which indexed every space unconditionally; that could shift indices or wire
            // up the wrong space when a program has non-basic spaces mixed in with basic ones.
            let ty = spc.space_type();
            if !matches!(
                ty,
                AddressSpaceType::Constant
                    | AddressSpaceType::Ram
                    | AddressSpaceType::Register
                    | AddressSpaceType::Unique
                    | AddressSpaceType::Other
            ) {
                continue;
            }
            let ind = spc.unique() as usize;
            if spaces.len() <= ind {
                spaces.resize(ind + 1, None);
            }
            spaces[ind] = Some(spc);
        }
        spaces
    }

    fn get_next_byte(&self, pos: &AtomicUsize) -> Result<u8, DecoderError> {
        let p = pos.fetch_add(1, Ordering::SeqCst);
        if p >= self.data.len() {
            return Err(DecoderError::UnexpectedEndOfStream);
        }
        Ok(self.data[p])
    }

    fn peek_byte(&self, pos: &AtomicUsize) -> Result<u8, DecoderError> {
        let p = pos.load(Ordering::SeqCst);
        if p >= self.data.len() {
            return Err(DecoderError::UnexpectedEndOfStream);
        }
        Ok(self.data[p])
    }

    /// Peek at an absolute byte offset without touching any cursor. Used by
    /// `read_signed_integer_expect_string` to inspect the upcoming type byte the same way
    /// Java's `readSignedIntegerExpectString` does with a throwaway `tmpPos` copy of `curPos`,
    /// without disturbing `cur_pos` itself.
    fn peek_byte_at(&self, pos: usize) -> Result<u8, DecoderError> {
        if pos >= self.data.len() {
            return Err(DecoderError::UnexpectedEndOfStream);
        }
        Ok(self.data[pos])
    }

    fn read_integer(&self, len: u8) -> Result<u64, DecoderError> {
        let mut res = 0u64;
        for _ in 0..len {
            let b = self.get_next_byte(&self.cur_pos)?;
            res <<= RAWDATA_BITSPERBYTE;
            res |= (b & RAWDATA_MASK) as u64;
        }
        Ok(res)
    }

    fn skip_attribute(&self) -> Result<(), DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        let attrib_type = type_byte >> TYPECODE_SHIFT;
        if attrib_type == TYPECODE_BOOLEAN || attrib_type == TYPECODE_SPECIALSPACE {
            return Ok(());
        }
        let mut length = (type_byte & LENGTHCODE_MASK) as usize;
        if attrib_type == TYPECODE_STRING {
            length = self.read_integer(length as u8)? as usize;
        }
        self.cur_pos.fetch_add(length, Ordering::SeqCst);
        Ok(())
    }

    /// Port of `PackedDecode.skipAttributeRemaining`: like `skip_attribute`, but the caller has
    /// already consumed the header and type byte (typically while checking whether the
    /// attribute's type matches what was expected) and just wants to skip past the remaining
    /// payload before reporting a type-mismatch error, leaving `cur_pos` positioned at the next
    /// attribute/element the same way Java leaves `curPos`.
    fn skip_attribute_remaining(&self, type_byte: u8) -> Result<(), DecoderError> {
        let attrib_type = type_byte >> TYPECODE_SHIFT;
        if attrib_type == TYPECODE_BOOLEAN || attrib_type == TYPECODE_SPECIALSPACE {
            return Ok(());
        }
        let mut length = (type_byte & LENGTHCODE_MASK) as usize;
        if attrib_type == TYPECODE_STRING {
            length = self.read_integer(length as u8)? as usize;
        }
        self.cur_pos.fetch_add(length, Ordering::SeqCst);
        Ok(())
    }

    fn find_matching_attribute(&self, attrib_id: AttributeId) -> Result<(), DecoderError> {
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        loop {
            let header1 = self.peek_byte(&self.cur_pos)?;
            if (header1 & HEADER_MASK) != ATTRIBUTE {
                break;
            }
            let mut id = (header1 & ELEMENTID_MASK) as i32;
            if (header1 & HEADEREXTEND_MASK) != 0 {
                let next_byte = self.data[self.cur_pos.load(Ordering::SeqCst) + 1];
                id <<= RAWDATA_BITSPERBYTE;
                id |= (next_byte & RAWDATA_MASK) as i32;
            }
            if id == attrib_id.id {
                return Ok(());
            }
            self.skip_attribute()?;
        }
        Err(DecoderError::MissingAttribute(attrib_id.name.to_string()))
    }
}

impl Decoder for PackedDecode {
    fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
        self.addr_factory.read().unwrap().clone()
    }

    fn set_address_factory(&self, factory: Arc<dyn AddressFactory>) {
        let new_spaces = Self::build_spaces(factory.as_ref());
        *self.addr_factory.write().unwrap() = factory;
        *self.spaces.write().unwrap() = new_spaces;
    }

    fn peek_element(&self) -> Result<i32, DecoderError> {
        let header1 = self.peek_byte(&self.end_pos)?;
        if (header1 & HEADER_MASK) != ELEMENT_START {
            return Ok(0);
        }
        let mut id = (header1 & ELEMENTID_MASK) as i32;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            let next_byte = self.data[self.end_pos.load(Ordering::SeqCst) + 1];
            id <<= RAWDATA_BITSPERBYTE;
            id |= (next_byte & RAWDATA_MASK) as i32;
        }
        Ok(id)
    }

    fn open_element(&self) -> Result<i32, DecoderError> {
        let header1 = self.peek_byte(&self.end_pos)?;
        if (header1 & HEADER_MASK) != ELEMENT_START {
            return Ok(0);
        }
        self.get_next_byte(&self.end_pos)?;
        let mut id = (header1 & ELEMENTID_MASK) as i32;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            let b = self.get_next_byte(&self.end_pos)?;
            id <<= RAWDATA_BITSPERBYTE;
            id |= (b & RAWDATA_MASK) as i32;
        }
        self.start_pos
            .store(self.end_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        self.cur_pos
            .store(self.end_pos.load(Ordering::SeqCst), Ordering::SeqCst);

        loop {
            let h = self.peek_byte(&self.cur_pos)?;
            if (h & HEADER_MASK) != ATTRIBUTE {
                break;
            }
            self.skip_attribute()?;
        }
        self.end_pos
            .store(self.cur_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        self.attribute_read.store(true, Ordering::SeqCst);
        Ok(id)
    }

    fn open_element_with_id(&self, elem_id: ElementId) -> Result<i32, DecoderError> {
        let id = self.open_element()?;
        if id != elem_id.id {
            return Err(DecoderError::InvalidElement {
                expected: elem_id.name.to_string(),
                actual: format!("id {}", id),
            });
        }
        Ok(id)
    }

    fn close_element(&self, id: i32) -> Result<(), DecoderError> {
        let header1 = self.get_next_byte(&self.end_pos)?;
        if (header1 & HEADER_MASK) != ELEMENT_END {
            return Err(DecoderError::Generic(format!(
                "Expecting element close (expected {}, found header 0x{:02x} at pos {})",
                id,
                header1,
                self.end_pos.load(Ordering::SeqCst) - 1
            )));
        }
        let mut close_id = (header1 & ELEMENTID_MASK) as i32;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            let b = self.get_next_byte(&self.end_pos)?;
            close_id <<= RAWDATA_BITSPERBYTE;
            close_id |= (b & RAWDATA_MASK) as i32;
        }
        if id != close_id {
            return Err(DecoderError::Generic(format!(
                "Did not see expected closing element (expected {}, found {})",
                id, close_id
            )));
        }
        Ok(())
    }

    fn close_element_skipping(&self, id: i32) -> Result<(), DecoderError> {
        let mut idstack = vec![id];
        while !idstack.is_empty() {
            let header1 = self.peek_byte(&self.end_pos)? & HEADER_MASK;
            if header1 == ELEMENT_END {
                let last_id = idstack.pop().unwrap();
                self.close_element(last_id)?;
            } else if header1 == ELEMENT_START {
                idstack.push(self.open_element()?);
            } else {
                return Err(DecoderError::Generic(format!(
                    "Corrupt stream in close_element_skipping (header 0x{:02x} at pos {})",
                    self.peek_byte(&self.end_pos)?,
                    self.end_pos.load(Ordering::SeqCst)
                )));
            }
        }
        Ok(())
    }

    fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
        if !self.attribute_read.load(Ordering::SeqCst) {
            self.skip_attribute()?;
        }
        let header1 = self.peek_byte(&self.cur_pos)?;
        if (header1 & HEADER_MASK) != ATTRIBUTE {
            return Ok(0);
        }
        let mut id = (header1 & ELEMENTID_MASK) as i32;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            let next_byte = self.data[self.cur_pos.load(Ordering::SeqCst) + 1];
            id <<= RAWDATA_BITSPERBYTE;
            id |= (next_byte & RAWDATA_MASK) as i32;
        }
        self.attribute_read.store(false, Ordering::SeqCst);
        Ok(id)
    }

    fn rewind_attributes(&self) {
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        self.attribute_read.store(true, Ordering::SeqCst);
    }

    fn read_bool(&self) -> Result<bool, DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        if (type_byte >> TYPECODE_SHIFT) != TYPECODE_BOOLEAN {
            return Err(DecoderError::Generic(
                "Expecting boolean attribute".to_string(),
            ));
        }
        self.attribute_read.store(true, Ordering::SeqCst);
        Ok((type_byte & LENGTHCODE_MASK) != 0)
    }

    fn read_bool_with_id(&self, attrib_id: AttributeId) -> Result<bool, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_bool();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    fn read_signed_integer(&self) -> Result<i64, DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        let res = if type_code == TYPECODE_SIGNEDINT_POSITIVE {
            self.read_integer(type_byte & LENGTHCODE_MASK)? as i64
        } else if type_code == TYPECODE_SIGNEDINT_NEGATIVE {
            // Use `wrapping_neg` rather than plain `-` to match Java's silent long-overflow
            // semantics for `-Long.MIN_VALUE` (which stays `Long.MIN_VALUE` in two's
            // complement). `PackedEncode.writeSignedInteger` relies on that same wraparound to
            // correctly encode `i64::MIN`'s true magnitude (2^63) as an unsigned quantity, so
            // decoding must undo it the same way rather than panicking on overflow.
            (self.read_integer(type_byte & LENGTHCODE_MASK)? as i64).wrapping_neg()
        } else {
            self.skip_attribute_remaining(type_byte)?;
            return Err(DecoderError::Generic(
                "Expecting signed integer attribute".to_string(),
            ));
        };
        self.attribute_read.store(true, Ordering::SeqCst);
        Ok(res)
    }

    fn read_signed_integer_with_id(&self, attrib_id: AttributeId) -> Result<i64, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_signed_integer();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        let res = if type_code == TYPECODE_UNSIGNEDINT {
            self.read_integer(type_byte & LENGTHCODE_MASK)?
        } else {
            self.skip_attribute_remaining(type_byte)?;
            return Err(DecoderError::Generic(
                "Expecting unsigned integer attribute".to_string(),
            ));
        };
        self.attribute_read.store(true, Ordering::SeqCst);
        Ok(res)
    }

    fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_unsigned_integer();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    fn read_string(&self) -> Result<String, DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        if type_code != TYPECODE_STRING {
            self.skip_attribute_remaining(type_byte)?;
            return Err(DecoderError::Generic(
                "Expecting string attribute".to_string(),
            ));
        }
        let length = self.read_integer(type_byte & LENGTHCODE_MASK)? as usize;
        self.attribute_read.store(true, Ordering::SeqCst);

        let p = self.cur_pos.load(Ordering::SeqCst);
        if p + length > self.data.len() {
            return Err(DecoderError::UnexpectedEndOfStream);
        }
        let s = String::from_utf8_lossy(&self.data[p..p + length]).to_string();
        self.cur_pos.store(p + length, Ordering::SeqCst);
        Ok(s)
    }

    fn read_string_with_id(&self, attrib_id: AttributeId) -> Result<String, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_string();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
        let header1 = self.get_next_byte(&self.cur_pos)?;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            self.get_next_byte(&self.cur_pos)?;
        }
        let type_byte = self.get_next_byte(&self.cur_pos)?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        let mut spc = None;
        if type_code == TYPECODE_ADDRESSSPACE {
            let res = self.read_integer(type_byte & LENGTHCODE_MASK)? as usize;
            let spaces = self.spaces.read().unwrap();
            if res < spaces.len() {
                spc = spaces[res].clone();
            }
            if spc.is_none() {
                return Err(DecoderError::Generic(
                    "Unknown address space index".to_string(),
                ));
            }
        } else if type_code == TYPECODE_SPECIALSPACE {
            let special_code = type_byte & LENGTHCODE_MASK;
            if special_code == SPECIALSPACE_STACK {
                let addr_factory = self.get_address_factory();
                spc = addr_factory.get_stack_space();
            } else if special_code == SPECIALSPACE_JOIN {
                // TODO(port): Java returns the shared `AddressSpace.VARIABLE_SPACE` singleton
                // here (see `PackedDecode.readSpace`, `case SPECIALSPACE_JOIN`). This crate's
                // `program::model::address` module has no equivalent join/variable-space
                // singleton reachable from an `AddressFactory` (no `get_variable_space()` or
                // similar), so a real join-space `Arc<AddressSpace>` cannot be constructed here
                // yet. Blocked on that singleton/accessor being ported first.
                return Err(DecoderError::Generic(
                    "Cannot marshal special address space: join space not yet supported (TODO(port): needs AddressSpace.VARIABLE_SPACE equivalent)"
                        .to_string(),
                ));
            } else if special_code == SPECIALSPACE_SPACEBASE {
                // TODO(port): Java deliberately leaves `spc == null` and returns *successfully*
                // for this code (see the comment in `PackedDecode.readSpace`: "We let the null
                // address space get returned here... resulting in NO_ADDRESS"). This trait's
                // `read_space` signature is `Result<Arc<AddressSpace>, DecoderError>`, which has
                // no way to represent a valid "no space" result, so this case cannot be ported
                // faithfully without changing the `Decoder` trait (out of scope here -
                // `decoder.rs` is an already-DONE file many other ported classes depend on).
                return Err(DecoderError::Generic(
                    "Cannot marshal special address space: spacebase (null space) not representable by this Decoder trait (TODO(port): needs Option<Arc<AddressSpace>> return type)"
                        .to_string(),
                ));
            } else {
                return Err(DecoderError::Generic(
                    "Cannot marshal special address space".to_string(),
                ));
            }
        } else {
            self.skip_attribute_remaining(type_byte)?;
            return Err(DecoderError::Generic(
                "Expecting space attribute".to_string(),
            ));
        }
        self.attribute_read.store(true, Ordering::SeqCst);
        spc.ok_or_else(|| DecoderError::Generic("Missing space".to_string()))
    }

    fn read_space_with_id(
        &self,
        attrib_id: AttributeId,
    ) -> Result<Arc<AddressSpace>, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_space();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }
}

/// Additional `PackedDecode` methods that mirror real public methods on Java's `PackedDecode`
/// (and its `Decoder` interface) but have no counterpart on this crate's [`Decoder`] trait
/// (`decoder.rs`), which does not declare `readOpcode`/`readOpcode(AttributeId)`,
/// `readSignedIntegerExpectString`, or `getIndexedAttributeId` even though Java's `Decoder`
/// interface does. Since `decoder.rs` is an already-DONE file with many existing implementors
/// and consumers across the crate, extending the trait is out of scope here; these are exposed
/// as inherent methods directly on the concrete decoder instead so the capability genuinely
/// exists and is callable.
impl PackedDecode {
    /// Port of `PackedDecode.readOpcode`.
    pub fn read_opcode(&self) -> Result<i32, DecoderError> {
        let val = self.read_signed_integer()?;
        if val < 0 || OpCode::from_ordinal(val as usize).is_none() {
            return Err(DecoderError::Generic("Bad OpCode".to_string()));
        }
        Ok(val as i32)
    }

    /// Port of `PackedDecode.readOpcode(AttributeId)`.
    pub fn read_opcode_with_id(&self, attrib_id: AttributeId) -> Result<i32, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_opcode();
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    /// Port of `PackedDecode.readSignedIntegerExpectString`. Peeks the upcoming type byte at an
    /// absolute offset (mirroring Java's throwaway `tmpPos` copy of `curPos`) without disturbing
    /// the shared cursor, then either parses a string and checks it against `expect`, or falls
    /// through to a normal `read_signed_integer`.
    pub fn read_signed_integer_expect_string(
        &self,
        expect: &str,
        expect_val: i64,
    ) -> Result<i64, DecoderError> {
        let mut p = self.cur_pos.load(Ordering::SeqCst);
        let header1 = self.peek_byte_at(p)?;
        p += 1;
        if (header1 & HEADEREXTEND_MASK) != 0 {
            p += 1;
        }
        let type_byte = self.peek_byte_at(p)?;
        let type_code = type_byte >> TYPECODE_SHIFT;
        if type_code == TYPECODE_STRING {
            let val = self.read_string()?;
            if val != expect {
                return Err(DecoderError::Generic(format!(
                    "Expecting string \"{}\" but read \"{}\"",
                    expect, val
                )));
            }
            Ok(expect_val)
        } else {
            self.read_signed_integer()
        }
    }

    /// Port of `PackedDecode.readSignedIntegerExpectString(AttributeId, String, long)`.
    pub fn read_signed_integer_expect_string_with_id(
        &self,
        attrib_id: AttributeId,
        expect: &str,
        expect_val: i64,
    ) -> Result<i64, DecoderError> {
        self.find_matching_attribute(attrib_id)?;
        let res = self.read_signed_integer_expect_string(expect, expect_val);
        self.cur_pos
            .store(self.start_pos.load(Ordering::SeqCst), Ordering::SeqCst);
        res
    }

    /// Port of `PackedDecode.getIndexedAttributeId`. Faithfully reproduces a real Java quirk:
    /// despite `Decoder.getIndexedAttributeId`'s Javadoc describing "reinterpret the attribute
    /// as being an indexed form of the given attribute... return this indexed id, otherwise
    /// return ATTRIB_UNKNOWN", `PackedDecode`'s actual body ignores `attribId` entirely and
    /// unconditionally returns `AttributeId.ATTRIB_UNKNOWN.id()` - i.e. indexed-attribute lookup
    /// is effectively unimplemented for this decoder, by design or oversight in the original.
    pub fn get_indexed_attribute_id(&self, _attrib_id: AttributeId) -> i32 {
        ATTRIB_UNKNOWN.id
    }
}

/// Port of `ghidra.program.model.pcode.PackedEncode`: a byte-based [`Encoder`] designed to
/// marshal info to the decompiler efficiently, matching the wire format documented in
/// [`PackedDecode`] (element/attribute headers, type-tagged/length-coded attribute payloads).
///
/// Java's `PackedEncode` wraps a `java.io.OutputStream` (nullable, settable later via a
/// subclass's `clear()`, as `PatchPackedEncode` does). This port instead owns a generic `W:
/// io::Write` directly, matching the pattern already established by `CachedEncoder`/
/// `PatchEncoder` in this crate (see `cached_encoder.rs`, `patch_encoder.rs`) - a stream must be
/// supplied up front via [`PackedEncode::new`] rather than left `None`.
pub struct PackedEncode<W: io::Write> {
    out_stream: W,
}

impl<W: io::Write> PackedEncode<W> {
    /// Port of `PackedEncode(OutputStream)`. (Java's no-arg `PackedEncode()`, which leaves
    /// `outStream` `null` until a subclass sets it, has no direct counterpart here since `W` is
    /// a concrete, always-present type; see the struct-level note.)
    pub fn new(out_stream: W) -> Self {
        Self { out_stream }
    }

    /// Port of `PackedEncode.getOutputStream`.
    pub fn output_stream(&mut self) -> &mut W {
        &mut self.out_stream
    }

    /// Consumes the encoder, returning the underlying stream/buffer.
    pub fn into_inner(self) -> W {
        self.out_stream
    }

    /// Port of `PackedEncode.writeHeader`.
    fn write_header(&mut self, header: u8, id: i32) -> io::Result<()> {
        if id > 0x1f {
            let extended_header = header | HEADEREXTEND_MASK | ((id >> RAWDATA_BITSPERBYTE) as u8);
            let extend_byte = ((id & RAWDATA_MASK as i32) as u8) | RAWDATA_MARKER;
            self.out_stream.write_all(&[extended_header, extend_byte])
        } else {
            let full_header = header | (id as u8);
            self.out_stream.write_all(&[full_header])
        }
    }

    /// Port of `PackedEncode.writeInteger`. `val` is treated the same way Java's `long val`
    /// parameter is: a genuine 64-bit unsigned magnitude when called from
    /// `write_unsigned_integer`, or a known-non-negative magnitude everywhere else. Whenever the
    /// value's top bit is set (i.e. it would read as negative if reinterpreted as `i64`), Java's
    /// `val <= 0` branch (excluding the `val == 0` case) kicks in and always emits the full
    /// 10-byte / 70-bit encoding using an *unsigned* right shift - which is exactly what's needed
    /// to losslessly round-trip any 64-bit unsigned quantity, so that's reproduced here by
    /// checking `val as i64 == i64::MIN..0` rather than trying to special-case "large u64".
    fn write_integer(&mut self, mut type_byte: u8, val: u64) -> io::Result<()> {
        let len_code: u8;
        let mut sa: i32;
        if val == 0 {
            len_code = 0;
            sa = -1;
        } else if (val as i64) < 0 {
            // Top bit set: matches Java's `val <= 0` (but nonzero) branch.
            len_code = 10;
            sa = 9 * RAWDATA_BITSPERBYTE as i32;
        } else if val < 0x800000000u64 {
            if val < 0x200000u64 {
                if val < 0x80u64 {
                    len_code = 1; // 7 bits
                    sa = 0;
                } else if val < 0x4000u64 {
                    len_code = 2; // 14 bits
                    sa = RAWDATA_BITSPERBYTE as i32;
                } else {
                    len_code = 3; // 21 bits
                    sa = 2 * RAWDATA_BITSPERBYTE as i32;
                }
            } else if val < 0x10000000u64 {
                len_code = 4; // 28 bits
                sa = 3 * RAWDATA_BITSPERBYTE as i32;
            } else {
                len_code = 5; // 35 bits
                sa = 4 * RAWDATA_BITSPERBYTE as i32;
            }
        } else if val < 0x2000000000000u64 {
            if val < 0x40000000000u64 {
                len_code = 6;
                sa = 5 * RAWDATA_BITSPERBYTE as i32;
            } else {
                len_code = 7;
                sa = 6 * RAWDATA_BITSPERBYTE as i32;
            }
        } else if val < 0x100000000000000u64 {
            len_code = 8;
            sa = 7 * RAWDATA_BITSPERBYTE as i32;
        } else {
            len_code = 9;
            sa = 8 * RAWDATA_BITSPERBYTE as i32;
        }
        type_byte |= len_code;
        self.out_stream.write_all(&[type_byte])?;
        while sa >= 0 {
            let piece = (((val >> sa) & (RAWDATA_MASK as u64)) as u8) | RAWDATA_MARKER;
            self.out_stream.write_all(&[piece])?;
            sa -= RAWDATA_BITSPERBYTE as i32;
        }
        Ok(())
    }
}

impl<W: io::Write> Encoder for PackedEncode<W> {
    fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        self.write_header(ELEMENT_START, elem_id.id)
    }

    fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
        self.write_header(ELEMENT_END, elem_id.id)
    }

    fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        let type_byte: u8 = if val { 0x11 } else { 0x10 };
        self.out_stream.write_all(&[type_byte])
    }

    fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        let (type_byte, num): (u8, u64) = if val < 0 {
            // `wrapping_neg` reproduces Java's silent `-Long.MIN_VALUE` overflow (see
            // `write_integer`'s doc comment and the matching note on `read_signed_integer`).
            (
                TYPECODE_SIGNEDINT_NEGATIVE << TYPECODE_SHIFT,
                val.wrapping_neg() as u64,
            )
        } else {
            (TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT, val as u64)
        };
        self.write_integer(type_byte, num)
    }

    fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        self.write_integer(TYPECODE_UNSIGNEDINT << TYPECODE_SHIFT, val)
    }

    fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
        let bytes = val.as_bytes();
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, bytes.len() as u64)?;
        self.out_stream.write_all(bytes)
    }

    fn write_string_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        val: &str,
    ) -> io::Result<()> {
        let bytes = val.as_bytes();
        self.write_header(ATTRIBUTE, attrib_id.id + index)?;
        self.write_integer(TYPECODE_STRING << TYPECODE_SHIFT, bytes.len() as u64)?;
        self.out_stream.write_all(bytes)
    }

    fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        match spc.space_type() {
            AddressSpaceType::Constant
            | AddressSpaceType::Ram
            | AddressSpaceType::Register
            | AddressSpaceType::Unique
            | AddressSpaceType::Other => {
                self.write_integer(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, spc.unique() as u64)
            }
            // Note: the Java space *type* that maps onto the packed format's "join" special
            // space is `AddressSpace.TYPE_VARIABLE` (this crate's `AddressSpaceType::Variable`),
            // not `TYPE_JOIN` - see `PackedEncode.writeSpace`'s `case AddressSpace.TYPE_VARIABLE`.
            AddressSpaceType::Variable => self
                .out_stream
                .write_all(&[(TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_JOIN]),
            AddressSpaceType::Stack => self
                .out_stream
                .write_all(&[(TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK]),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Cannot marshal address space: {}", spc.name()),
            )),
        }
    }

    fn write_space_indexed(
        &mut self,
        attrib_id: AttributeId,
        index: i32,
        _name: &str,
    ) -> io::Result<()> {
        // Port of `PackedEncode.writeSpace(AttributeId, int, String)`. Faithfully matches Java:
        // only `index` is written to the wire (the packed format's TYPECODE_ADDRESSSPACE payload
        // is just an integer index into the decoder's `spaces` table); `name` is accepted per
        // the `Encoder` interface contract but never actually encoded here, in Java either.
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        self.write_integer(TYPECODE_ADDRESSSPACE << TYPECODE_SHIFT, index as u64)
    }

    fn write_opcode(&mut self, attrib_id: AttributeId, opcode: OpCode) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        self.write_integer(
            TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT,
            opcode.ordinal() as u64,
        )
    }

    fn write_opcode_ordinal(&mut self, attrib_id: AttributeId, opcode: i32) -> io::Result<()> {
        self.write_header(ATTRIBUTE, attrib_id.id)?;
        // Matches Java's implicit int->long widening (sign-extends, then `writeInteger`'s own
        // `val <= 0` branch handles a negative `opcode` the same way it handles any other
        // top-bit-set 64-bit magnitude).
        self.write_integer(
            TYPECODE_SIGNEDINT_POSITIVE << TYPECODE_SHIFT,
            (opcode as i64) as u64,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::DefaultAddressFactory;
    use crate::program::model::pcode::ids::{
        ATTRIB_CONTENT, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_VAL, ELEM_ADDR, ELEM_DATA,
        ELEM_VOID,
    };

    // Note: `DefaultAddressFactory::new`/`with_default_space` calls `validate_space`, which
    // panics if given a `Stack`, `Variable`, or `External` typed space (see `factory.rs`) - those
    // spaces are only ever handed out via dedicated accessors like `get_stack_space()`, never
    // stored in a factory's own space list. So tests that need a stack/join space construct a
    // bare `AddressSpace` value directly instead of registering it with a factory.
    fn factory_with_spaces() -> Arc<DefaultAddressFactory> {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let register = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Arc::new(DefaultAddressFactory::new(vec![ram, register]))
    }

    /// The single most valuable test for this pair: encode a representative nested-element
    /// tree, with several different attribute kinds (string, signed int, unsigned int, bool,
    /// space), using the new `PackedEncode`, then decode the resulting bytes back with
    /// `PackedDecode` and check every value round-trips.
    #[test]
    fn encode_then_decode_round_trip() {
        let factory = factory_with_spaces();
        let ram = factory.get_address_space_by_name("ram").unwrap();

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_string(ATTRIB_NAME, "outer").unwrap();
        encoder.write_bool(ATTRIB_CONTENT, true).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, -12345).unwrap();
        encoder.write_unsigned_integer(ATTRIB_SIZE, 0xdead_beef).unwrap();
        encoder.write_space(ATTRIB_SPACE, &ram).unwrap();

        encoder.open_element(ELEM_ADDR).unwrap();
        encoder.write_string(ATTRIB_NAME, "inner").unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, 42).unwrap();
        encoder.close_element(ELEM_ADDR).unwrap();

        encoder.open_element(ELEM_VOID).unwrap();
        encoder.write_bool(ATTRIB_CONTENT, false).unwrap();
        encoder.close_element(ELEM_VOID).unwrap();

        encoder.close_element(ELEM_DATA).unwrap();

        let bytes = encoder.into_inner();
        let decoder = PackedDecode::new(factory.clone(), bytes);

        let outer_id = decoder.open_element().unwrap();
        assert_eq!(outer_id, ELEM_DATA.id);
        assert_eq!(decoder.read_string_with_id(ATTRIB_NAME).unwrap(), "outer");
        assert!(decoder.read_bool_with_id(ATTRIB_CONTENT).unwrap());
        assert_eq!(decoder.read_signed_integer_with_id(ATTRIB_VAL).unwrap(), -12345);
        assert_eq!(
            decoder.read_unsigned_integer_with_id(ATTRIB_SIZE).unwrap(),
            0xdead_beef
        );
        let decoded_space = decoder.read_space_with_id(ATTRIB_SPACE).unwrap();
        assert_eq!(decoded_space.name(), "ram");

        let inner_id = decoder.open_element().unwrap();
        assert_eq!(inner_id, ELEM_ADDR.id);
        assert_eq!(decoder.read_string_with_id(ATTRIB_NAME).unwrap(), "inner");
        assert_eq!(decoder.read_signed_integer_with_id(ATTRIB_VAL).unwrap(), 42);
        decoder.close_element(inner_id).unwrap();

        let void_id = decoder.open_element().unwrap();
        assert_eq!(void_id, ELEM_VOID.id);
        assert!(!decoder.read_bool_with_id(ATTRIB_CONTENT).unwrap());
        decoder.close_element(void_id).unwrap();

        // No more children.
        assert_eq!(decoder.peek_element().unwrap(), 0);
        decoder.close_element(outer_id).unwrap();
    }

    #[test]
    fn round_trip_signed_integer_min_value() {
        // Regression test for the `i64::MIN` negation edge case: Java's `-Long.MIN_VALUE`
        // silently overflows back to `Long.MIN_VALUE`, and `writeInteger`'s `val <= 0` branch
        // then encodes that bit pattern as an unsigned 64-bit magnitude (2^63), which happens to
        // be i64::MIN's true magnitude. `wrapping_neg` reproduces this on both the encode and
        // decode side; plain `-` would panic on overflow in a debug build.
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, i64::MIN).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder.read_signed_integer_with_id(ATTRIB_VAL).unwrap(),
            i64::MIN
        );
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn round_trip_unsigned_integer_top_bit_set() {
        // u64 values >= 2^63 read as negative if bitcast to i64; exercises the same
        // "val <= 0 but not 0" branch of `write_integer` from the unsigned side.
        let big: u64 = 0xffff_ffff_ffff_ffff;
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_unsigned_integer(ATTRIB_VAL, big).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert_eq!(decoder.read_unsigned_integer_with_id(ATTRIB_VAL).unwrap(), big);
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn write_space_stack_type_writes_stack_special_space() {
        // Encode side of the STACK/TYPE_STACK mapping. `DefaultAddressFactory` cannot itself
        // hold a `Stack`-typed space (see the comment on `factory_with_spaces`), so this
        // constructs a bare `AddressSpace` directly rather than going through a factory.
        let stack = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0);
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.write_space(ATTRIB_SPACE, &stack).unwrap();
        let bytes = encoder.into_inner();
        assert_eq!(bytes.len(), 2);
        assert_eq!(
            bytes[1],
            (TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK
        );
    }

    #[test]
    fn read_space_stack_special_space_with_no_stack_space_in_factory_errors() {
        // Decode side of the STACK special space: `PackedDecode.readSpace` asks the factory for
        // `getStackSpace()`. A `DefaultAddressFactory` built from an ordinary space list never
        // has one (see the comment on `factory_with_spaces`), so decoding a STACK special-space
        // attribute against it must surface a real, honest error rather than panicking or
        // silently returning a bogus space.
        let factory = factory_with_spaces();
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        // Hand-encode a STACK special-space attribute directly since `PackedEncode::write_space`
        // needs an actual `Stack`-typed `AddressSpace` to drive it, which can't come from this
        // factory; the wire bytes are identical either way.
        encoder.write_header(ATTRIBUTE, ATTRIB_SPACE.id).unwrap();
        encoder
            .out_stream
            .push((TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_STACK);
        encoder.close_element(ELEM_DATA).unwrap();

        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert!(decoder.read_space_with_id(ATTRIB_SPACE).is_err());
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn build_spaces_excludes_code_type_from_basic_index_table() {
        // Regression test for the missing type filter in `build_spaces`: a `Code`-type space
        // (Java's deprecated `TYPE_CODE`) must not occupy a slot in the basic-address-space
        // index table used by TYPECODE_ADDRESSSPACE, since Java's `buildAddrSpaceArray`
        // explicitly excludes it (only CONSTANT/RAM/REGISTER/UNIQUE/OTHER are indexed). Unlike
        // `Stack`/`Variable`/`External`, a `Code` space *can* legally sit in a
        // `DefaultAddressFactory`'s space list (see the comment on `factory_with_spaces`), so
        // this can be a genuine round-trip test through a real factory.
        //
        // `code` is deliberately given the *same* unique index (0) as `ram`. Before the fix,
        // `build_spaces` indexed every space unconditionally, so whichever of the two came last
        // in `get_all_address_spaces()` would win that slot - meaning decoding `ram`'s index
        // could resolve to the wrong space depending on iteration order.
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let code = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 0);
        let factory = Arc::new(DefaultAddressFactory::with_default_space(
            vec![ram.clone(), code],
            Some(ram.clone()),
        ));

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_space(ATTRIB_SPACE, &ram).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();

        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        let decoded = decoder.read_space_with_id(ATTRIB_SPACE).unwrap();
        assert_eq!(decoded.name(), "ram");
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn read_opcode_round_trip_and_rejects_out_of_range() {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_opcode(ATTRIB_VAL, OpCode::CpuiIntAdd).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let decoder = PackedDecode::new(factory.clone(), encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder.read_opcode_with_id(ATTRIB_VAL).unwrap(),
            OpCode::CpuiIntAdd.ordinal() as i32
        );
        decoder.close_element(id).unwrap();

        // A signed integer far outside the valid opcode range must be rejected.
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, 999_999).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert!(decoder.read_opcode_with_id(ATTRIB_VAL).is_err());
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn read_signed_integer_expect_string_round_trip() {
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));

        // Case 1: encoded as a string that matches `expect`.
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_string(ATTRIB_VAL, "unique").unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let decoder = PackedDecode::new(factory.clone(), encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder
                .read_signed_integer_expect_string_with_id(ATTRIB_VAL, "unique", -1)
                .unwrap(),
            -1
        );
        decoder.close_element(id).unwrap();

        // Case 2: encoded as a plain signed integer.
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_DATA).unwrap();
        encoder.write_signed_integer(ATTRIB_VAL, 7).unwrap();
        encoder.close_element(ELEM_DATA).unwrap();
        let decoder = PackedDecode::new(factory, encoder.into_inner());
        let id = decoder.open_element().unwrap();
        assert_eq!(
            decoder
                .read_signed_integer_expect_string_with_id(ATTRIB_VAL, "unique", -1)
                .unwrap(),
            7
        );
        decoder.close_element(id).unwrap();
    }

    #[test]
    fn get_indexed_attribute_id_always_returns_unknown() {
        // Faithfully reproduces the Java quirk documented on `get_indexed_attribute_id`: the
        // input attribute id is ignored entirely.
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, Vec::new());
        assert_eq!(decoder.get_indexed_attribute_id(ATTRIB_VAL), ATTRIB_UNKNOWN.id);
        assert_eq!(decoder.get_indexed_attribute_id(ATTRIB_NAME), ATTRIB_UNKNOWN.id);
    }

    #[test]
    fn write_space_variable_type_writes_join_special_space() {
        // Encode side of the JOIN/TYPE_VARIABLE mapping (see `write_space`'s doc comment). The
        // decode side is documented as a TODO(port) blocker (no VARIABLE_SPACE-equivalent
        // singleton in this crate yet), so this test only checks the encoder emits the expected
        // raw special-space byte, without attempting a full decode round trip.
        let variable = AddressSpace::new("join", 32, 1, AddressSpaceType::Variable, 0);
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.write_space(ATTRIB_SPACE, &variable).unwrap();
        let bytes = encoder.into_inner();
        // header byte, then one payload byte: (SPECIALSPACE<<4) | SPECIALSPACE_JOIN
        assert_eq!(bytes.len(), 2);
        assert_eq!(
            bytes[1],
            (TYPECODE_SPECIALSPACE << TYPECODE_SHIFT) | SPECIALSPACE_JOIN
        );
    }

    #[test]
    fn write_space_unsupported_type_errors() {
        let symbol = AddressSpace::new("symbol", 32, 1, AddressSpaceType::Symbol, 0);
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        assert!(encoder.write_space(ATTRIB_SPACE, &symbol).is_err());
    }
}
