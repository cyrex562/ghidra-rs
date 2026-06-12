use super::decoder::{Decoder, DecoderError};
use super::ids::{AttributeId, ElementId};
use crate::program::model::address::{AddressFactory, AddressSpace};
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
            -(self.read_integer(type_byte & LENGTHCODE_MASK)? as i64)
        } else {
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
            let addr_factory = self.get_address_factory();
            if special_code == SPECIALSPACE_STACK {
                spc = addr_factory.get_stack_space();
            } else {
                return Err(DecoderError::Generic(
                    "Cannot marshal special address space".to_string(),
                ));
            }
        } else {
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
