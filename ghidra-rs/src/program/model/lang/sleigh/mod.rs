use super::Endian;
use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
use crate::program::model::pcode::{
    Decoder, DecoderError, ATTRIB_ALIGN, ATTRIB_BIGENDIAN, ATTRIB_DEFAULTSPACE, ATTRIB_DELAY,
    ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_NUMSECTIONS, ATTRIB_SIZE, ATTRIB_UNIQBASE, ATTRIB_UNIQMASK,
    ATTRIB_VERSION, ATTRIB_WORDSIZE, ELEM_SLEIGH, ELEM_SOURCEFILES, ELEM_SPACE, ELEM_SPACES,
    ELEM_SPACE_OTHER, ELEM_SPACE_UNIQUE,
};
use std::collections::HashMap;
use std::sync::Arc;

pub mod constructor;
pub mod decision;
pub mod expression;
pub mod handle;
pub mod pattern;
pub mod symbol;
pub mod template;
pub mod walker;

pub use handle::FixedHandle;
pub use walker::{ParserWalker, SleighError};

use symbol::{SleighSymbol, SubtableSymbol, SymbolTable};

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
}

impl SleighLanguage {
    pub fn get_id(&self) -> &str {
        &self._id
    }

    pub fn get_symbol_table(&self) -> &SymbolTable {
        &self._symbol_table
    }

    pub fn get_address_factory(&self) -> Arc<DefaultAddressFactory> {
        self._address_factory.clone()
    }

    pub fn is_big_endian(&self) -> bool {
        self._endian == Endian::Big
    }

    pub fn decode(decoder: &dyn Decoder, id: String) -> Result<Self, DecoderError> {
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

        if decoder.peek_element()? == ELEM_SOURCEFILES.id {
            let indexer_el = decoder.open_element()?;
            decoder.close_element_skipping(indexer_el)?;
        }

        let (space_table, default_space) = Self::parse_spaces(decoder)?;

        let mut all_spaces: Vec<Arc<AddressSpace>> = space_table.values().cloned().collect();
        all_spaces.sort_by_key(|s| s.space_id());
        let address_factory = Arc::new(DefaultAddressFactory::new(all_spaces));
        decoder.set_address_factory(address_factory.clone());

        let mut sleigh = Self {
            _id: id,
            _endian: endian,
            _instruction_endian: endian,
            _unique_base: unique_base,
            _alignment: alignment,
            _unique_allocate_mask: unique_allocate_mask,
            _num_sections: num_sections,
            _address_factory: address_factory,
            _default_space: default_space,
            _space_table: space_table,
            _symbol_table: SymbolTable::new(),
        };

        let mut symbol_table = SymbolTable::new();
        symbol_table.decode(decoder, &sleigh)?;
        sleigh._symbol_table = symbol_table;

        decoder.close_element(el)?;

        Ok(sleigh)
    }

    fn parse_spaces(
        decoder: &dyn Decoder,
    ) -> Result<
        (
            HashMap<String, Arc<AddressSpace>>,
            Option<Arc<AddressSpace>>,
        ),
        DecoderError,
    > {
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

            let spc = AddressSpace::new(&name, 8 * size, wordsize, space_type, index);
            space_table.insert(name.clone(), spc);
            decoder.close_element(subel)?;
        }

        let default_space = space_table.get(&defname).cloned();
        decoder.close_element(el)?;

        Ok((space_table, default_space))
    }

    pub fn resolve(&self, walker: &mut ParserWalker) -> Result<(), SleighError> {
        let root_sym = self._symbol_table.find_symbol_by_name("instruction", 0);
        if let Some(SleighSymbol::Subtable(root_sub)) = root_sym {
            self.resolve_subtable(walker, root_sub)?;
            Ok(())
        } else {
            Err(SleighError::UnknownInstruction(walker.context.addr.clone()))
        }
    }

    fn resolve_subtable(
        &self,
        walker: &mut ParserWalker,
        subtable: &SubtableSymbol,
    ) -> Result<(), SleighError> {
        let tree = subtable
            .decision_tree
            .as_ref()
            .ok_or_else(|| SleighError::UnknownInstruction(walker.context.addr.clone()))?;
        let ct = tree.resolve(walker, subtable)?;

        let state_idx = walker.current_state;
        walker.states[state_idx].ct = Some(ct.clone());

        // Resolve operands
        for i in 0..ct.operands.len() {
            let op = &ct.operands[i];
            if let Some(triple_id) = op.triple_id {
                let sym = self._symbol_table.find_symbol(triple_id);
                if let Some(SleighSymbol::Subtable(sub)) = sym {
                    walker.allocate_operand(i);
                    walker.push_operand(i);
                    self.resolve_subtable(walker, sub)?;
                    walker.pop_operand();
                }
            }
        }
        Ok(())
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
                .ok_or_else(|| MemoryAccessException("out of bounds".to_string()))
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
        use crate::program::model::lang::sleigh::walker::ParserContext;

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space.clone(), 0x1000);
        let mem = Arc::new(MockMemBuffer {
            addr: addr.clone(),
            data: vec![0x39, 0x00, 0x00, 0x00],
        });

        let context = Arc::new(ParserContext {
            addr: addr.clone(),
            naddr: addr.clone(),
            n2addr: addr.clone(),
            context: vec![0],
            mem_buffer: mem,
            handle_map: HashMap::new(),
        });

        let mut walker = ParserWalker::new(context);

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
        let sleigh = SleighLanguage::decode(&decoder, "test".to_string()).unwrap();

        sleigh.resolve(&mut walker).unwrap();

        assert!(walker.states[0].ct.is_some());
    }
}
