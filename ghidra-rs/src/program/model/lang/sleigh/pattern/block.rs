use crate::program::model::lang::sleigh::walker::ParserWalker;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::ids::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternBlock {
    offset: i32,
    nonzerosize: i32,
    maskvec: Vec<u32>,
    valvec: Vec<u32>,
}

impl PatternBlock {
    pub fn new(off: i32, msk: u32, val: u32) -> Self {
        let mut res = Self {
            offset: off,
            nonzerosize: 4,
            maskvec: vec![msk],
            valvec: vec![val],
        };
        res.normalize();
        res
    }

    pub fn always_true() -> Self {
        Self {
            offset: 0,
            nonzerosize: 0,
            maskvec: Vec::new(),
            valvec: Vec::new(),
        }
    }

    pub fn always_false() -> Self {
        Self {
            offset: 0,
            nonzerosize: -1,
            maskvec: Vec::new(),
            valvec: Vec::new(),
        }
    }

    pub fn is_always_true(&self) -> bool {
        self.nonzerosize == 0
    }

    pub fn is_always_false(&self) -> bool {
        self.nonzerosize == -1
    }

    pub fn get_length(&self) -> i32 {
        self.offset + self.nonzerosize
    }

    fn normalize(&mut self) {
        if self.nonzerosize <= 0 {
            self.offset = 0;
            self.maskvec.clear();
            self.valvec.clear();
            return;
        }

        let mut iter = 0;
        while iter < self.maskvec.len() && self.maskvec[iter] == 0 {
            iter += 1;
            self.offset += 4;
        }

        if iter > 0 {
            self.maskvec.drain(0..iter);
            self.valvec.drain(0..iter);
        }

        if !self.maskvec.is_empty() {
            let mut suboff = 0;
            let mut tmp = self.maskvec[0];
            while tmp != 0 {
                suboff += 1;
                tmp >>= 8;
            }
            suboff = 4 - suboff;
            if suboff != 0 {
                self.offset += suboff;
                for i in 0..self.maskvec.len() - 1 {
                    let mut tmp = self.maskvec[i] << (suboff * 8);
                    tmp |= self.maskvec[i + 1] >> ((4 - suboff) * 8);
                    self.maskvec[i] = tmp;
                }
                *self.maskvec.last_mut().unwrap() <<= suboff * 8;

                for i in 0..self.valvec.len() - 1 {
                    let mut tmp = self.valvec[i] << (suboff * 8);
                    tmp |= self.valvec[i + 1] >> ((4 - suboff) * 8);
                    self.valvec[i] = tmp;
                }
                *self.valvec.last_mut().unwrap() <<= suboff * 8;
            }

            let mut last = self.maskvec.len();
            while last > 0 {
                if self.maskvec[last - 1] != 0 {
                    break;
                }
                last -= 1;
            }
            if last < self.maskvec.len() {
                self.maskvec.truncate(last);
                self.valvec.truncate(last);
            }
        }

        if self.maskvec.is_empty() {
            self.offset = 0;
            self.nonzerosize = 0;
            self.valvec.clear();
            return;
        }

        self.nonzerosize = (self.maskvec.len() as i32) * 4;
        let mut tmp = *self.maskvec.last().unwrap();
        while (tmp & 0xff) == 0 {
            self.nonzerosize -= 1;
            tmp >>= 8;
        }
    }

    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderError> {
        let el = decoder.open_element_with_id(ELEM_PAT_BLOCK)?;
        let offset = decoder.read_signed_integer_with_id(ATTRIB_OFF)? as i32;
        let nonzerosize = decoder.read_signed_integer_with_id(ATTRIB_NONZERO)? as i32;

        let mut maskvec = Vec::new();
        let mut valvec = Vec::new();

        while decoder.peek_element()? == ELEM_MASK_WORD.id {
            let subel = decoder.open_element()?;
            maskvec.push(decoder.read_unsigned_integer_with_id(ATTRIB_MASK)? as u32);
            valvec.push(decoder.read_unsigned_integer_with_id(ATTRIB_VAL)? as u32);
            decoder.close_element(subel)?;
        }
        decoder.close_element(el)?;

        Ok(Self {
            offset,
            nonzerosize,
            maskvec,
            valvec,
        })
    }

    pub fn get_mask(&self, mut startbit: i32, size: i32) -> u32 {
        startbit -= 8 * self.offset;
        let wordnum1 = (startbit / 32) as usize;
        let shift = (startbit % 32) as u32;
        let wordnum2 = ((startbit + size - 1) / 32) as usize;

        let mut res = if wordnum1 >= self.maskvec.len() {
            0
        } else {
            self.maskvec[wordnum1]
        };

        res <<= shift;
        if wordnum1 != wordnum2 {
            let tmp = if wordnum2 >= self.maskvec.len() {
                0
            } else {
                self.maskvec[wordnum2]
            };
            res |= tmp >> (32 - shift);
        }
        res >> (32 - size)
    }

    pub fn is_instruction_match(&self, walker: &ParserWalker) -> bool {
        if self.nonzerosize <= 0 {
            return self.nonzerosize == 0;
        }
        let mut off = self.offset;
        for &mask in &self.maskvec {
            let data = match walker.get_instruction_bits(off * 8, 32) {
                Ok(d) => d,
                Err(_) => return false,
            };
            // Need to handle bit order correctly, Ghidra's getInstructionBytes is 4 bytes big endian
            // Our get_instruction_bits handles bit extraction.
            // Simplified for now: assume mask is aligned
            if (mask & data) != self.valvec[((off - self.offset) / 4) as usize] {
                return false;
            }
            off += 4;
        }
        true
    }

    pub fn is_context_match(&self, walker: &ParserWalker) -> bool {
        if self.nonzerosize <= 0 {
            return self.nonzerosize == 0;
        }
        let mut off = self.offset;
        for &mask in &self.maskvec {
            let data = walker.get_context_bits(off * 8, 32);
            if (mask & data) != self.valvec[((off - self.offset) / 4) as usize] {
                return false;
            }
            off += 4;
        }
        true
    }
}
