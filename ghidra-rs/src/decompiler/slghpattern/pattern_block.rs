//! Models `ghidra.pcodeCPort.slghpattern.PatternBlock`.

use std::fmt;
use std::io;

use crate::decompiler::utils::utils::{unsigned_divide, unsigned_int, unsigned_modulo};
use crate::program::model::pcode::{
    Encoder, ATTRIB_MASK, ATTRIB_NONZERO, ATTRIB_OFF, ATTRIB_VAL, ELEM_MASK_WORD, ELEM_PAT_BLOCK,
};

/// Logical (unsigned) right shift on an `i32`, matching Java's `>>>` operator.
fn ushr(val: i32, amount: i32) -> i32 {
    ((val as u32) >> (amount as u32)) as i32
}

/// A mask/value pattern confined to a byte-aligned run of words.
///
/// Models `ghidra.pcodeCPort.slghpattern.PatternBlock`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternBlock {
    /// Offset (in bytes) to the first non-zero byte of the mask.
    offset: i32,
    /// Last byte (+1) containing a non-zero mask bit.
    nonzerosize: i32,
    /// Mask words.
    maskvec: Vec<i32>,
    /// Value words.
    valvec: Vec<i32>,
}

impl PatternBlock {
    /// Defines a mask and value pattern, confined to one word.
    pub fn new(off: i32, msk: i32, val: i32) -> Self {
        let mut block = Self {
            offset: off,
            nonzerosize: 4, // Assume all non-zero bytes before normalization
            maskvec: vec![msk],
            valvec: vec![val],
        };
        block.normalize();
        block
    }

    /// Constructs a pattern block that always matches.
    pub fn always_true() -> Self {
        Self {
            offset: 0,
            nonzerosize: 0,
            maskvec: Vec::new(),
            valvec: Vec::new(),
        }
    }

    /// Constructs a pattern block that never matches.
    pub fn always_false() -> Self {
        Self {
            offset: 0,
            nonzerosize: -1,
            maskvec: Vec::new(),
            valvec: Vec::new(),
        }
    }

    /// Constructs a pattern block by ANDing two others together.
    pub fn from_intersection(a: &PatternBlock, b: &PatternBlock) -> Self {
        a.intersect(b)
    }

    /// ANDs a list of blocks together to construct a new block.
    pub fn from_and_list(list: &[PatternBlock]) -> Self {
        if list.is_empty() {
            // If not ANDing anything, make the constructed block always true.
            return Self::always_true();
        }
        let mut res = list[0].clone();
        for next in &list[1..] {
            res = res.intersect(next);
        }
        res
    }

    /// Shifts the pattern by `sa` bytes.
    pub fn shift(&mut self, sa: i32) {
        self.offset += sa;
        self.normalize();
    }

    /// Gets the total length, in bytes, spanned by this pattern.
    pub fn get_length(&self) -> i32 {
        self.offset + self.nonzerosize
    }

    /// Checks whether this pattern always matches.
    pub fn is_always_true(&self) -> bool {
        self.nonzerosize == 0
    }

    /// Checks whether this pattern never matches.
    pub fn is_always_false(&self) -> bool {
        self.nonzerosize == -1
    }

    fn normalize(&mut self) {
        if self.nonzerosize <= 0 {
            // Check if alwaystrue or alwaysfalse, in which case we don't need mask and value
            self.offset = 0;
            self.maskvec.clear();
            self.valvec.clear();
            return;
        }

        // Cut zeros from beginning of mask
        let mut lead = 0usize;
        while lead < self.maskvec.len() && self.maskvec[lead] == 0 {
            lead += 1;
            self.offset += 4; // sizeof Integer
        }
        if lead > 0 {
            self.maskvec.drain(0..lead);
            self.valvec.drain(0..lead);
        }

        if !self.maskvec.is_empty() {
            // Cut off unaligned zeros from beginning of mask
            let mut suboff = 0;
            let mut tmp = self.maskvec[0];
            while tmp != 0 {
                suboff += 1;
                tmp = ushr(tmp, 8);
            }
            suboff = 4 - suboff; // 4 is sizeof int
            if suboff != 0 {
                self.offset += suboff; // Slide up maskvec by suboff bytes
                let len = self.maskvec.len();
                for i in 0..len - 1 {
                    let mut tmp = self.maskvec[i] << (suboff * 8);
                    tmp |= ushr(self.maskvec[i + 1], (4 - suboff) * 8); // 4 is sizeof int
                    self.maskvec[i] = tmp;
                }
                *self.maskvec.last_mut().unwrap() <<= suboff * 8;

                // Slide up valvec by suboff bytes
                let vlen = self.valvec.len();
                for i in 0..vlen - 1 {
                    let mut tmp = self.valvec[i] << (suboff * 8);
                    tmp |= ushr(self.valvec[i + 1], (4 - suboff) * 8); // 4 is sizeof int
                    self.valvec[i] = tmp;
                }
                *self.valvec.last_mut().unwrap() <<= suboff * 8;
            }

            // Cut zeros from end of mask: find the last non-zero word and truncate after it.
            let mut trail = self.maskvec.len();
            while trail > 0 {
                if self.maskvec[trail - 1] != 0 {
                    break;
                }
                trail -= 1;
            }
            if trail < self.maskvec.len() {
                self.maskvec.truncate(trail);
                self.valvec.truncate(trail);
            }
        }

        if self.maskvec.is_empty() {
            self.offset = 0;
            self.nonzerosize = 0; // Always true
            return;
        }
        self.nonzerosize = (self.maskvec.len() as i32) * 4; // 4 is sizeof int
        let mut tmp = *self.maskvec.last().unwrap(); // tmp must be nonzero
        while (tmp & 0xff) == 0 {
            self.nonzerosize -= 1;
            tmp = ushr(tmp, 8);
        }
    }

    /// The resulting pattern has a 1-bit in the mask only if the two pieces have a 1-bit and the
    /// values agree.
    pub fn common_sub_pattern(&self, b: &PatternBlock) -> PatternBlock {
        let mut res = Self::always_true();
        let maxlength = self.get_length().max(b.get_length());

        res.offset = 0;
        let mut offset1 = 0;
        while offset1 < maxlength {
            let mask1 = self.get_mask(offset1 * 8, 4 * 8); // 4 is sizeof int
            let val1 = self.get_value(offset1 * 8, 4 * 8);
            let mask2 = b.get_mask(offset1 * 8, 4 * 8);
            let val2 = b.get_value(offset1 * 8, 4 * 8);
            let resmask = mask1 & mask2 & !(val1 ^ val2);
            let resval = val1 & val2 & resmask;
            res.maskvec.push(resmask);
            res.valvec.push(resval);
            offset1 += 4; // 4 is sizeof int
        }
        res.nonzerosize = maxlength;
        res.normalize();
        res
    }

    /// Constructs the intersecting pattern.
    pub fn intersect(&self, b: &PatternBlock) -> PatternBlock {
        if self.is_always_false() || b.is_always_false() {
            return Self::always_false();
        }
        let mut res = Self::always_true();
        let maxlength = self.get_length().max(b.get_length());

        res.offset = 0;
        let mut offset1 = 0;
        while offset1 < maxlength {
            let mask1 = self.get_mask(offset1 * 8, 4 * 8);
            let val1 = self.get_value(offset1 * 8, 4 * 8);
            let mask2 = b.get_mask(offset1 * 8, 4 * 8);
            let val2 = b.get_value(offset1 * 8, 4 * 8);
            let commonmask = mask1 & mask2; // Bits in mask shared by both patterns
            if (commonmask & val1) != (commonmask & val2) {
                res.nonzerosize = -1; // Impossible pattern
                res.normalize();
                return res;
            }
            let resmask = mask1 | mask2;
            let resval = (mask1 & val1) | (mask2 & val2);
            res.maskvec.push(resmask);
            res.valvec.push(resval);
            offset1 += 4;
        }
        res.nonzerosize = maxlength;
        res.normalize();
        res
    }

    /// Does every masked bit in `self` match the corresponding masked bit in `op2`.
    pub fn specializes(&self, op2: &PatternBlock) -> bool {
        let length = 8 * op2.get_length();
        let mut sbit = 0;
        while sbit < length {
            let mut tmplength = length - sbit;
            if tmplength > 8 * 4 {
                tmplength = 8 * 4;
            }
            let mask1 = self.get_mask(sbit, tmplength);
            let value1 = self.get_value(sbit, tmplength);
            let mask2 = op2.get_mask(sbit, tmplength);
            let value2 = op2.get_value(sbit, tmplength);
            if (mask1 & mask2) != mask2 {
                return false;
            }
            if (value1 & mask2) != (value2 & mask2) {
                return false;
            }
            sbit += tmplength;
        }
        true
    }

    /// Do the mask and value match exactly.
    pub fn identical(&self, op2: &PatternBlock) -> bool {
        let mut length = 8 * op2.get_length();
        let tmplength = 8 * self.get_length();
        if tmplength > length {
            length = tmplength; // Maximum of two lengths
        }

        let mut sbit = 0;
        while sbit < length {
            let mut tmplength = length - sbit;
            if tmplength > 8 * 4 {
                tmplength = 8 * 4;
            }
            let mask1 = self.get_mask(sbit, tmplength);
            let value1 = self.get_value(sbit, tmplength);
            let mask2 = op2.get_mask(sbit, tmplength);
            let value2 = op2.get_value(sbit, tmplength);
            if mask1 != mask2 {
                return false;
            }
            if (mask1 & value1) != (mask2 & value2) {
                return false;
            }
            sbit += tmplength;
        }
        true
    }

    /// Gets `size` bits of the mask starting at `startbit`.
    pub fn get_mask(&self, startbit: i32, size: i32) -> i32 {
        let startbit = startbit - 8 * self.offset;
        // Note the division and remainder here is unsigned. Then it is recast to signed.
        // If startbit is negative, then wordnum1 is either negative or very big,
        // if (unsigned size is same as sizeof int)
        // In either case, shift should come out between 0 and 8*sizeof(uintm)-1
        let wordnum1 = unsigned_divide(startbit, 8 * 4); // 4 is sizeof int
        let shift = unsigned_modulo(startbit, 8 * 4);
        let wordnum2 = unsigned_divide(startbit + size - 1, 8 * 4);

        let mut res = if wordnum1 < 0 || wordnum1 as usize >= self.maskvec.len() {
            0
        } else {
            self.maskvec[wordnum1 as usize]
        };

        res <<= shift;
        if wordnum1 != wordnum2 {
            let tmp = if wordnum2 < 0 || wordnum2 as usize >= self.maskvec.len() {
                0
            } else {
                self.maskvec[wordnum2 as usize]
            };
            res |= ushr(tmp, 8 * 4 - shift);
        }
        ushr(res, 8 * 4 - size)
    }

    /// Gets `size` bits of the value starting at `startbit`.
    pub fn get_value(&self, startbit: i32, size: i32) -> i32 {
        let startbit = startbit - 8 * self.offset;
        let wordnum1 = unsigned_divide(startbit, 8 * 4);
        let shift = unsigned_modulo(startbit, 8 * 4);
        let wordnum2 = unsigned_divide(startbit + size - 1, 8 * 4);

        let mut res = if wordnum1 < 0 || wordnum1 as usize >= self.valvec.len() {
            0
        } else {
            self.valvec[wordnum1 as usize]
        };

        res <<= shift;
        if wordnum1 != wordnum2 {
            let tmp = if wordnum2 < 0 || wordnum2 as usize >= self.valvec.len() {
                0
            } else {
                self.valvec[wordnum2 as usize]
            };
            res |= ushr(tmp, 8 * 4 - shift);
        }
        ushr(res, 8 * 4 - size)
    }

    /// Encodes this pattern block to the given encoder.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_PAT_BLOCK)?;
        encoder.write_signed_integer(ATTRIB_OFF, self.offset as i64)?;
        encoder.write_signed_integer(ATTRIB_NONZERO, self.nonzerosize as i64)?;
        for i in 0..self.maskvec.len() {
            encoder.open_element(ELEM_MASK_WORD)?;
            encoder.write_unsigned_integer(ATTRIB_MASK, unsigned_int(self.maskvec[i]) as u64)?;
            encoder.write_unsigned_integer(ATTRIB_VAL, unsigned_int(self.valvec[i]) as u64)?;
            encoder.close_element(ELEM_MASK_WORD)?;
        }
        encoder.close_element(ELEM_PAT_BLOCK)?;
        Ok(())
    }
}

impl fmt::Display for PatternBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        for _ in 0..self.offset {
            s.push_str("........ ");
        }
        let mut pos = -1;
        'outer: for (i, (&m0, &v0)) in self.maskvec.iter().zip(self.valvec.iter()).enumerate() {
            let mut m = m0;
            let mut v = v0;
            for j in 0..32 {
                if j % 8 == 0 {
                    pos += 1;
                    if pos >= self.nonzerosize {
                        break 'outer;
                    }
                    if i != 0 || j != 0 {
                        s.push(' ');
                    }
                }
                if m < 0 {
                    if v < 0 {
                        s.push('1');
                    } else {
                        s.push('0');
                    }
                } else {
                    s.push('.');
                }
                m <<= 1;
                v <<= 1;
            }
        }
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_true_matches_everything_and_has_zero_length() {
        let block = PatternBlock::always_true();
        assert!(block.is_always_true());
        assert!(!block.is_always_false());
        assert_eq!(block.get_length(), 0);
    }

    #[test]
    fn always_false_never_matches() {
        let block = PatternBlock::always_false();
        assert!(block.is_always_false());
        assert!(!block.is_always_true());
    }

    #[test]
    fn new_normalizes_leading_and_trailing_zero_bytes() {
        // Mask/value confined to the second byte from the top: 0x00ff0000 / 0x00ab0000.
        let block = PatternBlock::new(0, 0x00ff_0000u32 as i32, 0x00ab_0000u32 as i32);
        // Leading zero byte trimmed into offset, trailing zero bytes trimmed from nonzerosize.
        assert_eq!(block.offset, 1);
        assert_eq!(block.get_length(), 2);
    }

    #[test]
    fn shift_adjusts_offset_and_length() {
        let mut block = PatternBlock::new(0, 0xff00_0000u32 as i32, 0x1200_0000u32 as i32);
        let before = block.get_length();
        block.shift(4);
        assert_eq!(block.get_length(), before + 4);
    }

    #[test]
    fn get_mask_and_get_value_round_trip() {
        let block = PatternBlock::new(0, 0xffff_0000u32 as i32, 0x1234_0000u32 as i32);
        assert_eq!(block.get_mask(0, 16) as u32, 0xffff);
        assert_eq!(block.get_value(0, 16) as u32, 0x1234);
        assert_eq!(block.get_mask(16, 16), 0);
    }

    #[test]
    fn intersect_combines_disjoint_masks() {
        let a = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = PatternBlock::new(0, 0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        let combined = a.intersect(&b);
        assert!(!combined.is_always_false());
        assert_eq!(combined.get_value(0, 8) as u32, 0xaa);
        assert_eq!(combined.get_value(8, 8) as u32, 0xbb);
    }

    #[test]
    fn intersect_conflicting_values_is_always_false() {
        let a = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xbb00_0000u32 as i32);
        let combined = a.intersect(&b);
        assert!(combined.is_always_false());
    }

    #[test]
    fn from_intersection_matches_instance_intersect() {
        let a = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = PatternBlock::new(0, 0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        assert_eq!(PatternBlock::from_intersection(&a, &b), a.intersect(&b));
    }

    #[test]
    fn from_and_list_empty_is_always_true() {
        let block = PatternBlock::from_and_list(&[]);
        assert!(block.is_always_true());
    }

    #[test]
    fn from_and_list_ands_all_blocks() {
        let a = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = PatternBlock::new(0, 0x00ff_0000u32 as i32, 0x00bb_0000u32 as i32);
        let c = PatternBlock::new(0, 0x0000_ff00u32 as i32, 0x0000_cc00u32 as i32);
        let block = PatternBlock::from_and_list(&[a, b, c]);
        assert_eq!(block.get_value(0, 8) as u32, 0xaa);
        assert_eq!(block.get_value(8, 8) as u32, 0xbb);
        assert_eq!(block.get_value(16, 8) as u32, 0xcc);
    }

    #[test]
    fn identical_blocks_are_identical() {
        let a = PatternBlock::new(0, 0xffff_0000u32 as i32, 0x1234_0000u32 as i32);
        let b = PatternBlock::new(0, 0xffff_0000u32 as i32, 0x1234_0000u32 as i32);
        assert!(a.identical(&b));
        assert!(a.specializes(&b));
    }

    #[test]
    fn specializes_true_when_more_specific() {
        // `general` only constrains the top byte; `specific` further constrains the next byte too.
        let general = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let specific = PatternBlock::new(0, 0xffff_0000u32 as i32, 0xaa12_0000u32 as i32);
        assert!(specific.specializes(&general));
        assert!(!general.specializes(&specific));
    }

    #[test]
    fn common_sub_pattern_keeps_only_agreeing_bits() {
        let a = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xaa00_0000u32 as i32);
        let b = PatternBlock::new(0, 0xff00_0000u32 as i32, 0xab00_0000u32 as i32);
        let common = a.common_sub_pattern(&b);
        // 0xaa = 1010_1010, 0xab = 1010_1011: bits agree everywhere except the low bit.
        assert_eq!(common.get_mask(0, 8) as u32, 0xfe);
        assert_eq!(common.get_value(0, 8) as u32, 0xaa & 0xfe);
    }

    #[test]
    fn clone_is_a_deep_copy() {
        let original = PatternBlock::new(0, 0xffff_0000u32 as i32, 0x1234_0000u32 as i32);
        let copy = original.clone();
        assert_eq!(original, copy);
    }

    #[derive(Default)]
    struct RecordingEncoder {
        writes: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("open:{}", elem_id.name));
            Ok(())
        }

        fn close_element(
            &mut self,
            elem_id: crate::program::model::pcode::ids::ElementId,
        ) -> io::Result<()> {
            self.writes.push(format!("close:{}", elem_id.name));
            Ok(())
        }

        fn write_bool(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: bool,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: i64,
        ) -> io::Result<()> {
            self.writes.push(format!("int:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_unsigned_integer(
            &mut self,
            attrib_id: crate::program::model::pcode::ids::AttributeId,
            val: u64,
        ) -> io::Result<()> {
            self.writes
                .push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_string_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _val: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _spc: &crate::program::model::address::AddressSpace,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_space_indexed(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _index: i32,
            _name: &str,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }

        fn write_opcode_ordinal(
            &mut self,
            _attrib_id: crate::program::model::pcode::ids::AttributeId,
            _opcode: i32,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn encode_writes_offset_nonzerosize_and_mask_words() {
        let block = PatternBlock::new(0, 0xffff_0000u32 as i32, 0x1234_0000u32 as i32);
        let mut encoder = RecordingEncoder::default();
        block.encode(&mut encoder).unwrap();

        assert_eq!(encoder.writes[0], "open:pat_block");
        assert!(encoder.writes.contains(&"int:off=0".to_string()));
        assert!(encoder
            .writes
            .contains(&format!("int:nonzero={}", block.nonzerosize)));
        assert!(encoder.writes.contains(&"open:mask_word".to_string()));
        assert_eq!(encoder.writes.last().unwrap(), "close:pat_block");
    }

    #[test]
    fn display_marks_known_bits_and_dots_for_unknown() {
        let block = PatternBlock::new(0, 0xf000_0000u32 as i32, 0x9000_0000u32 as i32);
        let text = format!("{}", block);
        // 0xf0 mask means the top nibble is known; 0x9 = 1001.
        assert!(text.starts_with("1001...."));
    }
}
