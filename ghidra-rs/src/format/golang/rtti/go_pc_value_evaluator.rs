//! Port of `ghidra.app.util.bin.format.golang.rtti.GoPcValueEvaluator`.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::program::model::address::address_set::AddressSetView;
use crate::format::golang::structmapping::MarkupSession;
use crate::program::model::data::unsigned_leb128_data_type::UnsignedLeb128DataType;
use crate::program::model::listing::comment_type::CommentType;

/// Evaluates a sequence of `(value_delta, pc_delta)` leb128 pairs to calculate a value for a
/// certain PC location.
///
/// Java's constructor `GoPcValueEvaluator(GoFuncData, long)` looks up the function's
/// moduledata to get the pc quantum (`getGoBinary().getMinLC()`) and a reader over the
/// moduledata's pc value table positioned at the offset; [`new`](Self::new) takes those inputs
/// directly (the moduledata builds evaluators with it).
pub struct GoPcValueEvaluator {
    pcquantum: i32,
    func_entry: i64,
    reader: BinaryReader,
    start_position: u64,
    pctab_offset: i64,
    value: i32,
    pc: i64,
}

fn invalid(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl GoPcValueEvaluator {
    /// Creates an evaluator reading the pc value table from `reader` (positioned at
    /// `pctab_offset` within the moduledata's pctab), for the function starting at `func_entry`.
    pub fn new(pcquantum: i32, reader: BinaryReader, pctab_offset: i64, func_entry: i64) -> Self {
        let start_position = reader.get_pointer_index();
        GoPcValueEvaluator { pcquantum, func_entry, reader, start_position, pctab_offset, value: -1, pc: func_entry }
    }

    /// `getPC()`.
    pub fn get_pc(&self) -> i64 {
        self.pc
    }

    /// `reset()`: rewinds to the start of the sequence.
    pub fn reset(&mut self) {
        self.reader.set_pointer_index(self.start_position);
        self.value = -1;
        self.pc = self.func_entry;
    }

    /// Returns the largest PC value calculated when evaluating the result of the table's
    /// sequence (`getMaxPC()`).
    ///
    /// # Errors
    /// Error reading the table.
    pub fn get_max_pc(&mut self) -> io::Result<i64> {
        self.eval(i64::MAX)?;
        Ok(self.pc)
    }

    /// Returns the value encoded into the table at the specified pc, or `-1` if the sequence
    /// ended before reaching it (`eval(long)`).
    ///
    /// # Errors
    /// Error reading the table.
    pub fn eval(&mut self, target_pc: i64) -> io::Result<i32> {
        while self.pc <= target_pc {
            if !self.step()? {
                return Ok(-1);
            }
        }
        Ok(self.value)
    }

    /// `evalNext()`.
    ///
    /// # Errors
    /// Error reading the table.
    pub fn eval_next(&mut self) -> io::Result<i32> {
        self.eval(self.pc)
    }

    /// Returns the values of each pc section up to `target_pc` (`evalAll(long)`).
    ///
    /// # Errors
    /// Error reading the table.
    pub fn eval_all(&mut self, target_pc: i64) -> io::Result<Vec<i32>> {
        let mut result = Vec::new();
        while self.pc <= target_pc {
            if !self.step()? {
                return Ok(result);
            }
            result.push(self.value);
        }
        Ok(result)
    }

    fn read_uvarint(&mut self) -> io::Result<u32> {
        self.reader
            .read_next_unsigned_var_int_exact(|r| LEB128Info::unsigned(r).map(|i| i.as_long()))
            .map_err(invalid)
    }

    fn step(&mut self) -> io::Result<bool> {
        let uvdelta = self.read_uvarint()? as i32;
        if uvdelta == 0 && self.pc != self.func_entry {
            // a delta of 0 is only valid on the first element
            return Ok(false);
        }
        self.value = self.value.wrapping_add(zigzag_decode(uvdelta));

        let pcdelta = self.read_uvarint()? as i64;
        self.pc += pcdelta * self.pcquantum as i64;
        Ok(true)
    }

    /// Marks up the table: labels its start, applies a uleb128 to each delta and annotates the
    /// running value / pc in comments (`markup(MarkupSession)`).
    ///
    /// # Errors
    /// Error reading the table or marking up the program.
    pub fn markup(&mut self, session: &mut MarkupSession<'_>) -> io::Result<()> {
        let start_addr = session.get_mapping_context().get_data_address(self.start_position as i64);
        if session.get_markedup_addresses().contains(&start_addr) {
            return Ok(());
        }
        session.label_address(&start_addr, &format!("pctab[0x{:x}]", self.pctab_offset))?;
        let mut count = 0;
        while self.markup_step(session)? {
            count += 1;
        }
        let size = self.reader.get_pointer_index() - self.start_position;
        let msg = format!("stepcount={count},size={size}");
        session.append_comment_at(&start_addr, CommentType::Pre, Some(""), &msg, ",")
    }

    fn markup_step(&mut self, session: &mut MarkupSession<'_>) -> io::Result<bool> {
        let leb_dt = UnsignedLeb128DataType::data_type();
        let uvdelta_info = LEB128Info::unsigned(&mut self.reader)?;
        let uvdelta_addr = session.get_mapping_context().get_data_address(uvdelta_info.get_offset() as i64);
        if session.get_markedup_addresses().contains(&uvdelta_addr) {
            return Ok(false);
        }
        session.markup_address_with_length(&uvdelta_addr, leb_dt.as_ref(), uvdelta_info.get_length())?;

        let uvdelta = uvdelta_info.as_u_int32().map_err(invalid)? as i32;
        if uvdelta == 0 && self.pc != self.func_entry {
            // a delta of 0 is only valid on the first element
            session.append_comment_at(&uvdelta_addr, CommentType::Eol, Some(""), "end", ",")?;
            return Ok(false);
        }

        let vdelta = zigzag_decode(uvdelta);
        self.value = self.value.wrapping_add(vdelta);
        let msg = format!("value+{vdelta}=0x{:x}", self.value);
        session.append_comment_at(&uvdelta_addr, CommentType::Eol, Some(""), &msg, ",")?;

        let pcdelta_info = LEB128Info::unsigned(&mut self.reader)?;
        let pcdelta_addr = session.get_mapping_context().get_data_address(pcdelta_info.get_offset() as i64);
        session.markup_address_with_length(&pcdelta_addr, leb_dt.as_ref(), pcdelta_info.get_length())?;

        let pcdelta = pcdelta_info.as_u_int32().map_err(invalid)? as i64;
        self.pc += pcdelta * self.pcquantum as i64;
        let msg = format!("pc+0x{:x}=+0x{:08x}", pcdelta * self.pcquantum as i64, self.pc - self.func_entry);
        session.append_comment_at(&pcdelta_addr, CommentType::Eol, Some(""), &msg, ",")?;

        Ok(true)
    }
}

/// Java's `-(uvdelta & 1) ^ (uvdelta >> 1)`: zig-zag decoding.
fn zigzag_decode(uvdelta: i32) -> i32 {
    -(uvdelta & 1) ^ (uvdelta >> 1)
}

/// Encodes a `(value, pc)` script as a pctab sequence (zig-zag value deltas, pc deltas in
/// `pcquantum` units, ending with a 0 value delta), as the Go linker writes it. Test helper.
#[cfg(test)]
pub(crate) fn encode_pc_value_table(func_entry: i64, pcquantum: i64, script: &[(i32, i64)]) -> Vec<u8> {
    fn uleb(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
    }
    let mut out = Vec::new();
    let (mut value, mut pc) = (-1i32, func_entry);
    for &(v, p) in script {
        let delta = v - value;
        uleb(&mut out, ((delta << 1) ^ (delta >> 31)) as u32 as u64);
        uleb(&mut out, ((p - pc) / pcquantum) as u64);
        value = v;
        pc = p;
    }
    out.push(0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluator(bytes: Vec<u8>, func_entry: i64, pcquantum: i32) -> GoPcValueEvaluator {
        GoPcValueEvaluator::new(pcquantum, BinaryReader::from_bytes(bytes, true), 0, func_entry)
    }

    #[test]
    fn decodes_go_pcvalue_sequence() {
        // Go's runtime/symtab.go example: value deltas are zig-zag, pc deltas scaled by minLC.
        // (-1 -> 0 at pc+0x10), (0 -> 3 at +0x14), (3 -> 1 at +0x20), end
        let bytes = vec![0x02, 0x10, 0x06, 0x04, 0x03, 0x0c, 0x00];
        let mut e = evaluator(bytes, 0x1000, 1);
        assert_eq!(e.eval(0x1000).unwrap(), 0);
        assert_eq!(e.get_pc(), 0x1010);
        assert_eq!(e.eval(0x1013).unwrap(), 3);
        assert_eq!(e.eval(0x101f).unwrap(), 1);
        assert_eq!(e.eval(0x1020).unwrap(), -1); // past the end
        e.reset();
        assert_eq!(e.eval_all(i64::MAX).unwrap(), vec![0, 3, 1]);
        e.reset();
        assert_eq!(e.get_max_pc().unwrap(), 0x1020);
        e.reset();
        assert_eq!(e.eval_next().unwrap(), 0);
        assert_eq!(e.eval_next().unwrap(), 3);
    }

    #[test]
    fn pc_quantum_scales_deltas() {
        let bytes = encode_pc_value_table(0x400, 4, &[(7, 0x408), (5, 0x410)]);
        let mut e = evaluator(bytes, 0x400, 4);
        assert_eq!(e.eval_all(i64::MAX).unwrap(), vec![7, 5]);
        assert_eq!(e.get_pc(), 0x410);
        assert_eq!(zigzag_decode(3), -2);
        assert_eq!(zigzag_decode(4), 2);
    }

    #[test]
    fn truncated_table_is_an_error() {
        let mut e = evaluator(vec![0x02], 0x1000, 1);
        assert!(e.eval(0x2000).is_err());
    }
}
