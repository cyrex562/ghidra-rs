//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.RebaseTable`.
//!
//! A Mach-O rebase table: the REBASE-opcode state machine from dyld's
//! `MachOLayout.cpp`/`MachOAnalyzer.cpp`, run over the `dyld_info_command` rebase bytes.
//!
//! Java's `RebaseTable extends OpcodeTable`; the inherited offset lists live in an embedded
//! [`OpcodeTableData`] and are exposed through the [`OpcodeTable`] trait.
//!
//! Divergence: Java switches on `RebaseOpcode.forOpcode(b & REBASE_OPCODE_MASK)`, which is `null`
//! for the unassigned opcodes `0x90..=0xF0`, so Java throws a `NullPointerException` before ever
//! reaching its `default` (unknown-opcode) arm. This port routes those opcodes to the `default`
//! arm the Java authors wrote for exactly that purpose: the unknown opcode is recorded on a final
//! [`Rebase`] and parsing stops.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::macho::commands::dyld::opcode_table::{OpcodeTable, OpcodeTableData};
use crate::format::macho::commands::dyld::rebase_opcode::RebaseOpcode;
use crate::format::macho::commands::dyld_info_command_constants::{
    REBASE_IMMEDIATE_MASK, REBASE_OPCODE_MASK,
};
use crate::format::macho::mach_header::MachHeader;

/// One rebase entry produced by the REBASE-opcode state machine.
///
/// Port of the nested `RebaseTable.Rebase`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rebase {
    type_: i32,
    segment_offset: i64,
    segment_index: i32,
    unknown_opcode: Option<i32>,
}

impl Default for Rebase {
    fn default() -> Self {
        Rebase { type_: 0, segment_offset: 0, segment_index: -1, unknown_opcode: None }
    }
}

impl Rebase {
    /// Java `Rebase()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Java `getSegmentIndex()`.
    pub fn get_segment_index(&self) -> i32 {
        self.segment_index
    }

    /// Java `getSegmentOffset()`.
    pub fn get_segment_offset(&self) -> i64 {
        self.segment_offset
    }

    /// Java `getType()`.
    pub fn get_type(&self) -> i32 {
        self.type_
    }

    /// Java `getUnknownOpcode()`: `None` if this rebase was created from a known opcode.
    pub fn get_unknown_opcode(&self) -> Option<i32> {
        self.unknown_opcode
    }
}

impl std::fmt::Display for Rebase {
    /// Java `toString()`. (Java labels the segment index "segment" and the segment offset
    /// "index"; kept verbatim.)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "segment: 0x{:x}, index: 0x{:x}, kind: {}",
            self.segment_index, self.segment_offset, self.type_
        )
    }
}

/// A Mach-O rebase table.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.RebaseTable`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RebaseTable {
    data: OpcodeTableData,
    rebases: Vec<Rebase>,
}

impl RebaseTable {
    /// Java `RebaseTable()`: an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Java `RebaseTable(BinaryReader, MachHeader, long)`: runs the REBASE-opcode state machine
    /// over `table_size` bytes starting at `reader`'s current position.
    pub fn parse(reader: &mut BinaryReader, header: &MachHeader, table_size: i64) -> io::Result<Self> {
        Self::parse_with_pointer_size(reader, header.get_address_size(), table_size)
    }

    /// [`parse`](Self::parse) with the header's pointer size already extracted (the only thing
    /// the Java constructor reads from the `MachHeader`).
    pub fn parse_with_pointer_size(
        reader: &mut BinaryReader,
        pointer_size: i32,
        table_size: i64,
    ) -> io::Result<Self> {
        let mut table = RebaseTable::new();
        let pointer_size = pointer_size as i64;
        let orig_index = reader.get_pointer_index();
        let end = (orig_index as i64).wrapping_add(table_size);
        let mut rebase = Rebase::new();

        while (reader.get_pointer_index() as i64) < end {
            table.data.opcode_offsets.push(reader.get_pointer_index() - orig_index);
            let b = reader.read_next_byte()?;
            let immediate = (b as u32 & REBASE_IMMEDIATE_MASK) as i32;
            let opcode = RebaseOpcode::for_opcode((b as u32 & REBASE_OPCODE_MASK) as i32);

            match opcode {
                Some(RebaseOpcode::REBASE_OPCODE_DONE) => {
                    return Ok(table);
                }
                Some(RebaseOpcode::REBASE_OPCODE_SET_TYPE_IMM) => {
                    rebase.type_ = immediate;
                }
                Some(RebaseOpcode::REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    rebase.segment_index = immediate;
                    rebase.segment_offset = read_uleb_exact(reader)? as i64;
                }
                Some(RebaseOpcode::REBASE_OPCODE_ADD_ADDR_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    rebase.segment_offset =
                        rebase.segment_offset.wrapping_add(read_uleb_exact(reader)? as i64);
                }
                Some(RebaseOpcode::REBASE_OPCODE_ADD_ADDR_IMM_SCALED) => {
                    rebase.segment_offset = rebase
                        .segment_offset
                        .wrapping_add((immediate as i64).wrapping_mul(pointer_size));
                }
                Some(RebaseOpcode::REBASE_OPCODE_DO_REBASE_IMM_TIMES) => {
                    for _ in 0..immediate {
                        table.rebases.push(rebase.clone());
                        rebase.segment_offset = rebase.segment_offset.wrapping_add(pointer_size);
                    }
                }
                Some(RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let count = read_uleb_exact(reader)?;
                    for _ in 0..count {
                        table.rebases.push(rebase.clone());
                        rebase.segment_offset = rebase.segment_offset.wrapping_add(pointer_size);
                    }
                }
                Some(RebaseOpcode::REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    table.rebases.push(rebase.clone());
                    rebase.segment_offset =
                        rebase.segment_offset.wrapping_add(read_uleb_exact(reader)? as i64);
                }
                Some(RebaseOpcode::REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let count = read_uleb_exact(reader)?;
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let skip = read_uleb_exact(reader)? as i64;
                    for _ in 0..count {
                        table.rebases.push(rebase.clone());
                        rebase.segment_offset =
                            rebase.segment_offset.wrapping_add(skip + pointer_size);
                    }
                }
                None => {
                    // Java's `default` arm (see the module docs for why `None` lands here).
                    let mut unknown = rebase.clone();
                    unknown.unknown_opcode = Some((b as u32 & REBASE_OPCODE_MASK) as i32);
                    table.rebases.push(unknown);
                    return Ok(table);
                }
            }
        }
        Ok(table)
    }

    /// Java `getRebases()`.
    pub fn get_rebases(&self) -> &[Rebase] {
        &self.rebases
    }
}

/// Java `reader.readNextUnsignedVarIntExact(LEB128::unsigned)`.
fn read_uleb_exact(reader: &mut BinaryReader) -> io::Result<u32> {
    Ok(LEB128Info::unsigned(reader)?.as_u_int32()?)
}

impl OpcodeTable for RebaseTable {
    fn opcode_offsets(&self) -> &[u64] {
        self.data.opcode_offsets()
    }
    fn uleb_offsets(&self) -> &[u64] {
        self.data.uleb_offsets()
    }
    fn sleb_offsets(&self) -> &[u64] {
        self.data.sleb_offsets()
    }
    fn string_offsets(&self) -> &[u64] {
        self.data.string_offsets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: Vec<u8>, pointer_size: i32) -> RebaseTable {
        let len = bytes.len() as i64;
        let mut reader = BinaryReader::from_bytes(bytes, true);
        RebaseTable::parse_with_pointer_size(&mut reader, pointer_size, len).unwrap()
    }

    #[test]
    fn empty_table_has_no_rebases() {
        let t = RebaseTable::new();
        assert!(t.get_rebases().is_empty());
        assert!(t.opcode_offsets().is_empty());
    }

    #[test]
    fn typical_64bit_rebase_stream() {
        // A typical ld64 stream:
        //   0x11              SET_TYPE_IMM(1 = pointer)
        //   0x22 0x10         SET_SEGMENT_AND_OFFSET_ULEB(seg 2, offset 0x10)
        //   0x53              DO_REBASE_IMM_TIMES(3)
        //   0x41              ADD_ADDR_IMM_SCALED(1)
        //   0x62 0x02         DO_REBASE_ULEB_TIMES(2)
        //   0x00              DONE
        let t = parse(vec![0x11, 0x22, 0x10, 0x53, 0x41, 0x62, 0x02, 0x00, 0xFF], 8);
        let offs: Vec<i64> = t.get_rebases().iter().map(Rebase::get_segment_offset).collect();
        // 3 rebases at 0x10,0x18,0x20; then +8 skip -> 0x30; then 2 at 0x30,0x38.
        assert_eq!(offs, vec![0x10, 0x18, 0x20, 0x30, 0x38]);
        assert!(t.get_rebases().iter().all(|r| r.get_segment_index() == 2 && r.get_type() == 1));
        assert_eq!(t.opcode_offsets(), &[0, 1, 3, 4, 5, 7]);
        assert_eq!(t.uleb_offsets(), &[2, 6]);
        assert!(t.sleb_offsets().is_empty());
        assert!(t.string_offsets().is_empty());
    }

    #[test]
    fn add_addr_uleb_and_skipping_32bit() {
        //   0x21 0x00         SET_SEGMENT_AND_OFFSET_ULEB(seg 1, 0)
        //   0x30 0x80 0x01    ADD_ADDR_ULEB(0x80)
        //   0x70 0x08         DO_REBASE_ADD_ADDR_ULEB(8) -> rebase @0x80, then +8
        //   0x80 0x02 0x04    DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(count 2, skip 4)
        let t = parse(vec![0x21, 0x00, 0x30, 0x80, 0x01, 0x70, 0x08, 0x80, 0x02, 0x04], 4);
        let offs: Vec<i64> = t.get_rebases().iter().map(Rebase::get_segment_offset).collect();
        // 0x80; then 0x88; then +4+4 -> 0x90
        assert_eq!(offs, vec![0x80, 0x88, 0x90]);
        assert_eq!(t.opcode_offsets(), &[0, 2, 5, 7]);
        assert_eq!(t.uleb_offsets(), &[1, 3, 6, 8, 9]);
        // Ran out of table bytes without DONE: loop simply ends.
    }

    #[test]
    fn unknown_opcode_is_recorded_and_stops() {
        let t = parse(vec![0x21, 0x04, 0x91, 0x51], 8);
        assert_eq!(t.get_rebases().len(), 1);
        let r = &t.get_rebases()[0];
        assert_eq!(r.get_unknown_opcode(), Some(0x90));
        assert_eq!(r.get_segment_offset(), 4);
        assert_eq!(r.get_segment_index(), 1);
    }

    #[test]
    fn rebase_to_string_matches_java_format() {
        let mut r = Rebase::new();
        r.segment_index = 2;
        r.segment_offset = 0x40;
        r.type_ = 1;
        assert_eq!(r.to_string(), "segment: 0x2, index: 0x40, kind: 1");
        assert_eq!(Rebase::new().get_segment_index(), -1);
    }

    #[test]
    fn parse_starts_at_reader_position() {
        let mut reader = BinaryReader::from_bytes(vec![0xAA, 0xAA, 0x21, 0x08, 0x51, 0x00], true);
        reader.set_pointer_index(2);
        let t = RebaseTable::parse_with_pointer_size(&mut reader, 8, 4).unwrap();
        assert_eq!(t.get_rebases().len(), 1);
        assert_eq!(t.get_rebases()[0].get_segment_offset(), 8);
        assert_eq!(t.opcode_offsets(), &[0, 2, 3]);
    }
}
