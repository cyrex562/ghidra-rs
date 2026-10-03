//! Port of `ghidra.app.util.bin.format.macho.commands.dyld.BindingTable`.
//!
//! A Mach-O binding table: the BIND-opcode state machine from dyld's
//! `MachOLayout.cpp`/`MachOAnalyzer.cpp`, run over a `dyld_info_command` bind, weak-bind or
//! lazy-bind byte range.
//!
//! Java's `BindingTable extends OpcodeTable`; the inherited offset lists live in an embedded
//! [`OpcodeTableData`] and are exposed through the [`OpcodeTable`] trait.
//!
//! Divergences, both on inputs where Java throws a `NullPointerException`:
//! * `BindOpcode.forOpcode(b & BIND_OPCODE_MASK)` is `null` for the unassigned opcodes
//!   `0xE0`/`0xF0`; this port routes them to Java's `default` (unknown-opcode) arm, which records
//!   the opcode on a final [`Binding`] and stops.
//! * `BIND_SUBOPCODE_THREADED_APPLY` before any `..._SET_BIND_ORDINAL_TABLE_SIZE_ULEB` (Java's
//!   `threadedBindings` still `null`) is reported as an `InvalidData` I/O error.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::leb128_info::LEB128Info;
use crate::format::macho::commands::dyld::bind_opcode::BindOpcode;
use crate::format::macho::commands::dyld::opcode_table::{OpcodeTable, OpcodeTableData};
use crate::format::macho::commands::dyld_info_command_constants::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_MASK, BIND_SUBOPCODE_THREADED_APPLY,
    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB, BIND_SYMBOL_FLAGS_WEAK_IMPORT,
};
use crate::format::macho::mach_header::MachHeader;

/// One binding produced by the BIND-opcode state machine.
///
/// Port of the nested `BindingTable.Binding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    symbol_name: Option<String>,
    type_: i32,
    library_ordinal: i32,
    segment_offset: i64,
    segment_index: i32,
    addend: i64,
    weak: bool,
    unknown_opcode: Option<i32>,
}

impl Default for Binding {
    fn default() -> Self {
        Binding {
            symbol_name: None,
            type_: 0,
            library_ordinal: 0,
            segment_offset: 0,
            segment_index: -1,
            addend: 0,
            weak: false,
            unknown_opcode: None,
        }
    }
}

impl Binding {
    /// Java `Binding()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a binding with the fields chained-fixup and test code construct directly (no
    /// Java counterpart; Java code populates the private fields from inside the state machine).
    pub fn with_symbol(symbol_name: Option<String>, library_ordinal: i32, weak: bool) -> Self {
        Binding { symbol_name, library_ordinal, weak, ..Self::default() }
    }

    /// Java `getSymbolName()`. `None` stands in for Java's `null` (no
    /// `SET_SYMBOL_TRAILING_FLAGS_IMM` seen yet).
    pub fn get_symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }

    /// Java `getType()`.
    pub fn get_type(&self) -> i32 {
        self.type_
    }

    /// Java `getLibraryOrdinal()`.
    pub fn get_library_ordinal(&self) -> i32 {
        self.library_ordinal
    }

    /// Java `getSegmentOffset()`.
    pub fn get_segment_offset(&self) -> i64 {
        self.segment_offset
    }

    /// Java `getSegmentIndex()`.
    pub fn get_segment_index(&self) -> i32 {
        self.segment_index
    }

    /// Java `getAddend()`.
    pub fn get_addend(&self) -> i64 {
        self.addend
    }

    /// Java `isWeak()`.
    pub fn is_weak(&self) -> bool {
        self.weak
    }

    /// Java `getUnknownOpcode()`: `None` if this binding was created from a known opcode.
    pub fn get_unknown_opcode(&self) -> Option<i32> {
        self.unknown_opcode
    }
}

/// A Mach-O binding table.
///
/// Port of `ghidra.app.util.bin.format.macho.commands.dyld.BindingTable`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BindingTable {
    data: OpcodeTableData,
    bindings: Vec<Binding>,
    threaded_bindings: Option<Vec<Binding>>,
}

impl BindingTable {
    /// Java `BindingTable()`: an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Java `BindingTable(BinaryReader, MachHeader, long, boolean)`: runs the BIND-opcode state
    /// machine over `table_size` bytes starting at `reader`'s current position. `lazy` makes
    /// `BIND_OPCODE_DONE` a separator rather than a terminator.
    pub fn parse(
        reader: &mut BinaryReader,
        header: &MachHeader,
        table_size: i64,
        lazy: bool,
    ) -> io::Result<Self> {
        Self::parse_with_pointer_size(reader, header.get_address_size(), table_size, lazy)
    }

    /// [`parse`](Self::parse) with the header's pointer size already extracted (the only thing
    /// the Java constructor reads from the `MachHeader`).
    pub fn parse_with_pointer_size(
        reader: &mut BinaryReader,
        pointer_size: i32,
        table_size: i64,
        lazy: bool,
    ) -> io::Result<Self> {
        let mut table = BindingTable::new();
        let pointer_size = pointer_size as i64;
        let orig_index = reader.get_pointer_index();
        let end = (orig_index as i64).wrapping_add(table_size);
        let mut binding = Binding::new();

        while (reader.get_pointer_index() as i64) < end {
            table.data.opcode_offsets.push(reader.get_pointer_index() - orig_index);
            let b = reader.read_next_byte()?;
            let opcode = BindOpcode::for_opcode((b as u32 & BIND_OPCODE_MASK) as i32);
            let immediate = b as u32 & BIND_IMMEDIATE_MASK;

            match opcode {
                Some(BindOpcode::BIND_OPCODE_DONE) => {
                    if !lazy {
                        return Ok(table);
                    }
                }
                Some(BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_IMM) => {
                    binding.library_ordinal = immediate as i32;
                }
                Some(BindOpcode::BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    binding.library_ordinal = LEB128Info::unsigned(reader)?.as_u_int32()? as i32;
                }
                Some(BindOpcode::BIND_OPCODE_SET_DYLIB_SPECIAL_IMM) => {
                    // The special ordinals are negative numbers.
                    binding.library_ordinal = if immediate == 0 {
                        0
                    } else {
                        ((BIND_OPCODE_MASK | immediate) as u8) as i8 as i32
                    };
                }
                Some(BindOpcode::BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) => {
                    table.data.string_offsets.push(reader.get_pointer_index() - orig_index);
                    binding.symbol_name = Some(reader.read_next_ascii_string()?);
                    binding.weak = (immediate & BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
                }
                Some(BindOpcode::BIND_OPCODE_SET_TYPE_IMM) => {
                    binding.type_ = immediate as i32;
                }
                Some(BindOpcode::BIND_OPCODE_SET_ADDEND_SLEB) => {
                    table.data.sleb_offsets.push(reader.get_pointer_index() - orig_index);
                    binding.addend = LEB128Info::signed(reader)?.as_long();
                }
                Some(BindOpcode::BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    binding.segment_offset = LEB128Info::unsigned(reader)?.as_long();
                    binding.segment_index = immediate as i32;
                }
                Some(BindOpcode::BIND_OPCODE_ADD_ADDR_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    binding.segment_offset = binding
                        .segment_offset
                        .wrapping_add(LEB128Info::unsigned(reader)?.as_long());
                }
                Some(BindOpcode::BIND_OPCODE_DO_BIND) => {
                    table.bindings.push(binding.clone());
                    if table.threaded_bindings.is_none() {
                        binding.segment_offset = binding.segment_offset.wrapping_add(pointer_size);
                    }
                }
                Some(BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB) => {
                    table.bindings.push(binding.clone());
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let delta = LEB128Info::unsigned(reader)?.as_long();
                    binding.segment_offset =
                        binding.segment_offset.wrapping_add(delta.wrapping_add(pointer_size));
                }
                Some(BindOpcode::BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED) => {
                    table.bindings.push(binding.clone());
                    binding.segment_offset = binding
                        .segment_offset
                        .wrapping_add((immediate as i64) * pointer_size + pointer_size);
                }
                Some(BindOpcode::BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB) => {
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let count = LEB128Info::unsigned(reader)?.as_long();
                    table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                    let skip = LEB128Info::unsigned(reader)?.as_long();
                    // Java: `for (int i = 0; i < count; ++i)` with a long `count`.
                    let mut i: i32 = 0;
                    while (i as i64) < count {
                        table.bindings.push(binding.clone());
                        binding.segment_offset =
                            binding.segment_offset.wrapping_add(skip.wrapping_add(pointer_size));
                        i = i.wrapping_add(1);
                    }
                }
                Some(BindOpcode::BIND_OPCODE_THREADED) => match immediate {
                    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB => {
                        table.data.uleb_offsets.push(reader.get_pointer_index() - orig_index);
                        let num_threaded = LEB128Info::unsigned(reader)?.as_int32()?;
                        table.threaded_bindings =
                            Some(Vec::with_capacity(num_threaded.clamp(0, 0x10000) as usize));
                    }
                    BIND_SUBOPCODE_THREADED_APPLY => match table.threaded_bindings.as_mut() {
                        Some(threaded) => threaded.push(binding.clone()),
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "BIND_SUBOPCODE_THREADED_APPLY before the threaded bind ordinal table size was set",
                            ));
                        }
                    },
                    _ => {
                        let mut unknown = binding.clone();
                        unknown.unknown_opcode = Some(b as i32);
                        table.bindings.push(unknown);
                        return Ok(table);
                    }
                },
                None => {
                    // Java's `default` arm (see the module docs for why `None` lands here).
                    let mut unknown = binding.clone();
                    unknown.unknown_opcode = Some((b as u32 & BIND_OPCODE_MASK) as i32);
                    table.bindings.push(unknown);
                    return Ok(table);
                }
            }
        }
        Ok(table)
    }

    /// Java `getBindings()`.
    pub fn get_bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Java `getThreadedBindings()`: `None` (Java `null`) unless the table contained a
    /// `BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB`.
    pub fn get_threaded_bindings(&self) -> Option<&[Binding]> {
        self.threaded_bindings.as_deref()
    }
}

impl OpcodeTable for BindingTable {
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

    fn parse(bytes: Vec<u8>, pointer_size: i32, lazy: bool) -> io::Result<BindingTable> {
        let len = bytes.len() as i64;
        let mut reader = BinaryReader::from_bytes(bytes, true);
        BindingTable::parse_with_pointer_size(&mut reader, pointer_size, len, lazy)
    }

    #[test]
    fn typical_64bit_bind_stream() {
        let mut v = vec![
            0x11, // SET_DYLIB_ORDINAL_IMM(1)
            0x40, // SET_SYMBOL_TRAILING_FLAGS_IMM(0) "_printf"
        ];
        v.extend_from_slice(b"_printf\0");
        v.extend_from_slice(&[
            0x51, // SET_TYPE_IMM(1)
            0x72, 0x18, // SET_SEGMENT_AND_OFFSET_ULEB(seg 2, 0x18)
            0x90, // DO_BIND -> @0x18, then +8
            0x41, // SET_SYMBOL_TRAILING_FLAGS_IMM(WEAK) "_w"
        ]);
        v.extend_from_slice(b"_w\0");
        v.extend_from_slice(&[
            0x60, 0x7C, // SET_ADDEND_SLEB(-4)
            0xB1, // DO_BIND_ADD_ADDR_IMM_SCALED(1) -> @0x20, then +8+8
            0xA0, 0x10, // DO_BIND_ADD_ADDR_ULEB(0x10) -> @0x30, then +0x10+8
            0x00, // DONE
        ]);
        let t = parse(v, 8, false).unwrap();
        let b = t.get_bindings();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].get_symbol_name(), Some("_printf"));
        assert_eq!(b[0].get_library_ordinal(), 1);
        assert_eq!(b[0].get_segment_offset(), 0x18);
        assert_eq!(b[0].get_segment_index(), 2);
        assert_eq!(b[0].get_type(), 1);
        assert!(!b[0].is_weak());
        assert_eq!(b[1].get_symbol_name(), Some("_w"));
        assert!(b[1].is_weak());
        assert_eq!(b[1].get_addend(), -4);
        assert_eq!(b[1].get_segment_offset(), 0x20);
        assert_eq!(b[2].get_segment_offset(), 0x30);
        assert_eq!(t.string_offsets(), &[2, 15]);
        assert_eq!(t.sleb_offsets(), &[19]);
        assert_eq!(t.uleb_offsets(), &[12, 22]);
        assert_eq!(t.opcode_offsets(), &[0, 1, 10, 11, 13, 14, 18, 20, 21, 23]);
        assert!(t.get_threaded_bindings().is_none());
    }

    #[test]
    fn special_dylib_ordinals_are_sign_extended() {
        // SET_DYLIB_SPECIAL_IMM(0xF) -> -1 (main executable); DO_BIND
        // SET_DYLIB_SPECIAL_IMM(0xE) -> -2 (flat lookup); DO_BIND
        // SET_DYLIB_SPECIAL_IMM(0) -> 0 (self); DO_BIND
        let t = parse(vec![0x3F, 0x90, 0x3E, 0x90, 0x30, 0x90, 0x00], 4, false).unwrap();
        let ords: Vec<i32> = t.get_bindings().iter().map(Binding::get_library_ordinal).collect();
        assert_eq!(ords, vec![-1, -2, 0]);
        // 32-bit pointer stride.
        let offs: Vec<i64> = t.get_bindings().iter().map(Binding::get_segment_offset).collect();
        assert_eq!(offs, vec![0, 4, 8]);
    }

    #[test]
    fn lazy_table_treats_done_as_separator() {
        // Two lazy entries separated by DONE.
        let mut v = vec![0x72, 0x00, 0x11, 0x40];
        v.extend_from_slice(b"_a\0");
        v.extend_from_slice(&[0x90, 0x00, 0x72, 0x08, 0x12, 0x40]);
        v.extend_from_slice(b"_b\0");
        v.extend_from_slice(&[0x90, 0x00]);
        let lazy = parse(v.clone(), 8, true).unwrap();
        let names: Vec<_> = lazy.get_bindings().iter().map(|b| b.get_symbol_name().unwrap()).collect();
        assert_eq!(names, vec!["_a", "_b"]);
        assert_eq!(lazy.get_bindings()[1].get_library_ordinal(), 2);
        assert_eq!(lazy.get_bindings()[1].get_segment_offset(), 8);

        let non_lazy = parse(v, 8, false).unwrap();
        assert_eq!(non_lazy.get_bindings().len(), 1);
    }

    #[test]
    fn uleb_times_skipping() {
        // SET_SEGMENT_AND_OFFSET_ULEB(seg 1, 0); DO_BIND_ULEB_TIMES_SKIPPING_ULEB(3, 8)
        let t = parse(vec![0x71, 0x00, 0xC0, 0x03, 0x08], 8, false).unwrap();
        let offs: Vec<i64> = t.get_bindings().iter().map(Binding::get_segment_offset).collect();
        assert_eq!(offs, vec![0, 16, 32]);
        assert_eq!(t.uleb_offsets(), &[1, 3, 4]);
    }

    #[test]
    fn threaded_bindings() {
        // THREADED SET_BIND_ORDINAL_TABLE_SIZE_ULEB(2); SET_DYLIB_ORDINAL_IMM(1);
        // SET_SYMBOL "_t"; THREADED APPLY; DO_BIND (no offset advance once threaded)
        let mut v = vec![0xD0, 0x02, 0x11, 0x40];
        v.extend_from_slice(b"_t\0");
        v.extend_from_slice(&[0xD1, 0x90, 0x90, 0x00]);
        let t = parse(v, 8, false).unwrap();
        let threaded = t.get_threaded_bindings().unwrap();
        assert_eq!(threaded.len(), 1);
        assert_eq!(threaded[0].get_symbol_name(), Some("_t"));
        let offs: Vec<i64> = t.get_bindings().iter().map(Binding::get_segment_offset).collect();
        assert_eq!(offs, vec![0, 0]);
    }

    #[test]
    fn threaded_apply_without_table_is_an_error() {
        assert!(parse(vec![0xD1], 8, false).is_err());
    }

    #[test]
    fn unknown_opcodes_record_and_stop() {
        let t = parse(vec![0x11, 0xE3, 0x90], 8, false).unwrap();
        assert_eq!(t.get_bindings().len(), 1);
        assert_eq!(t.get_bindings()[0].get_unknown_opcode(), Some(0xE0));
        assert_eq!(t.get_bindings()[0].get_library_ordinal(), 1);

        // Unknown THREADED sub-opcode keeps the full byte.
        let t = parse(vec![0xD5, 0x90], 8, false).unwrap();
        assert_eq!(t.get_bindings()[0].get_unknown_opcode(), Some(0xD5));
    }
}
