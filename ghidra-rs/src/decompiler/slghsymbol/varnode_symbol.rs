use super::sleigh_symbol::SleighSymbol;
use super::symbol_type::SymbolType;
use crate::decompiler::context::SleighError;
use crate::decompiler::slghpatexpress::{ConstantValue, PatternExpression};
use crate::decompiler::slghsymbol::specific_symbol::SpecificSymbol;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::lang::sleigh::template::{ConstTpl, ConstTplType, VarnodeTpl};
use crate::program::model::pcode::ids::{ATTRIB_ID, ATTRIB_OFF, ATTRIB_SIZE, ATTRIB_SPACE, ELEM_VARNODE_SYM, ELEM_VARNODE_SYM_HEAD};
use crate::program::model::pcode::Encoder;
use crate::program::model::pcode::VarnodeData;
use crate::sleigh::grammar::location::Location;
use std::io;
use std::sync::Arc;

/// A symbol representing a global (fixed) varnode in SLEIGH -- a named location at a constant
/// space/offset/size, as opposed to a varnode resolved dynamically through a handle.
///
/// Models `ghidra.pcodeCPort.slghsymbol.VarnodeSymbol`, which extends `PatternlessSymbol`.
pub struct VarnodeSymbol {
    symbol: SleighSymbol,
    /// The fixed space/offset/size this symbol resolves to, present once constructed via
    /// [`VarnodeSymbol::with_fixed`] (Java's `fix` field; `None` matches Java's implicit
    /// zero/null-initialized state from the bare `VarnodeSymbol(Location)` constructor).
    fix: Option<VarnodeData>,
    /// A constant-zero pattern expression, matching every other `PatternlessSymbol` descendant
    /// in this crate (see [`crate::decompiler::slghsymbol::patternless_symbol::PatternlessSymbol`],
    /// whose own `get_pattern_expression` this mirrors) -- Java's `VarnodeSymbol` inherits this
    /// from `PatternlessSymbol`; composition needs its own copy of the same field instead.
    patexp: ConstantValue,
}

impl VarnodeSymbol {
    /// An unresolved varnode symbol (Java's `VarnodeSymbol(Location location)`).
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location.clone()),
            fix: None,
            patexp: ConstantValue::new(location),
        }
    }

    /// Creates a new varnode symbol with a name at the given location, but no fixed location yet
    /// (test/construction convenience predating this port's completion; matches Java's bare
    /// constructor plus a name, which Java itself doesn't offer as a single constructor either).
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location.clone(), name),
            fix: None,
            patexp: ConstantValue::new(location),
        }
    }

    /// A varnode symbol fixed at `[offset, offset + size)` of address space `base` (Java's
    /// `VarnodeSymbol(Location location, String nm, AddrSpace base, long offset, int size)`).
    ///
    /// # Panics
    /// Panics with a [`SleighError`] if the range would extend beyond the end of `base` (mirrors
    /// Java's own overflow-checking `throw`). `addr_size`/`word_size` map to Java's
    /// `base.getAddrSize()` (bytes needed for an address into the space, i.e.
    /// [`AddressSpace::pointer_size`]) and `base.getWordSize()` (data bytes per address unit,
    /// i.e. [`AddressSpace::unit_size`]).
    pub fn with_fixed(
        location: Location,
        name: impl Into<String>,
        base: Arc<AddressSpace>,
        offset: u64,
        size: i32,
    ) -> Self {
        let name = name.into();
        let addr_size = base.pointer_size();
        let max_byte_offset = if addr_size >= 8 {
            u64::MAX
        } else {
            ((base.unit_size() as u128) << (8 * addr_size)) as u64 - 1
        };
        let end_offset = offset.wrapping_add(size as u64).wrapping_sub(1);
        let mut size_error = size != 0 && offset > end_offset;
        if !size_error && addr_size < 8 {
            size_error = end_offset > max_byte_offset;
        }
        if size_error {
            panic!(
                "{}",
                SleighError::new(
                    format!(
                        "{}:{} @ {}:{:#x} extends beyond end of space (max offset is {:#x})",
                        name,
                        size,
                        base.name(),
                        offset,
                        max_byte_offset
                    ),
                    location.clone(),
                )
            );
        }

        Self {
            symbol: SleighSymbol::with_name(location.clone(), name),
            fix: Some(VarnodeData { space: base, offset, size }),
            patexp: ConstantValue::new(location),
        }
    }

    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::VarnodeSymbol
    }

    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    pub fn name(&self) -> &str {
        self.symbol.name()
    }

    /// The fixed space/offset/size this symbol resolves to (Java's `getFixedVarnode`).
    ///
    /// # Panics
    /// Panics if this symbol was never given a fixed location, matching Java's implicit NPE on
    /// `fix.space`/`fix.offset`/`fix.size`.
    pub fn get_fixed_varnode(&self) -> &VarnodeData {
        self.fix
            .as_ref()
            .expect("VarnodeSymbol::get_fixed_varnode called before a fixed location was set")
    }

    pub fn get_size(&self) -> i32 {
        self.get_fixed_varnode().size
    }

    pub fn collect_local_values(&self, results: &mut Vec<i64>) {
        let fix = self.get_fixed_varnode();
        if fix.space.space_type() == AddressSpaceType::Unique {
            results.push(fix.offset as i64);
        }
    }

    /// The varnode template this symbol resolves to (Java's `getVarnode`, a `SpecificSymbol`
    /// override): a fixed, real constant space/offset/size, not resolved through a handle.
    pub fn get_varnode(&self) -> VarnodeTpl {
        let fix = self.get_fixed_varnode();
        VarnodeTpl::with_fields(
            ConstTpl {
                tp: ConstTplType::SpaceId,
                value_real: 0,
                value_spaceid: Some(fix.space.clone()),
                handle_index: 0,
                select: None,
            },
            ConstTpl {
                tp: ConstTplType::Real,
                value_real: fix.offset,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            ConstTpl {
                tp: ConstTplType::Real,
                value_real: fix.size as u64,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
        )
    }

    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        let fix = self.get_fixed_varnode();
        encoder.open_element(ELEM_VARNODE_SYM)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.symbol.id() as u64)?;
        encoder.write_space(ATTRIB_SPACE, &fix.space)?;
        encoder.write_unsigned_integer(ATTRIB_OFF, fix.offset)?;
        encoder.write_signed_integer(ATTRIB_SIZE, fix.size as i64)?;
        encoder.close_element(ELEM_VARNODE_SYM)
    }

    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_VARNODE_SYM_HEAD)?;
        self.symbol.encode_sleigh_symbol_header(encoder)?;
        encoder.close_element(ELEM_VARNODE_SYM_HEAD)
    }
}

impl TripleSymbol for VarnodeSymbol {
    /// Matches every other `PatternlessSymbol` descendant in this crate (Java's `VarnodeSymbol`
    /// inherits `PatternlessSymbol.getPatternExpression()`, which returns its constant-zero
    /// pattern expression).
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        Box::new(self.patexp.clone())
    }

    fn get_size(&self) -> i32 {
        VarnodeSymbol::get_size(self)
    }

    fn collect_local_values(&self, results: &mut Vec<i64>) {
        VarnodeSymbol::collect_local_values(self, results)
    }
}

impl SpecificSymbol for VarnodeSymbol {
    fn get_varnode(&self) -> Box<VarnodeTpl> {
        Box::new(VarnodeSymbol::get_varnode(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    fn space(size: i32, unit_size: i32) -> Arc<AddressSpace> {
        AddressSpace::new("ram", size, unit_size, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_creates_unnamed_symbol() {
        let vs = VarnodeSymbol::new(loc());
        assert_eq!(vs.name(), "");
        assert_eq!(vs.symbol_type(), SymbolType::VarnodeSymbol);
    }

    #[test]
    fn with_name_sets_name() {
        let vs = VarnodeSymbol::with_name(loc(), "my_varnode");
        assert_eq!(vs.name(), "my_varnode");
    }

    #[test]
    fn symbol_type_is_varnode() {
        let vs = VarnodeSymbol::with_name(loc(), "test");
        assert_eq!(vs.symbol_type(), SymbolType::VarnodeSymbol);
    }

    #[test]
    fn can_access_base_symbol() {
        let vs = VarnodeSymbol::with_name(loc(), "varnode1");
        let sym = vs.symbol();
        assert_eq!(sym.name(), "varnode1");
    }

    #[test]
    fn can_mutate_via_symbol_mut() {
        let mut vs = VarnodeSymbol::with_name(loc(), "initial");
        vs.symbol_mut().set_was_sought(true);
        assert!(vs.symbol().was_sought());
    }

    #[test]
    fn with_fixed_stores_space_offset_size() {
        let vs = VarnodeSymbol::with_fixed(loc(), "r0", space(32, 1), 0, 4);
        let fix = vs.get_fixed_varnode();
        assert_eq!(fix.offset, 0);
        assert_eq!(fix.size, 4);
        assert_eq!(fix.space.name(), "ram");
    }

    #[test]
    fn get_size_returns_fixed_size() {
        let vs = VarnodeSymbol::with_fixed(loc(), "r0", space(32, 1), 4, 4);
        assert_eq!(TripleSymbol::get_size(&vs), 4);
    }

    #[test]
    #[should_panic(expected = "get_fixed_varnode called before")]
    fn get_size_panics_without_a_fixed_location() {
        let vs = VarnodeSymbol::new(loc());
        let _ = TripleSymbol::get_size(&vs);
    }

    #[test]
    #[should_panic(expected = "extends beyond end of space")]
    fn with_fixed_panics_on_out_of_range_offset() {
        // 8-bit space (byte offsets 0..255 addressable): offset 300 is out of range.
        VarnodeSymbol::with_fixed(loc(), "bad", space(8, 1), 300, 1);
    }

    #[test]
    fn collect_local_values_pushes_offset_for_unique_space() {
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 0);
        let vs = VarnodeSymbol::with_fixed(loc(), "u0", unique, 8, 4);
        let mut results = Vec::new();
        TripleSymbol::collect_local_values(&vs, &mut results);
        assert_eq!(results, vec![8]);
    }

    #[test]
    fn collect_local_values_is_empty_for_non_unique_space() {
        let vs = VarnodeSymbol::with_fixed(loc(), "r0", space(32, 1), 0, 4);
        let mut results = Vec::new();
        TripleSymbol::collect_local_values(&vs, &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn get_varnode_encodes_fixed_space_offset_size() {
        let vs = VarnodeSymbol::with_fixed(loc(), "r0", space(32, 1), 4, 4);
        let vn = SpecificSymbol::get_varnode(&vs);
        assert_eq!(vn.offset.tp, ConstTplType::Real);
        assert_eq!(vn.offset.value_real, 4);
        assert_eq!(vn.size.value_real, 4);
        assert_eq!(vn.space.tp, ConstTplType::SpaceId);
        assert_eq!(vn.space.value_spaceid.as_ref().unwrap().name(), "ram");
    }

    #[derive(Default)]
    struct RecordingEncoder {
        opened: Vec<&'static str>,
        closed: Vec<&'static str>,
        uints: Vec<u64>,
        ints: Vec<i64>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.opened.push(elem_id.name);
            Ok(())
        }
        fn close_element(&mut self, elem_id: crate::program::model::pcode::ids::ElementId) -> io::Result<()> {
            self.closed.push(elem_id.name);
            Ok(())
        }
        fn write_bool(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: bool) -> io::Result<()> { Ok(()) }
        fn write_signed_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, v: i64) -> io::Result<()> {
            self.ints.push(v);
            Ok(())
        }
        fn write_unsigned_integer(&mut self, _a: crate::program::model::pcode::ids::AttributeId, v: u64) -> io::Result<()> {
            self.uints.push(v);
            Ok(())
        }
        fn write_string(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_string_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _v: &str) -> io::Result<()> { Ok(()) }
        fn write_space(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _s: &crate::program::model::address::AddressSpace) -> io::Result<()> { Ok(()) }
        fn write_space_indexed(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _i: i32, _n: &str) -> io::Result<()> { Ok(()) }
        fn write_opcode(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: crate::decompiler::opcodes::op_code::OpCode) -> io::Result<()> { Ok(()) }
        fn write_opcode_ordinal(&mut self, _a: crate::program::model::pcode::ids::AttributeId, _o: i32) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn encode_writes_element_and_offset_size() {
        let vs = VarnodeSymbol::with_fixed(loc(), "r0", space(32, 1), 4, 8);
        let mut encoder = RecordingEncoder::default();
        vs.encode(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["varnode_sym"]);
        assert_eq!(encoder.closed, vec!["varnode_sym"]);
        assert!(encoder.uints.contains(&4));
        assert_eq!(encoder.ints, vec![8]);
    }

    #[test]
    fn encode_header_writes_header_element() {
        let vs = VarnodeSymbol::with_name(loc(), "r0");
        let mut encoder = RecordingEncoder::default();
        vs.encode_header(&mut encoder).unwrap();
        assert_eq!(encoder.opened, vec!["varnode_sym_head"]);
        assert_eq!(encoder.closed, vec!["varnode_sym_head"]);
    }
}
