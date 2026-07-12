use super::symbol_type::SymbolType;
use super::sleigh_symbol::SleighSymbol;
use super::varnode_symbol::VarnodeSymbol;
use crate::sleigh::grammar::location::Location;

/// A smaller bitrange within a varnode.
///
/// Models `ghidra.pcodeCPort.slghsymbol.BitrangeSymbol`.
pub struct BitrangeSymbol {
    symbol: SleighSymbol,
    varsym: Option<Box<VarnodeSymbol>>,
    bitoffset: i32,
    numbits: i32,
}

impl BitrangeSymbol {
    /// Creates a new bitrange symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location),
            varsym: None,
            bitoffset: 0,
            numbits: 0,
        }
    }

    /// Creates a new bitrange symbol with full parameters.
    pub fn with_params(
        location: Location,
        name: impl Into<String>,
        sym: VarnodeSymbol,
        bitoff: i32,
        num: i32,
    ) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            varsym: Some(Box::new(sym)),
            bitoffset: bitoff,
            numbits: num,
        }
    }

    /// Gets the parent varnode symbol.
    pub fn parent_symbol(&self) -> Option<&VarnodeSymbol> {
        self.varsym.as_ref().map(|b| b.as_ref())
    }

    /// Gets the bit offset (least significant bit of range).
    pub fn bit_offset(&self) -> i32 {
        self.bitoffset
    }

    /// Gets the number of bits in this range.
    pub fn num_bits(&self) -> i32 {
        self.numbits
    }

    /// Returns the symbol type for this bitrange.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::BitrangeSymbol
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 10)
    }

    #[test]
    fn new_creates_unnamed_symbol() {
        let br = BitrangeSymbol::new(loc());
        assert_eq!(br.symbol().name(), "");
        assert_eq!(br.bit_offset(), 0);
        assert_eq!(br.num_bits(), 0);
        assert!(br.parent_symbol().is_none());
    }

    #[test]
    fn with_params_sets_all_fields() {
        let parent = VarnodeSymbol::with_name(loc(), "parent_var");
        let br = BitrangeSymbol::with_params(loc(), "myrange", parent, 5, 8);
        assert_eq!(br.symbol().name(), "myrange");
        assert_eq!(br.bit_offset(), 5);
        assert_eq!(br.num_bits(), 8);
        assert!(br.parent_symbol().is_some());
    }

    #[test]
    fn parent_symbol_returns_reference() {
        let parent = VarnodeSymbol::with_name(loc(), "test_var");
        let br = BitrangeSymbol::with_params(loc(), "range", parent, 0, 16);
        let retrieved = br.parent_symbol().unwrap();
        assert_eq!(retrieved.name(), "test_var");
    }

    #[test]
    fn parent_symbol_is_none_for_unnamed() {
        let br = BitrangeSymbol::new(loc());
        assert!(br.parent_symbol().is_none());
    }

    #[test]
    fn bit_offset_and_num_bits() {
        let parent = VarnodeSymbol::with_name(loc(), "var");
        let br = BitrangeSymbol::with_params(loc(), "range", parent, 3, 10);
        assert_eq!(br.bit_offset(), 3);
        assert_eq!(br.num_bits(), 10);
    }

    #[test]
    fn symbol_type_is_bitrange() {
        let br = BitrangeSymbol::new(loc());
        assert_eq!(br.symbol_type(), SymbolType::BitrangeSymbol);
    }

    #[test]
    fn symbol_type_with_params() {
        let parent = VarnodeSymbol::new(loc());
        let br = BitrangeSymbol::with_params(loc(), "range", parent, 0, 1);
        assert_eq!(br.symbol_type(), SymbolType::BitrangeSymbol);
    }

    #[test]
    fn can_mutate_via_symbol_mut() {
        let mut br = BitrangeSymbol::new(loc());
        br.symbol_mut().set_was_sought(true);
        assert!(br.symbol().was_sought());
    }

    #[test]
    fn zero_bits_range() {
        let parent = VarnodeSymbol::with_name(loc(), "var");
        let br = BitrangeSymbol::with_params(loc(), "empty_range", parent, 0, 0);
        assert_eq!(br.num_bits(), 0);
    }

    #[test]
    fn various_bit_offsets() {
        let br1 = BitrangeSymbol::with_params(loc(), "r1", VarnodeSymbol::new(loc()), 0, 8);
        let br2 = BitrangeSymbol::with_params(loc(), "r2", VarnodeSymbol::new(loc()), 8, 8);
        let br3 = BitrangeSymbol::with_params(loc(), "r3", VarnodeSymbol::new(loc()), 16, 16);
        assert_eq!(br1.bit_offset(), 0);
        assert_eq!(br2.bit_offset(), 8);
        assert_eq!(br3.bit_offset(), 16);
    }
}
