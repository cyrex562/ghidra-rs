use super::symbol_type::SymbolType;
use super::sleigh_symbol::SleighSymbol;
use crate::sleigh::grammar::location::Location;

/// A label symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.LabelSymbol`.
pub struct LabelSymbol {
    symbol: SleighSymbol,
    index: i32,
    isplaced: bool,
    refcount: i32,
}

impl LabelSymbol {
    /// Creates a new label symbol at the given location.
    pub fn new(location: Location, name: impl Into<String>, index: i32) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            index,
            isplaced: false,
            refcount: 0,
        }
    }

    /// Gets the index of this label.
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Increments the reference count for this label.
    pub fn increment_ref_count(&mut self) {
        self.refcount += 1;
    }

    /// Gets the reference count for this label.
    pub fn ref_count(&self) -> i32 {
        self.refcount
    }

    /// Marks this label as placed.
    pub fn set_placed(&mut self) {
        self.isplaced = true;
    }

    /// Checks if this label has been placed.
    pub fn is_placed(&self) -> bool {
        self.isplaced
    }

    /// Returns the symbol type for this label.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::LabelSymbol
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
        Location::new("test.sla", 1)
    }

    #[test]
    fn new_initializes_fields() {
        let label = LabelSymbol::new(loc(), "loop_label", 42);
        assert_eq!(label.symbol().name(), "loop_label");
        assert_eq!(label.index(), 42);
        assert_eq!(label.ref_count(), 0);
        assert!(!label.is_placed());
    }

    #[test]
    fn increment_ref_count() {
        let mut label = LabelSymbol::new(loc(), "label", 1);
        assert_eq!(label.ref_count(), 0);
        label.increment_ref_count();
        assert_eq!(label.ref_count(), 1);
        label.increment_ref_count();
        label.increment_ref_count();
        assert_eq!(label.ref_count(), 3);
    }

    #[test]
    fn set_and_check_placed() {
        let mut label = LabelSymbol::new(loc(), "label", 1);
        assert!(!label.is_placed());
        label.set_placed();
        assert!(label.is_placed());
    }

    #[test]
    fn symbol_type_is_label() {
        let label = LabelSymbol::new(loc(), "label", 1);
        assert_eq!(label.symbol_type(), SymbolType::LabelSymbol);
    }

    #[test]
    fn symbol_access() {
        let label = LabelSymbol::new(loc(), "test_label", 99);
        assert_eq!(label.symbol().name(), "test_label");
    }

    #[test]
    fn multiple_indices() {
        let label1 = LabelSymbol::new(loc(), "label1", 10);
        let label2 = LabelSymbol::new(loc(), "label2", 20);
        assert_eq!(label1.index(), 10);
        assert_eq!(label2.index(), 20);
    }
}
