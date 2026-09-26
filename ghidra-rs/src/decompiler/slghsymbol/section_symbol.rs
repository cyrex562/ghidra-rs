use super::symbol_type::SymbolType;
use super::sleigh_symbol::SleighSymbol;
use crate::sleigh::grammar::location::Location;

/// A named p-code section symbol in SLEIGH.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SectionSymbol`.
pub struct SectionSymbol {
    symbol: SleighSymbol,
    template_id: i32,
    define_count: i32,
    ref_count: i32,
}

impl SectionSymbol {
    /// Creates a new section symbol at the given location.
    pub fn new(location: Location, name: impl Into<String>, id: i32) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location, name),
            template_id: id,
            define_count: 0,
            ref_count: 0,
        }
    }

    /// Gets the template id for this section.
    pub fn template_id(&self) -> i32 {
        self.template_id
    }

    /// Increments the definition count for this section.
    pub fn increment_define_count(&mut self) {
        self.define_count += 1;
    }

    /// Increments the reference count for this section.
    pub fn increment_ref_count(&mut self) {
        self.ref_count += 1;
    }

    /// Gets the definition count for this section.
    pub fn define_count(&self) -> i32 {
        self.define_count
    }

    /// Gets the reference count for this section.
    pub fn ref_count(&self) -> i32 {
        self.ref_count
    }

    /// Returns the symbol type for this section.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::SectionSymbol
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
        Location::new("test.sla", 5)
    }

    #[test]
    fn new_initializes_fields() {
        let section = SectionSymbol::new(loc(), "my_section", 42);
        assert_eq!(section.symbol().name(), "my_section");
        assert_eq!(section.template_id(), 42);
        assert_eq!(section.define_count(), 0);
        assert_eq!(section.ref_count(), 0);
    }

    #[test]
    fn increment_define_count() {
        let mut section = SectionSymbol::new(loc(), "section", 1);
        assert_eq!(section.define_count(), 0);
        section.increment_define_count();
        assert_eq!(section.define_count(), 1);
        section.increment_define_count();
        section.increment_define_count();
        assert_eq!(section.define_count(), 3);
    }

    #[test]
    fn increment_ref_count() {
        let mut section = SectionSymbol::new(loc(), "section", 1);
        assert_eq!(section.ref_count(), 0);
        section.increment_ref_count();
        assert_eq!(section.ref_count(), 1);
        section.increment_ref_count();
        section.increment_ref_count();
        assert_eq!(section.ref_count(), 3);
    }

    #[test]
    fn symbol_type_is_section() {
        let section = SectionSymbol::new(loc(), "section", 1);
        assert_eq!(section.symbol_type(), SymbolType::SectionSymbol);
    }

    #[test]
    fn symbol_access() {
        let section = SectionSymbol::new(loc(), "test_section", 99);
        assert_eq!(section.symbol().name(), "test_section");
    }

    #[test]
    fn different_template_ids() {
        let section1 = SectionSymbol::new(loc(), "section1", 10);
        let section2 = SectionSymbol::new(loc(), "section2", 20);
        assert_eq!(section1.template_id(), 10);
        assert_eq!(section2.template_id(), 20);
    }
}
