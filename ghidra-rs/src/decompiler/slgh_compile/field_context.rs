use super::field_quality::FieldQuality;
use crate::decompiler::slghsymbol::VarnodeSymbol;
use std::cmp::Ordering;
use std::fmt;

/// Field context combining a symbol and quality information.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.FieldContext`.
pub struct FieldContext {
    pub sym: VarnodeSymbol,
    pub qual: FieldQuality,
}

impl FieldContext {
    pub fn new(sym: VarnodeSymbol, qual: FieldQuality) -> Self {
        Self { sym, qual }
    }
}

impl PartialEq for FieldContext {
    fn eq(&self, other: &Self) -> bool {
        self.sym.name() == other.sym.name() && self.qual.low == other.qual.low
    }
}

impl Eq for FieldContext {}

impl PartialOrd for FieldContext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FieldContext {
    fn cmp(&self, other: &Self) -> Ordering {
        let name_cmp = self.sym.name().cmp(other.sym.name());
        if name_cmp == Ordering::Equal {
            self.qual.low.cmp(&other.qual.low)
        } else {
            name_cmp
        }
    }
}

impl fmt::Display for FieldContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.sym.name(), self.qual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::grammar::location::Location;

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    fn make_symbol(name: &str) -> VarnodeSymbol {
        VarnodeSymbol::with_name(loc(), name)
    }

    #[test]
    fn test_construction() {
        let sym = make_symbol("test_sym");
        let qual = FieldQuality::new("field1".to_string(), loc(), 0, 31);
        let fc = FieldContext::new(sym, qual);

        assert_eq!(fc.sym.name(), "test_sym");
        assert_eq!(fc.qual.name, "field1");
    }

    #[test]
    fn test_comparable_by_name() {
        let sym1 = make_symbol("aaa");
        let qual1 = FieldQuality::new("f1".to_string(), loc(), 0, 31);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("zzz");
        let qual2 = FieldQuality::new("f1".to_string(), loc(), 0, 31);
        let fc2 = FieldContext::new(sym2, qual2);

        assert!(fc1 < fc2);
    }

    #[test]
    fn test_comparable_by_quality_low_when_names_equal() {
        let sym1 = make_symbol("same");
        let qual1 = FieldQuality::new("f1".to_string(), loc(), 0, 31);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("same");
        let qual2 = FieldQuality::new("f2".to_string(), loc(), 10, 31);
        let fc2 = FieldContext::new(sym2, qual2);

        assert!(fc1 < fc2);
    }

    #[test]
    fn test_to_string() {
        let sym = make_symbol("sym_name");
        let qual = FieldQuality::new("field".to_string(), loc(), 5, 10);
        let fc = FieldContext::new(sym, qual);

        let s = fc.to_string();
        assert!(s.contains("sym_name"));
        assert!(s.contains("field"));
    }

    #[test]
    fn test_equal_contexts_are_equal() {
        let sym1 = make_symbol("test");
        let qual1 = FieldQuality::new("f".to_string(), loc(), 1, 2);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("test");
        let qual2 = FieldQuality::new("f".to_string(), loc(), 1, 2);
        let fc2 = FieldContext::new(sym2, qual2);

        assert_eq!(fc1, fc2);
    }

    #[test]
    fn test_different_names_are_not_equal() {
        let sym1 = make_symbol("test1");
        let qual1 = FieldQuality::new("f".to_string(), loc(), 1, 2);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("test2");
        let qual2 = FieldQuality::new("f".to_string(), loc(), 1, 2);
        let fc2 = FieldContext::new(sym2, qual2);

        assert_ne!(fc1, fc2);
    }

    #[test]
    fn test_different_qualities_are_not_equal() {
        let sym1 = make_symbol("test");
        let qual1 = FieldQuality::new("f".to_string(), loc(), 1, 2);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("test");
        let qual2 = FieldQuality::new("f".to_string(), loc(), 5, 10);
        let fc2 = FieldContext::new(sym2, qual2);

        assert_ne!(fc1, fc2);
    }

    #[test]
    fn test_sort_order() {
        let sym1 = make_symbol("bbb");
        let qual1 = FieldQuality::new("f".to_string(), loc(), 0, 31);
        let fc1 = FieldContext::new(sym1, qual1);

        let sym2 = make_symbol("aaa");
        let qual2 = FieldQuality::new("f".to_string(), loc(), 0, 31);
        let fc2 = FieldContext::new(sym2, qual2);

        let sym3 = make_symbol("aaa");
        let qual3 = FieldQuality::new("f".to_string(), loc(), 1, 31);
        let fc3 = FieldContext::new(sym3, qual3);

        let mut contexts = vec![fc1, fc3, fc2];
        contexts.sort();

        assert_eq!(contexts[0].sym.name(), "aaa");
        assert_eq!(contexts[0].qual.low, 0);
        assert_eq!(contexts[1].sym.name(), "aaa");
        assert_eq!(contexts[1].qual.low, 1);
        assert_eq!(contexts[2].sym.name(), "bbb");
    }
}
