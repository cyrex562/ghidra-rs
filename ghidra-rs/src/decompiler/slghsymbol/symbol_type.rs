/// Discriminant tag for every SLEIGH symbol variant.
///
/// Models `ghidra.pcodeCPort.slghsymbol.symbol_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    SpaceSymbol,
    TokenSymbol,
    UseropSymbol,
    ValueSymbol,
    ValuemapSymbol,
    NameSymbol,
    VarnodeSymbol,
    VarnodelistSymbol,
    OperandSymbol,
    /// Covers `inst_start`, `inst_ref`, and `inst_def` pseudo-symbols.
    StartSymbol,
    /// Covers the `inst_next` pseudo-symbol.
    EndSymbol,
    /// Covers the `inst_next2` pseudo-symbol.
    Next2Symbol,
    SubtableSymbol,
    MacroSymbol,
    SectionSymbol,
    BitrangeSymbol,
    ContextSymbol,
    EpsilonSymbol,
    LabelSymbol,
    FlowdestSymbol,
    FlowrefSymbol,
    DummySymbol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_distinct() {
        let variants = [
            SymbolType::SpaceSymbol,
            SymbolType::TokenSymbol,
            SymbolType::UseropSymbol,
            SymbolType::ValueSymbol,
            SymbolType::ValuemapSymbol,
            SymbolType::NameSymbol,
            SymbolType::VarnodeSymbol,
            SymbolType::VarnodelistSymbol,
            SymbolType::OperandSymbol,
            SymbolType::StartSymbol,
            SymbolType::EndSymbol,
            SymbolType::Next2Symbol,
            SymbolType::SubtableSymbol,
            SymbolType::MacroSymbol,
            SymbolType::SectionSymbol,
            SymbolType::BitrangeSymbol,
            SymbolType::ContextSymbol,
            SymbolType::EpsilonSymbol,
            SymbolType::LabelSymbol,
            SymbolType::FlowdestSymbol,
            SymbolType::FlowrefSymbol,
            SymbolType::DummySymbol,
        ];
        for i in 0..variants.len() {
            for j in 0..variants.len() {
                if i == j {
                    assert_eq!(variants[i], variants[j]);
                } else {
                    assert_ne!(variants[i], variants[j]);
                }
            }
        }
    }

    #[test]
    fn clone_and_copy() {
        let a = SymbolType::SubtableSymbol;
        let b = a;
        assert_eq!(a, b);
        let c = a.clone();
        assert_eq!(a, c);
    }

    #[test]
    fn debug_format() {
        assert_eq!(format!("{:?}", SymbolType::DummySymbol), "DummySymbol");
        assert_eq!(format!("{:?}", SymbolType::StartSymbol), "StartSymbol");
    }
}
