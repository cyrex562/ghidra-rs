/// Symbol class for a Code Fragment Manager (CFM) export.
///
/// Mirrors `CFragSymbolClass` from the original Ghidra Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CFragSymbolClass {
    /// Executable code symbol.
    KCodeCFragSymbol,
    /// Data symbol.
    KDataCFragSymbol,
    /// TVector (transition vector) symbol used for cross-fragment calls.
    KTVectorCFragSymbol,
    /// Table of Contents (TOC) symbol.
    KTOCCFragSymbol,
    /// Glue code symbol.
    KGlueCFragSymbol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let all = [
            CFragSymbolClass::KCodeCFragSymbol,
            CFragSymbolClass::KDataCFragSymbol,
            CFragSymbolClass::KTVectorCFragSymbol,
            CFragSymbolClass::KTOCCFragSymbol,
            CFragSymbolClass::KGlueCFragSymbol,
        ];
        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }

    #[test]
    fn copy_and_clone() {
        let original = CFragSymbolClass::KTVectorCFragSymbol;
        let copied = original;
        let cloned = original.clone();
        assert_eq!(original, copied);
        assert_eq!(original, cloned);
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", CFragSymbolClass::KCodeCFragSymbol),
            "KCodeCFragSymbol"
        );
        assert_eq!(
            format!("{:?}", CFragSymbolClass::KGlueCFragSymbol),
            "KGlueCFragSymbol"
        );
    }
}
