use std::fmt;

/// Microsoft product type stored in a PE Rich header entry.
///
/// Mirrors `ghidra.app.util.bin.format.pe.rich.MSProductType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsProductType {
    CxxCompiler,
    CCompiler,
    Assembler,
    Import,
    Export,
    ImportExport,
    Linker,
    CvtRes,
    Unknown,
}

impl MsProductType {
    /// Returns the human-readable description, matching the Java `toString()` output.
    pub fn description(self) -> &'static str {
        match self {
            MsProductType::CxxCompiler => "C++ Compiler",
            MsProductType::CCompiler => "C Compiler",
            MsProductType::Assembler => "Assembler",
            MsProductType::Import => "Linker",
            MsProductType::Export => "Linker",
            MsProductType::ImportExport => "Linker",
            MsProductType::Linker => "Linker",
            MsProductType::CvtRes => "CVTRes",
            MsProductType::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for MsProductType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cxx_compiler_description() {
        assert_eq!(MsProductType::CxxCompiler.description(), "C++ Compiler");
        assert_eq!(MsProductType::CxxCompiler.to_string(), "C++ Compiler");
    }

    #[test]
    fn c_compiler_description() {
        assert_eq!(MsProductType::CCompiler.description(), "C Compiler");
    }

    #[test]
    fn assembler_description() {
        assert_eq!(MsProductType::Assembler.description(), "Assembler");
    }

    #[test]
    fn linker_variants_all_return_linker() {
        assert_eq!(MsProductType::Import.description(), "Linker");
        assert_eq!(MsProductType::Export.description(), "Linker");
        assert_eq!(MsProductType::ImportExport.description(), "Linker");
        assert_eq!(MsProductType::Linker.description(), "Linker");
    }

    #[test]
    fn cvtres_description() {
        assert_eq!(MsProductType::CvtRes.description(), "CVTRes");
    }

    #[test]
    fn unknown_description() {
        assert_eq!(MsProductType::Unknown.description(), "Unknown");
        assert_eq!(MsProductType::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn display_matches_description_for_all_variants() {
        let variants = [
            MsProductType::CxxCompiler,
            MsProductType::CCompiler,
            MsProductType::Assembler,
            MsProductType::Import,
            MsProductType::Export,
            MsProductType::ImportExport,
            MsProductType::Linker,
            MsProductType::CvtRes,
            MsProductType::Unknown,
        ];
        for v in variants {
            assert_eq!(v.to_string(), v.description());
        }
    }
}
