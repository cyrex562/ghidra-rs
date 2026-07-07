use std::fmt;

/// Defines various types of analyzers that Ghidra provides.
///
/// Analyzers are kicked off based on certain events or conditions, such as a function being
/// defined at a location. Different analyzer types trigger on different program events:
///
/// - **ByteAnalyzer**: Triggered when bytes are added (memory block added).
/// - **InstructionAnalyzer**: Triggered when instructions are created.
/// - **FunctionAnalyzer**: Triggered when functions are created.
/// - **FunctionModifiersAnalyzer**: Triggered when a function's modifier changes (e.g., thunk,
///   inline, noreturn, call fixup, purge).
/// - **FunctionSignaturesAnalyzer**: Triggered when a function's signature changes (e.g.,
///   parameters, return type).
/// - **DataAnalyzer**: Triggered when data is created.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AnalyzerType {
    ByteAnalyzer,
    InstructionAnalyzer,
    FunctionAnalyzer,
    FunctionModifiersAnalyzer,
    FunctionSignaturesAnalyzer,
    DataAnalyzer,
}

impl AnalyzerType {
    /// Returns the display name of this analyzer type.
    pub fn name(self) -> &'static str {
        match self {
            AnalyzerType::ByteAnalyzer => "Byte Analyzer",
            AnalyzerType::InstructionAnalyzer => "Instructions Analyzer",
            AnalyzerType::FunctionAnalyzer => "Function Analyzer",
            AnalyzerType::FunctionModifiersAnalyzer => "Function-modifiers Analyzer",
            AnalyzerType::FunctionSignaturesAnalyzer => "Function-Signatures Analyzer",
            AnalyzerType::DataAnalyzer => "Data Analyzer",
        }
    }

    /// Returns the description of this analyzer type.
    pub fn description(self) -> &'static str {
        match self {
            AnalyzerType::ByteAnalyzer => "Triggered when bytes are added (memory block added).",
            AnalyzerType::InstructionAnalyzer => "Triggered when instructions are created.",
            AnalyzerType::FunctionAnalyzer => "Triggered when functions are created.",
            AnalyzerType::FunctionModifiersAnalyzer => {
                "Triggered when a function's modifier changes"
            }
            AnalyzerType::FunctionSignaturesAnalyzer => {
                "Triggered when a function's signature changes."
            }
            AnalyzerType::DataAnalyzer => "Triggered when data is created.",
        }
    }

    /// Returns all analyzer types.
    pub fn all() -> &'static [AnalyzerType] {
        &[
            AnalyzerType::ByteAnalyzer,
            AnalyzerType::InstructionAnalyzer,
            AnalyzerType::FunctionAnalyzer,
            AnalyzerType::FunctionModifiersAnalyzer,
            AnalyzerType::FunctionSignaturesAnalyzer,
            AnalyzerType::DataAnalyzer,
        ]
    }
}

impl fmt::Display for AnalyzerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_type_names() {
        assert_eq!(AnalyzerType::ByteAnalyzer.name(), "Byte Analyzer");
        assert_eq!(
            AnalyzerType::InstructionAnalyzer.name(),
            "Instructions Analyzer"
        );
        assert_eq!(AnalyzerType::FunctionAnalyzer.name(), "Function Analyzer");
        assert_eq!(
            AnalyzerType::FunctionModifiersAnalyzer.name(),
            "Function-modifiers Analyzer"
        );
        assert_eq!(
            AnalyzerType::FunctionSignaturesAnalyzer.name(),
            "Function-Signatures Analyzer"
        );
        assert_eq!(AnalyzerType::DataAnalyzer.name(), "Data Analyzer");
    }

    #[test]
    fn test_analyzer_type_descriptions() {
        assert_eq!(
            AnalyzerType::ByteAnalyzer.description(),
            "Triggered when bytes are added (memory block added)."
        );
        assert_eq!(
            AnalyzerType::InstructionAnalyzer.description(),
            "Triggered when instructions are created."
        );
        assert_eq!(
            AnalyzerType::FunctionAnalyzer.description(),
            "Triggered when functions are created."
        );
        assert_eq!(
            AnalyzerType::FunctionModifiersAnalyzer.description(),
            "Triggered when a function's modifier changes"
        );
        assert_eq!(
            AnalyzerType::FunctionSignaturesAnalyzer.description(),
            "Triggered when a function's signature changes."
        );
        assert_eq!(
            AnalyzerType::DataAnalyzer.description(),
            "Triggered when data is created."
        );
    }

    #[test]
    fn test_analyzer_type_display() {
        assert_eq!(AnalyzerType::ByteAnalyzer.to_string(), "Byte Analyzer");
        assert_eq!(
            AnalyzerType::InstructionAnalyzer.to_string(),
            "Instructions Analyzer"
        );
        assert_eq!(AnalyzerType::FunctionAnalyzer.to_string(), "Function Analyzer");
        assert_eq!(
            AnalyzerType::FunctionModifiersAnalyzer.to_string(),
            "Function-modifiers Analyzer"
        );
        assert_eq!(
            AnalyzerType::FunctionSignaturesAnalyzer.to_string(),
            "Function-Signatures Analyzer"
        );
        assert_eq!(AnalyzerType::DataAnalyzer.to_string(), "Data Analyzer");
    }

    #[test]
    fn test_analyzer_type_all() {
        let all = AnalyzerType::all();
        assert_eq!(all.len(), 6);
        assert!(all.contains(&AnalyzerType::ByteAnalyzer));
        assert!(all.contains(&AnalyzerType::InstructionAnalyzer));
        assert!(all.contains(&AnalyzerType::FunctionAnalyzer));
        assert!(all.contains(&AnalyzerType::FunctionModifiersAnalyzer));
        assert!(all.contains(&AnalyzerType::FunctionSignaturesAnalyzer));
        assert!(all.contains(&AnalyzerType::DataAnalyzer));
    }

    #[test]
    fn test_analyzer_type_clone_copy() {
        let t1 = AnalyzerType::ByteAnalyzer;
        let t2 = t1;
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_analyzer_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AnalyzerType::ByteAnalyzer);
        set.insert(AnalyzerType::FunctionAnalyzer);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&AnalyzerType::ByteAnalyzer));
    }
}
