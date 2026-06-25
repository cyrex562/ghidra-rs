use std::fmt;

/// Priority level for automated analysis phases within the Ghidra analysis pipeline.
///
/// Analysis priorities define the order in which basic components are laid down in a program.
/// Analyzers are scheduled at particular priorities; for example, the ReferenceAnalyzer runs
/// at the REFERENCE_ANALYSIS priority. Higher priority analyzers run earlier and are generally
/// more confident about the information they produce. Lower priority analyzers run later and
/// may be more speculative, depending on prior analysis.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct AnalysisPriority {
    priority: i32,
    name: Option<String>,
}

impl AnalysisPriority {
    /// Creates a new `AnalysisPriority` with the given priority value.
    pub fn new(priority: i32) -> Self {
        AnalysisPriority {
            priority,
            name: None,
        }
    }

    /// Creates a new `AnalysisPriority` with a name and priority value.
    pub fn with_name(name: impl Into<String>, priority: i32) -> Self {
        AnalysisPriority {
            priority,
            name: Some(name.into()),
        }
    }

    /// Returns the priority value for this analysis priority.
    #[inline]
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Returns a priority that is slightly higher (1 less) than this one.
    /// Used to schedule an analyzer to run before the current priority.
    pub fn before(&self) -> Self {
        let new_name = if let Some(name) = &self.name {
            format!("{}-", name)
        } else {
            String::new()
        };
        AnalysisPriority {
            priority: self.priority - 1,
            name: if new_name.is_empty() { None } else { Some(new_name) },
        }
    }

    /// Returns a priority that is slightly lower (1 more) than this one.
    /// Used to schedule an analyzer to run after the current priority.
    pub fn after(&self) -> Self {
        let new_name = if let Some(name) = &self.name {
            format!("{}+", name)
        } else {
            String::new()
        };
        AnalysisPriority {
            priority: self.priority + 1,
            name: if new_name.is_empty() { None } else { Some(new_name) },
        }
    }

    /// Returns the initial gross priority level with the given name (priority = 100).
    pub fn initial(name: impl Into<String>) -> Self {
        AnalysisPriority {
            priority: 100,
            name: Some(name.into()),
        }
    }

    /// Returns the next gross priority level relative to this one (current priority + 100).
    pub fn next(&self, next_name: impl Into<String>) -> Self {
        AnalysisPriority {
            priority: self.priority + 100,
            name: Some(next_name.into()),
        }
    }

    // Standard predefined analysis phases

    /// Priority for format analysis — the first phase after import.
    /// Analyzers at this level handle file format parsing and initial layout.
    pub fn format_analysis() -> Self {
        Self::initial("FORMAT")
    }

    /// Priority for block analysis — the second phase.
    /// Initial markup of raw bytes and disassembly of entry points occur at this level.
    pub fn block_analysis() -> Self {
        Self::format_analysis().next("BLOCK")
    }

    /// Priority for disassembly — the third phase.
    /// Code disassembly through reliable control flow occurs at this level.
    pub fn disassembly() -> Self {
        Self::block_analysis().next("DISASSEMBLY")
    }

    /// Priority for code analysis — the fourth phase.
    /// Analyzers examining raw code and instruction flow should use this level or later.
    pub fn code_analysis() -> Self {
        Self::disassembly().next("CODE")
    }

    /// Priority for function analysis — the fifth phase.
    /// After this priority, basic functions and their instructions should be recovered.
    pub fn function_analysis() -> Self {
        Self::code_analysis().next("FUNCTION")
    }

    /// Priority for reference analysis — the sixth phase.
    /// Basic reference recovery should have taken place at this level.
    pub fn reference_analysis() -> Self {
        Self::function_analysis().next("REFERENCE")
    }

    /// Priority for data analysis — the seventh phase.
    /// String and pointer data creation should have settled down at this level.
    pub fn data_analysis() -> Self {
        Self::reference_analysis().next("DATA")
    }

    /// Priority for function identification analysis — the eighth phase.
    /// Full function name and class evaluation should occur at this level.
    pub fn function_id_analysis() -> Self {
        Self::data_analysis().next("FUNCTION ID")
    }

    /// Priority for data type propagation — the ninth phase.
    /// Data type propagation analysis should occur as late as possible.
    pub fn data_type_propagation() -> Self {
        Self::function_id_analysis().next("DATA TYPE PROPOGATION")
    }

    /// The lowest priority level (priority = 10000).
    /// Speculative analysis such as scalar-to-pointer conversion should use this level.
    pub fn low_priority() -> Self {
        AnalysisPriority::with_name("LOW", 10000)
    }

    /// The highest priority level (priority = 1).
    /// Reserved for critical analyzers that must run first.
    pub fn highest_priority() -> Self {
        AnalysisPriority::with_name("HIGH", 1)
    }
}

impl fmt::Display for AnalysisPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "[{}]  {}", name, self.priority)
        } else {
            write!(f, "{}", self.priority)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_priority() {
        let p = AnalysisPriority::new(50);
        assert_eq!(p.priority(), 50);
        assert_eq!(p.to_string(), "50");
    }

    #[test]
    fn test_with_name() {
        let p = AnalysisPriority::with_name("TEST", 75);
        assert_eq!(p.priority(), 75);
        assert_eq!(p.to_string(), "[TEST]  75");
    }

    #[test]
    fn test_before() {
        let p = AnalysisPriority::with_name("TEST", 50);
        let before = p.before();
        assert_eq!(before.priority(), 49);
        assert_eq!(before.to_string(), "[TEST-]  49");
    }

    #[test]
    fn test_after() {
        let p = AnalysisPriority::with_name("TEST", 50);
        let after = p.after();
        assert_eq!(after.priority(), 51);
        assert_eq!(after.to_string(), "[TEST+]  51");
    }

    #[test]
    fn test_initial() {
        let p = AnalysisPriority::initial("START");
        assert_eq!(p.priority(), 100);
        assert_eq!(p.to_string(), "[START]  100");
    }

    #[test]
    fn test_next() {
        let p1 = AnalysisPriority::initial("FIRST");
        let p2 = p1.next("SECOND");
        assert_eq!(p2.priority(), 200);
        assert_eq!(p2.to_string(), "[SECOND]  200");
    }

    #[test]
    fn test_format_analysis_chain() {
        let format = AnalysisPriority::format_analysis();
        assert_eq!(format.priority(), 100);
        assert_eq!(format.to_string(), "[FORMAT]  100");

        let block = AnalysisPriority::block_analysis();
        assert_eq!(block.priority(), 200);
        assert_eq!(block.to_string(), "[BLOCK]  200");

        let disassembly = AnalysisPriority::disassembly();
        assert_eq!(disassembly.priority(), 300);
        assert_eq!(disassembly.to_string(), "[DISASSEMBLY]  300");

        let code = AnalysisPriority::code_analysis();
        assert_eq!(code.priority(), 400);
        assert_eq!(code.to_string(), "[CODE]  400");

        let function = AnalysisPriority::function_analysis();
        assert_eq!(function.priority(), 500);
        assert_eq!(function.to_string(), "[FUNCTION]  500");

        let reference = AnalysisPriority::reference_analysis();
        assert_eq!(reference.priority(), 600);
        assert_eq!(reference.to_string(), "[REFERENCE]  600");

        let data = AnalysisPriority::data_analysis();
        assert_eq!(data.priority(), 700);
        assert_eq!(data.to_string(), "[DATA]  700");

        let func_id = AnalysisPriority::function_id_analysis();
        assert_eq!(func_id.priority(), 800);
        assert_eq!(func_id.to_string(), "[FUNCTION ID]  800");

        let propagation = AnalysisPriority::data_type_propagation();
        assert_eq!(propagation.priority(), 900);
        assert_eq!(propagation.to_string(), "[DATA TYPE PROPOGATION]  900");
    }

    #[test]
    fn test_special_priorities() {
        let low = AnalysisPriority::low_priority();
        assert_eq!(low.priority(), 10000);
        assert_eq!(low.to_string(), "[LOW]  10000");

        let high = AnalysisPriority::highest_priority();
        assert_eq!(high.priority(), 1);
        assert_eq!(high.to_string(), "[HIGH]  1");
    }

    #[test]
    fn test_ordering() {
        let p1 = AnalysisPriority::new(100);
        let p2 = AnalysisPriority::new(200);
        assert!(p1 < p2);
        assert!(p2 > p1);
        assert_eq!(p1, p1);
    }

    #[test]
    fn test_before_without_name() {
        let p = AnalysisPriority::new(50);
        let before = p.before();
        assert_eq!(before.priority(), 49);
        assert_eq!(before.to_string(), "49");
    }

    #[test]
    fn test_after_without_name() {
        let p = AnalysisPriority::new(50);
        let after = p.after();
        assert_eq!(after.priority(), 51);
        assert_eq!(after.to_string(), "51");
    }
}
