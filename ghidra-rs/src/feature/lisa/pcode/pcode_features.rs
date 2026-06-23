/// Strategy used to match actual arguments to formal parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParameterMatchingStrategy {
    /// Java-like overload resolution: exact type or compatible supertype.
    JavaLike,
}

/// Strategy used to traverse a type hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HierarchyTraversalStrategy {
    /// Walk up a single-inheritance chain one parent at a time.
    SingleInheritance,
}

/// Strategy used to assign actual arguments to formal parameter positions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParameterAssigningStrategy {
    /// Python-like assignment: positional with flexible handling of extras.
    PythonLike,
}

/// Logic applied to validate a program before analysis begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramValidationLogic {
    /// Base structural validation — checks well-formedness of the program graph.
    Base,
}

/// Language feature configuration for the Pcode frontend.
///
/// Configures the LiSA analysis framework with strategies appropriate for
/// Pcode IR. Per the original source, most of these strategies are not deeply
/// relevant for the Pcode frontend but are required by the framework contract.
///
/// Corresponds to `ghidra.lisa.pcode.PcodeFeatures` in the Java source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PcodeFeatures;

impl PcodeFeatures {
    /// Returns the parameter matching strategy (Java-like overload resolution).
    pub fn matching_strategy(self) -> ParameterMatchingStrategy {
        ParameterMatchingStrategy::JavaLike
    }

    /// Returns the hierarchy traversal strategy (single-inheritance chain).
    pub fn traversal_strategy(self) -> HierarchyTraversalStrategy {
        HierarchyTraversalStrategy::SingleInheritance
    }

    /// Returns the parameter assigning strategy (Python-like assignment).
    pub fn assigning_strategy(self) -> ParameterAssigningStrategy {
        ParameterAssigningStrategy::PythonLike
    }

    /// Returns the program validation logic (base structural checks).
    pub fn program_validation_logic(self) -> ProgramValidationLogic {
        ProgramValidationLogic::Base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_strategy_is_java_like() {
        assert_eq!(PcodeFeatures.matching_strategy(), ParameterMatchingStrategy::JavaLike);
    }

    #[test]
    fn traversal_strategy_is_single_inheritance() {
        assert_eq!(
            PcodeFeatures.traversal_strategy(),
            HierarchyTraversalStrategy::SingleInheritance
        );
    }

    #[test]
    fn assigning_strategy_is_python_like() {
        assert_eq!(
            PcodeFeatures.assigning_strategy(),
            ParameterAssigningStrategy::PythonLike
        );
    }

    #[test]
    fn program_validation_logic_is_base() {
        assert_eq!(
            PcodeFeatures.program_validation_logic(),
            ProgramValidationLogic::Base
        );
    }

    #[test]
    fn pcode_features_is_copy_and_eq() {
        let a = PcodeFeatures;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn default_equals_unit_struct() {
        assert_eq!(PcodeFeatures::default(), PcodeFeatures);
    }
}
