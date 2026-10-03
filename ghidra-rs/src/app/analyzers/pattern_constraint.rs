use crate::util::classfinder::ExtensionPoint;

/// Marker trait for pattern constraint implementations.
///
/// Port of `ghidra.app.analyzers.PatternConstraint`. Extends `ExtensionPoint` for
/// Ghidra's type discovery framework. Implementations define constraints that filter
/// or validate patterns in the analysis pipeline.
pub trait PatternConstraint: ExtensionPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPatternConstraint;

    impl ExtensionPoint for TestPatternConstraint {}

    impl PatternConstraint for TestPatternConstraint {}

    #[test]
    fn pattern_constraint_trait_is_implementable() {
        let _constraint: Box<dyn PatternConstraint> = Box::new(TestPatternConstraint);
    }
}
