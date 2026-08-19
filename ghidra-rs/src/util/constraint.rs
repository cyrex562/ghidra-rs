use crate::generic::constraint::constraint_data::ConstraintData;
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use std::any::Any;

/// A constraint on a Program.
///
/// Implementations of this trait are Program-specific constraints that can be used to make
/// decisions based on program characteristics. Implementers must satisfy the requirements of
/// the constraint interface and be marked as extension points for dynamic discovery.
///
/// Port of `ghidra.util.constraint.ProgramConstraint`.
pub trait ProgramConstraint: Send + Sync + ExtensionPoint + Any {
    /// Returns the name of the constraint.
    fn name(&self) -> &str;

    /// Returns true if the given program satisfies this constraint.
    fn is_satisfied(&self, obj: &dyn Program) -> bool;

    /// Initializes this constraint's state from the provided constraint data.
    fn load_constraint_data(&mut self, data: &ConstraintData);

    /// Returns true if this constraint is equal to the other constraint.
    fn equals(&self, other: &dyn ProgramConstraint) -> bool;

    /// Returns a description of this constraint for journaling purposes.
    fn get_description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestConstraint {
        name: String,
    }

    impl ProgramConstraint for TestConstraint {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_satisfied(&self, _obj: &dyn Program) -> bool {
            true
        }

        fn load_constraint_data(&mut self, _data: &ConstraintData) {}

        fn equals(&self, other: &dyn ProgramConstraint) -> bool {
            self.name() == other.name()
        }

        fn get_description(&self) -> String {
            format!("TestConstraint[{}]", self.name)
        }
    }

    impl ExtensionPoint for TestConstraint {}

    #[test]
    fn implements_program_constraint() {
        let constraint = TestConstraint {
            name: "test".to_string(),
        };
        let _pc: &dyn ProgramConstraint = &constraint;
    }

    #[test]
    fn trait_name_is_accessible() {
        let constraint = TestConstraint {
            name: "my_program_constraint".to_string(),
        };
        assert_eq!(constraint.name(), "my_program_constraint");
    }

    #[test]
    fn description_is_generated() {
        let constraint = TestConstraint {
            name: "test_desc".to_string(),
        };
        let desc = constraint.get_description();
        assert!(desc.contains("test_desc"));
    }

    #[test]
    fn equals_same_name() {
        let c1 = TestConstraint {
            name: "test".to_string(),
        };
        let c2 = TestConstraint {
            name: "test".to_string(),
        };
        assert!(c1.equals(&c2));
    }

    #[test]
    fn not_equals_different_name() {
        let c1 = TestConstraint {
            name: "test1".to_string(),
        };
        let c2 = TestConstraint {
            name: "test2".to_string(),
        };
        assert!(!c1.equals(&c2));
    }

    #[test]
    fn trait_object_dispatch() {
        let constraint = TestConstraint {
            name: "dispatch_test".to_string(),
        };
        let pc: &dyn ProgramConstraint = &constraint;
        assert_eq!(pc.name(), "dispatch_test");
    }
}
