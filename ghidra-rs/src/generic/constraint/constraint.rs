use super::constraint_data::ConstraintData;

/// Constraints are used to make decisions to traverse a decision tree where each node in the
/// tree has a constraint that is used to decide if that node is part of the successful decision path.
///
/// Implementers must provide a name (used as an XML tag), test whether an object satisfies the
/// constraint, initialize from XML data, and provide equality and description methods.
pub trait Constraint<T>: Send + Sync {
    /// Returns the name of the constraint. Note: this name is also the XML tag used in the
    /// constraints specification files.
    fn name(&self) -> &str;

    /// Returns true if the given object satisfies this constraint.
    fn is_satisfied(&self, obj: &T) -> bool;

    /// Initializes this constraint's state. Attributes in the XML element with this
    /// constraint's tag name will be extracted into the ConstraintData object for easy retrieval.
    fn load_constraint_data(&mut self, data: &ConstraintData);

    /// Returns true if this constraint is equal to the other object.
    ///
    /// Note: Constraints must override equality. This is critical for correctness.
    fn equals(&self, other: &dyn Constraint<T>) -> bool;

    /// Returns a description of this constraint (with its configuration data) to be used
    /// to journal the decision path that was taken.
    fn get_description(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct SimpleConstraint {
        name: String,
    }

    impl Constraint<String> for SimpleConstraint {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_satisfied(&self, obj: &String) -> bool {
            obj == "test"
        }

        fn load_constraint_data(&mut self, _data: &ConstraintData) {
        }

        fn equals(&self, other: &dyn Constraint<String>) -> bool {
            self.name() == other.name()
        }

        fn get_description(&self) -> String {
            format!("SimpleConstraint[{}]", self.name)
        }
    }

    #[test]
    fn test_constraint_name() {
        let constraint = SimpleConstraint {
            name: "my_constraint".to_string(),
        };
        assert_eq!(constraint.name(), "my_constraint");
    }

    #[test]
    fn test_constraint_is_satisfied_true() {
        let constraint = SimpleConstraint {
            name: "test".to_string(),
        };
        assert!(constraint.is_satisfied(&"test".to_string()));
    }

    #[test]
    fn test_constraint_is_satisfied_false() {
        let constraint = SimpleConstraint {
            name: "test".to_string(),
        };
        assert!(!constraint.is_satisfied(&"other".to_string()));
    }

    #[test]
    fn test_constraint_equals() {
        let c1 = SimpleConstraint {
            name: "test".to_string(),
        };
        let c2 = SimpleConstraint {
            name: "test".to_string(),
        };
        assert!(c1.equals(&c2 as &dyn Constraint<String>));
    }

    #[test]
    fn test_constraint_not_equals() {
        let c1 = SimpleConstraint {
            name: "test1".to_string(),
        };
        let c2 = SimpleConstraint {
            name: "test2".to_string(),
        };
        assert!(!c1.equals(&c2 as &dyn Constraint<String>));
    }

    #[test]
    fn test_constraint_get_description() {
        let constraint = SimpleConstraint {
            name: "my_constraint".to_string(),
        };
        let desc = constraint.get_description();
        assert!(desc.contains("my_constraint"));
    }
}
