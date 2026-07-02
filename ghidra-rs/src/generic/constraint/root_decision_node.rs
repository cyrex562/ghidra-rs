use super::constraint::Constraint;
use super::constraint_data::ConstraintData;
use super::decision_node::NodeRef;

struct DummyConstraint<T: Send + Sync> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Send + Sync> Constraint<T> for DummyConstraint<T> {
    fn name(&self) -> &str {
        ""
    }

    fn is_satisfied(&self, _obj: &T) -> bool {
        true
    }

    fn load_constraint_data(&mut self, _data: &ConstraintData) {
    }

    fn equals(&self, other: &dyn Constraint<T>) -> bool {
        std::ptr::eq(self as *const _, other as *const dyn Constraint<T>)
    }

    fn get_description(&self) -> String {
        String::new()
    }
}

/// Creates a root node for a decision tree. Root nodes have no parent and use a dummy constraint
/// that is always satisfied.
pub fn new_root_decision_node<T: Send + Sync + 'static>() -> NodeRef<T> {
    let dummy_constraint: Box<dyn Constraint<T>> = Box::new(DummyConstraint {
        _phantom: std::marker::PhantomData,
    });
    super::decision_node::DecisionNode::new(dummy_constraint, None)
}

#[cfg(test)]
mod tests {
    use super::super::decision_set::DecisionSet;
    use super::*;

    #[test]
    fn root_node_decision_path_is_empty() {
        let root = new_root_decision_node::<()>();
        assert_eq!(root.borrow().to_string(), "");
    }

    #[test]
    fn root_node_constraint_always_satisfied_finds_property() {
        let root = new_root_decision_node::<i32>();
        root.borrow_mut().set_property("KEY", "root_value", "source").unwrap();

        let mut decision_set = DecisionSet::new("KEY".to_string());
        let found = root.borrow().populate_decisions(&42, &mut decision_set, "KEY");

        assert!(found);
        assert_eq!(decision_set.decisions().len(), 1);
        assert_eq!(decision_set.decisions()[0].value(), "root_value");
        assert_eq!(decision_set.decisions()[0].decision_path().len(), 0);
    }

    #[test]
    fn root_node_can_create_children() {
        struct SimpleConstraint;

        impl Constraint<i32> for SimpleConstraint {
            fn name(&self) -> &str {
                "simple"
            }

            fn is_satisfied(&self, _obj: &i32) -> bool {
                true
            }

            fn load_constraint_data(&mut self, _data: &ConstraintData) {
            }

            fn equals(&self, other: &dyn Constraint<i32>) -> bool {
                other.name() == "simple"
            }

            fn get_description(&self) -> String {
                "Simple".to_string()
            }
        }

        let root = new_root_decision_node::<i32>();
        let child = root.borrow_mut().get_or_create_node_for_constraint(Box::new(SimpleConstraint));
        root.borrow_mut().set_property("KEY", "root_value", "source").unwrap();
        child.borrow_mut().set_property("KEY", "child_value", "source").unwrap();

        let mut decision_set = DecisionSet::new("KEY".to_string());
        root.borrow().populate_decisions(&1, &mut decision_set, "KEY");

        assert_eq!(decision_set.decisions().len(), 1);
        assert_eq!(decision_set.decisions()[0].value(), "child_value");
        assert_eq!(decision_set.decisions()[0].decision_path(), &["Simple"]);
    }
}
