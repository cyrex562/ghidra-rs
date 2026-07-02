use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::{Rc, Weak};

use super::constraint::Constraint;
use super::decision::Decision;
use super::decision_set::DecisionSet;
use crate::util::xml::xml_parse_exception::XmlParseException;

/// Shared-ownership reference to a [`DecisionNode`].
pub type NodeRef<T> = Rc<RefCell<DecisionNode<T>>>;

/// Weak (non-owning) reference to a [`DecisionNode`], used for the parent link.
pub type WeakNodeRef<T> = Weak<RefCell<DecisionNode<T>>>;

struct PropertyValue {
    value: String,
    source: String,
}

/// A node in a decision tree. Each node contains exactly one constraint and a map of property
/// values.
///
/// `T` is the type of objects that the constraint operates on. Mirrors
/// `generic.constraint.DecisionNode`.
pub struct DecisionNode<T> {
    self_ref: WeakNodeRef<T>,
    property_map: HashMap<String, PropertyValue>,
    constraint: Box<dyn Constraint<T>>,
    children: Vec<NodeRef<T>>,
    parent: Option<WeakNodeRef<T>>,
}

impl<T> DecisionNode<T> {
    /// Creates a new node with the given `constraint` and `parent`. A `parent` of `None`
    /// marks this node as the root of its tree.
    pub fn new(constraint: Box<dyn Constraint<T>>, parent: Option<&NodeRef<T>>) -> NodeRef<T> {
        Rc::new_cyclic(|weak| {
            RefCell::new(DecisionNode {
                self_ref: weak.clone(),
                property_map: HashMap::new(),
                constraint,
                children: Vec::new(),
                parent: parent.map(Rc::downgrade),
            })
        })
    }

    /// Returns the child whose constraint equals `new_constraint`, creating and appending a
    /// new child node for it if none of the existing children match.
    pub fn get_or_create_node_for_constraint(
        &mut self,
        new_constraint: Box<dyn Constraint<T>>,
    ) -> NodeRef<T> {
        for child in &self.children {
            if new_constraint.equals(child.borrow().constraint.as_ref()) {
                return Rc::clone(child);
            }
        }
        let parent = self.self_ref.upgrade();
        let new_child = DecisionNode::new(new_constraint, parent.as_ref());
        self.children.push(Rc::clone(&new_child));
        new_child
    }

    /// Associates `property_name` with `value` (recording `source` for later reporting).
    ///
    /// Returns an error if this node already has a value for `property_name`.
    pub(crate) fn set_property(
        &mut self,
        property_name: &str,
        value: &str,
        source: &str,
    ) -> Result<(), XmlParseException> {
        if self.property_map.contains_key(property_name) {
            return Err(XmlParseException::new(format!(
                "Attempted to overwrite property value for {} in contraint node: {}",
                property_name, self
            )));
        }
        self.property_map.insert(
            property_name.to_string(),
            PropertyValue { value: value.to_string(), source: source.to_string() },
        );
        Ok(())
    }

    /// Tests `t` against this node's constraint and, if satisfied, recurses into its children
    /// looking for `property_name`. If none of the children find a more specific decision and
    /// this node has a value for `property_name`, that value is recorded as a decision.
    ///
    /// Returns `true` if a decision was found at or below this node.
    pub fn populate_decisions(
        &self,
        t: &T,
        decision_set: &mut DecisionSet,
        property_name: &str,
    ) -> bool {
        if !self.constraint.is_satisfied(t) {
            return false;
        }

        let mut decision_found = false;
        for child in &self.children {
            decision_found |= child.borrow().populate_decisions(t, decision_set, property_name);
        }

        // if no child found a more specific decision, see if we have a value for the property
        if !decision_found {
            if let Some(value) = self.property_map.get(property_name) {
                let decision_path = self.get_decision_path();
                decision_set.add_decision(Decision::new(
                    value.value.clone(),
                    decision_path,
                    value.source.clone(),
                ));
                decision_found = true;
            }
        }

        decision_found
    }

    /// Returns the descriptions of the constraints from just below the root down to this node.
    ///
    /// A node with no parent is the root of the tree and contributes nothing to the path.
    fn get_decision_path(&self) -> Vec<String> {
        let parent = match self.parent.as_ref().and_then(|w| w.upgrade()) {
            Some(parent) => parent,
            None => return Vec::new(),
        };
        let mut decision_path = parent.borrow().get_decision_path();
        decision_path.push(self.constraint.get_description());
        decision_path
    }
}

impl<T> fmt::Display for DecisionNode<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in self.get_decision_path() {
            write!(f, "/{}", segment)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::constraint_data::ConstraintData;

    struct FixedConstraint {
        id: String,
        description: String,
        satisfied: bool,
    }

    impl Constraint<i32> for FixedConstraint {
        fn name(&self) -> &str {
            &self.id
        }

        fn is_satisfied(&self, _obj: &i32) -> bool {
            self.satisfied
        }

        fn load_constraint_data(&mut self, _data: &ConstraintData) {
        }

        fn equals(&self, other: &dyn Constraint<i32>) -> bool {
            self.id == other.name()
        }

        fn get_description(&self) -> String {
            self.description.clone()
        }
    }

    fn constraint(id: &str, description: &str, satisfied: bool) -> Box<dyn Constraint<i32>> {
        Box::new(FixedConstraint {
            id: id.to_string(),
            description: description.to_string(),
            satisfied,
        })
    }

    #[test]
    fn get_or_create_node_for_constraint_creates_new_child() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let child = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("a", "A", true));
        assert!(!Rc::ptr_eq(&root, &child));
        assert!(Rc::ptr_eq(&child.borrow().parent.as_ref().unwrap().upgrade().unwrap(), &root));
    }

    #[test]
    fn get_or_create_node_for_constraint_reuses_matching_child() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let first = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("a", "A", true));
        let second = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("a", "A-again", true));
        assert!(Rc::ptr_eq(&first, &second));
    }

    #[test]
    fn get_or_create_node_for_constraint_distinct_for_different_constraints() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let a = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("a", "A", true));
        let b = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("b", "B", true));
        assert!(!Rc::ptr_eq(&a, &b));
    }

    #[test]
    fn set_property_succeeds() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let result = root.borrow_mut().set_property("NAME", "WHITE", "colors.xml");
        assert!(result.is_ok());
    }

    #[test]
    fn set_property_rejects_duplicate() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        root.borrow_mut().set_property("NAME", "WHITE", "colors.xml").unwrap();
        let result = root.borrow_mut().set_property("NAME", "BLACK", "colors.xml");
        assert!(result.is_err());
        assert!(result.unwrap_err().message().contains("NAME"));
    }

    #[test]
    fn populate_decisions_false_when_own_constraint_unsatisfied() {
        let node = DecisionNode::new(constraint("root", "root", false), None);
        node.borrow_mut().set_property("NAME", "WHITE", "colors.xml").unwrap();
        let mut decision_set = DecisionSet::new("NAME".to_string());
        let found = node.borrow().populate_decisions(&1, &mut decision_set, "NAME");
        assert!(!found);
        assert!(decision_set.is_empty());
    }

    #[test]
    fn populate_decisions_false_when_no_property_and_no_children() {
        let node = DecisionNode::new(constraint("root", "root", true), None);
        let mut decision_set = DecisionSet::new("NAME".to_string());
        let found = node.borrow().populate_decisions(&1, &mut decision_set, "NAME");
        assert!(!found);
        assert!(decision_set.is_empty());
    }

    #[test]
    fn populate_decisions_uses_own_property_when_no_child_matches() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        root.borrow_mut().set_property("NAME", "UNKNOWN", "colors.xml").unwrap();

        let mut decision_set = DecisionSet::new("NAME".to_string());
        let found = root.borrow().populate_decisions(&1, &mut decision_set, "NAME");

        assert!(found);
        assert_eq!(decision_set.decisions().len(), 1);
        let decision = &decision_set.decisions()[0];
        assert_eq!(decision.value(), "UNKNOWN");
        assert_eq!(decision.source(), "colors.xml");
        // The root contributes nothing to the decision path.
        assert!(decision.decision_path().is_empty());
    }

    #[test]
    fn populate_decisions_prefers_child_decision_over_own_property() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        root.borrow_mut().set_property("NAME", "UNKNOWN", "colors.xml").unwrap();
        let child = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("red", "Red value = 255", true));
        child.borrow_mut().set_property("NAME", "RED", "colors.xml").unwrap();

        let mut decision_set = DecisionSet::new("NAME".to_string());
        let found = root.borrow().populate_decisions(&1, &mut decision_set, "NAME");

        assert!(found);
        assert_eq!(decision_set.decisions().len(), 1);
        assert_eq!(decision_set.decisions()[0].value(), "RED");
    }

    #[test]
    fn populate_decisions_builds_full_path_from_root_to_leaf() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let red = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("red", "Red value = 255", true));
        let blue = red
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("blue", "Blue value = 255", true));
        blue.borrow_mut().set_property("NAME", "WHITE", "ColorXML1").unwrap();

        let mut decision_set = DecisionSet::new("NAME".to_string());
        let found = root.borrow().populate_decisions(&1, &mut decision_set, "NAME");

        assert!(found);
        let decision = &decision_set.decisions()[0];
        assert_eq!(decision.value(), "WHITE");
        assert_eq!(decision.source(), "ColorXML1");
        assert_eq!(decision.decision_path(), &["Red value = 255", "Blue value = 255"]);
    }

    #[test]
    fn to_string_joins_decision_path_with_slashes() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        let red = root
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("red", "Red value = 255", true));
        let blue = red
            .borrow_mut()
            .get_or_create_node_for_constraint(constraint("blue", "Blue value = 255", true));
        assert_eq!(blue.borrow().to_string(), "/Red value = 255/Blue value = 255");
    }

    #[test]
    fn to_string_empty_for_root_with_no_ancestors() {
        let root = DecisionNode::new(constraint("root", "root", true), None);
        assert_eq!(root.borrow().to_string(), "");
    }
}
