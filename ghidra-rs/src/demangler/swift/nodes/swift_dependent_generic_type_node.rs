//! Port of `ghidra.app.util.demangler.swift.nodes.SwiftDependentGenericTypeNode`.

use std::rc::Rc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// A [`SwiftDemangledNodeKind::DependentGenericType`] [`SwiftNode`].
///
/// Port of `ghidra.app.util.demangler.swift.nodes.SwiftDependentGenericTypeNode`.
pub struct SwiftDependentGenericTypeNode {
    base: SwiftNodeBase,
}

impl SwiftDependentGenericTypeNode {
    /// Create a new `SwiftDependentGenericTypeNode`.
    pub fn new(props: NodeProperties) -> Self {
        SwiftDependentGenericTypeNode { base: SwiftNodeBase::new(props) }
    }
}

impl SwiftNode for SwiftDependentGenericTypeNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: demangles the `Type` child (there should be exactly
    /// one), skipping everything else.
    fn demangle(
        &self,
        demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        let mut ty: Option<Box<dyn Demangled>> = None;
        // Cloned up front (mirrors `SwiftNodeBase::demangle_first_child`) so the loop isn't
        // holding the `children` `RefCell` borrow while recursing into `child.demangle(...)`.
        let children: Vec<Rc<dyn SwiftNode>> = self.base.children().clone();
        for child in &children {
            match child.base().kind() {
                SwiftDemangledNodeKind::Type => {
                    ty = child.demangle(demangler)?;
                }
                _ => {
                    self.base.skip(&**child);
                }
            }
        }
        Ok(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::demangled_type::DemangledType;

    fn props(kind: SwiftDemangledNodeKind) -> NodeProperties {
        NodeProperties::new(kind, None, None, 0, "$sMangled", "OriginalDemangled", true)
    }

    /// A leaf test node that demangles to a fixed `DemangledType` named after its "text"
    /// property, or to `None` if it has none -- standing in for real (unported) child node kinds.
    struct FixedNode {
        base: SwiftNodeBase,
    }
    impl FixedNode {
        fn new(kind: SwiftDemangledNodeKind, text: Option<&str>) -> Rc<dyn SwiftNode> {
            Rc::new(Self { base: SwiftNodeBase::new(NodeProperties::new(kind, text.map(str::to_string), None, 1, "$s", "orig", true)) })
        }
    }
    impl SwiftNode for FixedNode {
        fn base(&self) -> &SwiftNodeBase {
            &self.base
        }
        fn demangle(&self, _demangler: &SwiftDemangler) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
            match self.base.text() {
                Some(text) => Ok(Some(Box::new(DemangledType::new("$s", text, text)))),
                None => Ok(None),
            }
        }
    }

    fn link(parent: &Rc<dyn SwiftNode>, child: Rc<dyn SwiftNode>) {
        child.base().set_parent(parent);
        parent.base().add_child(child);
    }

    #[test]
    fn demangles_the_type_child_and_returns_its_result() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftDependentGenericTypeNode::new(props(SwiftDemangledNodeKind::DependentGenericType)));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Type, Some("Foo")));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "Foo");
    }

    #[test]
    fn skips_non_type_children_and_marks_them_skipped() {
        // Java's skip(child) here has an *implicit* `this` receiver (`skip(child)`, not
        // `child.skip(child)`) -- it marks the node performing the skip (this node), not the
        // skipped child. See SwiftDependentGenericTypeNode.java's own `skip(child)` call versus
        // demangleFirstChild's `child.skip(child)` (a genuinely different call site/receiver).
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftDependentGenericTypeNode::new(props(SwiftDemangledNodeKind::DependentGenericType)));
        let other = FixedNode::new(SwiftDemangledNodeKind::Identifier, Some("Ignored"));
        link(&node, Rc::clone(&other));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Type, Some("Bar")));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "Bar");
        assert!(node.base().child_was_skipped());
    }

    #[test]
    fn with_no_children_returns_none() {
        let node = SwiftDependentGenericTypeNode::new(props(SwiftDemangledNodeKind::DependentGenericType));
        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles");
        assert!(demangled.is_none());
    }

    #[test]
    fn later_type_children_overwrite_earlier_ones() {
        // Java: `type = child.demangle(demangler);` unconditionally overwrites on every `Type`
        // child seen, so the last one wins.
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftDependentGenericTypeNode::new(props(SwiftDemangledNodeKind::DependentGenericType)));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Type, Some("First")));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Type, Some("Second")));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "Second");
    }

    #[test]
    fn a_type_child_that_demangles_to_nothing_yields_none() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftDependentGenericTypeNode::new(props(SwiftDemangledNodeKind::DependentGenericType)));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Type, None));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles");
        assert!(demangled.is_none());
    }
}
