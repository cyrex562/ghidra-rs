//! Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericPassthroughNode`.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// A [`SwiftNode`] that simply passes through to its child [`SwiftNode`].
///
/// Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericPassthroughNode`.
pub struct SwiftGenericPassthroughNode {
    base: SwiftNodeBase,
}

impl SwiftGenericPassthroughNode {
    /// Create a new `SwiftGenericPassthroughNode`.
    pub fn new(props: NodeProperties) -> Self {
        SwiftGenericPassthroughNode { base: SwiftNodeBase::new(props) }
    }
}

impl SwiftNode for SwiftGenericPassthroughNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: `return demangleFirstChild(demangler);`.
    fn demangle(
        &self,
        demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        self.base.demangle_first_child(demangler).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::demangled_type::DemangledType;
    use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;
    use std::rc::Rc;

    struct FixedNode {
        base: SwiftNodeBase,
        name: String,
    }
    impl FixedNode {
        fn new(kind: SwiftDemangledNodeKind, name: &str) -> Rc<dyn SwiftNode> {
            Rc::new(Self {
                base: SwiftNodeBase::new(NodeProperties::new(kind, None, None, 1, "$s", "orig", true)),
                name: name.to_string(),
            })
        }
    }
    impl SwiftNode for FixedNode {
        fn base(&self) -> &SwiftNodeBase {
            &self.base
        }
        fn demangle(&self, _demangler: &SwiftDemangler) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
            Ok(Some(Box::new(DemangledType::new("$s", &self.name, &self.name))))
        }
    }

    fn link(parent: &Rc<dyn SwiftNode>, child: Rc<dyn SwiftNode>) {
        child.base().set_parent(parent);
        parent.base().add_child(child);
    }

    fn props() -> NodeProperties {
        NodeProperties::new(SwiftDemangledNodeKind::Type, None, None, 0, "$sMangled", "orig", true)
    }

    #[test]
    fn demangles_to_its_first_childs_result() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftGenericPassthroughNode::new(props()));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Structure, "Foo"));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "Foo");
    }

    #[test]
    fn marks_subsequent_children_skipped() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftGenericPassthroughNode::new(props()));
        let first = FixedNode::new(SwiftDemangledNodeKind::Structure, "First");
        let second = FixedNode::new(SwiftDemangledNodeKind::Structure, "Second");
        link(&node, Rc::clone(&first));
        link(&node, Rc::clone(&second));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "First");
        assert!(!first.base().child_was_skipped());
        assert!(second.base().child_was_skipped());
    }

    #[test]
    fn no_children_fails_with_no_children_error() {
        // `Option<Box<dyn Demangled>>` is not `Debug` (`Demangled`'s only supertraits are `Send +
        // Sync + Any`), so `expect_err`/`unwrap_err` (which require `T: Debug`) can't be used here
        // -- matched explicitly instead, mirroring `swift_node.rs`'s own
        // `demangle_first_child_fails_without_children` test.
        let node = SwiftGenericPassthroughNode::new(props());
        let err = match node.demangle(&SwiftDemangler::new()) {
            Ok(_) => panic!("expected a `No children` failure"),
            Err(err) => err,
        };
        assert_eq!(err.to_string(), "No children");
    }

    #[test]
    fn usable_as_a_trait_object() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftGenericPassthroughNode::new(props()));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Structure, "X"));
        let dyn_node: &dyn SwiftNode = &*node;
        assert!(dyn_node.demangle(&SwiftDemangler::new()).is_ok());
    }
}
