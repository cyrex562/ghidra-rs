//! Port of `ghidra.app.util.demangler.swift.nodes.SwiftUnsupportedNode`.

use std::fmt;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// An "unsupported node kind" [`SwiftNode`].
///
/// Port of `ghidra.app.util.demangler.swift.nodes.SwiftUnsupportedNode`, the first real
/// (non-test) implementor of the [`SwiftNode`]/[`SwiftNodeBase`] split -- see that module's docs
/// for the split's rationale. Construction returns a plain `Self`; callers that need to wire this
/// node into a shared demangled tree wrap it in `Rc::new`, the same way the sibling module's own
/// `TestNode` factory does.
pub struct SwiftUnsupportedNode {
    base: SwiftNodeBase,

    /// The original, unsupported [`SwiftDemangledNodeKind`](crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind)
    /// of [`SwiftNode`] this node stands in for. Mirrors the `private String originalKind` field.
    original_kind: String,
}

impl SwiftUnsupportedNode {
    /// Create a new `SwiftUnsupportedNode`.
    ///
    /// Port of `SwiftUnsupportedNode(String originalKind, NodeProperties props)`.
    ///
    /// * `original_kind` - The original kind of [`SwiftNode`] that is not supported
    /// * `props` - The node's [`NodeProperties`]
    pub fn new(original_kind: impl Into<String>, props: NodeProperties) -> Self {
        SwiftUnsupportedNode { base: SwiftNodeBase::new(props), original_kind: original_kind.into() }
    }
}

impl SwiftNode for SwiftUnsupportedNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: marks this node as having skipped a child (mirroring
    /// Java's `skip(this)` -- see [`SwiftNodeBase::skip`]'s docs for why the argument is ignored
    /// either way), then returns the generic "unknown" demangling.
    fn demangle(
        &self,
        _demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        self.base.skip(self);
        Ok(Some(Box::new(self.base.unknown())))
    }
}

impl fmt::Display for SwiftUnsupportedNode {
    /// Port of `toString()`: `super.toString() + " (" + originalKind + ")"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.base, self.original_kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;

    fn props(kind: SwiftDemangledNodeKind) -> NodeProperties {
        NodeProperties::new(kind, None, None, 0, "$s4main3FooV", "main.Foo", true)
    }

    #[test]
    fn demangle_marks_child_skipped_and_returns_unknown() {
        let node = SwiftUnsupportedNode::new("SomeWeirdKind", props(SwiftDemangledNodeKind::Unsupported));
        assert!(!node.base().child_was_skipped());

        let demangled = node
            .demangle(&SwiftDemangler::new())
            .expect("demangle never fails")
            .expect("always returns Some");

        assert!(node.base().child_was_skipped());
        assert_eq!(demangled.get_mangled_string(), "$s4main3FooV");
        assert_eq!(demangled.get_original_demangled(), "main.Foo");
    }

    #[test]
    fn to_string_appends_the_original_kind_in_parens() {
        let node = SwiftUnsupportedNode::new("WeirdKind", props(SwiftDemangledNodeKind::Unsupported));
        let base_string = node.base().to_string();
        assert_eq!(node.to_string(), format!("{base_string} (WeirdKind)"));
        assert!(node.to_string().ends_with("(WeirdKind)"));
    }

    #[test]
    fn base_accessor_reaches_shared_node_state() {
        let node = SwiftUnsupportedNode::new("X", props(SwiftDemangledNodeKind::Unsupported));
        assert_eq!(node.base().kind(), SwiftDemangledNodeKind::Unsupported);
        assert_eq!(node.base().depth(), 0);
    }

    #[test]
    fn usable_as_a_trait_object() {
        let node: Box<dyn SwiftNode> =
            Box::new(SwiftUnsupportedNode::new("X", props(SwiftDemangledNodeKind::Unsupported)));
        let result = node.demangle(&SwiftDemangler::new());
        assert!(result.is_ok());
    }
}
