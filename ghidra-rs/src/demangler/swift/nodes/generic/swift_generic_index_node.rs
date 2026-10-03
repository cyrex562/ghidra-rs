//! Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericIndexNode`.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_label::DemangledLabel;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// A [`SwiftNode`] that just contains an index.
///
/// Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericIndexNode`.
pub struct SwiftGenericIndexNode {
    base: SwiftNodeBase,
}

impl SwiftGenericIndexNode {
    /// Create a new `SwiftGenericIndexNode`.
    pub fn new(props: NodeProperties) -> Self {
        SwiftGenericIndexNode { base: SwiftNodeBase::new(props) }
    }
}

impl SwiftNode for SwiftGenericIndexNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: `new DemangledLabel(properties.mangled(),
    /// properties.originalDemangled(), getIndex())`. Java's `getIndex()` may be `null` if the
    /// "index" attribute is absent, and Java tolerates a null `name` flowing into `Demangled`'s
    /// nullable name field; [`DemangledLabel::new`] in this port requires a `&str`, so a missing
    /// index falls back to an empty string rather than mirroring a Java-side crash that doesn't
    /// actually occur at this call site.
    fn demangle(
        &self,
        _demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        let index = self.base.properties.index.as_deref().unwrap_or_default();
        Ok(Some(Box::new(DemangledLabel::new(
            self.base.properties.mangled.clone(),
            self.base.properties.original_demangled.clone(),
            index,
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;

    #[test]
    fn demangle_produces_a_demangled_label_named_after_the_index() {
        let props = NodeProperties::new(
            SwiftDemangledNodeKind::Number,
            None,
            Some("7".to_string()),
            0,
            "$sMangled",
            "OriginalDemangled",
            true,
        );
        let node = SwiftGenericIndexNode::new(props);

        let demangled = node.demangle(&SwiftDemangler::new()).expect("never fails").expect("always Some");
        assert_eq!(demangled.get_mangled_string(), "$sMangled");
        assert_eq!(demangled.get_original_demangled(), "OriginalDemangled");
        assert_eq!(demangled.get_name(), "7");
    }

    #[test]
    fn missing_index_falls_back_to_an_empty_name() {
        let props = NodeProperties::new(
            SwiftDemangledNodeKind::Number,
            None,
            None,
            0,
            "$s",
            "orig",
            true,
        );
        let node = SwiftGenericIndexNode::new(props);

        let demangled = node.demangle(&SwiftDemangler::new()).expect("never fails").expect("always Some");
        assert_eq!(demangled.get_name(), "");
    }

    #[test]
    fn base_accessor_reaches_shared_node_state() {
        let props = NodeProperties::new(SwiftDemangledNodeKind::Number, None, Some("3".to_string()), 2, "$s", "orig", true);
        let node = SwiftGenericIndexNode::new(props);
        assert_eq!(node.base().kind(), SwiftDemangledNodeKind::Number);
        assert_eq!(node.base().index(), Some("3"));
        assert_eq!(node.base().depth(), 2);
    }

    #[test]
    fn usable_as_a_trait_object() {
        let props = NodeProperties::new(SwiftDemangledNodeKind::Number, None, Some("1".to_string()), 0, "$s", "orig", true);
        let node: Box<dyn SwiftNode> = Box::new(SwiftGenericIndexNode::new(props));
        assert!(node.demangle(&SwiftDemangler::new()).is_ok());
    }
}
