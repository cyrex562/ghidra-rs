//! Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericTextNode`.

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::demangled_label::DemangledLabel;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// A [`SwiftNode`] that just contains text.
///
/// Port of `ghidra.app.util.demangler.swift.nodes.generic.SwiftGenericTextNode`.
pub struct SwiftGenericTextNode {
    base: SwiftNodeBase,
}

impl SwiftGenericTextNode {
    /// Create a new `SwiftGenericTextNode`.
    pub fn new(props: NodeProperties) -> Self {
        SwiftGenericTextNode { base: SwiftNodeBase::new(props) }
    }
}

impl SwiftNode for SwiftGenericTextNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: `new DemangledLabel(properties.mangled(),
    /// properties.originalDemangled(), getText())`. See
    /// [`super::swift_generic_index_node::SwiftGenericIndexNode::demangle`]'s docs for why a
    /// missing "text" attribute falls back to an empty string rather than mirroring a Java-side
    /// crash that doesn't actually occur at this call site.
    fn demangle(
        &self,
        _demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        let text = self.base.properties.text.as_deref().unwrap_or_default();
        Ok(Some(Box::new(DemangledLabel::new(
            self.base.properties.mangled.clone(),
            self.base.properties.original_demangled.clone(),
            text,
        ))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;

    #[test]
    fn demangle_produces_a_demangled_label_named_after_the_text() {
        let props = NodeProperties::new(
            SwiftDemangledNodeKind::Identifier,
            Some("SomeText".to_string()),
            None,
            0,
            "$sMangled",
            "OriginalDemangled",
            true,
        );
        let node = SwiftGenericTextNode::new(props);

        let demangled = node.demangle(&SwiftDemangler::new()).expect("never fails").expect("always Some");
        assert_eq!(demangled.get_mangled_string(), "$sMangled");
        assert_eq!(demangled.get_original_demangled(), "OriginalDemangled");
        assert_eq!(demangled.get_name(), "SomeText");
    }

    #[test]
    fn missing_text_falls_back_to_an_empty_name() {
        let props = NodeProperties::new(SwiftDemangledNodeKind::Identifier, None, None, 0, "$s", "orig", true);
        let node = SwiftGenericTextNode::new(props);

        let demangled = node.demangle(&SwiftDemangler::new()).expect("never fails").expect("always Some");
        assert_eq!(demangled.get_name(), "");
    }

    #[test]
    fn base_accessor_reaches_shared_node_state() {
        let props = NodeProperties::new(
            SwiftDemangledNodeKind::Identifier,
            Some("Foo".to_string()),
            None,
            2,
            "$s",
            "orig",
            true,
        );
        let node = SwiftGenericTextNode::new(props);
        assert_eq!(node.base().kind(), SwiftDemangledNodeKind::Identifier);
        assert_eq!(node.base().text(), Some("Foo"));
        assert_eq!(node.base().depth(), 2);
    }

    #[test]
    fn usable_as_a_trait_object() {
        let props = NodeProperties::new(SwiftDemangledNodeKind::Identifier, Some("X".to_string()), None, 0, "$s", "orig", true);
        let node: Box<dyn SwiftNode> = Box::new(SwiftGenericTextNode::new(props));
        assert!(node.demangle(&SwiftDemangler::new()).is_ok());
    }
}
