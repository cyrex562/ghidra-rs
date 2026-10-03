//! Port of `ghidra.app.util.demangler.swift.nodes.SwiftExtensionNode`.

use std::rc::Rc;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::demangled::Demangled;
use crate::demangler::swift::nodes::swift_node::{NodeProperties, SwiftNode, SwiftNodeBase};
use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;
use crate::demangler::swift::swift_demangler::SwiftDemangler;

/// A [`SwiftDemangledNodeKind::Extension`] [`SwiftNode`].
///
/// Port of `ghidra.app.util.demangler.swift.nodes.SwiftExtensionNode`.
pub struct SwiftExtensionNode {
    base: SwiftNodeBase,
}

impl SwiftExtensionNode {
    /// Create a new `SwiftExtensionNode`.
    pub fn new(props: NodeProperties) -> Self {
        SwiftExtensionNode { base: SwiftNodeBase::new(props) }
    }
}

impl SwiftNode for SwiftExtensionNode {
    fn base(&self) -> &SwiftNodeBase {
        &self.base
    }

    /// Port of `demangle(SwiftDemangler)`: demangles the `Module` child as the extension's
    /// namespace (renaming it to `"(extension_<name>)"`) and the `Class`/`Enum`/`Protocol`/
    /// `Structure` child as the extended type, then splices the namespace beneath the type's own
    /// (shallow, one level -- not walked to the top, unlike
    /// [`crate::demangler::swift::nodes::swift_node::join`]) namespace if it already has one.
    fn demangle(
        &self,
        demangler: &SwiftDemangler,
    ) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
        let mut namespace: Option<Box<dyn Demangled>> = None;
        let mut ty: Option<Box<dyn Demangled>> = None;

        let children: Vec<Rc<dyn SwiftNode>> = self.base.children().clone();
        for child in &children {
            match child.base().kind() {
                SwiftDemangledNodeKind::Module => {
                    let mut ns = child.demangle(demangler)?;
                    // Java calls `namespace.setName(...)` unconditionally, with no null check --
                    // if the Module child demangled to `null` (`None` here), that's an NPE in
                    // Java. Faithfully reproduced as a panic rather than silently guarding it.
                    let ns_ref = ns.as_deref_mut().expect(
                        "NullPointerException: Module child demangled to null",
                    );
                    let new_name = format!("(extension_{})", ns_ref.get_name());
                    ns_ref.set_name(&new_name);
                    namespace = ns;
                }
                SwiftDemangledNodeKind::Class
                | SwiftDemangledNodeKind::Enum
                | SwiftDemangledNodeKind::Protocol
                | SwiftDemangledNodeKind::Structure => {
                    ty = child.demangle(demangler)?;
                }
                _ => {
                    self.base.skip(&**child);
                }
            }
        }

        let (Some(mut ty), Some(namespace)) = (ty, namespace) else {
            return Ok(Some(Box::new(self.base.unknown())));
        };

        if ty.get_namespace().is_some() {
            let type_namespace = ty.get_namespace_mut().expect("checked Some above");
            type_namespace.set_namespace(Some(namespace));
        } else {
            ty.set_namespace(Some(namespace));
        }
        Ok(Some(ty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demangler::demangled_type::DemangledType;

    fn props(kind: SwiftDemangledNodeKind) -> NodeProperties {
        NodeProperties::new(kind, None, None, 0, "$sMangled", "OriginalDemangled", true)
    }

    struct FixedNode {
        base: SwiftNodeBase,
        result: RefCellResult,
    }

    /// Interior mutability wrapper letting each `FixedNode` hand back a distinct, owned
    /// `Demangled` on demand (mirrors real Swift child nodes, each producing a fresh object).
    struct RefCellResult(std::cell::RefCell<Option<Box<dyn Fn() -> Option<Box<dyn Demangled>>>>>);

    impl FixedNode {
        fn new(kind: SwiftDemangledNodeKind, make: impl Fn() -> Option<Box<dyn Demangled>> + 'static) -> Rc<dyn SwiftNode> {
            Rc::new(Self {
                base: SwiftNodeBase::new(NodeProperties::new(kind, None, None, 1, "$s", "orig", true)),
                result: RefCellResult(std::cell::RefCell::new(Some(Box::new(make)))),
            })
        }
    }
    impl SwiftNode for FixedNode {
        fn base(&self) -> &SwiftNodeBase {
            &self.base
        }
        fn demangle(&self, _demangler: &SwiftDemangler) -> Result<Option<Box<dyn Demangled>>, DemangledException> {
            let make = self.result.0.borrow();
            Ok(make.as_ref().expect("configured")())
        }
    }

    fn link(parent: &Rc<dyn SwiftNode>, child: Rc<dyn SwiftNode>) {
        child.base().set_parent(parent);
        parent.base().add_child(child);
    }

    fn module_child(name: &str) -> Rc<dyn SwiftNode> {
        let name = name.to_string();
        FixedNode::new(SwiftDemangledNodeKind::Module, move || {
            Some(Box::new(DemangledType::new("$sMod", &name, &name)))
        })
    }

    fn structure_child(name: &str) -> Rc<dyn SwiftNode> {
        let name = name.to_string();
        FixedNode::new(SwiftDemangledNodeKind::Structure, move || {
            Some(Box::new(DemangledType::new("$sTy", &name, &name)))
        })
    }

    #[test]
    fn joins_module_as_extension_namespace_beneath_the_type() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
        link(&node, module_child("MyModule"));
        link(&node, structure_child("MyStruct"));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "MyStruct");
        let namespace = demangled.get_namespace().expect("namespace attached");
        assert_eq!(namespace.get_name(), "(extension_MyModule)");
    }

    #[test]
    fn missing_module_or_type_yields_unknown() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
        link(&node, structure_child("MyStruct")); // no Module child

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        // getUnknown()'s name is the original demangled string set on this node's own properties.
        assert_eq!(demangled.get_name(), "OriginalDemangled");
    }

    #[test]
    fn other_kinds_are_skipped() {
        // Java's `skip(child)` here has an *implicit* `this` receiver -- it marks the node
        // performing the skip (this node), not the skipped child. See
        // SwiftExtensionNode.java's own `skip(child)` call versus demangleFirstChild's
        // `child.skip(child)` (a genuinely different call site/receiver).
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
        let other = FixedNode::new(SwiftDemangledNodeKind::Identifier, || None);
        link(&node, Rc::clone(&other));
        link(&node, module_child("M"));
        link(&node, structure_child("S"));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "S");
        assert!(node.base().child_was_skipped());
    }

    #[test]
    fn class_enum_protocol_and_structure_children_are_all_accepted_as_the_type() {
        for kind in [
            SwiftDemangledNodeKind::Class,
            SwiftDemangledNodeKind::Enum,
            SwiftDemangledNodeKind::Protocol,
            SwiftDemangledNodeKind::Structure,
        ] {
            let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
            link(&node, module_child("M"));
            let name = format!("{kind}");
            link(&node, FixedNode::new(kind, move || Some(Box::new(DemangledType::new("$s", &name, &name)))));

            let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
            assert_eq!(demangled.get_name(), format!("{kind}"));
        }
    }

    #[test]
    #[should_panic(expected = "NullPointerException")]
    fn module_child_demangling_to_nothing_panics_like_the_java_npe() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Module, || None));
        link(&node, structure_child("S"));

        let _ = node.demangle(&SwiftDemangler::new());
    }

    #[test]
    fn type_with_existing_namespace_gets_the_extension_namespace_spliced_beneath_it() {
        let node: Rc<dyn SwiftNode> = Rc::new(SwiftExtensionNode::new(props(SwiftDemangledNodeKind::Extension)));
        link(&node, module_child("Outer"));
        link(&node, FixedNode::new(SwiftDemangledNodeKind::Structure, || {
            let mut ty = DemangledType::new("$sTy", "Inner", "Inner");
            ty.set_namespace(Some(Box::new(DemangledType::new("$sNs", "Existing", "Existing"))));
            Some(Box::new(ty))
        }));

        let demangled = node.demangle(&SwiftDemangler::new()).expect("demangles").expect("Some");
        assert_eq!(demangled.get_name(), "Inner");
        let existing = demangled.get_namespace().expect("existing namespace kept as the immediate one");
        assert_eq!(existing.get_name(), "Existing");
        let extension_ns = existing.get_namespace().expect("extension namespace spliced beneath it");
        assert_eq!(extension_ns.get_name(), "(extension_Outer)");
    }
}
