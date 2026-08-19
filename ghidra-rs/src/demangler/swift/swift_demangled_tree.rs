//! A Swift demangled symbol, structured as a tree of nodes.
//!
//! Port of `ghidra.app.util.demangler.swift.SwiftDemangledTree`.

use std::rc::Rc;
use std::sync::OnceLock;

use regex::Regex;

use crate::demangler::demangle_exception::DemangledException;
use crate::demangler::seam_stubs::{SwiftNativeDemangledOutput, SwiftNativeDemangler, SwiftUnsupportedNode};
use crate::demangler::swift::nodes::swift_node::{self, NodeProperties, SwiftNode};
use crate::demangler::swift::swift_demangled_node_kind::SwiftDemangledNodeKind;

/// A Swift demangled symbol, structured as a tree of [`SwiftNode`]s.
///
/// Port of `SwiftDemangledTree`. `SwiftNode.get`'s dispatch to ~50 concrete node subclasses isn't
/// ported yet (see [`crate::demangler::seam_stubs::SwiftUnsupportedNode`]'s docs), so every node
/// this currently builds is a [`SwiftUnsupportedNode`], carrying the real parsed kind.
pub struct SwiftDemangledTree {
    root: Option<Rc<dyn SwiftNode>>,
    demangled_string: Option<String>,
}

impl SwiftDemangledTree {
    /// Creates a new [`SwiftDemangledTree`] by running the native Swift demangler over `mangled`.
    ///
    /// Mirrors `SwiftDemangledTree(SwiftNativeDemangler, String, boolean)`.
    ///
    /// # Errors
    /// Returns a [`DemangledException`] if there was an issue demangling.
    pub fn new(
        native_demangler: &SwiftNativeDemangler,
        mangled: &str,
        is64bit: bool,
    ) -> Result<Self, DemangledException> {
        let demangled_output =
            native_demangler.demangle(mangled).map_err(DemangledException::from_cause)?;
        Ok(Self::build(&demangled_output, mangled, is64bit))
    }

    /// Builds the tree from an already-produced [`SwiftNativeDemangledOutput`].
    ///
    /// Mirrors the body of the constructor after `nativeDemangler.demangle(mangled)` returns.
    /// Split out from [`SwiftDemangledTree::new`] so the tree-building logic can be exercised
    /// without a working native Swift toolchain.
    fn build(demangled_output: &SwiftNativeDemangledOutput, mangled: &str, is64bit: bool) -> Self {
        let demangled_string = demangled_output.demangled.clone();
        let mut root: Option<Rc<dyn SwiftNode>> = None;
        let mut stack: Vec<Rc<dyn SwiftNode>> = Vec::new();

        for line in &demangled_output.tree {
            let depth = Self::depth(line);
            let kind_name = Self::match_pattern(line, kind_pattern());
            let text = Self::match_pattern(line, text_pattern());
            let index = Self::match_pattern(line, index_pattern());

            let parsed_kind = kind_name.as_deref().and_then(SwiftDemangledNodeKind::from_name);
            let kind = parsed_kind.unwrap_or(SwiftDemangledNodeKind::Unsupported);
            let properties = NodeProperties::new(
                kind,
                text,
                index,
                depth,
                mangled,
                demangled_string.clone().unwrap_or_default(),
                is64bit,
            );
            let node: Rc<dyn SwiftNode> =
                Rc::new(SwiftUnsupportedNode::new(kind_name.unwrap_or_default(), properties));

            if depth == 0 {
                root = Some(Rc::clone(&node));
            } else if let Some(mut top_depth) = stack.last().map(|top| top.base().depth()) {
                if depth <= top_depth {
                    while top_depth > depth - 1 {
                        stack.pop();
                        top_depth = match stack.last() {
                            Some(top) => top.base().depth(),
                            None => break,
                        };
                    }
                }
                if let Some(parent) = stack.last() {
                    node.base().set_parent(parent);
                    parent.base().add_child(Rc::clone(&node));
                }
            }
            stack.push(node);
        }

        Self { root, demangled_string }
    }

    /// Gets the root [`SwiftNode`] of the tree.
    ///
    /// Mirrors `getRoot()`. Could be `None` if demangling finished gracefully but did not return
    /// a result.
    pub fn root(&self) -> Option<Rc<dyn SwiftNode>> {
        self.root.clone()
    }

    /// Gets the demangled string.
    ///
    /// Mirrors `getDemangledString()`. Could be `None` if demangling finished gracefully but did
    /// not return a result.
    pub fn demangled_string(&self) -> Option<&str> {
        self.demangled_string.as_deref()
    }

    /// Gets the tree-depth of a line of `swift demangle --tree-only` output.
    ///
    /// Mirrors the private `depth(String)`.
    fn depth(line: &str) -> usize {
        line.chars().take_while(|&c| c == ' ').count() / 2
    }

    /// Gets a matched pattern on the given line.
    ///
    /// Mirrors the private `match(String, Pattern)`.
    fn match_pattern(line: &str, pattern: &Regex) -> Option<String> {
        pattern.captures(line).and_then(|captures| captures.get(1)).map(|m| m.as_str().to_string())
    }
}

impl std::fmt::Display for SwiftDemangledTree {
    /// Mirrors `toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.root {
            Some(root) => write!(f, "{}", swift_node::to_string(&**root, true)),
            None => Ok(()),
        }
    }
}

fn kind_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"kind=([^,]+)").unwrap())
}

fn text_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"text="(.+)""#).unwrap())
}

fn index_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"index=(.+)").unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `$s4main3fooV` demangling to `Global -> Function -> (Module "Swift", Identifier "print")`,
    /// the same shape as the `Swift.print` example in the original Java class's doc comment.
    fn sample_output() -> SwiftNativeDemangledOutput {
        SwiftNativeDemangledOutput {
            demangled: Some("Swift.print".to_string()),
            tree: vec![
                "kind=Global".to_string(),
                "  kind=Function".to_string(),
                "    kind=Module, text=\"Swift\"".to_string(),
                "    kind=Identifier, text=\"print\"".to_string(),
            ],
        }
    }

    #[test]
    fn build_links_children_by_indentation_depth() {
        let tree = SwiftDemangledTree::build(&sample_output(), "$s4main3fooV", true);

        assert_eq!(tree.demangled_string(), Some("Swift.print"));

        let root = tree.root().expect("root");
        assert_eq!(root.base().kind(), SwiftDemangledNodeKind::Global);
        assert_eq!(root.base().depth(), 0);

        let function = root.base().child(SwiftDemangledNodeKind::Function).expect("Function child");
        assert_eq!(function.base().depth(), 1);

        let children: Vec<_> = function.base().children().iter().cloned().collect();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].base().kind(), SwiftDemangledNodeKind::Module);
        assert_eq!(children[0].base().text(), Some("Swift"));
        assert_eq!(children[1].base().kind(), SwiftDemangledNodeKind::Identifier);
        assert_eq!(children[1].base().text(), Some("print"));

        assert!(function.base().parent().is_some());
        assert_eq!(
            function.base().parent().unwrap().base().kind(),
            SwiftDemangledNodeKind::Global
        );
    }

    #[test]
    fn display_recurses_depth_first_over_unsupported_nodes() {
        let tree = SwiftDemangledTree::build(&sample_output(), "$s4main3fooV", true);

        // `swift_node::to_string` (already ported) renders via `node.base().to_string()`, not a
        // polymorphic override, so `SwiftUnsupportedNode`'s "(OriginalKind)" suffix (verified
        // directly on the concrete type below) does not surface through this recursive render.
        assert_eq!(
            tree.to_string(),
            concat!(
                "kind=Global\n",
                "  kind=Function\n",
                "    kind=Module, text=\"Swift\"\n",
                "    kind=Identifier, text=\"print\"\n",
            )
        );
    }

    #[test]
    fn unrecognized_kind_names_fall_back_to_unsupported() {
        let output = SwiftNativeDemangledOutput {
            demangled: Some("?".to_string()),
            tree: vec!["kind=VariadicMarker".to_string()],
        };

        let tree = SwiftDemangledTree::build(&output, "mangled", false);
        let root = tree.root().expect("root");
        assert_eq!(root.base().kind(), SwiftDemangledNodeKind::Unsupported);
        assert_eq!(root.base().to_string(), "kind=Unsupported");
    }

    #[test]
    fn swift_unsupported_node_display_appends_the_original_kind_name() {
        use crate::demangler::seam_stubs::SwiftUnsupportedNode;

        let properties = NodeProperties::new(
            SwiftDemangledNodeKind::Unsupported,
            None,
            None,
            0,
            "mangled",
            "?",
            false,
        );
        let node = SwiftUnsupportedNode::new("VariadicMarker", properties);
        assert_eq!(node.to_string(), "kind=Unsupported (VariadicMarker)");
    }

    #[test]
    fn empty_tree_has_no_root_and_displays_as_empty() {
        let output = SwiftNativeDemangledOutput { demangled: None, tree: vec![] };
        let tree = SwiftDemangledTree::build(&output, "mangled", false);

        assert!(tree.root().is_none());
        assert_eq!(tree.demangled_string(), None);
        assert_eq!(tree.to_string(), "");
    }

    #[test]
    fn new_propagates_native_demangler_io_errors() {
        let native_demangler = SwiftNativeDemangler;
        match SwiftDemangledTree::new(&native_demangler, "$s4main3fooV", true) {
            Err(error) => assert!(!error.is_invalid_mangled_name()),
            Ok(_) => panic!("native demangler is not yet ported"),
        }
    }
}
